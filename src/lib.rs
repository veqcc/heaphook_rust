use std::alloc::Layout;
use std::env;
use std::process;
use std::ptr;
use std::ptr::NonNull;
use std::sync::atomic::AtomicBool;
use libc::{mmap, PROT_READ, PROT_WRITE, MAP_PRIVATE, MAP_ANONYMOUS, MAP_FIXED};
use rlsf::Tlsf;
use std::mem::MaybeUninit;
use once_cell::sync::Lazy;
use std::os::raw::c_void;
use libc::{dlsym, RTLD_NEXT};
use std::ffi::CStr;
use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::cell::RefCell;

static INITIALIZED : AtomicBool = AtomicBool::new(false);

type MallocType = unsafe extern "C" fn(usize) -> *mut c_void;
static ORIGINAL_MALLOC : Lazy<MallocType> = Lazy::new(|| {
    unsafe {
        let symbol = CStr::from_bytes_with_nul(b"malloc\0").unwrap();
        let malloc_ptr = dlsym(RTLD_NEXT, symbol.as_ptr());
        std::mem::transmute(malloc_ptr)
    }
});

type FreeType = unsafe extern "C" fn(*mut c_void) -> ();
static ORIGINAL_FREE : Lazy<FreeType> = Lazy::new(|| {
    unsafe {
        let symbol = CStr::from_bytes_with_nul(b"free\0").unwrap();
        let free_ptr = dlsym(RTLD_NEXT, symbol.as_ptr());
        std::mem::transmute(free_ptr)
    }
});

type CallocType = unsafe extern "C" fn(usize, usize) -> *mut c_void;
static ORIGINAL_CALLOC : Lazy<CallocType> = Lazy::new(|| {
    unsafe {
        let symbol = CStr::from_bytes_with_nul(b"calloc\0").unwrap();
        let calloc_ptr = dlsym(RTLD_NEXT, symbol.as_ptr());
        std::mem::transmute(calloc_ptr)
    }
});

type ReallocType = unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void;
static ORIGINAL_REALLOC : Lazy<ReallocType> = Lazy::new(|| {
    unsafe {
        let symbol = CStr::from_bytes_with_nul(b"realloc\0").unwrap();
        let realloc_ptr = dlsym(RTLD_NEXT, symbol.as_ptr());
        std::mem::transmute(realloc_ptr)
    }
});

type TlsfType = Tlsf<'static, u32, u32, 20, 16>;
static TLSF : Lazy<Mutex<TlsfType>> = Lazy::new(|| {
    let mempool_size_env : String = match env::var("MEMPOOL_SIZE") {
        Ok(value) => { value }
        Err(error) => {
            println!("MEMPOOL_SIZE is not set in environment variable: {}", error);
            process::exit(1);
        }
    };

    let mempool_size : usize = mempool_size_env.parse::<usize>().unwrap();

    const PAGE_SIZE: usize = 4096;
    let aligned_size = (mempool_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let addr : *mut c_void = 0x40000000000 as *mut c_void;

    let ptr = unsafe {
        mmap(addr, aligned_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0)
    };

    if ptr == libc::MAP_FAILED {
        println!("mmap failed");
        process::exit(1);
    }

    let pool: &mut [MaybeUninit<u8>] = unsafe {
        std::slice::from_raw_parts_mut(ptr as *mut MaybeUninit<u8>, mempool_size)
    };

    let mut tlsf: TlsfType = Tlsf::new();
    tlsf.insert_free_block(pool);

    Mutex::new(tlsf)
});

fn tlsf_allocate_internal(size : usize) -> *mut c_void {
    let layout = Layout::from_size_align(size, 4096).unwrap();
    let ptr = TLSF.lock().unwrap().allocate(layout).unwrap();
    ptr.as_ptr() as *mut c_void
}

fn tlsf_malloc_wrapped(size : usize) -> *mut c_void {
    tlsf_allocate_internal(size)
}

fn tlsf_free_wrapped(ptr : *mut c_void) {
    unsafe {
        let non_null_ptr: NonNull<u8> = NonNull::new_unchecked(ptr as *mut u8);
        TLSF.lock().unwrap().deallocate(non_null_ptr, 4096);
    }
}

fn tlsf_calloc_wrapped(num : usize, size : usize) -> *mut c_void {
    tlsf_allocate_internal(num * size)
}

fn tlsf_realloc_wrapped(ptr : *mut c_void, size : usize) -> *mut c_void {
    let layout = Layout::from_size_align(size, 4096).unwrap();
    let new_ptr = unsafe {
        let non_null_ptr: NonNull<u8> = NonNull::new_unchecked(ptr as *mut u8);
        TLSF.lock().unwrap().reallocate(non_null_ptr, layout).unwrap()
    };
    new_ptr.as_ptr() as *mut c_void
}


thread_local! {
    static HOOKED : RefCell<bool> = RefCell::new(false);
}

#[no_mangle]
pub extern "C" fn malloc(size : usize) -> *mut c_void {
    unsafe {
        HOOKED.with(|hooked| {
            if *hooked.borrow() {
                ORIGINAL_MALLOC(size)
            } else {
                hooked.replace(true);
                let ret = tlsf_malloc_wrapped(size);
                INITIALIZED.store(true, Ordering::Release);
                hooked.replace(false);
                ret
            }
        })
    }
}

#[no_mangle]
pub extern "C" fn free(ptr : *mut c_void) {
    unsafe {
        if INITIALIZED.load(Ordering::Acquire) {
            tlsf_free_wrapped(ptr)
        } else {
            ORIGINAL_FREE(ptr)
        }
    }
}

#[no_mangle]
pub extern "C" fn calloc(num : usize, size : usize) -> *mut c_void {
    unsafe {
        HOOKED.with(|hooked| {
            if *hooked.borrow() {
                ORIGINAL_CALLOC(num, size)
            } else {
                hooked.replace(true);
                let ret = tlsf_calloc_wrapped(num, size);
                INITIALIZED.store(true, Ordering::Release);
                hooked.replace(false);
                ret
            }
        })
    }
}

#[no_mangle]
pub extern "C" fn realloc(ptr : *mut c_void, new_size : usize) -> *mut c_void {
    unsafe {
        if INITIALIZED.load(Ordering::Acquire) {
            tlsf_realloc_wrapped(ptr, new_size)
        } else {
            ORIGINAL_REALLOC(ptr, new_size)
        }
    }
}

#[no_mangle]
pub extern "C" fn posix_memalign(_memptr : *mut *mut c_void, _alignment : usize, _size : usize) -> i32 {
    println!("TODO: posix_memalign should be implemented");
    0
}

#[no_mangle]
pub extern "C" fn memalign(_alignment : usize, _size : usize) -> *mut c_void {
    println!("TODO: memalign should be implemented");
    ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn aligned_alloc(_alignment : usize, _size : usize) -> *mut c_void {
    println!("TODO: aligned_alloc should be implemented");
    ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn valloc(_size : usize) -> *mut c_void {
    println!("TODO: valloc should be implemented");
    ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn pvalloc(_size : usize) -> *mut c_void {
    println!("TODO: pvalloc should be implemented");
    ptr::null_mut()
}
