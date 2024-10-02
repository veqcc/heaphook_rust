use std::{
    alloc::Layout,
    cell::RefCell,
    ffi::CStr,
    os::raw::c_void,
    mem::MaybeUninit,
    collections::HashMap,
    sync::Mutex
};
use libc::{dlsym, RTLD_NEXT};
use rlsf::Tlsf;
use once_cell::sync::Lazy;

const ALIGNMENT : usize = 64;

static ALIGNED_TO_ORIGINAL : Lazy<Mutex<HashMap<usize, usize>>> = Lazy::new(|| {
    Mutex::new(HashMap::new())
});

type MallocType = unsafe extern "C" fn(usize) -> *mut c_void;
static ORIGINAL_MALLOC : Lazy<MallocType> = Lazy::new(|| {
    let symbol = CStr::from_bytes_with_nul(b"malloc\0").unwrap();
    unsafe {
        let malloc_ptr = dlsym(RTLD_NEXT, symbol.as_ptr());
        std::mem::transmute(malloc_ptr)
    }
});

type FreeType = unsafe extern "C" fn(*mut c_void) -> ();
static ORIGINAL_FREE : Lazy<FreeType> = Lazy::new(|| {
    let symbol = CStr::from_bytes_with_nul(b"free\0").unwrap();
    unsafe {
        let free_ptr = dlsym(RTLD_NEXT, symbol.as_ptr());
        std::mem::transmute(free_ptr)
    }
});

type CallocType = unsafe extern "C" fn(usize, usize) -> *mut c_void;
static ORIGINAL_CALLOC : Lazy<CallocType> = Lazy::new(|| {
    let symbol = CStr::from_bytes_with_nul(b"calloc\0").unwrap();
    unsafe {
        let calloc_ptr = dlsym(RTLD_NEXT, symbol.as_ptr());
        std::mem::transmute(calloc_ptr)
    }
});

type ReallocType = unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void;
static ORIGINAL_REALLOC : Lazy<ReallocType> = Lazy::new(|| {
    let symbol = CStr::from_bytes_with_nul(b"realloc\0").unwrap();
    unsafe {
        let realloc_ptr = dlsym(RTLD_NEXT, symbol.as_ptr());
        std::mem::transmute(realloc_ptr)
    }
});

type PosixMemalignType = unsafe extern "C" fn(*mut *mut c_void, usize, usize) -> i32;
static ORIGINAL_POSIX_MEMALIGN : Lazy<PosixMemalignType> = Lazy::new(|| {
    let symbol = CStr::from_bytes_with_nul(b"posix_memalign\0").unwrap();
    unsafe {
        let posix_memalign_ptr = dlsym(RTLD_NEXT, symbol.as_ptr());
        std::mem::transmute(posix_memalign_ptr)
    }
});

type AlignedAllocType = unsafe extern "C" fn(usize, usize) -> *mut c_void;
static ORIGINAL_ALIGNED_ALLOC : Lazy<AlignedAllocType> = Lazy::new(|| {
    let symbol = CStr::from_bytes_with_nul(b"aligned_alloc\0").unwrap();
    unsafe {
        let aligned_alloc_ptr = dlsym(RTLD_NEXT, symbol.as_ptr());
        std::mem::transmute(aligned_alloc_ptr)
    }
});

type MemalignType = unsafe extern "C" fn(usize, usize) -> *mut c_void;
static ORIGINAL_MEMALIGN : Lazy<MemalignType> = Lazy::new(|| {
    let symbol = CStr::from_bytes_with_nul(b"memalign\0").unwrap();
    unsafe {
        let memalign_ptr = dlsym(RTLD_NEXT, symbol.as_ptr());
        std::mem::transmute(memalign_ptr)
    }
});

type TlsfType = Tlsf<'static, u32, u32, 32, 32>;
static TLSF : Lazy<Mutex<TlsfType>> = Lazy::new(|| {
    let mempool_size_env : String = match std::env::var("MEMPOOL_SIZE") {
        Ok(value) => { value }
        Err(error) => {
            println!("MEMPOOL_SIZE is not set in environment variable: {}", error);
            std::process::exit(1);
        }
    };

    let mempool_size : usize = mempool_size_env.parse::<usize>().unwrap();

    const PAGE_SIZE: usize = 4096;
    let aligned_size = (mempool_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let addr : *mut c_void = 0x40000000000 as *mut c_void;

    let ptr = unsafe {
        libc::mmap(addr, aligned_size, libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE, -1, 0)
    };

    if ptr == libc::MAP_FAILED {
        println!("mmap failed");
        std::process::exit(1);
    }

    let pool: &mut [MaybeUninit<u8>] = unsafe {
        std::slice::from_raw_parts_mut(ptr as *mut MaybeUninit<u8>, mempool_size)
    };

    let mut tlsf: TlsfType = Tlsf::new();
    tlsf.insert_free_block(pool);

    Mutex::new(tlsf)
});

fn tlsf_allocate(size : usize) -> *mut c_void {
    let layout = Layout::from_size_align(size, ALIGNMENT).unwrap();
    let ptr = TLSF.lock().unwrap().allocate(layout).unwrap();
    ptr.as_ptr() as *mut c_void
}

fn tlsf_reallcate(ptr : *mut c_void, size : usize) -> *mut c_void {
    let layout = Layout::from_size_align(size, ALIGNMENT).unwrap();
    let new_ptr = unsafe {
        let non_null_ptr: std::ptr::NonNull<u8> = std::ptr::NonNull::new_unchecked(ptr as *mut u8);
        TLSF.lock().unwrap().reallocate(non_null_ptr, layout).unwrap()
    };
    new_ptr.as_ptr() as *mut c_void
}

fn tlsf_deallocate(ptr : *mut c_void) {
    unsafe {
        let non_null_ptr = std::ptr::NonNull::new_unchecked(ptr as *mut u8);
        TLSF.lock().unwrap().deallocate(non_null_ptr, ALIGNMENT);
    }
}

fn aligned_alloc_wrapped(alignment : usize, size : usize) -> *mut c_void {
    let addr = tlsf_allocate(size + alignment) as usize;
    let aligned_addr = addr + alignment - (addr % alignment);
    ALIGNED_TO_ORIGINAL.lock().unwrap().insert(aligned_addr, addr);
    aligned_addr as *mut c_void
}

thread_local! {
    static HOOKED : RefCell<bool> = RefCell::new(false);
}

#[no_mangle]
pub extern "C" fn malloc(size : usize) -> *mut c_void {
    HOOKED.with(|hooked| {
        if *hooked.borrow() {
            unsafe { ORIGINAL_MALLOC(size) }
        } else {
            hooked.replace(true);
            let ret = tlsf_allocate(size);
            hooked.replace(false);
            ret
        }
    })
}

#[no_mangle]
pub extern "C" fn free(ptr : *mut c_void) {
    if ptr.is_null() { return; };

    let ptr_addr = unsafe { std::ptr::NonNull::new_unchecked(ptr as *mut u8).as_ptr() as usize };

    HOOKED.with(|hooked| {
        if *hooked.borrow() || !(0x40000000000..=0x50000000000).contains(&ptr_addr) {
            unsafe { ORIGINAL_FREE(ptr); }
        } else {
            hooked.replace(true);

            let mut aligned_to_original_map = ALIGNED_TO_ORIGINAL.lock().unwrap();
            if let Some(original_addr) = aligned_to_original_map.get(&ptr_addr) {
                tlsf_deallocate(*original_addr as *mut c_void);
                aligned_to_original_map.remove(&ptr_addr);
            } else {
                tlsf_deallocate(ptr);
            }

            hooked.replace(false);
        }
    });
}

#[no_mangle]
pub extern "C" fn calloc(num : usize, size : usize) -> *mut c_void {
    HOOKED.with(|hooked| {
        if *hooked.borrow() {
            unsafe { ORIGINAL_CALLOC(num, size) }
        } else {
            hooked.replace(true);
            let ret = tlsf_allocate(num * size);
            unsafe { std::ptr::write_bytes(ret, 0, num * size); };
            hooked.replace(false);
            ret
        }
    })
}

#[no_mangle]
pub extern "C" fn realloc(ptr : *mut c_void, new_size : usize) -> *mut c_void {
    HOOKED.with(|hooked| {
        if *hooked.borrow() {
            unsafe { ORIGINAL_REALLOC(ptr, new_size) }
        } else {
            hooked.replace(true);

            let realloc_ret = if ptr.is_null() {
                tlsf_allocate(new_size)
            } else {
                let ptr_addr = unsafe { std::ptr::NonNull::new_unchecked(ptr as *mut u8).as_ptr() as usize };
                if !(0x40000000000..=0x50000000000).contains(&ptr_addr) {
                    unsafe { ORIGINAL_REALLOC(ptr, new_size) }
                } else {
                    let mut aligned_to_original_map = ALIGNED_TO_ORIGINAL.lock().unwrap();
                    if let Some(original_addr) = aligned_to_original_map.get(&ptr_addr) {
                        let ret = tlsf_reallcate(*original_addr as *mut c_void, new_size);
                        aligned_to_original_map.remove(&ptr_addr);
                        ret
                    } else {
                        tlsf_reallcate(ptr, new_size)
                    }
                }
            };

            hooked.replace(false);
            realloc_ret
        }
    })
}

#[no_mangle]
pub extern "C" fn posix_memalign(memptr : *mut *mut c_void, alignment : usize, size : usize) -> i32 {
    HOOKED.with(|hooked| {
        if *hooked.borrow() {
            unsafe { ORIGINAL_POSIX_MEMALIGN(memptr, alignment, size) }
        } else {
            hooked.replace(true);
            unsafe { *memptr = aligned_alloc_wrapped(alignment, size); };
            hooked.replace(false);
            0
        }
    })
}

#[no_mangle]
pub extern "C" fn aligned_alloc(alignment : usize, size : usize) -> *mut c_void {
    HOOKED.with(|hooked| {
        if *hooked.borrow() {
            unsafe { ORIGINAL_ALIGNED_ALLOC(alignment, size) }
        } else {
            hooked.replace(true);
            let ret = aligned_alloc_wrapped(alignment, size);
            hooked.replace(false);
            ret
        }
    })
}

#[no_mangle]
pub extern "C" fn memalign(alignment : usize, size : usize) -> *mut c_void {
    HOOKED.with(|hooked| {
        if *hooked.borrow() {
            unsafe { ORIGINAL_MEMALIGN(alignment, size) }
        } else {
            hooked.replace(true);
            let ret = aligned_alloc_wrapped(alignment, size);
            hooked.replace(false);
            ret
        }
    })
}

#[no_mangle]
pub extern "C" fn valloc(_size : usize) -> *mut c_void {
    println!("NOTE: valloc is not supported");
    std::ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn pvalloc(_size : usize) -> *mut c_void {
    println!("NOTE: pvalloc is not supported");
    std::ptr::null_mut()
}
