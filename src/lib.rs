use std::alloc::Layout;
use std::env;
use std::process;
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

type TlsfType = Tlsf<'static, u16, u16, 12, 16>;
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
    println!("aligned size = {}", aligned_size);

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

fn tlsf_malloc_wrapped(size : usize) -> *mut c_void {
    let layout = Layout::from_size_align(size, 4096).unwrap();
    println!("allocate size = {}", size);
    let ptr = TLSF.lock().unwrap().allocate(layout).unwrap();
    ptr.as_ptr() as *mut c_void
}

fn tlsf_free_wrapped(ptr : *mut c_void) -> () {
    unsafe {
        let non_null_ptr: NonNull<u8> = NonNull::new_unchecked(ptr as *mut u8);
        TLSF.lock().unwrap().deallocate(non_null_ptr, 4096);
    }
}

#[no_mangle]
pub extern "C" fn malloc(size : usize) -> *mut c_void {
    static mut HOOKED : bool = false;
    unsafe {
        if HOOKED {
            ORIGINAL_MALLOC(size)
        } else {
            HOOKED = true;
            let ret = tlsf_malloc_wrapped(size);
            INITIALIZED.store(true, Ordering::Release);
            println!("addr = {:p}", ret);
            HOOKED = false;
            ret
        }
    }
}

#[no_mangle]
pub extern "C" fn free(ptr : *mut c_void) -> () {    
    unsafe {
        if INITIALIZED.load(Ordering::Acquire) {
            tlsf_free_wrapped(ptr)
        } else {
            ORIGINAL_FREE(ptr);
        }
    }
}
