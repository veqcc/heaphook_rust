use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::env;
use std::process;
use lazy_static::lazy_static;
use std::ptr;
use libc::{mmap, PROT_READ, PROT_WRITE, MAP_PRIVATE, MAP_ANONYMOUS};
use rlsf::Tlsf;
use std::mem::MaybeUninit;
use once_cell::sync::Lazy;
use std::os::raw::c_void;
use libc::{dlsym, RTLD_NEXT};
use std::ffi::CStr;

static MEMPOOL_INITIALIZED : AtomicBool = AtomicBool::new(false);
lazy_static! {
    static ref MUTEX : Mutex<bool> = Mutex::new(false);
}

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

fn initialize() -> () {
    if MEMPOOL_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

    let _guard = MUTEX.lock().unwrap();


    if MEMPOOL_INITIALIZED.load(Ordering::Acquire) {
        return;
    }

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

    let ptr = unsafe {
        mmap(ptr::null_mut(), aligned_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
    };

    if ptr == libc::MAP_FAILED {
        println!("mmap failed");
        process::exit(1);
    }

    let pool: &mut [MaybeUninit<u8>] = unsafe {
        std::slice::from_raw_parts_mut(ptr as *mut MaybeUninit<u8>, mempool_size)
    };

    const FLLEN : usize = 12; // first level
    const SLLEN : usize = 16; // second level
    let mut tlsf: Tlsf<'_, u16, u16, FLLEN, SLLEN> = Tlsf::new();
    tlsf.insert_free_block(pool);

    MEMPOOL_INITIALIZED.store(true, Ordering::Release);
}

#[no_mangle]
pub extern "C" fn malloc(size : usize) -> *mut c_void {
    static mut IS_IN_HOOKED_CALL : bool = false;
    
    unsafe {
        if IS_IN_HOOKED_CALL {
            ORIGINAL_MALLOC(size)
        } else {
            IS_IN_HOOKED_CALL = true;
            initialize();
            let ret = ORIGINAL_MALLOC(size);
            IS_IN_HOOKED_CALL = false;

            ret
        }
    }
}

#[no_mangle]
pub extern "C" fn free(ptr : *mut c_void) -> () {
    static mut IS_IN_HOOKED_CALL : bool = false;
    
    unsafe {
        if IS_IN_HOOKED_CALL {
            ORIGINAL_FREE(ptr)
        } else {
            IS_IN_HOOKED_CALL = true;
            initialize();
            ORIGINAL_FREE(ptr);
            IS_IN_HOOKED_CALL = false;
        }
    }
}
