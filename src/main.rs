use std::sync::Mutex;
use once_cell::sync::Lazy;

static GLOBAL : Lazy<Mutex<u32>> = Lazy::new(|| Mutex::new(1));

fn main() {
    let data = GLOBAL.lock().unwrap();
    println!("global = {}", *data);
}