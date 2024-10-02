# heaphook_rust
Heaphook implemented in Rust


# Build

```bash
cargo build --release
```


# Run example

```bash
cd example
g++ main.cpp
LD_PRELOAD="../target/release/libheaphook_rust.so" MEMPOOL_SIZE="123456789" ./a.out
```