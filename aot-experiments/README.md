# AOT Experiments

This Rust project was created to experiment with reverse engineering NativeAOT binaries, specifically targeting the HytaleClient.exe binary.

To understand more about how this tool has came to be, check out the [NativeAOT Docs](../docs/nativeaot/README.md).

The code right now (specifically `main.rs`) is a hot mess with hardcoded paths and references to files that no longer exist.

I have tried making all the other code not as shit as the main file.

## Requirements

- [Rust](https://rustup.rs/)
- [Clang](https://releases.llvm.org/download.html) (google distro instructions if on Linux/MacOS)

## Building

```sh
cargo update # makes sure that idalib is up-to-date
```

```
cargo build
```