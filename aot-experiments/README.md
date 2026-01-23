# AOT Experiments

This Rust project was created to experiment with reverse engineering NativeAOT binaries, specifically targeting the HytaleClient.exe binary.

To understand more about how this tool has came to be, check out the [NativeAOT Docs](../docs/nativeaot/README.md).

## Usage

```sh
cargo run -- <path to HytaleClient.exe> dump-ida
```

Running the above command will generate a `hytale_def.json` file. To load this file into IDA, run the `hytale.py` script found in the `python` directory through IDAs "Script file..." menu item.

## Requirements

- [Rust](https://rustup.rs/)
