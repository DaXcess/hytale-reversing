# Hytale Client Reverse Engineering

This repo contains some stuff about reverse engineering the Hytale Client.

The code right now (specifically `main.rs`) is a hot mess with hardcoded paths and references to files that no longer exist.

I have tried making all the other code not as shit as the main file.

Yes this repo still requires a bunch of documentation (how to reverse AOT, what game internals have been discovered, etc, etc)

## Building

```sh
cargo update # makes sure that idalib is up-to-date
```

```
cargo build
```