# boring2

[![crates.io](https://img.shields.io/crates/v/boring2.svg)](https://crates.io/crates/boring2)

BoringSSL bindings for the Rust programming language and HTTP client for [wreq](https://github.com/0x676e67/wreq) built on top of it.

## Non-goals

This package implements only the TLS extensions specification and supports the original [boring](https://github.com/cloudflare/boring) library with the following features:

- Required TLS extensions for Safari and Firefox
- kDHE, ffdhe2048, and ffdhe3072 implementations
- RPK is not supported
- Support for LoongArch P64 and P32 architectures

## Documentation
 - Boring API: <https://docs.rs/boring2>
 - tokio TLS adapters: <https://docs.rs/tokio-boring2>
 - compio TLS adapters: <https://docs.rs/compio-boring2>
 - FFI bindings: <https://docs.rs/boring-sys2>

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed under the terms of both the Apache License,
Version 2.0 and the MIT license without any additional terms or conditions.

## Accolades

The project is based on a fork of [boring](https://github.com/cloudflare/boring).
