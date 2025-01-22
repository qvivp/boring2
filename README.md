# boring

[![crates.io](https://img.shields.io/crates/v/boring2.svg)](https://crates.io/crates/boring2)

BoringSSL bindings are available for the Rust programming language, and the [HTTP Client](https://github.com/0x676e67/rquest) is built on top of it.

## Non-goals

This package is focused solely on implementing the TLS extensions spec. It supports the original [boring](https://github.com/cloudflare/boring) , including:

* Safari required TLS extensions
* Firefox required TLS extensions
* `kDHE` && `ffdhe2048`/`ffdhe3072` implementations

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed under the terms of both the Apache License,
Version 2.0 and the MIT license without any additional terms or conditions.

## Accolades

The project is based on a fork of [boring](https://github.com/cloudflare/boring).
