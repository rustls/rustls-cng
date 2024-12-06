# Windows CNG bridge for rustls

[![github actions](https://github.com/ancwrd1/rustls-cng/workflows/CI/badge.svg)](https://github.com/rustls/rustls-cng/actions)
[![crates](https://img.shields.io/crates/v/rustls-cng.svg)](https://crates.io/crates/rustls-cng)
[![license](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![docs.rs](https://docs.rs/rustls-cng/badge.svg)](https://docs.rs/rustls-cng)

This crate allows you to use the Windows CNG private keys together with [rustls](https://docs.rs/rustls/latest/rustls)
 for both the client and server sides of the TLS channel.

Rationale: In many situations, it is required to use non-exportable private certificate chains
 from the Windows certificate store instead of the external PKCS8 file.
 `rustls-cng` can use such chains in the `rustls` context.

Supported key/certificate types: **RSA**, **ECDSA/ECDH**. Supported elliptic curves: secp256r1 (prime256v1), secp384r1.

## Documentation

Documentation is available [here](https://rustls.github.io/rustls-cng/doc/rustls_cng).

## Usage

The central struct to use in `rustls-cng` is `CngSigningKey`, which can be constructed
 from the low-level `NCryptKey` handle. The instance of `CngSigningKey` can then be
 used in `rustls` in the custom `ResolvesServerCert` or `ResolvesClientCert` implementation.

See the `examples` directory for usage examples.

## License

Licensed under the MIT or Apache licenses ([LICENSE-MIT](https://opensource.org/licenses/MIT) or [LICENSE-APACHE](https://opensource.org/licenses/Apache-2.0))
