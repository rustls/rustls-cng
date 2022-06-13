# Windows CNG bridge for rustls

This crate allows to use the Windows CNG private keys together with [rustls](https://docs.rs/rustls/latest/rustls)
 for both client and server side of the TLS channel.

Rationale: in many situations it is required to use non-exportable private certificate chains
 from the Windows certificate store. `rustls-cng` can use such chains in the `rustls` context.

Supported key/certificate types: **RSA**, **ECDSA/ECDH** (secp256r1, secp384r1, secp521r1 curves).

## Usage

The central struct to use in `rustls-cng` is `CngSigningKey` which can be constructed
 from the low-level `NCryptKey` handle. The instance of `CngSigningKey` can be then be
 used in `rustls` in the custom `ResolvesServerCert` or `ResolvesClientCert` implementation.

See the `examples` directory for usage examples.

## License

Licensed under MIT or Apache license ([LICENSE-MIT](https://opensource.org/licenses/MIT) or [LICENSE-APACHE](https://opensource.org/licenses/Apache-2.0))
