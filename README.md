# Windows CNG bridge for rustls

This project allows to use private keys from the Windows certificate store together with `rustls`,
either as a server keychain or client certificate identity.

Rationale: in many situations it is required to use non-exportable private certificate chains
 from the Windows certificate store. `rustls-cng` can use such chains in the `rustls` context.

Supported key/certificate types: **RSA**, **ECDSA/ECDH** (secp256r1, secp384r1, secp521r1 curves).

## Usage

The central struct to use in `rustls` is `CngSigningKey` which can be constructed
 from the low-level `NCryptKey` handle. The instance of `CngSigningKey` can be then be
 used in `rustls` in the custom `ResolvesServerCert` implementation.

See the `examples/server.rs` for an example how to use it.

## License

Licensed under MIT or Apache license ([LICENSE-MIT](https://opensource.org/licenses/MIT) or [LICENSE-APACHE](https://opensource.org/licenses/Apache-2.0))
