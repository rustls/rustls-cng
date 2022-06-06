# Windows CNG bridge for rustls

This project allows to use private keys from the Windows certificate store together with rustls,
both as server key chain and client key chain.

Rationale: in many situations it is required to use non-exportable private certificate chains
 from the Windows certificate store. `rustls-cng` can use such chains in the rustls context.

Supported key types: RSA, ECDSA/ECDH (secp256r1, secp384r1, secp521r1 curves).
