//! Windows CNG bridge for [rustls](https://docs.rs/rustls/latest/rustls).
//!
//! This crate allows private keys stored in the Windows certificate store and managed by the
//! [CNG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal) API to be used by
//! `rustls` on both the client and the server side of a TLS connection.
//!
//! In many environments certificate chains are provisioned into the Windows certificate store
//! with non-exportable private keys (including keys backed by smart cards or TPMs), so they
//! cannot be loaded from an external PKCS#8 file. `rustls-cng` performs signing operations
//! through CNG instead, so the private key never leaves its key storage provider.
//!
//! Supported key types are **RSA** and **ECDSA**, with the secp256r1 (prime256v1), secp384r1
//! and secp521r1 elliptic curves.
//!
//! # Overview
//!
//! * [`store::CertStore`] opens a system certificate store (or imports a PKCS#12 blob) and
//!   looks up certificates by subject, issuer, hash or key id.
//! * [`cert::CertContext`] wraps a found certificate; it provides the DER-encoded certificate
//!   chain and acquires the associated private key as a [`key::NCryptKey`].
//! * [`config::CngCredentials`] bundles the key and the certificate chain.
//! * [`config::WithClientCngCredentials`] and [`config::WithServerCngCredentials`] are
//!   extension traits for the `rustls` config builders which install the credentials into a
//!   [`rustls::ClientConfig`] or a [`rustls::ServerConfig`].
//! * [`signer::CngSigningKey`] is the underlying [`rustls::crypto::SigningKey`] implementation,
//!   for use cases not covered by the config helpers.
//!
//! The `rustls` crate is re-exported as [`rustls`] so that the matching version is always
//! available to dependents.
//!
//! # Client example
//!
//! Authenticate a TLS client with a certificate from the current user's personal store:
//!
//! ```rust,no_run
//! use std::sync::Arc;
//!
//! use rustls::{ClientConfig, RootCertStore};
//! use rustls_cng::{
//!     config::{CngCredentials, WithClientCngCredentials},
//!     store::{CertStore, CertStoreType},
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let store = CertStore::open(CertStoreType::CurrentUser, "my")?;
//! let contexts = store.find_by_subject_str("client-cert-name")?;
//! let context = contexts.first().ok_or("client certificate not found")?;
//!
//! let credentials = CngCredentials {
//!     key: context.acquire_key(false)?,
//!     chain: context.as_chain_der()?.into_iter().map(Into::into).collect(),
//! };
//!
//! let config = ClientConfig::builder(Arc::new(rustls_aws_lc_rs::DEFAULT_PROVIDER))
//!     .with_root_certificates(RootCertStore::empty())
//!     .with_client_cng_credentials(credentials)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Server example
//!
//! On the server side the credentials are resolved per connection, e.g. based on the SNI name
//! sent by the client:
//!
//! ```rust,no_run
//! use std::sync::Arc;
//!
//! use rustls::{ServerConfig, server::ClientHello};
//! use rustls_cng::{
//!     config::{CngCredentials, WithServerCngCredentials},
//!     store::{CertStore, CertStoreType},
//! };
//!
//! fn resolve(store: &CertStore, client_hello: &ClientHello) -> Result<CngCredentials, rustls::Error> {
//!     let name = client_hello.server_name().ok_or(rustls::Error::NoSuitableCertificate)?;
//!     let contexts = store
//!         .find_by_subject_str(name)
//!         .map_err(|_| rustls::Error::NoSuitableCertificate)?;
//!
//!     contexts
//!         .into_iter()
//!         .find_map(|ctx| {
//!             let key = ctx.acquire_key(true).ok()?;
//!             let chain = ctx.as_chain_der().ok()?.into_iter().map(Into::into).collect();
//!             Some(CngCredentials { key, chain })
//!         })
//!         .ok_or(rustls::Error::NoSuitableCertificate)
//! }
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let store = CertStore::open(CertStoreType::LocalMachine, "my")?;
//!
//! let config = ServerConfig::builder(Arc::new(rustls_aws_lc_rs::DEFAULT_PROVIDER))
//!     .with_no_client_auth()
//!     .with_server_cng_credentials(move |client_hello| resolve(&store, client_hello))?;
//! # Ok(())
//! # }
//! ```
//!
//! Complete client and server programs can be found in the
//! [`examples`](https://github.com/rustls/rustls-cng/tree/dev/examples) directory.

pub mod cert;
pub mod config;
pub mod error;
pub mod key;
pub mod signer;
pub mod store;

pub use rustls;

pub type Result<T> = std::result::Result<T, error::CngError>;

#[macro_export]
macro_rules! utf16z {
    ($str: expr) => {
        $str.encode_utf16().chain([0]).collect::<Vec<_>>()
    };
}
