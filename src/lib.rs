#![doc(html_root_url = "https://rustls.github.io/rustls-cng/doc/rustls_cng")]
#![doc = include_str!("../README.md")]

pub mod cert;
pub mod error;
pub mod key;
pub mod signer;
pub mod store;

pub type Result<T> = std::result::Result<T, error::CngError>;
