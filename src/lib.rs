#![doc(html_root_url = "https://rustls.github.io/rustls-cng/doc/rustls_cng")]
#![doc = include_str!("../README.md")]

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
