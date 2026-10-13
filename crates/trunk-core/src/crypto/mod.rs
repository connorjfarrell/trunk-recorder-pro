//! Decryption with keys the operator supplies. [`KeyStore`] holds them (in
//! memory only, never shown or logged); [`ekc`] reads them from a KFDtool
//! encrypted key container.

pub mod ekc;
mod keystore;
pub mod p25;

pub use keystore::{Key, KeyInfo, KeyStore};
