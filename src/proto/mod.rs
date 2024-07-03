// #![doc = include_str!("../README.md")]
// #![doc(
//     html_logo_url = "https://raw.githubusercontent.com/cosmos/cosmos-rust/main/.images/cosmos.png"
// )]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![allow(
    rustdoc::bare_urls,
    rustdoc::broken_intra_doc_links,
    clippy::derive_partial_eq_without_eq
)]
#![forbid(unsafe_code)]
#![warn(trivial_casts, trivial_numeric_casts, unused_import_braces)]

pub use prost;
pub use prost_types::{Any, Timestamp};
// pub use tendermint_proto as tendermint;

/// The version (commit hash) of the Cosmos SDK used when generating this library.
pub const COSMOS_SDK_VERSION: &str = include_str!("side/SIDE_COMMIT");

/// Cosmos protobuf definitions.

pub mod btcbridge {
    pub mod v1beta1 {
        include!("side/side.btcbridge.rs");
    }
}
