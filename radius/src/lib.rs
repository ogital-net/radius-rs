#[macro_use]
extern crate log;

pub mod client;
pub mod core;
pub mod server;

#[cfg(all(feature = "md5", feature = "openssl"))]
compile_error!("feature \"md5\" and feature \"openssl\" cannot be enabled at the same time");

#[cfg(all(feature = "aws-lc", feature = "md5"))]
compile_error!("feature \"aws-lc\" and feature \"md5\" cannot be enabled at the same time");

#[cfg(all(feature = "aws-lc", feature = "openssl"))]
compile_error!("feature \"aws-lc\" and feature \"openssl\" cannot be enabled at the same time");
