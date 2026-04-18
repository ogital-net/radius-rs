//! Async/await RADIUS server and client library.
//!
//! This crate provides a complete implementation of the RADIUS protocol
//! ([RFC 2865](https://tools.ietf.org/html/rfc2865)) for building authentication,
//! authorization, and accounting (AAA) services in Rust.
//!
//! # Structure
//!
//! - [`client`] — UDP RADIUS client
//! - [`server`] — async Tokio RADIUS server
//! - [`core`] — packet, AVP, and code primitives
//! - [`dict`] — generated attribute helpers for standard RFCs and vendor dictionaries
//!
//! # Example: sending an Access-Request
//!
//! ```no_run
//! # use std::error::Error;
//! # async fn run() -> Result<(), Box<dyn Error>> {
//! use std::net::SocketAddr;
//! use radius::client::Client;
//! use radius::core::code::Code;
//! use radius::core::packet::Packet;
//! use radius::dict::rfc2865;
//!
//! let addr: SocketAddr = "127.0.0.1:1812".parse()?;
//! let client = Client::new(None, None);
//!
//! let mut packet = Packet::new(Code::AccessRequest, b"secret");
//! rfc2865::add_user_name(&mut packet, "alice");
//! rfc2865::add_user_password(&mut packet, b"password")?;
//!
//! let response = client.send_packet(&addr, &packet).await?;
//! println!("Response: {}", response.code());
//! #     Ok(())
//! # }
//! ```

#[macro_use]
extern crate log;

pub mod client;
pub mod core;
pub mod dict;
pub mod server;

#[cfg(all(feature = "md5", feature = "openssl"))]
compile_error!("feature \"md5\" and feature \"openssl\" cannot be enabled at the same time");

#[cfg(all(feature = "aws-lc", feature = "md5"))]
compile_error!("feature \"aws-lc\" and feature \"md5\" cannot be enabled at the same time");

#[cfg(all(feature = "aws-lc", feature = "openssl"))]
compile_error!("feature \"aws-lc\" and feature \"openssl\" cannot be enabled at the same time");
