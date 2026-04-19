# radius-rs [![Check](https://github.com/moznion/radius-rs/workflows/Check/badge.svg)](https://github.com/moznion/radius-rs/actions) [![crates.io](https://img.shields.io/crates/v/radius.svg)](https://crates.io/crates/radius)

An async/await native implementation of the RADIUS server and client for Rust. And this also can be used for parsing/constructing (i.e. decoding/encoding) purposes as a RADIUS library.

## Description

This RADIUS server and client implementation use [tokio](https://tokio.rs/) to support asynchronous operations natively. This implementation satisfies basic functions that are described in [RFC2865](https://tools.ietf.org/html/rfc2865).

## Usage

Simple example implementations are here:

- [server](./examples/server.rs)
- [client](./examples/client.rs)
- [EAP-MD5 server + client](./examples/eap_md5.rs)

Those examples implement a quite simple `Access-Request` processor. You can try those with the following commands.

```
$ RUST_LOG=debug cargo run --example server --package examples
$ RUST_LOG=debug cargo run --example client --package examples # in another shell
```

The EAP-MD5 example runs a self-contained server and built-in client in-process:

```
$ cargo run --example eap_md5 --package examples
```

## Supported Dictionaries

### RFC Dictionaries

- [RFC2865](https://tools.ietf.org/html/rfc2865)
- [RFC2866](https://tools.ietf.org/html/rfc2866)
- [RFC2867](https://tools.ietf.org/html/rfc2867)
- [RFC2868](https://tools.ietf.org/html/rfc2868)
- [RFC2869](https://tools.ietf.org/html/rfc2869)
- [RFC3162](https://tools.ietf.org/html/rfc3162)
- [RFC3576](https://tools.ietf.org/html/rfc3576)
- [RFC3580](https://tools.ietf.org/html/rfc3580)
- [RFC4072](https://tools.ietf.org/html/rfc4072)
- [RFC4372](https://tools.ietf.org/html/rfc4372)
- [RFC4603](https://tools.ietf.org/html/rfc4603)
- [RFC4675](https://tools.ietf.org/html/rfc4675)
- [RFC4818](https://tools.ietf.org/html/rfc4818)
- [RFC4849](https://tools.ietf.org/html/rfc4849)
- [RFC5090](https://tools.ietf.org/html/rfc5090)
- [RFC5176](https://tools.ietf.org/html/rfc5176)
- [RFC5580](https://tools.ietf.org/html/rfc5580)
- [RFC5607](https://tools.ietf.org/html/rfc5607)
- [RFC5904](https://tools.ietf.org/html/rfc5904)
- [RFC6519](https://tools.ietf.org/html/rfc6519)
- [RFC6572](https://tools.ietf.org/html/rfc6572)
- [RFC6677](https://tools.ietf.org/html/rfc6677)
- [RFC6911](https://tools.ietf.org/html/rfc6911)
- [RFC7055](https://tools.ietf.org/html/rfc7055)
- [RFC7155](https://tools.ietf.org/html/rfc7155)

### Vendor Dictionaries

- Ascend (`radius::dict::ascend`)
- Cisco (`radius::dict::cisco`)
- Juniper (`radius::dict::juniper`)
- Microsoft (`radius::dict::microsoft`)
- MikroTik (`radius::dict::mikrotik`)
- Ruckus (`radius::dict::ruckus`)
- TP-Link (`radius::dict::tplink`)
- WISPr (`radius::dict::wispr`)

## Cryptography backends

This library supports three mutually exclusive cryptography backends, controlled by Cargo features.
Exactly one must be active at a time.

| Feature | Description | Default |
|---------|-------------|--------|
| `aws-lc` | Uses [AWS-LC](https://github.com/aws/aws-lc) via `aws-lc-sys` for MD5 and random bytes | ✓ |
| `openssl` | Uses [OpenSSL](https://www.openssl.org/) via the `openssl` crate | |
| `rust-crypto` | Pure-Rust backend using RustCrypto crates (`md-5`, `md4`, `sha1`, `hmac`, `des`) and `rand` | |

To select a different backend, disable the default and enable the one you want:

```toml
[dependencies]
# OpenSSL backend
radius = { version = "__version__", default-features = false, features = ["openssl"] }

# Pure-Rust backend
radius = { version = "__version__", default-features = false, features = ["rust-crypto"] }
```

## Implementation guide for your RADIUS application

### Common

- `Packet` struct represents request packet and response one.
  - This struct has a list of AVPs.
  - You can get a specific AVP via a dictionary module (e.g. `radius::dict::rfc2865`).
    - e.g. `rfc2865::lookup_user_name(packet)`
      - This method returns `Some(Result<String, AVPError>)` if the packet contains `User-Name` attribute.
      - On the other hand, if the packet doesn't have that attribute, it returns `None`.
  - You can construct a packet with a dictionary module.
    - e.g. `rfc2865::add_user_name(&mut packet, "user")`
      - This method adds a `User-Name` AVP to the packet.
  - Please refer to the rustdoc for each dictionary module in detail.

### Vendor-Specific Attributes (VSAs)

Vendor dictionaries expose the same `add_*` / `lookup_*` / `lookup_all_*` / `delete_*` interface as RFC dictionaries, but encode values inside a type-26 Vendor-Specific AVP automatically.

```rust
use radius::core::code::Code;
use radius::core::packet::Packet;
use radius::dict::{cisco, rfc2865};

// Build an Access-Request with standard and Cisco-specific attributes.
let mut req = Packet::new(Code::AccessRequest, b"secret");
rfc2865::add_user_name(&mut req, "alice");

// String VSA — multiple values per attribute are supported.
cisco::add_cisco_av_pair(&mut req, "shell:priv-lvl=15");
cisco::add_cisco_av_pair(&mut req, "audit:event=login");
cisco::add_cisco_nas_port(&mut req, "GigabitEthernet0/1");

// Decode after a wire roundtrip.
let wire = req.encode().unwrap();
let decoded = Packet::decode(&wire, b"secret").unwrap();

let all_pairs = cisco::lookup_all_cisco_av_pair(&decoded).unwrap();
// => ["shell:priv-lvl=15", "audit:event=login"]

// Integer VSA.
let mut acct = Packet::new(Code::AccountingRequest, b"secret");
cisco::add_cisco_multilink_id(&mut acct, 7);
cisco::add_cisco_disconnect_cause(&mut acct, cisco::CISCO_DISCONNECT_CAUSE_SESSION_TIMEOUT);
```

For low-level access, `Packet::lookup_vsa(vendor_id, vendor_type)` and
`Packet::lookup_all_vsa` / `Packet::delete_vsa` are also available.

A runnable example is provided at [examples/cisco_vsa.rs](./examples/cisco_vsa.rs):

```
$ cargo run --example cisco_vsa --package examples
```

### EAP (Extensible Authentication Protocol)

The library includes first-class support for EAP over RADIUS ([RFC 3579](https://tools.ietf.org/html/rfc3579)) via `radius::core::eap`.

Key types:

| Type | Description |
|---|---|
| `EapPacket` | Parsed EAP packet with `encode()` / `decode()` |
| `EapCode` | `Request`, `Response`, `Success`, `Failure` |
| `EapType` | `Identity`, `Md5Challenge`, `Tls`, `Ttls`, `Peap`, … |

Key `Packet` helpers:

| Method | Description |
|---|---|
| `packet.add_eap_message(bytes)` | Append `EAP-Message` attribute(s), chunked to 253 bytes |
| `packet.lookup_eap_message()` | Reassemble all `EAP-Message` fragments |
| `packet.add_message_authenticator()` | Compute and attach `Message-Authenticator` (HMAC-MD5) |
| `Packet::verify_message_authenticator(bytes, req_auth, secret)` | Verify the MAC on raw wire bytes |

A complete EAP-MD5 server + client example is provided at [examples/eap_md5.rs](./examples/eap_md5.rs):

```
$ cargo run --example eap_md5 --package examples
```

### Cryptographic primitives (`radius::core::crypto`)

The backend-agnostic crypto helpers are exposed publicly so that application code can implement
EAP methods without pulling in additional crates:

| Function | Description |
|---|---|
| `crypto::md5(data)` | Raw MD5 digest — 16 bytes |
| `crypto::hmac_md5(key, data)` | HMAC-MD5 keyed MAC — 16 bytes |
| `crypto::fill_random(buf)` | Fill a `&mut [u8]` with secure random bytes |
| `crypto::random_bytes(n)` | Allocate `n` secure random bytes |

The active cryptography feature (`aws-lc`, `openssl`, or `rust-crypto`) is selected at compile time; see the [Cryptography backends](#cryptography-backends) section.

### Server

- Must implement `RequestHandler<T, E>` interface.
  - This interface method is the core function of the server application what you need.
- Please refer also to the example implementation: [server](./examples/server.rs)

### Client

- Please refer also to the example implementation: [client](./examples/client.rs)

## Roadmap

- Support the following RFC dictionaries:
  - rfc4679
  - rfc5447
  - rfc6929
  - rfc6930
  - rfc7268
  - rfc7499
  - rfc7930
  - rfc8045
  - rfc8559

## Development guide for this library

### How to generate code from dictionary

```shell
$ make gen
```

`code-generator` sub project has the responsibility to generate the Rust code according to
given RFC dictionary files. The dictionary files are in `dicts` directory.

The format of the dictionary files respect the [FreeRADIUS project's ones](https://github.com/FreeRADIUS/freeradius-server/tree/master/share/dictionary/radius).

## Note

The original implementation and design of this are inspired by [layeh/radius](https://github.com/layeh/radius).

## Author

moznion (<moznion@gmail.com>)
