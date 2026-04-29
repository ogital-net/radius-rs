//! EAP-MD5 example: a self-contained RADIUS server that authenticates one peer
//! using EAP-MD5, driven by a built-in test client.
//!
//! The exchange follows RFC 3579 (RADIUS and EAP) and RFC 3748 §5.4 (EAP-MD5):
//!
//! ```text
//! Client (EAP peer)              Server (EAP authenticator / RADIUS)
//! ──────────────────             ──────────────────────────────────────
//! Access-Request
//!   EAP-Response/Identity ──►
//!                           ◄── Access-Challenge
//!                                 EAP-Request/MD5-Challenge
//!                                 State
//! Access-Request
//!   EAP-Response/MD5-Challenge
//!   State                  ──►
//!                           ◄── Access-Accept  (or Access-Reject)
//!                                 EAP-Success  (or EAP-Failure)
//! ```
//!
//! Run with:
//! ```
//! cargo run --example eap_md5 --package examples
//! ```

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::net::UdpSocket;

use radius::client::Client;
use radius::core::code::Code;
use radius::core::crypto;
use radius::core::eap::{EapCode, EapPacket, EapType};
use radius::core::packet::Packet;
use radius::core::request::Request;
use radius::dict::rfc2865;
use radius::server::{RequestHandler, SecretProvider, SecretProviderError, Server};

// ── Shared secret and credentials ────────────────────────────────────────────

const SECRET: &[u8] = b"testing123";
const USERNAME: &str = "alice";
const PASSWORD: &str = "p@ssw0rd";

// ── Server-side EAP-MD5 handler ──────────────────────────────────────────────

/// In-flight session: maps a 16-byte State token to the challenge that was issued.
type Sessions = Arc<Mutex<HashMap<Vec<u8>, [u8; 16]>>>;

struct EapMd5Handler {
    sessions: Sessions,
}

impl RequestHandler<(), io::Error> for EapMd5Handler {
    async fn handle_radius_request(
        &self,
        conn: &UdpSocket,
        req: &Request,
    ) -> Result<(), io::Error> {
        let req_packet = req.packet();

        let Some(eap_bytes) = req_packet.lookup_eap_message() else {
            eprintln!("[server] packet has no EAP-Message - ignoring");
            return Ok(());
        };

        let eap_pkt = match EapPacket::decode(&eap_bytes) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[server] malformed EAP packet: {e}");
                return Ok(());
            }
        };

        match (eap_pkt.code, eap_pkt.eap_type()) {
            // ── Round 1: peer identifies itself ──────────────────────────────
            (EapCode::Response, Some(EapType::Identity)) => {
                // Use a single 32-byte random buffer: first 16 = challenge,
                // last 16 = State token (avoids two RNG calls).
                let mut buf = [0u8; 32];
                crypto::fill_random(&mut buf);
                let mut challenge = [0u8; 16];
                let mut state_token = [0u8; 16];
                challenge.copy_from_slice(&buf[..16]);
                state_token.copy_from_slice(&buf[16..]);

                self.sessions
                    .lock()
                    .unwrap()
                    .insert(state_token.to_vec(), challenge);

                // EAP-Request/MD5-Challenge type-data: [ value_size(1) | challenge(16) ]
                let mut type_data = Vec::with_capacity(17);
                type_data.push(16u8);
                type_data.extend_from_slice(&challenge);

                let challenge_pkt = EapPacket::new_request_response(
                    EapCode::Request,
                    eap_pkt.identifier.wrapping_add(1),
                    EapType::Md5Challenge,
                    &type_data,
                );

                let mut resp = req_packet.make_response_packet(Code::AccessChallenge);
                resp.add_eap_message(&challenge_pkt.encode());
                rfc2865::add_state(&mut resp, &state_token);
                resp.add_message_authenticator()
                    .map_err(|e| io::Error::other(e.to_string()))?;

                eprintln!("[server] sent Access-Challenge (EAP-Request/MD5-Challenge)");
                conn.send_to(&resp.encode().unwrap(), req.remote_addr())
                    .await?;
            }

            // ── Round 2: verify the MD5 response ─────────────────────────────
            (EapCode::Response, Some(EapType::Md5Challenge)) => {
                let Some(state_token) = rfc2865::lookup_state(req_packet) else {
                    eprintln!("[server] no State attribute \u{2013} dropping");
                    return Ok(());
                };

                let Some(challenge) = self.sessions.lock().unwrap().remove(state_token.as_ref())
                else {
                    eprintln!("[server] unknown State token \u{2013} dropping");
                    return Ok(());
                };

                // type-data: [ value_size(1) | md5_value(value_size) | identity... ]
                let type_data = eap_pkt.type_data();
                if type_data.is_empty() {
                    return Ok(());
                }
                let value_size = type_data[0] as usize;
                if type_data.len() < 1 + value_size {
                    return Ok(());
                }
                let md5_response = &type_data[1..=value_size];

                // RFC 3748 §5.4: expected = MD5(identifier || password || challenge)
                let mut preimage = Vec::with_capacity(1 + PASSWORD.len() + challenge.len());
                preimage.push(eap_pkt.identifier);
                preimage.extend_from_slice(PASSWORD.as_bytes());
                preimage.extend_from_slice(&challenge);
                let expected = crypto::md5(&preimage);

                let (radius_code, eap_code) = if md5_response == expected {
                    eprintln!("[server] EAP-MD5 verified – sending Access-Accept");
                    (Code::AccessAccept, EapCode::Success)
                } else {
                    eprintln!("[server] EAP-MD5 mismatch – sending Access-Reject");
                    (Code::AccessReject, EapCode::Failure)
                };

                let result_eap = EapPacket::new_success_failure(eap_code, eap_pkt.identifier);
                let mut resp = req_packet.make_response_packet(radius_code);
                resp.add_eap_message(&result_eap.encode());
                resp.add_message_authenticator()
                    .map_err(|e| io::Error::other(e.to_string()))?;

                conn.send_to(&resp.encode().unwrap(), req.remote_addr())
                    .await?;
            }

            other => {
                eprintln!("[server] unhandled EAP state: {other:?}");
            }
        }

        Ok(())
    }
}

struct MySecretProvider;

impl SecretProvider for MySecretProvider {
    fn fetch_secret(&self, _remote_addr: SocketAddr) -> Result<Vec<u8>, SecretProviderError> {
        Ok(SECRET.to_vec())
    }
}

// ── Client-side EAP-MD5 driver ───────────────────────────────────────────────

/// Drive the EAP-MD5 exchange as a RADIUS client.
///
/// Returns `true` if authentication succeeded (Access-Accept received).
async fn run_eap_md5_client(server_addr: SocketAddr) -> bool {
    let client = Client::new(
        Some(std::time::Duration::from_secs(5)),
        Some(std::time::Duration::from_secs(5)),
    );

    // ── Round 1: send EAP-Response/Identity ──────────────────────────────
    let identity_eap = EapPacket::new_request_response(
        EapCode::Response,
        1, // initial identifier chosen by the peer
        EapType::Identity,
        USERNAME.as_bytes(),
    );

    let mut req1 = Packet::new(Code::AccessRequest, SECRET);
    rfc2865::add_user_name(&mut req1, USERNAME);
    req1.add_eap_message(&identity_eap.encode());
    req1.add_message_authenticator()
        .expect("failed to add Message-Authenticator");

    eprintln!("[client] sent EAP-Response/Identity");
    let challenge_pkt = client
        .send_packet(&server_addr, &req1)
        .await
        .expect("round-1 send failed");

    assert_eq!(
        challenge_pkt.code(),
        Code::AccessChallenge,
        "expected Access-Challenge, got {:?}",
        challenge_pkt.code()
    );

    // Extract EAP-Request/MD5-Challenge and State.
    let eap_bytes = challenge_pkt
        .lookup_eap_message()
        .expect("no EAP-Message in Access-Challenge");
    let server_eap = EapPacket::decode(&eap_bytes).expect("malformed EAP in Access-Challenge");

    assert_eq!(
        server_eap.eap_type(),
        Some(EapType::Md5Challenge),
        "expected MD5-Challenge, got {:?}",
        server_eap.eap_type()
    );

    // type-data: [ value_size(1) | challenge(value_size) ]
    let type_data = server_eap.type_data();
    let value_size = type_data[0] as usize;
    let challenge = &type_data[1..=value_size];

    let state = rfc2865::lookup_state(&challenge_pkt).expect("no State in Access-Challenge");

    eprintln!("[client] received Access-Challenge, computing MD5 response");

    // ── Round 2: compute and send EAP-Response/MD5-Challenge ─────────────
    // RFC 3748 §5.4: response = MD5(identifier || password || challenge)
    let mut preimage = Vec::with_capacity(1 + PASSWORD.len() + challenge.len());
    preimage.push(server_eap.identifier);
    preimage.extend_from_slice(PASSWORD.as_bytes());
    preimage.extend_from_slice(challenge);
    let md5_result = crypto::md5(&preimage);

    // type-data: [ value_size(1) | md5_result(16) | identity... ]
    let mut response_type_data = Vec::with_capacity(1 + 16 + USERNAME.len());
    response_type_data.push(16u8);
    response_type_data.extend_from_slice(&md5_result);
    response_type_data.extend_from_slice(USERNAME.as_bytes());

    let response_eap = EapPacket::new_request_response(
        EapCode::Response,
        server_eap.identifier,
        EapType::Md5Challenge,
        &response_type_data,
    );

    let mut req2 = Packet::new(Code::AccessRequest, SECRET);
    rfc2865::add_user_name(&mut req2, USERNAME);
    req2.add_eap_message(&response_eap.encode());
    rfc2865::add_state(&mut req2, &state);
    req2.add_message_authenticator()
        .expect("failed to add Message-Authenticator");

    eprintln!("[client] sent EAP-Response/MD5-Challenge");
    let result_pkt = client
        .send_packet(&server_addr, &req2)
        .await
        .expect("round-2 send failed");

    eprintln!("[client] received {:?}", result_pkt.code());
    result_pkt.code() == Code::AccessAccept
}

// ── main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let mut server = Server::listen(
        "127.0.0.1",
        0,
        EapMd5Handler {
            sessions: sessions.clone(),
        },
        MySecretProvider,
    )
    .await
    .expect("failed to bind RADIUS server");

    let server_addr = server.listen_address().unwrap();
    eprintln!("[server] listening on {server_addr}");

    let server_handle = tokio::spawn(async move {
        server.run(shutdown_rx).await.unwrap();
    });

    // Run the client exchange.
    let accepted = run_eap_md5_client(server_addr).await;

    // Shut down the server.
    let _: Result<_, _> = shutdown_tx.send(());
    server_handle.await.unwrap();

    if accepted {
        println!("EAP-MD5 authentication succeeded — Access-Accept received.");
    } else {
        eprintln!("EAP-MD5 authentication failed — Access-Reject received.");
        std::process::exit(1);
    }
}
