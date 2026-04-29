#![allow(unused)]

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::sleep;

use radius::core::code::Code;
use radius::core::crypto;
use radius::core::eap::{EapCode, EapPacket, EapType};
use radius::core::request::Request;
use radius::dict::{cisco, microsoft, rfc2865};
use radius::server::{RequestHandler, SecretProvider, SecretProviderError};

struct MyRequestHandler {}

impl RequestHandler<(), io::Error> for MyRequestHandler {
    async fn handle_radius_request(
        &self,
        conn: &UdpSocket,
        req: &Request,
    ) -> Result<(), io::Error> {
        let req_packet = req.packet();
        let maybe_user_name_attr = rfc2865::lookup_user_name(req_packet);
        let maybe_user_password_attr = rfc2865::lookup_user_password(req_packet);

        let user_name = maybe_user_name_attr.unwrap().unwrap();
        let user_password =
            String::from_utf8(maybe_user_password_attr.unwrap().unwrap().clone()).unwrap();
        let code = if user_name == "admin" && user_password == "p@ssw0rd" {
            Code::AccessAccept
        } else {
            Code::AccessReject
        };

        let mut resp_packet = req_packet.make_response(code);
        rfc2865::add_user_name(&mut resp_packet, user_name.as_str());
        conn.send_to(&resp_packet.encode().unwrap(), req.remote_addr())
            .await?;
        Ok(())
    }
}

struct LongTimeTakingHandler {}

impl RequestHandler<(), io::Error> for LongTimeTakingHandler {
    async fn handle_radius_request(
        &self,
        conn: &UdpSocket,
        req: &Request,
    ) -> Result<(), io::Error> {
        sleep(Duration::from_secs(30)).await;
        let req_packet = req.packet();
        let resp_packet = req_packet.make_response(Code::AccessReject);
        conn.send_to(&resp_packet.encode().unwrap(), req.remote_addr())
            .await?;
        Ok(())
    }
}

struct MySecretProvider {}

impl SecretProvider for MySecretProvider {
    fn fetch_secret(&self, _remote_addr: SocketAddr) -> Result<Vec<u8>, SecretProviderError> {
        Ok(b"secret".to_vec())
    }
}

/// Data captured by [`VsaCaptureHandler`] from an incoming packet.
#[derive(Debug)]
struct CapturedVsaData {
    user_name: String,
    av_pair: String,
    nas_port: String,
}

/// A request handler that captures Cisco VSAs and stores them in shared state,
/// then responds with Access-Accept.
struct VsaCaptureHandler {
    captured: Arc<Mutex<Option<CapturedVsaData>>>,
}

impl RequestHandler<(), io::Error> for VsaCaptureHandler {
    async fn handle_radius_request(
        &self,
        conn: &UdpSocket,
        req: &Request,
    ) -> Result<(), io::Error> {
        let req_packet = req.packet();

        let user_name = rfc2865::lookup_user_name(req_packet)
            .and_then(Result::ok)
            .unwrap_or_default();
        let av_pair = cisco::lookup_cisco_av_pair(req_packet)
            .and_then(Result::ok)
            .unwrap_or_default();
        let nas_port = cisco::lookup_cisco_nas_port(req_packet)
            .and_then(Result::ok)
            .unwrap_or_default();

        *self.captured.lock().unwrap() = Some(CapturedVsaData {
            user_name,
            av_pair,
            nas_port,
        });

        let resp_packet = req_packet.make_response(Code::AccessAccept);
        conn.send_to(&resp_packet.encode().unwrap(), req.remote_addr())
            .await?;
        Ok(())
    }
}

/// A request handler that implements EAP-MD5 authentication for interop testing.
///
/// The exchange is two rounds:
/// 1. EAP-Response/Identity → Access-Challenge + EAP-Request/MD5-Challenge + State
/// 2. EAP-Response/MD5-Challenge + State → Access-Accept/Reject + EAP-Success/Failure
struct EapMd5Handler {
    /// The password checked against the incoming EAP-MD5 response.
    password: &'static str,
    /// Per-session state: State token → (challenge bytes).
    sessions: Arc<Mutex<HashMap<Vec<u8>, [u8; 16]>>>,
}

impl RequestHandler<(), io::Error> for EapMd5Handler {
    async fn handle_radius_request(
        &self,
        conn: &UdpSocket,
        req: &Request,
    ) -> Result<(), io::Error> {
        let req_packet = req.packet();

        let Some(eap_bytes) = req_packet.lookup_eap_message() else {
            return Ok(());
        };

        let Ok(eap_pkt) = EapPacket::decode(&eap_bytes) else {
            return Ok(());
        };

        match (eap_pkt.code, eap_pkt.eap_type()) {
            (EapCode::Response, Some(EapType::Identity)) => {
                // Generate challenge (16 bytes) and State token (16 bytes) from a
                // single 32-byte buffer to minimise RNG calls.
                let mut buf = [0u8; 32];
                crypto::fill_random(&mut buf);
                let mut challenge = [0u8; 16];
                let mut state = [0u8; 16];
                challenge.copy_from_slice(&buf[..16]);
                state.copy_from_slice(&buf[16..]);

                // Store challenge keyed by the State token.
                self.sessions
                    .lock()
                    .unwrap()
                    .insert(state.to_vec(), challenge);

                // EAP-Request/MD5-Challenge type-data: [value_size(1), challenge(16)]
                let mut type_data = Vec::with_capacity(17);
                type_data.push(16u8);
                type_data.extend_from_slice(&challenge);

                let challenge_eap = EapPacket::new_request_response(
                    EapCode::Request,
                    eap_pkt.identifier.wrapping_add(1),
                    EapType::Md5Challenge,
                    &type_data,
                );

                let mut resp = req_packet.make_response(Code::AccessChallenge);
                resp.add_eap_message(&challenge_eap.encode());
                rfc2865::add_state(&mut resp, &state);
                resp.add_message_authenticator()
                    .map_err(|e| io::Error::other(e.to_string()))?;
                conn.send_to(&resp.encode().unwrap(), req.remote_addr())
                    .await?;
            }

            (EapCode::Response, Some(EapType::Md5Challenge)) => {
                // Retrieve and remove the stored challenge using the State attribute.
                let Some(state) = rfc2865::lookup_state(req_packet) else {
                    return Ok(());
                };
                let Some(challenge) = self.sessions.lock().unwrap().remove(state.as_ref()) else {
                    return Ok(());
                };

                // Parse type-data: [value_size(1), md5_value(value_size), name...]
                let type_data = eap_pkt.type_data();
                if type_data.is_empty() {
                    return Ok(());
                }
                let value_size = type_data[0] as usize;
                if type_data.len() < 1 + value_size {
                    return Ok(());
                }
                let md5_response = &type_data[1..=value_size];

                // EAP-MD5 verification: MD5(identifier || password || challenge)
                // RFC 3748 §5.4: the identifier is the one echoed in the Response.
                let mut to_hash = Vec::with_capacity(1 + self.password.len() + challenge.len());
                to_hash.push(eap_pkt.identifier);
                to_hash.extend_from_slice(self.password.as_bytes());
                to_hash.extend_from_slice(&challenge);
                let expected = crypto::md5(&to_hash);

                let (code, eap_code) = if md5_response == expected {
                    (Code::AccessAccept, EapCode::Success)
                } else {
                    (Code::AccessReject, EapCode::Failure)
                };

                let result_eap = EapPacket::new_success_failure(eap_code, eap_pkt.identifier);
                let mut resp = req_packet.make_response(code);
                resp.add_eap_message(&result_eap.encode());
                resp.add_message_authenticator()
                    .map_err(|e| io::Error::other(e.to_string()))?;
                conn.send_to(&resp.encode().unwrap(), req.remote_addr())
                    .await?;
            }

            _ => {}
        }

        Ok(())
    }
}

// ── EAP-MSCHAPv2 handler ──────────────────────────────────────────────────────

/// Per-session state tracked across the three EAP-MSCHAPv2 RADIUS round-trips.
enum MsChapV2State {
    /// Server has issued a Challenge; waiting for the client's `MSCHAPv2` Response.
    Challenged { ms_id: u8, auth_challenge: [u8; 16] },
    /// Server has issued a Success message; waiting for the client's ACK.
    AwaitingAck,
}

/// A request handler that implements EAP-MSCHAPv2 authentication.
///
/// Exchange (three RADIUS round-trips per RFC 2759 / MS-EAP-CHAPv2):
/// 1. EAP-Response/Identity → Access-Challenge + EAP-Request/MSCHAPv2-Challenge + State
/// 2. EAP-Response/MSCHAPv2-Response + State → Access-Challenge + EAP-Request/MSCHAPv2-Success
///    (or Access-Reject + MSCHAPv2-Failure if credentials are wrong)
/// 3. EAP-Response/MSCHAPv2-Success + State → Access-Accept + EAP-Success
struct EapMsChapV2Handler {
    password: &'static str,
    sessions: Arc<Mutex<HashMap<Vec<u8>, MsChapV2State>>>,
}

impl RequestHandler<(), io::Error> for EapMsChapV2Handler {
    #[allow(clippy::too_many_lines)]
    async fn handle_radius_request(
        &self,
        conn: &UdpSocket,
        req: &Request,
    ) -> Result<(), io::Error> {
        let req_packet = req.packet();

        let Some(eap_bytes) = req_packet.lookup_eap_message() else {
            return Ok(());
        };
        let Ok(eap_pkt) = EapPacket::decode(&eap_bytes) else {
            return Ok(());
        };

        match (eap_pkt.code, eap_pkt.eap_type()) {
            // Round 1: Identity → send MSCHAPv2 Challenge.
            (EapCode::Response, Some(EapType::Identity)) => {
                // Allocate 32 bytes in one RNG call: 16 for the authenticator
                // challenge, 16 for the State token.
                let mut buf = [0u8; 32];
                crypto::fill_random(&mut buf);
                let mut auth_challenge = [0u8; 16];
                let mut state = [0u8; 16];
                auth_challenge.copy_from_slice(&buf[..16]);
                state.copy_from_slice(&buf[16..]);

                let ms_id = eap_pkt.identifier.wrapping_add(1);

                self.sessions.lock().unwrap().insert(
                    state.to_vec(),
                    MsChapV2State::Challenged {
                        ms_id,
                        auth_challenge,
                    },
                );

                // MSCHAPv2 Challenge type-data (inside EAP type-data, after type byte 26):
                //   OpCode(1) | MS-CHAPv2-ID(1) | MS-Length(2) | Value-Size(1) |
                //   Value(16) | Name(n)
                let server_name = b"radius-rs";
                let ms_length =
                    (5u16 + 16 + u16::try_from(server_name.len()).unwrap()).to_be_bytes();
                let mut td = Vec::with_capacity(5 + 16 + server_name.len());
                td.push(1u8); // OpCode = Challenge
                td.push(ms_id);
                td.extend_from_slice(&ms_length);
                td.push(16u8); // Value-Size
                td.extend_from_slice(&auth_challenge);
                td.extend_from_slice(server_name);

                let challenge_eap = EapPacket::new_request_response(
                    EapCode::Request,
                    ms_id,
                    EapType::MsChapV2,
                    &td,
                );
                let mut resp = req_packet.make_response(Code::AccessChallenge);
                resp.add_eap_message(&challenge_eap.encode());
                rfc2865::add_state(&mut resp, &state);
                resp.add_message_authenticator()
                    .map_err(|e| io::Error::other(e.to_string()))?;
                conn.send_to(&resp.encode().unwrap(), req.remote_addr())
                    .await?;
            }

            // Rounds 2 & 3: MSCHAPv2 sub-protocol responses.
            (EapCode::Response, Some(EapType::MsChapV2)) => {
                let type_data = eap_pkt.type_data();
                if type_data.is_empty() {
                    return Ok(());
                }
                let opcode = type_data[0];

                let Some(state) = rfc2865::lookup_state(req_packet) else {
                    return Ok(());
                };

                match opcode {
                    // Round 2: client Response — validate NT-Response.
                    2 => {
                        // type_data layout (after EAP type byte 26):
                        //   OpCode(1) | MS-CHAPv2-ID(1) | MS-Length(2) |
                        //   Value-Size(1) | Value(49) | Name(n)
                        // Value(49) = PeerChallenge(16) | Reserved(8) | NTResponse(24) | Flags(1)
                        if type_data.len() < 5 + 49 {
                            return Ok(());
                        }
                        let value = &type_data[5..5 + 49];
                        let peer_challenge: [u8; 16] = value[..16].try_into().unwrap();
                        let nt_response: [u8; 24] = value[24..48].try_into().unwrap();
                        let name = &type_data[5 + 49..];

                        let Some(MsChapV2State::Challenged {
                            ms_id,
                            auth_challenge,
                        }) = self.sessions.lock().unwrap().remove(state.as_ref())
                        else {
                            return Ok(());
                        };

                        let valid = crypto::verify_mschapv2_nt_response(
                            &auth_challenge,
                            &peer_challenge,
                            name,
                            self.password,
                            &nt_response,
                        );

                        if valid {
                            let auth_resp = crypto::generate_mschapv2_authenticator_response(
                                &auth_challenge,
                                &peer_challenge,
                                name,
                                self.password,
                                &nt_response,
                            );

                            // MSCHAPv2 Success type-data:
                            //   OpCode(1) | MS-CHAPv2-ID(1) | MS-Length(2) | Message(42)
                            let ms_length =
                                (4u16 + u16::try_from(auth_resp.len()).unwrap()).to_be_bytes();
                            let mut td = Vec::with_capacity(4 + auth_resp.len());
                            td.push(3u8); // OpCode = Success
                            td.push(ms_id);
                            td.extend_from_slice(&ms_length);
                            td.extend_from_slice(&auth_resp);

                            let mut new_state = [0u8; 16];
                            crypto::fill_random(&mut new_state);
                            self.sessions
                                .lock()
                                .unwrap()
                                .insert(new_state.to_vec(), MsChapV2State::AwaitingAck);

                            let success_eap = EapPacket::new_request_response(
                                EapCode::Request,
                                eap_pkt.identifier.wrapping_add(1),
                                EapType::MsChapV2,
                                &td,
                            );
                            let mut resp = req_packet.make_response(Code::AccessChallenge);
                            resp.add_eap_message(&success_eap.encode());
                            rfc2865::add_state(&mut resp, &new_state);
                            resp.add_message_authenticator()
                                .map_err(|e| io::Error::other(e.to_string()))?;
                            conn.send_to(&resp.encode().unwrap(), req.remote_addr())
                                .await?;
                        } else {
                            // MSCHAPv2 Failure type-data: OpCode(1) | MS-CHAPv2-ID(1) | MS-Length(2)
                            let mut td = Vec::with_capacity(4);
                            td.push(4u8); // OpCode = Failure
                            td.push(ms_id);
                            td.extend_from_slice(&4u16.to_be_bytes());

                            let failure_eap = EapPacket::new_request_response(
                                EapCode::Request,
                                eap_pkt.identifier.wrapping_add(1),
                                EapType::MsChapV2,
                                &td,
                            );
                            let mut resp = req_packet.make_response(Code::AccessReject);
                            resp.add_eap_message(&failure_eap.encode());
                            resp.add_message_authenticator()
                                .map_err(|e| io::Error::other(e.to_string()))?;
                            conn.send_to(&resp.encode().unwrap(), req.remote_addr())
                                .await?;
                        }
                    }

                    // Round 3: client Success ACK → send Access-Accept + EAP-Success.
                    3 => {
                        match self.sessions.lock().unwrap().remove(state.as_ref()) {
                            Some(MsChapV2State::AwaitingAck) => {}
                            _ => return Ok(()),
                        }
                        let success_eap =
                            EapPacket::new_success_failure(EapCode::Success, eap_pkt.identifier);
                        let mut resp = req_packet.make_response(Code::AccessAccept);
                        resp.add_eap_message(&success_eap.encode());
                        resp.add_message_authenticator()
                            .map_err(|e| io::Error::other(e.to_string()))?;
                        conn.send_to(&resp.encode().unwrap(), req.remote_addr())
                            .await?;
                    }

                    _ => {}
                }
            }

            _ => {}
        }

        Ok(())
    }
}

/// A request handler that authenticates MS-CHAPv1 (RFC 2433) requests.
///
/// Extracts `MS-CHAP-Challenge` (8 bytes) and `MS-CHAP-Response` (50 bytes) from
/// the Access-Request, verifies the NT-Response field against the configured
/// password, and replies with Access-Accept or Access-Reject accordingly.
struct MsChapV1Handler {
    /// The expected cleartext password verified for every request.
    password: &'static str,
}

impl RequestHandler<(), io::Error> for MsChapV1Handler {
    async fn handle_radius_request(
        &self,
        conn: &UdpSocket,
        req: &Request,
    ) -> Result<(), io::Error> {
        let req_packet = req.packet();

        let challenge_bytes = microsoft::lookup_ms_chap_challenge(req_packet);
        let response_bytes = microsoft::lookup_ms_chap_response(req_packet);

        let code = match (challenge_bytes, response_bytes) {
            (Some(ch), Some(resp)) if ch.len() == 8 && resp.len() == 50 => {
                // MS-CHAP-Response layout (RFC 2433 §5.2):
                //   Ident(1) | Flags(1) | LM-Response(24) | NT-Response(24)
                let challenge: [u8; 8] = ch[..8].try_into().unwrap();
                let nt_response: [u8; 24] = resp[26..50].try_into().unwrap();
                if crypto::verify_mschap_nt_response(&challenge, self.password, &nt_response) {
                    Code::AccessAccept
                } else {
                    Code::AccessReject
                }
            }
            _ => Code::AccessReject,
        };

        let resp_packet = req_packet.make_response(code);
        conn.send_to(&resp_packet.encode().unwrap(), req.remote_addr())
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tokio::sync::oneshot;

    use radius::client::{Client, ClientError};
    use radius::core::code::Code;
    use radius::core::packet::Packet;
    use radius::dict::rfc2865;

    use crate::test::{
        CapturedVsaData, EapMd5Handler, EapMsChapV2Handler, LongTimeTakingHandler, MsChapV1Handler,
        MyRequestHandler, MySecretProvider, VsaCaptureHandler,
    };
    use radius::server::Server;

    #[tokio::test]
    async fn test_runner() {
        test_access_request().await;
        test_socket_timeout().await;
    }

    async fn test_access_request() {
        let (sender, receiver) = oneshot::channel::<()>();

        let mut server = Server::listen("127.0.0.1", 0, MyRequestHandler {}, MySecretProvider {})
            .await
            .unwrap();

        let port = server.listen_address().unwrap().port();

        let server_proc = tokio::spawn(async move {
            server.run(receiver).await.unwrap();
        });

        let remote_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let client = Client::new(None, None);

        let mut req_packet = Packet::new(Code::AccessRequest, b"secret".as_ref());
        rfc2865::add_user_name(&mut req_packet, "admin");
        rfc2865::add_user_password(&mut req_packet, b"p@ssw0rd").unwrap();
        let res = client.send_packet(&remote_addr, &req_packet).await.unwrap();
        let maybe_user_name = rfc2865::lookup_user_name(&res);
        let maybe_user_pass = rfc2865::lookup_user_password(&res);
        assert_eq!(res.code(), Code::AccessAccept);
        assert!(maybe_user_name.is_some());
        assert_eq!(maybe_user_name.unwrap().unwrap(), "admin");
        assert!(maybe_user_pass.is_none());

        let mut req_packet = Packet::new(Code::AccessRequest, b"secret".as_ref());
        rfc2865::add_user_name(&mut req_packet, "admin");
        rfc2865::add_user_password(&mut req_packet, b"INVALID-PASS").unwrap();
        let res = client.send_packet(&remote_addr, &req_packet).await.unwrap();
        assert_eq!(res.code(), Code::AccessReject);

        sender.send(()).unwrap();
        server_proc.await.unwrap();
    }

    async fn test_socket_timeout() {
        let (sender, receiver) = oneshot::channel::<()>();

        let mut server = Server::listen(
            "127.0.0.1",
            0,
            LongTimeTakingHandler {},
            MySecretProvider {},
        )
        .await
        .unwrap();

        let port = server.listen_address().unwrap().port();

        let server_proc = tokio::spawn(async move {
            server.run(receiver).await.unwrap();
        });

        let remote_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let client = Client::new(None, Some(Duration::from_secs(0)));

        let mut req_packet = Packet::new(Code::AccessRequest, b"secret".as_ref());
        rfc2865::add_user_name(&mut req_packet, "admin");
        rfc2865::add_user_password(&mut req_packet, b"p@ssw0rd").unwrap();
        let res = client.send_packet(&remote_addr, &req_packet).await;

        let err = res.unwrap_err();
        match err {
            ClientError::SocketTimeoutError() => {}
            _ => panic!("unexpected error: {err}"),
        }

        sender.send(()).unwrap();
        server_proc.await.unwrap();
    }

    /// Sends a RADIUS Access-Request carrying Cisco VSAs via `radclient` and
    /// verifies that our server decodes them correctly.  The test is silently
    /// skipped when `radclient` is not present on `PATH`.
    #[tokio::test]
    async fn test_radclient_vsa_interop() {
        // Skip gracefully when radclient is not installed.
        if std::process::Command::new("radclient")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("radclient not found on PATH - skipping radclient VSA interop test");
            return;
        }

        let captured: Arc<Mutex<Option<CapturedVsaData>>> = Arc::new(Mutex::new(None));
        let captured_for_handler = captured.clone();

        let (sender, receiver) = oneshot::channel::<()>();

        // Bind to port 0 so the OS assigns an ephemeral port (avoids conflicts).
        let mut server = Server::listen(
            "127.0.0.1",
            0,
            VsaCaptureHandler {
                captured: captured_for_handler,
            },
            MySecretProvider {},
        )
        .await
        .unwrap();

        let port = server.listen_address().unwrap().port();

        let server_proc = tokio::spawn(async move {
            server.run(receiver).await.unwrap();
        });

        // Invoke radclient: one retry, 3-second timeout, auth command, shared secret "secret".
        // Attributes are written to stdin; radclient reads from "-".
        let mut child = tokio::process::Command::new("radclient")
            .args([
                "-r",
                "1",
                "-t",
                "3",
                "-f",
                "-",
                &format!("127.0.0.1:{port}"),
                "auth",
                "secret",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("failed to spawn radclient");

        let mut stdin = child.stdin.take().expect("failed to open radclient stdin");
        tokio::io::AsyncWriteExt::write_all(
            &mut stdin,
            b"User-Name = \"alice\"\nCisco-AVPair = \"shell:priv-lvl=15\"\nCisco-NAS-Port = \"GigabitEthernet0/1\"\n",
        )
        .await
        .expect("failed to write to radclient stdin");
        drop(stdin); // close stdin so radclient sees EOF

        let output = child
            .wait_with_output()
            .await
            .expect("failed to wait on radclient");

        // Allow the server handler a moment to finish before we shut it down.
        tokio::time::sleep(Duration::from_millis(100)).await;

        sender.send(()).unwrap();
        server_proc.await.unwrap();

        assert!(
            output.status.success(),
            "radclient exited with non-zero status {}; stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
        );

        let data = captured
            .lock()
            .unwrap()
            .take()
            .expect("server handler did not capture any data – packet was never received");

        assert_eq!(data.user_name, "alice");
        assert_eq!(data.av_pair, "shell:priv-lvl=15");
        assert_eq!(data.nas_port, "GigabitEthernet0/1");
    }

    /// Runs a full EAP-MD5 authentication exchange via `eapol_test` against our
    /// in-process RADIUS server.  The test is silently skipped when `eapol_test`
    /// is not present on `PATH`.
    #[tokio::test]
    async fn test_eapol_test_eap_md5_interop() {
        // Skip gracefully when eapol_test is not installed.
        if std::process::Command::new("eapol_test")
            .arg("-v")
            .output()
            .is_err()
        {
            eprintln!("eapol_test not found on PATH - skipping EAP-MD5 interop test");
            return;
        }

        let sessions = Arc::new(Mutex::new(HashMap::new()));

        let (sender, receiver) = oneshot::channel::<()>();

        let mut server = Server::listen(
            "127.0.0.1",
            0,
            EapMd5Handler {
                password: "p@ssw0rd",
                sessions: sessions.clone(),
            },
            MySecretProvider {},
        )
        .await
        .unwrap();

        let port = server.listen_address().unwrap().port();

        let server_proc = tokio::spawn(async move {
            server.run(receiver).await.unwrap();
        });

        // Write a temporary eapol_test configuration file for EAP-MD5.
        let config_content = concat!(
            "network={\n",
            "\tkey_mgmt=IEEE8021X\n",
            "\teap=MD5\n",
            "\tidentity=\"alice\"\n",
            "\tpassword=\"p@ssw0rd\"\n",
            "\teapol_flags=0\n",
            "}\n",
        );
        let config_path = format!("/tmp/eapol_test_{port}.conf");
        std::fs::write(&config_path, config_content)
            .expect("failed to write eapol_test config file");

        // Invoke eapol_test:
        //   -c  config file
        //   -a  RADIUS server address
        //   -p  RADIUS server port
        //   -s  shared secret
        //   -n  no MPPE keys expected (EAP-MD5 does not generate keying material)
        //   -t  timeout in seconds
        let output = tokio::process::Command::new("eapol_test")
            .args([
                "-c",
                &config_path,
                "-a",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-s",
                "secret",
                "-n",
                "-t",
                "5",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .await
            .expect("failed to run eapol_test");

        let _ = std::fs::remove_file(&config_path);

        // Allow the server handler a moment to finish before shutdown.
        tokio::time::sleep(Duration::from_millis(100)).await;

        sender.send(()).unwrap();
        server_proc.await.unwrap();

        assert!(
            output.status.success(),
            "eapol_test exited with non-zero status {};\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    /// Runs a full EAP-MSCHAPv2 authentication exchange via `eapol_test` against
    /// our in-process RADIUS server.  Test vectors (identity/password) are taken
    /// from the `FreeRADIUS` eap-mschapv2.conf test fixture.  The test is silently
    /// skipped when `eapol_test` is not present on `PATH`.
    #[tokio::test]
    async fn test_eapol_test_eap_mschapv2_interop() {
        // Skip gracefully when eapol_test is not installed.
        if std::process::Command::new("eapol_test")
            .arg("-v")
            .output()
            .is_err()
        {
            eprintln!("eapol_test not found on PATH - skipping EAP-MSCHAPv2 interop test");
            return;
        }

        let sessions = Arc::new(Mutex::new(HashMap::new()));

        let (sender, receiver) = oneshot::channel::<()>();

        let mut server = Server::listen(
            "127.0.0.1",
            0,
            EapMsChapV2Handler {
                password: "bob",
                sessions: sessions.clone(),
            },
            MySecretProvider {},
        )
        .await
        .unwrap();

        let port = server.listen_address().unwrap().port();

        let server_proc = tokio::spawn(async move {
            server.run(receiver).await.unwrap();
        });

        // Test vectors from the FreeRADIUS eap-mschapv2.conf fixture:
        //   identity = "bob", password = "bob", shared secret = "testing123"
        // We use our own shared secret ("secret") via MySecretProvider.
        let config_content = concat!(
            "network={\n",
            "\tkey_mgmt=IEEE8021X\n",
            "\teap=MSCHAPV2\n",
            "\tidentity=\"bob\"\n",
            "\tpassword=\"bob\"\n",
            "}\n",
        );
        let config_path = format!("/tmp/eapol_test_mschapv2_{port}.conf");
        std::fs::write(&config_path, config_content)
            .expect("failed to write eapol_test config file");

        // -n: skip MPPE keying-material check (our test server does not send MS-MPPE keys)
        let output = tokio::process::Command::new("eapol_test")
            .args([
                "-c",
                &config_path,
                "-a",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-s",
                "secret",
                "-n",
                "-t",
                "5",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .await
            .expect("failed to run eapol_test");

        let _ = std::fs::remove_file(&config_path);

        // Allow the server handler a moment to finish before shutdown.
        tokio::time::sleep(Duration::from_millis(100)).await;

        sender.send(()).unwrap();
        server_proc.await.unwrap();

        assert!(
            output.status.success(),
            "eapol_test exited with non-zero status {};\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    /// Sends a RADIUS Access-Request carrying MS-CHAPv1 attributes via `radclient`
    /// and verifies that our server authenticates them correctly using the test
    /// vectors from the `FreeRADIUS` source tree:
    /// <https://github.com/FreeRADIUS/freeradius-server/blob/v3.2.x/src/tests/mschapv1>
    ///
    /// Test vector summary:
    ///   User-Name            = "bob"
    ///   Cleartext-Password   = "bob"
    ///   MS-CHAP-Challenge    = 0xb9634adc358b2ab3
    ///   MS-CHAP-Response     = 0xb901<24-byte-LM-zeros><24-byte-NT-response>
    ///
    /// The test is silently skipped when `radclient` is not present on `PATH`.
    #[tokio::test]
    async fn test_radclient_mschapv1_interop() {
        // Skip gracefully when radclient is not installed.
        if std::process::Command::new("radclient")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("radclient not found on PATH - skipping radclient MSCHAPv1 interop test");
            return;
        }

        let (sender, receiver) = oneshot::channel::<()>();

        let mut server = Server::listen(
            "127.0.0.1",
            0,
            MsChapV1Handler { password: "bob" },
            MySecretProvider {},
        )
        .await
        .unwrap();

        let port = server.listen_address().unwrap().port();

        let server_proc = tokio::spawn(async move {
            server.run(receiver).await.unwrap();
        });

        // Invoke radclient: one retry, 3-second timeout, auth command, shared secret "secret".
        // Attributes are written to stdin; radclient reads from "-".
        let mut child = tokio::process::Command::new("radclient")
            .args([
                "-r",
                "1",
                "-t",
                "3",
                "-f",
                "-",
                &format!("127.0.0.1:{port}"),
                "auth",
                "secret",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("failed to spawn radclient");

        let mut stdin = child.stdin.take().expect("failed to open radclient stdin");
        // FreeRADIUS mschapv1 test vector:
        //   MS-CHAP-Challenge = 0xb9634adc358b2ab3  (8 bytes)
        //   MS-CHAP-Response  = 0xb9 01 <24 zero bytes LM-Response> <24-byte NT-Response>
        //                     = 0xb9010000000000000000000000000000000000000000000000
        //                         007a42408782f745ef90a86fd21b0d9294132750f4af66a419
        tokio::io::AsyncWriteExt::write_all(
            &mut stdin,
            b"User-Name = \"bob\"\n\
              MS-CHAP-Challenge = 0xb9634adc358b2ab3\n\
              MS-CHAP-Response = 0xb9010000000000000000000000000000000000000000000000007a42408782f745ef90a86fd21b0d9294132750f4af66a419\n",
        )
        .await
        .expect("failed to write to radclient stdin");
        drop(stdin); // close stdin so radclient sees EOF

        let output = child
            .wait_with_output()
            .await
            .expect("failed to wait on radclient");

        // Allow the server handler a moment to finish before we shut it down.
        tokio::time::sleep(Duration::from_millis(100)).await;

        sender.send(()).unwrap();
        server_proc.await.unwrap();

        assert!(
            output.status.success(),
            "radclient exited with non-zero status {}; stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
        );
    }
}
