#![allow(unused)]

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::sleep;

use radius::core::code::Code;
use radius::core::request::Request;
use radius::dict::{cisco, rfc2865};
use radius::server::{RequestHandler, SecretProvider, SecretProviderError};

struct MyRequestHandler {}

impl RequestHandler<(), io::Error> for MyRequestHandler {
    async fn handle_radius_request(
        &self,
        conn: &UdpSocket,
        req: &Request,
    ) -> Result<(), io::Error> {
        let req_packet = req.get_packet();
        let maybe_user_name_attr = rfc2865::lookup_user_name(req_packet);
        let maybe_user_password_attr = rfc2865::lookup_user_password(req_packet);

        let user_name = maybe_user_name_attr.unwrap().unwrap();
        let user_password = String::from_utf8(maybe_user_password_attr.unwrap().unwrap()).unwrap();
        let code = if user_name == "admin" && user_password == "p@ssw0rd" {
            Code::AccessAccept
        } else {
            Code::AccessReject
        };

        let mut resp_packet = req_packet.make_response_packet(code);
        rfc2865::add_user_name(&mut resp_packet, user_name.as_str());
        conn.send_to(&resp_packet.encode().unwrap(), req.get_remote_addr())
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
        let req_packet = req.get_packet();
        let resp_packet = req_packet.make_response_packet(Code::AccessReject);
        conn.send_to(&resp_packet.encode().unwrap(), req.get_remote_addr())
            .await?;
        Ok(())
    }
}

struct MySecretProvider {}

impl SecretProvider for MySecretProvider {
    fn fetch_secret(&self, _remote_addr: SocketAddr) -> Result<Vec<u8>, SecretProviderError> {
        let bs = b"secret".to_vec();
        Ok(bs)
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
        let req_packet = req.get_packet();

        let user_name = rfc2865::lookup_user_name(req_packet)
            .and_then(|r| r.ok())
            .unwrap_or_default();
        let av_pair = cisco::lookup_cisco_av_pair(req_packet)
            .and_then(|r| r.ok())
            .unwrap_or_default();
        let nas_port = cisco::lookup_cisco_nas_port(req_packet)
            .and_then(|r| r.ok())
            .unwrap_or_default();

        *self.captured.lock().unwrap() = Some(CapturedVsaData {
            user_name,
            av_pair,
            nas_port,
        });

        let resp_packet = req_packet.make_response_packet(Code::AccessAccept);
        conn.send_to(&resp_packet.encode().unwrap(), req.get_remote_addr())
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use tokio::sync::oneshot;

    use radius::client::{Client, ClientError};
    use radius::core::code::Code;
    use radius::core::packet::Packet;
    use radius::dict::rfc2865;

    use crate::test::{LongTimeTakingHandler, MyRequestHandler, MySecretProvider};
    use radius::server::Server;

    #[tokio::test]
    async fn test_runner() {
        test_access_request().await;
        test_socket_timeout().await;
    }

    async fn test_access_request() {
        let (sender, receiver) = oneshot::channel::<()>();

        let port = 1812;

        let mut server = Server::listen("0.0.0.0", port, MyRequestHandler {}, MySecretProvider {})
            .await
            .unwrap();

        let server_proc = tokio::spawn(async move {
            server.run(receiver).await.unwrap();
        });

        let remote_addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        let client = Client::new(None, None);

        let mut req_packet = Packet::new(Code::AccessRequest, b"secret".as_ref());
        rfc2865::add_user_name(&mut req_packet, "admin");
        rfc2865::add_user_password(&mut req_packet, b"p@ssw0rd").unwrap();
        let res = client.send_packet(&remote_addr, &req_packet).await.unwrap();
        let maybe_user_name = rfc2865::lookup_user_name(&res);
        let maybe_user_pass = rfc2865::lookup_user_password(&res);
        assert_eq!(res.get_code(), Code::AccessAccept);
        assert!(maybe_user_name.is_some());
        assert_eq!(maybe_user_name.unwrap().unwrap(), "admin");
        assert!(maybe_user_pass.is_none());

        let mut req_packet = Packet::new(Code::AccessRequest, b"secret".as_ref());
        rfc2865::add_user_name(&mut req_packet, "admin");
        rfc2865::add_user_password(&mut req_packet, b"INVALID-PASS").unwrap();
        let res = client.send_packet(&remote_addr, &req_packet).await.unwrap();
        assert_eq!(res.get_code(), Code::AccessReject);

        sender.send(()).unwrap();
        server_proc.await.unwrap();
    }

    async fn test_socket_timeout() {
        let (sender, receiver) = oneshot::channel::<()>();

        let port = 1812;

        let mut server = Server::listen(
            "0.0.0.0",
            port,
            LongTimeTakingHandler {},
            MySecretProvider {},
        )
        .await
        .unwrap();

        let server_proc = tokio::spawn(async move {
            server.run(receiver).await.unwrap();
        });

        let remote_addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        let client = Client::new(None, Some(Duration::from_secs(0)));

        let mut req_packet = Packet::new(Code::AccessRequest, b"secret".as_ref());
        rfc2865::add_user_name(&mut req_packet, "admin");
        rfc2865::add_user_password(&mut req_packet, b"p@ssw0rd").unwrap();
        let res = client.send_packet(&remote_addr, &req_packet).await;

        let err = res.unwrap_err();
        match err {
            ClientError::SocketTimeoutError() => {}
            _ => panic!("unexpected error: {}", err),
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

        use crate::test::{CapturedVsaData, MySecretProvider, VsaCaptureHandler};
        use std::sync::{Arc, Mutex};

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

        let port = server.get_listen_address().unwrap().port();

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
                &format!("127.0.0.1:{}", port),
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
}
