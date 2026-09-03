//! Black-box smoke test: boots the real `matter-server` binary with `--backend mock`, drives it
//! purely over TCP/WS, same as HA would. Verifies PLAN.md T2's required shapes end to end.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::Value as Json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::MaybeTlsStream;

type Ws = tokio_tungstenite::WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct TempDir(std::path::PathBuf);
impl TempDir {
    fn new() -> Self {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "matter-server-smoke-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn free_port() -> u16 {
    // Bind :0 to let the OS pick a free port, then release it before the child binds it. Small
    // TOCTOU window; acceptable for a single test process.
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn wait_for_health(port: u16) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if tokio::time::Instant::now() > deadline {
            panic!("matter-server did not become healthy in time");
        }
        if let Ok(mut stream) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
            let _ = stream
                .write_all(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .await;
            let mut buf = Vec::new();
            let _ = stream.read_to_end(&mut buf).await;
            let text = String::from_utf8_lossy(&buf);
            if text.contains("200 OK") && text.trim_end().ends_with("ok") {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn send(ws: &mut Ws, text: &str) {
    ws.send(Message::Text(text.to_string().into()))
        .await
        .expect("ws send");
}

async fn next_json(ws: &mut Ws) -> Json {
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("timed out waiting for a frame")
            .expect("ws stream ended")
            .expect("ws error");
        if let Message::Text(text) = msg {
            return serde_json::from_str(&text).expect("frame is valid JSON");
        }
    }
}

/// Reads frames until it finds the response for `message_id` (skipping any events interleaved
/// with it — event delivery and the direct reply race each other, same as the real server).
async fn recv_response(ws: &mut Ws, message_id: &str) -> Json {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "never got a response for {message_id}"
        );
        let v = next_json(ws).await;
        if v.get("message_id").and_then(Json::as_str) == Some(message_id) {
            return v;
        }
    }
}

#[tokio::test]
async fn ws_smoke() {
    let port = free_port();
    let storage = TempDir::new();
    let exe = env!("CARGO_BIN_EXE_matter-server");
    let child = ChildGuard(
        Command::new(exe)
            .args([
                "--backend",
                "mock",
                "--port",
                &port.to_string(),
                "--storage-path",
                storage.0.to_str().unwrap(),
                "--log-level",
                "error",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn matter-server"),
    );

    wait_for_health(port).await;

    let url = format!("ws://127.0.0.1:{port}/ws");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("ws connect");

    // On-connect: a bare server_info object, not wrapped in event/message_id/result
    // (WIRE_PROTOCOL.md §1/§8).
    let info = next_json(&mut ws).await;
    assert!(info.get("event").is_none());
    assert!(info.get("message_id").is_none());
    assert_eq!(info["fabric_id"], 1);
    assert!(info["sdk_version"]
        .as_str()
        .unwrap()
        .contains("matter-fast"));

    // start_listening
    send(
        &mut ws,
        r#"{"message_id":"1","command":"start_listening","args":{}}"#,
    )
    .await;
    let resp = recv_response(&mut ws, "1").await;
    assert!(resp["result"].as_array().unwrap().is_empty());

    // commission a node so there is something to write to.
    send(
        &mut ws,
        r#"{"message_id":"2","command":"commission_with_code","args":{"code":"mock"}}"#,
    )
    .await;
    let resp = recv_response(&mut ws, "2").await;
    let node_id = resp["result"]["node_id"]
        .as_u64()
        .expect("node_id in commission result");

    // write_attribute drives the mock "device" to report the change back over the same
    // subscription HA relies on, exercising the exact attribute_updated shape.
    let write_req = serde_json::json!({
        "message_id": "3",
        "command": "write_attribute",
        "args": {"node_id": node_id, "attribute_path": "1/6/0", "value": true},
    });
    send(&mut ws, &write_req.to_string()).await;

    let mut got_response = false;
    let mut got_event = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !(got_response && got_event) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for write response + attribute_updated"
        );
        let v = next_json(&mut ws).await;
        if v.get("message_id").and_then(Json::as_str) == Some("3") {
            got_response = true;
        }
        if v.get("event").and_then(Json::as_str) == Some("attribute_updated") {
            // WIRE_PROTOCOL.md §3: data = [node_id, "endpoint/cluster/attribute", value]
            assert_eq!(v["data"], serde_json::json!([node_id, "1/6/0", true]));
            got_event = true;
        }
    }

    // unknown node -> error_code 5 (WIRE_PROTOCOL.md §1/§4)
    send(
        &mut ws,
        r#"{"message_id":"4","command":"get_node","args":{"node_id":999999}}"#,
    )
    .await;
    let resp = recv_response(&mut ws, "4").await;
    assert_eq!(resp["error_code"], 5);

    // unknown command -> error_code 9 (WIRE_PROTOCOL.md §1)
    send(
        &mut ws,
        r#"{"message_id":"5","command":"totally_bogus_command","args":{}}"#,
    )
    .await;
    let resp = recv_response(&mut ws, "5").await;
    assert_eq!(resp["error_code"], 9);

    let _ = ws.close(None).await;
    drop(child);
}

/// `--backend mc` (PLAN.md T4): same black-box approach as `ws_smoke`, but against
/// `backend_mc::McBackend` instead of the mock. No real Matter device is reachable in CI, so this
/// only exercises what does not require one -- server_info shape, empty node list, and the two
/// error paths that fire before any network I/O (`commission_with_code` on a garbage code,
/// `read_attribute` on an unknown node) -- plus that `compressed_fabric_id`/`controller_node_id`
/// survive a restart of the same storage dir (`fabric_identity.rs`'s synthetic-cache persistence).
#[tokio::test]
async fn mc_backend_smoke() {
    let storage = TempDir::new();
    let exe = env!("CARGO_BIN_EXE_matter-server");

    let boot = |port: u16| {
        ChildGuard(
            Command::new(exe)
                .args([
                    "--backend",
                    "mc",
                    "--port",
                    &port.to_string(),
                    "--storage-path",
                    storage.0.to_str().unwrap(),
                    "--log-level",
                    "error",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("failed to spawn matter-server --backend mc"),
        )
    };

    // ---- first boot: fresh storage dir ----
    let port1 = free_port();
    let child1 = boot(port1);
    wait_for_health(port1).await;

    let url1 = format!("ws://127.0.0.1:{port1}/ws");
    let (mut ws1, _) = tokio_tungstenite::connect_async(&url1)
        .await
        .expect("ws connect (first boot)");

    let info1 = next_json(&mut ws1).await;
    assert!(info1.get("event").is_none());
    assert!(info1.get("message_id").is_none());
    assert_eq!(info1["fabric_id"], 1);
    let compressed1 = info1["compressed_fabric_id"]
        .as_u64()
        .expect("compressed_fabric_id is a number");
    assert_ne!(
        compressed1, 0,
        "compressed_fabric_id must be non-zero even before any device is commissioned"
    );
    let controller_node_id1 = info1["controller_node_id"]
        .as_u64()
        .expect("controller_node_id is a number");
    assert_ne!(controller_node_id1, 0);

    send(
        &mut ws1,
        r#"{"message_id":"1","command":"get_nodes","args":{}}"#,
    )
    .await;
    let resp = recv_response(&mut ws1, "1").await;
    assert_eq!(resp["result"], serde_json::json!([]));

    send(
        &mut ws1,
        r#"{"message_id":"2","command":"start_listening","args":{}}"#,
    )
    .await;
    let resp = recv_response(&mut ws1, "2").await;
    assert_eq!(resp["result"], serde_json::json!([]));

    // Garbage setup code -> the commission attempt itself fails -> error 1 (NodeCommissionFailed),
    // not 8 (see backend-mc/src/errors.rs::commission_failed's doc for why).
    send(
        &mut ws1,
        r#"{"message_id":"3","command":"commission_with_code","args":{"code":"not-a-real-code"}}"#,
    )
    .await;
    let resp = recv_response(&mut ws1, "3").await;
    assert_eq!(resp["error_code"], 1);
    assert!(!resp["details"].as_str().unwrap_or_default().is_empty());

    // Node 42 was never commissioned -> ws_protocol::server's own node map rejects it before the
    // backend is ever called -> error 5 (NodeNotExists).
    send(
        &mut ws1,
        r#"{"message_id":"4","command":"read_attribute","args":{"node_id":42,"attribute_path":"1/6/0"}}"#,
    )
    .await;
    let resp = recv_response(&mut ws1, "4").await;
    assert_eq!(resp["error_code"], 5);

    let _ = ws1.close(None).await;
    drop(child1);

    // ---- second boot: same storage dir ----
    let port2 = free_port();
    let child2 = boot(port2);
    wait_for_health(port2).await;

    let url2 = format!("ws://127.0.0.1:{port2}/ws");
    let (mut ws2, _) = tokio_tungstenite::connect_async(&url2)
        .await
        .expect("ws connect (second boot)");
    let info2 = next_json(&mut ws2).await;
    assert_eq!(
        info2["compressed_fabric_id"].as_u64(),
        Some(compressed1),
        "compressed_fabric_id must survive a restart of the same storage dir"
    );
    assert_eq!(
        info2["controller_node_id"].as_u64(),
        Some(controller_node_id1),
        "controller_node_id must survive a restart of the same storage dir"
    );

    let _ = ws2.close(None).await;
    drop(child2);
}
