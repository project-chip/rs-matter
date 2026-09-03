//! `matter-server`: the HA/matterjs-server-compatible WS listener (PLAN.md §4/T2). Ported from
//! `../matter-rs/src/main.rs`'s head-peeking `/health` vs `/ws` routing + `CombinedStream`; all
//! wire-format logic lives in `ws-protocol`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tracing::{info, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use ws_protocol::backend::FabricSummary;
use ws_protocol::{
    ErrorResponse, MatterNames, MockBackend, Request, Server, ServerConfig, SuccessResponse,
};

/// Fixed controller node id for the mock backend's single-fabric setup (PLAN.md §5 R1 uses the
/// same convention for `backend-rsm`'s controller NOC, and `backend-mc` mints the same id for its
/// own real fabric -- `crates/backend-mc/src/lib.rs::CONTROLLER_NODE_ID` -- so this stays the
/// stable value across every backend). Not user-configurable in this build.
const CONTROLLER_NODE_ID: u64 = 112233;

#[derive(Debug, Parser)]
#[command(
    name = "matter-server",
    about = "Rust Matter server (HA/matterjs-server compatible)"
)]
struct Cli {
    #[arg(long, env = "STORAGE_PATH", default_value = "~/.matter-fast")]
    storage_path: String,
    #[arg(long, env = "PORT", default_value_t = 5580)]
    port: u16,
    #[arg(long, env = "LISTEN_ADDRESS")]
    listen_address: Option<String>,
    #[arg(long, env = "LOG_LEVEL", default_value = "info")]
    log_level: String,
    #[arg(long, env = "VENDOR_ID", default_value_t = 0xfff1)]
    vendor_id: u16,
    #[arg(long, env = "FABRIC_ID", default_value_t = 1)]
    fabric_id: u64,
    #[arg(long, env = "DEFAULT_FABRIC_LABEL")]
    default_fabric_label: Option<String>,
    /// `mock` (protocol-layer testing) or `mc` (`matter-controller`, PLAN.md T4 -- the fast path
    /// to a lamp in HA); `rsm` is a future backend (PLAN.md R1-R6). Default stays `mock` until the
    /// conformance suite (T5) passes on `mc` (PLAN.md §0.2).
    #[arg(long, env = "MATTER_BACKEND", default_value = "mock")]
    backend: String,
    /// PAA (Product Attestation Authority) root certificates directory, `mc` backend only. Unset
    /// -> device attestation only validates CSA test/example devices (PLAN.md §0.5).
    #[arg(long, env = "PAA_ROOTS_DIR")]
    paa_roots_dir: Option<PathBuf>,
    /// CD (Certification Declaration) signing roots directory, `mc` backend only. Paired with
    /// `paa_roots_dir` -- both or neither.
    #[arg(long, env = "CD_ROOTS_DIR")]
    cd_roots_dir: Option<PathBuf>,
}

fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

struct TracingLogControl(
    tracing_subscriber::reload::Handle<tracing_subscriber::EnvFilter, tracing_subscriber::Registry>,
);

impl ws_protocol::LogControl for TracingLogControl {
    fn set_console_level(&self, tracing_directive: &str) {
        if let Ok(filter) = tracing_directive.parse() {
            if let Err(e) = self.0.modify(|f| *f = filter) {
                warn!("failed to reload log filter: {e}");
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let storage_path = expand_tilde(&cli.storage_path);
    std::fs::create_dir_all(&storage_path)?;

    let filter: tracing_subscriber::EnvFilter =
        cli.log_level.parse().unwrap_or_else(|_| "info".into());
    let (filter_layer, reload_handle) = tracing_subscriber::reload::Layer::new(filter);
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(tracing_subscriber::fmt::layer())
        .init();

    let backend: Arc<dyn ws_protocol::Backend> = match cli.backend.as_str() {
        "mock" => {
            let fabric = FabricSummary {
                fabric_id: cli.fabric_id,
                compressed_fabric_id: cli.fabric_id, // not a real Matter compressed fabric id
                fabric_index: 1,
                controller_node_id: CONTROLLER_NODE_ID,
            };
            Arc::new(MockBackend::new(fabric))
        }
        "mc" => {
            let cfg = backend_mc::McConfig {
                storage_dir: storage_path.clone(),
                fabric_id: cli.fabric_id,
                admin_vendor_id: cli.vendor_id,
                paa_roots_dir: cli.paa_roots_dir.clone(),
                cd_roots_dir: cli.cd_roots_dir.clone(),
            };
            match backend_mc::McBackend::new(cfg).await {
                Ok(b) => Arc::new(b),
                Err(e) => {
                    eprintln!("failed to start backend-mc: {e}");
                    std::process::exit(1);
                }
            }
        }
        other => {
            eprintln!("backend '{other}' not built yet");
            std::process::exit(2);
        }
    };

    let sdk_version = format!(
        "matter-fast/{} (backend-{})",
        env!("CARGO_PKG_VERSION"),
        cli.backend
    );
    let server = Server::new(
        backend,
        Arc::new(MatterNames),
        ServerConfig {
            sdk_version,
            storage_dir: storage_path,
            default_fabric_label: cli.default_fabric_label,
        },
        Arc::new(TracingLogControl(reload_handle)),
    );

    let bind: SocketAddr = format!(
        "{}:{}",
        cli.listen_address.as_deref().unwrap_or("0.0.0.0"),
        cli.port
    )
    .parse()
    .map_err(|e| anyhow::anyhow!("bad listen address: {e}"))?;
    let listener = TcpListener::bind(bind).await?;
    info!("matter-server listening on {bind} (/ws, /health, POST /ota-upload/<id>)");

    loop {
        let (stream, peer) = listener.accept().await?;
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            if let Err(e) = serve_conn(stream, server).await {
                warn!("connection from {peer} ended: {e}");
            }
        });
    }
}

async fn serve_conn(stream: TcpStream, server: Arc<Server>) -> anyhow::Result<()> {
    use tokio::io::AsyncReadExt;

    // Read the HTTP request head to route /health vs POST /ota-upload vs /ws without a full HTTP
    // stack — matches ../matter-rs/src/main.rs's approach.
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    let mut stream = stream;
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            anyhow::bail!("eof before request");
        }
        head.extend_from_slice(&buf[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") || head.len() > 8192 {
            break;
        }
    }
    serve_with_head(stream, head, server).await
}

async fn serve_with_head(
    stream: TcpStream,
    head: Vec<u8>,
    server: Arc<Server>,
) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;

    let text = String::from_utf8_lossy(&head);
    let request_line = text.lines().next().unwrap_or("");
    let mut stream = stream;

    if request_line.starts_with("GET /health") {
        let body = "ok";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    if request_line.starts_with("POST /ota-upload/") {
        // T2 stub (PLAN.md §4/§7): real upload handling lands with backend OTA support (Milestone 3).
        let body = "OTA upload is not implemented in this build";
        let resp = format!(
            "HTTP/1.1 501 Not Implemented\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    // Reconstruct a stream starting with the already-read bytes for tungstenite.
    let pre = std::io::Cursor::new(head);
    let combined = CombinedStream { pre, inner: stream };
    let ws = tokio_tungstenite::accept_async(combined).await?;
    handle_ws(ws, server).await
}

/// A stream that first drains buffered bytes, then reads from the socket. Lets us peek the HTTP
/// head and still hand a complete stream to tungstenite.
struct CombinedStream {
    pre: std::io::Cursor<Vec<u8>>,
    inner: TcpStream,
}

impl tokio::io::AsyncRead for CombinedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = &mut *self;
        if (this.pre.position() as usize) < this.pre.get_ref().len() {
            let n = {
                let pos = this.pre.position() as usize;
                let src = &this.pre.get_ref()[pos..];
                let n = src.len().min(buf.remaining());
                buf.put_slice(&src[..n]);
                n
            };
            this.pre.set_position(this.pre.position() + n as u64);
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for CombinedStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn handle_ws<S>(
    ws: tokio_tungstenite::WebSocketStream<S>,
    server: Arc<Server>,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sink, mut stream) = ws.split();
    let mut conn = server.connect();

    // WIRE_PROTOCOL.md §1: a bare `server_info` object, pushed before any request is read.
    let info = server.server_info().await;
    sink.send(Message::Text(info.to_string().into())).await?;

    // Outgoing frames (command responses and events) are funnelled through one channel into a
    // single writer below, so the connection has one owner of `sink` even though replies now
    // complete out of order. Requests must be handled *concurrently*, not one-at-a-time: a slow
    // backend call (e.g. `discover`'s 3s mDNS scan, or a ~60s commission) must not stall replies
    // to other requests on the same connection, nor delay `attribute_updated`/`node_event`
    // delivery — matterjs-server's `WebSocketConnection` does the same (PLAN.md task, §4a). Each
    // valid request is therefore spawned as its own task; responses are written in completion
    // order, which is what real clients (including python-matter-server) already tolerate since
    // they match replies by `message_id`, not by arrival order.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();

    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sink.send(msg).await.is_err() {
                break;
            }
        }
    });

    loop {
        tokio::select! {
            msg = stream.next() => {
                let Some(msg) = msg else { break };
                let msg = msg?;
                if msg.is_close() {
                    break;
                }
                if !msg.is_text() {
                    continue;
                }
                let text = msg.to_text()?;
                match serde_json::from_str::<Request>(text) {
                    Ok(req) => {
                        let server = Arc::clone(&server);
                        let conn = conn.clone_for_task();
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            let message_id = req.message_id.clone();
                            let reply = match server.handle(&conn, &req).await {
                                Ok(result) => serde_json::to_string(&SuccessResponse { message_id, result })
                                    .unwrap_or_else(|e| format!(r#"{{"message_id":"","error_code":0,"details":"encode: {e}"}}"#)),
                                Err(err) => serde_json::to_string(&err.to_response(message_id))
                                    .unwrap_or_else(|_| r#"{"message_id":"","error_code":0,"details":"encode error"}"#.into()),
                            };
                            let _ = tx.send(Message::Text(reply.into()));
                        });
                    }
                    Err(e) => {
                        let reply = serde_json::to_string(&ErrorResponse {
                            message_id: String::new(),
                            error_code: 8,
                            details: format!("bad request: {e}"),
                        })
                        .unwrap_or_default();
                        let _ = tx.send(Message::Text(reply.into()));
                    }
                }
            }
            ev = conn.recv() => {
                let Some(ev) = ev else { break };
                if tx.send(Message::Text(ev.to_json_string().into())).is_err() {
                    break;
                }
            }
        }
    }
    drop(tx);
    let _ = writer.await;
    server.disconnect(conn.id).await;
    Ok(())
}
