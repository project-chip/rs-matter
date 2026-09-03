//! `CommandNames` is the seam between the wire protocol and the Matter IDL name table
//! (`crates/matter-names`, task T3): `device_command` needs `command_name` (camelCase) -> command
//! id resolution, name-based response decoding (WIRE_PROTOCOL.md §7), and name-based event
//! decoding (§3 `node_event`). `NoNames` keeps this crate buildable and testable stand-alone with
//! no generated table; `MatterNames` below is the real thing, a thin bridge onto `matter_names`'s
//! own `Tlv`/JSON API — every binary (`matter-server`, all backends) should construct `Server`
//! with `MatterNames`, not `NoNames`.

use serde_json::Value as Json;

use crate::value::MValue;
use crate::wire::ServerError;

pub trait CommandNames: Send + Sync {
    /// `command_name` (already `camelize()`d) + JSON payload (field-name keyed) -> command id +
    /// tag-based `MValue` fields to invoke. Unknown cluster/command -> error 8
    /// (WIRE_PROTOCOL.md §7).
    fn encode_command(
        &self,
        cluster: u32,
        name: &str,
        payload: &Json,
    ) -> Result<(u32, MValue), ServerError>;

    /// Tag-based response fields -> name-based JSON (WIRE_PROTOCOL.md §7). Unknown cluster/command
    /// model -> `{}`.
    fn decode_response(&self, cluster: u32, name: &str, fields: &MValue) -> Json;

    /// Tag-based event data -> name-based JSON (WIRE_PROTOCOL.md §3 `node_event`). Unknown ->
    /// tag-based fallback (bare `MValue::to_json()`), never an error: an event a client can't
    /// name is still delivered.
    fn decode_event(&self, cluster: u32, event: u32, fields: &MValue) -> Json;
}

/// `camelize()` (WIRE_PROTOCOL.md §7): `"MoveToLevel"` and `"move_to_level"` both -> `"moveToLevel"`.
/// Lowercases a leading capital (PascalCase -> camelCase) and folds `_x` -> `X` (snake_case ->
/// camelCase); the two rules compose so mixed input normalizes the same way.
pub fn camelize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    if let Some(first) = chars.next() {
        out.extend(first.to_lowercase());
    }
    let mut upper_next = false;
    for c in chars {
        if c == '_' {
            upper_next = true;
        } else if upper_next {
            out.extend(c.to_uppercase());
            upper_next = false;
        } else {
            out.push(c);
        }
    }
    out
}

/// No name table available: every command lookup fails (error 8); decoding falls back to the
/// crate's own tag-based `MValue::to_json`, which is always well-formed even without field names.
pub struct NoNames;

impl CommandNames for NoNames {
    fn encode_command(
        &self,
        cluster: u32,
        name: &str,
        _payload: &Json,
    ) -> Result<(u32, MValue), ServerError> {
        Err(ServerError::invalid_arguments(format!(
            "unknown command '{name}' on cluster {cluster} (no command name table loaded)"
        )))
    }

    fn decode_response(&self, _cluster: u32, _name: &str, fields: &MValue) -> Json {
        fields.to_json()
    }

    fn decode_event(&self, _cluster: u32, _event: u32, fields: &MValue) -> Json {
        fields.to_json()
    }
}

/// `CommandNames` backed by the generated Matter IDL table (`matter-names`, task T3). `MValue`
/// and `matter_names::Tlv` are the same TLV shape by construction (PLAN.md §3's `MValue` and
/// `matter-names`'s doc comment both say so), so bridging is a structural 1:1 mapping with no
/// semantic decisions of its own — the octet-string caveat (WIRE_PROTOCOL.md §24: `MValue::Bytes`
/// only for fields the schema knows are octet strings) is already resolved by `matter_names`
/// itself, which emits `Tlv::Bytes` exactly for `Kind::OctStr` fields; this bridge just carries
/// that variant straight through.
pub struct MatterNames;

fn mvalue_to_tlv(v: &MValue) -> matter_names::Tlv {
    use matter_names::Tlv;
    match v {
        MValue::Null => Tlv::Null,
        MValue::Bool(b) => Tlv::Bool(*b),
        MValue::U(u) => Tlv::U(*u),
        MValue::I(i) => Tlv::I(*i),
        MValue::F32(f) => Tlv::F32(*f),
        MValue::F64(f) => Tlv::F64(*f),
        MValue::Str(s) => Tlv::Str(s.clone()),
        MValue::Bytes(b) => Tlv::Bytes(b.clone()),
        MValue::Array(items) => Tlv::Array(items.iter().map(mvalue_to_tlv).collect()),
        MValue::Struct(members) => Tlv::Struct(
            members
                .iter()
                .map(|(t, v)| (*t, mvalue_to_tlv(v)))
                .collect(),
        ),
    }
}

fn tlv_to_mvalue(v: &matter_names::Tlv) -> MValue {
    use matter_names::Tlv;
    match v {
        Tlv::Null => MValue::Null,
        Tlv::Bool(b) => MValue::Bool(*b),
        Tlv::U(u) => MValue::U(*u),
        Tlv::I(i) => MValue::I(*i),
        Tlv::F32(f) => MValue::F32(*f),
        Tlv::F64(f) => MValue::F64(*f),
        Tlv::Str(s) => MValue::Str(s.clone()),
        Tlv::Bytes(b) => MValue::Bytes(b.clone()),
        Tlv::Array(items) => MValue::Array(items.iter().map(tlv_to_mvalue).collect()),
        Tlv::Struct(members) => MValue::Struct(
            members
                .iter()
                .map(|(t, v)| (*t, tlv_to_mvalue(v)))
                .collect(),
        ),
    }
}

impl CommandNames for MatterNames {
    fn encode_command(
        &self,
        cluster: u32,
        name: &str,
        payload: &Json,
    ) -> Result<(u32, MValue), ServerError> {
        let (id, tlv) = matter_names::encode_command(cluster, name, payload)
            .map_err(|e| ServerError::invalid_arguments(e.to_string()))?;
        Ok((id, tlv_to_mvalue(&tlv)))
    }

    fn decode_response(&self, cluster: u32, name: &str, fields: &MValue) -> Json {
        let tlv = mvalue_to_tlv(fields);
        // "Unknown cluster/command model -> {}" (WIRE_PROTOCOL.md §7); `decode_response` also
        // returns `None` for a status-only command, which never reaches here (the server only
        // calls this on `InvokeOutcome::Fields`), but `{}` is the right fallback either way.
        matter_names::decode_response(cluster, name, &tlv)
            .unwrap_or_else(|| Json::Object(serde_json::Map::new()))
    }

    fn decode_event(&self, cluster: u32, event: u32, fields: &MValue) -> Json {
        let tlv = mvalue_to_tlv(fields);
        // Unknown event -> tag-based fallback, never an error (trait doc / WIRE_PROTOCOL.md §3).
        matter_names::decode_event(cluster, event, &tlv).unwrap_or_else(|| fields.to_json())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_names_encode_is_error_8() {
        let err = NoNames
            .encode_command(6, "toggle", &Json::Null)
            .unwrap_err();
        assert_eq!(u16::from(err.code), 8);
    }

    #[test]
    fn no_names_decode_falls_back_to_tag_based() {
        let fields = MValue::Struct(vec![(0, MValue::U(1))]);
        assert_eq!(
            NoNames.decode_response(6, "x", &fields),
            serde_json::json!({"0": 1})
        );
        assert_eq!(
            NoNames.decode_event(6, 1, &fields),
            serde_json::json!({"0": 1})
        );
    }

    #[test]
    fn camelize_matches_examples() {
        assert_eq!(camelize("MoveToLevel"), "moveToLevel");
        assert_eq!(camelize("move_to_level"), "moveToLevel");
        assert_eq!(camelize("toggle"), "toggle");
        assert_eq!(camelize("PINCode"), "pINCode");
    }

    #[test]
    fn matter_names_tlv_bridge_round_trips() {
        let v = MValue::Struct(vec![
            (0, MValue::U(1)),
            (1, MValue::Bytes(vec![1, 2, 3])),
            (2, MValue::Array(vec![MValue::Bool(true), MValue::Null])),
        ]);
        let tlv = mvalue_to_tlv(&v);
        assert_eq!(tlv_to_mvalue(&tlv), v);
    }

    #[test]
    fn matter_names_encode_move_to_level_with_on_off() {
        let payload = serde_json::json!({"level": 128, "transitionTime": 10, "optionsMask": 0, "optionsOverride": 0});
        let (id, fields) = MatterNames
            .encode_command(8, "moveToLevelWithOnOff", &payload)
            .unwrap();
        assert_eq!(id, 4);
        assert_eq!(
            fields,
            MValue::Struct(vec![
                (0, MValue::U(128)),
                (1, MValue::U(10)),
                (2, MValue::U(0)),
                (3, MValue::U(0)),
            ])
        );
    }

    #[test]
    fn matter_names_decode_switch_multi_press_complete() {
        let fields = MValue::Struct(vec![(0, MValue::U(1)), (1, MValue::U(2))]);
        assert_eq!(
            MatterNames.decode_event(59, 6, &fields),
            serde_json::json!({"previousPosition": 1, "totalNumberOfPressesCounted": 2})
        );
    }

    #[test]
    fn matter_names_unknown_command_is_error_8() {
        let err = MatterNames
            .encode_command(6, "explode", &Json::Null)
            .unwrap_err();
        assert_eq!(u16::from(err.code), 8);
    }

    #[test]
    fn matter_names_unknown_event_falls_back_to_tag_based() {
        let fields = MValue::Struct(vec![(0, MValue::U(1))]);
        assert_eq!(
            MatterNames.decode_event(6, 9999, &fields),
            serde_json::json!({"0": 1})
        );
    }

    // ---- end-to-end through `Server` + `MockBackend`, per PLAN.md T4 Part A -------------------

    fn fabric() -> crate::backend::FabricSummary {
        crate::backend::FabricSummary {
            fabric_id: 1,
            compressed_fabric_id: 0x1234_5678_9abc_def0,
            fabric_index: 1,
            controller_node_id: 112233,
        }
    }

    async fn test_server_with_names(
        dir: &std::path::Path,
    ) -> (
        std::sync::Arc<crate::server::Server>,
        std::sync::Arc<crate::mock::MockBackend>,
    ) {
        let backend = std::sync::Arc::new(crate::mock::MockBackend::new(fabric()));
        let server = crate::server::Server::new(
            backend.clone() as std::sync::Arc<dyn crate::backend::Backend>,
            std::sync::Arc::new(MatterNames),
            crate::server::ServerConfig {
                sdk_version: "test/0.0.0".into(),
                storage_dir: dir.to_path_buf(),
                default_fabric_label: None,
            },
            std::sync::Arc::new(crate::server::NoLogControl),
        );
        (server, backend)
    }

    fn req(id: &str, command: &str, args: Json) -> crate::wire::Request {
        crate::wire::Request {
            message_id: id.into(),
            command: command.into(),
            args,
        }
    }

    fn tempdir() -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "ws-protocol-names-test-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn device_command_reaches_backend_as_cluster_8_command_4() {
        let dir = tempdir();
        let (server, backend) = test_server_with_names(&dir).await;
        let conn = server.connect();

        let commissioned = server
            .handle(
                &conn,
                &req(
                    "1",
                    "commission_with_code",
                    serde_json::json!({"code": "mock"}),
                ),
            )
            .await
            .unwrap();
        let node_id = commissioned["node_id"].as_u64().unwrap();

        let result = server
            .handle(
                &conn,
                &req(
                    "2",
                    "device_command",
                    serde_json::json!({
                        "node_id": node_id,
                        "endpoint_id": 1,
                        "cluster_id": 8,
                        "command_name": "moveToLevelWithOnOff",
                        "payload": {"level": 128, "transitionTime": 10, "optionsMask": 0, "optionsOverride": 0},
                    }),
                ),
            )
            .await
            .unwrap();
        // The mock backend answers every invoke with a bare status, so device_command -> null
        // (WIRE_PROTOCOL.md §7); what matters here is what reached the backend.
        assert!(result.is_null());

        let (endpoint, cluster, command, fields) = backend.last_invoke().await.unwrap();
        assert_eq!((endpoint, cluster, command), (1, 8, 4));
        match fields {
            MValue::Struct(members) => {
                assert_eq!(
                    members.iter().map(|(t, _)| *t).collect::<Vec<_>>(),
                    vec![0, 1, 2, 3]
                );
                assert_eq!(
                    members,
                    vec![
                        (0, MValue::U(128)),
                        (1, MValue::U(10)),
                        (2, MValue::U(0)),
                        (3, MValue::U(0)),
                    ]
                );
            }
            other => panic!("expected a ctx-tagged struct, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn node_event_from_backend_is_emitted_name_based() {
        let dir = tempdir();
        let (server, backend) = test_server_with_names(&dir).await;
        let mut conn = server.connect();

        server
            .handle(&conn, &req("1", "start_listening", serde_json::json!({})))
            .await
            .unwrap();
        let commissioned = server
            .handle(
                &conn,
                &req(
                    "2",
                    "commission_with_code",
                    serde_json::json!({"code": "mock"}),
                ),
            )
            .await
            .unwrap();
        let node_id = commissioned["node_id"].as_u64().unwrap();

        // Switch (cluster 59) MultiPressComplete (event 6): {previousPosition, totalNumberOfPressesCounted}.
        backend
            .push_event(
                node_id,
                1,
                59,
                6,
                42,
                1,
                Some(1_704_067_200_000),
                MValue::Struct(vec![(0, MValue::U(1)), (1, MValue::U(2))]),
            )
            .await;

        let ev = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let e = conn.recv().await.expect("broadcaster still alive");
                if e.event == "node_event" {
                    return e;
                }
            }
        })
        .await
        .expect("timed out waiting for node_event");

        assert_eq!(ev.data["node_id"], node_id);
        assert_eq!(ev.data["endpoint_id"], 1);
        assert_eq!(ev.data["cluster_id"], 59);
        assert_eq!(ev.data["event_id"], 6);
        assert_eq!(
            ev.data["data"],
            serde_json::json!({"previousPosition": 1, "totalNumberOfPressesCounted": 2})
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
