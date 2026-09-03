//! Frame shapes from WIRE_PROTOCOL.md §1: request, success/error response, event envelope.

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

/// `{"message_id": string, "command": string, "args": {...}}`
#[derive(Debug, Clone, Deserialize)]
pub struct Request {
    pub message_id: String,
    pub command: String,
    #[serde(default)]
    pub args: Json,
}

/// `{"message_id": string, "result": any}`
#[derive(Debug, Serialize)]
pub struct SuccessResponse {
    pub message_id: String,
    pub result: Json,
}

/// `{"message_id": string, "error_code": u16, "details": string}`
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub message_id: String,
    pub error_code: u16,
    pub details: String,
}

/// `{"event": "<name>", "data": <payload>}` — every server->client event (WIRE_PROTOCOL.md §3).
#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub event: &'static str,
    pub data: Json,
}

impl Event {
    pub fn new(event: &'static str, data: Json) -> Self {
        Self { event, data }
    }

    pub fn to_json_string(&self) -> String {
        // Infallible: Event's fields are always JSON-representable.
        serde_json::to_string(self).expect("Event is always serializable")
    }
}

/// `ServerErrorCode` (WIRE_PROTOCOL.md §1 / matterjs WMT:57-86).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorCode {
    UnknownError = 0,
    NodeCommissionFailed = 1,
    NodeInterviewFailed = 2,
    NodeNotReady = 3,
    NodeNotResolving = 4,
    NodeNotExists = 5,
    VersionMismatch = 6,
    SdkStackError = 7,
    InvalidArguments = 8,
    InvalidCommand = 9,
    UpdateCheckError = 10,
    UpdateError = 11,
    /// OHF extension: `details` is a JSON string of `{"message", "admin_vendor_ids"}`.
    IcdMultiAdmin = 100,
    /// OHF extension.
    OtaUploadError = 101,
}

impl From<ErrorCode> for u16 {
    fn from(c: ErrorCode) -> u16 {
        c as u16
    }
}

/// Backend/protocol error carrying a wire error code + human details, as thrown by
/// matterjs's `ServerError` (WIRE_PROTOCOL.md §1). This is `BErr` in the `Backend` trait.
#[derive(Debug, Clone, thiserror::Error)]
#[error("[{code:?}] {details}")]
pub struct ServerError {
    pub code: ErrorCode,
    pub details: String,
}

impl ServerError {
    pub fn new(code: ErrorCode, details: impl Into<String>) -> Self {
        Self {
            code,
            details: details.into(),
        }
    }

    pub fn unknown(details: impl Into<String>) -> Self {
        Self::new(ErrorCode::UnknownError, details)
    }

    pub fn node_commission_failed(details: impl Into<String>) -> Self {
        Self::new(ErrorCode::NodeCommissionFailed, details)
    }

    pub fn node_interview_failed(details: impl Into<String>) -> Self {
        Self::new(ErrorCode::NodeInterviewFailed, details)
    }

    pub fn node_not_ready(details: impl Into<String>) -> Self {
        Self::new(ErrorCode::NodeNotReady, details)
    }

    pub fn node_not_resolving(details: impl Into<String>) -> Self {
        Self::new(ErrorCode::NodeNotResolving, details)
    }

    pub fn node_not_exists(node_id: u64) -> Self {
        Self::new(
            ErrorCode::NodeNotExists,
            format!("Node {node_id} does not exist"),
        )
    }

    pub fn version_mismatch(details: impl Into<String>) -> Self {
        Self::new(ErrorCode::VersionMismatch, details)
    }

    pub fn sdk_stack(details: impl Into<String>) -> Self {
        Self::new(ErrorCode::SdkStackError, details)
    }

    pub fn invalid_arguments(details: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidArguments, details)
    }

    pub fn invalid_command(name: impl Into<String>) -> Self {
        let name = name.into();
        Self::new(
            ErrorCode::InvalidCommand,
            format!("Unknown command '{name}'"),
        )
    }

    pub fn update_check(details: impl Into<String>) -> Self {
        Self::new(ErrorCode::UpdateCheckError, details)
    }

    pub fn update_error(details: impl Into<String>) -> Self {
        Self::new(ErrorCode::UpdateError, details)
    }

    pub fn icd_multi_admin(message: impl Into<String>, admin_vendor_ids: Vec<u32>) -> Self {
        let details =
            serde_json::json!({"message": message.into(), "admin_vendor_ids": admin_vendor_ids})
                .to_string();
        Self::new(ErrorCode::IcdMultiAdmin, details)
    }

    pub fn ota_upload(details: impl Into<String>) -> Self {
        Self::new(ErrorCode::OtaUploadError, details)
    }

    pub fn not_implemented(what: &str) -> Self {
        Self::new(
            ErrorCode::SdkStackError,
            format!("{what}: not implemented in this build"),
        )
    }

    pub fn to_response(&self, message_id: String) -> ErrorResponse {
        ErrorResponse {
            message_id,
            error_code: self.code.into(),
            details: self.details.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_response_shape_matches_spec_example() {
        // WIRE_PROTOCOL.md §1: {"message_id": "42", "error_code": 5, "details": "Node 1234 does not exist"}
        let err = ServerError::node_not_exists(1234);
        let resp = err.to_response("42".into());
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"message_id": "42", "error_code": 5, "details": "Node 1234 does not exist"})
        );
    }

    #[test]
    fn success_response_shape() {
        let resp = SuccessResponse {
            message_id: "1".into(),
            result: serde_json::json!({"ok": true}),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"message_id": "1", "result": {"ok": true}})
        );
    }

    #[test]
    fn event_envelope_shape() {
        let ev = Event::new("node_removed", serde_json::json!(1234));
        assert_eq!(
            ev.to_json_string(),
            r#"{"event":"node_removed","data":1234}"#
        );
    }

    #[test]
    fn unknown_command_is_code_9() {
        let err = ServerError::invalid_command("subscribe_attribute");
        assert_eq!(err.code, ErrorCode::InvalidCommand);
        assert_eq!(u16::from(err.code), 9);
    }
}
