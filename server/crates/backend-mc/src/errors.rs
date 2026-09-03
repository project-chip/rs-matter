//! `matter_controller::Error` -> `ws_protocol::ServerError` (the wire error-code table,
//! WIRE_PROTOCOL.md §1). `matter_controller::Error` is `#[non_exhaustive]`, so every mapper here
//! ends in a catch-all -- new error variants degrade to `UnknownError` (0) rather than failing to
//! compile on a matter-controller point release.

use std::future::Future;
use std::time::Duration;

use matter_controller::Error as McError;
use ws_protocol::ServerError;

/// `matter-controller` calls that talk to a device have no built-in ceiling of their own: an
/// unreachable node (powered off, out of range, dropped from Wi-Fi) can leave a read/write/
/// invoke/commission/open-window call pending forever, wedging the request that issued it (and,
/// pre-concurrency-fix, the whole WS connection). Every such call is wrapped in one of these
/// budgets and, on expiry, mapped to `ErrorCode::NodeNotResolving` (4) — the same code
/// `operational()` above already uses for a `Driver`/`Transport`/`ResponseTimeout` failure, since
/// from HA's point of view "the device didn't answer in time" and "the device never answered" are
/// the same fact.
pub const READ_WRITE_INVOKE_TIMEOUT: Duration = Duration::from_secs(30);
pub const COMMISSION_TIMEOUT: Duration = Duration::from_secs(120);
pub const OPEN_WINDOW_TIMEOUT: Duration = Duration::from_secs(30);

/// Runs `fut`, applying `dur` as a hard ceiling. `Elapsed` becomes `NodeNotResolving` with `what`
/// in the detail; a real `Err` from `fut` is passed to `on_err` unchanged (so callers keep their
/// existing, more specific `McError` mapping for everything that isn't a timeout).
pub async fn with_timeout<T, E>(
    dur: Duration,
    what: &str,
    fut: impl Future<Output = Result<T, E>>,
    on_err: impl FnOnce(E) -> ServerError,
) -> Result<T, ServerError> {
    match tokio::time::timeout(dur, fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(on_err(e)),
        Err(_) => Err(ServerError::node_not_resolving(format!(
            "{what} timed out after {dur:?} with no response from the device"
        ))),
    }
}

#[cfg(test)]
mod timeout_tests {
    use super::*;

    /// A never-resolving device call (the exact failure mode a real unreachable node produces --
    /// PLAN.md task 4d) must surface as `NodeNotResolving` (error 4) rather than hang the caller
    /// forever.
    #[tokio::test(start_paused = true)]
    async fn expiry_maps_to_node_not_resolving() {
        let err = with_timeout(
            Duration::from_millis(10),
            "read",
            std::future::pending::<Result<(), McError>>(),
            |_: McError| unreachable!("pending future never resolves Err"),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, ws_protocol::ErrorCode::NodeNotResolving);
        assert!(
            err.details.contains("read"),
            "detail should name the call: {}",
            err.details
        );
    }

    #[tokio::test]
    async fn success_within_budget_passes_through() {
        let ok = with_timeout(
            Duration::from_secs(30),
            "read",
            std::future::ready(Ok::<_, McError>(42)),
            operational,
        )
        .await
        .unwrap();
        assert_eq!(ok, 42);
    }

    #[tokio::test]
    async fn real_error_within_budget_uses_the_given_mapper_not_a_timeout() {
        let err = with_timeout(
            Duration::from_secs(30),
            "read",
            std::future::ready(Err::<(), McError>(McError::ControllerStopped)),
            operational,
        )
        .await
        .unwrap_err();
        assert_ne!(
            err.code,
            ws_protocol::ErrorCode::NodeNotResolving,
            "a real, prompt error must not be misreported as a timeout"
        );
    }
}

/// Generic operational mapper: for read/write/invoke/subscribe/fabric-management calls on an
/// already-commissioned node. Node-existence (`error 5`) is never this backend's job to report --
/// `ws_protocol::server::Server::ensure_node` gates every command against its own commissioned-node
/// map before the backend is ever called (see `crates/ws-protocol/src/server/nodes.rs`), so by the
/// time a `matter_controller::Error` reaches here the node id is known-good and any failure is
/// about *reaching* or *talking to* that device, not about it being unknown to HA.
pub fn operational(e: McError) -> ServerError {
    match e {
        // Could not resolve/connect/handshake with the device.
        McError::Driver(_) | McError::Transport(_) => {
            ServerError::node_not_resolving(e.to_string())
        }
        // Device acknowledged delivery but never answered -- distinct from a resolution failure,
        // but still "the device isn't behaving", which `node_not_resolving` communicates better to
        // an HA user than a bare protocol error would.
        McError::ResponseTimeout { .. } => ServerError::node_not_resolving(e.to_string()),
        McError::InteractionModel(_) => ServerError::sdk_stack(e.to_string()),
        McError::NotCommissioned(_) => ServerError::node_not_ready(e.to_string()),
        McError::ControllerStopped => ServerError::unknown(e.to_string()),
        McError::CommissioningWindowRejected(_) => ServerError::sdk_stack(e.to_string()),
        McError::OperationalCredentialsRejected(_) => ServerError::sdk_stack(e.to_string()),
        McError::WouldRemoveSelf | McError::AclWouldLockOut => {
            ServerError::invalid_arguments(e.to_string())
        }
        McError::GroupCommandRejected(_) | McError::GroupNotProvisioned(_) => {
            ServerError::sdk_stack(e.to_string())
        }
        McError::SetupCode(_) => ServerError::invalid_arguments(e.to_string()),
        McError::NoTrust | McError::Trust(_) => ServerError::sdk_stack(e.to_string()),
        McError::Store(_)
        | McError::Codec(_)
        | McError::Cert(_)
        | McError::Noc(_)
        | McError::Signer(_)
        | McError::Snapshot(_)
        | McError::FabricAlreadyExists(_)
        | McError::InvalidFabricValidity(_)
        | McError::SystemClockUnset(_) => ServerError::unknown(e.to_string()),
        _ => ServerError::unknown(e.to_string()),
    }
}

/// Commission-path mapper: `commission_with_code`/`commission_on_network`. Every failure in this
/// path -- a garbage setup code, a device that rejects attestation, one that never answers PASE,
/// a transport failure mid-handshake -- is "the commission attempt failed", which is exactly
/// `ErrorCode::NodeCommissionFailed` (1), the code WIRE_PROTOCOL.md's T4 verification pins
/// ("commission_with_code with a garbage code -> error 1 with a detail"). This intentionally
/// collapses variants `operational()` above splits out (`SetupCode` -> 8 there): a bad setup code
/// during an *established* connection to a known device is a client-input mistake, but a bad setup
/// code *at* `commission_with_code` is the commission failing, which HA's `commission_with_code`
/// handler surfaces as code 1 either way (matterjs `WSH:1002-1048` wraps the whole commission
/// attempt in one try/catch that always throws `NodeCommissionFailed`).
pub fn commission_failed(e: McError) -> ServerError {
    ServerError::node_commission_failed(e.to_string())
}
