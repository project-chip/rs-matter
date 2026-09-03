//! `compressed_fabric_id` (Matter Core Spec §4.3.2.2, WIRE_PROTOCOL.md §8): an HKDF-SHA256 of the
//! fabric's **root** (RCAC) public key with the fabric id as salt.
//!
//! `matter-controller` 0.11 mints and owns that root key entirely internally
//! (`crate::fabric::create_fabric`, a `RingSigner::generate()` call with no public accessor) and
//! exposes no public API to read it back for our own fabric -- `MatterController::fabrics()`
//! returns `FabricInfo` (fabric_id/commissioner_node_id/node_count/icac_enabled only, no key
//! material), and `ControllerState`/`FabricEntry` (which *do* carry `rcac_cert`, and are `pub`
//! types) are reachable only from inside the crate's own actor. The **only** public path to a
//! fabric's root public key is `Node::list_fabrics()` -- reading a *device's* own
//! `OperationalCredentials.Fabrics` list, which requires a commissioned, reachable device.
//!
//! That is a real gap for a controller with zero devices yet (this backend's own `server_info`
//! must report a `compressed_fabric_id` before anything is commissioned -- WIRE_PROTOCOL.md §8,
//! and PLAN.md T4's own smoke test asserts a non-zero value on a completely fresh boot). The
//! workaround: mint our own throwaway P-256 keypair (via `matter_crypto::RingSigner`, the same
//! primitive matter-controller's RCAC uses) purely to have *a* stable public key to feed the real
//! spec derivation through, and cache the resulting id. The very first time this backend can reach
//! a real device's `Fabrics` list (right after a successful commission, best-effort), it re-derives
//! the id from that device's reported root public key -- the actual value every device on the
//! fabric will agree on -- and that real value permanently replaces the synthetic one in the
//! cache. `source` in the persisted file records which kind is currently cached, purely for
//! diagnostics; nothing in this backend branches on it.

use std::path::{Path, PathBuf};

use matter_crypto::{derive_compressed_fabric_id, Signer};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Source {
    /// Derived from our own throwaway keypair -- stable across restarts, but will not match the
    /// value any real device on the fabric advertises in mDNS.
    Synthetic,
    /// Derived from a real device's reported root public key (`Node::list_fabrics`) -- the value
    /// every device on the fabric actually uses.
    Real,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Cached {
    compressed_fabric_id: u64,
    source: Source,
}

fn cache_path(storage_dir: &Path) -> PathBuf {
    storage_dir.join("mc-fabric.json")
}

fn load(storage_dir: &Path) -> Option<Cached> {
    let data = std::fs::read_to_string(cache_path(storage_dir)).ok()?;
    serde_json::from_str(&data).ok()
}

fn save(storage_dir: &Path, cached: &Cached) {
    if let Ok(data) = serde_json::to_string_pretty(cached) {
        if let Err(e) = std::fs::write(cache_path(storage_dir), data) {
            tracing::warn!(error = %e, "failed to persist mc-fabric.json");
        }
    }
}

/// The 8 bytes of `derive_compressed_fabric_id`, packed big-endian into a `u64` -- matching how
/// matter.js/HA display it (a plain decimal integer, WIRE_PROTOCOL.md §0/§8), and how
/// `<compressed-fabric-hex>-<node-hex>` mDNS instance names are built (`mdns.rs`).
fn pack_be(bytes: [u8; 8]) -> u64 {
    u64::from_be_bytes(bytes)
}

/// Load the cached compressed fabric id, or mint the synthetic fallback and persist it, on first
/// boot in a fresh storage dir. Synchronous and infallible (beyond logging) by design: this must
/// resolve before the very first `server_info` push, with no device or network round trip.
pub fn load_or_mint_synthetic(storage_dir: &Path, fabric_id: u64) -> u64 {
    if let Some(cached) = load(storage_dir) {
        return cached.compressed_fabric_id;
    }
    let id = derive_synthetic(fabric_id);
    save(
        storage_dir,
        &Cached {
            compressed_fabric_id: id,
            source: Source::Synthetic,
        },
    );
    id
}

fn derive_synthetic(fabric_id: u64) -> u64 {
    // A throwaway P-256 keypair exists only to have a public key to hash; the private half is
    // dropped immediately (nothing here or later needs to sign anything with it).
    let (signer, _pkcs8) =
        matter_crypto::RingSigner::generate().expect("system RNG must be available at boot");
    let bytes = signer.public_key().as_bytes();
    let mut root_pub = [0u8; 65];
    root_pub.copy_from_slice(bytes);
    let derived = derive_compressed_fabric_id(&root_pub, fabric_id)
        .expect("fixed-length HKDF expand never fails");
    pack_be(derived)
}

/// Whether the cached value is still the boot-time synthetic placeholder (and so worth trying to
/// upgrade to the real, device-derived one).
pub fn is_synthetic(storage_dir: &Path) -> bool {
    load(storage_dir).is_none_or(|c| matches!(c.source, Source::Synthetic))
}

/// Derive the real compressed fabric id from a device's reported root public key and persist it,
/// permanently overwriting any cached synthetic value. Called best-effort after a successful
/// commission or a successful `list_fabrics()` read (`lib.rs`); a failure here is never fatal to
/// the caller.
pub fn upgrade_to_real(storage_dir: &Path, root_public_key: &[u8], fabric_id: u64) -> Option<u64> {
    let root_pub: [u8; 65] = root_public_key.try_into().ok()?;
    let derived = derive_compressed_fabric_id(&root_pub, fabric_id).ok()?;
    let id = pack_be(derived);
    save(
        storage_dir,
        &Cached {
            compressed_fabric_id: id,
            source: Source::Real,
        },
    );
    Some(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Matter Core Spec §4.3.2.2 worked example, byte-for-byte the same vector
    /// `matter_crypto::operational::compressed_fabric_id_matches_spec_vector` pins (connectedhomeip
    /// `TestChipCryptoPAL.cpp::TestCompressedFabricIdentifier`) -- proves `derive_compressed_fabric_id`
    /// really is the spec derivation, not just self-consistent.
    #[test]
    fn matches_matter_core_spec_worked_example() {
        let hex = "044a9f42b1ca4840d37292bbc7f6a7e11e22200c976fc900dbc98a7a383a641cb8254a2e56d4e295a847943b4e3897c4a773e930277b4d9fbede8a052686bfacfa";
        let mut root_pub = [0u8; 65];
        for (i, byte) in root_pub.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        let fabric_id: u64 = 0x2906_C908_D115_D362;
        let got = derive_compressed_fabric_id(&root_pub, fabric_id).unwrap();
        assert_eq!(got, [0x87, 0xe1, 0xb0, 0x04, 0xe2, 0x35, 0xa1, 0x30]);
        assert_eq!(pack_be(got), 0x87e1_b004_e235_a130);
    }

    #[test]
    fn synthetic_is_stable_across_reload_and_nonzero() {
        let dir = tempdir();
        let first = load_or_mint_synthetic(dir.path(), 1);
        assert_ne!(first, 0);
        let second = load_or_mint_synthetic(dir.path(), 1);
        assert_eq!(
            first, second,
            "must be stable across a reload of the same dir"
        );
        assert!(is_synthetic(dir.path()));
    }

    #[test]
    fn upgrade_to_real_replaces_the_cache_and_clears_is_synthetic() {
        let dir = tempdir();
        let synthetic = load_or_mint_synthetic(dir.path(), 1);
        let hex = "044a9f42b1ca4840d37292bbc7f6a7e11e22200c976fc900dbc98a7a383a641cb8254a2e56d4e295a847943b4e3897c4a773e930277b4d9fbede8a052686bfacfa";
        let mut root_pub = vec![0u8; 65];
        for (i, byte) in root_pub.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        let real = upgrade_to_real(dir.path(), &root_pub, 1).unwrap();
        assert_ne!(real, synthetic);
        assert!(!is_synthetic(dir.path()));
        assert_eq!(load_or_mint_synthetic(dir.path(), 1), real);
    }

    fn tempdir() -> TempDir {
        TempDir::new()
    }

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            // `SystemTime` resolution on some platforms (macOS included) is coarser than one
            // nanosecond, so two `TempDir::new()` calls from different test threads in the same
            // process can land on the same nanosecond tick and collide on a shared directory name
            // -- each test then reads/writes the other's `mc-fabric.json`, producing exactly the
            // flaky "must be stable across a reload" mismatch this crate's tests were hitting. An
            // in-process atomic counter guarantees uniqueness regardless of clock resolution.
            static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "backend-mc-fabric-identity-test-{}-{}-{}",
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
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
