/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

//! End-to-end proof that a fabric and everything attached to it survives a
//! (simulated) reboot of the device.
//!
//! The first boot seeds a device fabric offline — a NOC for the controller, two
//! ACL entries, (under `groups`) a group key set + key map + group endpoint
//! mapping, and a fabric label — then persists it to a retained key-value store
//! and is torn down. The second boot brings up a *fresh* `Matter` over the
//! *same* store and re-hydrates it via `Matter::startup`. It proves:
//!
//! - the fabric count, node id, fabric id, label, ACL entries and group tables
//!   read back identical to what boot 1 wrote;
//! - a CASE handshake from the controller succeeds against the rebooted device
//!   and a typed `OnOff` read works — so the NOC / IPK / operational keys were
//!   restored intact;
//! - a read by a subject that has no ACL entry is denied with `UnsupportedAccess`;
//! - and, in a second test, removing the fabric before reboot leaves boot 2 with
//!   zero fabrics and a CASE handshake that fails.

#![cfg(all(feature = "std", feature = "async-io"))]

use core::future::Future;
use core::num::NonZeroU8;
use core::pin::pin;

use embassy_futures::select::{select, select3, Either};
use embassy_time::{Duration, Timer};

use log::info;

use rs_matter::acl::{AclEntry, AuthMode};
use rs_matter::cert::gen::VALID_FOREVER;
use rs_matter::cert::MAX_CERT_TLV_AND_ASN1_LEN;
use rs_matter::crypto::{
    test_only_crypto, CanonAeadKey, CanonAeadKeyRef, CanonPkcSecretKey, Crypto, Rng, SecretKey,
    SigningSecretKey, AEAD_CANON_KEY_LEN,
};
use rs_matter::dm::clusters::app::on_off::{
    self, test::TestOnOffDeviceLogic, OnOffClient as _, OnOffHooks as _,
};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::net_comm::DummyNetworks;
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_ON_OFF_LIGHT;
use rs_matter::dm::networks::unix::UnixNetifs;
use rs_matter::dm::{endpoints, Async, DataModel, Dataver, Endpoint, Node, Privilege};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::fabric::FabricPersist;
use rs_matter::im::subscriptions::DEFAULT_MAX_SUBSCRIPTIONS;
use rs_matter::im::{InteractionModel, InteractionModelState};
use rs_matter::onboard::cac::RcacGenerator;
use rs_matter::onboard::noc::NocGenerator;
use rs_matter::persist::{DummyKvBlobStore, FABRIC_KEYS_START};
use rs_matter::respond::{DefaultResponder, Responder};
use rs_matter::sc::case::CaseInitiator;
use rs_matter::sc::SecureChannel;
use rs_matter::transport::exchange::{Exchange, MatterBuffers};
use rs_matter::transport::network::{Address, NoNetwork};
use rs_matter::utils::select::Coalesce;
use rs_matter::{clusters, devices, root_endpoint, Matter};

use crate::common::{create_localhost_socket_pair, init_env_logger, MemKvBlobStore};

#[allow(dead_code)]
mod common;

const TEST_FABRIC_ID: u64 = 1;
const DEVICE_NODE_ID: u64 = 200;
/// The controller's admin identity — seeded as the fabric's `CaseAdminSubject`.
const ADMIN_NODE_ID: u64 = 100;
/// A second subject granted `Operate` in the ACL, to prove multiple entries
/// round-trip. It never actually connects.
const OTHER_SUBJECT_NODE_ID: u64 = 300;
/// A valid operational identity on the same fabric with *no* ACL entry.
const UNAUTH_NODE_ID: u64 = 400;

const ADMIN_VENDOR_ID: u16 = 0xFFF1;
const ENDPOINT: u16 = 1;
const FABRIC_LABEL: &str = "reboot-survivor";

#[cfg(feature = "groups")]
const GROUP_ID: u16 = 0x002A;
#[cfg(feature = "groups")]
const GROUP_KEY_SET_ID: u16 = 0x01A3;
#[cfg(feature = "groups")]
const GROUP_EPOCH_KEY: [u8; 16] = [
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
];

/// The device's data model state on boot 2.
type DeviceDmState = InteractionModelState<DummyNetworks, DEFAULT_MAX_SUBSCRIPTIONS, 0>;

/// The device data model served on boot 2: the standard Ethernet root endpoint
/// plus a single OnOff light on [`ENDPOINT`].
const NODE: Node<'static> = Node {
    endpoints: &[
        root_endpoint!(eth),
        Endpoint::new(
            ENDPOINT,
            devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters!(desc::DescHandler::CLUSTER, TestOnOffDeviceLogic::CLUSTER),
        ),
    ],
};

fn device_data_model<'a>(
    mut rand: impl Rng + Copy,
    on_off: &'a on_off::OnOffHandler<'a, TestOnOffDeviceLogic, on_off::NoLevelControl>,
) -> impl DataModel + 'a {
    (
        NODE,
        endpoints::EthSysHandlerBuilder::new()
            .netif_diag(&UnixNetifs)
            .build(rand)
            .chain(
                |e, c| e == ENDPOINT && c == desc::DescHandler::CLUSTER.id,
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                |e, c| e == ENDPOINT && c == TestOnOffDeviceLogic::CLUSTER.id,
                on_off::HandlerAsyncAdaptor(on_off),
            ),
    )
}

/// One operational identity's pre-signed material: its secret key and its NOC
/// bytes (both owned so they can be installed in any boot scope).
struct Identity {
    key: CanonPkcSecretKey,
    noc: [u8; MAX_CERT_TLV_AND_ASN1_LEN],
    noc_len: usize,
}

/// A fabric's shared material: one RCAC + IPK, and the three identities (device,
/// admin controller, unauthorized controller) all signed against that RCAC.
struct FabricMaterial {
    rcac: [u8; MAX_CERT_TLV_AND_ASN1_LEN],
    rcac_len: usize,
    ipk: CanonAeadKey,
    device: Identity,
    admin: Identity,
    unauth: Identity,
}

impl FabricMaterial {
    fn rcac(&self) -> &[u8] {
        &self.rcac[..self.rcac_len]
    }

    fn ipk(&self) -> CanonAeadKeyRef<'_> {
        self.ipk.reference()
    }
}

impl Identity {
    fn noc(&self) -> &[u8] {
        &self.noc[..self.noc_len]
    }
}

/// Mint the RCAC once and sign all three NOCs against it, so the device and the
/// controller end up on the *same* fabric.
fn mint_fabric_material<C: Crypto>(crypto: &C) -> FabricMaterial {
    let mut rcac_gen_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
    let mut rcac_gen = RcacGenerator::new(&mut rcac_gen_buf);
    let (rcac_priv, rcac) = rcac_gen
        .generate(crypto, TEST_FABRIC_ID, VALID_FOREVER)
        .unwrap();

    let mut rcac_bytes = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
    rcac_bytes[..rcac.len()].copy_from_slice(rcac);
    let rcac_len = rcac.len();

    let mut noc_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
    let mut noc_gen = NocGenerator::create(rcac_priv.reference(), rcac, &[], &mut noc_buf).unwrap();

    let mut mint = |node_id: u64| {
        let sk = crypto.generate_secret_key().unwrap();
        let mut csr_buf = [0u8; 256];
        let csr = sk.csr(&mut csr_buf).unwrap();
        let mut key = CanonPkcSecretKey::new();
        sk.write_canon(&mut key).unwrap();

        let noc_slice = noc_gen
            .generate(crypto, csr, node_id, &[], VALID_FOREVER)
            .unwrap();
        let mut noc = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        noc[..noc_slice.len()].copy_from_slice(noc_slice);
        let noc_len = noc_slice.len();

        Identity { key, noc, noc_len }
    };

    let device = mint(DEVICE_NODE_ID);
    let admin = mint(ADMIN_NODE_ID);
    let unauth = mint(UNAUTH_NODE_ID);

    let mut ipk = CanonAeadKey::new();
    let mut ipk_bytes = [0u8; AEAD_CANON_KEY_LEN];
    crypto.rand().unwrap().fill_bytes(&mut ipk_bytes);
    ipk.load_from_array(&ipk_bytes);

    FabricMaterial {
        rcac: rcac_bytes,
        rcac_len,
        ipk,
        device,
        admin,
        unauth,
    }
}

/// Install `identity` as a new fabric on `matter`, seeding a single admin ACL
/// entry for `admin_subject`. Returns the new fabric index.
fn add_fabric<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    mat: &FabricMaterial,
    identity: &Identity,
    admin_subject: u64,
) -> NonZeroU8 {
    matter
        .with_state(|state| {
            state
                .fabrics
                .add(
                    crypto,
                    identity.key.reference(),
                    mat.rcac(),
                    identity.noc(),
                    &[],
                    Some(mat.ipk()),
                    ADMIN_VENDOR_ID,
                    admin_subject,
                )
                .map(|f| f.fab_idx())
        })
        .unwrap()
}

/// Race a future against a bounded timeout, panicking if it does not complete.
async fn with_timeout<T>(
    secs: u64,
    label: &str,
    fut: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    let mut fut = pin!(fut);
    let mut timeout = pin!(Timer::after(Duration::from_secs(secs)));
    match select(&mut fut, &mut timeout).await {
        Either::First(r) => r,
        Either::Second(_) => panic!("{label} timed out after {secs}s"),
    }
}

/// A fabric with a NOC, two ACL entries, group tables and a label persists on
/// boot 1 and re-hydrates identically on boot 2, where CASE + a typed OnOff read
/// succeed for the admin and are denied for an unlisted subject.
#[test]
fn test_fabric_survives_reboot() {
    // Two in-process Matter stacks plus a full data model do not fit the default
    // 2 MiB test-thread stack.
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            init_env_logger();
            futures_lite::future::block_on(run_fabric_survives_reboot());
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn run_fabric_survives_reboot() {
    let crypto = test_only_crypto();
    let mat = mint_fabric_material(&crypto);

    let store = MemKvBlobStore::default();

    // ---- Boot 1: seed the device fabric offline and persist it. ----
    let boot1_acl: std::vec::Vec<AclEntry> = {
        let device_matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0);

        let fab_idx = device_matter
            .with_state(|state| {
                let fabric = state.fabrics.add(
                    &crypto,
                    mat.device.key.reference(),
                    mat.rcac(),
                    mat.device.noc(),
                    &[],
                    Some(mat.ipk()),
                    ADMIN_VENDOR_ID,
                    ADMIN_NODE_ID,
                )?;
                let fab_idx = fabric.fab_idx();

                // `add` already seeded the admin ACL entry for `ADMIN_NODE_ID`;
                // add a second `Operate` entry for another subject.
                let mut operate = AclEntry::new(None, Privilege::OPERATE, AuthMode::Case);
                operate.add_subject(OTHER_SUBJECT_NODE_ID)?;
                fabric.acl_add(operate)?;

                #[cfg(feature = "groups")]
                {
                    use rs_matter::fabric::GroupKeyMapping;
                    use rs_matter::group_keys::{GroupEpochKeyEntry, GroupKeySet};
                    use rs_matter::utils::storage::Vec;

                    let mut epoch_key = CanonAeadKey::new();
                    epoch_key.load_from_array(&GROUP_EPOCH_KEY);

                    let mut epoch_keys = Vec::new();
                    epoch_keys
                        .push(GroupEpochKeyEntry {
                            epoch_key,
                            epoch_start_time: 1,
                        })
                        .map_err(|_| ErrorCode::ResourceExhausted)?;

                    let groups = fabric.groups_mut();
                    groups.key_set_add(GroupKeySet {
                        group_key_set_id: GROUP_KEY_SET_ID,
                        group_key_security_policy: 0,
                        epoch_keys,
                    })?;
                    groups.key_map_add(GroupKeyMapping {
                        group_id: GROUP_ID,
                        group_key_set_id: GROUP_KEY_SET_ID,
                    })?;
                    groups.add(ENDPOINT, GROUP_ID, "grp")?;
                }

                Ok::<_, Error>(fab_idx)
            })
            .unwrap();

        device_matter
            .with_state(|state| {
                state
                    .fabrics
                    .update_label(fab_idx, FABRIC_LABEL)
                    .map(|_| ())
            })
            .unwrap();

        // Persist the fully-seeded fabric to the retained store.
        let kv = device_matter.kv(store.clone());
        let mut persist = FabricPersist::new(&kv);
        device_matter
            .with_state(|state| persist.store(state.fabrics.fabric(fab_idx)?))
            .unwrap();
        persist.run().unwrap();

        assert!(
            store.contains_key(FABRIC_KEYS_START + fab_idx.get() as u16),
            "boot 1 should have persisted the fabric blob"
        );

        device_matter.with_state(|state| state.fabrics.fabric(fab_idx).unwrap().acl().to_vec())
    };

    assert_eq!(
        boot1_acl.len(),
        2,
        "expected an admin + an operate ACL entry"
    );

    // ---- Boot 2: fresh device, same store, re-hydrate and verify. ----
    let device_matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0);
    device_matter
        .startup(device_matter.kv(store.clone()))
        .unwrap();

    let fab_idx = NonZeroU8::new(1).unwrap();
    device_matter.with_state(|state| {
        assert_eq!(state.fabrics.iter().count(), 1, "one fabric should survive");
        let fabric = state.fabrics.fabric(fab_idx).unwrap();

        assert_eq!(fabric.node_id(), DEVICE_NODE_ID);
        assert_eq!(fabric.fabric_id(), TEST_FABRIC_ID);
        assert_eq!(fabric.label(), FABRIC_LABEL);
        assert_eq!(fabric.acl(), boot1_acl.as_slice(), "ACL must round-trip");

        #[cfg(feature = "groups")]
        {
            let groups = fabric.groups();
            let key_set = groups
                .key_set_get(GROUP_KEY_SET_ID)
                .expect("group key set must survive");
            assert_eq!(key_set.epoch_keys.len(), 1);
            assert_eq!(groups.key_map_get(GROUP_ID), Some(GROUP_KEY_SET_ID));
            assert!(groups
                .get(GROUP_ID)
                .expect("group endpoint mapping must survive")
                .endpoints
                .contains(&ENDPOINT));
        }
    });

    // Build the controller with two fabrics on the same RCAC/IPK: an admin
    // identity (in the ACL) and an unauthorized one (absent from the ACL).
    let ctrl_matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0);
    let admin_fab_idx = add_fabric(&ctrl_matter, &crypto, &mat, &mat.admin, ADMIN_NODE_ID);
    let unauth_fab_idx = add_fabric(&ctrl_matter, &crypto, &mat, &mat.unauth, UNAUTH_NODE_ID);

    // Bring up the device data model + responder and the controller transport.
    let (device_socket, controller_socket) = create_localhost_socket_pair();
    let peer_addr = Address::Udp(device_socket.get_ref().local_addr().unwrap());

    let device_crypto = test_only_crypto();
    let mut rand = device_crypto.rand().unwrap();

    let buffers: MatterBuffers = MatterBuffers::new();
    let state: DeviceDmState = InteractionModelState::new(DummyNetworks);
    let on_off_handler = on_off::OnOffHandler::new_standalone(
        Dataver::new_rand(&mut rand),
        ENDPOINT,
        TestOnOffDeviceLogic::new(false),
    );
    let device_kv = device_matter.kv(DummyKvBlobStore);

    let dm = InteractionModel::new(
        &device_matter,
        &device_crypto,
        &buffers,
        device_data_model(rand, &on_off_handler),
        &device_kv,
        &state,
    );
    let responder = DefaultResponder::new(&dm);

    let device_fut = async {
        select3(
            device_matter.run(&device_crypto, &device_socket, &device_socket, NoNetwork),
            responder.run::<4, 4>(),
            dm.run(),
        )
        .coalesce()
        .await
    };

    let controller_fut = async {
        let mut transport =
            pin!(ctrl_matter.run(&crypto, &controller_socket, &controller_socket, NoNetwork,));
        let mut flow = pin!(async {
            // Admin: CASE, then a typed OnOff read that must succeed.
            info!("Admin CASE handshake against the rebooted device...");
            let exchange = Exchange::initiate_plaintext(&ctrl_matter, &crypto, peer_addr).await?;
            with_timeout(
                30,
                "admin CASE",
                CaseInitiator::perform(exchange, &crypto, admin_fab_idx, DEVICE_NODE_ID),
            )
            .await?;

            let exchange = Exchange::initiate(
                &ctrl_matter,
                test_only_crypto(),
                admin_fab_idx,
                DEVICE_NODE_ID,
            )
            .await?;
            let value = with_timeout(
                10,
                "admin OnOff read",
                exchange.on_off().on_off_read(ENDPOINT),
            )
            .await?;
            assert!(!value, "the light starts Off");

            // Unauthorized subject: CASE succeeds (valid NOC on the fabric) but
            // the OnOff read is denied by ACL.
            info!("Unauthorized-subject CASE handshake...");
            let exchange = Exchange::initiate_plaintext(&ctrl_matter, &crypto, peer_addr).await?;
            with_timeout(
                30,
                "unauthorized CASE",
                CaseInitiator::perform(exchange, &crypto, unauth_fab_idx, DEVICE_NODE_ID),
            )
            .await?;

            let exchange = Exchange::initiate(
                &ctrl_matter,
                test_only_crypto(),
                unauth_fab_idx,
                DEVICE_NODE_ID,
            )
            .await?;
            let denied = with_timeout(10, "unauthorized OnOff read", async {
                Ok::<_, Error>(exchange.on_off().on_off_read(ENDPOINT).await)
            })
            .await?;
            assert!(
                matches!(
                    denied.as_ref().map_err(|e| e.code()),
                    Err(ErrorCode::UnsupportedAccess)
                ),
                "a subject with no ACL entry must be denied, got {denied:?}"
            );

            Ok::<_, Error>(())
        });

        match select(&mut transport, &mut flow).await {
            Either::First(r) => panic!("controller transport exited prematurely: {r:?}"),
            Either::Second(result) => {
                let mut flush = pin!(Timer::after(Duration::from_millis(300)));
                let _ = select(&mut transport, &mut flush).await;
                result
            }
        }
    };

    let mut device_fut = pin!(device_fut);
    let mut controller_fut = pin!(controller_fut);
    match select(&mut device_fut, &mut controller_fut).await {
        Either::First(r) => panic!("device exited unexpectedly: {r:?}"),
        Either::Second(result) => result.unwrap(),
    }
}

/// Removing the fabric before the reboot leaves boot 2 with zero fabrics, and a
/// CASE handshake against the device then fails.
#[test]
fn test_removed_fabric_gone_after_reboot() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            init_env_logger();
            futures_lite::future::block_on(run_removed_fabric_gone_after_reboot());
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn run_removed_fabric_gone_after_reboot() {
    let crypto = test_only_crypto();
    let mat = mint_fabric_material(&crypto);

    let store = MemKvBlobStore::default();

    // ---- Boot 1: seed a fabric, persist, then remove it (store included). ----
    {
        let device_matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0);
        let fab_idx = add_fabric(&device_matter, &crypto, &mat, &mat.device, ADMIN_NODE_ID);

        let kv = device_matter.kv(store.clone());
        let mut persist = FabricPersist::new(&kv);
        device_matter
            .with_state(|state| persist.store(state.fabrics.fabric(fab_idx)?))
            .unwrap();
        persist.run().unwrap();
        assert!(store.contains_key(FABRIC_KEYS_START + fab_idx.get() as u16));

        // Remove the fabric from memory and from the store.
        device_matter
            .with_state(|state| state.fabrics.remove(fab_idx))
            .unwrap();
        let mut persist = FabricPersist::new(&kv);
        persist.remove(fab_idx).unwrap();
        persist.run().unwrap();
        assert!(
            !store.contains_key(FABRIC_KEYS_START + fab_idx.get() as u16),
            "the removed fabric must be gone from storage"
        );
    }

    // ---- Boot 2: fresh device over the same store — no fabrics. ----
    let device_matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0);
    device_matter
        .startup(device_matter.kv(store.clone()))
        .unwrap();
    device_matter.with_state(|state| {
        assert_eq!(
            state.fabrics.iter().count(),
            0,
            "the removed fabric must not come back"
        );
    });

    // The controller keeps an admin fabric; CASE against the fabric-less device
    // must fail.
    let ctrl_matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0);
    let admin_fab_idx = add_fabric(&ctrl_matter, &crypto, &mat, &mat.admin, ADMIN_NODE_ID);

    let (device_socket, controller_socket) = create_localhost_socket_pair();
    let peer_addr = Address::Udp(device_socket.get_ref().local_addr().unwrap());

    let sc = SecureChannel::new(&crypto, &());
    let responder = Responder::new("device", sc, &device_matter, 0);

    let device_fut = async {
        select(
            device_matter.run(&crypto, &device_socket, &device_socket, NoNetwork),
            responder.run::<4>(),
        )
        .coalesce()
        .await
    };

    let controller_fut = async {
        let mut transport =
            pin!(ctrl_matter.run(&crypto, &controller_socket, &controller_socket, NoNetwork,));
        let mut flow = pin!(async {
            let exchange = Exchange::initiate_plaintext(&ctrl_matter, &crypto, peer_addr).await?;
            let mut perform = pin!(CaseInitiator::perform(
                exchange,
                &crypto,
                admin_fab_idx,
                DEVICE_NODE_ID,
            ));
            let mut timeout = pin!(Timer::after(Duration::from_secs(15)));
            match select(&mut perform, &mut timeout).await {
                Either::First(r) => assert!(
                    r.is_err(),
                    "CASE unexpectedly succeeded against a device with no fabrics"
                ),
                // A timeout also proves the handshake never completed.
                Either::Second(_) => info!("CASE did not complete (timed out) — as expected"),
            }
            Ok::<_, Error>(())
        });

        match select(&mut transport, &mut flow).await {
            Either::First(r) => panic!("controller transport exited prematurely: {r:?}"),
            Either::Second(result) => result,
        }
    };

    let mut device_fut = pin!(device_fut);
    let mut controller_fut = pin!(controller_fut);
    match select(&mut device_fut, &mut controller_fut).await {
        Either::First(r) => panic!("device exited unexpectedly: {r:?}"),
        Either::Second(result) => result.unwrap(),
    }
}
