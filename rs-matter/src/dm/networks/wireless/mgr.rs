/*
 *
 *    Copyright (c) 2025-2026 Project CHIP Authors
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

//! This module contains a wireless manager that - post commissioning - tries to maintain the wireless connectivity.

use core::pin::pin;

use embassy_futures::select::select;
use embassy_time::Timer;

use crate::dm::clusters::net_comm::{self, NetCtlError, NetworksError, WirelessCreds};
use crate::dm::clusters::wifi_diag;
use crate::error::{Error, ErrorCode};
use crate::utils::select::Coalesce;

use super::thread::Thread;
use super::{NetChangeNotif, OwnedWirelessNetworkId};

/// The maximum size of one network credentials
pub const MAX_CREDS_SIZE: usize = 256;

/// A wireless manager that - post commissioning - tries to maintain the wireless connectivity.
///
/// It does so by by connecting to the networks in a round-robin fashion
/// and retrying multiple times the current network in case of a failure,
/// prior to moving to the next network.
pub struct WirelessMgr<'a, W, T> {
    networks: W,
    net_ctl: T,
    buf: &'a mut [u8; MAX_CREDS_SIZE],
}

impl<'a, W, T> WirelessMgr<'a, W, T>
where
    W: net_comm::NetworksAccess + NetChangeNotif,
    T: net_comm::NetCtl + net_comm::NetCtlStatus + wifi_diag::WirelessDiag + NetChangeNotif,
{
    /// Creates a new `WirelessMgr` instance.
    ///
    /// # Arguments
    /// - `networks`: A reference to the networks storage.
    /// - `net_ctl`: A reference to the network controller.
    /// - `buf`: A mutable buffer used as temp credentials storage.
    pub const fn new(networks: W, net_ctl: T, buf: &'a mut [u8; MAX_CREDS_SIZE]) -> Self {
        Self {
            networks,
            net_ctl,
            buf,
        }
    }

    /// Runs the wireless manager.
    ///
    /// This function will try to connect to the networks in a round-robin fashion
    /// and will retry multiple times the current network in case of a failure, prior to
    /// moving to the next network.
    pub async fn run(&mut self) -> Result<(), Error> {
        loop {
            // Stay hands-off while the store is unmanaged: either the device
            // was never commissioned (store empty), or network changes are
            // currently staged under an armed fail-safe - in both cases the
            // commissioner drives connectivity explicitly via
            // `ConnectNetwork`, and the manager must not race it.
            Self::wait_while_not_managed(&self.networks).await?;

            // The store became managed (commit or revert), so start trying to
            // connect to the networks. Do it while the networks don't change.
            let mut changed = pin!(Self::wait_while_not_changed(&self.networks));
            let mut connect = pin!(Self::run_connect(&self.networks, &self.net_ctl, self.buf));

            select(&mut changed, &mut connect).coalesce().await?;
        }
    }

    /// Perform a single, one-shot connect to the network with the given ID.
    ///
    /// Unlike [`WirelessMgr::run`] - which is the operational connectivity
    /// maintainer and therefore only acts once the device is commissioned - this
    /// method connects immediately, regardless of the commissioning status.
    ///
    /// It exists to support **non-concurrent** commissioning over BLE: there, the
    /// commissioner's `ConnectNetwork` command arrives while the operational
    /// (Wifi/Thread) network cannot yet run (the radio is busy with BLE), so the
    /// actual connect must be *deferred* and replayed once BLE is torn down and
    /// the operational network is brought up - but still *before* commissioning
    /// completes (the commissioner re-establishes a CASE session over the
    /// operational network and only then sends `CommissioningComplete`).
    ///
    /// The credentials are looked up by `network_id` from the networks storage
    /// (they were stored earlier by the commissioner's `AddOrUpdate*Network`
    /// command). Returns `Ok(())` on a successful connect; the same retry/backoff
    /// as the operational loop is applied before giving up.
    pub async fn connect_once(&mut self, network_id: &[u8]) -> Result<(), Error> {
        let creds = Self::creds(&self.networks, network_id, self.buf)?;

        let Some(creds) = creds else {
            warn!("No network with the requested ID found; cannot perform the deferred connect");
            return Err(ErrorCode::InvalidData.into());
        };

        match Self::connect(&self.net_ctl, &creds).await {
            Ok(()) => Ok(()),
            // Surface the underlying error verbatim, or map a typed connection
            // failure to a generic "no network interface" error.
            Err(NetCtlError::Other(e)) => Err(e),
            Err(_) => Err(ErrorCode::NoNetworkInterface.into()),
        }
    }

    async fn run_connect(networks: &W, net_ctl: &T, buf: &mut [u8]) -> Result<(), Error> {
        // Try to connect to the networks in a round-robin fashion until we succeed or the commissioning status changes.

        // A "connected" device parks the manager here - but only while the
        // network it is connected to is (still) one of the stored ones. When
        // the fail-safe expires and reverts the networks store, the device
        // may well remain attached to a network that is no longer stored
        // (`TC_CNET_4_12`: `ConnectNetwork` moved it to a staged network,
        // then the fail-safe rolled the store back) - treating plain
        // "connected" as terminal would strand it there forever, because the
        // cluster handler that performed the staged connect is not coming
        // back to undo it. Skipping the wait sends the manager into the
        // round-robin below, which moves the device back onto a stored
        // network.
        //
        // Racing the commissioner is not a concern here: every staged
        // (fail-safe-gated) network mutation - `AddOrUpdate*` / `Remove` /
        // `Reorder` / `ConnectNetwork` - flips the store to unmanaged, so
        // for the remainder of such a window [`WirelessMgr::run`] holds the
        // manager in `wait_while_not_managed` instead of here.
        if Self::connected_network_stored(networks, net_ctl)? {
            Self::wait_while_connected_status(net_ctl, true).await?;
        }

        let mut network_id = OwnedWirelessNetworkId::new();

        loop {
            let creds = Self::next_creds(
                networks,
                (!network_id.is_empty()).then(|| network_id.as_slice()),
                buf,
            )?;

            network_id.clear();

            if let Some(creds) = creds {
                match creds {
                    WirelessCreds::Wifi { ssid, .. } => {
                        network_id
                            .extend_from_slice(ssid)
                            .map_err(|_| ErrorCode::InvalidData)?;
                    }
                    WirelessCreds::Thread { dataset_tlv } => {
                        network_id
                            .extend_from_slice(Thread::dataset_ext_pan_id(dataset_tlv)?)
                            .map_err(|_| ErrorCode::InvalidData)?;
                    }
                }

                loop {
                    if Self::connect(net_ctl, &creds).await.is_err() {
                        // We failed to (re)connect to the current network after multiple attempts,
                        // try the next one
                        break;
                    }

                    Self::wait_while_connected_status(net_ctl, true).await?;
                }
            } else {
                // No networks to connect to, wait for a change in the networks state before trying again
                core::future::pending::<()>().await;
            }
        }
    }

    /// Look up the credentials for a specific `network_id`, copying them into
    /// `buf` and returning a `WirelessCreds` borrowing from it (or `None` if no
    /// such network is recorded). Mirrors [`WirelessMgr::next_creds`] but selects
    /// a network by ID rather than by round-robin position.
    fn creds<'d>(
        networks: &W,
        network_id: &[u8],
        buf: &'d mut [u8],
    ) -> Result<Option<WirelessCreds<'d>>, Error> {
        let mut offsets = None;

        let found = networks.access(|networks| {
            networks.creds(network_id, &mut |creds| {
                offsets = Some(Self::copy_creds(buf, creds)?);

                Ok(())
            })
        });

        // A missing network is not an error here - the caller decides what to do.
        if matches!(found, Err(NetworksError::NetworkIdNotFound)) {
            return Ok(None);
        }

        found.map_err(|e| match e {
            NetworksError::Other(e) => e,
            _ => ErrorCode::InvalidData.into(),
        })?;

        Ok(offsets.map(|offsets| Self::rebuild_creds(buf, offsets)))
    }

    fn next_creds<'d>(
        networks: &W,
        last_network_id: Option<&[u8]>,
        buf: &'d mut [u8],
    ) -> Result<Option<WirelessCreds<'d>>, Error> {
        let mut offsets = None;

        networks.access(|networks| {
            networks.next_creds(last_network_id, &mut |creds| {
                offsets = Some(Self::copy_creds(buf, creds)?);

                Ok(())
            })
        })?;

        Ok(offsets.map(|offsets| Self::rebuild_creds(buf, offsets)))
    }

    /// Copy the credentials yielded by a `Networks` accessor into `buf`,
    /// returning the byte offsets of the copied fields: `(len1, Some(len2))` for
    /// WiFi (`ssid` then `pass`), or `(len1, None)` for Thread (the dataset TLV).
    ///
    /// The yielded `WirelessCreds` borrow from the (locked) networks storage, so
    /// they cannot outlive the accessor; copying into the caller's `buf` lets the
    /// credentials be used (e.g. passed to `connect`) outside the lock. Pair with
    /// [`WirelessMgr::rebuild_creds`] to turn the offsets back into a borrowing
    /// `WirelessCreds`.
    fn copy_creds(buf: &mut [u8], creds: &WirelessCreds) -> Result<(usize, Option<usize>), Error> {
        match creds {
            WirelessCreds::Wifi { ssid, pass } => {
                if ssid.len() + pass.len() > buf.len() {
                    error!("SSID and password too large");
                    return Err(ErrorCode::InvalidData.into());
                }

                buf[..ssid.len()].copy_from_slice(ssid);
                buf[ssid.len()..][..pass.len()].copy_from_slice(pass);

                Ok((ssid.len(), Some(pass.len())))
            }
            WirelessCreds::Thread { dataset_tlv } => {
                if dataset_tlv.len() > buf.len() {
                    error!("Dataset TLV too large");
                    return Err(ErrorCode::InvalidData.into());
                }

                buf[..dataset_tlv.len()].copy_from_slice(dataset_tlv);

                Ok((dataset_tlv.len(), None))
            }
        }
    }

    /// Reconstruct a `WirelessCreds` borrowing from `buf`, given the offsets
    /// returned by [`WirelessMgr::copy_creds`].
    fn rebuild_creds(buf: &[u8], (len1, len2): (usize, Option<usize>)) -> WirelessCreds<'_> {
        if let Some(len2) = len2 {
            WirelessCreds::Wifi {
                ssid: &buf[..len1],
                pass: &buf[len1..][..len2],
            }
        } else {
            WirelessCreds::Thread {
                dataset_tlv: &buf[..len1],
            }
        }
    }

    async fn connect(net_ctl: &T, creds: &WirelessCreds<'_>) -> Result<(), NetCtlError> {
        let delays = [2, 5, 10];
        let mut result = Ok(());

        for (attempt, delay) in delays.iter().copied().enumerate() {
            info!("Connecting to network with ID {}", creds);

            result = net_ctl.connect(creds).await;

            if result.is_ok() {
                break;
            } else if attempt < delays.len() - 1 {
                warn!(
                    "Connection to network with ID {} failed: {:?}, retrying in {}s",
                    creds, result, delay
                );

                Timer::after_secs(delay).await;
            }
        }

        if let Err(e) = &result {
            error!("Failed to connect to network with ID {}: {:?}", creds, e);
        }

        result
    }

    /// Whether the network of the last (successful) connect operation is
    /// present in the networks store.
    ///
    /// An unknown last network (no connect recorded yet) counts as "not
    /// stored": if the device nevertheless reports link-level connectivity,
    /// the manager proceeds to (re)connect to a stored network, which is at
    /// worst an idempotent re-connect.
    ///
    /// NB: the last-operation network ID is also updated by directed *scans*,
    /// so a scan of a foreign network while connected can make this
    /// spuriously return `false` once - the resulting reconnect to the
    /// current network is benign.
    fn connected_network_stored(networks: &W, net_ctl: &T) -> Result<bool, Error> {
        net_ctl.last_network_id(|id| {
            let Some(id) = id else {
                return Ok(false);
            };

            if id.is_empty() {
                return Ok(false);
            }

            let mut found = false;

            networks.access(|networks| {
                networks.networks(&mut |network_id| {
                    found |= network_id == id;

                    Ok(())
                })
            })?;

            Ok(found)
        })
    }

    async fn wait_while_connected_status(net_ctl: &T, connected: bool) -> Result<(), Error> {
        loop {
            if connected != net_ctl.connected()? {
                break Ok(());
            }

            net_ctl.wait_changed().await;
        }
    }

    async fn wait_while_not_managed(networks: &W) -> Result<(), Error> {
        loop {
            let managed = networks.access(|networks| networks.managed())?;
            if managed {
                break Ok(());
            }

            Self::wait_while_not_changed(networks).await?;
        }
    }

    async fn wait_while_not_changed(networks: &W) -> Result<(), Error> {
        networks.wait_changed().await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::cell::Cell;

    use crate::dm::clusters::net_comm::{
        self, NetCtlError, NetCtlStatus, NetworkScanInfo, NetworkType, NetworksAccess,
        SharedNetworks, WirelessCreds,
    };
    use crate::dm::clusters::wifi_diag;
    use crate::dm::networks::wireless::wifi::WifiNetworks;
    use crate::dm::networks::NetChangeNotif;
    use crate::error::{Error, ErrorCode};
    use crate::utils::sync::DynBase;

    // ── Helper: create SharedNetworks<WifiNetworks> with entries ──

    type TestNetworks = SharedNetworks<WifiNetworks<4>>;

    fn make_networks(entries: &[(&[u8], &[u8])], managed: bool) -> TestNetworks {
        let shared = SharedNetworks::new(WifiNetworks::new());

        shared.access(|networks| {
            for &(ssid, pass) in entries {
                networks
                    .add_or_update(&WirelessCreds::Wifi { ssid, pass })
                    .unwrap();
            }

            if managed {
                networks.set_managed(true).unwrap();
            }
        });

        shared
    }

    // ── Fake NetCtl (no production equivalent with controllable state) ──

    struct FakeNetCtl {
        connected: Cell<bool>,
        connect_fails_remaining: Cell<u32>,
        connect_calls: Cell<u32>,
        /// The SSID of the last `connect` call (successful or not) - what a
        /// `NetCtlWithStatusImpl` would report as `LastNetworkID`. Seedable
        /// by tests to model a device attached to a network the manager did
        /// not connect itself (e.g. via the cluster's `ConnectNetwork`).
        last_network_id: core::cell::RefCell<heapless::Vec<u8, 32>>,
    }

    impl FakeNetCtl {
        fn new() -> Self {
            Self {
                connected: Cell::new(false),
                connect_fails_remaining: Cell::new(0),
                connect_calls: Cell::new(0),
                last_network_id: core::cell::RefCell::new(heapless::Vec::new()),
            }
        }

        fn with_connected_to(network_id: &[u8]) -> Self {
            let this = Self::new();

            this.connected.set(true);
            this.last_network_id
                .borrow_mut()
                .extend_from_slice(network_id)
                .unwrap();

            this
        }
    }

    impl net_comm::NetCtl for FakeNetCtl {
        fn net_type(&self) -> NetworkType {
            NetworkType::Wifi
        }

        async fn scan<F>(&self, _network: Option<&[u8]>, _f: F) -> Result<(), NetCtlError>
        where
            F: FnMut(&NetworkScanInfo) -> Result<(), Error>,
        {
            Err(NetCtlError::Other(ErrorCode::InvalidAction.into()))
        }

        async fn connect(&self, creds: &WirelessCreds<'_>) -> Result<(), NetCtlError> {
            self.connect_calls.set(self.connect_calls.get() + 1);

            if let WirelessCreds::Wifi { ssid, .. } = creds {
                let mut last = self.last_network_id.borrow_mut();
                last.clear();
                last.extend_from_slice(ssid).unwrap();
            }

            let remaining = self.connect_fails_remaining.get();
            if remaining > 0 {
                self.connect_fails_remaining.set(remaining - 1);
                Err(NetCtlError::OtherConnectionFailure)
            } else {
                self.connected.set(true);
                Ok(())
            }
        }
    }

    impl DynBase for FakeNetCtl {}

    impl net_comm::NetCtlStatus for FakeNetCtl {
        fn last_networking_status(
            &self,
        ) -> Result<Option<net_comm::NetworkCommissioningStatusEnum>, Error> {
            Ok(None)
        }

        fn last_network_id<F, R>(&self, f: F) -> Result<R, Error>
        where
            F: FnOnce(Option<&[u8]>) -> Result<R, Error>,
        {
            let last = self.last_network_id.borrow();

            f((!last.is_empty()).then_some(last.as_slice()))
        }

        fn last_connect_error_value(&self) -> Result<Option<i32>, Error> {
            Ok(None)
        }
    }

    impl wifi_diag::WirelessDiag for FakeNetCtl {
        fn connected(&self) -> Result<bool, Error> {
            Ok(self.connected.get())
        }
    }

    impl NetChangeNotif for FakeNetCtl {
        async fn wait_changed(&self) {
            core::future::pending().await
        }
    }

    // Type alias for the test WirelessMgr
    type TestMgr<'a> = WirelessMgr<'a, TestNetworks, FakeNetCtl>;

    // ── next_creds tests ──

    #[test]
    fn next_creds_empty_returns_none() {
        let networks = make_networks(&[], false);
        let mut buf = [0u8; MAX_CREDS_SIZE];

        let result = TestMgr::next_creds(&networks, None, &mut buf).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn next_creds_single_wifi() {
        let networks = make_networks(&[(b"MySSID", b"MyPass")], false);
        let mut buf = [0u8; MAX_CREDS_SIZE];

        let creds = TestMgr::next_creds(&networks, None, &mut buf)
            .unwrap()
            .unwrap();
        match creds {
            WirelessCreds::Wifi { ssid, pass } => {
                assert_eq!(ssid, b"MySSID");
                assert_eq!(pass, b"MyPass");
            }
            _ => panic!("Expected WiFi creds"),
        }
    }

    #[test]
    fn next_creds_single_wifi_wraps_to_itself() {
        let networks = make_networks(&[(b"Only", b"Net")], false);
        let mut buf = [0u8; MAX_CREDS_SIZE];

        let creds = TestMgr::next_creds(&networks, Some(b"Only"), &mut buf)
            .unwrap()
            .unwrap();
        match creds {
            WirelessCreds::Wifi { ssid, .. } => assert_eq!(ssid, b"Only"),
            _ => panic!("Expected WiFi creds"),
        }
    }

    #[test]
    fn next_creds_round_robin() {
        let networks = make_networks(
            &[
                (b"Net1", b"Pass1"),
                (b"Net2", b"Pass2"),
                (b"Net3", b"Pass3"),
            ],
            false,
        );
        let mut buf = [0u8; MAX_CREDS_SIZE];

        // None → first network
        let creds = TestMgr::next_creds(&networks, None, &mut buf)
            .unwrap()
            .unwrap();
        assert!(matches!(creds, WirelessCreds::Wifi { ssid, .. } if ssid == b"Net1"));

        // After Net1 → Net2
        let creds = TestMgr::next_creds(&networks, Some(b"Net1"), &mut buf)
            .unwrap()
            .unwrap();
        assert!(matches!(creds, WirelessCreds::Wifi { ssid, .. } if ssid == b"Net2"));

        // After Net2 → Net3
        let creds = TestMgr::next_creds(&networks, Some(b"Net2"), &mut buf)
            .unwrap()
            .unwrap();
        assert!(matches!(creds, WirelessCreds::Wifi { ssid, .. } if ssid == b"Net3"));

        // After Net3 → wraps to Net1
        let creds = TestMgr::next_creds(&networks, Some(b"Net3"), &mut buf)
            .unwrap()
            .unwrap();
        assert!(matches!(creds, WirelessCreds::Wifi { ssid, .. } if ssid == b"Net1"));
    }

    #[test]
    fn next_creds_unknown_last_id_returns_first() {
        let networks = make_networks(&[(b"Net1", b"Pass1"), (b"Net2", b"Pass2")], false);
        let mut buf = [0u8; MAX_CREDS_SIZE];

        let creds = TestMgr::next_creds(&networks, Some(b"NoSuchNet"), &mut buf)
            .unwrap()
            .unwrap();
        assert!(matches!(creds, WirelessCreds::Wifi { ssid, .. } if ssid == b"Net1"));
    }

    #[test]
    fn next_creds_copies_into_buffer() {
        let networks = make_networks(&[(b"SSID_A", b"secret123")], false);
        let mut buf = [0u8; MAX_CREDS_SIZE];

        let creds = TestMgr::next_creds(&networks, None, &mut buf)
            .unwrap()
            .unwrap();
        match creds {
            WirelessCreds::Wifi { ssid, pass } => {
                assert_eq!(ssid, b"SSID_A");
                assert_eq!(pass, b"secret123");
                assert_eq!(&buf[..6], b"SSID_A");
                assert_eq!(&buf[6..15], b"secret123");
            }
            _ => panic!("Expected WiFi creds"),
        }
    }

    // ── connect tests ──

    #[test]
    fn connect_succeeds_immediately() {
        let net_ctl = FakeNetCtl::new();
        let creds = WirelessCreds::Wifi {
            ssid: b"Test",
            pass: b"Pass",
        };

        embassy_futures::block_on(async {
            let result = TestMgr::connect(&net_ctl, &creds).await;
            assert!(result.is_ok());
            assert!(net_ctl.connected.get());
        });
    }

    // ── commissioned tests ──

    #[test]
    fn wait_while_not_managed_returns_when_managed() {
        let networks = make_networks(&[], true);

        embassy_futures::block_on(async {
            let result = TestMgr::wait_while_not_managed(&networks).await;
            assert!(result.is_ok());
        });
    }

    // ── connected-status tests ──

    #[test]
    fn wait_while_connected_returns_when_disconnected() {
        let net_ctl = FakeNetCtl::new();

        embassy_futures::block_on(async {
            // wait_while_connected_status(net_ctl, true) breaks when connected() != true
            // Since FakeNetCtl starts disconnected, this should return immediately.
            let result = TestMgr::wait_while_connected_status(&net_ctl, true).await;
            assert!(result.is_ok());
        });
    }

    // ── post-revert reconnect tests ──

    /// Run `fut` until `done` reports completion, panicking if `fut` exits
    /// first. `fut` is the (never-ending) manager future under test.
    async fn drive_until<F: core::future::Future + Unpin>(fut: F, done: impl Fn() -> bool) {
        use embassy_futures::select::{select, Either};

        let watcher = async {
            while !done() {
                embassy_futures::yield_now().await;
            }
        };

        match select(fut, pin!(watcher)).await {
            Either::First(_) => panic!("manager future exited unexpectedly"),
            Either::Second(()) => {}
        }
    }

    #[test]
    fn run_connect_reconnects_when_connected_network_not_stored() {
        // The device is attached to a network that is NOT in the store: the
        // `TC_CNET_4_12` ending, where a staged `ConnectNetwork` moved the
        // device and the fail-safe then reverted the store. "Connected" must
        // not park the manager; it must move the device onto a stored
        // network.
        let networks = make_networks(&[(b"Stored", b"Pass")], true);
        let net_ctl = FakeNetCtl::with_connected_to(b"Gone");
        let mut buf = [0u8; MAX_CREDS_SIZE];

        embassy_futures::block_on(async {
            let connect = pin!(TestMgr::run_connect(&networks, &net_ctl, &mut buf));

            drive_until(connect, || {
                net_ctl
                    .last_network_id(|id| Ok(id == Some(b"Stored".as_slice())))
                    .unwrap()
            })
            .await;
        });

        assert_eq!(net_ctl.connect_calls.get(), 1);
    }

    #[test]
    fn run_connect_stays_put_when_connected_network_stored() {
        // The inverse: attached to a network that IS stored - the manager
        // must park in the connected-wait without issuing any connect.
        let networks = make_networks(&[(b"Stored", b"Pass")], true);
        let net_ctl = FakeNetCtl::with_connected_to(b"Stored");
        let mut buf = [0u8; MAX_CREDS_SIZE];

        embassy_futures::block_on(async {
            let connect = pin!(TestMgr::run_connect(&networks, &net_ctl, &mut buf));

            // Give the manager a bounded number of polls to (wrongly) act.
            let polls = Cell::new(0u32);
            drive_until(connect, || {
                polls.set(polls.get() + 1);
                polls.get() > 64
            })
            .await;
        });

        assert_eq!(net_ctl.connect_calls.get(), 0);
    }

    // ── creds-by-id / connect_once tests (deferred non-concurrent connect) ──

    #[test]
    fn creds_by_id_returns_matching_or_none() {
        let networks = make_networks(
            &[(b"MySSID", b"MyPass"), (b"OtherSSID", b"OtherPass")],
            false,
        );
        let mut buf = [0u8; MAX_CREDS_SIZE];

        // An existing network is looked up by id.
        let creds = TestMgr::creds(&networks, b"MySSID", &mut buf)
            .unwrap()
            .unwrap();
        match creds {
            WirelessCreds::Wifi { ssid, pass } => {
                assert_eq!(ssid, b"MySSID");
                assert_eq!(pass, b"MyPass");
            }
            _ => panic!("Expected WiFi creds"),
        }

        // A missing network is `Ok(None)` (not found), not an error.
        assert!(TestMgr::creds(&networks, b"NonExistent", &mut buf)
            .unwrap()
            .is_none());
    }

    #[test]
    fn connect_once_connects_to_named_network() {
        let networks = make_networks(&[(b"MySSID", b"MyPass")], false);
        let net_ctl = FakeNetCtl::new();
        let mut buf = [0u8; MAX_CREDS_SIZE];
        // `new` takes the networks/net_ctl by value, so the manager owns them;
        // `Ok` already implies `FakeNetCtl::connect` ran (its only `Ok` path
        // sets `connected = true`), so there's no need to inspect it afterwards.
        let mut mgr = TestMgr::new(networks, net_ctl, &mut buf);

        embassy_futures::block_on(async {
            assert!(mgr.connect_once(b"MySSID").await.is_ok());
        });
    }

    #[test]
    fn connect_once_unknown_network_is_invalid_data() {
        let networks = make_networks(&[], false);
        let net_ctl = FakeNetCtl::new();
        let mut buf = [0u8; MAX_CREDS_SIZE];
        let mut mgr = TestMgr::new(networks, net_ctl, &mut buf);

        embassy_futures::block_on(async {
            // No matching network -> a deferred connect can't proceed.
            let err = mgr.connect_once(b"MySSID").await.unwrap_err();
            assert!(matches!(err.code(), ErrorCode::InvalidData));
        });
    }
}
