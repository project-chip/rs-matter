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

//! Runs the stack over an in-memory network stack and fake drivers, and checks
//! which network each driver brings up, and when.

use core::future::{pending, ready, Future};
use core::mem::MaybeUninit;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use std::sync::Mutex;

use rs_matter_crypto::test_only_crypto;
use rs_matter_dm::clusters::gen_diag::{GenDiag, InterfaceTypeEnum, NetifDiag, NetifInfo};
use rs_matter_dm::clusters::net_comm::{NetworkType, Networks};
use rs_matter_dm::endpoints::ROOT_ENDPOINT_ID;
use rs_matter_dm::networks::any::AnyNetworks;
use rs_matter_dm::networks::eth::EthNetwork;
use rs_matter_dm::networks::wireless::{NoopWirelessNetCtl, ThreadNetworks, WifiNetworks};
use rs_matter_dm::networks::NetChangeNotif;
use rs_matter_dm_core::persist::{KvBlobStore, MemKvBlobStore, NETWORKS_KEY};
use rs_matter_dm_core::{Async, EmptyHandler, Node};
use rs_matter_node::Matter;
use rs_matter_node::MATTER_PORT;
use rs_matter_node_core::test_device::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter_stack::any::{AnyDriver, AnyNetDriver};
use rs_matter_stack::ble::GattPeripheral;
use rs_matter_stack::eth::{EthernetDriver, EthernetTask, PreexistingEthernet};
use rs_matter_stack::net::{NetSocket, NetStack};
use rs_matter_stack::wireless::{
    GattDriver, GattTask, PreexistingWireless, ThreadCoexDriver, ThreadCoexTask, ThreadDriver,
    ThreadTask, WifiCoexDriver, WifiCoexTask, WifiDriver, WifiTask,
};
use rs_matter_stack::{MatterStack, Options, RunOptions, UserTask};
use rs_matter_transport::network::btp::{AdvData, Btp};
use rs_matter_transport::network::mdns::builtin::BuiltinMdns;
use rs_matter_transport::network::mdns::{
    MDNS_IPV4_BROADCAST_ADDR, MDNS_IPV6_BROADCAST_ADDR, MDNS_PORT,
};
use rs_matter_transport::network::{Address, NetworkMulticast, NetworkSend, NoNetwork};
use rs_matter_utils::error::Error;
use rs_matter_utils::futures::{select, Either};
use rs_matter_utils::init::InitMaybeUninit;
use rs_matter_utils::sync::MaybeSend;
use rs_matter_utils::timers::{Duration, Timer};

const BUMP_SIZE: usize = 64 * 1024;

const IPV4_INTERFACE: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 10);
const IPV6_ADDR: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
const IPV6_INTERFACE: u32 = 7;

type EthMatterStack<'a, const B: usize> = MatterStack<'a, B, EthNetwork<'static>>;
type WifiMatterStack<'a, const B: usize> = MatterStack<'a, B, WifiNetworks>;
type ThreadMatterStack<'a, const B: usize> = MatterStack<'a, B, ThreadNetworks>;
type AnyMatterStack<'a, const B: usize> = MatterStack<'a, B, AnyNetworks>;

/// What the fakes saw.
#[derive(Default)]
struct Log {
    binds: Mutex<Vec<(u16, Ipv4Addr, u32)>>,
    joins: Mutex<Vec<IpAddr>>,
    sends: Mutex<usize>,
    events: Mutex<Vec<&'static str>>,
}

impl Log {
    fn event(&self, event: &'static str) {
        self.events.lock().unwrap().push(event);
    }

    fn events(&self) -> Vec<&'static str> {
        self.events.lock().unwrap().clone()
    }

    fn bound_ports(&self) -> Vec<u16> {
        self.binds.lock().unwrap().iter().map(|b| b.0).collect()
    }
}

#[derive(Clone, Copy)]
struct FakeNetStack<'a>(&'a Log);

impl<'a> NetStack for FakeNetStack<'a> {
    type Socket<'s>
        = FakeSocket<'a>
    where
        Self: 's;

    fn bind(
        &self,
        addr: SocketAddr,
        ipv4_interface: Ipv4Addr,
        ipv6_interface: u32,
    ) -> impl Future<Output = Result<Self::Socket<'_>, Error>> + MaybeSend {
        self.0
            .binds
            .lock()
            .unwrap()
            .push((addr.port(), ipv4_interface, ipv6_interface));

        ready(Ok(FakeSocket(self.0)))
    }
}

struct FakeSocket<'a>(&'a Log);

impl<'a> NetSocket for FakeSocket<'a> {
    type Send<'s>
        = FakeHalf<'a>
    where
        Self: 's;

    type Receive<'s>
        = NoNetwork
    where
        Self: 's;

    type Multicast<'s>
        = FakeHalf<'a>
    where
        Self: 's;

    fn split(&mut self) -> (Self::Send<'_>, Self::Receive<'_>, Self::Multicast<'_>) {
        (FakeHalf(self.0), NoNetwork, FakeHalf(self.0))
    }
}

struct FakeHalf<'a>(&'a Log);

impl NetworkSend for FakeHalf<'_> {
    async fn send_to(&mut self, _data: &[u8], _addr: Address) -> Result<(), Error> {
        *self.0.sends.lock().unwrap() += 1;

        Ok(())
    }
}

impl NetworkMulticast for FakeHalf<'_> {
    async fn join(&mut self, addr: IpAddr) -> Result<(), Error> {
        self.0.joins.lock().unwrap().push(addr);

        Ok(())
    }

    async fn leave(&mut self, _addr: IpAddr) -> Result<(), Error> {
        Ok(())
    }
}

struct FakeNetif;

impl NetifDiag for FakeNetif {
    fn netifs(&self, f: &mut dyn FnMut(&NetifInfo) -> Result<(), Error>) -> Result<(), Error> {
        f(&NetifInfo {
            name: "fake0",
            operational: true,
            offprem_svc_reachable_ipv4: None,
            offprem_svc_reachable_ipv6: None,
            hw_addr: &[1, 2, 3, 4, 5, 6, 0, 0],
            ipv4_addrs: &[IPV4_INTERFACE],
            ipv6_addrs: &[IPV6_ADDR],
            netif_type: InterfaceTypeEnum::Ethernet,
            netif_index: IPV6_INTERFACE,
        })
    }
}

impl NetChangeNotif for FakeNetif {
    fn wait_changed(&self) -> impl Future<Output = ()> + MaybeSend {
        pending()
    }
}

struct FakeGatt<'a>(&'a Log);

impl GattPeripheral for FakeGatt<'_> {
    async fn run(
        &mut self,
        _btp: &Btp,
        _service_name: &str,
        _service_adv: &AdvData,
    ) -> Result<(), Error> {
        self.0.event("gatt running");

        pending().await
    }
}

/// A driver over a single radio, which is either in BLE mode or in Thread mode.
struct FakeRadio<'a> {
    log: &'a Log,
    net_ctl: NoopWirelessNetCtl,
    mdns: BuiltinMdns,
}

impl GattDriver for FakeRadio<'_> {
    async fn run<T>(&mut self, mut task: T) -> Result<(), Error>
    where
        T: GattTask,
    {
        self.log.event("ble up");

        let result = task.run(FakeGatt(self.log)).await;

        self.log.event("ble down");

        result
    }
}

impl ThreadDriver for FakeRadio<'_> {
    type NetCtl<'a>
        = &'a NoopWirelessNetCtl
    where
        Self: 'a;

    async fn run<T>(&mut self, mut task: T) -> Result<(), Error>
    where
        T: ThreadTask,
    {
        self.log.event("thread up");

        task.run(
            FakeNetStack(self.log),
            &FakeNetif,
            &self.net_ctl,
            &mut self.mdns,
        )
        .await
    }
}

/// A driver for Ethernet, Wifi or Thread, whichever `net_type` names. Logs the network
/// it brings up.
struct FakeAny<'a> {
    log: &'a Log,
    net_type: NetworkType,
    net_ctl: NoopWirelessNetCtl,
    mdns: BuiltinMdns,
}

impl<'a> FakeAny<'a> {
    fn new(log: &'a Log, net_type: NetworkType) -> Self {
        Self {
            log,
            net_type,
            net_ctl: NoopWirelessNetCtl::new(net_type),
            mdns: BuiltinMdns::new(),
        }
    }
}

impl AnyDriver for FakeAny<'_> {
    type WifiCtl<'a>
        = &'a NoopWirelessNetCtl
    where
        Self: 'a;

    type ThreadCtl<'a>
        = &'a NoopWirelessNetCtl
    where
        Self: 'a;

    fn net_type(&self) -> NetworkType {
        self.net_type
    }
}

impl EthernetDriver for FakeAny<'_> {
    async fn run<T>(&mut self, mut task: T) -> Result<(), Error>
    where
        T: EthernetTask,
    {
        self.log.event("eth up");

        task.run(FakeNetStack(self.log), &FakeNetif, &(), &mut self.mdns)
            .await
    }
}

impl ThreadCoexDriver for FakeAny<'_> {
    async fn run<T>(&mut self, mut task: T) -> Result<(), Error>
    where
        T: ThreadCoexTask,
    {
        self.log.event("thread up");

        task.run(
            FakeNetStack(self.log),
            &FakeNetif,
            &self.net_ctl,
            &mut self.mdns,
            FakeGatt(self.log),
        )
        .await
    }
}

impl WifiCoexDriver for FakeAny<'_> {
    async fn run<T>(&mut self, mut task: T) -> Result<(), Error>
    where
        T: WifiCoexTask,
    {
        self.log.event("wifi up");

        task.run(
            FakeNetStack(self.log),
            &FakeNetif,
            &self.net_ctl,
            &mut self.mdns,
            FakeGatt(self.log),
        )
        .await
    }
}

impl ThreadDriver for FakeAny<'_> {
    type NetCtl<'a>
        = &'a NoopWirelessNetCtl
    where
        Self: 'a;

    async fn run<T>(&mut self, mut task: T) -> Result<(), Error>
    where
        T: ThreadTask,
    {
        self.log.event("thread up");

        task.run(
            FakeNetStack(self.log),
            &FakeNetif,
            &self.net_ctl,
            &mut self.mdns,
        )
        .await
    }
}

impl WifiDriver for FakeAny<'_> {
    type NetCtl<'a>
        = &'a NoopWirelessNetCtl
    where
        Self: 'a;

    async fn run<T>(&mut self, mut task: T) -> Result<(), Error>
    where
        T: WifiTask,
    {
        self.log.event("wifi up");

        task.run(
            FakeNetStack(self.log),
            &FakeNetif,
            &self.net_ctl,
            &mut self.mdns,
        )
        .await
    }
}

impl GattDriver for FakeAny<'_> {
    async fn run<T>(&mut self, mut task: T) -> Result<(), Error>
    where
        T: GattTask,
    {
        self.log.event("ble up");

        task.run(FakeGatt(self.log)).await
    }
}

/// The interfaces of a host: only the third one is what Matter should use.
struct FakeHostNetifs;

impl NetifDiag for FakeHostNetifs {
    fn netifs(&self, f: &mut dyn FnMut(&NetifInfo) -> Result<(), Error>) -> Result<(), Error> {
        let netif = |name, ipv4_addrs, ipv6_addrs, netif_index| NetifInfo {
            name,
            operational: true,
            offprem_svc_reachable_ipv4: None,
            offprem_svc_reachable_ipv6: None,
            hw_addr: &[1, 2, 3, 4, 5, 6, 0, 0],
            ipv4_addrs,
            ipv6_addrs,
            netif_type: InterfaceTypeEnum::Ethernet,
            netif_index,
        };

        const GLOBAL: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);

        // The loopback one, and one with a routable IPv6 address only
        f(&netif(
            "lo",
            &[Ipv4Addr::LOCALHOST],
            &[Ipv6Addr::LOCALHOST],
            1,
        ))?;
        f(&netif("tun0", &[], &[GLOBAL], 2))?;
        // The one to use, followed by a virtual one which only ties with it
        f(&netif(
            "eth0",
            &[IPV4_INTERFACE],
            &[IPV6_ADDR],
            IPV6_INTERFACE,
        ))?;
        f(&netif(
            "docker0",
            &[Ipv4Addr::new(192, 168, 0, 20)],
            &[IPV6_ADDR],
            8,
        ))
    }
}

impl NetChangeNotif for FakeHostNetifs {
    fn wait_changed(&self) -> impl Future<Output = ()> + MaybeSend {
        pending()
    }
}

/// Run an Ethernet stack for a moment, and return its outcome if it exits.
/// Logs when the stack starts it.
struct FakeUserTask<'a>(&'a Log);

impl UserTask for FakeUserTask<'_> {
    fn run<S, N>(
        &mut self,
        _net_stack: S,
        _netif: N,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        S: NetStack,
        N: NetifDiag + NetChangeNotif,
    {
        self.0.event("user task");

        pending()
    }
}

/// A `GenDiag` that borrows the node, which the stack it is given to owns.
struct NodeDiag<'a>(&'a Matter<'a>);

impl GenDiag for NodeDiag<'_> {
    fn test_event_triggers_enabled(&self) -> Result<bool, Error> {
        Ok(self.0.port() != 0)
    }

    fn test_event_trigger(&self, _key: &[u8], _trigger: u64) -> Result<(), Error> {
        Ok(())
    }
}

fn run_ethernet<C, U, N, O>(
    stack: &EthMatterStack<'_, BUMP_SIZE>,
    crypto: C,
    net_stack: U,
    netif: N,
    options: O,
) -> Option<Result<(), Error>>
where
    C: rs_matter_crypto::Crypto,
    U: NetStack,
    N: NetifDiag + NetChangeNotif,
    O: RunOptions,
{
    const NODE: Node = Node {
        endpoints: &[EthMatterStack::<0>::eth_root_endpoint()],
    };

    let mut rand = crypto.weak_rand().unwrap();

    let handler = EmptyHandler.chain(
        |e, _| e == ROOT_ENDPOINT_ID,
        Async(EthMatterStack::<0>::root_handler(
            stack.matter(),
            &(),
            &mut rand,
        )),
    );

    let mut store = MemKvBlobStore::new();
    futures_lite::future::block_on(stack.startup(&crypto, &mut store)).unwrap();

    let kv = stack.matter().kv(store);

    futures_lite::future::block_on(run_for(
        stack.run_eth(
            PreexistingEthernet::new(net_stack, netif, &(), BuiltinMdns::new()),
            &crypto,
            (NODE, handler),
            kv,
            options,
        ),
        300,
    ))
}

/// Run `f` on a thread with a big stack, as the futures of the stack do not
/// fit the default stack of the test threads in a debug build.
fn on_big_stack<F, R>(f: F) -> R
where
    F: FnOnce() -> R + Send,
    R: Send,
{
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn_scoped(scope, f)
            .unwrap()
            .join()
            .unwrap()
    })
}

fn leak<T>() -> &'static mut MaybeUninit<T> {
    Box::leak(Box::new_uninit())
}

async fn run_for<F>(fut: F, millis: u64) -> Option<Result<(), Error>>
where
    F: Future<Output = Result<(), Error>>,
{
    let mut fut = core::pin::pin!(fut);
    let mut timer = core::pin::pin!(Timer::after(Duration::from_millis(millis)));

    match select(&mut fut, &mut timer).await {
        Either::First(result) => Some(result),
        Either::Second(_) => None,
    }
}

#[test]
fn ethernet_binds_the_matter_and_the_mdns_sockets() {
    const NODE: Node = Node {
        endpoints: &[EthMatterStack::<0>::eth_root_endpoint()],
    };

    on_big_stack(|| {
        let log = Log::default();
        let crypto = test_only_crypto();

        let stack = leak::<EthMatterStack<BUMP_SIZE>>().init_with(EthMatterStack::init(
            &TEST_DEV_DET,
            TEST_DEV_COMM,
            &TEST_DEV_ATT,
        ));

        let mut rand = rs_matter_crypto::Crypto::weak_rand(&crypto).unwrap();

        let handler = EmptyHandler.chain(
            |e, _| e == ROOT_ENDPOINT_ID,
            Async(EthMatterStack::<0>::root_handler(
                stack.matter(),
                &(),
                &mut rand,
            )),
        );

        let mut store = MemKvBlobStore::new();
        futures_lite::future::block_on(stack.startup(&crypto, &mut store)).unwrap();

        let kv = stack.matter().kv(store);

        let result = futures_lite::future::block_on(run_for(
            stack.run_eth(
                PreexistingEthernet::new(FakeNetStack(&log), &FakeNetif, &(), BuiltinMdns::new()),
                &crypto,
                (NODE, handler),
                kv,
                (),
            ),
            300,
        ));

        assert!(result.is_none(), "The stack exited: {result:?}");

        let mut binds = log.binds.lock().unwrap().clone();
        binds.sort();

        assert_eq!(
            binds,
            vec![
                (MDNS_PORT, IPV4_INTERFACE, IPV6_INTERFACE),
                (MATTER_PORT, Ipv4Addr::UNSPECIFIED, 0),
            ]
        );

        assert_eq!(
            *log.joins.lock().unwrap(),
            vec![
                IpAddr::V4(MDNS_IPV4_BROADCAST_ADDR),
                IpAddr::V6(MDNS_IPV6_BROADCAST_ADDR),
            ]
        );

        // The mDNS responder announced the commissioning window
        assert!(*log.sends.lock().unwrap() > 0);
    });
}

#[test]
fn concurrent_commissioning_runs_ble_next_to_the_operational_network() {
    const NODE: Node = Node {
        endpoints: &[WifiMatterStack::<0>::wifi_root_endpoint()],
    };

    on_big_stack(|| {
        let log = Log::default();
        let crypto = test_only_crypto();

        let stack = leak::<WifiMatterStack<BUMP_SIZE>>().init_with(WifiMatterStack::init(
            &TEST_DEV_DET,
            TEST_DEV_COMM,
            &TEST_DEV_ATT,
        ));

        let mut rand = rs_matter_crypto::Crypto::weak_rand(&crypto).unwrap();

        let handler = EmptyHandler.chain(
            |e, _| e == ROOT_ENDPOINT_ID,
            Async(WifiMatterStack::<0>::root_handler(
                stack.matter(),
                &(),
                &mut rand,
            )),
        );

        let mut store = MemKvBlobStore::new();
        futures_lite::future::block_on(stack.startup(&crypto, &mut store)).unwrap();

        let kv = stack.matter().kv(store);

        let result = futures_lite::future::block_on(run_for(
            stack.run_wifi(
                PreexistingWireless::new(
                    FakeNetStack(&log),
                    &FakeNetif,
                    NoopWirelessNetCtl::new(NetworkType::Wifi),
                    BuiltinMdns::new(),
                    FakeGatt(&log),
                ),
                &crypto,
                (NODE, handler),
                kv,
                (),
            ),
            300,
        ));

        assert!(result.is_none(), "The stack exited: {result:?}");

        assert_eq!(log.events(), vec!["gatt running"]);

        assert!(log.bound_ports().contains(&MATTER_PORT));
    });
}

const ANY_ETH_NODE: Node = Node {
    endpoints: &[EthMatterStack::<0>::eth_root_endpoint()],
};
const ANY_WIFI_NODE: Node = Node {
    endpoints: &[WifiMatterStack::<0>::wifi_root_endpoint()],
};
const ANY_THREAD_NODE: Node = Node {
    endpoints: &[ThreadMatterStack::<0>::thread_root_endpoint()],
};

#[test]
fn any_runs_the_network_the_driver_names() {
    assert_eq!(
        run_any(NetworkType::Ethernet, ANY_ETH_NODE, false),
        vec!["eth up"]
    );
    assert_eq!(
        run_any(NetworkType::Wifi, ANY_WIFI_NODE, false),
        vec!["wifi up", "gatt running"]
    );
    assert_eq!(
        run_any(NetworkType::Thread, ANY_THREAD_NODE, false),
        vec!["thread up", "gatt running"]
    );
}

#[test]
fn any_oper_runs_the_network_without_ble() {
    assert_eq!(
        run_any(NetworkType::Ethernet, ANY_ETH_NODE, true),
        vec!["eth up"]
    );
    assert_eq!(
        run_any(NetworkType::Wifi, ANY_WIFI_NODE, true),
        vec!["wifi up"]
    );
    assert_eq!(
        run_any(NetworkType::Thread, ANY_THREAD_NODE, true),
        vec!["thread up"]
    );
}

#[test]
fn any_refuses_a_driver_for_another_network() {
    on_big_stack(|| {
        let log = Log::default();
        let crypto = test_only_crypto();

        let stack = leak::<AnyMatterStack<BUMP_SIZE>>().init_with(AnyMatterStack::init(
            &TEST_DEV_DET,
            TEST_DEV_COMM,
            &TEST_DEV_ATT,
        ));

        futures_lite::future::block_on(
            stack.networks(|networks| networks.set_net_type(NetworkType::Wifi)),
        );

        let kv = stack.matter().kv(MemKvBlobStore::new());

        let result = futures_lite::future::block_on(run_for(
            stack.run(
                FakeAny::new(&log, NetworkType::Thread),
                &crypto,
                (ANY_THREAD_NODE, EmptyHandler),
                kv,
                (),
            ),
            300,
        ));

        assert!(matches!(result, Some(Err(_))), "{result:?}");
        assert!(log.events().is_empty());
    });
}

#[test]
fn select_net_type_takes_the_saved_network() {
    let stack = leak::<AnyMatterStack<BUMP_SIZE>>().init_with(AnyMatterStack::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
    ));

    let mut store = MemKvBlobStore::new();
    let mut buf = [0; 1024];

    // Nothing saved: the default
    let net_type = futures_lite::future::block_on(stack.select_net_type(
        &mut store,
        &mut buf,
        NetworkType::Wifi,
    ))
    .unwrap();

    assert_eq!(net_type, NetworkType::Wifi);

    // An Ethernet store saves its type, though it has no networks
    let mut data = [0; 64];
    let len = AnyNetworks::<2>::new(NetworkType::Ethernet)
        .save(&mut data)
        .unwrap()
        .unwrap();

    store.store(NETWORKS_KEY, &data[..len], &mut buf).unwrap();

    let net_type = futures_lite::future::block_on(stack.select_net_type(
        &mut store,
        &mut buf,
        NetworkType::Wifi,
    ))
    .unwrap();

    assert_eq!(net_type, NetworkType::Ethernet);
    assert_eq!(
        futures_lite::future::block_on(stack.networks(|networks| networks.net_type())),
        Some(NetworkType::Ethernet)
    );
}

#[test]
fn any_net_driver_runs_the_driver_it_holds() {
    type Driver<'a> = AnyNetDriver<
        PreexistingEthernet<FakeNetStack<'a>, &'static FakeNetif, &'static (), BuiltinMdns>,
        PreexistingWireless<
            FakeNetStack<'a>,
            &'static FakeNetif,
            NoopWirelessNetCtl,
            BuiltinMdns,
            FakeGatt<'a>,
        >,
        PreexistingWireless<
            FakeNetStack<'a>,
            &'static FakeNetif,
            NoopWirelessNetCtl,
            BuiltinMdns,
            FakeGatt<'a>,
        >,
    >;

    for (net_type, node) in [
        (NetworkType::Ethernet, ANY_ETH_NODE),
        (NetworkType::Wifi, ANY_WIFI_NODE),
        (NetworkType::Thread, ANY_THREAD_NODE),
    ] {
        let events = on_big_stack(move || {
            let log = Log::default();
            let crypto = test_only_crypto();

            let stack = leak::<AnyMatterStack<BUMP_SIZE>>().init_with(AnyMatterStack::init(
                &TEST_DEV_DET,
                TEST_DEV_COMM,
                &TEST_DEV_ATT,
            ));

            futures_lite::future::block_on(
                stack.networks(|networks| networks.set_net_type(net_type)),
            );

            let wireless = || {
                PreexistingWireless::new(
                    FakeNetStack(&log),
                    &FakeNetif,
                    NoopWirelessNetCtl::new(net_type),
                    BuiltinMdns::new(),
                    FakeGatt(&log),
                )
            };

            let driver: Driver = match net_type {
                NetworkType::Ethernet => AnyNetDriver::Eth(PreexistingEthernet::new(
                    FakeNetStack(&log),
                    &FakeNetif,
                    &(),
                    BuiltinMdns::new(),
                )),
                NetworkType::Wifi => AnyNetDriver::Wifi(wireless()),
                NetworkType::Thread => AnyNetDriver::Thread(wireless()),
            };

            let mut store = MemKvBlobStore::new();
            futures_lite::future::block_on(stack.startup(&crypto, &mut store)).unwrap();

            let kv = stack.matter().kv(store);

            let result = futures_lite::future::block_on(run_for(
                stack.run(driver, &crypto, (node, EmptyHandler), kv, ()),
                300,
            ));

            assert!(result.is_none(), "The stack exited: {result:?}");
            assert!(log.bound_ports().contains(&MATTER_PORT));

            log.events()
        });

        let expected: Vec<&str> = if net_type == NetworkType::Ethernet {
            vec![]
        } else {
            vec!["gatt running"]
        };

        assert_eq!(events, expected, "{net_type:?}");
    }
}

/// Run an `AnyNetworks` stack for a moment over a driver for `net_type`, with `run_oper`
/// if `oper` or `run` otherwise, and return the driver's log. Panics if the stack exits
/// or does not bind its port.
fn run_any(net_type: NetworkType, node: Node<'static>, oper: bool) -> Vec<&'static str> {
    on_big_stack(move || {
        let log = Log::default();
        let crypto = test_only_crypto();

        let stack = leak::<AnyMatterStack<BUMP_SIZE>>().init_with(AnyMatterStack::init(
            &TEST_DEV_DET,
            TEST_DEV_COMM,
            &TEST_DEV_ATT,
        ));

        futures_lite::future::block_on(stack.networks(|networks| networks.set_net_type(net_type)));

        let mut rand = rs_matter_crypto::Crypto::weak_rand(&crypto).unwrap();

        let handler = EmptyHandler.chain(
            |e, _| e == ROOT_ENDPOINT_ID,
            Async(AnyMatterStack::<0>::root_handler(
                stack.matter(),
                &(),
                &mut rand,
            )),
        );

        let mut store = MemKvBlobStore::new();
        futures_lite::future::block_on(stack.startup(&crypto, &mut store)).unwrap();

        let kv = stack.matter().kv(store);

        let driver = FakeAny::new(&log, net_type);

        let result = if oper {
            futures_lite::future::block_on(run_for(
                stack.run_oper(driver, &crypto, (node, handler), kv, ()),
                300,
            ))
        } else {
            futures_lite::future::block_on(run_for(
                stack.run(driver, &crypto, (node, handler), kv, ()),
                300,
            ))
        };

        assert!(result.is_none(), "The stack exited: {result:?}");

        assert!(log.bound_ports().contains(&MATTER_PORT));

        log.events()
    })
}

#[test]
fn wifi_oper_accepts_a_driver_without_gatt() {
    const NODE: Node = Node {
        endpoints: &[WifiMatterStack::<0>::wifi_root_endpoint()],
    };

    on_big_stack(|| {
        let log = Log::default();
        let crypto = test_only_crypto();

        let stack = leak::<WifiMatterStack<BUMP_SIZE>>().init_with(WifiMatterStack::init(
            &TEST_DEV_DET,
            TEST_DEV_COMM,
            &TEST_DEV_ATT,
        ));

        let mut rand = rs_matter_crypto::Crypto::weak_rand(&crypto).unwrap();

        let handler = EmptyHandler.chain(
            |e, _| e == ROOT_ENDPOINT_ID,
            Async(WifiMatterStack::<0>::root_handler(
                stack.matter(),
                &(),
                &mut rand,
            )),
        );

        let mut store = MemKvBlobStore::new();
        futures_lite::future::block_on(stack.startup(&crypto, &mut store)).unwrap();

        let kv = stack.matter().kv(store);

        let result = futures_lite::future::block_on(run_for(
            stack.run_wifi_oper(
                // `()` is not a `GattPeripheral`, so this driver is not a `GattDriver`
                PreexistingWireless::new(
                    FakeNetStack(&log),
                    &FakeNetif,
                    NoopWirelessNetCtl::new(NetworkType::Wifi),
                    BuiltinMdns::new(),
                    (),
                ),
                &crypto,
                (NODE, handler),
                kv,
                FakeUserTask(&log),
            ),
            300,
        ));

        assert!(result.is_none(), "The stack exited: {result:?}");

        assert_eq!(log.events(), vec!["user task"]);

        assert!(log.bound_ports().contains(&MATTER_PORT));
    });
}

#[test]
fn thread_oper_accepts_a_driver_without_gatt() {
    const NODE: Node = Node {
        endpoints: &[ThreadMatterStack::<0>::thread_root_endpoint()],
    };

    on_big_stack(|| {
        let log = Log::default();
        let crypto = test_only_crypto();

        let stack = leak::<ThreadMatterStack<BUMP_SIZE>>().init_with(ThreadMatterStack::init(
            &TEST_DEV_DET,
            TEST_DEV_COMM,
            &TEST_DEV_ATT,
        ));

        let mut rand = rs_matter_crypto::Crypto::weak_rand(&crypto).unwrap();

        let handler = EmptyHandler.chain(
            |e, _| e == ROOT_ENDPOINT_ID,
            Async(ThreadMatterStack::<0>::root_handler(
                stack.matter(),
                &(),
                &mut rand,
            )),
        );

        let mut store = MemKvBlobStore::new();
        futures_lite::future::block_on(stack.startup(&crypto, &mut store)).unwrap();

        let kv = stack.matter().kv(store);

        let result = futures_lite::future::block_on(run_for(
            stack.run_thread_oper(
                // `()` is not a `GattPeripheral`, so this driver is not a `GattDriver`
                PreexistingWireless::new(
                    FakeNetStack(&log),
                    &FakeNetif,
                    NoopWirelessNetCtl::new(NetworkType::Thread),
                    BuiltinMdns::new(),
                    (),
                ),
                &crypto,
                (NODE, handler),
                kv,
                FakeUserTask(&log),
            ),
            300,
        ));

        assert!(result.is_none(), "The stack exited: {result:?}");

        assert_eq!(log.events(), vec!["user task"]);

        assert!(log.bound_ports().contains(&MATTER_PORT));
    });
}

#[test]
fn oper_keeps_the_network_when_the_device_opens_a_window() {
    on_big_stack(|| {
        let log = Log::default();

        run_commissioned_thread(&log, true);

        // No handover to BLE, and the network is not restarted either
        assert_eq!(log.events(), vec!["thread up"]);
    });
}

#[test]
fn non_concurrent_hands_the_radio_back_when_the_device_opens_a_window() {
    on_big_stack(|| {
        let log = Log::default();

        run_commissioned_thread(&log, false);

        assert_eq!(log.events(), vec!["thread up", "ble up", "gatt running"]);
    });
}

/// Run a commissioned Thread stack with `run_thread_oper` (or with `run_thread_no_coex`, if `oper` is `false`), and
/// open a commissioning window for the device itself while it runs. Panics if the stack exits.
fn run_commissioned_thread(log: &Log, oper: bool) {
    const NODE: Node = Node {
        endpoints: &[ThreadMatterStack::<0>::thread_root_endpoint()],
    };

    let crypto = test_only_crypto();

    let stack = leak::<ThreadMatterStack<BUMP_SIZE>>().init_with(ThreadMatterStack::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
    ));

    let mut rand = rs_matter_crypto::Crypto::weak_rand(&crypto).unwrap();

    let handler = EmptyHandler.chain(
        |e, _| e == ROOT_ENDPOINT_ID,
        Async(ThreadMatterStack::<0>::root_handler(
            stack.matter(),
            &(),
            &mut rand,
        )),
    );

    let mut store = MemKvBlobStore::new();
    futures_lite::future::block_on(stack.startup(&crypto, &mut store)).unwrap();

    // A commissioned device, with the window of the initial commissioning closed
    stack.matter().with_state(|state| {
        state.fabrics.add_with_post_init(|_| Ok(())).unwrap();
    });

    stack.matter().close_comm_window(&()).unwrap();

    let kv = stack.matter().kv(store);

    let radio = FakeRadio {
        log,
        net_ctl: NoopWirelessNetCtl::new(NetworkType::Thread),
        mdns: BuiltinMdns::new(),
    };

    let run = async {
        if oper {
            stack
                .run_thread_oper(radio, &crypto, (NODE, handler), kv, ())
                .await
        } else {
            stack
                .run_thread_no_coex(radio, &crypto, (NODE, handler), kv, ())
                .await
        }
    };

    let open = async {
        Timer::after(Duration::from_millis(200)).await;

        assert_eq!(log.events(), vec!["thread up"]);

        stack.open_basic_comm_window(&crypto, &()).unwrap();

        Timer::after(Duration::from_millis(200)).await;

        assert!(stack
            .matter()
            .comm_window_state()
            .is_open_on_all_transports());

        Ok::<_, Error>(())
    };

    futures_lite::future::block_on(async {
        let mut run = core::pin::pin!(run);
        let mut open = core::pin::pin!(open);

        match select(&mut run, &mut open).await {
            Either::First(result) => panic!("The stack exited: {result:?}"),
            Either::Second(result) => result.unwrap(),
        }
    });
}

#[test]
fn non_concurrent_commissioning_hands_the_radio_over() {
    const NODE: Node = Node {
        endpoints: &[ThreadMatterStack::<0>::thread_root_endpoint()],
    };

    on_big_stack(|| {
        let log = Log::default();
        let crypto = test_only_crypto();

        let stack = leak::<ThreadMatterStack<BUMP_SIZE>>().init_with(ThreadMatterStack::init(
            &TEST_DEV_DET,
            TEST_DEV_COMM,
            &TEST_DEV_ATT,
        ));

        let mut rand = rs_matter_crypto::Crypto::weak_rand(&crypto).unwrap();

        let handler = EmptyHandler.chain(
            |e, _| e == ROOT_ENDPOINT_ID,
            Async(ThreadMatterStack::<0>::root_handler(
                stack.matter(),
                &(),
                &mut rand,
            )),
        );

        let mut store = MemKvBlobStore::new();
        futures_lite::future::block_on(stack.startup(&crypto, &mut store)).unwrap();

        let kv = stack.matter().kv(store);

        let matter: &Matter<'_> = stack.matter();

        let run = stack.run_thread_no_coex(
            FakeRadio {
                log: &log,
                net_ctl: NoopWirelessNetCtl::new(NetworkType::Thread),
                mdns: BuiltinMdns::new(),
            },
            &crypto,
            (NODE, handler),
            kv,
            (),
        );

        let close = async {
            // The commissioning window is open: BLE only, and nothing on the network
            Timer::after(Duration::from_millis(200)).await;

            assert_eq!(log.events(), vec!["ble up", "gatt running"]);
            assert!(log.bound_ports().is_empty());

            // Once it is closed, there is nothing to advertise over BLE
            matter.close_comm_window(&()).unwrap();

            Timer::after(Duration::from_millis(200)).await;

            Ok(())
        };

        let result = futures_lite::future::block_on(async {
            let mut run = core::pin::pin!(run);
            let mut close = core::pin::pin!(close);

            match select(&mut run, &mut close).await {
                Either::First(result) => result,
                Either::Second(result) => result,
            }
        });

        result.unwrap();

        assert_eq!(
            log.events(),
            vec!["ble up", "gatt running", "ble down", "thread up"]
        );

        assert!(log.bound_ports().contains(&MATTER_PORT));
    });
}

#[test]
fn ethernet_binds_the_configured_port() {
    const PORT: u16 = 5541;

    on_big_stack(|| {
        let log = Log::default();
        let crypto = test_only_crypto();

        let stack = leak::<EthMatterStack<BUMP_SIZE>>().init_with(EthMatterStack::init_with_port(
            &TEST_DEV_DET,
            TEST_DEV_COMM,
            &TEST_DEV_ATT,
            PORT,
        ));

        assert_eq!(stack.matter().port(), PORT);

        let result = run_ethernet(stack, &crypto, FakeNetStack(&log), &FakeNetif, ());

        assert!(result.is_none(), "The stack exited: {result:?}");

        let ports = log.bound_ports();

        assert!(ports.contains(&PORT));
        assert!(!ports.contains(&MATTER_PORT));
    });
}

#[test]
fn ethernet_advertises_on_the_first_of_the_most_suitable_netifs() {
    on_big_stack(|| {
        let log = Log::default();
        let crypto = test_only_crypto();

        let stack = leak::<EthMatterStack<BUMP_SIZE>>().init_with(EthMatterStack::init(
            &TEST_DEV_DET,
            TEST_DEV_COMM,
            &TEST_DEV_ATT,
        ));

        let result = run_ethernet(stack, &crypto, FakeNetStack(&log), &FakeHostNetifs, ());

        assert!(result.is_none(), "The stack exited: {result:?}");

        assert!(log
            .binds
            .lock()
            .unwrap()
            .contains(&(MDNS_PORT, IPV4_INTERFACE, IPV6_INTERFACE)));
    });
}

/// With `send-sync` the futures of the stack are `Send`, if those of the drivers are.
#[test]
fn ethernet_runs_the_user_task() {
    on_big_stack(|| {
        // Both forms of passing it
        for bare in [true, false] {
            let log = Log::default();
            let crypto = test_only_crypto();

            let stack = leak::<EthMatterStack<BUMP_SIZE>>().init_with(EthMatterStack::init(
                &TEST_DEV_DET,
                TEST_DEV_COMM,
                &TEST_DEV_ATT,
            ));

            let net_stack = FakeNetStack(&log);
            let task = FakeUserTask(&log);

            let result = if bare {
                run_ethernet(stack, &crypto, net_stack, &FakeNetif, task)
            } else {
                let options = Options::new().user_task(task);

                run_ethernet(stack, &crypto, net_stack, &FakeNetif, options)
            };

            assert!(result.is_none(), "The stack exited: {result:?}");
            assert!(log.events().contains(&"user task"));
        }
    });
}

#[test]
fn ethernet_takes_a_gen_diag_that_borrows_the_node() {
    on_big_stack(|| {
        let log = Log::default();
        let crypto = test_only_crypto();

        let stack = &*leak::<EthMatterStack<BUMP_SIZE>>().init_with(EthMatterStack::init(
            &TEST_DEV_DET,
            TEST_DEV_COMM,
            &TEST_DEV_ATT,
        ));

        let diag = NodeDiag(stack.matter());

        let result = run_ethernet(
            stack,
            &crypto,
            FakeNetStack(&log),
            &FakeNetif,
            Options::new().gen_diag(&diag),
        );

        assert!(result.is_none(), "The stack exited: {result:?}");
    });
}

#[cfg(feature = "send-sync")]
#[test]
#[allow(clippy::large_stack_frames)]
fn futures_are_send() {
    fn assert_send<F: Send>(_: &F) {}

    const ETH_NODE: Node = Node {
        endpoints: &[EthMatterStack::<0>::eth_root_endpoint()],
    };
    const WIFI_NODE: Node = Node {
        endpoints: &[WifiMatterStack::<0>::wifi_root_endpoint()],
    };
    const THREAD_NODE: Node = Node {
        endpoints: &[ThreadMatterStack::<0>::thread_root_endpoint()],
    };

    // What the futures borrow outlives the stacks
    let log = &*Box::leak(Box::<Log>::default());
    let crypto = test_only_crypto();

    let eth = leak::<EthMatterStack<BUMP_SIZE>>().init_with(EthMatterStack::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
    ));
    let wifi = leak::<WifiMatterStack<BUMP_SIZE>>().init_with(WifiMatterStack::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
    ));
    let thread = leak::<ThreadMatterStack<BUMP_SIZE>>().init_with(ThreadMatterStack::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
    ));

    let mut rand = rs_matter_crypto::Crypto::weak_rand(&crypto).unwrap();

    let eth_handler = EmptyHandler.chain(
        |e, _| e == ROOT_ENDPOINT_ID,
        Async(EthMatterStack::<0>::root_handler(
            eth.matter(),
            &(),
            &mut rand,
        )),
    );
    let wifi_handler = EmptyHandler.chain(
        |e, _| e == ROOT_ENDPOINT_ID,
        Async(WifiMatterStack::<0>::root_handler(
            wifi.matter(),
            &(),
            &mut rand,
        )),
    );
    let thread_handler = EmptyHandler.chain(
        |e, _| e == ROOT_ENDPOINT_ID,
        Async(ThreadMatterStack::<0>::root_handler(
            thread.matter(),
            &(),
            &mut rand,
        )),
    );

    let eth_diag = NodeDiag(eth.matter());
    let thread_diag = NodeDiag(thread.matter());

    let eth_run = eth.run_eth(
        PreexistingEthernet::new(FakeNetStack(log), &FakeNetif, &(), BuiltinMdns::new()),
        &crypto,
        (ETH_NODE, eth_handler),
        eth.matter().kv(MemKvBlobStore::new()),
        Options::new().gen_diag(&eth_diag),
    );
    let wifi_run = wifi.run_wifi(
        PreexistingWireless::new(
            FakeNetStack(log),
            &FakeNetif,
            NoopWirelessNetCtl::new(NetworkType::Wifi),
            BuiltinMdns::new(),
            FakeGatt(log),
        ),
        &crypto,
        (WIFI_NODE, wifi_handler),
        wifi.matter().kv(MemKvBlobStore::new()),
        (),
    );
    let wifi_oper_handler = EmptyHandler.chain(
        |e, _| e == ROOT_ENDPOINT_ID,
        Async(WifiMatterStack::<0>::root_handler(
            wifi.matter(),
            &(),
            &mut rand,
        )),
    );
    let wifi_oper_run = wifi.run_wifi_oper(
        PreexistingWireless::new(
            FakeNetStack(log),
            &FakeNetif,
            NoopWirelessNetCtl::new(NetworkType::Wifi),
            BuiltinMdns::new(),
            (),
        ),
        &crypto,
        (WIFI_NODE, wifi_oper_handler),
        wifi.matter().kv(MemKvBlobStore::new()),
        (),
    );
    let any = leak::<AnyMatterStack<BUMP_SIZE>>().init_with(AnyMatterStack::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
    ));
    let any_handler = || {
        EmptyHandler.chain(
            |e, _| e == ROOT_ENDPOINT_ID,
            Async(AnyMatterStack::<0>::root_handler(
                any.matter(),
                &(),
                rs_matter_crypto::Crypto::weak_rand(&crypto).unwrap(),
            )),
        )
    };
    let any_run = any.run(
        FakeAny::new(log, NetworkType::Wifi),
        &crypto,
        (WIFI_NODE, any_handler()),
        any.matter().kv(MemKvBlobStore::new()),
        (),
    );
    let any_no_coex_run = any.run_no_coex(
        FakeAny::new(log, NetworkType::Wifi),
        &crypto,
        (WIFI_NODE, any_handler()),
        any.matter().kv(MemKvBlobStore::new()),
        (),
    );
    let any_oper_run = any.run_oper(
        FakeAny::new(log, NetworkType::Wifi),
        &crypto,
        (WIFI_NODE, any_handler()),
        any.matter().kv(MemKvBlobStore::new()),
        (),
    );
    let thread_run = thread.run_thread_no_coex(
        FakeRadio {
            log,
            net_ctl: NoopWirelessNetCtl::new(NetworkType::Thread),
            mdns: BuiltinMdns::new(),
        },
        &crypto,
        (THREAD_NODE, thread_handler),
        thread.matter().kv(MemKvBlobStore::new()),
        Options::new().user_task(()).gen_diag(&thread_diag),
    );
    let thread_oper_handler = EmptyHandler.chain(
        |e, _| e == ROOT_ENDPOINT_ID,
        Async(ThreadMatterStack::<0>::root_handler(
            thread.matter(),
            &(),
            &mut rand,
        )),
    );
    let thread_oper_run = thread.run_thread_oper(
        PreexistingWireless::new(
            FakeNetStack(log),
            &FakeNetif,
            NoopWirelessNetCtl::new(NetworkType::Thread),
            BuiltinMdns::new(),
            (),
        ),
        &crypto,
        (THREAD_NODE, thread_oper_handler),
        thread.matter().kv(MemKvBlobStore::new()),
        (),
    );

    assert_send(&eth_run);
    assert_send(&wifi_run);
    assert_send(&wifi_oper_run);
    assert_send(&any_run);
    assert_send(&any_no_coex_run);
    assert_send(&any_oper_run);
    assert_send(&thread_run);
    assert_send(&thread_oper_run);
}
