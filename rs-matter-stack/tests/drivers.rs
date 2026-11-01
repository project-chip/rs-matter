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
use rs_matter_dm::clusters::gen_diag::{InterfaceTypeEnum, NetifDiag, NetifInfo};
use rs_matter_dm::clusters::net_comm::NetworkType;
use rs_matter_dm::endpoints::ROOT_ENDPOINT_ID;
use rs_matter_dm::networks::wireless::NoopWirelessNetCtl;
use rs_matter_dm::networks::NetChangeNotif;
use rs_matter_dm_core::persist::MemKvBlobStore;
use rs_matter_dm_core::{Async, EmptyHandler, Node};
use rs_matter_node::Matter;
use rs_matter_node::MATTER_PORT;
use rs_matter_node_core::test_device::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter_stack::ble::GattPeripheral;
use rs_matter_stack::eth::EthMatterStack;
use rs_matter_stack::net::{NetSocket, NetStack};
use rs_matter_stack::wireless::{
    GattDriver, GattTask, PreexistingWireless, ThreadDriver, ThreadMatterStack, ThreadTask,
    WifiMatterStack,
};
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
        endpoints: &[EthMatterStack::<0, ()>::root_endpoint()],
    };

    on_big_stack(|| {
        let log = Log::default();
        let crypto = test_only_crypto();

        let stack = leak::<EthMatterStack<BUMP_SIZE, ()>>().init_with(EthMatterStack::init(
            &TEST_DEV_DET,
            TEST_DEV_COMM,
            &TEST_DEV_ATT,
        ));

        let mut rand = rs_matter_crypto::Crypto::weak_rand(&crypto).unwrap();

        let handler = EmptyHandler.chain(
            |e, _| e == ROOT_ENDPOINT_ID,
            Async(EthMatterStack::<0, ()>::root_handler(
                stack.matter(),
                &(),
                &mut rand,
            )),
        );

        let mut store = MemKvBlobStore::new();
        futures_lite::future::block_on(stack.startup(&crypto, &mut store)).unwrap();

        let kv = stack.matter().kv(store);

        let result = futures_lite::future::block_on(run_for(
            stack.run_preex(
                FakeNetStack(&log),
                &FakeNetif,
                &(),
                BuiltinMdns::new(),
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
        endpoints: &[WifiMatterStack::<0, ()>::root_endpoint()],
    };

    on_big_stack(|| {
        let log = Log::default();
        let crypto = test_only_crypto();

        let stack = leak::<WifiMatterStack<BUMP_SIZE, ()>>().init_with(WifiMatterStack::init(
            &TEST_DEV_DET,
            TEST_DEV_COMM,
            &TEST_DEV_ATT,
        ));

        let mut rand = rs_matter_crypto::Crypto::weak_rand(&crypto).unwrap();

        let handler = EmptyHandler.chain(
            |e, _| e == ROOT_ENDPOINT_ID,
            Async(WifiMatterStack::<0, ()>::root_handler(
                stack.matter(),
                &(),
                &mut rand,
            )),
        );

        let mut store = MemKvBlobStore::new();
        futures_lite::future::block_on(stack.startup(&crypto, &mut store)).unwrap();

        let kv = stack.matter().kv(store);

        let result = futures_lite::future::block_on(run_for(
            stack.run_coex(
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

#[test]
fn non_concurrent_commissioning_hands_the_radio_over() {
    const NODE: Node = Node {
        endpoints: &[ThreadMatterStack::<0, ()>::root_endpoint()],
    };

    on_big_stack(|| {
        let log = Log::default();
        let crypto = test_only_crypto();

        let stack = leak::<ThreadMatterStack<BUMP_SIZE, ()>>().init_with(ThreadMatterStack::init(
            &TEST_DEV_DET,
            TEST_DEV_COMM,
            &TEST_DEV_ATT,
        ));

        let mut rand = rs_matter_crypto::Crypto::weak_rand(&crypto).unwrap();

        let handler = EmptyHandler.chain(
            |e, _| e == ROOT_ENDPOINT_ID,
            Async(ThreadMatterStack::<0, ()>::root_handler(
                stack.matter(),
                &(),
                &mut rand,
            )),
        );

        let mut store = MemKvBlobStore::new();
        futures_lite::future::block_on(stack.startup(&crypto, &mut store)).unwrap();

        let kv = stack.matter().kv(store);

        let matter: &Matter<'_> = stack.matter();

        let run = stack.run(
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

/// With `send-sync` the futures of the stack are `Send`, if those of the drivers are.
#[cfg(feature = "send-sync")]
#[test]
#[allow(clippy::large_stack_frames)]
fn futures_are_send() {
    fn assert_send<F: Send>(_: &F) {}

    const ETH_NODE: Node = Node {
        endpoints: &[EthMatterStack::<0, ()>::root_endpoint()],
    };
    const WIFI_NODE: Node = Node {
        endpoints: &[WifiMatterStack::<0, ()>::root_endpoint()],
    };
    const THREAD_NODE: Node = Node {
        endpoints: &[ThreadMatterStack::<0, ()>::root_endpoint()],
    };

    // What the futures borrow outlives the stacks
    let log = &*Box::leak(Box::<Log>::default());
    let crypto = test_only_crypto();

    let eth = leak::<EthMatterStack<BUMP_SIZE, ()>>().init_with(EthMatterStack::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
    ));
    let wifi = leak::<WifiMatterStack<BUMP_SIZE, ()>>().init_with(WifiMatterStack::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
    ));
    let thread = leak::<ThreadMatterStack<BUMP_SIZE, ()>>().init_with(ThreadMatterStack::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
    ));

    let mut rand = rs_matter_crypto::Crypto::weak_rand(&crypto).unwrap();

    let eth_handler = EmptyHandler.chain(
        |e, _| e == ROOT_ENDPOINT_ID,
        Async(EthMatterStack::<0, ()>::root_handler(
            eth.matter(),
            &(),
            &mut rand,
        )),
    );
    let wifi_handler = EmptyHandler.chain(
        |e, _| e == ROOT_ENDPOINT_ID,
        Async(WifiMatterStack::<0, ()>::root_handler(
            wifi.matter(),
            &(),
            &mut rand,
        )),
    );
    let thread_handler = EmptyHandler.chain(
        |e, _| e == ROOT_ENDPOINT_ID,
        Async(ThreadMatterStack::<0, ()>::root_handler(
            thread.matter(),
            &(),
            &mut rand,
        )),
    );

    let eth_run = eth.run_preex(
        FakeNetStack(log),
        &FakeNetif,
        &(),
        BuiltinMdns::new(),
        &crypto,
        (ETH_NODE, eth_handler),
        eth.matter().kv(MemKvBlobStore::new()),
        (),
    );
    let wifi_run = wifi.run_coex(
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
    let thread_run = thread.run(
        FakeRadio {
            log,
            net_ctl: NoopWirelessNetCtl::new(NetworkType::Thread),
            mdns: BuiltinMdns::new(),
        },
        &crypto,
        (THREAD_NODE, thread_handler),
        thread.matter().kv(MemKvBlobStore::new()),
        (),
    );

    assert_send(&eth_run);
    assert_send(&wifi_run);
    assert_send(&thread_run);
}
