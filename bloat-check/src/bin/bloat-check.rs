/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
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

//! This is a specially-crafted executable suitable for checking the code and memory size of `rs-matter`.
//!
//! RAM specifics:
//! - An attempt is made to allocate all memory - including the futures themselves - in `.bss`
//!   rather than on-stack so that bloaty can detect and report realistic figures;
//! - The `rs-matter` stack is configured with BTP and wireless enabled so that the memory of those
//!   and the wireless network storage is counted towards code size and memory usage;
//! - The `rs-matter` stack uses the built-in mDNS responder;
//! - There is a fake persister memory, so that any memory used by a persister is counted as well.
//!
//! Code specifics:
//! - The executable is heavily optimized for size.
//!
//! What is NOT counted towards code and memory size are the following device-specific stacks:
//! - The UDP/IP stack;
//! - The Wifi (or Thread) stack below the IP stack;
//! - The BLE GATT stack.
//!
//! These are not counted because they are highly platform-specific and vary in size
//! depending on the used platform and stack.
//! Accounting for those can be done in downstream projects, like `rs-matter-embassy` and `esp-idf-matter`
#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]
#![recursion_limit = "256"]

use core::future::Future;
use core::mem::{size_of_val, MaybeUninit};

// Logging - `defmt` for embedded targets, `log` for others
#[cfg(target_os = "none")]
use defmt::{info, unwrap};
#[cfg(not(target_os = "none"))]
use log::info;

// Always use embassy executor for all targets
#[cfg(not(target_arch = "riscv32"))]
use embassy_executor::Executor;
#[cfg(target_arch = "riscv32")]
use esp_rtos::embassy::Executor;

use embassy_sync::blocking_mutex::raw::{CriticalSectionRawMutex, NoopRawMutex, RawMutex};

use rs_matter::dm::clusters::desc::{self, ClusterHandler as _, DescHandler};
use rs_matter::dm::clusters::net_comm::{
    NetCtl, NetCtlError, NetCtlStatus, NetworkScanInfo, NetworkType, Networks, WirelessCreds,
};
use rs_matter::dm::clusters::on_off::NoLevelControl;
use rs_matter::dm::clusters::on_off::{self, test::TestOnOffDeviceLogic, OnOffHooks};
use rs_matter::dm::clusters::wifi_diag::{
    SecurityTypeEnum, WiFiVersionEnum, WifiDiag, WirelessDiag,
};
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_ON_OFF_LIGHT;
use rs_matter::dm::endpoints::{SysHandler, WifiHandler};
use rs_matter::dm::networks::wireless::{
    NetCtlState, NetCtlStateMutex, NetCtlWithStatusImpl, WifiNetworks, WirelessMgr, MAX_CREDS_SIZE,
};
use rs_matter::dm::networks::NetChangeNotif;
use rs_matter::dm::subscriptions::{Subscriptions, DEFAULT_MAX_SUBSCRIPTIONS};
use rs_matter::dm::{endpoints, IMBuffer};
use rs_matter::dm::{Async, DataModel, Dataver, EmptyHandler, Endpoint, EpClMatcher, Node};
use rs_matter::error::Error;
use rs_matter::respond::DefaultResponder;
use rs_matter::tlv::Nullable;
use rs_matter::transport::network::btp::{
    AdvData, Btp, BtpContext, GattPeripheral, GattPeripheralEvent,
};
use rs_matter::transport::network::mdns::builtin::{BuiltinMdnsResponder, Host};
use rs_matter::transport::network::{
    Address, BtAddr, Ipv4Addr, Ipv6Addr, NetworkReceive, NetworkSend,
};
use rs_matter::utils::epoch::dummy_epoch;
use rs_matter::utils::init::{init, Init, InitMaybeUninit};
use rs_matter::utils::rand::dummy_rand;
use rs_matter::utils::storage::pooled::PooledBuffers;
use rs_matter::{clusters, devices, handler_chain_type, Matter, MATTER_PORT};

// Baremetal entry point macro depending on target
#[cfg(all(target_arch = "arm", target_os = "none"))]
use cortex_m_rt::entry as main;
#[cfg(all(target_arch = "riscv32", target_os = "none"))]
use hal::main;

// Baremetal panic handler
#[cfg(target_os = "none")]
use panic_rtt_target as _;

// Baremetal hal
#[cfg(target_os = "none")]
use hal as _;

// Baremetal allocator
#[cfg(target_os = "none")]
#[global_allocator]
static HEAP: embedded_alloc::LlffHeap = embedded_alloc::LlffHeap::empty();

macro_rules! mk_static {
    ($t:ty) => {{
        static STATIC_CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        #[deny(unused_attributes)]
        let x = STATIC_CELL.uninit();
        x
    }};
    ($t:ty,$val:expr) => {{
        static STATIC_CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        #[deny(unused_attributes)]
        let x = STATIC_CELL.uninit().write($val);
        x
    }};
}

#[cfg(not(target_os = "none"))]
#[collapse_debuginfo(yes)]
macro_rules! unwrap {
    ($arg:expr) => {
        match $arg {
            ::core::result::Result::Ok(t) => t,
            ::core::result::Result::Err(e) => {
                ::core::panic!("unwrap of `{}` failed: {:?}", ::core::stringify!($arg), e);
            }
        }
    };
    ($arg:expr, $($msg:expr),+ $(,)? ) => {
        match $arg {
            ::core::result::Result::Ok(t) => t,
            ::core::result::Result::Err(e) => {
                ::core::panic!("unwrap of `{}` failed: {}: {:?}", ::core::stringify!($arg), ::core::format_args!($($msg,)*), e);
            }
        }
    }
}

struct MatterStack<'a, M: RawMutex> {
    matter: Matter<'a>, // #258 - Can't generify by the raw mutex
    buffers: PooledBuffers<10, M, IMBuffer>,
    subscriptions: Subscriptions<{ DEFAULT_MAX_SUBSCRIPTIONS }, M>,
    networks: WifiNetworks<3, M>,
    net_ctl_state: NetCtlStateMutex<M>,
    btp_context: BtpContext<CriticalSectionRawMutex>, // Need to be shareable across threads, for now
    wireless_mgr_buffer: MaybeUninit<[u8; MAX_CREDS_SIZE]>,
    // We don't run a persistence task, but emulate its typical memory consumnption
    psm_buffer: MaybeUninit<[u8; 4096]>,
}

impl<'a, M: RawMutex> MatterStack<'a, M> {
    fn init() -> impl Init<Self> {
        init!(Self {
            matter <- Matter::init(
                &TEST_DEV_DET,
                TEST_DEV_COMM,
                &TEST_DEV_ATT,
                dummy_epoch,
                dummy_rand,
                MATTER_PORT,
            ),
            buffers <- PooledBuffers::init(0),
            subscriptions <- Subscriptions::init(),
            networks <- WifiNetworks::init(),
            net_ctl_state <- NetCtlState::init_with_mutex(),
            btp_context <- BtpContext::init(),
            wireless_mgr_buffer: MaybeUninit::zeroed(),
            psm_buffer: MaybeUninit::zeroed(),
        })
    }
}

type AppNetCtl<'a> = NetCtlWithStatusImpl<'a, NoopRawMutex, FakeWifi>;
type AppWirelessMgr<'a> = WirelessMgr<'a, &'a WifiNetworks<3, NoopRawMutex>, &'a AppNetCtl<'a>>;
type AppBtp<'a> =
    Btp<&'a BtpContext<CriticalSectionRawMutex>, CriticalSectionRawMutex, FakeGattPeripheral>;
type AppHandler<'a> = handler_chain_type!(
    EpClMatcher => on_off::HandlerAsyncAdaptor<on_off::OnOffHandler<'a, TestOnOffDeviceLogic, NoLevelControl>>,
    EpClMatcher => Async<desc::HandlerAdaptor<DescHandler<'a>>>
    | EmptyHandler
);
type AppDmHandler<'a> = WifiHandler<'a, &'a AppNetCtl<'a>, SysHandler<'a, AppHandler<'a>>>;
type AppDataModel<'a> = DataModel<
    'a,
    DEFAULT_MAX_SUBSCRIPTIONS,
    PooledBuffers<10, NoopRawMutex, IMBuffer>,
    (Node<'a>, &'a AppDmHandler<'a>),
>;
type AppResponder<'d, 'a> = DefaultResponder<
    'd,
    'a,
    DEFAULT_MAX_SUBSCRIPTIONS,
    PooledBuffers<10, NoopRawMutex, IMBuffer>,
    (Node<'a>, &'a AppDmHandler<'a>),
>;

#[cfg_attr(target_os = "none", main)]
fn main() -> ! {
    #[cfg(feature = "defmt")]
    rtt_target::rtt_init_defmt!(rtt_target::ChannelMode::NoBlockSkip, 2048);

    info!("Starting bloat check app...");

    // `rs-matter` uses the `x509` crate which (still) needs a few kilos of heap space
    #[cfg(target_os = "none")]
    {
        const HEAP_SIZE: usize = 4096;

        static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
        unsafe { HEAP.init(core::ptr::addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE) }
    }

    #[cfg(target_arch = "riscv32")]
    {
        use hal;

        let p = hal::init(hal::Config::default());

        esp_rtos::start(
            hal::timer::timg::TimerGroup::new(p.TIMG0).timer0,
            hal::interrupt::software::SoftwareInterruptControl::new(p.SW_INTERRUPT)
                .software_interrupt0,
        );
    }

    //
    // Create the Matter stack statically in `.bss` using emplacement initialization
    // which does not take space in `.rodata`.
    //
    // Otherwise, the initial state of the (large) stack will be captured in `.rodata`
    // affecting flash size, as it is not all-zeroes
    //

    let stack = mk_static!(MatterStack<'static, NoopRawMutex>).init_with(MatterStack::init());

    info!("Matter stack size: {}B", size_of_val(&*stack));

    //
    // Now create all types that do borrow the stack
    //

    // The BTP transport impl with a fake GATT peripheral
    let btp = mk_static!(AppBtp, Btp::new(FakeGattPeripheral, &stack.btp_context));

    // The Wifi network controller with a fake underlying Wifi implementation
    let net_ctl = &*mk_static!(
        AppNetCtl,
        NetCtlWithStatusImpl::new(&stack.net_ctl_state, FakeWifi)
    );

    // Wifi network manager (cycle registered networks, auto-reconnect)
    let wifi_mgr = mk_static!(
        AppWirelessMgr,
        WirelessMgr::new(&stack.networks, net_ctl, unsafe {
            stack.wireless_mgr_buffer.assume_init_mut()
        },)
    );

    // A Wireless handler with a sample app cluster (on-off)
    let handler = mk_static!(
        AppDmHandler,
        dm_handler(
            &stack.matter,
            on_off::OnOffHandler::new_standalone(
                Dataver::new_rand(stack.matter.rand()),
                1,
                TestOnOffDeviceLogic::new(true),
            ),
            net_ctl,
            &stack.networks,
        )
    );

    // Data Model
    let dm = mk_static!(
        AppDataModel,
        DataModel::new(
            &stack.matter,
            &stack.buffers,
            &stack.subscriptions,
            (NODE, handler),
        )
    );

    // A default responder
    let responder = mk_static!(AppResponder, DefaultResponder::new(dm));

    //
    // Schedule all futures into embassy-executor
    // This way, they will be moved into `.bss` as well
    //

    let executor = mk_static!(Executor, Executor::new());

    executor.run(|spawner| {
        unwrap!(spawner.spawn(respond_task(responder)));
        unwrap!(spawner.spawn(dm_task(dm)));
        unwrap!(spawner.spawn(mdns_task(&stack.matter)));
        unwrap!(spawner.spawn(btp_task(btp)));
        unwrap!(spawner.spawn(wifi_task(wifi_mgr)));
        unwrap!(spawner.spawn(btp_transport_task(&stack.matter, btp)));
        unwrap!(spawner.spawn(udp_transport_task(&stack.matter)));
    });
}

#[embassy_executor::task]
async fn respond_task(responder: &'static AppResponder<'static, 'static>) {
    unwrap!(responder.run::<4, 4>().await)
}

#[embassy_executor::task]
async fn dm_task(dm: &'static AppDataModel<'static>) {
    unwrap!(dm.run().await);
}

#[embassy_executor::task]
async fn mdns_task(matter: &'static Matter<'static>) {
    unwrap!(
        BuiltinMdnsResponder::new(matter)
            .run(
                FakeUdp,
                FakeUdp,
                &Host {
                    id: 0,
                    hostname: "rs-matter-bloat-check",
                    ip: Ipv4Addr::LOCALHOST,
                    ipv6: Ipv6Addr::LOCALHOST,
                },
                Some(Ipv4Addr::LOCALHOST),
                Some(0),
            )
            .await
    );
}

#[embassy_executor::task]
async fn btp_task(btp: &'static AppBtp<'static>) {
    unwrap!(
        btp.run("MT", &TEST_DEV_DET, TEST_DEV_COMM.discriminator)
            .await
    );
}

#[embassy_executor::task]
async fn wifi_task(wifi_mgr: &'static mut AppWirelessMgr<'static>) {
    unwrap!(wifi_mgr.run().await);
}

#[embassy_executor::task]
async fn btp_transport_task(matter: &'static Matter<'static>, btp: &'static AppBtp<'static>) {
    unwrap!(matter.run_transport(btp, btp).await);
}

#[embassy_executor::task]
async fn udp_transport_task(matter: &'static Matter<'static>) {
    unwrap!(matter.run_transport(FakeUdp, FakeUdp).await);
}

/// The Node meta-data describing our Matter device.
const NODE: Node<'static> = Node {
    id: 0,
    endpoints: &[
        endpoints::root_endpoint(NetworkType::Wifi),
        Endpoint {
            id: 1,
            device_types: devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters: clusters!(
                desc::DescHandler::CLUSTER,
                on_off::test::TestOnOffDeviceLogic::CLUSTER
            ),
        },
    ],
};

/// The Data Model handler + meta-data for our Matter device.
/// The handler is the root endpoint 0 handler plus the on-off handler and its descriptor.
fn dm_handler<'a, N>(
    matter: &'a Matter<'a>,
    on_off: on_off::OnOffHandler<'a, TestOnOffDeviceLogic, NoLevelControl>,
    net_ctl: &'a N,
    networks: &'a dyn Networks,
) -> WifiHandler<'a, &'a N, SysHandler<'a, AppHandler<'a>>>
where
    N: NetCtl + NetCtlStatus + WifiDiag,
{
    endpoints::with_wifi(
        &(),
        &(),
        net_ctl,
        networks,
        matter.rand(),
        endpoints::with_sys(
            &true,
            matter.rand(),
            EmptyHandler
                .chain(
                    EpClMatcher::new(Some(1), Some(desc::DescHandler::CLUSTER.id)),
                    Async(desc::DescHandler::new(Dataver::new_rand(matter.rand())).adapt()),
                )
                .chain(
                    EpClMatcher::new(Some(1), Some(TestOnOffDeviceLogic::CLUSTER.id)),
                    on_off::HandlerAsyncAdaptor(on_off),
                ),
        ),
    )
}

struct FakeUdp;

impl NetworkReceive for FakeUdp {
    fn wait_available(&mut self) -> impl Future<Output = Result<(), Error>> {
        core::future::pending()
    }

    fn recv_from(
        &mut self,
        _buffer: &mut [u8],
    ) -> impl Future<Output = Result<(usize, Address), Error>> {
        core::future::pending()
    }
}

impl NetworkSend for FakeUdp {
    fn send_to(
        &mut self,
        _buffer: &[u8],
        _addr: Address,
    ) -> impl Future<Output = Result<(), Error>> {
        core::future::ready(Ok(()))
    }
}

struct FakeWifi;

impl NetCtl for FakeWifi {
    fn net_type(&self) -> NetworkType {
        NetworkType::Wifi
    }

    fn scan<F>(
        &self,
        _network: Option<&[u8]>,
        _f: F,
    ) -> impl Future<Output = Result<(), NetCtlError>>
    where
        F: FnMut(&NetworkScanInfo) -> Result<(), Error>,
    {
        core::future::pending()
    }

    fn connect(&self, _creds: &WirelessCreds) -> impl Future<Output = Result<(), NetCtlError>> {
        core::future::pending()
    }
}

impl NetChangeNotif for FakeWifi {
    fn wait_changed(&self) -> impl Future<Output = ()> {
        core::future::pending()
    }
}

impl WirelessDiag for FakeWifi {}

impl WifiDiag for FakeWifi {
    fn bssid(&self, f: &mut dyn FnMut(Option<&[u8]>) -> Result<(), Error>) -> Result<(), Error> {
        f(None)
    }

    fn security_type(&self) -> Result<Nullable<SecurityTypeEnum>, Error> {
        Ok(Nullable::none())
    }

    fn wi_fi_version(&self) -> Result<Nullable<WiFiVersionEnum>, Error> {
        Ok(Nullable::none())
    }

    fn channel_number(&self) -> Result<Nullable<u16>, Error> {
        Ok(Nullable::none())
    }

    fn rssi(&self) -> Result<Nullable<i8>, Error> {
        Ok(Nullable::none())
    }
}

struct FakeGattPeripheral;

impl GattPeripheral for FakeGattPeripheral {
    fn run<F>(
        &self,
        _service_name: &str,
        _adv_data: &AdvData,
        _callback: F,
    ) -> impl Future<Output = Result<(), Error>>
    where
        F: Fn(GattPeripheralEvent) + Send + Sync + Clone + 'static,
    {
        core::future::pending()
    }

    fn indicate(&self, _data: &[u8], _address: BtAddr) -> impl Future<Output = Result<(), Error>> {
        core::future::pending()
    }
}
