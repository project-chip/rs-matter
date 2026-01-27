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
use rs_matter::pairing::qr::QrTextType;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pake::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::tlv::Nullable;
use rs_matter::transport::network::btp::{
    AdvData, Btp, BtpContext, GattPeripheral, GattPeripheralEvent,
};
use rs_matter::transport::network::mdns::builtin::{BuiltinMdnsResponder, Host};
use rs_matter::transport::network::{
    Address, BtAddr, ChainedNetwork, Ipv4Addr, Ipv6Addr, NetworkReceive, NetworkSend,
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

// A macro to create static variables in `.bss` using `static_cell::StaticCell`
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

// An `unwrap!` polyfill when `defmt` is not available
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

/// One large struct holding the entire Matter stack state
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
    /// Return an in-place initializer for the Matter stack
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

// Fully spelled-out types for everything which is passed down as arguments to `embassy-executor` tasks
// Necessary, because `embassy-executor` doesn't grok generics

type AppNetCtl<'a> = NetCtlWithStatusImpl<'a, NoopRawMutex, FakeWifi>;
type AppWirelessMgr<'a> = WirelessMgr<'a, &'a WifiNetworks<3, NoopRawMutex>, &'a AppNetCtl<'a>>;
type AppBtp<'a> =
    Btp<&'a BtpContext<CriticalSectionRawMutex>, CriticalSectionRawMutex, FakeGattPeripheral>;
type AppTransport<'a> = ChainedNetwork<FakeUdp, &'a AppBtp<'a>, fn(&Address) -> bool>;
type AppHandler<'a> = handler_chain_type!(
    EpClMatcher => on_off::HandlerAdaptor<on_off::OnOffHandler<'a, TestOnOffDeviceLogic, NoLevelControl>>,
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
    #[cfg(target_os = "none")]
    rtt_target::rtt_init_defmt!(rtt_target::ChannelMode::NoBlockSkip, 2048);
    #[cfg(not(target_os = "none"))]
    unwrap!(simple_logger::init_with_env());

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
    // Otherwise, the initial state of the (large) `MatterStack` struct will be captured in `.rodata`
    // affecting flash size, as it is not all-zeroes
    //

    info!("===================================================");
    info!("Memory usage report");

    let stack = mk_static!(MatterStack<'static, NoopRawMutex>).init_with(MatterStack::init());

    let mut stack_total = 0;

    report_size("Matter", size_of_val(&stack.matter), &mut stack_total);
    report_size("Buffers", size_of_val(&stack.buffers), &mut stack_total);
    report_size(
        "Subscriptions",
        size_of_val(&stack.subscriptions),
        &mut stack_total,
    );
    report_size("Networks", size_of_val(&stack.networks), &mut stack_total);
    report_size(
        "NetCtl state",
        size_of_val(&stack.net_ctl_state),
        &mut stack_total,
    );
    report_size(
        "BTP context",
        size_of_val(&stack.btp_context),
        &mut stack_total,
    );
    report_size(
        "Wireless mgr buffer",
        size_of_val(&stack.wireless_mgr_buffer),
        &mut stack_total,
    );
    report_size(
        "Persister buffer",
        size_of_val(&stack.psm_buffer),
        &mut stack_total,
    );

    report_subtotal_size("TOTAL MATTER STACK ", stack_total);

    //
    // Now create all types that do borrow the stack
    //

    // The BTP transport impl with a fake GATT peripheral
    let btp = mk_static!(AppBtp, Btp::new(FakeGattPeripheral, &stack.btp_context));

    let mut aux_total = 0;

    report_size("BTP transport", size_of_val(&*btp), &mut aux_total);

    // The Wifi network controller with a fake underlying Wifi implementation
    let net_ctl = &*mk_static!(
        AppNetCtl,
        NetCtlWithStatusImpl::new(&stack.net_ctl_state, FakeWifi)
    );

    report_size("Network controller", size_of_val(net_ctl), &mut aux_total);

    // Wifi network manager (cycle registered networks, auto-reconnect)
    let wifi_mgr = mk_static!(
        AppWirelessMgr,
        WirelessMgr::new(&stack.networks, net_ctl, unsafe {
            stack.wireless_mgr_buffer.assume_init_mut()
        },)
    );

    report_size("Wireless manager", size_of_val(&*wifi_mgr), &mut aux_total);

    let mdns = mk_static!(
        BuiltinMdnsResponder,
        BuiltinMdnsResponder::new(&stack.matter)
    );

    let transport_send = mk_static!(
        AppTransport<'static>,
        ChainedNetwork::new(Address::is_udp, FakeUdp, &*btp)
    );

    report_size("Transport send", size_of_val(&*mdns), &mut aux_total);

    let transport_recv = mk_static!(
        AppTransport<'static>,
        ChainedNetwork::new(Address::is_udp, FakeUdp, &*btp)
    );

    report_size("Transport receive", size_of_val(&*mdns), &mut aux_total);

    report_size("mDNS responder", size_of_val(&*mdns), &mut aux_total);

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

    report_size("DM Handler size", size_of_val(&*handler), &mut aux_total);

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

    report_size("Data Model", size_of_val(&*dm), &mut aux_total);

    // A default responder
    let responder = mk_static!(AppResponder, DefaultResponder::new(dm));

    report_size("Responder", size_of_val(&*responder), &mut aux_total);

    let executor = mk_static!(Executor, Executor::new());

    report_size("Executor", size_of_val(&*executor), &mut aux_total);

    report_subtotal_size("TOTAL AUXILLIARY", aux_total);

    //
    // Schedule all futures into embassy-executor
    // This way, they will be moved into `.bss` as well
    //

    let mut fut_total = 0;

    report_size(
        "Respond tasks",
        size_of_val(&respond_task_fut(responder, 0)) * 4,
        &mut fut_total,
    );
    report_size(
        "Respond busy tasks",
        size_of_val(&respond_busy_task_fut(responder, 0)) * 2,
        &mut fut_total,
    );
    report_size("DM task", size_of_val(&dm_task_fut(dm)), &mut fut_total);
    report_size(
        "mDNS task",
        size_of_val(&mdns_task_fut(mdns)),
        &mut fut_total,
    );
    report_size("BTP task", size_of_val(&btp_task_fut(btp)), &mut fut_total);
    report_size(
        "Wifi task",
        size_of_val(&wifi_task_fut(wifi_mgr)),
        &mut fut_total,
    );
    report_size(
        "Transport task",
        size_of_val(&transport_task_fut(
            &stack.matter,
            transport_send,
            transport_recv,
        )),
        &mut fut_total,
    );

    report_subtotal_size("TOTAL FUTURES", fut_total);

    report_total_size(stack_total + aux_total + fut_total);

    info!("===================================================");

    if !stack.matter.is_commissioned() {
        // If the device is not commissioned yet, print the QR text and code to the console
        // and enable basic commissioning

        unwrap!(stack
            .matter
            .print_standard_qr_text(DiscoveryCapabilities::IP));
        unwrap!(stack
            .matter
            .print_standard_qr_code(QrTextType::Unicode, DiscoveryCapabilities::IP));

        unwrap!(stack
            .matter
            .open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS));
    }

    executor.run(|spawner| {
        unwrap!(spawner.spawn(respond_busy_task(responder, 1)));
        unwrap!(spawner.spawn(respond_busy_task(responder, 0)));
        unwrap!(spawner.spawn(respond_task(responder, 3)));
        unwrap!(spawner.spawn(respond_task(responder, 2)));
        unwrap!(spawner.spawn(respond_task(responder, 1)));
        unwrap!(spawner.spawn(respond_task(responder, 0)));
        unwrap!(spawner.spawn(dm_task(dm)));
        unwrap!(spawner.spawn(mdns_task(mdns)));
        unwrap!(spawner.spawn(btp_task(btp)));
        unwrap!(spawner.spawn(wifi_task(wifi_mgr)));
        unwrap!(spawner.spawn(transport_task(
            &stack.matter,
            transport_send,
            transport_recv
        )));
    });
}

#[inline(always)]
fn respond_task_fut<'d, 'a>(
    responder: &'a AppResponder<'d, 'a>,
    handler_id: u8,
) -> impl Future<Output = Result<(), Error>> + 'a {
    responder.responder().handle(handler_id)
}

#[embassy_executor::task(pool_size = 4)]
async fn respond_task(responder: &'static AppResponder<'static, 'static>, handler_id: u8) {
    info!("Starting responder task {}...", handler_id);
    unwrap!(respond_task_fut(responder, handler_id).await);
}

#[inline(always)]
fn respond_busy_task_fut<'d, 'a>(
    responder: &'a AppResponder<'d, 'a>,
    handler_id: u8,
) -> impl Future<Output = Result<(), Error>> + 'a {
    responder.busy_responder().handle(handler_id)
}

#[embassy_executor::task(pool_size = 2)]
async fn respond_busy_task(responder: &'static AppResponder<'static, 'static>, handler_id: u8) {
    info!("Starting busy responder task {}...", handler_id);
    unwrap!(respond_busy_task_fut(responder, handler_id).await);
}

#[inline(always)]
fn dm_task_fut<'a>(dm: &'a AppDataModel<'a>) -> impl Future<Output = Result<(), Error>> + 'a {
    dm.run()
}

#[embassy_executor::task]
async fn dm_task(dm: &'static AppDataModel<'static>) {
    info!("Starting DM task...");
    unwrap!(dm_task_fut(dm).await);
}

#[inline(always)]
fn mdns_task_fut<'a>(
    mdns: &'a mut BuiltinMdnsResponder<'static>,
) -> impl Future<Output = Result<(), Error>> + 'a {
    mdns.run(
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
}

#[embassy_executor::task]
async fn mdns_task(mdns: &'static mut BuiltinMdnsResponder<'static>) {
    info!("Starting mDNS task...");
    unwrap!(mdns_task_fut(mdns).await);
}

#[inline(always)]
fn btp_task_fut<'a>(btp: &'a AppBtp<'static>) -> impl Future<Output = Result<(), Error>> + 'a {
    btp.run("MT", &TEST_DEV_DET, TEST_DEV_COMM.discriminator)
}

#[embassy_executor::task]
async fn btp_task(btp: &'static AppBtp<'static>) {
    info!("Starting BTP task...");
    unwrap!(btp_task_fut(btp).await);
}

#[inline(always)]
fn wifi_task_fut<'a>(
    wifi_mgr: &'a mut AppWirelessMgr<'static>,
) -> impl Future<Output = Result<(), Error>> + 'a {
    wifi_mgr.run()
}

#[embassy_executor::task]
async fn wifi_task(wifi_mgr: &'static mut AppWirelessMgr<'static>) {
    info!("Starting Wifi task...");
    unwrap!(wifi_task_fut(wifi_mgr).await);
}

#[inline(always)]
fn transport_task_fut<'a>(
    matter: &'a Matter<'a>,
    transport_send: &'a mut AppTransport<'static>,
    transport_recv: &'a mut AppTransport<'static>,
) -> impl Future<Output = Result<(), Error>> + 'a {
    matter.run_transport(transport_send, transport_recv)
}

#[embassy_executor::task]
async fn transport_task(
    matter: &'static Matter<'static>,
    transport_send: &'static mut AppTransport<'static>,
    transport_recv: &'static mut AppTransport<'static>,
) {
    info!("Starting transport task...");
    unwrap!(transport_task_fut(matter, transport_send, transport_recv).await);
}

/// Report the size of an item and accumulate it into `total`
fn report_size(for_item: &str, size: usize, total: &mut usize) {
    *total += size;

    #[cfg(target_os = "none")]
    info!("[{} = {} B]", for_item, size);
    #[cfg(not(target_os = "none"))]
    info!("[{:20} = {:6} B]", for_item, size);
}

/// Report a subtotal size
fn report_subtotal_size(for_item: &str, subtotal_size: usize) {
    #[cfg(target_os = "none")]
    info!("({} = {} B)", for_item, subtotal_size);
    #[cfg(not(target_os = "none"))]
    info!("({:20} = {:6} B)", for_item, subtotal_size);
}

/// Report the total size
fn report_total_size(total_size: usize) {
    #[cfg(target_os = "none")]
    info!("(:GRAND TOTAL BSS: = {} B)", total_size);
    #[cfg(not(target_os = "none"))]
    info!("({:20} = {:6} B)", ":GRAND TOTAL BSS:", total_size);
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

/// The Data Model handler for our Matter device.
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
                    on_off::HandlerAdaptor(on_off),
                ),
        ),
    )
}

/// A fake UDP implementation
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

/// A fake Wifi implemewntation
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

/// A fake BTP GATT Peripheral implementation
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
