/*
 *
 *    Copyright (c) 2022-2026 Project CHIP Authors
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

pub mod e2e;
#[cfg(feature = "async-io")]
pub mod mdns;

use core::future::Future;
use core::pin::pin;

use std::collections::HashMap;

use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Timer};

use rs_matter::dm::clusters::basic_info::BasicInfoConfig;
use rs_matter::dm::devices::test::TEST_DEV_DET;
use rs_matter::error::Error;
use rs_matter::persist::KvBlobStore;
use rs_matter::transport::session::SessionMode;
use rs_matter::Matter;

/// A simple in-memory multi-key [`KvBlobStore`] for tests.
///
/// Unlike [`rs_matter::persist::DummyKvBlobStore`] it actually retains what it
/// stores, so a value written by one data-model incarnation can be read back by
/// a later one — the moral equivalent of on-disk state surviving a reboot.
#[derive(Default, Clone)]
#[allow(unused)]
pub struct MemKvBlobStore {
    blobs: std::rc::Rc<std::cell::RefCell<HashMap<u16, std::vec::Vec<u8>>>>,
}

#[allow(unused)]
impl MemKvBlobStore {
    /// Whether a value is stored under `key`.
    pub fn contains_key(&self, key: u16) -> bool {
        self.blobs.borrow().contains_key(&key)
    }
}

impl KvBlobStore for MemKvBlobStore {
    fn load<'a>(&mut self, key: u16, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, Error> {
        Ok(self.blobs.borrow().get(&key).map(|v| {
            buf[..v.len()].copy_from_slice(v);
            &buf[..v.len()]
        }))
    }

    fn store(&mut self, key: u16, data: &[u8], _buf: &mut [u8]) -> Result<(), Error> {
        self.blobs.borrow_mut().insert(key, data.to_vec());
        Ok(())
    }

    fn remove(&mut self, key: u16, _buf: &mut [u8]) -> Result<(), Error> {
        self.blobs.borrow_mut().remove(&key);
        Ok(())
    }
}

/// `TEST_DEV_DET` with distinctive MRP intervals, for a device whose
/// advertised SAI / SII should be told apart from the controller's defaults.
#[allow(unused)]
pub const TEST_DEV_DET_MRP: BasicInfoConfig<'static> = BasicInfoConfig {
    sai: Some(700),
    sii: Some(9000),
    ..TEST_DEV_DET
};

/// The peer MRP parameters - `(active interval, idle interval, active
/// threshold)`, in ms - of every secure (CASE / PASE) session `matter` holds.
#[allow(unused)]
pub fn secure_sessions_peer_mrp_params(matter: &Matter<'_>) -> Vec<(u32, u32, u16)> {
    matter.with_state(|state| {
        state
            .sessions
            .iter()
            .filter(|sess| {
                matches!(
                    sess.get_session_mode(),
                    SessionMode::Case { .. } | SessionMode::Pase { .. }
                )
            })
            .map(|sess| {
                (
                    sess.get_peer_active_interval_ms(),
                    sess.get_peer_idle_interval_ms(),
                    sess.get_peer_active_threshold_ms(),
                )
            })
            .collect()
    })
}

/// Drives a device future and a controller future concurrently.
///
/// The device future is expected to run indefinitely. The controller future
/// is expected to complete first. If the device exits first the test panics.
#[allow(unused)]
pub async fn run_device_controller<D, C>(device_fut: D, controller_fut: C) -> Result<(), Error>
where
    D: Future<Output = Result<(), Error>>,
    C: Future<Output = Result<(), Error>>,
{
    let mut device_fut = pin!(device_fut);
    let mut controller_fut = pin!(controller_fut);

    match select(&mut device_fut, &mut controller_fut).await {
        Either::First(Err(e)) => panic!("Device error: {e:?}"),
        Either::First(Ok(())) => panic!("Device exited unexpectedly"),
        Either::Second(result) => result,
    }
}

/// Runs a test future alongside a transport future.
///
/// When the test future completes, waits up to 500 ms to let the transport
/// flush any pending outbound messages (e.g. standalone ACKs), then returns
/// the test result. Panics if the transport exits before the test.
#[allow(unused)]
pub async fn run_with_transport<T, F>(transport: T, test: F) -> Result<(), Error>
where
    T: Future<Output = Result<(), Error>>,
    F: Future<Output = Result<(), Error>>,
{
    let mut transport = pin!(transport);
    let mut test = pin!(test);

    match select(&mut transport, &mut test).await {
        Either::First(r) => panic!("Transport exited prematurely: {r:?}"),
        Either::Second(result) => {
            let mut flush = pin!(Timer::after(Duration::from_millis(500)));
            if let Either::First(r) = select(&mut transport, &mut flush).await {
                panic!("Transport error during flush: {r:?}");
            }
            result
        }
    }
}

/// Binds two IPv6 UDP sockets on `[::1]:0` (localhost, ephemeral ports).
///
/// Suitable for in-process device/controller tests where both endpoints
/// live on the same host.
#[allow(unused)]
#[cfg(all(feature = "std", feature = "async-io"))]
pub fn create_localhost_socket_pair() -> (
    async_io::Async<std::net::UdpSocket>,
    async_io::Async<std::net::UdpSocket>,
) {
    use log::info;

    let addr = std::net::SocketAddrV6::new(std::net::Ipv6Addr::LOCALHOST, 0, 0, 0);
    let a = async_io::Async::<std::net::UdpSocket>::bind(addr).unwrap();
    let b = async_io::Async::<std::net::UdpSocket>::bind(addr).unwrap();
    info!(
        "Localhost socket pair: device={}, controller={}",
        a.get_ref().local_addr().unwrap(),
        b.get_ref().local_addr().unwrap()
    );
    (a, b)
}

pub fn init_env_logger() {
    #[cfg(all(feature = "std", not(target_os = "espidf")))]
    {
        let _ = env_logger::try_init_from_env(
            env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
        );
    }
}
