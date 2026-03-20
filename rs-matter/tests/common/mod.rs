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

pub mod e2e;
pub mod mdns;

use core::future::Future;
use core::pin::pin;

use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Timer};

use rs_matter::error::Error;

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
