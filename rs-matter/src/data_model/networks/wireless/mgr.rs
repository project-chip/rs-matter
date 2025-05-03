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

//! This module contains a wireless manager that can be used post-commissioning
//! for re-establishing wireless network connection upon loss of connectivity.

use embassy_time::{Duration, Timer};

use crate::data_model::sdm::net_comm::{self, NetCtlError};
use crate::error::{Error, ErrorCode};

use crate::data_model::sdm::net_comm::WirelessCreds;
use crate::data_model::sdm::wifi_diag;
use crate::data_model::sdm::wifi_diag::WirelessDiag;

use super::thread::Thread;
use super::{NetChangeNotif, OwnedWirelessNetworkId};

/// The maximum size of one network credentials
pub const MAX_CREDS_SIZE: usize = 256;

/// A wireless manager that can be used post-commissioning
/// for re-establishing wireless network connection upon loss of connectivity.
pub struct WirelessMgr<'a, W, T> {
    networks: W,
    net_ctl: T,
    buf: &'a mut [u8; MAX_CREDS_SIZE],
}

impl<'a, W, T> WirelessMgr<'a, W, T>
where
    W: net_comm::Networks + NetChangeNotif,
    T: net_comm::NetCtl + wifi_diag::WirelessDiag + NetChangeNotif,
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
            Self::run_connect(&self.networks, &self.net_ctl, self.buf).await?;
        }
    }

    async fn run_connect(networks: &W, net_ctl: &T, buf: &mut [u8]) -> Result<(), Error> {
        loop {
            Self::wait_connect_while(&net_ctl, true).await?;

            let mut network_id = OwnedWirelessNetworkId::new();

            let mut c = None;

            networks.next_creds(
                (!network_id.is_empty()).then_some(&network_id),
                &mut |creds| {
                    match creds {
                        WirelessCreds::Wifi { ssid, pass } => {
                            if ssid.len() + pass.len() > buf.len() {
                                error!("SSID and password too large");
                                return Err(ErrorCode::InvalidData.into());
                            }

                            buf[..ssid.len()].copy_from_slice(ssid);
                            buf[ssid.len()..][..pass.len()].copy_from_slice(pass);

                            c = Some((ssid.len(), Some(pass.len())))
                        }
                        WirelessCreds::Thread { dataset_tlv } => {
                            if dataset_tlv.len() > buf.len() {
                                error!("Dataset TLV too large");
                                return Err(ErrorCode::InvalidData.into());
                            }

                            buf[..dataset_tlv.len()].copy_from_slice(dataset_tlv);

                            c = Some((dataset_tlv.len(), None))
                        }
                    }

                    Ok(())
                },
            )?;

            if let Some((len1, len2)) = c {
                let creds = if let Some(len2) = len2 {
                    WirelessCreds::Wifi {
                        ssid: &buf[..len1],
                        pass: &buf[len1..][..len2],
                    }
                } else {
                    WirelessCreds::Thread {
                        dataset_tlv: &buf[..len1],
                    }
                };

                network_id.clear();
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

                match Self::connect_with_retries(net_ctl, &creds).await {
                    Ok(_) => unreachable!(),
                    Err(NetCtlError::Other(e)) => {
                        error!(
                            "General failure when connecting to network with ID {}: {:?}",
                            creds, e
                        );
                        return Err(e);
                    }
                    _ => continue,
                }
            } else {
                networks.wait_changed().await;
            }
        }
    }

    async fn connect_with_retries(
        net_ctl: &T,
        creds: &WirelessCreds<'_>,
    ) -> Result<(), NetCtlError> {
        loop {
            let mut result = Ok(());

            for delay in [2, 5, 10].iter().copied() {
                info!("Connecting to network with ID {}", creds);

                result = net_ctl.connect(creds).await;

                if result.is_ok() {
                    break;
                } else {
                    warn!(
                        "Connection to network with ID {} failed: {:?}, retrying in {}s",
                        creds, result, delay
                    );
                }

                Timer::after(Duration::from_secs(delay)).await;
            }

            if let Err(e) = result {
                error!("Failed to connect to network with ID {}: {:?}", creds, e);

                break Err(e);
            } else {
                info!("Connected to network with ID {}", creds);

                Self::wait_connect_while(&net_ctl, true).await?;
            }
        }
    }

    async fn wait_connect_while<N>(net_ctl: N, connected: bool) -> Result<(), Error>
    where
        N: WirelessDiag + NetChangeNotif,
    {
        loop {
            if net_ctl.connected()? != connected {
                break;
            }

            net_ctl.wait_changed().await;
        }

        Ok(())
    }
}
