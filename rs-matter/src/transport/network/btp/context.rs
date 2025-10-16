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

use cfg_if::cfg_if;

use embassy_sync::blocking_mutex::raw::RawMutex;

use crate::error::{Error, ErrorCode};
use crate::fmt::Bytes;
use crate::transport::network::BtAddr;
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init, IntoFallibleInit};
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::Notification;

use super::{session::Session, GattPeripheralEvent};

cfg_if! {
    if #[cfg(feature = "max-btp-sessions-8")] {
        /// The maximum number of BTP sessions that can be active at any given time.
        /// This is an `rs-matter` specific limit, and is not a requirement of the Matter BTP spec.
        ///
        /// The `GattPeripheral` implementation is expected to enforce this limit as well,
        /// i.e. it should not allow more than `MAX_BTP_SESSIONS` active subscriptions to characteristic `C2`.
        pub const MAX_BTP_SESSIONS: usize = 8;
    } else if #[cfg(feature = "max-btp-sessions-4")] {
        /// The maximum number of BTP sessions that can be active at any given time.
        /// This is an `rs-matter` specific limit, and is not a requirement of the Matter BTP spec.
        ///
        /// The `GattPeripheral` implementation is expected to enforce this limit as well,
        /// i.e. it should not allow more than `MAX_BTP_SESSIONS` active subscriptions to characteristic `C2`.
        pub const MAX_BTP_SESSIONS: usize = 4;
    } else if #[cfg(feature = "max-btp-sessions-2")] {
        /// The maximum number of BTP sessions that can be active at any given time.
        /// This is an `rs-matter` specific limit, and is not a requirement of the Matter BTP spec.
        ///
        /// The `GattPeripheral` implementation is expected to enforce this limit as well,
        /// i.e. it should not allow more than `MAX_BTP_SESSIONS` active subscriptions to characteristic `C2`.
        pub const MAX_BTP_SESSIONS: usize = 2;
    } else if #[cfg(feature = "max-btp-sessions-1")] {
        /// The maximum number of BTP sessions that can be active at any given time.
        /// This is an `rs-matter` specific limit, and is not a requirement of the Matter BTP spec.
        ///
        /// The `GattPeripheral` implementation is expected to enforce this limit as well,
        /// i.e. it should not allow more than `MAX_BTP_SESSIONS` active subscriptions to characteristic `C2`.
        pub const MAX_BTP_SESSIONS: usize = 1;
    } else {
        /// The maximum number of BTP sessions that can be active at any given time.
        /// This is an `rs-matter` specific limit, and is not a requirement of the Matter BTP spec.
        ///
        /// The `GattPeripheral` implementation is expected to enforce this limit as well,
        /// i.e. it should not allow more than `MAX_BTP_SESSIONS` active subscriptions to characteristic `C2`.
        pub const MAX_BTP_SESSIONS: usize = 1;
    }
}

/// Represents an error that occurred while trying to lock a session for sending.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum LockError {
    /// Session for the specified condition was not found.
    NoMatch,
    /// Session for the specified condition was found, but it was already locked for sending.
    AlreadyLocked,
}

/// An internal utility for representing a session which is locked for sending.
///
/// This type is used to ensure that at any moment in time, a session either is not sending anything,
/// or is sending the BTP PDUs of a single BTP SDU, which is a requirement of the Matter BTP spec.
///
/// The send lock is removed once this object is dropped.
pub(crate) struct SessionSendLock<'a, M>
where
    M: RawMutex,
{
    context: &'a BtpContext<M>,
    address: BtAddr,
}

impl<'a, M> SessionSendLock<'a, M>
where
    M: RawMutex,
{
    /// Try to find a session that matches the given condition and lock it for sending.
    ///
    /// - If there is no session matching the given condition, the method will return `LockError::NoMatch`.
    /// - If the first session matching the given condition is already locked for sending, the method will return `LockError::AlreadyLocked`.
    ///
    /// Due to the above semantics, the condition is expected to uniquely identify a session, by - say - matching on
    /// the session peer BLE address.
    pub fn try_lock<F>(context: &'a BtpContext<M>, condition: F) -> Result<Self, LockError>
    where
        F: Fn(&Session) -> bool,
    {
        context.state.lock(move |internal| {
            let sessions = &mut internal.borrow_mut().sessions;

            let Some(session) = sessions.iter_mut().find(|session| condition(session)) else {
                return Err(LockError::NoMatch);
            };

            if !session.set_sending(true) {
                Err(LockError::AlreadyLocked)?;
            }

            Ok(Self {
                context,
                address: session.address(),
            })
        })
    }

    /// Lock one (out of potentially many) sessions matcing the provided condition for sending.
    ///
    /// If all sessions matching the provided condition are already locked for sending, or if there is no
    /// session matching the provided condition, the method will return `None`.
    pub fn lock_any<F>(context: &'a BtpContext<M>, condition: F) -> Option<Self>
    where
        F: Fn(&Session) -> bool,
    {
        context.state.lock(move |internal| {
            internal
                .borrow_mut()
                .sessions
                .iter_mut()
                .find_map(|session| {
                    if condition(session) && session.set_sending(true) {
                        Some(Self {
                            context,
                            address: session.address(),
                        })
                    } else {
                        None
                    }
                })
        })
    }

    /// Return the peer BLE address.
    pub fn address(&self) -> BtAddr {
        self.address
    }

    /// Execute the provided closure with a mutable reference to the session locked for sending.
    ///
    /// If the session is no longer present, the method will return `ErrorCode::NoNetworkInterface`.
    pub fn with_session<F, R>(&self, f: F) -> Result<R, Error>
    where
        F: FnOnce(&mut Session) -> Result<R, Error>,
    {
        self.context.state.lock(|internal| {
            let sessions = &mut internal.borrow_mut().sessions;
            let session = sessions
                .iter_mut()
                .find(|session| session.address() == self.address)
                .ok_or(ErrorCode::NoNetworkInterface)?;

            f(session)
        })
    }
}

impl<M> Drop for SessionSendLock<'_, M>
where
    M: RawMutex,
{
    fn drop(&mut self) {
        self.context.state.lock(|internal| {
            if let Some(session) = internal
                .borrow_mut()
                .sessions
                .iter_mut()
                .find(|session| session.address() == self.address)
            {
                if !session.set_sending(false) || !session.set_running() {
                    // If we reach here this is a bug, because
                    // - a `SessionSendLock` cannot be acqired unless the session is
                    //   either in `Subscribed` or `Running` state already, during the
                    //   lock acqusition.
                    // - The session is set to `seding` state when the lock is acquired,
                    //   and is unset when the lock is dropped.
                    unreachable!("Should not happen")
                }
            }
        });

        self.context.send_notif.notify();
    }
}

pub(crate) struct BtpContextInner {
    pub(crate) conn_ct: usize,
    pub(crate) sessions: crate::utils::storage::Vec<Session, MAX_BTP_SESSIONS>,
}

impl BtpContextInner {
    #[inline(always)]
    const fn new() -> Self {
        Self {
            conn_ct: 0,
            sessions: crate::utils::storage::Vec::new(),
        }
    }

    /// Create a BTP context in-place initializer.
    fn init() -> impl Init<Self> {
        init!(Self {
            conn_ct: 0,
            sessions <- crate::utils::storage::Vec::init(),
        })
    }
}

/// A structure representing a BTP "context".
///
/// The BTP protocol implementation is split into two structures:
/// - `Btp` - the main BTP protocol implementation, which is responsible for handling the BTP protocol itself. This structure is not `Send` and `Sync`
///   and is overall a typical future-based protocol implementation, like the others in the `rs-matter` stack.
/// - `BtpContext` - a structure that holds the state of the BTP protocol shared between itself and the Gatt peripheral implementation.
///   In terms of ownership, The `Btp` instance holds a `'static` reference to the context, i.e. a `&'static BtpContext<M>` reference,
///   or an `Arc<BtpContext<M>>` instance for platforms where the Rust `alloc::sync` module is available.
///   Furthermore, the state kept in `BtpContext` is safe to share amongst multiple threads.
///
/// The need to split the BTP implementation into two structures is due to the fact that the `GattPeripheral` trait uses a
/// `'static + Send + Sync` callback closure so as to report subscribe, unsubscribe and write events back to the BTP protocol implementation.
///
/// While this simplifies the implementation of the `GattPeripheral` trait (as MCU-based Gatt peripheral stacks often expect a closure with these
/// precise restrictions), it complicates the implementation of the BTP protocol and necessiates the isolation of the shared state in the
/// `BtpContext` structure.
pub struct BtpContext<M>
where
    M: RawMutex,
{
    pub(crate) state: Mutex<M, RefCell<BtpContextInner>>,
    pub(crate) handshake_notif: Notification<M>,
    pub(crate) available_notif: Notification<M>,
    pub(crate) recv_notif: Notification<M>,
    pub(crate) ack_notif: Notification<M>,
    pub(crate) send_notif: Notification<M>,
    pub(crate) changed_notif: Notification<M>,
}

impl<M> Default for BtpContext<M>
where
    M: RawMutex,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<M> BtpContext<M>
where
    M: RawMutex,
{
    /// Create a new BTP context.
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(RefCell::new(BtpContextInner::new())),
            handshake_notif: Notification::new(),
            available_notif: Notification::new(),
            recv_notif: Notification::new(),
            ack_notif: Notification::new(),
            send_notif: Notification::new(),
            changed_notif: Notification::new(),
        }
    }

    /// Create a BTP context in-place initializer.
    pub fn init() -> impl Init<Self> {
        init!(Self {
            state <- Mutex::init(RefCell::init(BtpContextInner::init())),
            handshake_notif: Notification::new(),
            available_notif: Notification::new(),
            recv_notif: Notification::new(),
            ack_notif: Notification::new(),
            send_notif: Notification::new(),
            changed_notif: Notification::new(),
        })
    }
}

impl<M> BtpContext<M>
where
    M: RawMutex,
{
    /// The `Btp` instance passes a closure of this method to the `GattPeripheral` implementation which is in use
    /// so that the peripheral can report to it subscribe, unsubscribe and write events.
    pub(crate) fn on_event(&self, event: GattPeripheralEvent) {
        let result = match event {
            GattPeripheralEvent::NotifyConnected(address) => self.on_connect(address),
            GattPeripheralEvent::NotifyDisconnected(address) => self.on_disconnect(address),
            GattPeripheralEvent::NotifySubscribed(address) => self.on_subscribe(address),
            GattPeripheralEvent::NotifyUnsubscribed(address) => self.on_unsubscribe(address),
            GattPeripheralEvent::Write {
                address,
                data,
                gatt_mtu,
            } => self.on_write(address, data, gatt_mtu),
        };

        if let Err(e) = result {
            error!("Unexpected error in GATT callback: {:?}", e);
        }
    }

    /// Handles a write event to characteristic `C1` from the GATT peripheral.
    fn on_write(&self, address: BtAddr, data: &[u8], gatt_mtu: Option<u16>) -> Result<(), Error> {
        trace!("Received {} bytes from {}", Bytes(data), address);

        self.state.lock(|internal| {
            let sessions = &mut internal.borrow_mut().sessions;

            if Session::is_handshake(data)? {
                if sessions.len() >= MAX_BTP_SESSIONS {
                    warn!(
                        "Too many BTP sessions, dropping a handshake request from address {}",
                        address
                    );
                } else {
                    // Unwrap is safe because we checked the length above
                    unwrap!(sessions.push_init(
                        Session::process_rx_handshake(address, data, gatt_mtu)?
                            .into_fallible::<Error>(),
                        || ErrorCode::ResourceExhausted.into(),
                    ));
                }

                Ok(())
            } else {
                let Some(index) = sessions
                    .iter_mut()
                    .position(|session| session.address() == address)
                else {
                    warn!(
                        "Dropping data from address {} because there is no session for it",
                        address
                    );
                    return Ok(());
                };

                let session = &mut sessions[index];
                let result = session.process_rx_data(data);

                if result.is_err() {
                    sessions.swap_remove(index);
                    error!(
                        "Dropping session {} because of an error: {:?}",
                        address, result
                    );
                }

                self.available_notif.notify();
                self.recv_notif.notify();
                self.ack_notif.notify();
                self.send_notif.notify();

                result
            }
        })
    }

    /// Handles a subscribe event to characteristic `C2` from the GATT peripheral.
    fn on_connect(&self, address: BtAddr) -> Result<(), Error> {
        debug!("Connect request from {}", address);

        self.state.lock(|internal| {
            internal.borrow_mut().conn_ct += 1;
        });
        self.changed_notif.notify();

        Ok(())
    }

    /// Handles an unsubscribe event to characteristic `C2` from the GATT peripheral.
    fn on_disconnect(&self, address: BtAddr) -> Result<(), Error> {
        debug!("Disconnect request from {}", address);

        self.state.lock(|internal| {
            internal.borrow_mut().conn_ct -= 1;
        });
        self.changed_notif.notify();

        Ok(())
    }

    /// Handles a subscribe event to characteristic `C2` from the GATT peripheral.
    fn on_subscribe(&self, address: BtAddr) -> Result<(), Error> {
        debug!("Subscribe request from {}", address);

        self.state.lock(|internal| {
            let sessions = &mut internal.borrow_mut().sessions;
            if let Some(session) = sessions
                .iter_mut()
                .find(|session| session.address() == address)
            {
                if !session.set_subscribed() {
                    warn!("Got a second subscribe request for an address which is already subscribed: {}", address);
                    Err(ErrorCode::InvalidState)?;
                }

                self.handshake_notif.notify();
            } else {
                warn!("No session for address {}", address);
            }

            self.changed_notif.notify();

            Ok(())
        })
    }

    /// Handles an unsubscribe event to characteristic `C2` from the GATT peripheral.
    fn on_unsubscribe(&self, address: BtAddr) -> Result<(), Error> {
        debug!("Unsubscribe request from {}", address);

        self.remove(|session| session.address() == address)?;

        self.changed_notif.notify();

        Ok(())
    }

    pub fn conn_ct(&self) -> usize {
        self.state.lock(|internal| internal.borrow().conn_ct)
    }

    pub async fn wait_changed(&self) {
        self.changed_notif.wait().await;
    }

    /// Removes all sesssions that match the provided condition.
    pub(crate) fn remove<F>(&self, condition: F) -> Result<(), Error>
    where
        F: Fn(&Session) -> bool,
    {
        self.state.lock(|internal| {
            let sessions = &mut internal.borrow_mut().sessions;
            while let Some(index) = sessions.iter().position(&condition) {
                let session = sessions.swap_remove(index);
                debug!("Session {} removed", session.address());

                self.send_notif.notify();
            }

            Ok(())
        })
    }

    /// Will wait until there is at least one session which has a BTP SDU packet ready for consumption by the Matter stack.
    ///
    /// `Btp::wait_available` internally delegates to this method.
    pub(crate) async fn wait_available(&self) -> Result<(), Error> {
        loop {
            let available = self.state.lock(|internal| {
                internal
                    .borrow()
                    .sessions
                    .iter()
                    .any(|session| session.message_available())
            });

            if available {
                break;
            }

            self.available_notif.wait().await;
        }

        Ok(())
    }

    /// Receive a Matter (a.k.a. BTP SDU) packet.
    ///
    /// If there is no packet available, this method will block asynchronously until a packet is available.
    /// Returns the size of the received packet, as well as the address of the BLE peer from where the packet originates.
    ///
    /// `Btp::recv` internally delegates to this method.
    pub(crate) async fn recv(&self, buf: &mut [u8]) -> Result<(usize, BtAddr), Error> {
        loop {
            let result = self.state.lock(|internal| {
                let sessions = &mut internal.borrow_mut().sessions;

                let Some(session) = sessions
                    .iter_mut()
                    .find(|session| session.message_available())
                else {
                    return Ok::<_, Error>(None);
                };

                let len = session.fetch_message(buf)?;

                Ok(Some((len, session.address())))
            })?;

            if let Some(result) = result {
                break Ok(result);
            }

            self.recv_notif.wait().await;
        }
    }
}
