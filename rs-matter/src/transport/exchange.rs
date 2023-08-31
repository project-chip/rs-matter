use crate::{
    acl::Accessor,
    error::{Error, ErrorCode},
    utils::{epoch::Epoch, select::Notification},
    Matter,
};

use super::{
    mrp::ReliableMessage,
    network::Address,
    packet::Packet,
    session::{CloneData, Session, SessionMgr},
};

pub const MAX_EXCHANGES: usize = 8;

#[derive(Debug, PartialEq, Eq, Copy, Clone, Default)]
pub(crate) enum Role {
    #[default]
    Initiator = 0,
    Responder = 1,
}

impl Role {
    pub fn complementary(is_initiator: bool) -> Self {
        if is_initiator {
            Self::Responder
        } else {
            Self::Initiator
        }
    }
}

#[derive(Debug)]
pub(crate) struct ExchangeCtx {
    pub(crate) id: ExchangeId,
    pub(crate) role: Role,
    pub(crate) mrp: ReliableMessage,
    pub(crate) state: ExchangeState,
}

impl ExchangeCtx {
    pub(crate) fn get<'r>(
        exchanges: &'r mut heapless::Vec<ExchangeCtx, MAX_EXCHANGES>,
        id: &ExchangeId,
    ) -> Option<&'r mut ExchangeCtx> {
        exchanges.iter_mut().find(|exchange| exchange.id == *id)
    }

    pub fn new_ephemeral(session_id: SessionId, reply_to: Option<&Packet<'_>>) -> Self {
        Self {
            id: ExchangeId {
                id: if let Some(rx) = reply_to {
                    rx.proto.exch_id
                } else {
                    0
                },
                session_id: session_id.clone(),
            },
            role: if reply_to.is_some() {
                Role::Responder
            } else {
                Role::Initiator
            },
            mrp: ReliableMessage::new(),
            state: ExchangeState::Active,
        }
    }

    pub(crate) fn prep_ephemeral(
        session_id: SessionId,
        session_mgr: &mut SessionMgr,
        reply_to: Option<&Packet<'_>>,
        tx: &mut Packet<'_>,
    ) -> Result<ExchangeCtx, Error> {
        let mut ctx = Self::new_ephemeral(session_id.clone(), reply_to);

        let sess_index = session_mgr.get(
            session_id.id,
            session_id.peer_addr,
            session_id.peer_nodeid,
            session_id.is_encrypted,
        );

        let epoch = session_mgr.epoch;
        let rand = session_mgr.rand;

        if let Some(rx) = reply_to {
            ctx.mrp.recv(rx, epoch)?;
        } else {
            tx.proto.set_initiator();
        }

        tx.unset_reliable();

        if let Some(sess_index) = sess_index {
            let session = session_mgr.mut_by_index(sess_index).unwrap();
            ctx.pre_send_sess(session, tx, epoch)?;
        } else {
            let mut session =
                Session::new(session_id.peer_addr, session_id.peer_nodeid, epoch, rand);
            ctx.pre_send_sess(&mut session, tx, epoch)?;
        }

        Ok(ctx)
    }

    pub(crate) fn pre_send(
        &mut self,
        session_mgr: &mut SessionMgr,
        tx: &mut Packet,
    ) -> Result<(), Error> {
        let epoch = session_mgr.epoch;

        let sess_index = session_mgr
            .get(
                self.id.session_id.id,
                self.id.session_id.peer_addr,
                self.id.session_id.peer_nodeid,
                self.id.session_id.is_encrypted,
            )
            .ok_or(ErrorCode::NoSession)?;

        let session = session_mgr.mut_by_index(sess_index).unwrap();

        self.pre_send_sess(session, tx, epoch)
    }

    pub(crate) fn pre_send_sess(
        &mut self,
        session: &mut Session,
        tx: &mut Packet,
        epoch: Epoch,
    ) -> Result<(), Error> {
        tx.proto.exch_id = self.id.id;
        if self.role == Role::Initiator {
            tx.proto.set_initiator();
        }

        session.pre_send(tx)?;
        self.mrp.pre_send(tx)?;
        session.send(epoch, tx)
    }
}

#[derive(Debug, Clone)]
pub(crate) enum ExchangeState {
    Construction {
        rx: *mut Packet<'static>,
        notification: *const Notification,
    },
    Active,
    Acknowledge {
        notification: *const Notification,
    },
    ExchangeSend {
        tx: *const Packet<'static>,
        rx: *mut Packet<'static>,
        notification: *const Notification,
    },
    ExchangeRecv {
        _tx: *const Packet<'static>,
        tx_acknowledged: bool,
        rx: *mut Packet<'static>,
        notification: *const Notification,
    },
    Complete {
        tx: *const Packet<'static>,
        notification: *const Notification,
    },
    CompleteAcknowledge {
        _tx: *const Packet<'static>,
        notification: *const Notification,
    },
    Closed,
}

pub struct ExchangeCtr<'a> {
    pub(crate) exchange: Exchange<'a>,
    pub(crate) construction_notification: &'a Notification,
}

impl<'a> ExchangeCtr<'a> {
    pub const fn id(&self) -> &ExchangeId {
        self.exchange.id()
    }

    #[allow(clippy::all)]
    // Should be #[allow(clippy::needless_pass_by_ref_mut)], but this is only in 1.73 which is not released yet
    // rx is actually modified, but via an unsafe `*mut Packet<'static>` and apparently Clippy can't see this
    pub async fn get(mut self, rx: &mut Packet<'_>) -> Result<Exchange<'a>, Error> {
        let construction_notification = self.construction_notification;

        self.exchange.with_ctx_mut(move |exchange, ctx| {
            if !matches!(ctx.state, ExchangeState::Active) {
                Err(ErrorCode::NoExchange)?;
            }

            let rx: &'static mut Packet<'static> = unsafe { core::mem::transmute(rx) };
            let notification: &'static Notification =
                unsafe { core::mem::transmute(&exchange.notification) };

            ctx.state = ExchangeState::Construction { rx, notification };

            construction_notification.signal(());

            Ok(())
        })?;

        self.exchange.notification.wait().await;

        Ok(self.exchange)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ExchangeId {
    pub id: u16,
    pub session_id: SessionId,
}

impl ExchangeId {
    pub fn load(rx: &Packet) -> Self {
        Self {
            id: rx.proto.exch_id,
            session_id: SessionId::load(rx),
        }
    }
}
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SessionId {
    pub id: u16,
    pub peer_addr: Address,
    pub peer_nodeid: Option<u64>,
    pub is_encrypted: bool,
}

impl SessionId {
    pub fn load(rx: &Packet) -> Self {
        Self {
            id: rx.plain.sess_id,
            peer_addr: rx.peer,
            peer_nodeid: rx.plain.get_src_u64(),
            is_encrypted: rx.plain.is_encrypted(),
        }
    }
}
pub struct Exchange<'a> {
    pub(crate) id: ExchangeId,
    pub(crate) matter: &'a Matter<'a>,
    pub(crate) notification: Notification,
}

impl<'a> Exchange<'a> {
    pub const fn id(&self) -> &ExchangeId {
        &self.id
    }

    pub fn accessor(&self) -> Result<Accessor<'a>, Error> {
        self.with_session(|sess| Ok(Accessor::for_session(sess, &self.matter.acl_mgr)))
    }

    pub fn with_session_mut<F, T>(&self, f: F) -> Result<T, Error>
    where
        F: FnOnce(&mut Session) -> Result<T, Error>,
    {
        self.with_ctx(|_self, ctx| {
            let mut session_mgr = _self.matter.session_mgr.borrow_mut();

            let sess_index = session_mgr
                .get(
                    ctx.id.session_id.id,
                    ctx.id.session_id.peer_addr,
                    ctx.id.session_id.peer_nodeid,
                    ctx.id.session_id.is_encrypted,
                )
                .ok_or(ErrorCode::NoSession)?;

            f(session_mgr.mut_by_index(sess_index).unwrap())
        })
    }

    pub fn with_session<F, T>(&self, f: F) -> Result<T, Error>
    where
        F: FnOnce(&Session) -> Result<T, Error>,
    {
        self.with_session_mut(|sess| f(sess))
    }

    pub async fn acknowledge(&mut self) -> Result<(), Error> {
        let wait = self.with_ctx_mut(|_self, ctx| {
            if !matches!(ctx.state, ExchangeState::Active) {
                Err(ErrorCode::NoExchange)?;
            }

            if ctx.mrp.is_empty() {
                Ok(false)
            } else {
                ctx.state = ExchangeState::Acknowledge {
                    notification: &_self.notification as *const _,
                };
                _self.matter.send_notification.signal(());

                Ok(true)
            }
        })?;

        if wait {
            self.notification.wait().await;
        }

        Ok(())
    }

    pub async fn exchange(
        &mut self,
        tx: &mut Packet<'_>,
        rx: &mut Packet<'_>,
    ) -> Result<(), Error> {
        let tx: &mut Packet<'static> = unsafe { core::mem::transmute(tx) };
        let rx: &mut Packet<'static> = unsafe { core::mem::transmute(rx) };

        self.with_ctx_mut(|_self, ctx| {
            if !matches!(ctx.state, ExchangeState::Active) {
                Err(ErrorCode::NoExchange)?;
            }

            let mut session_mgr = _self.matter.session_mgr.borrow_mut();
            ctx.pre_send(&mut session_mgr, tx)?;

            ctx.state = ExchangeState::ExchangeSend {
                tx: tx as *const _,
                rx: rx as *mut _,
                notification: &_self.notification as *const _,
            };
            _self.matter.send_notification.signal(());

            Ok(())
        })?;

        self.notification.wait().await;

        Ok(())
    }

    pub async fn complete(mut self, tx: &mut Packet<'_>) -> Result<(), Error> {
        self.send_complete(tx).await
    }

    pub async fn send_complete(&mut self, tx: &mut Packet<'_>) -> Result<(), Error> {
        let tx: &mut Packet<'static> = unsafe { core::mem::transmute(tx) };

        self.with_ctx_mut(|_self, ctx| {
            if !matches!(ctx.state, ExchangeState::Active) {
                Err(ErrorCode::NoExchange)?;
            }

            let mut session_mgr = _self.matter.session_mgr.borrow_mut();
            ctx.pre_send(&mut session_mgr, tx)?;

            ctx.state = ExchangeState::Complete {
                tx: tx as *const _,
                notification: &_self.notification as *const _,
            };
            _self.matter.send_notification.signal(());

            Ok(())
        })?;

        self.notification.wait().await;

        Ok(())
    }

    pub(crate) fn get_next_sess_id(&mut self) -> u16 {
        self.matter.session_mgr.borrow_mut().get_next_sess_id()
    }

    pub(crate) async fn clone_session(
        &mut self,
        tx: &mut Packet<'_>,
        clone_data: &CloneData,
    ) -> Result<usize, Error> {
        loop {
            let result = self
                .matter
                .session_mgr
                .borrow_mut()
                .clone_session(clone_data);

            match result {
                Err(err) if err.code() == ErrorCode::NoSpaceSessions => {
                    self.matter.evict_session(tx).await?
                }
                other => break other,
            }
        }
    }

    fn with_ctx<F, T>(&self, f: F) -> Result<T, Error>
    where
        F: FnOnce(&Self, &ExchangeCtx) -> Result<T, Error>,
    {
        let mut exchanges = self.matter.exchanges.borrow_mut();

        let exchange = ExchangeCtx::get(&mut exchanges, &self.id).ok_or(ErrorCode::NoExchange)?; // TODO

        f(self, exchange)
    }

    fn with_ctx_mut<F, T>(&mut self, f: F) -> Result<T, Error>
    where
        F: FnOnce(&mut Self, &mut ExchangeCtx) -> Result<T, Error>,
    {
        let mut exchanges = self.matter.exchanges.borrow_mut();

        let exchange = ExchangeCtx::get(&mut exchanges, &self.id).ok_or(ErrorCode::NoExchange)?; // TODO

        f(self, exchange)
    }
}

impl<'a> Drop for Exchange<'a> {
    fn drop(&mut self) {
        let _ = self.with_ctx_mut(|_self, ctx| {
            ctx.state = ExchangeState::Closed;
            _self.matter.send_notification.signal(());

            Ok(())
        });
    }
}
