use core::{borrow::Borrow, cell::RefCell};

use crate::{
    acl::AclMgr,
    fabric::FabricMgr,
    handler_chain_type,
    mdns::MdnsMgr,
    secure_channel::pake::PaseMgr,
    utils::{epoch::Epoch, rand::Rand},
    Matter,
};

use super::{
    cluster_basic_information::{self, BasicInfoCluster, BasicInfoConfig},
    objects::{Cluster, EmptyHandler},
    sdm::{
        admin_commissioning::{self, AdminCommCluster},
        dev_att::DevAttDataFetcher,
        failsafe::FailSafe,
        general_commissioning::{self, GenCommCluster},
        noc::{self, NocCluster},
        nw_commissioning::{self, NwCommCluster},
    },
    system_model::access_control::{self, AccessControlCluster},
};

pub type RootEndpointHandler<'a> = handler_chain_type!(
    AccessControlCluster<'a>,
    NocCluster<'a>,
    AdminCommCluster<'a>,
    NwCommCluster,
    GenCommCluster,
    BasicInfoCluster<'a>
);

pub const CLUSTERS: [Cluster<'static>; 6] = [
    cluster_basic_information::CLUSTER,
    general_commissioning::CLUSTER,
    nw_commissioning::CLUSTER,
    admin_commissioning::CLUSTER,
    noc::CLUSTER,
    access_control::CLUSTER,
];

pub fn handler<'a>(
    endpoint_id: u16,
    dev_att: &'a dyn DevAttDataFetcher,
    matter: &'a Matter<'a>,
) -> RootEndpointHandler<'a> {
    wrap(
        endpoint_id,
        matter.dev_det(),
        dev_att,
        matter.borrow(),
        matter.borrow(),
        matter.borrow(),
        matter.borrow(),
        matter.borrow(),
        *matter.borrow(),
        *matter.borrow(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn wrap<'a>(
    endpoint_id: u16,
    basic_info: &'a BasicInfoConfig<'a>,
    dev_att: &'a dyn DevAttDataFetcher,
    pase: &'a RefCell<PaseMgr>,
    fabric: &'a RefCell<FabricMgr>,
    acl: &'a RefCell<AclMgr>,
    failsafe: &'a RefCell<FailSafe>,
    mdns_mgr: &'a RefCell<MdnsMgr<'a>>,
    epoch: Epoch,
    rand: Rand,
) -> RootEndpointHandler<'a> {
    EmptyHandler
        .chain(
            endpoint_id,
            cluster_basic_information::CLUSTER.id,
            BasicInfoCluster::new(basic_info, rand),
        )
        .chain(
            endpoint_id,
            general_commissioning::CLUSTER.id,
            GenCommCluster::new(rand),
        )
        .chain(
            endpoint_id,
            nw_commissioning::CLUSTER.id,
            NwCommCluster::new(rand),
        )
        .chain(
            endpoint_id,
            admin_commissioning::CLUSTER.id,
            AdminCommCluster::new(pase, mdns_mgr, rand),
        )
        .chain(
            endpoint_id,
            noc::CLUSTER.id,
            NocCluster::new(dev_att, fabric, acl, failsafe, mdns_mgr, epoch, rand),
        )
        .chain(
            endpoint_id,
            access_control::CLUSTER.id,
            AccessControlCluster::new(acl, rand),
        )
}
