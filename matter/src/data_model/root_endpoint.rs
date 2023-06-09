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
    objects::{Cluster, EmptyHandler, Endpoint, EndptId},
    sdm::{
        admin_commissioning::{self, AdminCommCluster},
        dev_att::DevAttDataFetcher,
        failsafe::FailSafe,
        general_commissioning::{self, GenCommCluster},
        noc::{self, NocCluster},
        nw_commissioning::{self, NwCommCluster},
    },
    system_model::{
        access_control::{self, AccessControlCluster},
        descriptor::{self, DescriptorCluster},
    },
};

pub type RootEndpointHandler<'a> = handler_chain_type!(
    DescriptorCluster,
    BasicInfoCluster<'a>,
    GenCommCluster<'a>,
    NwCommCluster,
    AdminCommCluster<'a>,
    NocCluster<'a>,
    AccessControlCluster<'a>
);

pub const CLUSTERS: [Cluster<'static>; 7] = [
    descriptor::CLUSTER,
    cluster_basic_information::CLUSTER,
    general_commissioning::CLUSTER,
    nw_commissioning::CLUSTER,
    admin_commissioning::CLUSTER,
    noc::CLUSTER,
    access_control::CLUSTER,
];

pub fn endpoint(id: EndptId) -> Endpoint<'static> {
    Endpoint {
        id,
        device_type: super::device_types::DEV_TYPE_ROOT_NODE,
        clusters: &CLUSTERS,
    }
}

pub fn handler<'a>(endpoint_id: u16, matter: &'a Matter<'a>) -> RootEndpointHandler<'a> {
    wrap(
        endpoint_id,
        matter.dev_det(),
        matter.dev_att(),
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
            access_control::ID,
            AccessControlCluster::new(acl, rand),
        )
        .chain(
            endpoint_id,
            noc::ID,
            NocCluster::new(dev_att, fabric, acl, failsafe, mdns_mgr, epoch, rand),
        )
        .chain(
            endpoint_id,
            admin_commissioning::ID,
            AdminCommCluster::new(pase, mdns_mgr, rand),
        )
        .chain(endpoint_id, nw_commissioning::ID, NwCommCluster::new(rand))
        .chain(
            endpoint_id,
            general_commissioning::ID,
            GenCommCluster::new(failsafe, rand),
        )
        .chain(
            endpoint_id,
            cluster_basic_information::ID,
            BasicInfoCluster::new(basic_info, rand),
        )
        .chain(endpoint_id, descriptor::ID, DescriptorCluster::new(rand))
}
