use crate::handler_chain_type;
use crate::utils::rand::Rand;

use super::cluster_basic_information::{self, BasicInfoCluster};
use super::objects::{Cluster, Dataver, EmptyHandler, Endpoint, EndptId, HandlerCompat};
use super::sdm::admin_commissioning::{self, AdminCommCluster};
use super::sdm::ethernet_nw_diagnostics::{self, EthNwDiagCluster};
use super::sdm::general_commissioning::{
    self, BasicCommissioningInfo, ConcurrentConnectionPolicy, GenCommCluster,
};
use super::sdm::general_diagnostics::{self, GenDiagCluster};
use super::sdm::group_key_management::{self, GrpKeyMgmtCluster};
use super::sdm::noc::{self, NocCluster};
use super::sdm::nw_commissioning::{self, EthNwCommCluster};
use super::sdm::wifi_nw_diagnostics;
use super::system_model::access_control::{self, AccessControlCluster};
use super::system_model::descriptor::{self, DescriptorCluster};

const ETH_NW_CLUSTERS: [Cluster<'static>; 10] = [
    descriptor::CLUSTER,
    cluster_basic_information::CLUSTER,
    general_commissioning::CLUSTER,
    nw_commissioning::ETH_CLUSTER,
    admin_commissioning::CLUSTER,
    noc::CLUSTER,
    access_control::CLUSTER,
    general_diagnostics::CLUSTER,
    ethernet_nw_diagnostics::CLUSTER,
    group_key_management::CLUSTER,
];

const WIFI_NW_CLUSTERS: [Cluster<'static>; 10] = [
    descriptor::CLUSTER,
    cluster_basic_information::CLUSTER,
    general_commissioning::CLUSTER,
    nw_commissioning::WIFI_CLUSTER,
    admin_commissioning::CLUSTER,
    noc::CLUSTER,
    access_control::CLUSTER,
    general_diagnostics::CLUSTER,
    wifi_nw_diagnostics::CLUSTER,
    group_key_management::CLUSTER,
];

const THREAD_NW_CLUSTERS: [Cluster<'static>; 10] = [
    descriptor::CLUSTER,
    cluster_basic_information::CLUSTER,
    general_commissioning::CLUSTER,
    nw_commissioning::THR_CLUSTER,
    admin_commissioning::CLUSTER,
    noc::CLUSTER,
    access_control::CLUSTER,
    general_diagnostics::CLUSTER,
    wifi_nw_diagnostics::CLUSTER,
    group_key_management::CLUSTER,
];

/// The type of operational network (Ethernet, Wifi or Thread)
/// for which root endpoint meta-data is being requested
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum OperNwType {
    Ethernet,
    Wifi,
    Thread,
}

/// A utility function to create a root (Endpoint 0) object using the requested operational network type.
pub const fn endpoint(id: EndptId, op_nw_type: OperNwType) -> Endpoint<'static> {
    Endpoint {
        id,
        device_types: &[super::device_types::DEV_TYPE_ROOT_NODE],
        clusters: clusters(op_nw_type),
    }
}

/// A utility function to return the clusters for a root (Endpoint 0) object using the requested operational network type.
pub const fn clusters(op_nw_type: OperNwType) -> &'static [Cluster<'static>] {
    match op_nw_type {
        OperNwType::Ethernet => &ETH_NW_CLUSTERS,
        OperNwType::Wifi => &WIFI_NW_CLUSTERS,
        OperNwType::Thread => &THREAD_NW_CLUSTERS,
    }
}

/// A type alias for a root (Endpoint 0) handler using Ethernet as an operational network
pub type EthRootEndpointHandler<'a> = RootEndpointHandler<'a, EthNwCommCluster, EthNwDiagCluster>;

/// A type representing the type of the root (Endpoint 0) handler
/// which is generic over the operational transport clusters (i.e. Ethernet, Wifi or Thread)
pub type RootEndpointHandler<'a, NWCOMM, NWDIAG> = handler_chain_type!(
    NWCOMM,
    NWDIAG,
    HandlerCompat<descriptor::DescriptorCluster<'a>>,
    HandlerCompat<cluster_basic_information::BasicInfoCluster>,
    HandlerCompat<general_commissioning::GenCommCluster<'a>>,
    HandlerCompat<admin_commissioning::AdminCommCluster>,
    HandlerCompat<noc::NocCluster>,
    HandlerCompat<access_control::AccessControlCluster>,
    HandlerCompat<general_diagnostics::GenDiagCluster>,
    HandlerCompat<group_key_management::GrpKeyMgmtCluster>
);

/// A utility function to instantiate the root (Endpoint 0) handler using Ethernet as the operational network.
pub fn eth_handler(endpoint_id: u16, rand: Rand) -> EthRootEndpointHandler<'static> {
    handler(
        endpoint_id,
        EthNwCommCluster::new(Dataver::new_rand(rand)),
        ethernet_nw_diagnostics::ID,
        EthNwDiagCluster::new(Dataver::new_rand(rand)),
        &true,
        rand,
    )
}

/// A utility function to instantiate the root (Endpoint 0) handler.
/// Besides a `Rand` function, this function
/// needs user-supplied implementations of the network commissioning
/// and network diagnostics clusters.
pub fn handler<NWCOMM, NWDIAG>(
    endpoint_id: u16,
    nwcomm: NWCOMM,
    nwdiag_id: u32,
    nwdiag: NWDIAG,
    concurrent_connection_policy: &dyn ConcurrentConnectionPolicy,
    rand: Rand,
) -> RootEndpointHandler<'_, NWCOMM, NWDIAG> {
    wrap(
        endpoint_id,
        nwcomm,
        nwdiag_id,
        nwdiag,
        concurrent_connection_policy,
        rand,
    )
}

fn wrap<NWCOMM, NWDIAG>(
    endpoint_id: u16,
    nwcomm: NWCOMM,
    nwdiag_id: u32,
    nwdiag: NWDIAG,
    concurrent_connection_policy: &dyn ConcurrentConnectionPolicy,
    rand: Rand,
) -> RootEndpointHandler<'_, NWCOMM, NWDIAG> {
    EmptyHandler
        .chain(
            endpoint_id,
            group_key_management::ID,
            HandlerCompat(GrpKeyMgmtCluster::new(Dataver::new_rand(rand))),
        )
        .chain(
            endpoint_id,
            general_diagnostics::ID,
            HandlerCompat(GenDiagCluster::new(Dataver::new_rand(rand))),
        )
        .chain(
            endpoint_id,
            access_control::ID,
            HandlerCompat(AccessControlCluster::new(Dataver::new_rand(rand))),
        )
        .chain(
            endpoint_id,
            noc::ID,
            HandlerCompat(NocCluster::new(Dataver::new_rand(rand))),
        )
        .chain(
            endpoint_id,
            admin_commissioning::ID,
            HandlerCompat(AdminCommCluster::new(Dataver::new_rand(rand))),
        )
        .chain(
            endpoint_id,
            general_commissioning::ID,
            HandlerCompat(GenCommCluster::new(
                Dataver::new_rand(rand),
                BasicCommissioningInfo::new(),
                concurrent_connection_policy,
            )),
        )
        .chain(
            endpoint_id,
            cluster_basic_information::ID,
            HandlerCompat(BasicInfoCluster::new(Dataver::new_rand(rand))),
        )
        .chain(
            endpoint_id,
            descriptor::ID,
            HandlerCompat(DescriptorCluster::new(Dataver::new_rand(rand))),
        )
        .chain(endpoint_id, nwdiag_id, nwdiag)
        .chain(endpoint_id, nw_commissioning::ID, nwcomm)
}
