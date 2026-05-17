/*
 *
 *    Copyright (c) 2023-2026 Project CHIP Authors
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

use std::collections::BTreeSet;

use embassy_futures::block_on;
use embassy_futures::select::select;

use rs_matter::dm::clusters::app::on_off;
use rs_matter::dm::clusters::{
    acl, adm_comm, basic_info, desc, gen_comm, gen_diag, grp_key_mgmt, net_comm, noc, time_sync,
};
use rs_matter::dm::GlobalElements;
use rs_matter::im::client::{ImClient, SubscribeOutcome, TxOutcome};
use rs_matter::im::AttrPath;
use rs_matter::im::AttrResp;
use rs_matter::im::GenericPath;
use rs_matter::utils::select::Coalesce;

use crate::common::e2e::im::attributes::TestAttrResp;
use crate::common::e2e::im::echo_cluster as echo;
use crate::common::e2e::new_default_runner;
use crate::common::init_env_logger;
use crate::{attr_data, attr_data_lel};

static ATTR_RESPS: &[TestAttrResp<'static>] = &[
    attr_data!(0, 29, desc::AttributeId::DeviceTypeList, None),
    attr_data!(0, 29, desc::AttributeId::ServerList, None),
    attr_data!(0, 29, desc::AttributeId::ClientList, None),
    attr_data!(0, 29, desc::AttributeId::PartsList, None),
    attr_data!(0, 29, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 29, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 29, GlobalElements::AttributeList, None),
    attr_data!(0, 29, GlobalElements::FeatureMap, None),
    attr_data!(0, 29, GlobalElements::ClusterRevision, None),
    attr_data!(0, 31, acl::AttributeId::Acl, None),
    attr_data!(0, 31, acl::AttributeId::SubjectsPerAccessControlEntry, None),
    attr_data!(0, 31, acl::AttributeId::TargetsPerAccessControlEntry, None),
    attr_data!(0, 31, acl::AttributeId::AccessControlEntriesPerFabric, None),
    attr_data!(0, 31, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 31, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 31, GlobalElements::AttributeList, None),
    attr_data!(0, 31, GlobalElements::FeatureMap, None),
    attr_data!(0, 31, GlobalElements::ClusterRevision, None),
    attr_data!(0, 40, basic_info::AttributeId::DataModelRevision, None),
    attr_data!(0, 40, basic_info::AttributeId::VendorName, None),
    attr_data!(0, 40, basic_info::AttributeId::VendorID, None),
    attr_data!(0, 40, basic_info::AttributeId::ProductName, None),
    attr_data!(0, 40, basic_info::AttributeId::ProductID, None),
    attr_data!(0, 40, basic_info::AttributeId::NodeLabel, None),
    attr_data!(0, 40, basic_info::AttributeId::Location, None),
    attr_data!(0, 40, basic_info::AttributeId::HardwareVersion, None),
    attr_data!(0, 40, basic_info::AttributeId::HardwareVersionString, None),
    attr_data!(0, 40, basic_info::AttributeId::SoftwareVersion, None),
    attr_data!(0, 40, basic_info::AttributeId::SoftwareVersionString, None),
    attr_data!(0, 40, basic_info::AttributeId::ManufacturingDate, None),
    attr_data!(0, 40, basic_info::AttributeId::PartNumber, None),
    attr_data!(0, 40, basic_info::AttributeId::ProductURL, None),
    attr_data!(0, 40, basic_info::AttributeId::ProductLabel, None),
    attr_data!(0, 40, basic_info::AttributeId::SerialNumber, None),
    attr_data!(0, 40, basic_info::AttributeId::LocalConfigDisabled, None),
    attr_data!(0, 40, basic_info::AttributeId::UniqueID, None),
    attr_data!(0, 40, basic_info::AttributeId::CapabilityMinima, None),
    attr_data!(0, 40, basic_info::AttributeId::ProductAppearance, None),
    attr_data!(0, 40, basic_info::AttributeId::SpecificationVersion, None),
    attr_data!(0, 40, basic_info::AttributeId::MaxPathsPerInvoke, None),
    //attr_data!(0, 40, basic_info::AttributeId::ConfigurationVersion, None),
    attr_data!(0, 40, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 40, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 40, GlobalElements::AttributeList, None),
    attr_data!(0, 40, GlobalElements::FeatureMap, None),
    attr_data!(0, 40, GlobalElements::ClusterRevision, None),
    attr_data!(0, 48, gen_comm::AttributeId::Breadcrumb, None),
    attr_data!(0, 48, gen_comm::AttributeId::BasicCommissioningInfo, None),
    attr_data!(0, 48, gen_comm::AttributeId::RegulatoryConfig, None),
    attr_data!(0, 48, gen_comm::AttributeId::LocationCapability, None),
    attr_data!(
        0,
        48,
        gen_comm::AttributeId::SupportsConcurrentConnection,
        None
    ),
    attr_data!(0, 48, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 48, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 48, GlobalElements::AttributeList, None),
    attr_data!(0, 48, GlobalElements::FeatureMap, None),
    attr_data!(0, 48, GlobalElements::ClusterRevision, None),
    attr_data!(0, 51, gen_diag::AttributeId::NetworkInterfaces, None),
    attr_data!(0, 51, gen_diag::AttributeId::RebootCount, None),
    attr_data!(0, 51, gen_diag::AttributeId::UpTime, None),
    attr_data!(0, 51, gen_diag::AttributeId::TestEventTriggersEnabled, None),
    attr_data!(0, 51, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 51, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 51, GlobalElements::AttributeList, None),
    attr_data!(0, 51, GlobalElements::FeatureMap, None),
    attr_data!(0, 51, GlobalElements::ClusterRevision, None),
    // SoftwareDiagnostics (0x0034 = 52): handler defaults expose
    // only required globals — heap counters and thread metrics are
    // opt-in via the handler's `HEAP` / `THREAD_METRICS` const
    // generics; the test runner uses the all-defaults shape.
    attr_data!(0, 52, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 52, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 52, GlobalElements::AttributeList, None),
    attr_data!(0, 52, GlobalElements::FeatureMap, None),
    attr_data!(0, 52, GlobalElements::ClusterRevision, None),
    // TimeSynchronization (0x0038 = 56): stub handler — `UTCTime` Null,
    // `Granularity` NoTime, `TimeSource` None (opted-in so the Python
    // test harness's `has_attribute(TimeSource)` gate on
    // `TC_TIMESYNC_2_1` matches), no features, no commands.
    attr_data!(0, 56, time_sync::AttributeId::UTCTime, None),
    attr_data!(0, 56, time_sync::AttributeId::Granularity, None),
    attr_data!(0, 56, time_sync::AttributeId::TimeSource, None),
    attr_data!(0, 56, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 56, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 56, GlobalElements::AttributeList, None),
    attr_data!(0, 56, GlobalElements::FeatureMap, None),
    attr_data!(0, 56, GlobalElements::ClusterRevision, None),
    attr_data!(0, 60, adm_comm::AttributeId::WindowStatus, None),
    attr_data!(0, 60, adm_comm::AttributeId::AdminFabricIndex, None),
    attr_data!(0, 60, adm_comm::AttributeId::AdminVendorId, None),
    attr_data!(0, 60, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 60, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 60, GlobalElements::AttributeList, None),
    attr_data!(0, 60, GlobalElements::FeatureMap, None),
    attr_data!(0, 60, GlobalElements::ClusterRevision, None),
    attr_data!(0, 62, noc::AttributeId::NOCs, None),
    attr_data!(0, 62, noc::AttributeId::Fabrics, None),
    attr_data!(0, 62, noc::AttributeId::SupportedFabrics, None),
    attr_data!(0, 62, noc::AttributeId::CommissionedFabrics, None),
    attr_data!(0, 62, noc::AttributeId::TrustedRootCertificates, None),
    attr_data!(0, 62, noc::AttributeId::CurrentFabricIndex, None),
    attr_data!(0, 62, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 62, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 62, GlobalElements::AttributeList, None),
    attr_data!(0, 62, GlobalElements::FeatureMap, None),
    attr_data!(0, 62, GlobalElements::ClusterRevision, None),
    attr_data!(0, 63, grp_key_mgmt::AttributeId::GroupKeyMap, None),
    attr_data!(0, 63, grp_key_mgmt::AttributeId::GroupTable, None),
    attr_data!(0, 63, grp_key_mgmt::AttributeId::MaxGroupsPerFabric, None),
    attr_data!(
        0,
        63,
        grp_key_mgmt::AttributeId::MaxGroupKeysPerFabric,
        None
    ),
    attr_data!(0, 63, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 63, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 63, GlobalElements::AttributeList, None),
    attr_data!(0, 63, GlobalElements::FeatureMap, None),
    attr_data!(0, 63, GlobalElements::ClusterRevision, None),
    attr_data!(0, 49, net_comm::AttributeId::MaxNetworks, None),
    attr_data!(0, 49, net_comm::AttributeId::Networks, None),
    attr_data!(0, 49, net_comm::AttributeId::InterfaceEnabled, None),
    attr_data!(0, 49, net_comm::AttributeId::LastNetworkingStatus, None),
    attr_data!(0, 49, net_comm::AttributeId::LastNetworkID, None),
    attr_data!(0, 49, net_comm::AttributeId::LastConnectErrorValue, None),
    attr_data!(0, 49, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 49, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 49, GlobalElements::AttributeList, None),
    attr_data!(0, 49, GlobalElements::FeatureMap, None),
    attr_data!(0, 49, GlobalElements::ClusterRevision, None),
    attr_data!(0, 55, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 55, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 55, GlobalElements::AttributeList, None),
    attr_data!(0, 55, GlobalElements::FeatureMap, None),
    attr_data!(0, 55, GlobalElements::ClusterRevision, None),
    attr_data!(0, echo::ID, echo::AttributesDiscriminants::Att1, None),
    attr_data!(0, echo::ID, echo::AttributesDiscriminants::Att2, None),
    attr_data!(0, echo::ID, echo::AttributesDiscriminants::AttCustom, None),
    attr_data!(0, echo::ID, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, echo::ID, GlobalElements::AcceptedCmdList, None),
    attr_data_lel!(0, echo::ID, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, echo::ID, GlobalElements::EventList, None),
    attr_data!(0, echo::ID, GlobalElements::AttributeList, None),
    attr_data!(0, echo::ID, GlobalElements::FeatureMap, None),
    attr_data!(0, echo::ID, GlobalElements::ClusterRevision, None),
    attr_data!(1, 29, desc::AttributeId::DeviceTypeList, None),
    attr_data!(1, 29, desc::AttributeId::ServerList, None),
    attr_data!(1, 29, desc::AttributeId::ClientList, None),
    attr_data!(1, 29, desc::AttributeId::PartsList, None),
    attr_data!(1, 29, GlobalElements::GeneratedCmdList, None),
    attr_data!(1, 29, GlobalElements::AcceptedCmdList, None),
    attr_data!(1, 29, GlobalElements::AttributeList, None),
    attr_data!(1, 29, GlobalElements::FeatureMap, None),
    attr_data!(1, 29, GlobalElements::ClusterRevision, None),
    attr_data!(1, 6, on_off::AttributeId::OnOff, None),
    attr_data!(1, 6, on_off::AttributeId::GlobalSceneControl, None),
    attr_data!(1, 6, on_off::AttributeId::OnTime, None),
    attr_data!(1, 6, on_off::AttributeId::OffWaitTime, None),
    attr_data!(1, 6, on_off::AttributeId::StartUpOnOff, None),
    attr_data!(1, 6, GlobalElements::GeneratedCmdList, None),
    attr_data!(1, 6, GlobalElements::AcceptedCmdList, None),
    attr_data!(1, 6, GlobalElements::AttributeList, None),
    attr_data!(1, 6, GlobalElements::FeatureMap, None),
    attr_data!(1, 6, GlobalElements::ClusterRevision, None),
    attr_data!(1, echo::ID, echo::AttributesDiscriminants::Att1, None),
    attr_data!(1, echo::ID, echo::AttributesDiscriminants::Att2, None),
    attr_data!(1, echo::ID, echo::AttributesDiscriminants::AttCustom, None),
    attr_data!(1, echo::ID, GlobalElements::GeneratedCmdList, None),
    attr_data!(1, echo::ID, GlobalElements::AcceptedCmdList, None),
    attr_data!(1, echo::ID, GlobalElements::EventList, None),
    attr_data!(1, echo::ID, GlobalElements::AttributeList, None),
    attr_data!(1, echo::ID, GlobalElements::FeatureMap, None),
    attr_data!(1, echo::ID, GlobalElements::ClusterRevision, None),
];

static ATTR_SUBSCR_RESPS: &[TestAttrResp<'static>] = &[
    attr_data!(0, 29, desc::AttributeId::DeviceTypeList, None),
    attr_data!(0, 29, desc::AttributeId::ServerList, None),
    attr_data!(0, 29, desc::AttributeId::ClientList, None),
    attr_data!(0, 29, desc::AttributeId::PartsList, None),
    attr_data!(0, 29, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 29, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 29, GlobalElements::AttributeList, None),
    attr_data!(0, 29, GlobalElements::FeatureMap, None),
    attr_data!(0, 29, GlobalElements::ClusterRevision, None),
    attr_data!(0, 31, acl::AttributeId::Acl, None),
    attr_data!(0, 31, acl::AttributeId::SubjectsPerAccessControlEntry, None),
    attr_data!(0, 31, acl::AttributeId::TargetsPerAccessControlEntry, None),
    attr_data!(0, 31, acl::AttributeId::AccessControlEntriesPerFabric, None),
    attr_data!(0, 31, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 31, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 31, GlobalElements::AttributeList, None),
    attr_data!(0, 31, GlobalElements::FeatureMap, None),
    attr_data!(0, 31, GlobalElements::ClusterRevision, None),
    attr_data!(0, 40, basic_info::AttributeId::DataModelRevision, None),
    attr_data!(0, 40, basic_info::AttributeId::VendorName, None),
    attr_data!(0, 40, basic_info::AttributeId::VendorID, None),
    attr_data!(0, 40, basic_info::AttributeId::ProductName, None),
    attr_data!(0, 40, basic_info::AttributeId::ProductID, None),
    attr_data!(0, 40, basic_info::AttributeId::NodeLabel, None),
    attr_data!(0, 40, basic_info::AttributeId::Location, None),
    attr_data!(0, 40, basic_info::AttributeId::HardwareVersion, None),
    attr_data!(0, 40, basic_info::AttributeId::HardwareVersionString, None),
    attr_data!(0, 40, basic_info::AttributeId::SoftwareVersion, None),
    attr_data!(0, 40, basic_info::AttributeId::SoftwareVersionString, None),
    attr_data!(0, 40, basic_info::AttributeId::ManufacturingDate, None),
    attr_data!(0, 40, basic_info::AttributeId::PartNumber, None),
    attr_data!(0, 40, basic_info::AttributeId::ProductURL, None),
    attr_data!(0, 40, basic_info::AttributeId::ProductLabel, None),
    attr_data!(0, 40, basic_info::AttributeId::SerialNumber, None),
    attr_data!(0, 40, basic_info::AttributeId::LocalConfigDisabled, None),
    attr_data!(0, 40, basic_info::AttributeId::UniqueID, None),
    attr_data!(0, 40, basic_info::AttributeId::CapabilityMinima, None),
    attr_data!(0, 40, basic_info::AttributeId::ProductAppearance, None),
    attr_data!(0, 40, basic_info::AttributeId::SpecificationVersion, None),
    attr_data!(0, 40, basic_info::AttributeId::MaxPathsPerInvoke, None),
    //attr_data!(0, 40, basic_info::AttributeId::ConfigurationVersion, None),
    attr_data!(0, 40, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 40, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 40, GlobalElements::AttributeList, None),
    attr_data!(0, 40, GlobalElements::FeatureMap, None),
    attr_data!(0, 40, GlobalElements::ClusterRevision, None),
    attr_data!(0, 48, gen_comm::AttributeId::Breadcrumb, None),
    attr_data!(0, 48, gen_comm::AttributeId::BasicCommissioningInfo, None),
    attr_data!(0, 48, gen_comm::AttributeId::RegulatoryConfig, None),
    attr_data!(0, 48, gen_comm::AttributeId::LocationCapability, None),
    attr_data!(
        0,
        48,
        gen_comm::AttributeId::SupportsConcurrentConnection,
        None
    ),
    attr_data!(0, 48, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 48, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 48, GlobalElements::AttributeList, None),
    attr_data!(0, 48, GlobalElements::FeatureMap, None),
    attr_data!(0, 48, GlobalElements::ClusterRevision, None),
    attr_data!(0, 51, gen_diag::AttributeId::NetworkInterfaces, None),
    attr_data!(0, 51, gen_diag::AttributeId::RebootCount, None),
    attr_data!(0, 51, gen_diag::AttributeId::UpTime, None),
    attr_data!(0, 51, gen_diag::AttributeId::TestEventTriggersEnabled, None),
    attr_data!(0, 51, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 51, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 51, GlobalElements::AttributeList, None),
    attr_data!(0, 51, GlobalElements::FeatureMap, None),
    attr_data!(0, 51, GlobalElements::ClusterRevision, None),
    // SoftwareDiagnostics (0x0034 = 52): handler defaults expose
    // only required globals — heap counters and thread metrics are
    // opt-in via the handler's `HEAP` / `THREAD_METRICS` const
    // generics; the test runner uses the all-defaults shape.
    attr_data!(0, 52, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 52, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 52, GlobalElements::AttributeList, None),
    attr_data!(0, 52, GlobalElements::FeatureMap, None),
    attr_data!(0, 52, GlobalElements::ClusterRevision, None),
    // TimeSynchronization (0x0038 = 56): stub handler — `UTCTime` Null,
    // `Granularity` NoTime, `TimeSource` None (opted-in so the Python
    // test harness's `has_attribute(TimeSource)` gate on
    // `TC_TIMESYNC_2_1` matches), no features, no commands.
    attr_data!(0, 56, time_sync::AttributeId::UTCTime, None),
    attr_data!(0, 56, time_sync::AttributeId::Granularity, None),
    attr_data!(0, 56, time_sync::AttributeId::TimeSource, None),
    attr_data!(0, 56, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 56, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 56, GlobalElements::AttributeList, None),
    attr_data!(0, 56, GlobalElements::FeatureMap, None),
    attr_data!(0, 56, GlobalElements::ClusterRevision, None),
    attr_data!(0, 60, adm_comm::AttributeId::WindowStatus, None),
    attr_data!(0, 60, adm_comm::AttributeId::AdminFabricIndex, None),
    attr_data!(0, 60, adm_comm::AttributeId::AdminVendorId, None),
    attr_data!(0, 60, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 60, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 60, GlobalElements::AttributeList, None),
    attr_data!(0, 60, GlobalElements::FeatureMap, None),
    attr_data!(0, 60, GlobalElements::ClusterRevision, None),
    attr_data!(0, 62, noc::AttributeId::NOCs, None),
    attr_data!(0, 62, noc::AttributeId::Fabrics, None),
    attr_data!(0, 62, noc::AttributeId::SupportedFabrics, None),
    attr_data!(0, 62, noc::AttributeId::CommissionedFabrics, None),
    attr_data!(0, 62, noc::AttributeId::TrustedRootCertificates, None),
    attr_data!(0, 62, noc::AttributeId::CurrentFabricIndex, None),
    attr_data!(0, 62, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 62, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 62, GlobalElements::AttributeList, None),
    attr_data!(0, 62, GlobalElements::FeatureMap, None),
    attr_data!(0, 62, GlobalElements::ClusterRevision, None),
    attr_data!(0, 63, grp_key_mgmt::AttributeId::GroupKeyMap, None),
    attr_data!(0, 63, grp_key_mgmt::AttributeId::GroupTable, None),
    attr_data!(0, 63, grp_key_mgmt::AttributeId::MaxGroupsPerFabric, None),
    attr_data!(
        0,
        63,
        grp_key_mgmt::AttributeId::MaxGroupKeysPerFabric,
        None
    ),
    attr_data!(0, 63, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 63, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 63, GlobalElements::AttributeList, None),
    attr_data!(0, 63, GlobalElements::FeatureMap, None),
    attr_data!(0, 63, GlobalElements::ClusterRevision, None),
    attr_data!(0, 49, net_comm::AttributeId::MaxNetworks, None),
    attr_data!(0, 49, net_comm::AttributeId::Networks, None),
    attr_data!(0, 49, net_comm::AttributeId::InterfaceEnabled, None),
    attr_data!(0, 49, net_comm::AttributeId::LastNetworkingStatus, None),
    attr_data!(0, 49, net_comm::AttributeId::LastNetworkID, None),
    attr_data!(0, 49, net_comm::AttributeId::LastConnectErrorValue, None),
    attr_data!(0, 49, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 49, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 49, GlobalElements::AttributeList, None),
    attr_data!(0, 49, GlobalElements::FeatureMap, None),
    attr_data!(0, 49, GlobalElements::ClusterRevision, None),
    attr_data!(0, 55, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 55, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 55, GlobalElements::AttributeList, None),
    attr_data!(0, 55, GlobalElements::FeatureMap, None),
    attr_data!(0, 55, GlobalElements::ClusterRevision, None),
    attr_data!(0, echo::ID, echo::AttributesDiscriminants::Att1, None),
    attr_data!(0, echo::ID, echo::AttributesDiscriminants::Att2, None),
    attr_data!(0, echo::ID, echo::AttributesDiscriminants::AttCustom, None),
    attr_data!(0, echo::ID, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, echo::ID, GlobalElements::AcceptedCmdList, None),
    attr_data_lel!(0, echo::ID, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, echo::ID, GlobalElements::EventList, None),
    attr_data!(0, echo::ID, GlobalElements::AttributeList, None),
    attr_data!(0, echo::ID, GlobalElements::FeatureMap, None),
    attr_data!(0, echo::ID, GlobalElements::ClusterRevision, None),
    attr_data!(1, 29, desc::AttributeId::DeviceTypeList, None),
    attr_data!(1, 29, desc::AttributeId::ServerList, None),
    attr_data!(1, 29, desc::AttributeId::ClientList, None),
    attr_data!(1, 29, desc::AttributeId::PartsList, None),
    attr_data!(1, 29, GlobalElements::GeneratedCmdList, None),
    attr_data!(1, 29, GlobalElements::AcceptedCmdList, None),
    attr_data!(1, 29, GlobalElements::AttributeList, None),
    attr_data!(1, 29, GlobalElements::FeatureMap, None),
    attr_data!(1, 29, GlobalElements::ClusterRevision, None),
    attr_data!(1, 6, on_off::AttributeId::OnOff, None),
    attr_data!(1, 6, on_off::AttributeId::GlobalSceneControl, None),
    attr_data!(1, 6, on_off::AttributeId::OnTime, None),
    attr_data!(1, 6, on_off::AttributeId::OffWaitTime, None),
    attr_data!(1, 6, on_off::AttributeId::StartUpOnOff, None),
    attr_data!(1, 6, GlobalElements::GeneratedCmdList, None),
    attr_data!(1, 6, GlobalElements::AcceptedCmdList, None),
    attr_data!(1, 6, GlobalElements::AttributeList, None),
    attr_data!(1, 6, GlobalElements::FeatureMap, None),
    attr_data!(1, 6, GlobalElements::ClusterRevision, None),
    attr_data!(1, echo::ID, echo::AttributesDiscriminants::Att1, None),
    attr_data!(1, echo::ID, echo::AttributesDiscriminants::Att2, None),
    attr_data!(1, echo::ID, echo::AttributesDiscriminants::AttCustom, None),
    attr_data!(1, echo::ID, GlobalElements::GeneratedCmdList, None),
    attr_data!(1, echo::ID, GlobalElements::AcceptedCmdList, None),
    attr_data!(1, echo::ID, GlobalElements::EventList, None),
    attr_data!(1, echo::ID, GlobalElements::AttributeList, None),
    attr_data!(1, echo::ID, GlobalElements::FeatureMap, None),
    attr_data!(1, echo::ID, GlobalElements::ClusterRevision, None),
];

/// Collect the expected `(endpoint, cluster, attr)` triples out of
/// the test-friendly `TestAttrResp` array (which mixes `AttrData`
/// and `AttrStatus`; we keep only the data entries). Sorted into a
/// `BTreeSet` so set-difference produces deterministic diff output
/// on failure.
fn expected_paths(resps: &[TestAttrResp<'_>]) -> BTreeSet<(u16, u32, u32)> {
    resps
        .iter()
        .filter_map(|r| match r {
            TestAttrResp::AttrData(d) => {
                let ep = d.path.endpoint?;
                let cl = d.path.cluster?;
                let at = d.path.attr?;
                Some((ep, cl, at))
            }
            TestAttrResp::AttrStatus(_) => None,
        })
        .collect()
}

/// Pretty-print a path-set diff in two halves: paths the test
/// expected but didn't see, then paths the device sent that the
/// test wasn't expecting. Empty sections are omitted.
fn pretty_diff(expected: &BTreeSet<(u16, u32, u32)>, actual: &BTreeSet<(u16, u32, u32)>) -> String {
    use core::fmt::Write;
    let missing: Vec<_> = expected.difference(actual).copied().collect();
    let extra: Vec<_> = actual.difference(expected).copied().collect();
    let mut s = String::new();
    if !missing.is_empty() {
        writeln!(s, "  expected but missing ({}):", missing.len()).unwrap();
        for (ep, cl, at) in &missing {
            writeln!(s, "    ep={ep} cluster=0x{cl:04x} attr=0x{at:04x}").unwrap();
        }
    }
    if !extra.is_empty() {
        writeln!(s, "  unexpected in response ({}):", extra.len()).unwrap();
        for (ep, cl, at) in &extra {
            writeln!(s, "    ep={ep} cluster=0x{cl:04x} attr=0x{at:04x}").unwrap();
        }
    }
    s
}

/// Drive a full-wildcard read through the IM client, walk every
/// response chunk, and aggregate the `(endpoint, cluster, attr)`
/// triples actually delivered into a deduplicated set.
///
/// Why a set (and not the exact sequence as the test used to do):
/// the byte-budget chunk boundary is sensitive to *every* attribute
/// on every endpoint, so adding a single cluster (or a single attr
/// to an existing cluster) reshuffles chunk contents and may flip
/// list-typed attributes between one-blob and per-element streaming.
/// What we actually want to verify is invariant under all of that:
/// the device emits exactly the expected set of paths across the
/// chunked stream, and the chunked stream does chunk (i.e. multi-MTU).
/// `listIndex` is intentionally dropped — list-element streaming
/// produces multiple `AttrData` entries with the same path differing
/// only by `listIndex`/data, which collapses to a single path here.
#[test]
fn test_long_read_success() {
    init_env_logger();

    let im = new_default_runner();
    let handler = im.handler();
    im.add_default_acl();

    let expected = expected_paths(ATTR_RESPS);

    block_on(
        select(im.run(handler), async {
            let exchange = im.initiate_exchange().await?;
            let mut sender = exchange.read_sender().await?;

            let paths = [AttrPath::from_gp(&GenericPath::new(None, None, None))];

            let mut chunk = loop {
                match sender.tx().await? {
                    TxOutcome::BuildRequest(builder) => {
                        sender = builder
                            .attr_requests_from(&paths)?
                            .fabric_filtered(false)?
                            .end()?;
                    }
                    TxOutcome::GotResponse(c) => break c,
                }
            };

            let mut actual: BTreeSet<(u16, u32, u32)> = BTreeSet::new();
            let mut chunk_count = 0u32;
            loop {
                chunk_count += 1;
                {
                    let resp = chunk.response()?;
                    if let Some(reports) = &resp.attr_reports {
                        for r in reports.iter() {
                            if let Ok(AttrResp::Data(d)) = r {
                                if let (Some(ep), Some(cl), Some(at)) =
                                    (d.path.endpoint, d.path.cluster, d.path.attr)
                                {
                                    actual.insert((ep, cl, at));
                                }
                            }
                        }
                    }
                }
                match chunk.complete().await? {
                    Some(next) => chunk = next,
                    None => break,
                }
            }

            assert!(
                chunk_count > 1,
                "Wildcard read of the full attribute database should produce a chunked \
                 stream (>1 ReportData), but got only {chunk_count} chunk(s)"
            );
            assert!(
                expected == actual,
                "Path set mismatch after a full-wildcard read:\n{}",
                pretty_diff(&expected, &actual)
            );

            Ok(())
        })
        .coalesce(),
    )
    .unwrap()
}

/// Subscribe variant of `test_long_read_success`: same set-based
/// path check on the priming `ReportData` chunks, plus the terminal
/// `SubscribeResponse` (subscription id assigned, max-int clamped
/// to the server's floor).
#[test]
fn test_long_read_subscription_success() {
    init_env_logger();

    let im = new_default_runner();
    let handler = im.handler();
    im.add_default_acl();

    let expected = expected_paths(ATTR_SUBSCR_RESPS);

    block_on(
        select(im.run(handler), async {
            let exchange = im.initiate_exchange().await?;
            let mut sender = exchange.subscribe_sender().await?;

            let paths = [AttrPath::from_gp(&GenericPath::new(None, None, None))];

            let mut chunk = loop {
                match sender.tx().await? {
                    TxOutcome::BuildRequest(builder) => {
                        sender = builder
                            .keep_subs(true)?
                            .min_int_floor(1)?
                            .max_int_ceil(10)?
                            .attr_requests_from(&paths)?
                            .fabric_filtered(false)?
                            .end()?;
                    }
                    TxOutcome::GotResponse(c) => break c,
                }
            };

            let mut actual: BTreeSet<(u16, u32, u32)> = BTreeSet::new();
            let mut chunk_count = 0u32;
            let established = loop {
                chunk_count += 1;
                {
                    let resp = chunk.response()?;
                    if let Some(reports) = &resp.attr_reports {
                        for r in reports.iter() {
                            if let Ok(AttrResp::Data(d)) = r {
                                if let (Some(ep), Some(cl), Some(at)) =
                                    (d.path.endpoint, d.path.cluster, d.path.attr)
                                {
                                    actual.insert((ep, cl, at));
                                }
                            }
                        }
                    }
                }
                match chunk.complete().await? {
                    SubscribeOutcome::NextChunk(next) => chunk = next,
                    SubscribeOutcome::Established(est) => break est,
                }
            };

            assert!(
                chunk_count > 1,
                "Wildcard subscribe priming should produce a chunked stream \
                 (>1 ReportData), but got only {chunk_count} chunk(s)"
            );
            assert!(
                expected == actual,
                "Path set mismatch after a full-wildcard subscribe priming:\n{}",
                pretty_diff(&expected, &actual)
            );
            assert_ne!(
                established.subscription_id, 0,
                "Server should have assigned a non-zero subscription id"
            );

            Ok(())
        })
        .coalesce(),
    )
    .unwrap()
}
