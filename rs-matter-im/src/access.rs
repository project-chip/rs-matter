/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
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

//! The access checks of the Interaction Model against the metadata of the data
//! model: the paths of a request, and the privileges of the accessor on them.

use crate::acl::{AccessReq, Accessor};
use crate::dm::{Access, AttrId, Cluster, CmdId, DeviceType, Endpoint, EventId, Node, NodeId};
use crate::encoding::{AttrPath, EventPath, GenericPath, IMStatusCode};

/// The access checks on the metadata of a cluster.
pub(crate) trait ClusterAccess {
    /// Check if the accessor has the required permissions to access the attribute
    /// designated by the provided path.
    fn check_attr_access(
        &self,
        accessor: &Accessor,
        timed: bool,
        path: GenericPath,
        device_types: &[DeviceType],
        write: bool,
        attr_id: AttrId,
    ) -> Result<(), IMStatusCode>;

    /// Check if the accessor has the required permissions to access the command
    /// designated by the provided path.
    fn check_cmd_access(
        &self,
        accessor: &Accessor,
        timed: bool,
        path: GenericPath,
        device_types: &[DeviceType],
        cmd_id: CmdId,
    ) -> Result<(), IMStatusCode>;

    /// Check if the accessor has the required permissions to access the event
    /// designated by the provided path.
    fn check_event_access(
        &self,
        accessor: &Accessor,
        path: GenericPath,
        device_types: &[DeviceType],
        event_id: EventId,
    ) -> Result<(), IMStatusCode>;
}

impl ClusterAccess for Cluster<'_> {
    /// Check if the accessor has the required permissions to access the attribute
    /// designated by the provided path.
    ///
    /// if `write` is true, the operation is a write operation, otherwise it is a read operation.
    /// `device_types` lists the device types declared by the endpoint hosting `path`,
    /// so ACL entries with a `Target` of kind `DeviceType` can be evaluated correctly.
    fn check_attr_access(
        &self,
        accessor: &Accessor,
        timed: bool,
        path: GenericPath,
        device_types: &[DeviceType],
        write: bool,
        attr_id: AttrId,
    ) -> Result<(), IMStatusCode> {
        let mut access_req = AccessReq::new(
            accessor,
            path,
            if write { Access::WRITE } else { Access::READ },
            device_types,
        );

        let target_perms = self
            .attributes
            .iter()
            .find(|attr| attr.id == attr_id)
            .map(|attr| attr.access)
            .unwrap_or(Access::empty());

        if write && !timed && target_perms.contains(Access::TIMED_ONLY) {
            Err(IMStatusCode::NeedsTimedInteraction)?;
        }

        if !target_perms.contains(access_req.operation()) {
            Err(if matches!(access_req.operation(), Access::WRITE) {
                IMStatusCode::UnsupportedWrite
            } else {
                IMStatusCode::UnsupportedRead
            })?;
        }

        access_req.set_target_perms(target_perms);
        if accessor.allow(&access_req) {
            Ok(())
        } else {
            Err(IMStatusCode::UnsupportedAccess)
        }
    }

    /// Check if the accessor has the required permissions to access the command
    /// designated by the provided path.
    /// `device_types` lists the device types declared by the endpoint hosting `path`.
    fn check_cmd_access(
        &self,
        accessor: &Accessor,
        timed: bool,
        path: GenericPath,
        device_types: &[DeviceType],
        cmd_id: CmdId,
    ) -> Result<(), IMStatusCode> {
        let mut access_req = AccessReq::new(accessor, path, Access::WRITE, device_types);

        let target_perms = self
            .commands
            .iter()
            .find(|cmd| cmd.id == cmd_id)
            .map(|cmd| cmd.access)
            .unwrap_or(Access::empty());

        if !timed && target_perms.contains(Access::TIMED_ONLY) {
            Err(IMStatusCode::NeedsTimedInteraction)?;
        }

        // Per Matter Core spec (Invoke Interaction): "Else if
        // the command in the path is fabric-scoped and there is no accessing
        // fabric, a CommandStatusIB SHALL be generated with the
        // UNSUPPORTED_ACCESS Status Code." This is the catch for fabric-scoped
        // admin commands invoked over a PASE session that hasn't yet promoted
        // its fabric index via AddNOC.
        if target_perms.contains(Access::FAB_SCOPED) && accessor.fab_idx == 0 {
            Err(IMStatusCode::UnsupportedAccess)?;
        }

        access_req.set_target_perms(target_perms);
        if accessor.allow(&access_req) {
            Ok(())
        } else {
            Err(IMStatusCode::UnsupportedAccess)
        }
    }

    /// Check if the accessor has the required permissions to access the event
    /// designated by the provided path.
    /// `device_types` lists the device types declared by the endpoint hosting `path`.
    fn check_event_access(
        &self,
        accessor: &Accessor,
        path: GenericPath,
        device_types: &[DeviceType],
        event_id: EventId,
    ) -> Result<(), IMStatusCode> {
        let mut access_req = AccessReq::new(accessor, path, Access::READ, device_types);

        let target_perms = self
            .events
            .iter()
            .find(|event| event.id == event_id)
            .map(|event| event.access)
            .unwrap_or(Access::empty());

        access_req.set_target_perms(target_perms);
        if accessor.allow(&access_req) {
            Ok(())
        } else {
            Err(IMStatusCode::UnsupportedAccess)
        }
    }
}

/// The validation of request paths against the metadata of a node.
pub(crate) trait NodeAccess {
    /// Validate an attribute path for a read (or, if `write` is true, a write).
    fn validate_attr_path(
        &self,
        path: &AttrPath,
        timed: bool,
        write: bool,
        accessor: &Accessor<'_>,
    ) -> Result<(), IMStatusCode>;

    /// Validate an event path.
    fn validate_event_path(
        &self,
        path: &EventPath,
        accessor: &Accessor<'_>,
    ) -> Result<(), IMStatusCode>;

    /// Return `true` if at least one attribute matching the (potentially wildcard) path
    /// is accessible to the given accessor. Used for subscription validation.
    fn has_accessible_attr(&self, path: &AttrPath, accessor: &Accessor<'_>) -> bool;
}

impl NodeAccess for Node<'_> {
    fn validate_attr_path(
        &self,
        path: &AttrPath,
        timed: bool,
        write: bool,
        accessor: &Accessor<'_>,
    ) -> Result<(), IMStatusCode> {
        if let Some(node_id) = path.node {
            validate_node_id(node_id, accessor)?;
        }

        let gp = path.to_gp();

        let Some((endpoint, cluster, attr_id)) = validate_cluster_path(self, &gp)? else {
            return Ok(());
        };

        let Some(attr) = cluster.attribute(attr_id) else {
            return Err(IMStatusCode::UnsupportedAttribute);
        };

        cluster.check_attr_access(accessor, timed, gp, endpoint.device_types, write, attr.id)
    }

    fn validate_event_path(
        &self,
        path: &EventPath,
        accessor: &Accessor<'_>,
    ) -> Result<(), IMStatusCode> {
        if let Some(node_id) = path.node {
            validate_node_id(node_id, accessor)?;
        }

        let gp = path.to_gp();

        let Some((endpoint, cluster, event_id)) = validate_cluster_path(self, &gp)? else {
            return Ok(());
        };

        let Some(event) = cluster.event(event_id) else {
            return Err(IMStatusCode::UnsupportedEvent);
        };

        cluster.check_event_access(accessor, gp, endpoint.device_types, event.id)
    }

    /// Return `true` if at least one attribute matching the (potentially wildcard) path
    /// is accessible to the given accessor. Used for subscription validation.
    fn has_accessible_attr(&self, path: &AttrPath, accessor: &Accessor<'_>) -> bool {
        for endpoint in self.endpoints.iter() {
            if let Some(ep_id) = path.endpoint {
                if endpoint.id != ep_id {
                    continue;
                }
            }

            for cluster in endpoint.clusters.iter() {
                if let Some(cluster_id) = path.cluster {
                    if cluster.id != cluster_id {
                        continue;
                    }
                }

                for attr in cluster.attributes.iter() {
                    if let Some(attr_id) = path.attr {
                        if attr.id != attr_id {
                            continue;
                        }
                    }

                    let gp = GenericPath::new(Some(endpoint.id), Some(cluster.id), Some(attr.id));

                    if cluster
                        .check_attr_access(
                            accessor,
                            false,
                            gp,
                            endpoint.device_types,
                            false,
                            attr.id,
                        )
                        .is_ok()
                    {
                        return true;
                    }
                }
            }
        }

        false
    }
}

fn validate_cluster_path<'a, 'n>(
    node: &'a Node<'n>,
    path: &GenericPath,
) -> Result<Option<(&'a Endpoint<'n>, &'a Cluster<'n>, u32)>, IMStatusCode> {
    let Some(endpoint_id) = path.endpoint else {
        return Ok(None);
    };

    let Some(endpoint) = node.endpoint(endpoint_id) else {
        // Endpoint does not exist
        return Err(IMStatusCode::UnsupportedEndpoint);
    };

    let Some(cluster_id) = path.cluster else {
        return Ok(None);
    };

    let Some(cluster) = endpoint.cluster(cluster_id) else {
        // Cluster does not exist on this endpoint
        return Err(IMStatusCode::UnsupportedCluster);
    };

    let Some(leaf_id) = path.leaf else {
        return Ok(None);
    };

    Ok(Some((endpoint, cluster, leaf_id)))
}

fn validate_node_id(node_id: NodeId, accessor: &Accessor<'_>) -> Result<(), IMStatusCode> {
    let Some(accessor_node_id) = accessor.node_id() else {
        return Err(IMStatusCode::UnsupportedNode);
    };

    if node_id != accessor_node_id {
        return Err(IMStatusCode::UnsupportedNode);
    }

    Ok(())
}
