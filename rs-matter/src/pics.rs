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

//! Emitting the data model as JSON, for PICS generation.
//!
//! A Matter PICS declaration answers, item by item, "does this device implement
//! X?" - which is exactly what [`Node`] already models: `Cluster::attributes` /
//! `commands` / `events` hold everything the *specification* defines, while the
//! `with_attrs` / `with_cmds` / `with_events` predicates say which of those this
//! particular instantiation actually serves.
//!
//! Answering the PICS questionnaire by hand against the firmware is slow and
//! quietly error-prone: an over-claim does not fail loudly, it enrolls the
//! device in test cases it cannot pass, or yields a vacuous pass. This module
//! lets a device emit its data model instead, so the answers can be derived
//! mechanically from the same metadata it advertises over `Descriptor`.
//!
//! The emitted JSON is consumed by `cargo xtask pics`, which merges it into the
//! CSA master PICS templates. Only *supported* items are listed - an item absent
//! from a list is unsupported, which is what the merge step relies on.
//!
//! The dump also reports the mDNS TXT keys and subtypes the device will
//! actually advertise. Those answer a further ~22 PICS items (`MCORE.SC.*_KEY`,
//! `MCORE.DD.TXT_KEY_*`, the `_V` / `_T` commissioning subtypes), and they are
//! **not** constants of the library: six of them are conditional on `dev_det`
//! (`device_type`, `sai`, `sii`, `tcp_supported`) or on ICD mode. Rather than
//! restate those rules here and let them drift, [`Matter::write_pics_json`] asks
//! [`MatterLocalService::service`] and reports whatever it genuinely emits.
//!
//! Rendering goes through [`core::fmt`] and allocates nothing, so it is usable
//! on the smallest targets:
//!
//! ```ignore
//! let mut buf = [0; 512];
//! let mut s = heapless::String::<4096>::new();
//! matter.write_pics_json(&node, &mut buf, &mut s)?;
//! info!("{}", s);
//! ```

use core::fmt::Write;

use crate::dm::Node;
use crate::error::{Error, ErrorCode};
use crate::transport::network::mdns::MdnsLocalService;
use crate::transport::network::MatterLocalService;
use crate::Matter;

/// Version of the JSON schema emitted by [`NodeJson`].
///
/// Bump on any incompatible change to the emitted shape, so that the consuming
/// `xtask` can reject a dump it does not understand rather than silently
/// mis-deriving a PICS declaration.
pub const SCHEMA_VERSION: u32 = 1;

impl Matter<'_> {
    /// Emit `node` plus the device's advertised mDNS records as JSON.
    ///
    /// `buf` is scratch space for building the mDNS service descriptions; a few
    /// hundred bytes suffice (the longest values are `device_name` and
    /// `pairing_instruction`). 512 bytes is a safe default.
    ///
    /// Commands are split into `commands_received` (what the cluster accepts,
    /// i.e. PICS `.Rsp` items) and `commands_generated` (the responses it can
    /// produce, i.e. PICS `.Tx` items), because the PICS questionnaire
    /// distinguishes the two.
    ///
    /// The mDNS section reports **key presence only**, and is valid whatever
    /// the device's commissioning state: `MatterLocalService::service` is a
    /// pure function of `dev_det`, the port, the ICD mode and the variant's own
    /// fields - it consults neither the fabric table nor session state. The
    /// `compressed_fabric_id` / `node_id` / instance id passed below are
    /// therefore placeholders, used only to format the instance name and the
    /// `_I` subtype, whose *values* nothing here depends on. Both the
    /// commissionable and the operational record can be described at once even
    /// though a device only ever advertises one of them at a time.
    ///
    /// The one live input is [`Matter::icd_mode`], which governs the `ICD` TXT
    /// key. No PICS item currently derives from it (ICD is covered by the
    /// `ICDM.*` cluster PICS instead), but a caller dumping at start-up, before
    /// any ICD registration, would see it reported absent.
    pub fn write_pics_json<W: Write>(
        &self,
        node: &Node<'_>,
        buf: &mut [u8],
        mut out: W,
    ) -> Result<(), Error> {
        self.write_node_pics_json(node, &mut out)?;
        out.write_str(",\"mdns\":{").map_err(fmt_err)?;

        {
            let (svc, _) = MatterLocalService::Commissionable {
                id: 0,
                discriminator: self.dev_comm().discriminator,
                enhanced: false,
            }
            .service(self, buf)?;

            self.write_mdns_service_pics_json(&mut out, "commissionable", &svc)?;
        }

        out.write_char(',').map_err(fmt_err)?;

        {
            let (svc, _) = MatterLocalService::Commissioned {
                compressed_fabric_id: 0,
                node_id: 0,
            }
            .service(self, buf)?;

            self.write_mdns_service_pics_json(&mut out, "operational", &svc)?;
        }

        out.write_str("}}").map_err(fmt_err)
    }

    /// Emit the TXT keys and service subtypes of one advertised service.
    fn write_mdns_service_pics_json<'a, W, S, T>(
        &self,
        mut out: W,
        label: &str,
        svc: &MdnsLocalService<'a, S, T>,
    ) -> Result<(), Error>
    where
        W: Write,
        S: Iterator<Item = &'a str> + Clone,
        T: Iterator<Item = (&'a str, &'a str)> + Clone,
    {
        write!(out, "\"{}\":{{\"txt\":[", label).map_err(fmt_err)?;
        for (i, (k, _)) in svc.txt_kvs.clone().enumerate() {
            if i > 0 {
                out.write_char(',').map_err(fmt_err)?;
            }
            write!(out, "\"{}\"", k).map_err(fmt_err)?;
        }

        out.write_str("],\"subtypes\":[").map_err(fmt_err)?;
        for (i, st) in svc.service_subtypes.clone().enumerate() {
            if i > 0 {
                out.write_char(',').map_err(fmt_err)?;
            }
            write!(out, "\"{}\"", st).map_err(fmt_err)?;
        }

        out.write_str("]}").map_err(fmt_err)
    }

    /// Emit the endpoint / cluster tree.
    fn write_node_pics_json<W: Write>(&self, node: &Node<'_>, out: W) -> Result<(), Error> {
        (move || -> core::fmt::Result {
            let mut f = out;
            write!(f, "{{\"schema\":{},\"endpoints\":[", SCHEMA_VERSION)?;

            for (i, ep) in node.endpoints.iter().enumerate() {
                if i > 0 {
                    f.write_char(',')?;
                }

                write!(f, "{{\"id\":{},\"device_types\":[", ep.id)?;
                for (j, dt) in ep.device_types.iter().enumerate() {
                    if j > 0 {
                        f.write_char(',')?;
                    }
                    write!(f, "{{\"dtype\":{},\"drev\":{}}}", dt.dtype, dt.drev)?;
                }

                f.write_str("],\"client_clusters\":[")?;
                for (j, id) in ep.client_clusters.iter().enumerate() {
                    if j > 0 {
                        f.write_char(',')?;
                    }
                    write!(f, "{}", id)?;
                }

                f.write_str("],\"clusters\":[")?;
                for (j, cl) in ep.clusters.iter().enumerate() {
                    if j > 0 {
                        f.write_char(',')?;
                    }

                    write!(
                        f,
                        "{{\"id\":{},\"revision\":{},\"feature_map\":{},\"attributes\":[",
                        cl.id, cl.revision, cl.feature_map
                    )?;
                    for (k, attr) in cl.attributes().enumerate() {
                        if k > 0 {
                            f.write_char(',')?;
                        }
                        write!(f, "{}", attr.id)?;
                    }

                    f.write_str("],\"commands_received\":[")?;
                    for (k, cmd) in cl.commands().enumerate() {
                        if k > 0 {
                            f.write_char(',')?;
                        }
                        write!(f, "{}", cmd.id)?;
                    }

                    // The generated (response) commands are the distinct `resp_id`s
                    // of the received ones. Emitted separately because PICS asks
                    // about the two directions as different items.
                    f.write_str("],\"commands_generated\":[")?;
                    let mut first = true;
                    for cmd in cl.commands() {
                        let Some(resp) = cmd.resp_id else {
                            continue;
                        };
                        // De-duplicate: several commands may share a response.
                        if cl
                            .commands()
                            .take_while(|prev| prev.id != cmd.id)
                            .any(|prev| prev.resp_id == Some(resp))
                        {
                            continue;
                        }
                        if !first {
                            f.write_char(',')?;
                        }
                        first = false;
                        write!(f, "{}", resp)?;
                    }

                    f.write_str("],\"events\":[")?;
                    for (k, ev) in cl.events().enumerate() {
                        if k > 0 {
                            f.write_char(',')?;
                        }
                        write!(f, "{}", ev.id)?;
                    }

                    f.write_str("]}")?;
                }

                f.write_str("]}")?;
            }

            f.write_str("]")
        })()
        .map_err(fmt_err)
    }
}

/// Map a `core::fmt` sink failure onto an `rs-matter` error.
fn fmt_err(_: core::fmt::Error) -> Error {
    Error::new(ErrorCode::BufferTooSmall)
}

#[cfg(test)]
mod tests {
    use crate::dm::clusters::identify;
    use crate::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
    use crate::dm::{Endpoint, Node};
    use crate::Matter;

    static NODE: Node = Node::new(&[Endpoint::new(1, &[], &[identify::CLUSTER])]);

    /// Emitting a node produces well-formed JSON carrying the narrowed
    /// attribute / command sets, and reports the mDNS records the device
    /// genuinely advertises.
    ///
    /// The mDNS assertions below are the point of this test: they pin the
    /// facts that `docs/pics-generation-design.md` (section 6a) turns into PICS
    /// answers. If `MatterLocalService::service` starts or stops emitting a key,
    /// this fails and the design note must be revisited - which is cheaper than
    /// shipping a PICS declaration that quietly disagrees with the firmware.
    #[test]
    fn emits_node_and_mdns_facts() {
        let matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0);

        let mut buf = [0u8; 512];
        let mut out = heapless::String::<4096>::new();
        matter.write_pics_json(&NODE, &mut buf, &mut out).unwrap();
        let json = out.as_str();

        // Shape.
        assert!(json.starts_with("{\"schema\":1,\"endpoints\":["), "{json}");
        assert!(json.ends_with("}}"), "{json}");
        assert!(json.contains("\"client_clusters\":[]"), "{json}");
        assert!(json.contains("\"commands_received\":"), "{json}");
        assert!(json.contains("\"commands_generated\":"), "{json}");
        assert_eq!(
            json.matches("\"id\":3").count(),
            1,
            "Identify cluster: {json}"
        );

        let (commissionable, operational) = json
            .split_once("\"operational\"")
            .expect("both services emitted");

        // Unconditional commissionable TXT keys. `PH` is here rather than among
        // the conditional ones because it renders the pairing-hint *bitmap*,
        // which is "0" - and therefore non-empty - even when no hint is set.
        for key in ["\"D\"", "\"CM\"", "\"VP\"", "\"PH\""] {
            assert!(
                commissionable.contains(key),
                "missing {key}: {commissionable}"
            );
        }

        // Conditional on `dev_det`, and every one of these is a PICS answer:
        // `DN` appears because TEST_DEV_DET sets `device_name`, while `PI`,
        // `DT`, `SAI`, `SII` and `T` are dropped by the empty-value filter
        // because this configuration leaves them unset.
        assert!(commissionable.contains("\"DN\""), "{commissionable}");
        for key in ["\"PI\"", "\"DT\"", "\"SAI\"", "\"SII\"", "\"T\""] {
            assert!(
                !commissionable.contains(key),
                "unexpected {key}: {commissionable}"
            );
        }

        // `RI` is never advertised -> MCORE.SC.RI_KEY / MCORE.DD.TXT_KEY_RI = false.
        assert!(!commissionable.contains("\"RI\""), "{commissionable}");

        // `SAT` is never advertised -> MCORE.SC.SAT_OP_DISCOVERY_KEY = false.
        assert!(!operational.contains("\"SAT\""), "{operational}");

        // Vendor and commissioning-mode subtypes are always present
        // -> MCORE.SC.VENDOR_SUBTYPE / MCORE.DD.COMMISSIONING_SUBTYPE_V = true.
        assert!(commissionable.contains("\"_V65521\""), "{commissionable}");
        assert!(commissionable.contains("\"_CM\""), "{commissionable}");
    }
}
