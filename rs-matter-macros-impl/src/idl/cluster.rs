/*
 * Copyright (c) 2024 Project CHIP Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! A module for generating the cluster metadata for a given IDL cluster.
//!
//! In other words, the `Cluster<'static>` static instance as well as simple enums for
//! the IDs of the cluster attributes, commands and command responses.

use proc_macro2::{Ident, Literal, Span, TokenStream};
use quote::quote;

use rs_matter_data_model::{AccessPrivilege, Cluster, StructType};

use super::id::idl_attribute_name_to_enum_variant_name;
use super::IdlGenerateContext;

pub(crate) const NO_RESPONSE: &str = "DefaultSuccess";
pub(crate) const GLOBAL_ATTR: core::ops::Range<u64> = 0xfff8..0xfffe;

/// Return a TokenStream containing a simple enum with variants for each
/// attribute in the given IDL cluster.
pub fn attribute_id(cluster: &Cluster, context: &IdlGenerateContext) -> TokenStream {
    let krate = context.rs_matter_crate.clone();

    let attributes = cluster.attributes.iter().map(|attr| {
        let attr_name = Ident::new(
            &idl_attribute_name_to_enum_variant_name(&attr.field.field.id),
            Span::call_site(),
        );
        let attr_code = Literal::i64_unsuffixed(attr.field.field.code as i64);

        quote!(
            #attr_name = #attr_code
        )
    });

    let attributes_debug = cluster.attributes.iter().map(|attr| {
        let attr_name = Ident::new(
            &idl_attribute_name_to_enum_variant_name(&attr.field.field.id),
            Span::call_site(),
        );
        let attr_name_str = Literal::string(&idl_attribute_name_to_enum_variant_name(&attr.field.field.id));

        quote!(
            AttributeId::#attr_name => write!(f, "{}(0x{:02x})", #attr_name_str, AttributeId::#attr_name as u32)?,
        )
    });

    let attributes_format = cluster.attributes.iter().map(|attr| {
        let attr_name = Ident::new(
            &idl_attribute_name_to_enum_variant_name(&attr.field.field.id),
            Span::call_site(),
        );
        let attr_name_str = Literal::string(&idl_attribute_name_to_enum_variant_name(&attr.field.field.id));

        quote!(
            AttributeId::#attr_name => #krate::reexport::defmt::write!(f, "{}(0x{:02x})", #attr_name_str, AttributeId::#attr_name as u32),
        )
    });

    quote!(
        #[doc = "The attribute IDs for the cluster."]
        #[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, #krate::reexport::strum::FromRepr)]
        #[cfg_attr(feature = "defmt", derive(#krate::reexport::defmt::Format))]
        #[repr(u32)]
        pub enum AttributeId {
            #(#attributes),*
        }

        impl core::convert::TryFrom<#krate::data_model::objects::AttrId> for AttributeId {
            type Error = #krate::error::Error;

            fn try_from(id: #krate::data_model::objects::CmdId) -> Result<Self, Self::Error> {
                AttributeId::from_repr(id).ok_or_else(|| #krate::error::ErrorCode::AttributeNotFound.into())
            }
        }

        impl core::fmt::Debug for MetadataDebug<(AttributeId, bool)> {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "Attr::")?;

                match self.0.0 {
                    #(#attributes_debug)*
                }

                if self.0.1 {
                    write!(f, "::Write")
                } else {
                    write!(f, "::Read")
                }
            }
        }

        #[cfg(feature = "defmt")]
        impl #krate::reexport::defmt::Format for MetadataDebug<(AttributeId, bool)> {
            fn format(&self, f: #krate::reexport::defmt::Formatter<'_>) {
                #krate::reexport::defmt::write!(f, "Attr::");

                match self.0.0 {
                    #(#attributes_format)*
                }

                if self.0.1 {
                    #krate::reexport::defmt::write!(f, "::Write")
                } else {
                    #krate::reexport::defmt::write!(f, "::Read")
                }
            }
        }
    )
}

/// Return a TokenStream containing a simple enum with variants for each
/// command in the given IDL cluster.
pub fn command_id(cluster: &Cluster, context: &IdlGenerateContext) -> TokenStream {
    let krate = context.rs_matter_crate.clone();

    let commands = cluster
        .commands
        .iter()
        .map(|cmd| {
            let cmd_name = Ident::new(&cmd.id, Span::call_site());
            let cmd_code = Literal::i64_unsuffixed(cmd.code as i64);

            quote!(
                #cmd_name = #cmd_code
            )
        })
        .collect::<Vec<_>>();

    let commands_debug = cluster.commands.iter().map(|cmd| {
        let cmd_name = Ident::new(&cmd.id, Span::call_site());
        let cmd_name_str = Literal::string(&cmd.id);

        quote!(
            CommandId::#cmd_name => write!(f, "{}(0x{:02x})", #cmd_name_str, CommandId::#cmd_name as u32)?,
        )
    });

    let commands_format = cluster.commands.iter().map(|cmd| {
        let cmd_name = Ident::new(&cmd.id, Span::call_site());
        let cmd_name_str = Literal::string(&cmd.id);

        quote!(
            CommandId::#cmd_name => #krate::reexport::defmt::write!(f, "{}(0x{:02x})", #cmd_name_str, CommandId::#cmd_name as u32),
        )
    });

    let repr = if !commands.is_empty() {
        quote!(#[repr(u32)])
    } else {
        quote!()
    };

    let try_from = if !commands.is_empty() {
        quote!(
            impl core::convert::TryFrom<#krate::data_model::objects::CmdId> for CommandId {
                type Error = #krate::error::Error;

                fn try_from(id: #krate::data_model::objects::CmdId) -> Result<Self, Self::Error> {
                    CommandId::from_repr(id).ok_or_else(|| #krate::error::ErrorCode::CommandNotFound.into())
                }
            }
        )
    } else {
        quote!(
            impl core::convert::TryFrom<#krate::data_model::objects::CmdId> for CommandId {
                type Error = #krate::error::Error;

                fn try_from(id: #krate::data_model::objects::CmdId) -> Result<Self, Self::Error> {
                    Err(#krate::error::ErrorCode::CommandNotFound.into())
                }
            }
        )
    };

    quote!(
        #[doc = "The command IDs for the cluster."]
        #[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, #krate::reexport::strum::FromRepr)]
        #[cfg_attr(feature = "defmt", derive(#krate::reexport::defmt::Format))]
        #repr
        pub enum CommandId {
            #(#commands),*
        }

        #try_from

        impl core::fmt::Debug for MetadataDebug<CommandId> {
            #[allow(unreachable_code)]
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "Cmd::")?;

                match self.0 {
                    #(#commands_debug)*
                }

                write!(f, "::Invoke")
            }
        }

        #[cfg(feature = "defmt")]
        impl #krate::reexport::defmt::Format for MetadataDebug<CommandId> {
            #[allow(unreachable_code)]
            fn format(&self, f: #krate::reexport::defmt::Formatter<'_>) {
                #krate::reexport::defmt::write!(f, "Cmd::");

                match self.0 {
                    #(#commands_format)*
                }

                #krate::reexport::defmt::write!(f, "::Invoke")
            }
        }
    )
}

/// Return a TokenStream containing a simple enum with variants for each
/// command response in the given IDL cluster.
pub fn command_response_id(cluster: &Cluster, context: &IdlGenerateContext) -> TokenStream {
    let krate = context.rs_matter_crate.clone();

    let command_responses = cluster
        .structs
        .iter()
        .filter_map(|s| {
            if let StructType::Response(code) = s.struct_type {
                let cmd_name = Ident::new(&s.id, Span::call_site());
                let cmd_code = Literal::i64_unsuffixed(code as i64);
                Some(quote!(
                    #cmd_name = #cmd_code
                ))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let command_responses_debug = cluster.structs.iter().filter_map(|s| {
        if let StructType::Response(_) = s.struct_type {
            let cmd_name = Ident::new(&s.id, Span::call_site());
            let cmd_name_str = Literal::string(&s.id);
            Some(quote!(
                CommandResponseId::#cmd_name => write!(f, "{}(0x{:02x})", #cmd_name_str, CommandResponseId::#cmd_name as u32)?,
            ))
        } else {
            None
        }
    });

    let command_responses_format = cluster.structs.iter().filter_map(|s| {
        if let StructType::Response(_) = s.struct_type {
            let cmd_name = Ident::new(&s.id, Span::call_site());
            let cmd_name_str = Literal::string(&s.id);
            Some(quote!(
                CommandResponseId::#cmd_name => #krate::reexport::defmt::write!(f, "{}(0x{:02x})", #cmd_name_str, CommandResponseId::#cmd_name as u32),
            ))
        } else {
            None
        }
    });

    let repr = if !command_responses.is_empty() {
        quote!(#[repr(u32)])
    } else {
        quote!()
    };

    let try_from = if !command_responses.is_empty() {
        quote!(
            impl core::convert::TryFrom<#krate::data_model::objects::CmdId> for CommandResponseId {
                type Error = #krate::error::Error;

                fn try_from(id: #krate::data_model::objects::CmdId) -> Result<Self, Self::Error> {
                    CommandResponseId::from_repr(id).ok_or_else(|| #krate::error::ErrorCode::CommandNotFound.into())
                }
            }
        )
    } else {
        quote!(
            impl core::convert::TryFrom<#krate::data_model::objects::CmdId> for CommandResponseId {
                type Error = #krate::error::Error;

                fn try_from(id: #krate::data_model::objects::CmdId) -> Result<Self, Self::Error> {
                    Err(#krate::error::ErrorCode::CommandNotFound.into())
                }
            }
        )
    };

    quote!(
        #[doc = "The command response IDs for the cluster."]
        #[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, #krate::reexport::strum::FromRepr)]
        #[cfg_attr(feature = "defmt", derive(#krate::reexport::defmt::Format))]
        #repr
        pub enum CommandResponseId {
            #(#command_responses),*
        }

        impl core::fmt::Debug for MetadataDebug<CommandResponseId> {
            #[allow(unreachable_code)]
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "Cmd::")?;

                match self.0 {
                    #(#command_responses_debug)*
                }

                write!(f, "::Response")
            }
        }

        #[cfg(feature = "defmt")]
        impl #krate::reexport::defmt::Format for MetadataDebug<CommandResponseId> {
            #[allow(unreachable_code)]
            fn format(&self, f: #krate::reexport::defmt::Formatter<'_>) {
                #krate::reexport::defmt::write!(f, "Cmd::");

                match self.0 {
                    #(#command_responses_format)*
                }

                #krate::reexport::defmt::write!(f, "::Response")
            }
        }

        #try_from
    )
}

/// Return a TokenStream containing a `ClusterConf` enum that allows the user to configure the `Cluster` instance
/// corresponding to the given IDL cluster.
///
/// The `Cluster` instance contains the cluster ID, revision, feature map, attributes, accepted commands, and generated commands
/// - basically, the cluster meta-data that `rs-matter` needs in order do path expansion and access checks on the cluster.
pub fn cluster(cluster: &Cluster, context: &IdlGenerateContext) -> TokenStream {
    let krate = context.rs_matter_crate.clone();

    let attributes = cluster.attributes.iter().map(|attr| {
        let attr_name = Ident::new(
            &idl_attribute_name_to_enum_variant_name(&attr.field.field.id),
            Span::call_site(),
        );

        let mut rw = quote!(#krate::data_model::objects::Access::READ);
        if !attr.is_read_only {
            rw = quote!(#rw.union(#krate::data_model::objects::Access::WRITE));
        }

        let (acl, needs_view) = if !attr.is_read_only {
            if attr.read_acl != attr.write_acl && !matches!(attr.read_acl, AccessPrivilege::View) || matches!(attr.write_acl, AccessPrivilege::View) {
                // These cases are not currently supported by the `Access` bitmask
                panic!("Unsupported access patern: attribute {attr_name} has {:?} read access and {:?} write access", attr.read_acl, attr.write_acl);
            }

            (attr.write_acl, attr.read_acl != attr.write_acl)
        } else {
            (attr.read_acl, false)
        };

        let mut acl = match acl {
            AccessPrivilege::View => quote!(#krate::data_model::objects::Access::NEED_VIEW),
            AccessPrivilege::Operate => quote!(#krate::data_model::objects::Access::NEED_OPERATE.union(#krate::data_model::objects::Access::NEED_MANAGE.union(#krate::data_model::objects::Access::NEED_ADMIN))),
            AccessPrivilege::Manage => quote!(#krate::data_model::objects::Access::NEED_MANAGE.union(#krate::data_model::objects::Access::NEED_ADMIN)),
            AccessPrivilege::Administer => quote!(#krate::data_model::objects::Access::NEED_ADMIN),
        };

        if needs_view {
            acl = quote!(#acl.union(#krate::data_model::objects::Access::NEED_VIEW));
        }

        let mut access = quote!(#rw.union(#acl));

        if attr.is_timed_write {
            access = quote!(#access.union(#krate::data_model::objects::Access::TIMED_ONLY));
        }

        if attr.field.is_fabric_sensitive {
            access = quote!(#access.union(#krate::data_model::objects::Access::FAB_SENSITIVE));
        }

        let quality = if attr.field.is_optional {
            quote!(#krate::data_model::objects::Quality::O)
        } else {
            quote!(#krate::data_model::objects::Quality::NONE)
        };

        // TODO: Fabric Scoped seems to be on the struct level

        quote!(
            #krate::data_model::objects::Attribute::new(
                AttributeId::#attr_name as _,
                #access,
                #quality
            ),
        )
    });

    let commands = cluster.commands.iter().map(|cmd| {
        let cmd_name = Ident::new(&cmd.id, Span::call_site());

        let access = match cmd.access {
            AccessPrivilege::View => panic!("Unsupported command access: {:?}", cmd.access),
            AccessPrivilege::Operate => quote!(#krate::data_model::objects::Access::WO),
            AccessPrivilege::Manage => quote!(#krate::data_model::objects::Access::WM),
            AccessPrivilege::Administer => quote!(#krate::data_model::objects::Access::WA),
        };

        let resp_id = if cmd.output != NO_RESPONSE {
            let cmd_name = Ident::new(&cmd.output, Span::call_site());

            quote!(Some(CommandResponseId::#cmd_name as _))
        } else {
            quote!(None)
        };

        quote!(
            #krate::data_model::objects::Command::new(
                CommandId::#cmd_name as _,
                #resp_id,
                #access,
            ),
        )
    });

    let cluster_id = Literal::u32_unsuffixed(cluster.code as u32);
    let cluster_revision = Literal::u16_unsuffixed(cluster.revision as u16);

    quote!(
        #[doc = "The cluster metadata. By default, all cluster attributes and commands are allowed, and the revision is the latest one. Use `Cluster::conf` to reconfigure."]
        pub const FULL_CLUSTER: #krate::data_model::objects::Cluster<'static> = #krate::data_model::objects::Cluster::new(
            #cluster_id,
            #cluster_revision,
            0,
            &[#(#attributes)*],
            &[#(#commands)*],
            |_, _, _| true,
            |_, _, _| true,
        );

        #[doc = "A helper struct to generate the cluster debug info."]
        struct MetadataDebug<T>(pub T);
    )
}

#[cfg(test)]
mod tests {
    use assert_tokenstreams_eq::assert_tokenstreams_eq;
    use quote::quote;

    use crate::idl::{
        tests::{get_cluster_named, parse_idl},
        IdlGenerateContext,
    };

    use super::cluster;

    #[test]
    fn test_cluster() {
        let idl = parse_idl(
            "
              cluster OnOff = 6 {
                revision 6;

                enum DelayedAllOffEffectVariantEnum : enum8 {
                  kDelayedOffFastFade = 0;
                  kNoFade = 1;
                  kDelayedOffSlowFade = 2;
                }

                enum DyingLightEffectVariantEnum : enum8 {
                  kDyingLightFadeOff = 0;
                }

                enum EffectIdentifierEnum : enum8 {
                  kDelayedAllOff = 0;
                  kDyingLight = 1;
                }

                enum StartUpOnOffEnum : enum8 {
                  kOff = 0;
                  kOn = 1;
                  kToggle = 2;
                }

                bitmap Feature : bitmap32 {
                  kLighting = 0x1;
                  kDeadFrontBehavior = 0x2;
                  kOffOnly = 0x4;
                }

                bitmap OnOffControlBitmap : bitmap8 {
                  kAcceptOnlyWhenOn = 0x1;
                }

                readonly attribute boolean onOff = 0;
                readonly attribute optional boolean globalSceneControl = 16384;
                attribute optional int16u onTime = 16385;
                attribute optional int16u offWaitTime = 16386;
                attribute access(write: manage) optional nullable StartUpOnOffEnum startUpOnOff = 16387;
                readonly attribute command_id generatedCommandList[] = 65528;
                readonly attribute command_id acceptedCommandList[] = 65529;
                readonly attribute event_id eventList[] = 65530;
                readonly attribute attrib_id attributeList[] = 65531;
                readonly attribute bitmap32 featureMap = 65532;
                readonly attribute int16u clusterRevision = 65533;

                request struct OffWithEffectRequest {
                  EffectIdentifierEnum effectIdentifier = 0;
                  enum8 effectVariant = 1;
                }

                request struct OnWithTimedOffRequest {
                  OnOffControlBitmap onOffControl = 0;
                  int16u onTime = 1;
                  int16u offWaitTime = 2;
                }

                /** On receipt of this command, a device SHALL enter its ‘Off’ state. This state is device dependent, but it is recommended that it is used for power off or similar functions. On receipt of the Off command, the OnTime attribute SHALL be set to 0. */
                command Off(): DefaultSuccess = 0;
                /** On receipt of this command, a device SHALL enter its ‘On’ state. This state is device dependent, but it is recommended that it is used for power on or similar functions. On receipt of the On command, if the value of the OnTime attribute is equal to 0, the device SHALL set the OffWaitTime attribute to 0. */
                command On(): DefaultSuccess = 1;
                /** On receipt of this command, if a device is in its ‘Off’ state it SHALL enter its ‘On’ state. Otherwise, if it is in its ‘On’ state it SHALL enter its ‘Off’ state. On receipt of the Toggle command, if the value of the OnOff attribute is equal to FALSE and if the value of the OnTime attribute is equal to 0, the device SHALL set the OffWaitTime attribute to 0. If the value of the OnOff attribute is equal to TRUE, the OnTime attribute SHALL be set to 0. */
                command Toggle(): DefaultSuccess = 2;
                /** The OffWithEffect command allows devices to be turned off using enhanced ways of fading. */
                command OffWithEffect(OffWithEffectRequest): DefaultSuccess = 64;
                /** The OnWithRecallGlobalScene command allows the recall of the settings when the device was turned off. */
                command OnWithRecallGlobalScene(): DefaultSuccess = 65;
                /** The OnWithTimedOff command allows devices to be turned on for a specific duration with a guarded off duration so that SHOULD the device be subsequently switched off, further OnWithTimedOff commands, received during this time, are prevented from turning the devices back on. */
                command OnWithTimedOff(OnWithTimedOffRequest): DefaultSuccess = 66;
              }
        ",
        );

        let cluster_meta = get_cluster_named(&idl, "OnOff").expect("Cluster exists");
        let context = IdlGenerateContext::new("rs_matter_crate");

        // panic!("====\n{}\n====", &cluster(cluster_meta, &context));

        assert_tokenstreams_eq!(
            &cluster(cluster_meta, &context),
            &quote!(
                const CLUSTER_REVISION: u16 = 6;

                pub const CLUSTER: rs_matter_crate::data_model::objects::Cluster<'static> =
                    ClusterConf::Default.cluster();

                #[derive(Debug, Default, Clone, Eq, PartialEq, Hash)]
                pub enum ClusterConf<'a> {
                    #[default]
                    Default,
                    Mandatory {
                        revision: u16,
                        feature_map: u32,
                    },
                    All {
                        revision: u16,
                        feature_map: u32,
                    },
                    Custom {
                        revision: u16,
                        feature_map: u32,
                        supported_attributes: &'a [u32],
                        accepted_commands: &'a [u32],
                        generated_commands: &'a [u32],
                    },
                }

                impl<'a> ClusterConf<'a> {
                    pub const fn cluster(
                        &self,
                    ) -> rs_matter_crate::data_model::objects::Cluster<'a> {
                        static ATTRIBUTES_ACCESS: &[rs_matter_crate::data_model::objects::Attribute] = &[
                            rs_matter_crate::data_model::objects::Attribute::new(
                                AttributeId::OnOff as _,
                                rs_matter_crate::data_model::objects::Access::READ
                                    .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                                rs_matter_crate::data_model::objects::Quality::SN,
                            ),
                            rs_matter_crate::data_model::objects::Attribute::new(
                                AttributeId::GlobalSceneControl as _,
                                rs_matter_crate::data_model::objects::Access::READ
                                    .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                                rs_matter_crate::data_model::objects::Quality::SN,
                            ),
                            rs_matter_crate::data_model::objects::Attribute::new(
                                AttributeId::OnTime as _,
                                rs_matter_crate::data_model::objects::Access::READ
                                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                                    .union(
                                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                                            .union(
                                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                                ),
                                            )
                                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                                    ),
                                rs_matter_crate::data_model::objects::Quality::SN,
                            ),
                            rs_matter_crate::data_model::objects::Attribute::new(
                                AttributeId::OffWaitTime as _,
                                rs_matter_crate::data_model::objects::Access::READ
                                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                                    .union(
                                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                                            .union(
                                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                                ),
                                            )
                                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                                    ),
                                rs_matter_crate::data_model::objects::Quality::SN,
                            ),
                            rs_matter_crate::data_model::objects::Attribute::new(
                                AttributeId::StartUpOnOff as _,
                                rs_matter_crate::data_model::objects::Access::READ
                                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                                    .union(
                                        rs_matter_crate::data_model::objects::Access::NEED_MANAGE
                                            .union(rs_matter_crate::data_model::objects::Access::NEED_ADMIN)
                                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                                    ),
                                rs_matter_crate::data_model::objects::Quality::SN,
                            ),
                            rs_matter_crate::data_model::objects::Attribute::new(
                                AttributeId::GeneratedCommandList as _,
                                rs_matter_crate::data_model::objects::Access::READ
                                    .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                                rs_matter_crate::data_model::objects::Quality::SN,
                            ),
                            rs_matter_crate::data_model::objects::Attribute::new(
                                AttributeId::AcceptedCommandList as _,
                                rs_matter_crate::data_model::objects::Access::READ
                                    .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                                rs_matter_crate::data_model::objects::Quality::SN,
                            ),
                            rs_matter_crate::data_model::objects::Attribute::new(
                                AttributeId::EventList as _,
                                rs_matter_crate::data_model::objects::Access::READ
                                    .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                                rs_matter_crate::data_model::objects::Quality::SN,
                            ),
                            rs_matter_crate::data_model::objects::Attribute::new(
                                AttributeId::AttributeList as _,
                                rs_matter_crate::data_model::objects::Access::READ
                                    .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                                rs_matter_crate::data_model::objects::Quality::SN,
                            ),
                            rs_matter_crate::data_model::objects::Attribute::new(
                                AttributeId::FeatureMap as _,
                                rs_matter_crate::data_model::objects::Access::READ
                                    .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                                rs_matter_crate::data_model::objects::Quality::SN,
                            ),
                            rs_matter_crate::data_model::objects::Attribute::new(
                                AttributeId::ClusterRevision as _,
                                rs_matter_crate::data_model::objects::Access::READ
                                    .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                                rs_matter_crate::data_model::objects::Quality::SN,
                            ),
                        ];
                        rs_matter_crate::data_model::objects::Cluster {
                            id: ID as _,
                            attributes_access: ATTRIBUTES_ACCESS,
                            revision: match self {
                                ClusterConf::Default => CLUSTER_REVISION,
                                ClusterConf::Mandatory { revision, .. } => *revision,
                                ClusterConf::All { revision, .. } => *revision,
                                ClusterConf::Custom { revision, .. } => *revision,
                            },
                            feature_map: match self {
                                ClusterConf::Default => 0,
                                ClusterConf::Mandatory { feature_map, .. } => *feature_map,
                                ClusterConf::All { feature_map, .. } => *feature_map,
                                ClusterConf::Custom { feature_map, .. } => *feature_map,
                            },
                            supported_attributes: match self {
                                ClusterConf::Custom {
                                    supported_attributes,
                                    ..
                                } => supported_attributes,
                                _ => AttributeId::all(),
                            },
                            accepted_commands: match self {
                                ClusterConf::Custom {
                                    accepted_commands, ..
                                } => accepted_commands,
                                _ => CommandId::all(),
                            },
                            generated_commands: match self {
                                ClusterConf::Custom {
                                    generated_commands, ..
                                } => generated_commands,
                                _ => CommandResponseId::all(),
                            },
                        }
                    }
                }
            )
        );
    }
}
