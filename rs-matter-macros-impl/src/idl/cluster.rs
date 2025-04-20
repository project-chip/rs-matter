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

use rs_matter_data_model::{Cluster, StructType};

use super::id::idl_attribute_name_to_enum_variant_name;
use super::IdlGenerateContext;

/// Return a TokenStream containing a simple enum with variants for each
/// attribute in the given IDL cluster.
pub fn attribute_id(cluster: &Cluster, context: &IdlGenerateContext) -> TokenStream {
    let krate = context.rs_matter_crate.clone();

    let attributes = cluster
        .attributes
        .iter()
        .map(|attr| {
            let attr_name = Ident::new(
                &idl_attribute_name_to_enum_variant_name(&attr.field.field.id),
                Span::call_site(),
            );
            let attr_code = Literal::i64_unsuffixed(attr.field.field.code as i64);

            quote!(
                #attr_name = #attr_code
            )
        })
        .collect::<Vec<_>>();

    if attributes.is_empty() {
        quote!()
    } else {
        quote!(
            #[derive(strum::FromRepr)]
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
        )
    }
}

/// Return a TokenStream containing a simple enum with variants for each
/// command in the given IDL cluster.
pub fn command_id(cluster: &Cluster, context: &IdlGenerateContext) -> TokenStream {
    let krate = context.rs_matter_crate.clone();

    let commands = cluster
        .commands
        .iter()
        .map(|cmd| {
            let command_name = Ident::new(&cmd.id, Span::call_site());
            let command_code = Literal::i64_unsuffixed(cmd.code as i64);

            quote!(
                #command_name = #command_code
            )
        })
        .collect::<Vec<_>>();

    if commands.is_empty() {
        quote!()
    } else {
        quote!(
            #[derive(strum::FromRepr)]
            #[repr(u32)]
            pub enum CommandId {
                #(#commands),*
            }

            impl core::convert::TryFrom<#krate::data_model::objects::CmdId> for CommandId {
                type Error = #krate::error::Error;

                fn try_from(id: #krate::data_model::objects::CmdId) -> Result<Self, Self::Error> {
                    CommandId::from_repr(id).ok_or_else(|| #krate::error::ErrorCode::CommandNotFound.into())
                }
            }
        )
    }
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
                let command_name = Ident::new(&s.id, Span::call_site());
                let command_code = Literal::i64_unsuffixed(code as i64);
                Some(quote!(
                    #command_name = #command_code
                ))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    if command_responses.is_empty() {
        quote!()
    } else {
        quote!(
            #[derive(strum::FromRepr)]
            #[repr(u32)]
            pub enum CommandResponseId {
                #(#command_responses),*
            }

            impl core::convert::TryFrom<#krate::data_model::objects::CmdId> for CommandResponseId {
                type Error = #krate::error::Error;

                fn try_from(id: #krate::data_model::objects::CmdId) -> Result<Self, Self::Error> {
                    CommandResponseId::from_repr(id).ok_or_else(|| #krate::error::ErrorCode::CommandNotFound.into())
                }
            }
        )
    }
}

/// Return a TokenStream containing a constant `CLUSTER` object of type `Cluster` for the given IDL cluster.
///
/// The `CLUSTER` object contains the cluster ID, revision, feature map, attributes, accepted commands, and generated commands
/// - basically, the cluster meta-data that `rs-matter` needs in order do path expansion and access checks on the cluster.
pub fn cluster(cluster: &Cluster, context: &IdlGenerateContext) -> TokenStream {
    let krate = context.rs_matter_crate.clone();

    let attributes_meta_data = cluster.attributes.iter().map(|attr| {
        let attr_name = Ident::new(
            &idl_attribute_name_to_enum_variant_name(&attr.field.field.id),
            Span::call_site(),
        );

        quote!(
            #krate::data_model::objects::Attribute::new(
                AttributeId::#attr_name as _,
                #krate::data_model::objects::Access::RV,
                #krate::data_model::objects::Quality::SN,
            ),
        )
    });

    let commands_meta_data = cluster.commands.iter().map(|cmd| {
        let command_name = Ident::new(&cmd.id, Span::call_site());

        quote!(CommandId::#command_name as _,)
    });

    let command_responses_meta_data = cluster.structs.iter().filter_map(|s| {
        if matches!(s.struct_type, StructType::Response(_)) {
            let command_name = Ident::new(&s.id, Span::call_site());

            Some(quote!(CommandResponseId::#command_name as _,))
        } else {
            None
        }
    });

    let cluster_revision = Literal::u16_unsuffixed(cluster.revision as u16);

    quote!(
        pub const CLUSTER: #krate::data_model::objects::Cluster<'static> = #krate::data_model::objects::Cluster {
            id: ID as _,
            revision: #cluster_revision,
            feature_map: 0, // TODO
            attributes: &[#(#attributes_meta_data)*],
            accepted_commands: &[#(#commands_meta_data)*],
            generated_commands: &[#(#command_responses_meta_data)*],
        };
    )
}
