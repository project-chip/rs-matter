/*
 * Copyright (c) 2026 Project CHIP Authors
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

//! Codegen for the IM-client extension traits.
//!
//! For every cluster the IDL declares, this module emits opt-in
//! extension traits over the streaming IM-client array builders
//! ([`CmdDataArrayBuilder`], `AttrPathArrayBuilder`, `AttrDataArrayBuilder`)
//! that pre-fill the cluster ID and command/attribute ID — the user
//! only supplies the endpoint and the request payload (via a chained
//! typed sub-builder).
//!
//! Output shape, per cluster:
//!
//! ```ignore
//! pub trait <ClusterName>CmdRequests<P>: Sized
//! where
//!     P: TLVBuilderParent,
//! {
//!     // One method per command. Parameterized commands return the
//!     // codegen-emitted typed request builder over `CmdDataBuilder<Self, 2>`;
//!     // empty-request commands open + close `Data` internally and return `Self`.
//!     fn push_<cluster>_<command>(self, endpoint: EndptId) -> Result<…, Error>;
//! }
//!
//! impl<P> <ClusterName>CmdRequests<P> for CmdDataArrayBuilder<P>
//! where
//!     P: TLVBuilderParent,
//! { … }
//! ```
//!
//! Method names are `push_<cluster_snake>_<command_snake>` so that
//! multiple cluster traits can coexist in scope without method-name
//! clashes (e.g. several clusters define a `Stop` command).
//!
//! Per cluster three traits are emitted:
//! - `<ClusterName>CmdRequests<P>` on `CmdDataArrayBuilder<P>` —
//!   one `push_<cluster>_<command>` method per command.
//! - `<ClusterName>AttrReads<P>` on `AttrPathArrayBuilder<P>` —
//!   one `push_<cluster>_<attr>` method per attribute (returns
//!   `Self` so multiple reads can be chained into one request).
//! - `<ClusterName>AttrWrites<P>` on `AttrDataArrayBuilder<P>` —
//!   one `push_<cluster>_<attr>_write` method per *writable*
//!   attribute. Scalar-valued attrs take a `value: T` argument
//!   and return `Self`; struct- or array-valued attrs return the
//!   codegen-emitted typed value builder so the caller can fill
//!   the value in-place (and double-`.end()`s to come back to
//!   `Self`).

use proc_macro2::{Literal, TokenStream};
use quote::quote;

use super::field::{field_type_builder, BuilderPolicy};
use super::id::{ident, idl_field_name_to_rs_name, idl_field_name_to_rs_type_name};
use super::parser::{Cluster, EntityContext};
use super::IdlGenerateContext;

/// Return a `TokenStream` containing the IM-client extension traits
/// for the given cluster: `<ClusterName>CmdRequests<P>`,
/// `<ClusterName>AttrReads<P>`, and `<ClusterName>AttrWrites<P>`.
pub fn client_im(
    cluster: &Cluster,
    entities: &EntityContext,
    context: &IdlGenerateContext,
) -> TokenStream {
    let cmd_requests = cmd_requests_trait(cluster, context);
    let attr_reads = attr_reads_trait(cluster, context);
    let attr_writes = attr_writes_trait(cluster, entities, context);

    quote!(
        #cmd_requests
        #attr_reads
        #attr_writes
    )
}

/// Emit the `<ClusterName>AttrReads<P>` trait + impl on
/// [`rs_matter::im::AttrPathArrayBuilder<P>`]. One method per
/// attribute (including global/read-only attrs like `FeatureMap` and
/// `AttributeList` — users may genuinely want to read them). Each
/// method pushes one concrete `AttrPath` entry and returns `Self` so
/// several reads can be chained into one request.
fn attr_reads_trait(cluster: &Cluster, context: &IdlGenerateContext) -> TokenStream {
    let krate = context.rs_matter_crate.clone();

    let cluster_snake = idl_field_name_to_rs_name(&cluster.id);
    let trait_name = ident(&format!(
        "{}AttrReads",
        idl_field_name_to_rs_type_name(&cluster.id)
    ));
    let cluster_code = Literal::u32_unsuffixed(cluster.code as u32);

    let methods_decl = cluster.attributes.iter().map(|attr| {
        let method_name = ident(&format!(
            "push_{cluster_snake}_{}",
            idl_field_name_to_rs_name(&attr.field.field.id)
        ));
        quote!(
            fn #method_name(
                self,
                endpoint: #krate::dm::EndptId,
            ) -> Result<Self, #krate::error::Error>;
        )
    });

    let methods_impl = cluster.attributes.iter().map(|attr| {
        let method_name = ident(&format!(
            "push_{cluster_snake}_{}",
            idl_field_name_to_rs_name(&attr.field.field.id)
        ));
        let attr_code = Literal::u32_unsuffixed(attr.field.field.code as u32);
        quote!(
            fn #method_name(
                self,
                endpoint: #krate::dm::EndptId,
            ) -> Result<Self, #krate::error::Error> {
                self.push()?
                    .endpoint(endpoint)?
                    .cluster(#cluster_code)?
                    .attr(#attr_code)?
                    .end()
            }
        )
    });

    let trait_doc = Literal::string(&format!(
        "IM-client extension trait for the `{}` cluster's attribute \
         reads. `use` this trait to see the `push_*` methods on \
         [`{}::im::AttrPathArrayBuilder`].",
        cluster.id, krate,
    ));

    quote!(
        #[doc = #trait_doc]
        pub trait #trait_name<P>: Sized
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            #(#methods_decl)*
        }

        impl<P> #trait_name<P> for #krate::im::AttrPathArrayBuilder<P>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            #(#methods_impl)*
        }
    )
}

/// Emit the `<ClusterName>AttrWrites<P>` trait + impl on
/// [`rs_matter::im::AttrDataArrayBuilder<P>`]. One method per
/// *writable* attribute (read-only attrs are skipped — they have no
/// meaningful write path). Two shapes:
///
/// - **Scalar-valued** attrs (`u8`, `bool`, enums, nullable scalars,
///   strings/octet-strings): the method takes a `value: T` and
///   returns `Self`. Body emits the path then `.data(|w| value.to_tlv(...))?.end()`.
///
/// - **Struct- or array-valued** attrs (codegen-emitted struct types,
///   lists, etc.): the method returns the codegen-emitted typed
///   value builder over `AttrDataBuilder<Self, 3>`. Caller fills the
///   value via the typed builder, then double-`.end()`s
///   (one for `Data`, one for `AttrData`) to come back to `Self`.
fn attr_writes_trait(
    cluster: &Cluster,
    entities: &EntityContext,
    context: &IdlGenerateContext,
) -> TokenStream {
    let krate = context.rs_matter_crate.clone();
    let krate_ident = krate.clone();

    let cluster_snake = idl_field_name_to_rs_name(&cluster.id);
    let trait_name = ident(&format!(
        "{}AttrWrites",
        idl_field_name_to_rs_type_name(&cluster.id)
    ));
    let cluster_code = Literal::u32_unsuffixed(cluster.code as u32);

    // Filter to writable attrs only (skip read-only — including all
    // global attrs which are read-only by convention).
    let writable = || cluster.attributes.iter().filter(|a| !a.is_read_only);

    let methods_decl = writable().map(|attr| {
        let method_name = ident(&format!(
            "push_{cluster_snake}_{}_write",
            idl_field_name_to_rs_name(&attr.field.field.id)
        ));

        // Determine the value type / builder type. `is_optional=false`
        // because the protocol-level optionality (the attribute may
        // not be present on the device) doesn't apply at write-time —
        // the caller is providing a concrete value. `is_nullable`
        // does propagate: a nullable attribute can be written as
        // `Nullable::Null` or `Nullable::Some(v)`.
        let (ty, builder) = field_type_builder(
            &attr.field.field.data_type,
            attr.field.is_nullable,
            false,
            BuilderPolicy::NonCopy,
            quote!(#krate_ident::im::AttrDataBuilder<Self, 3>),
            entities,
            &krate_ident,
        );

        if builder {
            quote!(
                fn #method_name(
                    self,
                    endpoint: #krate::dm::EndptId,
                ) -> Result<#ty, #krate::error::Error>;
            )
        } else {
            quote!(
                fn #method_name(
                    self,
                    endpoint: #krate::dm::EndptId,
                    value: #ty,
                ) -> Result<Self, #krate::error::Error>;
            )
        }
    });

    let methods_impl = writable().map(|attr| {
        let method_name = ident(&format!(
            "push_{cluster_snake}_{}_write",
            idl_field_name_to_rs_name(&attr.field.field.id)
        ));
        let attr_code = Literal::u32_unsuffixed(attr.field.field.code as u32);

        let (ty, builder) = field_type_builder(
            &attr.field.field.data_type,
            attr.field.is_nullable,
            false,
            BuilderPolicy::NonCopy,
            quote!(#krate_ident::im::AttrDataBuilder<Self, 3>),
            entities,
            &krate_ident,
        );

        if builder {
            // Struct- or array-valued: hand back the typed value
            // builder, opened at `AttrDataTag::Data` via
            // `data_builder()`. Caller double-`.end()`s.
            quote!(
                fn #method_name(
                    self,
                    endpoint: #krate::dm::EndptId,
                ) -> Result<#ty, #krate::error::Error> {
                    self.push()?
                        .path(endpoint, #cluster_code, #attr_code)?
                        .data_builder()
                }
            )
        } else {
            // Scalar-valued: take the value and emit it directly at
            // `AttrDataTag::Data`. Single `.end()` returns `Self`.
            quote!(
                fn #method_name(
                    self,
                    endpoint: #krate::dm::EndptId,
                    value: #ty,
                ) -> Result<Self, #krate::error::Error> {
                    self.push()?
                        .path(endpoint, #cluster_code, #attr_code)?
                        .data(|w| #krate::tlv::ToTLV::to_tlv(
                            &value,
                            &#krate::tlv::TLVTag::Context(
                                #krate::im::AttrDataTag::Data as u8,
                            ),
                            w,
                        ))?
                        .end()
                }
            )
        }
    });

    let trait_doc = Literal::string(&format!(
        "IM-client extension trait for the `{}` cluster's attribute \
         writes. `use` this trait to see the `push_*_write` methods on \
         [`{}::im::AttrDataArrayBuilder`].",
        cluster.id, krate,
    ));

    quote!(
        #[doc = #trait_doc]
        pub trait #trait_name<P>: Sized
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            #(#methods_decl)*
        }

        impl<P> #trait_name<P> for #krate::im::AttrDataArrayBuilder<P>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            #(#methods_impl)*
        }
    )
}

/// Emit the `<ClusterName>CmdRequests<P>` trait + impl on
/// [`rs_matter::im::CmdDataArrayBuilder<P>`]. One method per command.
fn cmd_requests_trait(cluster: &Cluster, context: &IdlGenerateContext) -> TokenStream {
    let krate = context.rs_matter_crate.clone();

    // Cluster naming helpers.
    let cluster_snake = idl_field_name_to_rs_name(&cluster.id);
    let trait_name = ident(&format!(
        "{}CmdRequests",
        idl_field_name_to_rs_type_name(&cluster.id)
    ));
    let cluster_code = Literal::u32_unsuffixed(cluster.code as u32);

    let methods_decl = cluster.commands.iter().map(|cmd| {
        let method_name = ident(&format!(
            "push_{cluster_snake}_{}",
            idl_field_name_to_rs_name(&cmd.id)
        ));

        match cmd.input.as_deref() {
            Some(req_struct) => {
                // Parameterized command: return the typed request builder
                // over `CmdDataBuilder<Self, 2>`. Caller closes with two
                // `.end()`s (one for `Data`, one for `CmdData`).
                let req_builder = ident(&format!("{req_struct}Builder"));
                quote!(
                    fn #method_name(
                        self,
                        endpoint: #krate::dm::EndptId,
                    ) -> Result<
                        #req_builder<#krate::im::CmdDataBuilder<Self, 2>, 0>,
                        #krate::error::Error,
                    >;
                )
            }
            None => {
                // Empty-request command: handle the Data slot inline,
                // return Self for chaining.
                quote!(
                    fn #method_name(
                        self,
                        endpoint: #krate::dm::EndptId,
                    ) -> Result<Self, #krate::error::Error>;
                )
            }
        }
    });

    let methods_impl = cluster.commands.iter().map(|cmd| {
        let method_name = ident(&format!(
            "push_{cluster_snake}_{}",
            idl_field_name_to_rs_name(&cmd.id)
        ));
        let cmd_code = Literal::u32_unsuffixed(cmd.code as u32);

        match cmd.input.as_deref() {
            Some(req_struct) => {
                let req_builder = ident(&format!("{req_struct}Builder"));
                quote!(
                    fn #method_name(
                        self,
                        endpoint: #krate::dm::EndptId,
                    ) -> Result<
                        #req_builder<#krate::im::CmdDataBuilder<Self, 2>, 0>,
                        #krate::error::Error,
                    > {
                        self.push()?
                            .path(endpoint, #cluster_code, #cmd_code)?
                            .data_builder()
                    }
                )
            }
            None => {
                // Empty request — open and immediately close an empty
                // `Data` struct at `CmdDataTag::Data`, then close
                // `CmdData`.
                quote!(
                    fn #method_name(
                        self,
                        endpoint: #krate::dm::EndptId,
                    ) -> Result<Self, #krate::error::Error> {
                        use #krate::tlv::TLVWrite;
                        self.push()?
                            .path(endpoint, #cluster_code, #cmd_code)?
                            .data(|w| {
                                w.start_struct(&#krate::tlv::TLVTag::Context(
                                    #krate::im::CmdDataTag::Data as u8,
                                ))?;
                                w.end_container()
                            })?
                            .end()
                    }
                )
            }
        }
    });

    let trait_doc = Literal::string(&format!(
        "IM-client extension trait for the `{}` cluster's commands. \
         `use` this trait to see the `push_*` methods on \
         [`{}::im::CmdDataArrayBuilder`].",
        cluster.id, krate,
    ));

    quote!(
        #[doc = #trait_doc]
        pub trait #trait_name<P>: Sized
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            #(#methods_decl)*
        }

        impl<P> #trait_name<P> for #krate::im::CmdDataArrayBuilder<P>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            #(#methods_impl)*
        }
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

    use super::super::parser::EntityContext;
    use super::{attr_reads_trait, attr_writes_trait, cmd_requests_trait};

    /// `OnOff` exercises both branches of the codegen: parameterized
    /// commands (`OffWithEffect`, `OnWithTimedOff`) hand back the
    /// codegen-emitted `*RequestBuilder`; empty-request commands
    /// (`Off`, `On`, `Toggle`, `OnWithRecallGlobalScene`) open and
    /// close `Data` inline and return `Self`. Method names are
    /// `push_<cluster_snake>_<command_snake>` so several cluster
    /// traits can coexist in scope without method-name clashes.
    #[test]
    fn test_client_im_onoff() {
        let idl = parse_idl(
            "
              cluster OnOff = 6 {
                revision 6;

                request struct OffWithEffectRequest {
                  enum8 effectIdentifier = 0;
                  enum8 effectVariant = 1;
                }

                request struct OnWithTimedOffRequest {
                  bitmap8 onOffControl = 0;
                  int16u onTime = 1;
                  int16u offWaitTime = 2;
                }

                command Off(): DefaultSuccess = 0;
                command On(): DefaultSuccess = 1;
                command Toggle(): DefaultSuccess = 2;
                command OffWithEffect(OffWithEffectRequest): DefaultSuccess = 64;
                command OnWithRecallGlobalScene(): DefaultSuccess = 65;
                command OnWithTimedOff(OnWithTimedOffRequest): DefaultSuccess = 66;
              }
        ",
        );

        let cluster_meta = get_cluster_named(&idl, "OnOff").expect("Cluster exists");
        let context = IdlGenerateContext::new("rs_matter_crate");

        assert_tokenstreams_eq!(
            &cmd_requests_trait(cluster_meta, &context),
            &quote!(
                #[doc = "IM-client extension trait for the `OnOff` cluster's commands. `use` this trait to see the `push_*` methods on [`rs_matter_crate::im::CmdDataArrayBuilder`]."]
                pub trait OnOffCmdRequests<P>: Sized
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn push_on_off_off(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                    ) -> Result<Self, rs_matter_crate::error::Error>;
                    fn push_on_off_on(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                    ) -> Result<Self, rs_matter_crate::error::Error>;
                    fn push_on_off_toggle(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                    ) -> Result<Self, rs_matter_crate::error::Error>;
                    fn push_on_off_off_with_effect(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                    ) -> Result<
                        OffWithEffectRequestBuilder<
                            rs_matter_crate::im::CmdDataBuilder<Self, 2>,
                            0,
                        >,
                        rs_matter_crate::error::Error,
                    >;
                    fn push_on_off_on_with_recall_global_scene(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                    ) -> Result<Self, rs_matter_crate::error::Error>;
                    fn push_on_off_on_with_timed_off(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                    ) -> Result<
                        OnWithTimedOffRequestBuilder<
                            rs_matter_crate::im::CmdDataBuilder<Self, 2>,
                            0,
                        >,
                        rs_matter_crate::error::Error,
                    >;
                }

                impl<P> OnOffCmdRequests<P> for rs_matter_crate::im::CmdDataArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn push_on_off_off(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        self.push()?
                            .path(endpoint, 6, 0)?
                            .data(|w| {
                                w.start_struct(&rs_matter_crate::tlv::TLVTag::Context(
                                    rs_matter_crate::im::CmdDataTag::Data as u8,
                                ))?;
                                w.end_container()
                            })?
                            .end()
                    }
                    fn push_on_off_on(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        self.push()?
                            .path(endpoint, 6, 1)?
                            .data(|w| {
                                w.start_struct(&rs_matter_crate::tlv::TLVTag::Context(
                                    rs_matter_crate::im::CmdDataTag::Data as u8,
                                ))?;
                                w.end_container()
                            })?
                            .end()
                    }
                    fn push_on_off_toggle(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        self.push()?
                            .path(endpoint, 6, 2)?
                            .data(|w| {
                                w.start_struct(&rs_matter_crate::tlv::TLVTag::Context(
                                    rs_matter_crate::im::CmdDataTag::Data as u8,
                                ))?;
                                w.end_container()
                            })?
                            .end()
                    }
                    fn push_on_off_off_with_effect(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                    ) -> Result<
                        OffWithEffectRequestBuilder<
                            rs_matter_crate::im::CmdDataBuilder<Self, 2>,
                            0,
                        >,
                        rs_matter_crate::error::Error,
                    > {
                        self.push()?.path(endpoint, 6, 64)?.data_builder()
                    }
                    fn push_on_off_on_with_recall_global_scene(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        self.push()?
                            .path(endpoint, 6, 65)?
                            .data(|w| {
                                w.start_struct(&rs_matter_crate::tlv::TLVTag::Context(
                                    rs_matter_crate::im::CmdDataTag::Data as u8,
                                ))?;
                                w.end_container()
                            })?
                            .end()
                    }
                    fn push_on_off_on_with_timed_off(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                    ) -> Result<
                        OnWithTimedOffRequestBuilder<
                            rs_matter_crate::im::CmdDataBuilder<Self, 2>,
                            0,
                        >,
                        rs_matter_crate::error::Error,
                    > {
                        self.push()?.path(endpoint, 6, 66)?.data_builder()
                    }
                }
            )
        );
    }

    /// Multi-word cluster names should be snake-cased in method names
    /// and CamelCased in the trait name. `LevelControl::MoveToLevel`
    /// is the canonical example from the design discussion. Also
    /// covers a parameterized command with a single struct argument.
    #[test]
    fn test_client_im_level_control_naming() {
        let idl = parse_idl(
            "
              cluster LevelControl = 8 {
                revision 6;

                request struct MoveToLevelRequest {
                  int8u level = 0;
                  nullable int16u transitionTime = 1;
                  bitmap8 optionsMask = 2;
                  bitmap8 optionsOverride = 3;
                }

                command MoveToLevel(MoveToLevelRequest): DefaultSuccess = 0;
                command Stop(): DefaultSuccess = 3;
              }
        ",
        );

        let cluster_meta = get_cluster_named(&idl, "LevelControl").expect("Cluster exists");
        let context = IdlGenerateContext::new("rs_matter_crate");

        assert_tokenstreams_eq!(
            &cmd_requests_trait(cluster_meta, &context),
            &quote!(
                #[doc = "IM-client extension trait for the `LevelControl` cluster's commands. `use` this trait to see the `push_*` methods on [`rs_matter_crate::im::CmdDataArrayBuilder`]."]
                pub trait LevelControlCmdRequests<P>: Sized
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn push_level_control_move_to_level(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                    ) -> Result<
                        MoveToLevelRequestBuilder<rs_matter_crate::im::CmdDataBuilder<Self, 2>, 0>,
                        rs_matter_crate::error::Error,
                    >;
                    fn push_level_control_stop(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                    ) -> Result<Self, rs_matter_crate::error::Error>;
                }

                impl<P> LevelControlCmdRequests<P> for rs_matter_crate::im::CmdDataArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn push_level_control_move_to_level(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                    ) -> Result<
                        MoveToLevelRequestBuilder<rs_matter_crate::im::CmdDataBuilder<Self, 2>, 0>,
                        rs_matter_crate::error::Error,
                    > {
                        self.push()?.path(endpoint, 8, 0)?.data_builder()
                    }
                    fn push_level_control_stop(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        self.push()?
                            .path(endpoint, 8, 3)?
                            .data(|w| {
                                w.start_struct(&rs_matter_crate::tlv::TLVTag::Context(
                                    rs_matter_crate::im::CmdDataTag::Data as u8,
                                ))?;
                                w.end_container()
                            })?
                            .end()
                    }
                }
            )
        );
    }

    /// Corner case: a cluster with no commands still emits the trait
    /// and impl — both with empty method lists. This means downstream
    /// users can blanket-`use` the trait for any cluster without
    /// running into "trait not defined" for the command-less ones
    /// (e.g. diagnostic-only clusters).
    #[test]
    fn test_client_im_no_commands() {
        let idl = parse_idl(
            "
              cluster Descriptor = 29 {
                revision 2;
                readonly attribute int16u clusterRevision = 65533;
              }
        ",
        );

        let cluster_meta = get_cluster_named(&idl, "Descriptor").expect("Cluster exists");
        let context = IdlGenerateContext::new("rs_matter_crate");

        assert_tokenstreams_eq!(
            &cmd_requests_trait(cluster_meta, &context),
            &quote!(
                #[doc = "IM-client extension trait for the `Descriptor` cluster's commands. `use` this trait to see the `push_*` methods on [`rs_matter_crate::im::CmdDataArrayBuilder`]."]
                pub trait DescriptorCmdRequests<P>: Sized
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                }

                impl<P> DescriptorCmdRequests<P> for rs_matter_crate::im::CmdDataArrayBuilder<P> where
                    P: rs_matter_crate::tlv::TLVBuilderParent
                {
                }
            )
        );
    }

    /// Attribute reads emit a uniform `push_<cluster>_<attr>` method
    /// per attribute (including global/read-only attrs like
    /// `FeatureMap` and `ClusterRevision` — callers may legitimately
    /// want to read them). Each method writes one concrete
    /// `AttrPath` entry and returns `Self` so multiple reads can
    /// chain.
    #[test]
    fn test_client_im_attr_reads_identify() {
        let idl = parse_idl(
            "
              cluster Identify = 3 {
                revision 6;

                attribute int16u identifyTime = 0;
                readonly attribute enum8 identifyType = 1;
                readonly attribute int16u clusterRevision = 65533;
              }
        ",
        );

        let cluster_meta = get_cluster_named(&idl, "Identify").expect("Cluster exists");
        let context = IdlGenerateContext::new("rs_matter_crate");

        assert_tokenstreams_eq!(
            &attr_reads_trait(cluster_meta, &context),
            &quote!(
                #[doc = "IM-client extension trait for the `Identify` cluster's attribute reads. `use` this trait to see the `push_*` methods on [`rs_matter_crate::im::AttrPathArrayBuilder`]."]
                pub trait IdentifyAttrReads<P>: Sized
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn push_identify_identify_time(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                    ) -> Result<Self, rs_matter_crate::error::Error>;
                    fn push_identify_identify_type(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                    ) -> Result<Self, rs_matter_crate::error::Error>;
                    fn push_identify_cluster_revision(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                    ) -> Result<Self, rs_matter_crate::error::Error>;
                }

                impl<P> IdentifyAttrReads<P> for rs_matter_crate::im::AttrPathArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn push_identify_identify_time(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        self.push()?.endpoint(endpoint)?.cluster(3)?.attr(0)?.end()
                    }
                    fn push_identify_identify_type(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        self.push()?.endpoint(endpoint)?.cluster(3)?.attr(1)?.end()
                    }
                    fn push_identify_cluster_revision(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        self.push()?
                            .endpoint(endpoint)?
                            .cluster(3)?
                            .attr(65533)?
                            .end()
                    }
                }
            )
        );
    }

    /// Attribute writes split into two shapes based on the
    /// attribute's value type. `OnOff` covers both:
    /// - `onTime: int16u` (scalar) → `value: u16`, returns `Self`.
    /// - `startUpOnOff: nullable StartUpOnOffEnum` (still a scalar
    ///   for write purposes; nullability propagates) →
    ///   `value: Nullable<StartUpOnOffEnum>`, returns `Self`.
    /// - The read-only `onOff` is **skipped** (no `_write` method
    ///   emitted; the spec disallows writing it).
    #[test]
    fn test_client_im_attr_writes_onoff_scalars() {
        let idl = parse_idl(
            "
              cluster OnOff = 6 {
                revision 6;

                enum StartUpOnOffEnum : enum8 {
                  kOff = 0;
                  kOn = 1;
                  kToggle = 2;
                }

                readonly attribute boolean onOff = 0;
                attribute optional int16u onTime = 16385;
                attribute access(write: manage) optional nullable StartUpOnOffEnum startUpOnOff = 16387;
              }
        ",
        );

        let cluster_meta = get_cluster_named(&idl, "OnOff").expect("Cluster exists");
        let entities = EntityContext::new(Some(cluster_meta), &idl.globals);
        let context = IdlGenerateContext::new("rs_matter_crate");

        assert_tokenstreams_eq!(
            &attr_writes_trait(cluster_meta, &entities, &context),
            &quote!(
                #[doc = "IM-client extension trait for the `OnOff` cluster's attribute writes. `use` this trait to see the `push_*_write` methods on [`rs_matter_crate::im::AttrDataArrayBuilder`]."]
                pub trait OnOffAttrWrites<P>: Sized
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn push_on_off_on_time_write(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                        value: u16,
                    ) -> Result<Self, rs_matter_crate::error::Error>;
                    fn push_on_off_start_up_on_off_write(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                        value: rs_matter_crate::tlv::Nullable<StartUpOnOffEnum>,
                    ) -> Result<Self, rs_matter_crate::error::Error>;
                }

                impl<P> OnOffAttrWrites<P> for rs_matter_crate::im::AttrDataArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn push_on_off_on_time_write(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                        value: u16,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        self.push()?
                            .path(endpoint, 6, 16385)?
                            .data(|w| {
                                rs_matter_crate::tlv::ToTLV::to_tlv(
                                    &value,
                                    &rs_matter_crate::tlv::TLVTag::Context(
                                        rs_matter_crate::im::AttrDataTag::Data as u8,
                                    ),
                                    w,
                                )
                            })?
                            .end()
                    }
                    fn push_on_off_start_up_on_off_write(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                        value: rs_matter_crate::tlv::Nullable<StartUpOnOffEnum>,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        self.push()?
                            .path(endpoint, 6, 16387)?
                            .data(|w| {
                                rs_matter_crate::tlv::ToTLV::to_tlv(
                                    &value,
                                    &rs_matter_crate::tlv::TLVTag::Context(
                                        rs_matter_crate::im::AttrDataTag::Data as u8,
                                    ),
                                    w,
                                )
                            })?
                            .end()
                    }
                }
            )
        );
    }

    /// Struct- or array-valued writable attrs return the codegen-
    /// emitted typed value builder over `AttrDataBuilder<Self, 3>`.
    /// `AccessControl::acl` is `list of AccessControlEntryStruct` —
    /// the canonical example.
    #[test]
    fn test_client_im_attr_writes_builder_shape() {
        let idl = parse_idl(
            "
              cluster AccessControl = 31 {
                revision 2;

                fabric_scoped struct AccessControlEntryStruct {
                  fabric_sensitive int8u privilege = 1;
                  fabric_sensitive int8u authMode = 2;
                }

                attribute access(read: administer, write: administer) AccessControlEntryStruct acl[] = 0;
              }
        ",
        );

        let cluster_meta = get_cluster_named(&idl, "AccessControl").expect("Cluster exists");
        let entities = EntityContext::new(Some(cluster_meta), &idl.globals);
        let context = IdlGenerateContext::new("rs_matter_crate");

        assert_tokenstreams_eq!(
            &attr_writes_trait(cluster_meta, &entities, &context),
            &quote!(
                #[doc = "IM-client extension trait for the `AccessControl` cluster's attribute writes. `use` this trait to see the `push_*_write` methods on [`rs_matter_crate::im::AttrDataArrayBuilder`]."]
                pub trait AccessControlAttrWrites<P>: Sized
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn push_access_control_acl_write(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                    ) -> Result<
                        AccessControlEntryStructArrayBuilder<
                            rs_matter_crate::im::AttrDataBuilder<Self, 3>,
                        >,
                        rs_matter_crate::error::Error,
                    >;
                }

                impl<P> AccessControlAttrWrites<P> for rs_matter_crate::im::AttrDataArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn push_access_control_acl_write(
                        self,
                        endpoint: rs_matter_crate::dm::EndptId,
                    ) -> Result<
                        AccessControlEntryStructArrayBuilder<
                            rs_matter_crate::im::AttrDataBuilder<Self, 3>,
                        >,
                        rs_matter_crate::error::Error,
                    > {
                        self.push()?.path(endpoint, 31, 0)?.data_builder()
                    }
                }
            )
        );
    }
}
