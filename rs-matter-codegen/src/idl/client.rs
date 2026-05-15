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

use super::cluster::NO_RESPONSE;
use super::field::{field_type_builder, BuilderPolicy};
use super::id::{ident, idl_field_name_to_rs_name, idl_field_name_to_rs_type_name};
use super::parser::{Cluster, EntityContext};
use super::IdlGenerateContext;

/// Snake-case method names that would collide with the inherent
/// methods of the per-cluster `<…>View` structs emitted by the
/// extension-trait codegen — currently just `end` (the view's exit
/// method). When a command or attribute name (after
/// `idl_field_name_to_rs_name`) lands on one of these, the codegen
/// prefixes it: `cmd_<name>` on `<Cluster>CmdRequestsView`,
/// `attr_<name>` on `<Cluster>AttrReadsView` / `AttrWritesView`.
///
/// Extend this list if future view-struct surface adds more inherent
/// methods.
const RESERVED_VIEW_METHOD_NAMES: &[&str] = &["end"];

/// Snake-case method name for a *command* on a `<Cluster>CmdRequestsView`,
/// applying the `cmd_` prefix when the raw IDL-derived name would
/// collide with a reserved view-inherent name (see
/// [`RESERVED_VIEW_METHOD_NAMES`]). The current motivating case is
/// the WebRTC cluster's `End` command, which would shadow the view's
/// `.end()` exit method; it becomes `cmd_end` instead.
fn view_cmd_method_name(idl_name: &str) -> String {
    let snake = idl_field_name_to_rs_name(idl_name);
    if RESERVED_VIEW_METHOD_NAMES.contains(&snake.as_str()) {
        format!("cmd_{snake}")
    } else {
        snake
    }
}

/// Counterpart for attributes — `attr_` prefix on collision.
fn view_attr_method_name(idl_name: &str) -> String {
    let snake = idl_field_name_to_rs_name(idl_name);
    if RESERVED_VIEW_METHOD_NAMES.contains(&snake.as_str()) {
        format!("attr_{snake}")
    } else {
        snake
    }
}

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
    let cmd_responses = cmd_responses_trait(cluster, context);
    let attr_responses = attr_responses_trait(cluster, entities, context);
    let write_responses = write_responses_trait(cluster, context);
    let client = client_trait(cluster, entities, context);

    quote!(
        #cmd_requests
        #attr_reads
        #attr_writes
        #cmd_responses
        #attr_responses
        #write_responses
        #client
    )
}

/// Emit the `<ClusterName>AttrReads<P>` extension trait on
/// [`rs_matter::im::AttrPathArrayBuilder<P>`], plus the cluster-scoped
/// view struct `<ClusterName>AttrReadsView<P>`.
///
/// The trait surface is intentionally tiny — one method,
/// `<cluster_snake>_read(self) -> <ClusterName>AttrReadsView<P>` — so
/// IDE completion at `array.<cluster>_read().` shows only this
/// cluster's per-attribute methods. The `_read` suffix lets a user
/// `use` all three `<Cluster>AttrReads / AttrWrites / CmdRequests`
/// traits in the same module without ambiguity.
///
/// The view's per-attribute methods drop the cluster prefix —
/// `view.on_off(endpoint)?` instead of `array.push_on_off_on_off(endpoint)?`.
/// Each pushes one concrete `AttrPath` and returns `Self` so several
/// reads can chain. `view.end()?` closes the wrapped array and
/// returns its parent (mirroring `AttrPathArrayBuilder::end()`).
fn attr_reads_trait(cluster: &Cluster, context: &IdlGenerateContext) -> TokenStream {
    let krate = context.rs_matter_crate.clone();

    let cluster_snake = idl_field_name_to_rs_name(&cluster.id);
    let cluster_camel = idl_field_name_to_rs_type_name(&cluster.id);
    let trait_name = ident(&format!("{cluster_camel}AttrReads"));
    let view_name = ident(&format!("{cluster_camel}AttrReadsView"));
    let entry_method = ident(&format!("{cluster_snake}_read"));
    let cluster_code = Literal::u32_unsuffixed(cluster.code as u32);

    let attr_methods = cluster.attributes.iter().map(|attr| {
        let method_name = ident(&view_attr_method_name(&attr.field.field.id));
        let attr_code = Literal::u32_unsuffixed(attr.field.field.code as u32);
        quote!(
            pub fn #method_name(
                self,
                endpoint: #krate::dm::EndptId,
            ) -> Result<Self, #krate::error::Error> {
                let array = self.array
                    .push()?
                    .endpoint(endpoint)?
                    .cluster(#cluster_code)?
                    .attr(#attr_code)?
                    .end()?;
                Ok(Self { array })
            }
        )
    });

    let trait_doc = Literal::string(&format!(
        "IM-client extension trait for the `{cluster_id}` cluster's \
         attribute reads. `use` this trait to call `.{cluster_snake}_read()` \
         on an [`{krate}::im::AttrPathArrayBuilder`]; the returned \
         [`{cluster_camel}AttrReadsView`] exposes one method per \
         attribute (cluster-prefix-free). `.end()` on the view closes \
         the wrapped array.",
        cluster_id = cluster.id,
    ));
    let view_doc = Literal::string(&format!(
        "Cluster-scoped view onto an [`{krate}::im::AttrPathArrayBuilder`] \
         for the `{cluster_id}` cluster. Each method pushes one \
         `AttrPath` (cluster ID baked in) and returns `Self` for chaining; \
         `.end()` closes the underlying array. Attribute names that \
         would collide with the view's own inherent methods (see \
         `RESERVED_VIEW_METHOD_NAMES` in the codegen) get an `attr_` \
         prefix.",
        cluster_id = cluster.id,
    ));

    quote!(
        #[doc = #view_doc]
        pub struct #view_name<P>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            array: #krate::im::AttrPathArrayBuilder<P>,
        }

        impl<P> #view_name<P>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            #(#attr_methods)*

            /// Close the wrapped array and return its parent.
            pub fn end(self) -> Result<P, #krate::error::Error> {
                self.array.end()
            }
        }

        #[doc = #trait_doc]
        pub trait #trait_name<P>: Sized
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            fn #entry_method(self) -> #view_name<P>;
        }

        impl<P> #trait_name<P> for #krate::im::AttrPathArrayBuilder<P>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            fn #entry_method(self) -> #view_name<P> {
                #view_name { array: self }
            }
        }
    )
}

/// Emit the `<ClusterName>AttrWrites<P>` extension trait on
/// [`rs_matter::im::AttrDataArrayBuilder<P>`], plus the cluster-scoped
/// view struct `<ClusterName>AttrWritesView<P>`.
///
/// Same shape as `attr_reads_trait`: the trait has a single entry
/// method `<cluster_snake>_write(self) -> <ClusterName>AttrWritesView<P>`,
/// and per-attribute methods live on the view (cluster-prefix-free,
/// chainable, `.end()` closes the wrapped array). Two shapes per attr:
///
/// - **Scalar-valued** attrs (`u8`, `bool`, enums, nullable scalars,
///   strings/octet-strings): the method takes a `value: T` and
///   returns `Self`.
///
/// - **Struct- or array-valued** attrs (codegen-emitted struct types,
///   lists, etc.): the method returns the codegen-emitted typed
///   value builder over `AttrDataBuilder<AttrDataArrayBuilder<P>, 3>`.
///   Caller fills the value via the typed builder, then double-`.end()`s
///   (Data, AttrData) to come back to the underlying array builder —
///   note this exits the view (the parent type chain doesn't include
///   the view wrapper).
fn attr_writes_trait(
    cluster: &Cluster,
    entities: &EntityContext,
    context: &IdlGenerateContext,
) -> TokenStream {
    let krate = context.rs_matter_crate.clone();
    let krate_ident = krate.clone();

    let cluster_snake = idl_field_name_to_rs_name(&cluster.id);
    let cluster_camel = idl_field_name_to_rs_type_name(&cluster.id);
    let trait_name = ident(&format!("{cluster_camel}AttrWrites"));
    let view_name = ident(&format!("{cluster_camel}AttrWritesView"));
    let entry_method = ident(&format!("{cluster_snake}_write"));
    let cluster_code = Literal::u32_unsuffixed(cluster.code as u32);

    // Filter to writable attrs only (skip read-only — including all
    // global attrs which are read-only by convention).
    let writable = || cluster.attributes.iter().filter(|a| !a.is_read_only);

    let attr_methods = writable().map(|attr| {
        let method_name = ident(&view_attr_method_name(&attr.field.field.id));
        let attr_code = Literal::u32_unsuffixed(attr.field.field.code as u32);

        // Builder-valued attrs return a builder whose parent is the
        // wrapped array (NOT the view). The caller's double-`.end()?`
        // after filling the value lands on the array directly, so
        // they continue with another `<cluster>_write()` if needed.
        let (ty, builder) = field_type_builder(
            &attr.field.field.data_type,
            attr.field.is_nullable,
            false,
            BuilderPolicy::NonCopy,
            quote!(#krate_ident::im::AttrDataBuilder<#krate_ident::im::AttrDataArrayBuilder<P>, 3>),
            entities,
            &krate_ident,
        );

        if builder {
            quote!(
                pub fn #method_name(
                    self,
                    endpoint: #krate::dm::EndptId,
                ) -> Result<#ty, #krate::error::Error> {
                    self.array
                        .push()?
                        .path(endpoint, #cluster_code, #attr_code)?
                        .data_builder()
                }
            )
        } else {
            quote!(
                pub fn #method_name(
                    self,
                    endpoint: #krate::dm::EndptId,
                    value: #ty,
                ) -> Result<Self, #krate::error::Error> {
                    let array = self.array
                        .push()?
                        .path(endpoint, #cluster_code, #attr_code)?
                        .data(|w| #krate::tlv::ToTLV::to_tlv(
                            &value,
                            &#krate::tlv::TLVTag::Context(
                                #krate::im::AttrDataTag::Data as u8,
                            ),
                            w,
                        ))?
                        .end()?;
                    Ok(Self { array })
                }
            )
        }
    });

    let trait_doc = Literal::string(&format!(
        "IM-client extension trait for the `{cluster_id}` cluster's \
         attribute writes. `use` this trait to call \
         `.{cluster_snake}_write()` on an \
         [`{krate}::im::AttrDataArrayBuilder`]; the returned \
         [`{cluster_camel}AttrWritesView`] exposes one method per \
         writable attribute (cluster-prefix-free). `.end()` on the \
         view closes the wrapped array.",
        cluster_id = cluster.id,
    ));
    let view_doc = Literal::string(&format!(
        "Cluster-scoped view onto an [`{krate}::im::AttrDataArrayBuilder`] \
         for the `{cluster_id}` cluster. Scalar-valued attrs push and \
         return `Self` for chaining; struct/list-valued attrs return \
         the codegen-emitted typed value builder (whose parent chain \
         bypasses the view — close back to the array via Data + AttrData \
         `.end()?`s). `.end()` closes the wrapped array. Attribute \
         names that would collide with the view's own inherent methods \
         (see `RESERVED_VIEW_METHOD_NAMES` in the codegen) get an \
         `attr_` prefix.",
        cluster_id = cluster.id,
    ));

    quote!(
        #[doc = #view_doc]
        pub struct #view_name<P>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            array: #krate::im::AttrDataArrayBuilder<P>,
        }

        impl<P> #view_name<P>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            #(#attr_methods)*

            /// Close the wrapped array and return its parent.
            pub fn end(self) -> Result<P, #krate::error::Error> {
                self.array.end()
            }
        }

        #[doc = #trait_doc]
        pub trait #trait_name<P>: Sized
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            fn #entry_method(self) -> #view_name<P>;
        }

        impl<P> #trait_name<P> for #krate::im::AttrDataArrayBuilder<P>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            fn #entry_method(self) -> #view_name<P> {
                #view_name { array: self }
            }
        }
    )
}

/// Emit the `<ClusterName>CmdRequests<P>` extension trait on
/// [`rs_matter::im::CmdDataArrayBuilder<P>`], plus the cluster-scoped
/// view struct `<ClusterName>CmdRequestsView<P>`.
///
/// Same shape as `attr_reads_trait` / `attr_writes_trait`: the trait
/// has a single entry method `<cluster_snake>_inv(self) ->
/// <ClusterName>CmdRequestsView<P>`, and per-command methods live on
/// the view (cluster-prefix-free). Two shapes per cmd:
///
/// - **Empty-request** commands: the method returns `Self` (the
///   view) for chaining.
///
/// - **Parameterized** commands: the method returns the codegen-emitted
///   typed `<Cmd>RequestBuilder` whose parent chain is
///   `CmdDataBuilder<CmdDataArrayBuilder<P>, 2>`. The caller fills the
///   request body and double-`.end()`s back to the underlying array
///   (the view wrapper is bypassed on the close path — same as the
///   builder-shape attr writes).
fn cmd_requests_trait(cluster: &Cluster, context: &IdlGenerateContext) -> TokenStream {
    let krate = context.rs_matter_crate.clone();

    let cluster_snake = idl_field_name_to_rs_name(&cluster.id);
    let cluster_camel = idl_field_name_to_rs_type_name(&cluster.id);
    let trait_name = ident(&format!("{cluster_camel}CmdRequests"));
    let view_name = ident(&format!("{cluster_camel}CmdRequestsView"));
    let entry_method = ident(&format!("{cluster_snake}_inv"));
    let cluster_code = Literal::u32_unsuffixed(cluster.code as u32);

    let cmd_methods = cluster.commands.iter().map(|cmd| {
        let method_name = ident(&view_cmd_method_name(&cmd.id));
        let cmd_code = Literal::u32_unsuffixed(cmd.code as u32);

        match cmd.input.as_deref() {
            Some(req_struct) => {
                let req_builder = ident(&format!("{req_struct}Builder"));
                quote!(
                    pub fn #method_name(
                        self,
                        endpoint: #krate::dm::EndptId,
                    ) -> Result<
                        #req_builder<
                            #krate::im::CmdDataBuilder<
                                #krate::im::CmdDataArrayBuilder<P>,
                                2,
                            >,
                            0,
                        >,
                        #krate::error::Error,
                    > {
                        self.array
                            .push()?
                            .path(endpoint, #cluster_code, #cmd_code)?
                            .data_builder()
                    }
                )
            }
            None => {
                quote!(
                    pub fn #method_name(
                        self,
                        endpoint: #krate::dm::EndptId,
                    ) -> Result<Self, #krate::error::Error> {
                        use #krate::tlv::TLVWrite;
                        let array = self.array
                            .push()?
                            .path(endpoint, #cluster_code, #cmd_code)?
                            .data(|w| {
                                w.start_struct(&#krate::tlv::TLVTag::Context(
                                    #krate::im::CmdDataTag::Data as u8,
                                ))?;
                                w.end_container()
                            })?
                            .end()?;
                        Ok(Self { array })
                    }
                )
            }
        }
    });

    let trait_doc = Literal::string(&format!(
        "IM-client extension trait for the `{cluster_id}` cluster's \
         commands. `use` this trait to call `.{cluster_snake}_inv()` \
         on a [`{krate}::im::CmdDataArrayBuilder`]; the returned \
         [`{cluster_camel}CmdRequestsView`] exposes one method per \
         command (cluster-prefix-free). `.end()` on the view closes \
         the wrapped array.",
        cluster_id = cluster.id,
    ));
    let view_doc = Literal::string(&format!(
        "Cluster-scoped view onto a [`{krate}::im::CmdDataArrayBuilder`] \
         for the `{cluster_id}` cluster. Empty-request commands push \
         and return `Self`; parameterized commands return the codegen-emitted \
         typed request builder (whose parent chain bypasses the view — \
         close back to the array via Data + CmdData `.end()?`s). \
         `.end()` closes the wrapped array. Command names that would \
         collide with the view's own inherent methods (see \
         `RESERVED_VIEW_METHOD_NAMES` in the codegen — currently `end`, \
         which the WebRTC cluster uses) get a `cmd_` prefix.",
        cluster_id = cluster.id,
    ));

    quote!(
        #[doc = #view_doc]
        pub struct #view_name<P>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            array: #krate::im::CmdDataArrayBuilder<P>,
        }

        impl<P> #view_name<P>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            #(#cmd_methods)*

            /// Close the wrapped array and return its parent.
            pub fn end(self) -> Result<P, #krate::error::Error> {
                self.array.end()
            }
        }

        #[doc = #trait_doc]
        pub trait #trait_name<P>: Sized
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            fn #entry_method(self) -> #view_name<P>;
        }

        impl<P> #trait_name<P> for #krate::im::CmdDataArrayBuilder<P>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            fn #entry_method(self) -> #view_name<P> {
                #view_name { array: self }
            }
        }
    )
}

// ─────────────────────────────────────────────────────────────────────
// Response-side extension traits
// ─────────────────────────────────────────────────────────────────────

/// Emit the `<ClusterName>CmdResponses<'a>` extension trait on
/// [`rs_matter::im::InvokeResp<'a>`], plus the cluster-scoped view
/// struct `<ClusterName>CmdResponsesView<'a, 'r>`.
///
/// Same single-entry-method-plus-view shape as the request-side
/// extensions (see [`cmd_requests_trait`]). The trait surface is a
/// single method `<cluster_snake>_inv_resp(&self) -> <…>View<'a, '_>`;
/// per-command iterator methods live on the view.
///
/// Method shape per command:
/// - **DefaultSuccess** (`cmd.output == NO_RESPONSE`): yields
///   `(EndptId, Result<(), Error>)` — see
///   [`rs_matter::im::InvokeResp::statuses`]. Useful for batched
///   invokes that mix DefaultSuccess and response-bearing commands;
///   single-command DefaultSuccess invokes don't populate
///   `invoke_responses` at all.
/// - **Response-bearing**: yields `(EndptId, Result<<Output><'a>, Error>)` —
///   see [`rs_matter::im::InvokeResp::responses`]. The codegen-emitted
///   response struct (e.g. `MoveToLevelResponse<'a>`) is `FromTLV`-able
///   over the lifetime `'a` of the underlying RX buffer.
fn cmd_responses_trait(cluster: &Cluster, context: &IdlGenerateContext) -> TokenStream {
    let krate = context.rs_matter_crate.clone();

    let cluster_snake = idl_field_name_to_rs_name(&cluster.id);
    let cluster_camel = idl_field_name_to_rs_type_name(&cluster.id);
    let trait_name = ident(&format!("{cluster_camel}CmdResponses"));
    let view_name = ident(&format!("{cluster_camel}CmdResponsesView"));
    let entry_method = ident(&format!("{cluster_snake}_inv_resp"));
    let cluster_code = Literal::u32_unsuffixed(cluster.code as u32);

    let cmd_methods = cluster.commands.iter().map(|cmd| {
        let method_name = ident(&view_cmd_method_name(&cmd.id));
        let cmd_code = Literal::u32_unsuffixed(cmd.code as u32);

        if cmd.output == NO_RESPONSE {
            // DefaultSuccess: iterator of (EndptId, Result<(), Error>)
            quote!(
                pub fn #method_name(
                    &self,
                ) -> impl Iterator<Item = (
                    #krate::dm::EndptId,
                    Result<(), #krate::error::Error>,
                )> + '_ {
                    self.resp.statuses(#cluster_code, #cmd_code)
                }
            )
        } else {
            let resp_ty = ident(&cmd.output);
            quote!(
                pub fn #method_name(
                    &self,
                ) -> impl Iterator<Item = (
                    #krate::dm::EndptId,
                    Result<#resp_ty<'a>, #krate::error::Error>,
                )> + use<'_, 'a, 'r> {
                    self.resp.responses::<#resp_ty<'a>>(#cluster_code, #cmd_code)
                }
            )
        }
    });

    let trait_doc = Literal::string(&format!(
        "IM-client extension trait for extracting `{cluster_id}`-cluster \
         command responses out of a generic [`{krate}::im::InvokeResp`]. \
         `use` this trait to call `.{cluster_snake}_inv_resp()` on an \
         `InvokeResp`; the returned [`{cluster_camel}CmdResponsesView`] \
         exposes one iterator method per command, each yielding \
         `(EndptId, Result<<Output>, Error>)` — see \
         [`{krate}::im::InvokeResp::responses`] / \
         [`{krate}::im::InvokeResp::statuses`] for the per-entry \
         semantics.",
        cluster_id = cluster.id,
    ));
    let view_doc = Literal::string(&format!(
        "Cluster-scoped response view onto a [`{krate}::im::InvokeResp`] \
         for the `{cluster_id}` cluster. Each method returns an \
         iterator of `(EndptId, Result<R, Error>)` over the entries \
         in `invoke_responses` whose path matches that command. \
         Command names that would collide with the view's own \
         inherent methods (see `RESERVED_VIEW_METHOD_NAMES` in the \
         codegen) get a `cmd_` prefix.",
        cluster_id = cluster.id,
    ));

    quote!(
        #[doc = #view_doc]
        pub struct #view_name<'a, 'r> {
            resp: &'r #krate::im::InvokeResp<'a>,
        }

        impl<'a, 'r> #view_name<'a, 'r> {
            #(#cmd_methods)*
        }

        #[doc = #trait_doc]
        pub trait #trait_name<'a> {
            fn #entry_method(&self) -> #view_name<'a, '_>;
        }

        impl<'a> #trait_name<'a> for #krate::im::InvokeResp<'a> {
            fn #entry_method(&self) -> #view_name<'a, '_> {
                #view_name { resp: self }
            }
        }
    )
}

/// Emit the `<ClusterName>AttrResponses<'a>` extension trait on
/// [`rs_matter::im::ReportDataResp<'a>`], plus the cluster-scoped
/// view struct `<ClusterName>AttrResponsesView<'a, 'r>`.
///
/// Single entry method per cluster (`<cluster_snake>_read_resp`);
/// per-attribute iterator methods on the view. Per Matter Core spec
/// §8.4, attribute reads support wildcards, so the iterator may
/// yield multiple `(endpoint, …)` entries (one per expansion). The
/// per-entry semantics — `Ok(T)` for data, `Err(_)` for status —
/// match [`rs_matter::im::ReportDataResp::attrs`].
///
/// **Scope:** emits one method per *scalar* attribute (same constraint
/// as `client_trait`'s read methods — `BuilderPolicy::NonCopyAndStrings`
/// with `is_builder == false`). Non-scalar attribute types
/// (struct, list, string) require their own FromTLV-able value type;
/// callers can use `ReportDataResp::attrs::<T>(cluster, attr)` with
/// the codegen-emitted struct type for those.
fn attr_responses_trait(
    cluster: &Cluster,
    entities: &EntityContext,
    context: &IdlGenerateContext,
) -> TokenStream {
    let krate = context.rs_matter_crate.clone();

    let cluster_snake = idl_field_name_to_rs_name(&cluster.id);
    let cluster_camel = idl_field_name_to_rs_type_name(&cluster.id);
    let trait_name = ident(&format!("{cluster_camel}AttrResponses"));
    let view_name = ident(&format!("{cluster_camel}AttrResponsesView"));
    let entry_method = ident(&format!("{cluster_snake}_read_resp"));
    let cluster_code = Literal::u32_unsuffixed(cluster.code as u32);

    let attr_methods = cluster.attributes.iter().filter_map(|attr| {
        let parent_dummy = quote!(());
        let (value_ty, is_builder) = field_type_builder(
            &attr.field.field.data_type,
            attr.field.is_nullable,
            attr.field.is_optional,
            BuilderPolicy::NonCopyAndStrings,
            parent_dummy,
            entities,
            &krate,
        );
        if is_builder {
            return None;
        }

        let method_name = ident(&view_attr_method_name(&attr.field.field.id));
        let attr_code = Literal::u32_unsuffixed(attr.field.field.code as u32);

        Some(quote!(
            pub fn #method_name(
                &self,
            ) -> impl Iterator<Item = (
                #krate::dm::EndptId,
                Result<#value_ty, #krate::error::Error>,
            )> + '_ {
                self.resp.attrs::<#value_ty>(#cluster_code, #attr_code)
            }
        ))
    });

    let trait_doc = Literal::string(&format!(
        "IM-client extension trait for extracting `{cluster_id}`-cluster \
         attribute reports out of a generic \
         [`{krate}::im::ReportDataResp`]. `use` this trait to call \
         `.{cluster_snake}_read_resp()` on a `ReportDataResp`; the \
         returned [`{cluster_camel}AttrResponsesView`] exposes one \
         iterator method per scalar attribute, each yielding \
         `(EndptId, Result<T, Error>)`. Non-scalar attributes (struct, \
         list, string) require `ReportDataResp::attrs::<T>(cluster, \
         attr)` directly with the right FromTLV-able type.",
        cluster_id = cluster.id,
    ));
    let view_doc = Literal::string(&format!(
        "Cluster-scoped response view onto a \
         [`{krate}::im::ReportDataResp`] for the `{cluster_id}` \
         cluster. Each method returns an iterator of \
         `(EndptId, Result<T, Error>)` over the entries in \
         `attr_reports` whose path matches that attribute. Attribute \
         names that would collide with the view's own inherent \
         methods (see `RESERVED_VIEW_METHOD_NAMES` in the codegen) \
         get an `attr_` prefix.",
        cluster_id = cluster.id,
    ));

    quote!(
        #[doc = #view_doc]
        pub struct #view_name<'a, 'r> {
            resp: &'r #krate::im::ReportDataResp<'a>,
        }

        impl<'a, 'r> #view_name<'a, 'r> {
            #(#attr_methods)*
        }

        #[doc = #trait_doc]
        pub trait #trait_name<'a> {
            fn #entry_method(&self) -> #view_name<'a, '_>;
        }

        impl<'a> #trait_name<'a> for #krate::im::ReportDataResp<'a> {
            fn #entry_method(&self) -> #view_name<'a, '_> {
                #view_name { resp: self }
            }
        }
    )
}

/// Emit the `<ClusterName>WriteResponses<'a>` extension trait on
/// [`rs_matter::im::WriteResp<'a>`], plus the cluster-scoped view
/// struct `<ClusterName>WriteResponsesView<'a, 'r>`.
///
/// Single entry method per cluster (`<cluster_snake>_write_resp`);
/// per-*writable* attribute iterator methods on the view. Each yields
/// `(EndptId, Result<(), Error>)` — see
/// [`rs_matter::im::WriteResp::statuses`]. Wildcards expand per the
/// Matter spec; the iterator yields one entry per expanded path.
fn write_responses_trait(cluster: &Cluster, context: &IdlGenerateContext) -> TokenStream {
    let krate = context.rs_matter_crate.clone();

    let cluster_snake = idl_field_name_to_rs_name(&cluster.id);
    let cluster_camel = idl_field_name_to_rs_type_name(&cluster.id);
    let trait_name = ident(&format!("{cluster_camel}WriteResponses"));
    let view_name = ident(&format!("{cluster_camel}WriteResponsesView"));
    let entry_method = ident(&format!("{cluster_snake}_write_resp"));
    let cluster_code = Literal::u32_unsuffixed(cluster.code as u32);

    let writable = || cluster.attributes.iter().filter(|a| !a.is_read_only);

    let attr_methods = writable().map(|attr| {
        let method_name = ident(&view_attr_method_name(&attr.field.field.id));
        let attr_code = Literal::u32_unsuffixed(attr.field.field.code as u32);

        quote!(
            pub fn #method_name(
                &self,
            ) -> impl Iterator<Item = (
                #krate::dm::EndptId,
                Result<(), #krate::error::Error>,
            )> + '_ {
                self.resp.statuses(#cluster_code, #attr_code)
            }
        )
    });

    let trait_doc = Literal::string(&format!(
        "IM-client extension trait for extracting `{cluster_id}`-cluster \
         per-attribute write statuses out of a generic \
         [`{krate}::im::WriteResp`]. `use` this trait to call \
         `.{cluster_snake}_write_resp()` on a `WriteResp`; the returned \
         [`{cluster_camel}WriteResponsesView`] exposes one iterator \
         method per writable attribute, each yielding \
         `(EndptId, Result<(), Error>)`.",
        cluster_id = cluster.id,
    ));
    let view_doc = Literal::string(&format!(
        "Cluster-scoped write-status view onto a \
         [`{krate}::im::WriteResp`] for the `{cluster_id}` cluster. \
         Each method returns an iterator of \
         `(EndptId, Result<(), Error>)` over the entries in \
         `write_responses` whose path matches that attribute. \
         Attribute names that would collide with the view's own \
         inherent methods (see `RESERVED_VIEW_METHOD_NAMES` in the \
         codegen) get an `attr_` prefix.",
        cluster_id = cluster.id,
    ));

    quote!(
        #[doc = #view_doc]
        pub struct #view_name<'a, 'r> {
            resp: &'r #krate::im::WriteResp<'a>,
        }

        impl<'a, 'r> #view_name<'a, 'r> {
            #(#attr_methods)*
        }

        #[doc = #trait_doc]
        pub trait #trait_name<'a> {
            fn #entry_method(&self) -> #view_name<'a, '_>;
        }

        impl<'a> #trait_name<'a> for #krate::im::WriteResp<'a> {
            fn #entry_method(&self) -> #view_name<'a, '_> {
                #view_name { resp: self }
            }
        }
    )
}

/// Emit the high-level `<ClusterName>Client<'a>` trait + blanket impl
/// on [`Exchange<'a>`]. One method per command / attribute, hiding
/// the full IM transaction (sender, retransmit loop, response chunk
/// iteration, status-only handling) behind a single async call.
///
/// Output shape, per cluster:
///
/// ```ignore
/// pub trait <ClusterName>Client<'a>: ImClient<'a> {
///     // DefaultSuccess command, parameterized:
///     async fn <cluster>_<cmd><F>(self, ep: EndptId, request: F) -> Result<(), Error>
///     where F: FnMut(<Cmd>RequestBuilder<...>) -> Result<<parent>, Error>;
///
///     // DefaultSuccess command, empty-request:
///     async fn <cluster>_<cmd>(self, ep: EndptId) -> Result<(), Error>;
///
///     // Scalar attribute read:
///     async fn <cluster>_<attr>_read(self, ep: EndptId) -> Result<T, Error>;
///
///     // Scalar attribute write:
///     async fn <cluster>_<attr>_write(self, ep: EndptId, value: T) -> Result<(), Error>;
/// }
/// impl<'a> <ClusterName>Client<'a> for Exchange<'a> {}
/// ```
///
/// Commands that return a real `*Response` struct (i.e. `cmd.output
/// != "DefaultSuccess"`) and attributes whose type is non-scalar
/// (structs / lists / strings) are *not* surfaced through this
/// trait — callers fall back to `ImClient::invoke_with` /
/// `read_with` / `write_with` plus the per-cluster `*CmdRequests` /
/// `*AttrReads` / `*AttrWrites` extension traits for those cases.
fn client_trait(
    cluster: &Cluster,
    entities: &EntityContext,
    context: &IdlGenerateContext,
) -> TokenStream {
    let krate = context.rs_matter_crate.clone();

    let cluster_snake = idl_field_name_to_rs_name(&cluster.id);
    let cluster_camel = idl_field_name_to_rs_type_name(&cluster.id);
    let trait_name = ident(&format!("{cluster_camel}Client"));
    let view_name = ident(&format!("{cluster_camel}ClientView"));
    let entry_method = ident(&cluster_snake);

    // The per-cluster IM-client extension traits (already emitted
    // above in this same module) that the view methods delegate to.
    // We `use` them inside each method body so the trait's entry
    // method (`<cluster_snake>_read`/`_write`/`_inv`) resolves.
    let cmd_requests_trait_name = ident(&format!("{cluster_camel}CmdRequests"));
    let attr_reads_trait_name = ident(&format!("{cluster_camel}AttrReads"));
    let attr_writes_trait_name = ident(&format!("{cluster_camel}AttrWrites"));
    let cmd_requests_entry = ident(&format!("{cluster_snake}_inv"));
    let attr_reads_entry = ident(&format!("{cluster_snake}_read"));
    let attr_writes_entry = ident(&format!("{cluster_snake}_write"));

    // ---- Command methods -------------------------------------------------
    //
    // Two flavours of body:
    // - DefaultSuccess (`cmd.output == NO_RESPONSE`): returns
    //   `Result<(), Error>`; drains the chunk loop internally so the
    //   trailing `StatusResponse(Success)` ACK is sent before
    //   returning.
    // - Response-bearing: returns
    //   `Result<<Output>Handle<'a>, Error>`. The handle keeps the
    //   exchange's RX buffer alive; the caller materialises the
    //   borrowed response via `handle.response()?` and explicitly
    //   `.complete().await?`s to send the trailing `StatusResponse(Success)`.
    //
    // Per Matter Core spec §10.7.10, single-command invokes produce
    // a single, non-chunked `InvokeResponseMessage` — chunking is only
    // legal for batched (N>1) invokes — so the handle's `response()`
    // can safely parse one IB without iterating.
    //
    // Methods live on the per-cluster *view* struct
    // (`<ClusterName>ClientView<'a>`) rather than on the trait, so
    // IDE completion at `exchange.<cluster>().` shows only this
    // cluster's surface.
    let cmd_methods = cluster.commands.iter().map(|cmd| {
        // `method_name` is the method on the high-level ClientView
        // (no renaming — the high-level view has no `end()` of its
        // own); `view_method_name` is the corresponding method on
        // the lower-level CmdRequestsView (renamed when it would
        // collide with the array-close `end()` — see
        // `view_cmd_method_name`).
        let method_name = ident(&idl_field_name_to_rs_name(&cmd.id));
        let view_method_name = ident(&view_cmd_method_name(&cmd.id));

        let default_success = cmd.output == NO_RESPONSE;
        let (return_ty, return_expr) = if default_success {
            (
                quote!(()),
                quote!(
                    while let Some(next) = chunk.complete().await? {
                        chunk = next;
                    }
                    Ok(())
                ),
            )
        } else {
            let handle = ident(&format!("{}Handle", cmd.output));
            (quote!(#handle<'a>), quote!(Ok(#handle { chunk })))
        };

        // For parameterized commands the closure takes the typed
        // `*RequestBuilder` over the concrete nested parent type the
        // codegen `push_*` method returns; for empty-request
        // commands we skip the closure entirely.
        //
        // The build closure is plain `FnMut`, not `AsyncFnMut`: the
        // MRP layer may invoke it multiple times across retransmits
        // (see `invoke_with` docs), and it MUST produce the same TLV
        // output on every call. A sync closure that captures values
        // by reference is naturally idempotent; an async closure
        // makes it easy to silently break that contract by `.await`ing
        // a state-changing hook (e.g. draining a queue) inside the
        // body. Callers that genuinely need async build work should
        // pre-fetch / snapshot the data outside the closure and
        // reference it by sync borrow inside (see how
        // `webrtc_prov::push_outbound` handles `take_offer_sdp`).
        if let Some(req_struct) = cmd.input.as_deref() {
            let req_builder = ident(&format!("{req_struct}Builder"));
            // Successful-completion path uses `mut chunk` so the
            // drain loop can rebind; handle-returning path doesn't
            // mutate so we drop the `mut`. Quoting the binding lets
            // each branch pick.
            let chunk_binding = if default_success {
                quote!(let mut chunk)
            } else {
                quote!(let chunk)
            };
            quote!(
                pub async fn #method_name<F>(
                    self,
                    endpoint: #krate::dm::EndptId,
                    mut request: F,
                ) -> Result<#return_ty, #krate::error::Error>
                where
                    F: FnMut(
                        #req_builder<
                            #krate::im::CmdDataBuilder<
                                #krate::im::CmdDataArrayBuilder<
                                    #krate::im::InvReqBuilder<#krate::im::client::InvokeSender<'a>, 3>,
                                >,
                                2,
                            >,
                            0,
                        >,
                    ) -> Result<
                        #krate::im::CmdDataBuilder<
                            #krate::im::CmdDataArrayBuilder<
                                #krate::im::InvReqBuilder<#krate::im::client::InvokeSender<'a>, 3>,
                            >,
                            2,
                        >,
                        #krate::error::Error,
                    >,
                {
                    use #krate::im::client::ImClient as _ImClient;
                    use self::#cmd_requests_trait_name as _Cmds;

                    #chunk_binding = _ImClient::invoke_with(self.exchange, None, |msg| {
                        // `suppress_response` and `timed_request` are
                        // skipped — `InvReqBuilder` fills them in as
                        // `false` on the wire (the common-case
                        // default). The view step
                        // (`<cluster>_inv()`) is a no-op typed
                        // wrapper; `<cmd>(endpoint)` is the
                        // codegen-emitted push method on the view
                        // (possibly `cmd_<cmd>` if the IDL name
                        // collides with the view's exit `end()` —
                        // see `view_cmd_method_name`).
                        let view = msg.invoke_requests()?.#cmd_requests_entry();
                        let req_builder = view.#view_method_name(endpoint)?;
                        let cmd_data = request(req_builder)?;
                        cmd_data.end()?.end()?.end()
                    })
                    .await?;

                    #return_expr
                }
            )
        } else {
            let chunk_binding = if default_success {
                quote!(let mut chunk)
            } else {
                quote!(let chunk)
            };
            quote!(
                pub async fn #method_name(
                    self,
                    endpoint: #krate::dm::EndptId,
                ) -> Result<#return_ty, #krate::error::Error> {
                    use #krate::im::client::ImClient as _ImClient;
                    use self::#cmd_requests_trait_name as _Cmds;

                    #chunk_binding = _ImClient::invoke_with(self.exchange, None, |msg| {
                        // `suppress_response` / `timed_request`
                        // skipped — see the parameterized branch.
                        // `.<cluster>_inv()` enters the cluster
                        // view; `.<cmd>(endpoint)?` pushes the
                        // empty-request command (possibly `cmd_<cmd>`
                        // on collision — see `view_cmd_method_name`);
                        // `.end()?` on the view closes the array.
                        msg.invoke_requests()?
                            .#cmd_requests_entry()
                            .#view_method_name(endpoint)?
                            .end()?
                            .end()
                    })
                    .await?;

                    #return_expr
                }
            )
        }
    });

    // ---- Response handles (deduped per cluster) -------------------------
    //
    // Multiple commands can share an output struct (e.g. both
    // `AddNetwork` and `RemoveNetwork` return `NetworkConfigResponse`),
    // so we collect the unique output names and emit one `Handle`
    // per output. `cmd.output == NO_RESPONSE` ("DefaultSuccess") is
    // skipped — those commands return `Result<(), Error>` directly.
    let mut output_names: Vec<&str> = Vec::new();
    for cmd in &cluster.commands {
        if cmd.output != NO_RESPONSE && !output_names.contains(&cmd.output.as_str()) {
            output_names.push(&cmd.output);
        }
    }
    let response_handles = output_names.iter().map(|output| {
        let resp_ty = ident(output);
        let handle_ty = ident(&format!("{output}Handle"));
        let handle_doc = Literal::string(&format!(
            "Single-shot handle wrapping the [`InvokeRespChunk`] of a `{output}` \
             response. Holds the exchange's RX buffer alive; `response()` \
             parses the embedded `CommandDataIB` into a borrowed \
             [`{output}`]. The trailing `StatusResponse(Success)` is sent \
             when the caller `.complete().await?`s the handle.\n\n\
             Single-command invokes never chunk per Matter Core spec \
             §10.7.10, so a single `response()` call is sufficient.",
        ));
        quote!(
            #[doc = #handle_doc]
            pub struct #handle_ty<'a> {
                chunk: #krate::im::client::InvokeRespChunk<'a>,
            }

            impl<'a> #handle_ty<'a> {
                /// Borrowed access to the parsed response. The returned
                /// value points into the exchange's RX buffer, which
                /// stays valid until this handle is dropped or
                /// `.complete()`d.
                pub fn response(&self) -> Result<#resp_ty<'_>, #krate::error::Error> {
                    let invoke_resp = self.chunk
                        .response()?
                        .ok_or(#krate::error::ErrorCode::InvalidData)?;
                    let invoke_responses = invoke_resp
                        .invoke_responses
                        .as_ref()
                        .ok_or(#krate::error::ErrorCode::InvalidData)?;
                    let cmd_resp = invoke_responses
                        .iter()
                        .next()
                        .ok_or(#krate::error::ErrorCode::InvalidData)?
                        .map_err(|_| #krate::error::ErrorCode::InvalidData)?;
                    match cmd_resp {
                        #krate::im::CmdResp::Cmd(data) => {
                            #krate::tlv::FromTLV::from_tlv(&data.data)
                        }
                        #krate::im::CmdResp::Status(s) => {
                            Err(s.status
                                .status
                                .to_error_code()
                                .unwrap_or(#krate::error::ErrorCode::Failure)
                                .into())
                        }
                    }
                }

                /// Send the trailing `StatusResponse(Success)` and close
                /// the exchange. Call this once after the borrowed
                /// response is no longer needed. Forgetting it lets the
                /// peer time out and resend — functional but wasteful.
                pub async fn complete(self) -> Result<(), #krate::error::Error> {
                    let mut chunk = self.chunk;
                    while let Some(next) = chunk.complete().await? {
                        chunk = next;
                    }
                    Ok(())
                }
            }
        )
    });

    // ---- Attribute-read methods (scalar attrs only) ---------------------
    let attr_read_methods = cluster.attributes.iter().filter_map(|attr| {
        // Skip non-scalar attributes — the user can fall back to
        // `read_with` + the per-cluster `AttrReads` extension trait
        // for those.
        let parent_dummy = quote!(());
        let (value_ty, is_builder) = field_type_builder(
            &attr.field.field.data_type,
            attr.field.is_nullable,
            attr.field.is_optional,
            BuilderPolicy::NonCopyAndStrings,
            parent_dummy,
            entities,
            &krate,
        );
        if is_builder {
            return None;
        }

        // `attr_method` is the renamed view method (collision-safe
        // via `view_attr_method_name`); `method_name` is the
        // high-level ClientView method, which keeps the raw
        // snake_case + `_read` suffix.
        let attr_method = ident(&view_attr_method_name(&attr.field.field.id));
        let method_name = ident(&format!(
            "{}_read",
            idl_field_name_to_rs_name(&attr.field.field.id)
        ));

        Some(quote!(
            pub async fn #method_name(
                self,
                endpoint: #krate::dm::EndptId,
            ) -> Result<#value_ty, #krate::error::Error> {
                use #krate::im::client::ImClient as _ImClient;
                use self::#attr_reads_trait_name as _Reads;

                let mut chunk = _ImClient::read_with(self.exchange, |msg| {
                    msg.attr_requests()?
                        .#attr_reads_entry()
                        .#attr_method(endpoint)?
                        .end()?
                        .fabric_filtered(true)?
                        .end()
                })
                .await?;

                let value = {
                    let resp = chunk.response()?;
                    let attr_reports = resp
                        .attr_reports
                        .as_ref()
                        .ok_or(#krate::error::ErrorCode::InvalidData)?;
                    let attr_resp = attr_reports
                        .iter()
                        .next()
                        .ok_or(#krate::error::ErrorCode::InvalidData)?
                        .map_err(|_| #krate::error::ErrorCode::InvalidData)?;
                    match attr_resp {
                        #krate::im::AttrResp::Data(data) => {
                            #krate::tlv::FromTLV::from_tlv(&data.data)?
                        }
                        #krate::im::AttrResp::Status(status) => {
                            return Err(status
                                .status
                                .status
                                .to_error_code()
                                .unwrap_or(#krate::error::ErrorCode::Failure)
                                .into());
                        }
                    }
                };

                // Drain any remaining chunks (sends trailing StatusResponse).
                while let Some(next) = chunk.complete().await? {
                    chunk = next;
                }
                Ok(value)
            }
        ))
    });

    // ---- Attribute-write methods (scalar attrs only) --------------------
    let attr_write_methods = cluster.attributes.iter().filter_map(|attr| {
        if attr.is_read_only {
            return None;
        }
        let parent_dummy = quote!(());
        let (value_ty, is_builder) = field_type_builder(
            &attr.field.field.data_type,
            attr.field.is_nullable,
            false, // `is_optional` is a protocol-level signal, not a write-time one
            BuilderPolicy::NonCopyAndStrings,
            parent_dummy,
            entities,
            &krate,
        );
        if is_builder {
            return None;
        }

        // See `attr_read_methods` above for the naming split.
        let attr_method = ident(&view_attr_method_name(&attr.field.field.id));
        let method_name = ident(&format!(
            "{}_write",
            idl_field_name_to_rs_name(&attr.field.field.id)
        ));

        Some(quote!(
            pub async fn #method_name(
                self,
                endpoint: #krate::dm::EndptId,
                value: #value_ty,
            ) -> Result<(), #krate::error::Error> {
                use #krate::im::client::ImClient as _ImClient;
                use self::#attr_writes_trait_name as _Writes;

                let handle = _ImClient::write_with(self.exchange, None, |msg| {
                    msg.write_requests()?
                        .#attr_writes_entry()
                        .#attr_method(endpoint, value.clone())?
                        .end()?
                        .end()
                })
                .await?;

                // Inspect per-attribute status. WriteResponse is
                // single-message — no chunking — so we only need to
                // look at the first (and only) status entry.
                let resp = handle.response()?;
                for status in resp.write_responses.iter() {
                    let status = status?;
                    if status.status.status != #krate::im::IMStatusCode::Success {
                        return Err(status
                            .status
                            .status
                            .to_error_code()
                            .unwrap_or(#krate::error::ErrorCode::Failure)
                            .into());
                    }
                }
                Ok(())
            }
        ))
    });

    let trait_doc = Literal::string(&format!(
        "Single-shot IM-client convenience trait for the `{cluster_id}` cluster. \
         `use` this trait to call `.{snake}()` on an \
         [`{krate}::transport::exchange::Exchange`]; the returned \
         [`{view}`] exposes one method per command and per scalar \
         attribute (read / write). The cluster ID, command/attribute \
         ID, request opcode, retransmit loop, response-chunk iteration, \
         and status-only handling are all baked in. DefaultSuccess \
         commands return `Result<(), Error>` and drain the response \
         internally; response-bearing commands return \
         `Result<<RespStruct>Handle<'a>, Error>` — the handle keeps \
         the RX buffer alive so the caller can read the borrowed \
         response via `.response()?` before `.complete().await?`ing \
         the exchange.\n\n\
         The indirection through `{view}` keeps each cluster's API \
         surface narrow: at the call site `exchange.{snake}().` shows \
         only this cluster's methods in IDE completion.",
        cluster_id = cluster.id,
        krate = krate,
        snake = cluster_snake,
        view = format!("{cluster_camel}ClientView"),
    ));
    let view_doc = Literal::string(&format!(
        "Per-exchange view onto the `{cluster_id}` cluster's client operations. \
         Returned by [`{cluster_camel}Client::{cluster_snake}`]. Each method \
         consumes the view (and therefore the underlying \
         [`{krate}::transport::exchange::Exchange`]) — one exchange is one \
         IM transaction.",
        cluster_id = cluster.id,
    ));

    quote!(
        #(#response_handles)*

        #[doc = #view_doc]
        pub struct #view_name<'a> {
            exchange: #krate::transport::exchange::Exchange<'a>,
        }

        impl<'a> #view_name<'a> {
            #(#cmd_methods)*
            #(#attr_read_methods)*
            #(#attr_write_methods)*
        }

        #[doc = #trait_doc]
        pub trait #trait_name<'a>: #krate::im::client::ImClient<'a> {
            /// Enter this cluster's client view. Consumes the
            /// exchange — call methods on the returned view to drive
            /// a single IM transaction (one command invoke or one
            /// attribute read/write).
            fn #entry_method(self) -> #view_name<'a> {
                #view_name { exchange: self.into() }
            }
        }

        impl<'a> #trait_name<'a> for #krate::transport::exchange::Exchange<'a> {}
    )
}

#[cfg(test)]
mod tests {
    // The detailed per-cluster shape tests that used to live here
    // (`test_client_im_onoff`, `test_client_im_level_control_naming`,
    // `test_client_im_attr_reads_identify`, etc.) were removed when
    // the codegen was restructured to emit one entry method per trait
    // (returning a cluster-scoped view struct) instead of one method
    // per attribute/command on the trait itself. The full-cluster
    // golden test `idl::tests::test_unit_testing_cluster` exercises
    // every emitted shape end-to-end via the CSA-standard cluster
    // library and is the source of truth for codegen output.
}
