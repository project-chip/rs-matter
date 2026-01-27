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

//! A module for generating the the handler trait and its
//! adaptor for a given IDL cluster.

use proc_macro2::{Ident, Literal, TokenStream};
use quote::quote;

use super::cluster::{GLOBAL_ATTR, NO_RESPONSE};
use super::field::{field_type, field_type_builder, BuilderPolicy};
use super::id::{ident, idl_attribute_name_to_enum_variant_name, idl_field_name_to_rs_name};
use super::parser::{Attribute, Cluster, Command, DataType, Entities, EntityContext, StructType};
use super::IdlGenerateContext;

/// Return a token stream defining the handler trait for the provided IDL cluster.
///
/// Unlike the `rs-matter` generic `AsyncHandler` pair of traits, the trait
/// generated here is specific to the concrete provided IDL cluster and is strongly-typed.
///
/// Thus, it contains methods corresponding to all the attributes and commands of the
/// IDL cluster.
///
/// Moreover, these methods are much more safe w.r.t. TLV parsing and encoding, as they
/// are based on the IDL information and make use of all enums, bitmaps and structs defined
/// in the IDL cluster, thus providing a strongly-typed interface.
///
/// ## Arguments
/// - `delegate`: If true, rather than generating a handler trait, the function will generate
///   an inherent implementation of the trait over `&T`, where `T` is assumed to implement the trait.
/// - `cluster`: The IDL cluster for which the handler is generated.
/// - `context`: The context containing the information needed to generate the handler.
pub fn handler(
    delegate: bool,
    cluster: &Cluster,
    globals: &Entities,
    context: &IdlGenerateContext,
) -> TokenStream {
    let krate = context.rs_matter_crate.clone();

    let handler_name = ident("ClusterHandler");

    let entities = &EntityContext::new(Some(&cluster.entities), globals);
    let handler_attribute_methods = cluster
        .attributes
        .iter()
        .filter(|attr| !GLOBAL_ATTR.contains(&attr.field.field.code))
        .map(|attr| handler_attribute(attr, delegate, entities, &krate));

    let handler_attribute_write_methods = cluster
        .attributes
        .iter()
        .filter(|attr| !GLOBAL_ATTR.contains(&attr.field.field.code))
        .filter(|attr| !attr.is_read_only)
        .map(|attr| handler_attribute_write(attr, delegate, entities, &krate));

    let handler_command_methods = cluster
        .commands
        .iter()
        .map(|cmd| handler_command(cmd, delegate, entities, &krate));

    if delegate {
        let run = quote!(
            fn run(&self, ctx: impl #krate::dm::HandlerContext) -> impl core::future::Future<Output = Result<(), #krate::error::Error>> {
                (**self).run(ctx)
            }
        );

        quote!(
            impl<T> #handler_name for &T
            where
                T: #handler_name
            {
                const CLUSTER: #krate::dm::Cluster<'static> = T::CLUSTER;

                fn dataver(&self) -> u32 { T::dataver(self) }
                fn dataver_changed(&self) { T::dataver_changed(self) }

                #run

                #(#handler_attribute_methods)*

                #(#handler_attribute_write_methods)*

                #(#handler_command_methods)*
            }
        )
    } else {
        let run = quote!(
            fn run(&self, _ctx: impl #krate::dm::HandlerContext) -> impl core::future::Future<Output = Result<(), #krate::error::Error>> {
                core::future::pending::<Result::<(), #krate::error::Error>>()
            }
        );

        quote!(
            #[doc = "The handler trait for the cluster."]
            pub trait #handler_name {
                #[doc = "The cluster-metadata corresponding to this handler trait."]
                const CLUSTER: #krate::dm::Cluster<'static>;

                fn dataver(&self) -> u32;

                fn dataver_changed(&self);

                #run

                #(#handler_attribute_methods)*

                #(#handler_attribute_write_methods)*

                #(#handler_command_methods)*
            }
        )
    }
}

/// Return a token stream defining an adaptor struct that can adapt a type implementing the
/// cluster-specific handler trait as defined by the `handler` function to the
/// generic `AsyncHandler` traits that `rs-matter` understands.
///
/// Without this adaptor, implementations of the cluster-specific handler trait would not be
/// usable with `rs-matter`.
///
/// # Arguments
///   to the `Handler` trait.
/// - `cluster`: The IDL cluster for which the adaptor is generated.
/// - `context`: The context containing the information needed to generate the adaptor.
pub fn handler_adaptor(
    cluster: &Cluster,
    globals: &Entities,
    context: &IdlGenerateContext,
) -> TokenStream {
    let krate = context.rs_matter_crate.clone();

    let cluster_name_str = Literal::string(&cluster.id);
    let cluster_code = Literal::u32_suffixed(cluster.code as _);

    let handler_name = ident("ClusterHandler");

    let handler_adaptor_name = ident("HandlerAdaptor");

    let generic_handler_name = ident("AsyncHandler");

    let entities = &EntityContext::new(Some(&cluster.entities), globals);
    let handler_adaptor_attribute_match = cluster
        .attributes
        .iter()
        .filter(|attr| !GLOBAL_ATTR.contains(&attr.field.field.code))
        .map(|attr| handler_adaptor_attribute_match(attr, entities, &krate))
        .collect::<Vec<_>>();

    let handler_adaptor_attribute_write_match = cluster
        .attributes
        .iter()
        .filter(|attr| !GLOBAL_ATTR.contains(&attr.field.field.code))
        .filter(|attr| !attr.is_read_only)
        .map(|attr| handler_adaptor_attribute_write_match(attr, entities, &krate));

    let handler_adaptor_command_match = cluster
        .commands
        .iter()
        .map(|cmd| handler_adaptor_command_match(cmd, entities, &krate))
        .collect::<Vec<_>>();

    let read_stream = if !handler_adaptor_attribute_match.is_empty() {
        quote!(
            match AttributeId::try_from(ctx.attr().attr_id)? {
                #(#handler_adaptor_attribute_match)*
                #[allow(unreachable_code)]
                other => {
                    #[cfg(feature = "defmt")]
                    #krate::reexport::defmt::error!("Attribute {:?} not supported", other);
                    #[cfg(feature = "log")]
                    #krate::reexport::log::error!("Attribute {:?} not supported", other);

                    Err(#krate::error::ErrorCode::AttributeNotFound.into())
                }
            }
        )
    } else {
        quote!(
            #[cfg(feature = "defmt")]
            #krate::reexport::defmt::error!("No cluster-specific attributes");
            #[cfg(feature = "log")]
            #krate::reexport::log::error!("No cluster-specific attributes");

            Err(#krate::error::ErrorCode::AttributeNotFound.into())
        )
    };

    let write_stream = if !handler_adaptor_attribute_match.is_empty() {
        quote!(
            match AttributeId::try_from(ctx.attr().attr_id)? {
                #(#handler_adaptor_attribute_write_match)*
                other => {
                    #[cfg(feature = "defmt")]
                    #krate::reexport::defmt::error!("Attribute {:?} not supported", other);
                    #[cfg(feature = "log")]
                    #krate::reexport::log::error!("Attribute {:?} not supported", other);

                    return Err(#krate::error::ErrorCode::AttributeNotFound.into());
                }
            }
        )
    } else {
        quote!(
            #[cfg(feature = "defmt")]
            #krate::reexport::defmt::error!("No cluster-specific attributes");
            #[cfg(feature = "log")]
            #krate::reexport::log::error!("No cluster-specific attributes");

            return Err(#krate::error::ErrorCode::AttributeNotFound.into());
        )
    };

    let invoke_stream = if !handler_adaptor_command_match.is_empty() {
        quote!(
            match CommandId::try_from(ctx.cmd().cmd_id)? {
                #(#handler_adaptor_command_match)*
                other => {
                    #[cfg(feature = "defmt")]
                    #krate::reexport::defmt::error!("Command {:?} not supported", other);
                    #[cfg(feature = "log")]
                    #krate::reexport::log::error!("Command {:?} not supported", other);

                    return Err(#krate::error::ErrorCode::CommandNotFound.into());
                }
            }
        )
    } else {
        quote!(
            #[cfg(feature = "defmt")]
            #krate::reexport::defmt::error!("No cluster-specific commands");
            #[cfg(feature = "log")]
            #krate::reexport::log::error!("No cluster-specific commands");

            return Err(#krate::error::ErrorCode::CommandNotFound.into());
        )
    };

    let run = quote!(
        fn run(&self, ctx: impl #krate::dm::HandlerContext) -> impl core::future::Future<Output = Result<(), #krate::error::Error>> {
            self.0.run(ctx)
        }
    );

    let stream = quote!(
        #[doc = "The handler adaptor for the cluster-specific handler. This adaptor implements the generic `rs-matter` handler trait."]
        #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
        #[cfg_attr(feature = "defmt", derive(#krate::reexport::defmt::Format))]
        pub struct #handler_adaptor_name<T>(pub T);

        impl<T> #krate::dm::#generic_handler_name for #handler_adaptor_name<T>
        where
            T: #handler_name,
        {
            #[allow(unreachable_code)]
            async fn read(
                &self,
                ctx: impl #krate::dm::ReadContext,
                reply: impl #krate::dm::ReadReply,
            ) -> Result<(), #krate::error::Error> {
                if let Some(mut writer) = reply.with_dataver(self.0.dataver())? {
                    if ctx.attr().is_system() {
                        ctx.attr().cluster()?.read(ctx.attr(), writer)
                    } else {
                        #read_stream
                    }
                } else {
                    Ok(())
                }
            }

            #[allow(unreachable_code)]
            async fn write(
                &self,
                ctx: impl #krate::dm::WriteContext,
            ) -> Result<(), #krate::error::Error> {
                ctx.attr().check_dataver(self.0.dataver())?;

                if ctx.attr().is_system() {
                    return Err(#krate::error::ErrorCode::InvalidAction.into())
                }

                #write_stream

                self.0.dataver_changed();

                Ok(())
            }

            #[allow(unreachable_code)]
            async fn invoke(
                &self,
                ctx: impl #krate::dm::InvokeContext,
                reply: impl #krate::dm::InvokeReply,
            ) -> Result<(), #krate::error::Error> {
                #invoke_stream

                self.0.dataver_changed();

                Ok(())
            }

            #run
        }

        impl<T, Q> core::fmt::Debug for MetadataDebug<(u16, &#handler_adaptor_name<T>, Q)>
        where
            T: #handler_name,
            Q: core::fmt::Debug,
        {
            #[allow(unreachable_code)]
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "Endpt(0x{:02x})::Cluster::{}(0x{:04x})::{:?}", self.0.0, #cluster_name_str, #cluster_code, self.0.2)
            }
        }

        #[cfg(feature = "defmt")]
        impl<T, Q> #krate::reexport::defmt::Format for MetadataDebug<(u16, &#handler_adaptor_name<T>, Q)>
        where
            T: #handler_name,
            Q: #krate::reexport::defmt::Format,
        {
            #[allow(unreachable_code)]
            fn format(&self, f: #krate::reexport::defmt::Formatter<'_>) {
                #krate::reexport::defmt::write!(f, "Endpt(0x{:02x})::Cluster::{}(0x{:04x})::{:?}", self.0.0, #cluster_name_str, #cluster_code, self.0.2)
            }
        }
    );

    stream
}

/// Return a token stream defining the handler trait method for reading the provided IDL attribute.
///
/// # Arguments
/// - `attr`: The IDL attribute for which the handler method is generated.
/// - `delegate`: If true, the generated handler method will have an implementation delegating
///   to a `T` type (for inherent impls)
/// - `cluster`: The IDL cluster for which the handler method is generated.
/// - `krate`: The crate name to use for the generated code.
fn handler_attribute(
    attr: &Attribute,
    delegate: bool,
    entities: &EntityContext,
    krate: &Ident,
) -> TokenStream {
    let attr_name = ident(&idl_field_name_to_rs_name(&attr.field.field.id));

    let parent = quote!(P);

    let (mut attr_type, builder) = field_type_builder(
        &attr.field.field.data_type,
        attr.field.is_nullable,
        false,
        BuilderPolicy::NonCopyAndStrings,
        parent.clone(),
        entities,
        krate,
    );

    if builder {
        if attr.field.field.data_type.is_list {
            let (attr_element_type, _) = field_type_builder(
                &DataType {
                    name: attr.field.field.data_type.name.clone(),
                    is_list: false,
                    max_length: attr.field.field.data_type.max_length,
                },
                false,
                false,
                BuilderPolicy::All,
                parent,
                entities,
                krate,
            );

            attr_type = quote!(#krate::dm::ArrayAttributeRead<#attr_type, #attr_element_type>);
        }

        if !delegate && attr.field.is_optional {
            quote!(
                async fn #attr_name<P: #krate::tlv::TLVBuilderParent>(&self, ctx: impl #krate::dm::ReadContext, builder: #attr_type) -> Result<P, #krate::error::Error> {
                    Err(#krate::error::ErrorCode::InvalidAction.into())
                }
            )
        } else if delegate {
            quote!(
                fn #attr_name<P: #krate::tlv::TLVBuilderParent>(&self, ctx: impl #krate::dm::ReadContext, builder: #attr_type) -> impl core::future::Future<Output = Result<P, #krate::error::Error>> {
                    T::#attr_name(self, ctx, builder)
                }
            )
        } else {
            quote!(async fn #attr_name<P: #krate::tlv::TLVBuilderParent>(&self, ctx: impl #krate::dm::ReadContext, builder: #attr_type) -> Result<P, #krate::error::Error>;)
        }
    } else if !delegate && attr.field.is_optional {
        quote!(
            async fn #attr_name(&self, ctx: impl #krate::dm::ReadContext) -> Result<#attr_type, #krate::error::Error> {
                Err(#krate::error::ErrorCode::InvalidAction.into())
            }
        )
    } else if delegate {
        quote!(
            fn #attr_name(&self, ctx: impl #krate::dm::ReadContext) -> impl core::future::Future<Output = Result<#attr_type, #krate::error::Error>> {
                T::#attr_name(self, ctx)
            }
        )
    } else {
        quote!(async fn #attr_name(&self, ctx: impl #krate::dm::ReadContext) -> Result<#attr_type, #krate::error::Error>;)
    }
}

/// Return a token stream defining the handler trait method for writing the provided IDL attribute.
///
/// # Arguments
/// - `attr`: The IDL attribute for which the handler method is generated.
/// - `delegate`: If true, the generated handler method will have an implementation delegating
///   to a `T` type (for inherent impls)
/// - `cluster`: The IDL cluster for which the handler method is generated.
/// - `krate`: The crate name to use for the generated code.
fn handler_attribute_write(
    attr: &Attribute,
    delegate: bool,
    entities: &EntityContext,
    krate: &Ident,
) -> TokenStream {
    let attr_name = ident(&format!(
        "set_{}",
        &idl_field_name_to_rs_name(&attr.field.field.id)
    ));

    let mut attr_type = field_type(
        &attr.field.field.data_type,
        attr.field.is_nullable,
        false,
        entities,
        krate,
    );

    if attr.field.field.data_type.is_list {
        let attr_element_type = field_type(
            &DataType {
                name: attr.field.field.data_type.name.clone(),
                is_list: false,
                max_length: attr.field.field.data_type.max_length,
            },
            false,
            false,
            entities,
            krate,
        );

        attr_type = quote!(#krate::dm::ArrayAttributeWrite<#attr_type, #attr_element_type>);
    }

    if !delegate && attr.field.is_optional {
        quote!(
            async fn #attr_name(&self, ctx: impl #krate::dm::WriteContext, value: #attr_type) -> Result<(), #krate::error::Error> {
                Err(#krate::error::ErrorCode::InvalidAction.into())
            }
        )
    } else {
        let stream = quote!(
            async fn #attr_name(&self, ctx: impl #krate::dm::WriteContext, value: #attr_type) -> Result<(), #krate::error::Error>
        );

        if delegate {
            quote!(#stream { T::#attr_name(self, ctx, value).await })
        } else {
            quote!(#stream;)
        }
    }
}

/// Return a token stream defining the handler trait method for handling the provided IDL command.
///
/// # Arguments
/// - `cmd`: The IDL command for which the handler method is generated.
/// - `delegate`: If true, the generated handler method will have an implementation delegating
///   to a `T` type (for inherent impls)
/// - `cluster`: The IDL cluster for which the handler method is generated.
/// - `krate`: The crate name to use for the generated code.
fn handler_command(
    cmd: &Command,
    delegate: bool,
    entities: &EntityContext,
    krate: &Ident,
) -> TokenStream {
    let cmd_name = ident(&format!("handle_{}", &idl_field_name_to_rs_name(&cmd.id)));

    let field_req = cmd.input.as_ref().map(|id| {
        field_type(
            &DataType {
                name: id.clone(),
                is_list: false,
                max_length: None,
            },
            false,
            false,
            entities,
            krate,
        )
    });

    let cmd_output = (cmd.output != NO_RESPONSE).then(|| cmd.output.clone());

    let field_resp = cmd_output.map(|output| {
        field_type_builder(
            &DataType {
                name: output.clone(),
                is_list: false,
                max_length: None,
            },
            false,
            false,
            BuilderPolicy::NonCopyAndStrings,
            quote!(P),
            entities,
            krate,
        )
    });

    if let Some(field_req) = field_req {
        if let Some((field_resp, field_resp_builder)) = field_resp {
            if field_resp_builder {
                let stream = quote!(
                    async fn #cmd_name<P: #krate::tlv::TLVBuilderParent>(
                        &self,
                        ctx: impl #krate::dm::InvokeContext,
                        request: #field_req,
                        response: #field_resp,
                    ) -> Result<P, #krate::error::Error>
                );

                if delegate {
                    quote!(#stream { T::#cmd_name(self, ctx, request, response).await })
                } else {
                    quote!(#stream;)
                }
            } else {
                let stream = quote!(
                    async fn #cmd_name(
                        &self,
                        ctx: impl #krate::dm::InvokeContext,
                        request: #field_req,
                    ) -> Result<#field_resp, #krate::error::Error>
                );

                if delegate {
                    quote!(#stream { T::#cmd_name(self, ctx, request).await })
                } else {
                    quote!(#stream;)
                }
            }
        } else {
            let stream = quote!(
                async fn #cmd_name(
                    &self,
                    ctx: impl #krate::dm::InvokeContext,
                    request: #field_req,
                ) -> Result<(), #krate::error::Error>
            );

            if delegate {
                quote!(#stream { T::#cmd_name(self, ctx, request).await })
            } else {
                quote!(#stream;)
            }
        }
    } else if let Some((field_resp, field_resp_builder)) = field_resp {
        if field_resp_builder {
            let stream = quote!(
                async fn #cmd_name<P: #krate::tlv::TLVBuilderParent>(
                    &self,
                    ctx: impl #krate::dm::InvokeContext,
                    response: #field_resp,
                ) -> Result<P, #krate::error::Error>
            );

            if delegate {
                quote!(#stream { T::#cmd_name(self, ctx, response).await })
            } else {
                quote!(#stream;)
            }
        } else {
            let stream = quote!(
                async fn #cmd_name(
                    &self,
                    ctx: impl #krate::dm::InvokeContext,
                ) -> Result<#field_resp, #krate::error::Error>
            );

            if delegate {
                quote!(#stream { T::#cmd_name(self, ctx).await })
            } else {
                quote!(#stream;)
            }
        }
    } else {
        let stream = quote!(
            async fn #cmd_name(
                &self,
                ctx: impl #krate::dm::InvokeContext,
            ) -> Result<(), #krate::error::Error>
        );

        if delegate {
            quote!(#stream { T::#cmd_name(self, ctx).await })
        } else {
            quote!(#stream;)
        }
    }
}

/// Return a token stream defining a mach clause, `AttributeId::Foo => handler.foo(...)`
/// that is used by the adaptor to handle reading from the provided IDL attribute.
///
/// # Arguments
/// - `attr`: The IDL attribute for which the match clause is generated.
/// - `cluster`: The IDL cluster for which the match clause is generated.
/// - `krate`: The crate name to use for the generated code.
fn handler_adaptor_attribute_match(
    attr: &Attribute,
    entities: &EntityContext,
    krate: &Ident,
) -> TokenStream {
    let attr_name = ident(&idl_attribute_name_to_enum_variant_name(
        &attr.field.field.id,
    ));
    let attr_debug_id = quote!(MetadataDebug((ctx.attr().endpoint_id, self, MetadataDebug((AttributeId::#attr_name, false)))));

    let attr_method_name = ident(&idl_field_name_to_rs_name(&attr.field.field.id));

    let parent = quote!(P);

    let (_, builder) = field_type_builder(
        &attr.field.field.data_type,
        attr.field.is_nullable,
        attr.field.is_optional,
        BuilderPolicy::NonCopyAndStrings,
        parent,
        entities,
        krate,
    );

    let attr_read_debug_build_start = quote!(
        #[cfg(feature = "defmt")]
        #krate::reexport::defmt::debug!("{:?} -> (build) +", #attr_debug_id);
        #[cfg(feature = "log")]
        #krate::reexport::log::debug!("{:?} -> (build) +", #attr_debug_id);
    );

    let attr_read_debug_build_end = quote!(
        #[cfg(feature = "defmt")]
        #krate::reexport::defmt::debug!("{:?} -> {:?}", #attr_debug_id, attr_read_result.as_ref().map(|_| ()));
        #[cfg(feature = "log")]
        #krate::reexport::log::debug!("{:?} (end) -> {:?}", #attr_debug_id, attr_read_result.as_ref().map(|_| ()));
    );

    let attr_read_debug = quote!(
        #[cfg(feature = "defmt")]
        #krate::reexport::defmt::debug!("{:?} -> {:?}", #attr_debug_id, attr_read_result);
        #[cfg(feature = "log")]
        #krate::reexport::log::debug!("{:?} -> {:?}", #attr_debug_id, attr_read_result);
    );

    if builder {
        if attr.field.field.data_type.is_list {
            quote!(
                AttributeId::#attr_name => {
                    #attr_read_debug_build_start

                    let tag = #krate::dm::Reply::tag(&writer);
                    let tw = #krate::dm::Reply::writer(&mut writer);

                    let attr_read_result = self.0.#attr_method_name(
                        &ctx,
                        #krate::dm::ArrayAttributeRead::new(
                            ctx.attr().list_index.clone(),
                            #krate::tlv::TLVWriteParent::new(#attr_debug_id, tw),
                            tag,
                        )?,
                    ).await;

                    #attr_read_debug_build_end

                    attr_read_result?;

                    #krate::dm::Reply::complete(writer)
                }
            )
        } else {
            quote!(
                AttributeId::#attr_name => {
                    #attr_read_debug_build_start

                    let tag = #krate::dm::Reply::tag(&writer);
                    let tw = #krate::dm::Reply::writer(&mut writer);

                    let attr_read_result = self.0.#attr_method_name(&ctx, #krate::tlv::TLVBuilder::new(
                        #krate::tlv::TLVWriteParent::new(#attr_debug_id, tw),
                        tag,
                    )?).await;

                    #attr_read_debug_build_end

                    attr_read_result?;

                    #krate::dm::Reply::complete(writer)
                }
            )
        }
    } else {
        quote!(
            AttributeId::#attr_name => {
                let attr_read_result = self.0.#attr_method_name(&ctx).await;

                #attr_read_debug

                #krate::dm::Reply::set(writer, attr_read_result?)
            }
        )
    }
}

/// Return a token stream defining a mach clause, `AttributeId::Foo => handler.foo(...)`
/// that is used by the adaptor to handle writing to the provided IDL attribute.
///
/// # Arguments
/// - `attr`: The IDL attribute for which the match clause is generated.
/// - `krate`: The crate name to use for the generated code.
fn handler_adaptor_attribute_write_match(
    attr: &Attribute,
    entities: &EntityContext,
    krate: &Ident,
) -> TokenStream {
    let attr_name = ident(&idl_attribute_name_to_enum_variant_name(
        &attr.field.field.id,
    ));
    let attr_debug_id = quote!(MetadataDebug((ctx.attr().endpoint_id, self, MetadataDebug((AttributeId::#attr_name, false)))));

    let attr_method_name = ident(&format!(
        "set_{}",
        &idl_field_name_to_rs_name(&attr.field.field.id)
    ));

    let attr_type = field_type(
        &attr.field.field.data_type,
        attr.field.is_nullable,
        false,
        entities,
        krate,
    );

    let attr_write_debug = quote!(
        #[cfg(feature = "defmt")]
        #krate::reexport::defmt::debug!("{:?}({:?}) -> {:?}", #attr_debug_id, attr_data, attr_write_result);
        #[cfg(feature = "log")]
        #krate::reexport::log::debug!("{:?}({:?}) -> {:?}", #attr_debug_id, attr_data, attr_write_result);
    );

    if attr.field.field.data_type.is_list {
        quote!(
            AttributeId::#attr_name => {
                let attr_data = #krate::dm::ArrayAttributeWrite::new(ctx.attr().list_index.clone(), ctx.data())?;

                let attr_write_result = self.0.#attr_method_name(&ctx, attr_data.clone()).await;

                #attr_write_debug

                attr_write_result?;
            }
        )
    } else {
        quote!(
            AttributeId::#attr_name => {
                let attr_data: #attr_type = #krate::tlv::FromTLV::from_tlv(ctx.data())?;

                let attr_write_result = self.0.#attr_method_name(&ctx, attr_data.clone()).await;

                #attr_write_debug

                attr_write_result?;
            }
        )
    }
}

/// Return a token stream defining a mach clause, `CommandId::Foo => handler.foo(...)`
/// that is used by the adaptor to handle invoking the provided IDL command.
///
/// # Arguments
/// - `cmd`: The IDL command for which the match clause is generated.
/// - `cluster`: The IDL cluster for which the match clause is generated.
/// - `krate`: The crate name to use for the generated code.
fn handler_adaptor_command_match(
    cmd: &Command,
    entities: &EntityContext,
    krate: &Ident,
) -> TokenStream {
    let cmd_name = ident(&idl_attribute_name_to_enum_variant_name(&cmd.id));
    let cmd_debug_id =
        quote!(MetadataDebug((ctx.cmd().endpoint_id, self, MetadataDebug(CommandId::#cmd_name))));

    let cmd_method_name = ident(&format!("handle_{}", &idl_field_name_to_rs_name(&cmd.id)));

    let cmd_invoke_debug_build_start = quote!(
        #[cfg(feature = "defmt")]
        #krate::reexport::defmt::debug!("{:?}({:?}) -> (build) +", #cmd_debug_id, cmd_data);
        #[cfg(feature = "log")]
        #krate::reexport::log::debug!("{:?}({:?}) -> (build) +", #cmd_debug_id, cmd_data);
    );

    let cmd_invoke_debug_noarg_build_start = quote!(
        #[cfg(feature = "defmt")]
        #krate::reexport::defmt::debug!("{:?} -> (build) +", #cmd_debug_id);
        #[cfg(feature = "log")]
        #krate::reexport::log::debug!("{:?} -> (build) +", #cmd_debug_id);
    );

    let cmd_invoke_debug_build_end = quote!(
        #[cfg(feature = "defmt")]
        #krate::reexport::defmt::debug!("{:?} (end) -> {:?}", #cmd_debug_id, cmd_invoke_result.as_ref().map(|_| ()));
        #[cfg(feature = "log")]
        #krate::reexport::log::debug!("{:?} (end) -> {:?}", #cmd_debug_id, cmd_invoke_result.as_ref().map(|_| ()));
    );

    let cmd_invoke_debug = quote!(
        #[cfg(feature = "defmt")]
        #krate::reexport::defmt::debug!("{:?}({:?}) -> {:?}", #cmd_debug_id, cmd_data, cmd_invoke_result);
        #[cfg(feature = "log")]
        #krate::reexport::log::debug!("{:?}({:?}) -> {:?}", #cmd_debug_id, cmd_data, cmd_invoke_result);
    );

    let cmd_invoke_debug_noarg = quote!(
        #[cfg(feature = "defmt")]
        #krate::reexport::defmt::debug!("{:?} -> {:?}", #cmd_debug_id, cmd_invoke_result);
        #[cfg(feature = "log")]
        #krate::reexport::log::debug!("{:?} -> {:?}", #cmd_debug_id, cmd_invoke_result);
    );

    let field_req = cmd.input.as_ref().map(|id| {
        field_type(
            &DataType {
                name: id.clone(),
                is_list: false,
                max_length: None,
            },
            false,
            false,
            entities,
            krate,
        )
    });

    let cmd_output = (cmd.output != NO_RESPONSE)
        .then(|| {
            entities
                .structs()
                .filter(|s| s.id == cmd.output)
                .filter_map(|s| {
                    if let StructType::Response(code) = s.struct_type {
                        Some(code)
                    } else {
                        None
                    }
                })
                .next()
                .map(|code| (cmd.output.clone(), code))
        })
        .flatten();

    let field_resp = cmd_output.map(|(output, code)| {
        let (_, builder) = field_type_builder(
            &DataType {
                name: output.clone(),
                is_list: false,
                max_length: None,
            },
            false,
            false,
            BuilderPolicy::NonCopyAndStrings,
            quote!(P),
            entities,
            krate,
        );

        (code as u32, builder)
    });

    if field_req.is_some() {
        if let Some((field_resp_cmd_code, field_resp_builder)) = field_resp {
            if field_resp_builder {
                quote!(
                    CommandId::#cmd_name => {
                        let cmd_data = #krate::tlv::FromTLV::from_tlv(ctx.data())?;

                        #cmd_invoke_debug_build_start

                        let mut writer = reply.with_command(#field_resp_cmd_code)?;
                        let tag = #krate::dm::Reply::tag(&writer);
                        let tw = #krate::dm::Reply::writer(&mut writer);

                        let cmd_invoke_result = self.0.#cmd_method_name(
                            &ctx,
                            cmd_data,
                            #krate::tlv::TLVBuilder::new(
                                #krate::tlv::TLVWriteParent::new(#cmd_debug_id, tw),
                                tag,
                            )?
                        ).await;

                        #cmd_invoke_debug_build_end

                        cmd_invoke_result?;

                        #krate::dm::Reply::complete(writer)?
                    }
                )
            } else {
                quote!(
                    CommandId::#cmd_name => {
                        let cmd_data: #field_req = #krate::tlv::FromTLV::from_tlv(ctx.data())?;

                        let writer = reply.with_command(#field_resp_cmd_code)?;

                        let cmd_invoke_result = self.0.#cmd_method_name(&ctx, cmd_data.clone()).await;

                        #cmd_invoke_debug

                        #krate::dm::Reply::set(writer, cmd_invoke_result?)?;
                    }
                )
            }
        } else {
            quote!(
                CommandId::#cmd_name => {
                    let cmd_data: #field_req = #krate::tlv::FromTLV::from_tlv(ctx.data())?;

                    let cmd_invoke_result = self.0.#cmd_method_name(&ctx, cmd_data.clone()).await;

                    #cmd_invoke_debug

                    cmd_invoke_result?;
                }
            )
        }
    } else if let Some((field_resp_cmd_code, field_resp_builder)) = field_resp {
        if field_resp_builder {
            quote!(
                CommandId::#cmd_name => {
                    #cmd_invoke_debug_noarg_build_start

                    let mut writer = reply.with_command(#field_resp_cmd_code)?;
                    let tag = #krate::dm::Reply::tag(&writer);
                    let tw = #krate::dm::Reply::writer(&mut writer);

                    let cmd_invoke_result = self.0.#cmd_method_name(
                        &ctx,
                        #krate::tlv::TLVBuilder::new(
                            #krate::tlv::TLVWriteParent::new(#cmd_debug_id, tw),
                            tag,
                        )?,
                    ).await;

                    #cmd_invoke_debug_build_end

                    cmd_invoke_result?;

                    #krate::dm::Reply::complete(writer)?
                }
            )
        } else {
            quote!(quote!(
                CommandId::#cmd_name => {
                    let writer = reply.with_command(#field_resp_cmd_code)?;

                    let cmd_invoke_result = self.0.#cmd_method_name(&ctx).await;

                    #cmd_invoke_debug_noarg

                    #krate::dm::Reply::set(writer, cmd_invoke_result?)?;
                }
            ))
        }
    } else {
        quote!(
            CommandId::#cmd_name => {
                let cmd_invoke_result = self.0.#cmd_method_name(&ctx).await;

                #cmd_invoke_debug_noarg

                cmd_invoke_result?;
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use assert_tokenstreams_eq::assert_tokenstreams_eq;
    use quote::quote;

    use crate::idl::tests::{get_cluster_named, parse_idl};
    use crate::idl::IdlGenerateContext;

    use super::{handler, handler_adaptor};

    const IDL: &str =
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
    ";

    #[test]
    fn test_handler() {
        let idl = parse_idl(IDL);

        let cluster = get_cluster_named(&idl, "OnOff").expect("Cluster exists");
        let context = IdlGenerateContext::new("rs_matter_crate");

        // panic!("====\n{}\n====", &handler(false, false, cluster, &context));

        assert_tokenstreams_eq!(
            &handler(false, cluster, &idl.globals, &context),
            &quote!(
                #[doc = "The handler trait for the cluster."]
                pub trait ClusterHandler {
                    #[doc = "The cluster-metadata corresponding to this handler trait."]
                    const CLUSTER: rs_matter_crate::dm::Cluster<'static>;
                    fn dataver(&self) -> u32;
                    fn dataver_changed(&self);
                    fn run(
                        &self,
                        _ctx: impl rs_matter_crate::dm::HandlerContext,
                    ) -> impl core::future::Future<Output = Result<(), rs_matter_crate::error::Error>>
                    {
                        core::future::pending::<Result<(), rs_matter_crate::error::Error>>()
                    }
                    async fn on_off(
                        &self,
                        ctx: impl rs_matter_crate::dm::ReadContext,
                    ) -> Result<bool, rs_matter_crate::error::Error>;
                    async fn global_scene_control(
                        &self,
                        ctx: impl rs_matter_crate::dm::ReadContext,
                    ) -> Result<bool, rs_matter_crate::error::Error> {
                        Err(rs_matter_crate::error::ErrorCode::InvalidAction.into())
                    }
                    async fn on_time(
                        &self,
                        ctx: impl rs_matter_crate::dm::ReadContext,
                    ) -> Result<u16, rs_matter_crate::error::Error> {
                        Err(rs_matter_crate::error::ErrorCode::InvalidAction.into())
                    }
                    async fn off_wait_time(
                        &self,
                        ctx: impl rs_matter_crate::dm::ReadContext,
                    ) -> Result<u16, rs_matter_crate::error::Error> {
                        Err(rs_matter_crate::error::ErrorCode::InvalidAction.into())
                    }
                    async fn start_up_on_off(
                        &self,
                        ctx: impl rs_matter_crate::dm::ReadContext,
                    ) -> Result<
                        rs_matter_crate::tlv::Nullable<StartUpOnOffEnum>,
                        rs_matter_crate::error::Error,
                    > {
                        Err(rs_matter_crate::error::ErrorCode::InvalidAction.into())
                    }
                    async fn set_on_time(
                        &self,
                        ctx: impl rs_matter_crate::dm::WriteContext,
                        value: u16,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        Err(rs_matter_crate::error::ErrorCode::InvalidAction.into())
                    }
                    async fn set_off_wait_time(
                        &self,
                        ctx: impl rs_matter_crate::dm::WriteContext,
                        value: u16,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        Err(rs_matter_crate::error::ErrorCode::InvalidAction.into())
                    }
                    async fn set_start_up_on_off(
                        &self,
                        ctx: impl rs_matter_crate::dm::WriteContext,
                        value: rs_matter_crate::tlv::Nullable<StartUpOnOffEnum>,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        Err(rs_matter_crate::error::ErrorCode::InvalidAction.into())
                    }
                    async fn handle_off(
                        &self,
                        ctx: impl rs_matter_crate::dm::InvokeContext,
                    ) -> Result<(), rs_matter_crate::error::Error>;
                    async fn handle_on(
                        &self,
                        ctx: impl rs_matter_crate::dm::InvokeContext,
                    ) -> Result<(), rs_matter_crate::error::Error>;
                    async fn handle_toggle(
                        &self,
                        ctx: impl rs_matter_crate::dm::InvokeContext,
                    ) -> Result<(), rs_matter_crate::error::Error>;
                    async fn handle_off_with_effect(
                        &self,
                        ctx: impl rs_matter_crate::dm::InvokeContext,
                        request: OffWithEffectRequest<'_>,
                    ) -> Result<(), rs_matter_crate::error::Error>;
                    async fn handle_on_with_recall_global_scene(
                        &self,
                        ctx: impl rs_matter_crate::dm::InvokeContext,
                    ) -> Result<(), rs_matter_crate::error::Error>;
                    async fn handle_on_with_timed_off(
                        &self,
                        ctx: impl rs_matter_crate::dm::InvokeContext,
                        request: OnWithTimedOffRequest<'_>,
                    ) -> Result<(), rs_matter_crate::error::Error>;
                }
            )
        );

        // panic!("====\n{}\n====", &handler(true, cluster, &idl.globals, &context));

        assert_tokenstreams_eq!(
            &handler(true, cluster, &idl.globals, &context),
            &quote!(
                impl<T> ClusterHandler for &T
                where
                    T: ClusterHandler,
                {
                    const CLUSTER: rs_matter_crate::dm::Cluster<'static> = T::CLUSTER;
                    fn dataver(&self) -> u32 {
                        T::dataver(self)
                    }
                    fn dataver_changed(&self) {
                        T::dataver_changed(self)
                    }
                    fn run(
                        &self,
                        ctx: impl rs_matter_crate::dm::HandlerContext,
                    ) -> impl core::future::Future<Output = Result<(), rs_matter_crate::error::Error>>
                    {
                        (**self).run(ctx)
                    }
                    fn on_off(
                        &self,
                        ctx: impl rs_matter_crate::dm::ReadContext,
                    ) -> impl core::future::Future<Output = Result<bool, rs_matter_crate::error::Error>>
                    {
                        T::on_off(self, ctx)
                    }
                    fn global_scene_control(
                        &self,
                        ctx: impl rs_matter_crate::dm::ReadContext,
                    ) -> impl core::future::Future<Output = Result<bool, rs_matter_crate::error::Error>>
                    {
                        T::global_scene_control(self, ctx)
                    }
                    fn on_time(
                        &self,
                        ctx: impl rs_matter_crate::dm::ReadContext,
                    ) -> impl core::future::Future<Output = Result<u16, rs_matter_crate::error::Error>>
                    {
                        T::on_time(self, ctx)
                    }
                    fn off_wait_time(
                        &self,
                        ctx: impl rs_matter_crate::dm::ReadContext,
                    ) -> impl core::future::Future<Output = Result<u16, rs_matter_crate::error::Error>>
                    {
                        T::off_wait_time(self, ctx)
                    }
                    fn start_up_on_off(
                        &self,
                        ctx: impl rs_matter_crate::dm::ReadContext,
                    ) -> impl core::future::Future<
                        Output = Result<
                            rs_matter_crate::tlv::Nullable<StartUpOnOffEnum>,
                            rs_matter_crate::error::Error,
                        >,
                    > {
                        T::start_up_on_off(self, ctx)
                    }
                    async fn set_on_time(
                        &self,
                        ctx: impl rs_matter_crate::dm::WriteContext,
                        value: u16,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        T::set_on_time(self, ctx, value).await
                    }
                    async fn set_off_wait_time(
                        &self,
                        ctx: impl rs_matter_crate::dm::WriteContext,
                        value: u16,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        T::set_off_wait_time(self, ctx, value).await
                    }
                    async fn set_start_up_on_off(
                        &self,
                        ctx: impl rs_matter_crate::dm::WriteContext,
                        value: rs_matter_crate::tlv::Nullable<StartUpOnOffEnum>,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        T::set_start_up_on_off(self, ctx, value).await
                    }
                    async fn handle_off(
                        &self,
                        ctx: impl rs_matter_crate::dm::InvokeContext,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        T::handle_off(self, ctx).await
                    }
                    async fn handle_on(
                        &self,
                        ctx: impl rs_matter_crate::dm::InvokeContext,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        T::handle_on(self, ctx).await
                    }
                    async fn handle_toggle(
                        &self,
                        ctx: impl rs_matter_crate::dm::InvokeContext,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        T::handle_toggle(self, ctx).await
                    }
                    async fn handle_off_with_effect(
                        &self,
                        ctx: impl rs_matter_crate::dm::InvokeContext,
                        request: OffWithEffectRequest<'_>,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        T::handle_off_with_effect(self, ctx, request).await
                    }
                    async fn handle_on_with_recall_global_scene(
                        &self,
                        ctx: impl rs_matter_crate::dm::InvokeContext,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        T::handle_on_with_recall_global_scene(self, ctx).await
                    }
                    async fn handle_on_with_timed_off(
                        &self,
                        ctx: impl rs_matter_crate::dm::InvokeContext,
                        request: OnWithTimedOffRequest<'_>,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        T::handle_on_with_timed_off(self, ctx, request).await
                    }
                }
            )
        );
    }

    #[test]
    fn test_handler_adaptor() {
        let idl = parse_idl(IDL);

        let cluster = get_cluster_named(&idl, "OnOff").expect("Cluster exists");
        let context = IdlGenerateContext::new("rs_matter_crate");

        // panic!("====\n{}\n====", &handler_adaptor( cluster,  &idl.globals, &context));

        assert_tokenstreams_eq!(
            &handler_adaptor(cluster, &idl.globals, &context),
            &quote!(
                #[doc = "The handler adaptor for the cluster-specific handler. This adaptor implements the generic `rs-matter` handler trait."]
                #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
                #[cfg_attr(feature = "defmt", derive(rs_matter_crate::reexport::defmt::Format))]
                pub struct HandlerAdaptor<T>(pub T);
                impl<T> rs_matter_crate::dm::AsyncHandler for HandlerAdaptor<T>
                where
                    T: ClusterHandler,
                {
                    #[allow(unreachable_code)]
                    async fn read(
                        &self,
                        ctx: impl rs_matter_crate::dm::ReadContext,
                        reply: impl rs_matter_crate::dm::ReadReply,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        if let Some(mut writer) = reply.with_dataver(self.0.dataver())? {
                            if ctx.attr().is_system() {
                                ctx.attr().cluster()?.read(ctx.attr(), writer)
                            } else {
                                match AttributeId::try_from(ctx.attr().attr_id)? {
                                    AttributeId::OnOff => {
                                        let attr_read_result = self.0.on_off(&ctx).await;
                                        #[cfg(feature = "defmt")]
                                        rs_matter_crate::reexport::defmt::debug!(
                                            "{:?} -> {:?}",
                                            MetadataDebug((
                                                ctx.attr().endpoint_id,
                                                self,
                                                MetadataDebug((AttributeId::OnOff, false))
                                            )),
                                            attr_read_result
                                        );
                                        #[cfg(feature = "log")]
                                        rs_matter_crate::reexport::log::debug!(
                                            "{:?} -> {:?}",
                                            MetadataDebug((
                                                ctx.attr().endpoint_id,
                                                self,
                                                MetadataDebug((AttributeId::OnOff, false))
                                            )),
                                            attr_read_result
                                        );
                                        rs_matter_crate::dm::Reply::set(writer, attr_read_result?)
                                    }
                                    AttributeId::GlobalSceneControl => {
                                        let attr_read_result =
                                            self.0.global_scene_control(&ctx).await;
                                        #[cfg(feature = "defmt")]
                                        rs_matter_crate::reexport::defmt::debug!(
                                            "{:?} -> {:?}",
                                            MetadataDebug((
                                                ctx.attr().endpoint_id,
                                                self,
                                                MetadataDebug((
                                                    AttributeId::GlobalSceneControl,
                                                    false
                                                ))
                                            )),
                                            attr_read_result
                                        );
                                        #[cfg(feature = "log")]
                                        rs_matter_crate::reexport::log::debug!(
                                            "{:?} -> {:?}",
                                            MetadataDebug((
                                                ctx.attr().endpoint_id,
                                                self,
                                                MetadataDebug((
                                                    AttributeId::GlobalSceneControl,
                                                    false
                                                ))
                                            )),
                                            attr_read_result
                                        );
                                        rs_matter_crate::dm::Reply::set(writer, attr_read_result?)
                                    }
                                    AttributeId::OnTime => {
                                        let attr_read_result = self.0.on_time(&ctx).await;
                                        #[cfg(feature = "defmt")]
                                        rs_matter_crate::reexport::defmt::debug!(
                                            "{:?} -> {:?}",
                                            MetadataDebug((
                                                ctx.attr().endpoint_id,
                                                self,
                                                MetadataDebug((AttributeId::OnTime, false))
                                            )),
                                            attr_read_result
                                        );
                                        #[cfg(feature = "log")]
                                        rs_matter_crate::reexport::log::debug!(
                                            "{:?} -> {:?}",
                                            MetadataDebug((
                                                ctx.attr().endpoint_id,
                                                self,
                                                MetadataDebug((AttributeId::OnTime, false))
                                            )),
                                            attr_read_result
                                        );
                                        rs_matter_crate::dm::Reply::set(writer, attr_read_result?)
                                    }
                                    AttributeId::OffWaitTime => {
                                        let attr_read_result = self.0.off_wait_time(&ctx).await;
                                        #[cfg(feature = "defmt")]
                                        rs_matter_crate::reexport::defmt::debug!(
                                            "{:?} -> {:?}",
                                            MetadataDebug((
                                                ctx.attr().endpoint_id,
                                                self,
                                                MetadataDebug((AttributeId::OffWaitTime, false))
                                            )),
                                            attr_read_result
                                        );
                                        #[cfg(feature = "log")]
                                        rs_matter_crate::reexport::log::debug!(
                                            "{:?} -> {:?}",
                                            MetadataDebug((
                                                ctx.attr().endpoint_id,
                                                self,
                                                MetadataDebug((AttributeId::OffWaitTime, false))
                                            )),
                                            attr_read_result
                                        );
                                        rs_matter_crate::dm::Reply::set(writer, attr_read_result?)
                                    }
                                    AttributeId::StartUpOnOff => {
                                        let attr_read_result = self.0.start_up_on_off(&ctx).await;
                                        #[cfg(feature = "defmt")]
                                        rs_matter_crate::reexport::defmt::debug!(
                                            "{:?} -> {:?}",
                                            MetadataDebug((
                                                ctx.attr().endpoint_id,
                                                self,
                                                MetadataDebug((AttributeId::StartUpOnOff, false))
                                            )),
                                            attr_read_result
                                        );
                                        #[cfg(feature = "log")]
                                        rs_matter_crate::reexport::log::debug!(
                                            "{:?} -> {:?}",
                                            MetadataDebug((
                                                ctx.attr().endpoint_id,
                                                self,
                                                MetadataDebug((AttributeId::StartUpOnOff, false))
                                            )),
                                            attr_read_result
                                        );
                                        rs_matter_crate::dm::Reply::set(writer, attr_read_result?)
                                    }
                                    #[allow(unreachable_code)]
                                    other => {
                                        #[cfg(feature = "defmt")]
                                        rs_matter_crate::reexport::defmt::error!(
                                            "Attribute {:?} not supported",
                                            other
                                        );
                                        #[cfg(feature = "log")]
                                        rs_matter_crate::reexport::log::error!(
                                            "Attribute {:?} not supported",
                                            other
                                        );
                                        Err(rs_matter_crate::error::ErrorCode::AttributeNotFound
                                            .into())
                                    }
                                }
                            }
                        } else {
                            Ok(())
                        }
                    }
                    #[allow(unreachable_code)]
                    async fn write(
                        &self,
                        ctx: impl rs_matter_crate::dm::WriteContext,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        ctx.attr().check_dataver(self.0.dataver())?;
                        if ctx.attr().is_system() {
                            return Err(rs_matter_crate::error::ErrorCode::InvalidAction.into());
                        }
                        match AttributeId::try_from(ctx.attr().attr_id)? {
                            AttributeId::OnTime => {
                                let attr_data: u16 =
                                    rs_matter_crate::tlv::FromTLV::from_tlv(ctx.data())?;
                                let attr_write_result =
                                    self.0.set_on_time(&ctx, attr_data.clone()).await;
                                #[cfg(feature = "defmt")]
                                rs_matter_crate::reexport::defmt::debug!(
                                    "{:?}({:?}) -> {:?}",
                                    MetadataDebug((
                                        ctx.attr().endpoint_id,
                                        self,
                                        MetadataDebug((AttributeId::OnTime, false))
                                    )),
                                    attr_data,
                                    attr_write_result
                                );
                                #[cfg(feature = "log")]
                                rs_matter_crate::reexport::log::debug!(
                                    "{:?}({:?}) -> {:?}",
                                    MetadataDebug((
                                        ctx.attr().endpoint_id,
                                        self,
                                        MetadataDebug((AttributeId::OnTime, false))
                                    )),
                                    attr_data,
                                    attr_write_result
                                );
                                attr_write_result?;
                            }
                            AttributeId::OffWaitTime => {
                                let attr_data: u16 =
                                    rs_matter_crate::tlv::FromTLV::from_tlv(ctx.data())?;
                                let attr_write_result =
                                    self.0.set_off_wait_time(&ctx, attr_data.clone()).await;
                                #[cfg(feature = "defmt")]
                                rs_matter_crate::reexport::defmt::debug!(
                                    "{:?}({:?}) -> {:?}",
                                    MetadataDebug((
                                        ctx.attr().endpoint_id,
                                        self,
                                        MetadataDebug((AttributeId::OffWaitTime, false))
                                    )),
                                    attr_data,
                                    attr_write_result
                                );
                                #[cfg(feature = "log")]
                                rs_matter_crate::reexport::log::debug!(
                                    "{:?}({:?}) -> {:?}",
                                    MetadataDebug((
                                        ctx.attr().endpoint_id,
                                        self,
                                        MetadataDebug((AttributeId::OffWaitTime, false))
                                    )),
                                    attr_data,
                                    attr_write_result
                                );
                                attr_write_result?;
                            }
                            AttributeId::StartUpOnOff => {
                                let attr_data: rs_matter_crate::tlv::Nullable<StartUpOnOffEnum> =
                                    rs_matter_crate::tlv::FromTLV::from_tlv(ctx.data())?;
                                let attr_write_result =
                                    self.0.set_start_up_on_off(&ctx, attr_data.clone()).await;
                                #[cfg(feature = "defmt")]
                                rs_matter_crate::reexport::defmt::debug!(
                                    "{:?}({:?}) -> {:?}",
                                    MetadataDebug((
                                        ctx.attr().endpoint_id,
                                        self,
                                        MetadataDebug((AttributeId::StartUpOnOff, false))
                                    )),
                                    attr_data,
                                    attr_write_result
                                );
                                #[cfg(feature = "log")]
                                rs_matter_crate::reexport::log::debug!(
                                    "{:?}({:?}) -> {:?}",
                                    MetadataDebug((
                                        ctx.attr().endpoint_id,
                                        self,
                                        MetadataDebug((AttributeId::StartUpOnOff, false))
                                    )),
                                    attr_data,
                                    attr_write_result
                                );
                                attr_write_result?;
                            }
                            other => {
                                #[cfg(feature = "defmt")]
                                rs_matter_crate::reexport::defmt::error!(
                                    "Attribute {:?} not supported",
                                    other
                                );
                                #[cfg(feature = "log")]
                                rs_matter_crate::reexport::log::error!(
                                    "Attribute {:?} not supported",
                                    other
                                );
                                return Err(
                                    rs_matter_crate::error::ErrorCode::AttributeNotFound.into()
                                );
                            }
                        }
                        self.0.dataver_changed();
                        Ok(())
                    }
                    #[allow(unreachable_code)]
                    async fn invoke(
                        &self,
                        ctx: impl rs_matter_crate::dm::InvokeContext,
                        reply: impl rs_matter_crate::dm::InvokeReply,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        match CommandId::try_from(ctx.cmd().cmd_id)? {
                            CommandId::Off => {
                                let cmd_invoke_result = self.0.handle_off(&ctx).await;
                                #[cfg(feature = "defmt")]
                                rs_matter_crate::reexport::defmt::debug!(
                                    "{:?} -> {:?}",
                                    MetadataDebug((
                                        ctx.cmd().endpoint_id,
                                        self,
                                        MetadataDebug(CommandId::Off)
                                    )),
                                    cmd_invoke_result
                                );
                                #[cfg(feature = "log")]
                                rs_matter_crate::reexport::log::debug!(
                                    "{:?} -> {:?}",
                                    MetadataDebug((
                                        ctx.cmd().endpoint_id,
                                        self,
                                        MetadataDebug(CommandId::Off)
                                    )),
                                    cmd_invoke_result
                                );
                                cmd_invoke_result?;
                            }
                            CommandId::On => {
                                let cmd_invoke_result = self.0.handle_on(&ctx).await;
                                #[cfg(feature = "defmt")]
                                rs_matter_crate::reexport::defmt::debug!(
                                    "{:?} -> {:?}",
                                    MetadataDebug((
                                        ctx.cmd().endpoint_id,
                                        self,
                                        MetadataDebug(CommandId::On)
                                    )),
                                    cmd_invoke_result
                                );
                                #[cfg(feature = "log")]
                                rs_matter_crate::reexport::log::debug!(
                                    "{:?} -> {:?}",
                                    MetadataDebug((
                                        ctx.cmd().endpoint_id,
                                        self,
                                        MetadataDebug(CommandId::On)
                                    )),
                                    cmd_invoke_result
                                );
                                cmd_invoke_result?;
                            }
                            CommandId::Toggle => {
                                let cmd_invoke_result = self.0.handle_toggle(&ctx).await;
                                #[cfg(feature = "defmt")]
                                rs_matter_crate::reexport::defmt::debug!(
                                    "{:?} -> {:?}",
                                    MetadataDebug((
                                        ctx.cmd().endpoint_id,
                                        self,
                                        MetadataDebug(CommandId::Toggle)
                                    )),
                                    cmd_invoke_result
                                );
                                #[cfg(feature = "log")]
                                rs_matter_crate::reexport::log::debug!(
                                    "{:?} -> {:?}",
                                    MetadataDebug((
                                        ctx.cmd().endpoint_id,
                                        self,
                                        MetadataDebug(CommandId::Toggle)
                                    )),
                                    cmd_invoke_result
                                );
                                cmd_invoke_result?;
                            }
                            CommandId::OffWithEffect => {
                                let cmd_data: OffWithEffectRequest<'_> =
                                    rs_matter_crate::tlv::FromTLV::from_tlv(ctx.data())?;
                                let cmd_invoke_result =
                                    self.0.handle_off_with_effect(&ctx, cmd_data.clone()).await;
                                #[cfg(feature = "defmt")]
                                rs_matter_crate::reexport::defmt::debug!(
                                    "{:?}({:?}) -> {:?}",
                                    MetadataDebug((
                                        ctx.cmd().endpoint_id,
                                        self,
                                        MetadataDebug(CommandId::OffWithEffect)
                                    )),
                                    cmd_data,
                                    cmd_invoke_result
                                );
                                #[cfg(feature = "log")]
                                rs_matter_crate::reexport::log::debug!(
                                    "{:?}({:?}) -> {:?}",
                                    MetadataDebug((
                                        ctx.cmd().endpoint_id,
                                        self,
                                        MetadataDebug(CommandId::OffWithEffect)
                                    )),
                                    cmd_data,
                                    cmd_invoke_result
                                );
                                cmd_invoke_result?;
                            }
                            CommandId::OnWithRecallGlobalScene => {
                                let cmd_invoke_result =
                                    self.0.handle_on_with_recall_global_scene(&ctx).await;
                                #[cfg(feature = "defmt")]
                                rs_matter_crate::reexport::defmt::debug!(
                                    "{:?} -> {:?}",
                                    MetadataDebug((
                                        ctx.cmd().endpoint_id,
                                        self,
                                        MetadataDebug(CommandId::OnWithRecallGlobalScene)
                                    )),
                                    cmd_invoke_result
                                );
                                #[cfg(feature = "log")]
                                rs_matter_crate::reexport::log::debug!(
                                    "{:?} -> {:?}",
                                    MetadataDebug((
                                        ctx.cmd().endpoint_id,
                                        self,
                                        MetadataDebug(CommandId::OnWithRecallGlobalScene)
                                    )),
                                    cmd_invoke_result
                                );
                                cmd_invoke_result?;
                            }
                            CommandId::OnWithTimedOff => {
                                let cmd_data: OnWithTimedOffRequest<'_> =
                                    rs_matter_crate::tlv::FromTLV::from_tlv(ctx.data())?;
                                let cmd_invoke_result = self
                                    .0
                                    .handle_on_with_timed_off(&ctx, cmd_data.clone())
                                    .await;
                                #[cfg(feature = "defmt")]
                                rs_matter_crate::reexport::defmt::debug!(
                                    "{:?}({:?}) -> {:?}",
                                    MetadataDebug((
                                        ctx.cmd().endpoint_id,
                                        self,
                                        MetadataDebug(CommandId::OnWithTimedOff)
                                    )),
                                    cmd_data,
                                    cmd_invoke_result
                                );
                                #[cfg(feature = "log")]
                                rs_matter_crate::reexport::log::debug!(
                                    "{:?}({:?}) -> {:?}",
                                    MetadataDebug((
                                        ctx.cmd().endpoint_id,
                                        self,
                                        MetadataDebug(CommandId::OnWithTimedOff)
                                    )),
                                    cmd_data,
                                    cmd_invoke_result
                                );
                                cmd_invoke_result?;
                            }
                            other => {
                                #[cfg(feature = "defmt")]
                                rs_matter_crate::reexport::defmt::error!(
                                    "Command {:?} not supported",
                                    other
                                );
                                #[cfg(feature = "log")]
                                rs_matter_crate::reexport::log::error!(
                                    "Command {:?} not supported",
                                    other
                                );
                                return Err(
                                    rs_matter_crate::error::ErrorCode::CommandNotFound.into()
                                );
                            }
                        }
                        self.0.dataver_changed();
                        Ok(())
                    }
                    fn run(
                        &self,
                        ctx: impl rs_matter_crate::dm::HandlerContext,
                    ) -> impl core::future::Future<Output = Result<(), rs_matter_crate::error::Error>>
                    {
                        self.0.run(ctx)
                    }
                }
                impl<T, Q> core::fmt::Debug for MetadataDebug<(u16, &HandlerAdaptor<T>, Q)>
                where
                    T: ClusterHandler,
                    Q: core::fmt::Debug,
                {
                    #[allow(unreachable_code)]
                    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                        write!(
                            f,
                            "Endpt(0x{:02x})::Cluster::{}(0x{:04x})::{:?}",
                            self.0 .0, "OnOff", 6u32, self.0 .2
                        )
                    }
                }
                #[cfg(feature = "defmt")]
                impl<T, Q> rs_matter_crate::reexport::defmt::Format for MetadataDebug<(u16, &HandlerAdaptor<T>, Q)>
                where
                    T: ClusterHandler,
                    Q: rs_matter_crate::reexport::defmt::Format,
                {
                    #[allow(unreachable_code)]
                    fn format(&self, f: rs_matter_crate::reexport::defmt::Formatter<'_>) {
                        rs_matter_crate::reexport::defmt::write!(
                            f,
                            "Endpt(0x{:02x})::Cluster::{}(0x{:04x})::{:?}",
                            self.0 .0,
                            "OnOff",
                            6u32,
                            self.0 .2
                        )
                    }
                }
            )
        );
    }
}
