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

use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;

use rs_matter_data_model::{Attribute, Cluster, Command, DataType, StructType};

use super::field::{field_type, field_type_builder, BuilderPolicy};
use super::id::{idl_attribute_name_to_enum_variant_name, idl_field_name_to_rs_name};
use super::IdlGenerateContext;

/// Return a token stream defining the handler trait for the provided IDL cluster.
///
/// Unlike the `rs-matter` generic `Handler` / `AsyncHandler` pair of traits, the trait
/// generated here is specific to the conrete provided IDL cluster and is strongly-typed.
///
/// Thus, it contains methods corresponding to all the attributes and commands of the
/// IDL cluster.
///
/// Moreover, these methods are much more safe w.r.t. TLV parsing and encoding, as they
/// are based on the IDL information and make use of all enums, bitmaps and structs defined
/// in the IDL cluster, thus providing a strongly-typed interface.
///
/// ## Arguments
/// - `asynch`: If true, the generated handler will be async.
/// - `delegate`: If true, rather than generating a handler trait, the function will generate
///   an inherent implementation of the trait over `&T`, where `T` is assumed to implement the trait.
/// - `cluster`: The IDL cluster for which the handler is generated.
/// - `context`: The context containing the information needed to generate the handler.
pub fn handler(
    asynch: bool,
    delegate: bool,
    cluster: &Cluster,
    context: &IdlGenerateContext,
) -> TokenStream {
    let krate = context.rs_matter_crate.clone();

    let handler_name = Ident::new(
        &format!("Cluster{}Handler", if asynch { "Async" } else { "" }),
        Span::call_site(),
    );

    let handler_attribute_methods = cluster
        .attributes
        .iter()
        .filter(|attr| attr.field.field.code < 0xf000) // TODO: Figure out the global attributes start
        .map(|attr| handler_attribute(attr, asynch, delegate, cluster, &krate));

    let handler_attribute_write_methods = cluster
        .attributes
        .iter()
        .filter(|attr| attr.field.field.code < 0xf000) // TODO: Figure out the global attributes start
        .filter(|attr| !attr.is_read_only)
        .map(|attr| handler_attribute_write(attr, asynch, delegate, cluster, &krate));

    let handler_command_methods = cluster
        .commands
        .iter()
        .map(|cmd| handler_command(cmd, asynch, delegate, cluster, &krate));

    if delegate {
        quote!(
            impl<T> #handler_name for &T
            where
                T: #handler_name
            {
                fn dataver(&self) -> u32 { T::dataver(self) }
                fn dataver_changed(&self) { T::dataver_changed(self) }

                #(#handler_attribute_methods)*

                #(#handler_attribute_write_methods)*

                #(#handler_command_methods)*
            }
        )
    } else {
        quote!(
            pub trait #handler_name {
                fn dataver(&self) -> u32;
                fn dataver_changed(&self);

                #(#handler_attribute_methods)*

                #(#handler_attribute_write_methods)*

                #(#handler_command_methods)*
            }
        )
    }
}

/// Return a token stream defining an adaptor struct that can adapt a type implementing the
/// cluster-specific handler trait as defined by the `handler` function to the
/// generic `Handler` / `AsyncHandler` traits that `rs-matter` understands.
///
/// Without this adaptor, implementations of the cluster-specific handler trait would not be
/// usable with `rs-matter`.
///
/// # Arguments
/// - `asynch`: If true, the adaptor implements to rs-matter's `AsyncHandler` trait, rather than
///   to the `Handler` trait.
/// - `cluster`: The IDL cluster for which the adaptor is generated.
/// - `context`: The context containing the information needed to generate the adaptor.
pub fn handler_adaptor(
    asynch: bool,
    cluster: &Cluster,
    context: &IdlGenerateContext,
) -> TokenStream {
    let krate = context.rs_matter_crate.clone();

    let handler_name = Ident::new(
        &format!("Cluster{}Handler", if asynch { "Async" } else { "" }),
        Span::call_site(),
    );

    let handler_adaptor_name = Ident::new(
        &format!("Handler{}Adaptor", if asynch { "Async" } else { "" }),
        Span::call_site(),
    );

    let generic_handler_name = Ident::new(
        &format!("{}Handler", if asynch { "Async" } else { "" }),
        Span::call_site(),
    );

    let handler_adaptor_attribute_match = cluster
        .attributes
        .iter()
        .filter(|attr| attr.field.field.code < 0xf000) // TODO: Figure out the global attributes start
        .map(|attr| handler_adaptor_attribute_match(attr, asynch, cluster, &krate))
        .collect::<Vec<_>>();

    let handler_adaptor_attribute_write_match = cluster
        .attributes
        .iter()
        .filter(|attr| attr.field.field.code < 0xf000) // TODO: Figure out the global attributes start
        .filter(|attr| !attr.is_read_only)
        .map(|attr| handler_adaptor_attribute_write_match(attr, asynch, cluster, &krate));

    let handler_adaptor_command_match = cluster
        .commands
        .iter()
        .map(|cmd| handler_adaptor_command_match(cmd, asynch, cluster, &krate))
        .collect::<Vec<_>>();

    let read_stream = if !handler_adaptor_attribute_match.is_empty() {
        quote!(
            match AttributeId::try_from(ctx.attr().attr_id)? {
                #(#handler_adaptor_attribute_match)*
                #[allow(unreachable_code)]
                _ => Err(#krate::error::ErrorCode::AttributeNotFound.into()),
            }
        )
    } else {
        quote!(
            Err(#krate::error::ErrorCode::AttributeNotFound.into())
        )
    };

    let write_stream = if !handler_adaptor_attribute_match.is_empty() {
        quote!(
            match AttributeId::try_from(ctx.attr().attr_id)? {
                #(#handler_adaptor_attribute_write_match)*
                _ => return Err(#krate::error::ErrorCode::AttributeNotFound.into()),
            }
        )
    } else {
        quote!(
            return Err(#krate::error::ErrorCode::AttributeNotFound.into());
        )
    };

    let invoke_stream = if !handler_adaptor_command_match.is_empty() {
        quote!(
            match CommandId::try_from(ctx.cmd().cmd_id)? {
                #(#handler_adaptor_command_match)*
                _ => return Err(#krate::error::ErrorCode::CommandNotFound.into()),
            }
        )
    } else {
        quote!(
            return Err(#krate::error::ErrorCode::CommandNotFound.into());
        )
    };

    let pasync = if asynch { quote!(async) } else { quote!() };

    let stream = quote!(
        pub struct #handler_adaptor_name<T>(pub T);

        impl<T> #krate::data_model::objects::#generic_handler_name for #handler_adaptor_name<T>
        where
            T: #handler_name,
        {
            #[allow(unreachable_code)]
            #pasync fn read(
                &self,
                ctx: &#krate::data_model::objects::ReadContext<'_>,
                encoder: #krate::data_model::objects::AttrDataEncoder<'_, '_, '_>,
            ) -> Result<(), #krate::error::Error> {
                if let Some(mut writer) = encoder.with_dataver(self.0.dataver())? {
                    if ctx.attr().is_system() {
                        ctx.attr().cluster()?.read(ctx.attr().attr_id, writer)
                    } else {
                        #read_stream
                    }
                } else {
                    Ok(())
                }
            }

            #[allow(unreachable_code)]
            #pasync fn write(
                &self,
                ctx: &#krate::data_model::objects::WriteContext<'_>,
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
            #pasync fn invoke(
                &self,
                ctx: &#krate::data_model::objects::InvokeContext<'_>,
                encoder: #krate::data_model::objects::CmdDataEncoder<'_, '_, '_>,
            ) -> Result<(), #krate::error::Error> {
                #invoke_stream

                self.0.dataver_changed();

                Ok(())
            }
        }
    );

    if asynch {
        stream
    } else {
        quote!(
            #stream

            impl<T> #krate::data_model::objects::NonBlockingHandler for #handler_adaptor_name<T>
            where
                T: #handler_name,
            {}
        )
    }
}

/// Return a token stream defining the handler trait method for reading the provided IDL attribute.
///
/// # Arguments
/// - `attr`: The IDL attribute for which the handler method is generated.
/// - `asynch`: If true, the generated handler method signature will be async.
/// - `delegate`: If true, the generated handler method will have an implementation delegating
///   to a `T` type (for inherent impls)
/// - `cluster`: The IDL cluster for which the handler method is generated.
/// - `krate`: The crate name to use for the generated code.
fn handler_attribute(
    attr: &Attribute,
    asynch: bool,
    delegate: bool,
    cluster: &Cluster,
    krate: &Ident,
) -> TokenStream {
    let attr_name = Ident::new(
        &idl_field_name_to_rs_name(&attr.field.field.id),
        Span::call_site(),
    );

    let parent = quote!(P);
    let (pasync, sawait) = if asynch {
        (quote!(async), quote!(.await))
    } else {
        (quote!(), quote!())
    };

    let (mut attr_type, builder) = field_type_builder(
        &attr.field.field.data_type,
        attr.field.is_nullable,
        false,
        BuilderPolicy::NonCopyAndStrings,
        parent.clone(),
        cluster,
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
                cluster,
                krate,
            );

            attr_type = quote!(#krate::data_model::objects::ArrayAttributeRead<#attr_type, #attr_element_type>);
        }

        if !delegate && attr.field.is_optional {
            quote!(
                #pasync fn #attr_name<P: #krate::tlv::TLVBuilderParent>(&self, ctx: &#krate::data_model::objects::ReadContext<'_>, builder: #attr_type) -> Result<P, #krate::error::Error> {
                    Err(#krate::error::ErrorCode::InvalidAction.into())
                }
            )
        } else {
            let stream = quote!(
                #pasync fn #attr_name<P: #krate::tlv::TLVBuilderParent>(&self, ctx: &#krate::data_model::objects::ReadContext<'_>, builder: #attr_type) -> Result<P, #krate::error::Error>
            );

            if delegate {
                quote!(#stream { T::#attr_name(self, ctx, builder)#sawait })
            } else {
                quote!(#stream;)
            }
        }
    } else if !delegate && attr.field.is_optional {
        quote!(
            #pasync fn #attr_name(&self, ctx: &#krate::data_model::objects::ReadContext<'_>) -> Result<#attr_type, #krate::error::Error> {
                Err(#krate::error::ErrorCode::InvalidAction.into())
            }
        )
    } else {
        let stream = quote!(
            #pasync fn #attr_name(&self, ctx: &#krate::data_model::objects::ReadContext<'_>) -> Result<#attr_type, #krate::error::Error>
        );

        if delegate {
            quote!(#stream { T::#attr_name(self, ctx)#sawait })
        } else {
            quote!(#stream;)
        }
    }
}

/// Return a token stream defining the handler trait method for writing the provided IDL attribute.
///
/// # Arguments
/// - `attr`: The IDL attribute for which the handler method is generated.
/// - `asynch`: If true, the generated handler method signature will be async.
/// - `delegate`: If true, the generated handler method will have an implementation delegating
///   to a `T` type (for inherent impls)
/// - `cluster`: The IDL cluster for which the handler method is generated.
/// - `krate`: The crate name to use for the generated code.
fn handler_attribute_write(
    attr: &Attribute,
    asynch: bool,
    delegate: bool,
    cluster: &Cluster,
    krate: &Ident,
) -> TokenStream {
    let attr_name = Ident::new(
        &format!("set_{}", &idl_field_name_to_rs_name(&attr.field.field.id)),
        Span::call_site(),
    );

    let (pasync, sawait) = if asynch {
        (quote!(async), quote!(.await))
    } else {
        (quote!(), quote!())
    };

    let mut attr_type = field_type(
        &attr.field.field.data_type,
        attr.field.is_nullable,
        false,
        cluster,
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
            cluster,
            krate,
        );

        attr_type = quote!(#krate::data_model::objects::ArrayAttributeWrite<#attr_type, #attr_element_type>);
    }

    if !delegate && attr.field.is_optional {
        quote!(
            #pasync fn #attr_name(&self, ctx: &#krate::data_model::objects::WriteContext<'_>, value: #attr_type) -> Result<(), #krate::error::Error> {
                Err(#krate::error::ErrorCode::InvalidAction.into())
            }
        )
    } else {
        let stream = quote!(
            #pasync fn #attr_name(&self, ctx: &#krate::data_model::objects::WriteContext<'_>, value: #attr_type) -> Result<(), #krate::error::Error>
        );

        if delegate {
            quote!(#stream { T::#attr_name(self, ctx, value)#sawait })
        } else {
            quote!(#stream;)
        }
    }
}

/// Return a token stream defining the handler trait method for handling the provided IDL command.
///
/// # Arguments
/// - `cmd`: The IDL command for which the handler method is generated.
/// - `asynch`: If true, the generated handler method signature will be async.
/// - `delegate`: If true, the generated handler method will have an implementation delegating
///   to a `T` type (for inherent impls)
/// - `cluster`: The IDL cluster for which the handler method is generated.
/// - `krate`: The crate name to use for the generated code.
fn handler_command(
    cmd: &Command,
    asynch: bool,
    delegate: bool,
    cluster: &Cluster,
    krate: &Ident,
) -> TokenStream {
    let cmd_name = Ident::new(
        &format!("handle_{}", &idl_field_name_to_rs_name(&cmd.id)),
        Span::call_site(),
    );

    let (pasync, sawait) = if asynch {
        (quote!(async), quote!(.await))
    } else {
        (quote!(), quote!())
    };

    let field_req = cmd.input.as_ref().map(|id| {
        field_type(
            &DataType {
                name: id.clone(),
                is_list: false,
                max_length: None,
            },
            false,
            false,
            cluster,
            krate,
        )
    });

    let cmd_output = (cmd.output != "DefaultSuccess").then(|| cmd.output.clone());

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
            cluster,
            krate,
        )
    });

    if let Some(field_req) = field_req {
        if let Some((field_resp, field_resp_builder)) = field_resp {
            if field_resp_builder {
                let stream = quote!(
                    #pasync fn #cmd_name<P: #krate::tlv::TLVBuilderParent>(
                        &self,
                        ctx: &#krate::data_model::objects::InvokeContext<'_>,
                        request: #field_req,
                        response: #field_resp,
                    ) -> Result<P, #krate::error::Error>
                );

                if delegate {
                    quote!(#stream { T::#cmd_name(self, ctx, request, response)#sawait })
                } else {
                    quote!(#stream;)
                }
            } else {
                let stream = quote!(
                    #pasync fn #cmd_name(
                        &self,
                        ctx: &#krate::data_model::objects::InvokeContext<'_>,
                        request: #field_req,
                    ) -> Result<#field_resp, #krate::error::Error>
                );

                if delegate {
                    quote!(#stream { T::#cmd_name(self, ctx, request)#sawait })
                } else {
                    quote!(#stream;)
                }
            }
        } else {
            let stream = quote!(
                #pasync fn #cmd_name(
                    &self,
                    ctx: &#krate::data_model::objects::InvokeContext<'_>,
                    request: #field_req,
                ) -> Result<(), #krate::error::Error>
            );

            if delegate {
                quote!(#stream { T::#cmd_name(self, ctx, request)#sawait })
            } else {
                quote!(#stream;)
            }
        }
    } else if let Some((field_resp, field_resp_builder)) = field_resp {
        if field_resp_builder {
            let stream = quote!(
                #pasync fn #cmd_name<P: #krate::tlv::TLVBuilderParent>(
                    &self,
                    ctx: &#krate::data_model::objects::InvokeContext<'_>,
                    response: #field_resp,
                ) -> Result<P, #krate::error::Error>
            );

            if delegate {
                quote!(#stream { T::#cmd_name(self, ctx, response)#sawait })
            } else {
                quote!(#stream;)
            }
        } else {
            let stream = quote!(
                #pasync fn #cmd_name(
                    &self,
                    ctx: &#krate::data_model::objects::InvokeContext<'_>,
                ) -> Result<#field_resp, #krate::error::Error>
            );

            if delegate {
                quote!(#stream { T::#cmd_name(self, ctx)#sawait })
            } else {
                quote!(#stream;)
            }
        }
    } else {
        let stream = quote!(
            #pasync fn #cmd_name(
                &self,
                ctx: &#krate::data_model::objects::InvokeContext<'_>,
            ) -> Result<(), #krate::error::Error>
        );

        if delegate {
            quote!(#stream { T::#cmd_name(self, ctx)#sawait })
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
/// - `asynch`: If true, the generated match clause will assume the cluster trait is async and will generate async code.
/// - `cluster`: The IDL cluster for which the match clause is generated.
/// - `krate`: The crate name to use for the generated code.
fn handler_adaptor_attribute_match(
    attr: &Attribute,
    asynch: bool,
    cluster: &Cluster,
    krate: &Ident,
) -> TokenStream {
    let attr_name = Ident::new(
        &idl_attribute_name_to_enum_variant_name(&attr.field.field.id),
        Span::call_site(),
    );
    let attr_debug_id = quote!(AttributeId::#attr_name.debug(false));

    let attr_method_name = Ident::new(
        &idl_field_name_to_rs_name(&attr.field.field.id),
        Span::call_site(),
    );

    let parent = quote!(P);
    let sawait = if asynch { quote!(.await) } else { quote!() };

    let (_, builder) = field_type_builder(
        &attr.field.field.data_type,
        attr.field.is_nullable,
        attr.field.is_optional,
        BuilderPolicy::NonCopyAndStrings,
        parent,
        cluster,
        krate,
    );

    let attr_read_debug_build_start = quote!(
        #[cfg(feature = "defmt")]
        #krate::reexport::defmt::info!("{:?} -> (build) +", #attr_debug_id);
        #[cfg(feature = "log")]
        #krate::reexport::log::info!("{:?} -> (build) +", #attr_debug_id);
    );

    let attr_read_debug_build_end = quote!(
        #[cfg(feature = "defmt")]
        #krate::reexport::defmt::info!("{:?} -> {:?}", #attr_debug_id, attr_read_result.as_ref().map(|_| ()));
        #[cfg(feature = "log")]
        #krate::reexport::log::info!("{:?} (end) -> {:?}", #attr_debug_id, attr_read_result.as_ref().map(|_| ()));
    );

    let attr_read_debug = quote!(
        #[cfg(feature = "defmt")]
        #krate::reexport::defmt::info!("{:?} -> {:?}", #attr_debug_id, attr_read_result);
        #[cfg(feature = "log")]
        #krate::reexport::log::info!("{:?} -> {:?}", #attr_debug_id, attr_read_result);
    );

    if builder {
        if attr.field.field.data_type.is_list {
            quote!(
                AttributeId::#attr_name => {
                    #attr_read_debug_build_start

                    let attr_read_result = self.0.#attr_method_name(
                        ctx,
                        #krate::data_model::objects::ArrayAttributeRead::new(
                            ctx.attr().list_index.clone(),
                            #krate::tlv::TLVWriteParent::new(#attr_debug_id, writer.writer()),
                            &#krate::data_model::objects::AttrDataWriter::TAG,
                        )?,
                    )#sawait;

                    #attr_read_debug_build_end

                    attr_read_result?;

                    writer.complete()
                }
            )
        } else {
            quote!(
                AttributeId::#attr_name => {
                    #attr_read_debug_build_start

                    let attr_read_result = self.0.#attr_method_name(ctx, #krate::tlv::TLVBuilder::new(
                        #krate::tlv::TLVWriteParent::new(#attr_debug_id, writer.writer()),
                        &#krate::data_model::objects::AttrDataWriter::TAG,
                    )?)#sawait;

                    #attr_read_debug_build_end

                    attr_read_result?;

                    writer.complete()
                }
            )
        }
    } else {
        quote!(
            AttributeId::#attr_name => {
               let attr_read_result = self.0.#attr_method_name(ctx)#sawait;

                #attr_read_debug

                writer.set(attr_read_result?)
            }
        )
    }
}

/// Return a token stream defining a mach clause, `AttributeId::Foo => handler.foo(...)`
/// that is used by the adaptor to handle writing to the provided IDL attribute.
///
/// # Arguments
/// - `attr`: The IDL attribute for which the match clause is generated.
/// - `asynch`: If true, the generated match clause will assume the cluster trait is async and will generate async code.
/// - `krate`: The crate name to use for the generated code.
fn handler_adaptor_attribute_write_match(
    attr: &Attribute,
    asynch: bool,
    cluster: &Cluster,
    krate: &Ident,
) -> TokenStream {
    let attr_name = Ident::new(
        &idl_attribute_name_to_enum_variant_name(&attr.field.field.id),
        Span::call_site(),
    );
    let attr_debug_id = quote!(AttributeId::#attr_name.debug(true));

    let attr_method_name = Ident::new(
        &format!("set_{}", &idl_field_name_to_rs_name(&attr.field.field.id)),
        Span::call_site(),
    );

    let attr_type = field_type(
        &attr.field.field.data_type,
        attr.field.is_nullable,
        false,
        cluster,
        krate,
    );

    let sawait = if asynch { quote!(.await) } else { quote!() };

    let attr_write_debug = quote!(
        #[cfg(feature = "defmt")]
        #krate::reexport::defmt::info!("{:?}({:?}) -> {:?}", #attr_debug_id, attr_data, attr_write_result);
        #[cfg(feature = "log")]
        #krate::reexport::log::info!("{:?}({:?}) -> {:?}", #attr_debug_id, attr_data, attr_write_result);
    );

    if attr.field.field.data_type.is_list {
        quote!(
            AttributeId::#attr_name => {
                let attr_data = #krate::data_model::objects::ArrayAttributeWrite::new(ctx.attr().list_index.clone(), ctx.data())?;

                let attr_write_result = self.0.#attr_method_name(ctx, attr_data.clone())#sawait;

                #attr_write_debug

                attr_write_result?;
            }
        )
    } else {
        quote!(
            AttributeId::#attr_name => {
                let attr_data: #attr_type = #krate::tlv::FromTLV::from_tlv(ctx.data())?;

                let attr_write_result = self.0.#attr_method_name(ctx, attr_data.clone())#sawait;

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
/// - `asynch`: If true, the generated match clause will assume the cluster trait is async and will generate async code.
/// - `cluster`: The IDL cluster for which the match clause is generated.
/// - `krate`: The crate name to use for the generated code.
fn handler_adaptor_command_match(
    cmd: &Command,
    asynch: bool,
    cluster: &Cluster,
    krate: &Ident,
) -> TokenStream {
    let cmd_name = Ident::new(
        &idl_attribute_name_to_enum_variant_name(&cmd.id),
        Span::call_site(),
    );
    let cmd_debug_id = quote!(CommandId::#cmd_name.debug(true));

    let cmd_method_name = Ident::new(
        &format!("handle_{}", &idl_field_name_to_rs_name(&cmd.id)),
        Span::call_site(),
    );

    let sawait = if asynch { quote!(.await) } else { quote!() };

    let cmd_invoke_debug_build_start = quote!(
        #[cfg(feature = "defmt")]
        #krate::reexport::defmt::info!("{:?}({:?}) -> (build) +", #cmd_debug_id, cmd_data);
        #[cfg(feature = "log")]
        #krate::reexport::log::info!("{:?}({:?}) -> (build) +", #cmd_debug_id, cmd_data);
    );

    let cmd_invoke_debug_noarg_build_start = quote!(
        #[cfg(feature = "defmt")]
        #krate::reexport::defmt::info!("{:?} -> (build) +", #cmd_debug_id);
        #[cfg(feature = "log")]
        #krate::reexport::log::info!("{:?} -> (build) +", #cmd_debug_id);
    );

    let cmd_invoke_debug_build_end = quote!(
        #[cfg(feature = "defmt")]
        #krate::reexport::defmt::info!("{:?} (end) -> {:?}", #cmd_debug_id, cmd_invoke_result.as_ref().map(|_| ()));
        #[cfg(feature = "log")]
        #krate::reexport::log::info!("{:?} (end) -> {:?}", #cmd_debug_id, cmd_invoke_result.as_ref().map(|_| ()));
    );

    let cmd_invoke_debug = quote!(
        #[cfg(feature = "defmt")]
        #krate::reexport::defmt::info!("{:?}({:?}) -> {:?}", #cmd_debug_id, cmd_data, cmd_invoke_result);
        #[cfg(feature = "log")]
        #krate::reexport::log::info!("{:?}({:?}) -> {:?}", #cmd_debug_id, cmd_data, cmd_invoke_result);
    );

    let cmd_invoke_debug_noarg = quote!(
        #[cfg(feature = "defmt")]
        #krate::reexport::defmt::info!("{:?} -> {:?}", #cmd_debug_id, cmd_invoke_result);
        #[cfg(feature = "log")]
        #krate::reexport::log::info!("{:?} -> {:?}", #cmd_debug_id, cmd_invoke_result);
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
            cluster,
            krate,
        )
    });

    let cmd_output = (cmd.output != "DefaultSuccess")
        .then(|| {
            cluster
                .structs
                .iter()
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
            cluster,
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

                        let mut writer = encoder.with_command(#field_resp_cmd_code)?;

                        let cmd_invoke_result = self.0.#cmd_method_name(
                            ctx,
                            cmd_data,
                            #krate::tlv::TLVBuilder::new(
                                #krate::tlv::TLVWriteParent::new(#cmd_debug_id, writer.writer()),
                                &#krate::data_model::objects::CmdDataWriter::TAG,
                            )?
                        )#sawait;

                        #cmd_invoke_debug_build_end

                        cmd_invoke_result?;

                        writer.complete()?
                    }
                )
            } else {
                quote!(
                    CommandId::#cmd_name => {
                        let cmd_data: #field_req = #krate::tlv::FromTLV::from_tlv(ctx.data())?;

                        let writer = encoder.with_command(#field_resp_cmd_code)?;

                        let cmd_invoke_result = self.0.#cmd_method_name(ctx, cmd_data.clone())#sawait;

                        #cmd_invoke_debug

                        writer.set(cmd_invoke_result?)?;
                    }
                )
            }
        } else {
            quote!(
                CommandId::#cmd_name => {
                    let cmd_data: #field_req = #krate::tlv::FromTLV::from_tlv(ctx.data())?;

                    let cmd_invoke_result = self.0.#cmd_method_name(ctx, cmd_data.clone())#sawait;

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

                    let mut writer = encoder.with_command(#field_resp_cmd_code)?;

                    let cmd_invoke_result = self.0.#cmd_method_name(
                        ctx,
                        #krate::tlv::TLVBuilder::new(
                            #krate::tlv::TLVWriteParent::new(#cmd_debug_id, writer.writer()),
                            &#krate::data_model::objects::CmdDataWriter::TAG,
                        )?,
                    )#sawait;

                    #cmd_invoke_debug_build_end

                    cmd_invoke_result?;

                    writer.complete()?
                }
            )
        } else {
            quote!(quote!(
                CommandId::#cmd_name => {
                    let writer = encoder.with_command(#field_resp_cmd_code)?;

                    let cmd_invoke_result = self.0.#cmd_method_name(ctx)#sawait;

                    #cmd_invoke_debug_noarg

                    writer.set(cmd_invoke_result?)?;
                }
            ))
        }
    } else {
        quote!(
            CommandId::#cmd_name => {
                let cmd_invoke_result = self.0.#cmd_method_name(ctx)#sawait;

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

        let cluster = get_cluster_named(&idl, "OnOff").expect("Cluster exists");
        let context = IdlGenerateContext::new("rs_matter_crate");

        // panic!("====\n{}\n====", &handler(false, false, cluster, &context));

        assert_tokenstreams_eq!(
            &handler(false, false, cluster, &context),
            &quote!(
                pub trait OnOffHandler {
                    fn dataver(&self) -> u32;
                    fn dataver_changed(&self);
                    fn on_off(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
                    ) -> Result<bool, rs_matter_crate::error::Error>;
                    fn global_scene_control(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
                    ) -> Result<bool, rs_matter_crate::error::Error> {
                        Err(rs_matter_crate::error::ErrorCode::InvalidAction.into())
                    }
                    fn on_time(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
                    ) -> Result<u16, rs_matter_crate::error::Error> {
                        Err(rs_matter_crate::error::ErrorCode::InvalidAction.into())
                    }
                    fn off_wait_time(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
                    ) -> Result<u16, rs_matter_crate::error::Error> {
                        Err(rs_matter_crate::error::ErrorCode::InvalidAction.into())
                    }
                    fn start_up_on_off(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
                    ) -> Result<
                        rs_matter_crate::tlv::Nullable<StartUpOnOffEnum>,
                        rs_matter_crate::error::Error,
                    > {
                        Err(rs_matter_crate::error::ErrorCode::InvalidAction.into())
                    }
                    fn set_on_time(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
                        value: u16,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        Err(rs_matter_crate::error::ErrorCode::InvalidAction.into())
                    }
                    fn set_off_wait_time(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
                        value: u16,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        Err(rs_matter_crate::error::ErrorCode::InvalidAction.into())
                    }
                    fn set_start_up_on_off(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
                        value: rs_matter_crate::tlv::Nullable<StartUpOnOffEnum>,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        Err(rs_matter_crate::error::ErrorCode::InvalidAction.into())
                    }
                    fn handle_off(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
                    ) -> Result<(), rs_matter_crate::error::Error>;
                    fn handle_on(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
                    ) -> Result<(), rs_matter_crate::error::Error>;
                    fn handle_toggle(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
                    ) -> Result<(), rs_matter_crate::error::Error>;
                    fn handle_off_with_effect(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
                        request: OffWithEffectRequest<'_>,
                    ) -> Result<(), rs_matter_crate::error::Error>;
                    fn handle_on_with_recall_global_scene(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
                    ) -> Result<(), rs_matter_crate::error::Error>;
                    fn handle_on_with_timed_off(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
                        request: OnWithTimedOffRequest<'_>,
                    ) -> Result<(), rs_matter_crate::error::Error>;
                }
            )
        );

        // panic!("====\n{}\n====", &handler(true, false, cluster, &context));

        // NOTE: (Temporarily) commented out, as `assert_tokenstreams_eq` does not seem to understand
        // Rust 2021
        // assert_tokenstreams_eq!(
        //     &handler(true, false, cluster, &context),
        //     &quote!(
        //         pub trait AsyncOnOffHandler {
        //             fn dataver(&self) -> u32;
        //             fn dataver_changed(&self);
        //             async fn on_off(
        //                 &self,
        //                 ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        //             ) -> Result<bool, rs_matter_crate::error::Error>;
        //             async fn global_scene_control(
        //                 &self,
        //                 ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        //             ) -> Result<bool, rs_matter_crate::error::Error> {
        //                 Err(rs_matter_crate::error::ErrorCode::InvalidAction.into())
        //             }
        //             async fn on_time(
        //                 &self,
        //                 ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        //             ) -> Result<u16, rs_matter_crate::error::Error> {
        //                 Err(rs_matter_crate::error::ErrorCode::InvalidAction.into())
        //             }
        //             async fn off_wait_time(
        //                 &self,
        //                 ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        //             ) -> Result<u16, rs_matter_crate::error::Error> {
        //                 Err(rs_matter_crate::error::ErrorCode::InvalidAction.into())
        //             }
        //             async fn start_up_on_off(
        //                 &self,
        //                 ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        //             ) -> Result<rs_matter_crate::tlv::Nullable<StartUpOnOffEnum>, rs_matter_crate::error::Error>
        //             {
        //                 Err(rs_matter_crate::error::ErrorCode::InvalidAction.into())
        //             }
        //             async fn set_on_time(
        //                 &self,
        //                 ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        //                 value: u16,
        //             ) -> Result<(), rs_matter_crate::error::Error> {
        //                 Err(rs_matter_crate::error::ErrorCode::InvalidAction.into())
        //             }
        //             async fn set_off_wait_time(
        //                 &self,
        //                 ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        //                 value: u16,
        //             ) -> Result<(), rs_matter_crate::error::Error> {
        //                 Err(rs_matter_crate::error::ErrorCode::InvalidAction.into())
        //             }
        //             async fn set_start_up_on_off(
        //                 &self,
        //                 ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        //                 value: rs_matter_crate::tlv::Nullable<StartUpOnOffEnum>,
        //             ) -> Result<(), rs_matter_crate::error::Error> {
        //                 Err(rs_matter_crate::error::ErrorCode::InvalidAction.into())
        //             }
        //             async fn handle_off(
        //                 &self,
        //                 ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        //             ) -> Result<(), rs_matter_crate::error::Error>;
        //             async fn handle_on(
        //                 &self,
        //                 ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        //             ) -> Result<(), rs_matter_crate::error::Error>;
        //             async fn handle_toggle(
        //                 &self,
        //                 ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        //             ) -> Result<(), rs_matter_crate::error::Error>;
        //             async fn handle_off_with_effect(
        //                 &self,
        //                 ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        //                 request: OffWithEffectRequest<'_>,
        //             ) -> Result<(), rs_matter_crate::error::Error>;
        //             async fn handle_on_with_recall_global_scene(
        //                 &self,
        //                 ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        //             ) -> Result<(), rs_matter_crate::error::Error>;
        //             async fn handle_on_with_timed_off(
        //                 &self,
        //                 ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        //                 request: OnWithTimedOffRequest<'_>,
        //             ) -> Result<(), rs_matter_crate::error::Error>;
        //         }
        //     )
        // );

        // panic!("====\n{}\n====", &handler(false, true, cluster, &context));

        assert_tokenstreams_eq!(
            &handler(false, true, cluster, &context),
            &quote!(
                impl<T> OnOffHandler for &T
                where
                    T: OnOffHandler,
                {
                    fn dataver(&self) -> u32 {
                        T::dataver(self)
                    }
                    fn dataver_changed(&self) {
                        T::dataver_changed(self)
                    }
                    fn on_off(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
                    ) -> Result<bool, rs_matter_crate::error::Error> {
                        T::on_off(self, ctx)
                    }
                    fn global_scene_control(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
                    ) -> Result<bool, rs_matter_crate::error::Error> {
                        T::global_scene_control(self, ctx)
                    }
                    fn on_time(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
                    ) -> Result<u16, rs_matter_crate::error::Error> {
                        T::on_time(self, ctx)
                    }
                    fn off_wait_time(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
                    ) -> Result<u16, rs_matter_crate::error::Error> {
                        T::off_wait_time(self, ctx)
                    }
                    fn start_up_on_off(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
                    ) -> Result<
                        rs_matter_crate::tlv::Nullable<StartUpOnOffEnum>,
                        rs_matter_crate::error::Error,
                    > {
                        T::start_up_on_off(self, ctx)
                    }
                    fn set_on_time(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
                        value: u16,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        T::set_on_time(self, ctx, value)
                    }
                    fn set_off_wait_time(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
                        value: u16,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        T::set_off_wait_time(self, ctx, value)
                    }
                    fn set_start_up_on_off(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
                        value: rs_matter_crate::tlv::Nullable<StartUpOnOffEnum>,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        T::set_start_up_on_off(self, ctx, value)
                    }
                    fn handle_off(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        T::handle_off(self, ctx)
                    }
                    fn handle_on(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        T::handle_on(self, ctx)
                    }
                    fn handle_toggle(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        T::handle_toggle(self, ctx)
                    }
                    fn handle_off_with_effect(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
                        request: OffWithEffectRequest<'_>,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        T::handle_off_with_effect(self, ctx, request)
                    }
                    fn handle_on_with_recall_global_scene(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        T::handle_on_with_recall_global_scene(self, ctx)
                    }
                    fn handle_on_with_timed_off(
                        &self,
                        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
                        request: OnWithTimedOffRequest<'_>,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        T::handle_on_with_timed_off(self, ctx, request)
                    }
                }
            )
        );

        // panic!("====\n{}\n====", &handler_adaptor(false, cluster, &context));

        assert_tokenstreams_eq!(
            &handler_adaptor(false, cluster, &context),
            &quote!(
                pub struct OnOffAdaptor<T>(pub T);
                impl<T> rs_matter_crate::data_model::objects::Handler for OnOffAdaptor<T>
                where
                    T: OnOffHandler,
                {
                    #[allow(unreachable_code)]
                    fn read(
                        &self,
                        exchange: &rs_matter_crate::transport::exchange::Exchange<'_>,
                        attr: &rs_matter_crate::data_model::objects::AttrDetails<'_>,
                        encoder: rs_matter_crate::data_model::objects::AttrDataEncoder<'_, '_, '_>,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        if let Some(mut writer) = encoder.with_dataver(self.0.dataver())? {
                            if attr.is_system() {
                                attr.cluster()?.read(attr.attr_id, writer)
                            } else {
                                match AttributeId::try_from(attr.attr_id)? {
                                    AttributeId::OnOff => writer.set(self.0.on_off(
                                        &rs_matter_crate::data_model::objects::ReadContext::new(
                                            exchange,
                                        ),
                                    )?),
                                    AttributeId::GlobalSceneControl => {
                                        writer.set(self.0.global_scene_control(
                                            &rs_matter_crate::data_model::objects::ReadContext::new(
                                                exchange,
                                            ),
                                        )?)
                                    }
                                    AttributeId::OnTime => writer.set(self.0.on_time(
                                        &rs_matter_crate::data_model::objects::ReadContext::new(
                                            exchange,
                                        ),
                                    )?),
                                    AttributeId::OffWaitTime => writer.set(self.0.off_wait_time(
                                        &rs_matter_crate::data_model::objects::ReadContext::new(
                                            exchange,
                                        ),
                                    )?),
                                    AttributeId::StartUpOnOff => {
                                        writer.set(self.0.start_up_on_off(
                                            &rs_matter_crate::data_model::objects::ReadContext::new(
                                                exchange,
                                            ),
                                        )?)
                                    }
                                    #[allow(unreachable_code)]
                                    _ => {
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
                    fn write(
                        &self,
                        exchange: &rs_matter_crate::transport::exchange::Exchange<'_>,
                        attr: &rs_matter_crate::data_model::objects::AttrDetails<'_>,
                        data: rs_matter_crate::data_model::objects::AttrData<'_>,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        let data = data.with_dataver(self.0.dataver())?;
                        if attr.is_system() {
                            return Err(rs_matter_crate::error::ErrorCode::InvalidAction.into());
                        }
                        match AttributeId::try_from(attr.attr_id)? {
                            AttributeId::OnTime => self.0.set_on_time(
                                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                            )?,
                            AttributeId::OffWaitTime => self.0.set_off_wait_time(
                                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                            )?,
                            AttributeId::StartUpOnOff => self.0.set_start_up_on_off(
                                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                            )?,
                            _ => {
                                return Err(
                                    rs_matter_crate::error::ErrorCode::AttributeNotFound.into()
                                )
                            }
                        }
                        self.0.dataver_changed();
                        Ok(())
                    }
                    #[allow(unreachable_code)]
                    fn invoke(
                        &self,
                        exchange: &rs_matter_crate::transport::exchange::Exchange<'_>,
                        cmd: &rs_matter_crate::data_model::objects::CmdDetails<'_>,
                        data: &rs_matter_crate::tlv::TLVElement<'_>,
                        encoder: rs_matter_crate::data_model::objects::CmdDataEncoder<'_, '_, '_>,
                    ) -> Result<(), rs_matter_crate::error::Error> {
                        match CommandId::try_from(cmd.cmd_id)? {
                            CommandId::Off => self.0.handle_off(
                                &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
                            )?,
                            CommandId::On => self.0.handle_on(
                                &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
                            )?,
                            CommandId::Toggle => self.0.handle_toggle(
                                &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
                            )?,
                            CommandId::OffWithEffect => self.0.handle_off_with_effect(
                                &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
                                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                            )?,
                            CommandId::OnWithRecallGlobalScene => {
                                self.0.handle_on_with_recall_global_scene(
                                    &rs_matter_crate::data_model::objects::InvokeContext::new(
                                        exchange,
                                    ),
                                )?
                            }
                            CommandId::OnWithTimedOff => self.0.handle_on_with_timed_off(
                                &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
                                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                            )?,
                            _ => {
                                return Err(
                                    rs_matter_crate::error::ErrorCode::CommandNotFound.into()
                                )
                            }
                        }
                        self.0.dataver_changed();
                        Ok(())
                    }
                }
                impl<T> rs_matter_crate::data_model::objects::NonBlockingHandler for OnOffAdaptor<T> where
                    T: OnOffHandler
                {
                }
            )
        );
    }
}
