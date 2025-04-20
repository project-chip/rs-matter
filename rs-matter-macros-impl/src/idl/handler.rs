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

use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;

use rs_matter_data_model::{Attribute, Cluster, Command, DataType, StructType};

use super::field::{field_type, field_type_out};
use super::id::{idl_attribute_name_to_enum_variant_name, idl_field_name_to_rs_name};
use super::IdlGenerateContext;

pub fn handler(
    asynch: bool,
    delegate: bool,
    cluster: &Cluster,
    context: &IdlGenerateContext,
) -> TokenStream {
    let krate = context.rs_matter_crate.clone();

    let handler_name = Ident::new(
        &format!("{}{}Handler", if asynch { "Async" } else { "" }, cluster.id),
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

pub fn handler_adaptor(
    asynch: bool,
    cluster: &Cluster,
    context: &IdlGenerateContext,
) -> TokenStream {
    let krate = context.rs_matter_crate.clone();

    let handler_adaptor_attribute_match = cluster
        .attributes
        .iter()
        .filter(|attr| attr.field.field.code < 0xf000) // TODO: Figure out the global attributes start
        .map(|attr| handler_adaptor_attribute_match(attr, asynch, cluster, &krate));

    let handler_adaptor_attribute_write_match = cluster
        .attributes
        .iter()
        .filter(|attr| attr.field.field.code < 0xf000) // TODO: Figure out the global attributes start
        .filter(|attr| !attr.is_read_only)
        .map(|attr| handler_adaptor_attribute_write_match(attr, asynch, &krate));

    let handler_adaptor_command_match = cluster
        .commands
        .iter()
        .map(|cmd| handler_adaptor_command_match(cmd, asynch, cluster, &krate));

    let handler_name = Ident::new(
        &format!("{}{}Handler", if asynch { "Async" } else { "" }, cluster.id),
        Span::call_site(),
    );

    let handler_adaptor_name = Ident::new(
        &format!(
            "{}{}HandlerAdaptor",
            if asynch { "Async" } else { "" },
            cluster.id
        ),
        Span::call_site(),
    );

    let generic_handler_name = Ident::new(
        &format!("{}Handler", if asynch { "Async" } else { "" }),
        Span::call_site(),
    );

    let pasync = if asynch { quote!(async) } else { quote!() };

    let stream = quote!(
        pub struct #handler_adaptor_name<T>(T);

        impl<T> #handler_adaptor_name<T> {
            pub const fn new(handler: T) -> Self {
                Self(handler)
            }
        }

        impl<T> #krate::data_model::objects::#generic_handler_name for #handler_adaptor_name<T>
        where
            T: #handler_name,
        {
            #pasync fn read(
                &self,
                exchange: &#krate::transport::exchange::Exchange<'_>,
                attr: &#krate::data_model::objects::AttrDetails<'_>,
                encoder: #krate::data_model::objects::AttrDataEncoder<'_, '_, '_>,
            ) -> Result<(), #krate::error::Error> {
                if let Some(mut writer) = encoder.with_dataver(self.0.dataver())? {
                    if attr.is_system() {
                        CLUSTER.read(attr.attr_id, writer)
                    } else {
                        match AttributeId::try_from(attr.attr_id)? {
                            #(#handler_adaptor_attribute_match)*
                            #[allow(unreachable_code)]
                            _ => Err(#krate::error::ErrorCode::AttributeNotFound.into()),
                        }
                    }
                } else {
                    Ok(())
                }
            }

            #[allow(unreachable_code)]
            #pasync fn write(
                &self,
                exchange: &#krate::transport::exchange::Exchange<'_>,
                attr: &#krate::data_model::objects::AttrDetails<'_>,
                data: #krate::data_model::objects::AttrData<'_>,
            ) -> Result<(), #krate::error::Error> {
                let data = data.with_dataver(self.0.dataver())?;

                if attr.is_system() {
                    return Err(#krate::error::ErrorCode::InvalidAction.into())
                }

                match AttributeId::try_from(attr.attr_id)? {
                    #(#handler_adaptor_attribute_write_match)*
                    _ => return Err(#krate::error::ErrorCode::AttributeNotFound.into()),
                }

                self.0.dataver_changed();

                Ok(())
            }

            #[allow(unreachable_code)]
            #pasync fn invoke(
                &self,
                exchange: &#krate::transport::exchange::Exchange<'_>,
                cmd: &#krate::data_model::objects::CmdDetails<'_>,
                data: &#krate::tlv::TLVElement<'_>,
                encoder: #krate::data_model::objects::CmdDataEncoder<'_, '_, '_>,
            ) -> Result<(), #krate::error::Error> {
                match CommandId::try_from(cmd.cmd_id)? {
                    #(#handler_adaptor_command_match)*
                    _ => return Err(#krate::error::ErrorCode::CommandNotFound.into()),
                }

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

    let (attr_type, builder) = field_type_out(
        &attr.field.field.data_type,
        attr.field.is_nullable,
        attr.field.is_optional,
        true,
        parent,
        cluster,
        krate,
    );

    if builder {
        if !delegate && attr.field.is_optional {
            quote!(
                #pasync fn #attr_name<P: #krate::tlv::TLVBuilderParent>(&self, exchange: &#krate::transport::exchange::Exchange<'_>, builder: #attr_type) -> Result<P, #krate::error::Error> {
                    Ok(builder.none())
                }
            )
        } else {
            let stream = quote!(
                #pasync fn #attr_name<P: #krate::tlv::TLVBuilderParent>(&self, exchange: &#krate::transport::exchange::Exchange<'_>, builder: #attr_type) -> Result<P, #krate::error::Error>
            );

            if delegate {
                quote!(#stream { T::#attr_name(self, exchange, builder)#sawait })
            } else {
                quote!(#stream;)
            }
        }
    } else if !delegate && attr.field.is_optional {
        quote!(
            #pasync fn #attr_name(&self, exchange: &#krate::transport::exchange::Exchange<'_>) -> Result<#attr_type, #krate::error::Error> {
                Ok(None)
            }
        )
    } else {
        let strream = quote!(
            #pasync fn #attr_name(&self, exchange: &#krate::transport::exchange::Exchange<'_>) -> Result<#attr_type, #krate::error::Error>
        );

        if delegate {
            quote!(#strream { T::#attr_name(self, exchange)#sawait })
        } else {
            quote!(#strream;)
        }
    }
}

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

    let attr_type = field_type(
        &attr.field.field.data_type,
        attr.field.is_nullable,
        attr.field.is_optional,
        cluster,
        krate,
    );

    if !delegate && attr.field.is_optional {
        quote!(
            #pasync fn #attr_name(&self, exchange: &#krate::transport::exchange::Exchange<'_>, value: #attr_type) -> Result<(), #krate::error::Error> {
                Ok(())
            }
        )
    } else {
        let stream = quote!(
            #pasync fn #attr_name(&self, exchange: &#krate::transport::exchange::Exchange<'_>, value: #attr_type) -> Result<(), #krate::error::Error>
        );

        if delegate {
            quote!(#stream { T::#attr_name(self, exchange, value)#sawait })
        } else {
            quote!(#stream;)
        }
    }
}

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
        field_type_out(
            &DataType {
                name: output.clone(),
                is_list: false,
                max_length: None,
            },
            false,
            false,
            true,
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
                        exchange: &#krate::transport::exchange::Exchange<'_>,
                        request: #field_req,
                        response: #field_resp,
                    ) -> Result<P, #krate::error::Error>
                );

                if delegate {
                    quote!(#stream { T::#cmd_name(self, exchange, request, response)#sawait })
                } else {
                    quote!(#stream;)
                }
            } else {
                let stream = quote!(
                    #pasync fn #cmd_name(
                        &self,
                        exchange: &#krate::transport::exchange::Exchange<'_>,
                        request: #field_req,
                    ) -> Result<#field_resp, #krate::error::Error>
                );

                if delegate {
                    quote!(#stream { T::#cmd_name(self, exchange, request)#sawait })
                } else {
                    quote!(#stream;)
                }
            }
        } else {
            let stream = quote!(
                #pasync fn #cmd_name(
                    &self,
                    exchange: &#krate::transport::exchange::Exchange<'_>,
                    request: #field_req,
                ) -> Result<(), #krate::error::Error>
            );

            if delegate {
                quote!(#stream { T::#cmd_name(self, exchange, request)#sawait })
            } else {
                quote!(#stream;)
            }
        }
    } else if let Some((field_resp, field_resp_builder)) = field_resp {
        if field_resp_builder {
            let stream = quote!(
                #pasync fn #cmd_name<P: #krate::tlv::TLVBuilderParent>(
                    &self,
                    exchange: &#krate::transport::exchange::Exchange<'_>,
                    response: #field_resp,
                ) -> Result<P, #krate::error::Error>
            );

            if delegate {
                quote!(#stream { T::#cmd_name(self, exchange, response)#sawait })
            } else {
                quote!(#stream;)
            }
        } else {
            let stream = quote!(
                #pasync fn #cmd_name(
                    &self,
                    exchange: &#krate::transport::exchange::Exchange<'_>,
                ) -> Result<#field_resp, #krate::error::Error>
            );

            if delegate {
                quote!(#stream { T::#cmd_name(self, exchange)#sawait })
            } else {
                quote!(#stream;)
            }
        }
    } else {
        let stream = quote!(
            #pasync fn #cmd_name(
                &self,
                exchange: &#krate::transport::exchange::Exchange<'_>,
            ) -> Result<(), #krate::error::Error>
        );

        if delegate {
            quote!(#stream { T::#cmd_name(self, exchange)#sawait })
        } else {
            quote!(#stream;)
        }
    }
}

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

    let attr_method_name = Ident::new(
        &idl_field_name_to_rs_name(&attr.field.field.id),
        Span::call_site(),
    );

    let parent = quote!(P);
    let sawait = if asynch { quote!(.await) } else { quote!() };

    let (_, builder) = field_type_out(
        &attr.field.field.data_type,
        attr.field.is_nullable,
        attr.field.is_optional,
        true,
        parent,
        cluster,
        krate,
    );

    if builder {
        quote!(
            AttributeId::#attr_name => {
                self.0.#attr_method_name(exchange, #krate::tlv::TLVBuilder::new(
                    #krate::tlv::TLVWriteParent::new(writer.writer()),
                    &#krate::data_model::objects::AttrDataWriter::TAG,
                )?)#sawait?;

                writer.complete()
            }
        )
    } else {
        quote!(
            AttributeId::#attr_name => writer.set(self.0.#attr_method_name(exchange)#sawait?),
        )
    }
}

fn handler_adaptor_attribute_write_match(
    attr: &Attribute,
    asynch: bool,
    krate: &Ident,
) -> TokenStream {
    let attr_name = Ident::new(
        &idl_attribute_name_to_enum_variant_name(&attr.field.field.id),
        Span::call_site(),
    );

    let attr_method_name = Ident::new(
        &format!("set_{}", &idl_field_name_to_rs_name(&attr.field.field.id)),
        Span::call_site(),
    );

    let sawait = if asynch { quote!(.await) } else { quote!() };

    quote!(
        AttributeId::#attr_name => self.0.#attr_method_name(exchange, #krate::tlv::FromTLV::from_tlv(&data)?)#sawait?,
    )
}

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

    let cmd_method_name = Ident::new(
        &format!("handle_{}", &idl_field_name_to_rs_name(&cmd.id)),
        Span::call_site(),
    );

    let sawait = if asynch { quote!(.await) } else { quote!() };

    let field_req = cmd
        .input
        .as_ref()
        .map(|id| {
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
        })
        .is_some();

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
        let (_, builder) = field_type_out(
            &DataType {
                name: output.clone(),
                is_list: false,
                max_length: None,
            },
            false,
            false,
            true,
            quote!(P),
            cluster,
            krate,
        );

        (code as u32, builder)
    });

    if field_req {
        if let Some((field_resp_cmd_code, field_resp_builder)) = field_resp {
            if field_resp_builder {
                quote!(
                    CommandId::#cmd_name => {
                        let mut writer = encoder.with_command(#field_resp_cmd_code)?;

                        self.0.#cmd_method_name(
                            exchange,
                            #krate::tlv::FromTLV::from_tlv(&data)?,
                            #krate::tlv::TLVBuilder::new(
                                #krate::tlv::TLVWriteParent::new(writer.writer()),
                                &#krate::data_model::objects::AttrDataWriter::TAG,
                            )?
                        )#sawait?;

                        writer.complete()?
                    }
                )
            } else {
                quote!(
                    CommandId::#cmd_name => {
                        encoder
                            .with_command(#field_resp_cmd_code)?
                            .set(self.0.#cmd_method_name(
                                exchange
                                #krate::tlv::FromTLV::from_tlv(&data)?,
                            )#sawait?)?
                    }
                )
            }
        } else {
            quote!(
                CommandId::#cmd_name => self.0.#cmd_method_name(
                    exchange,
                    #krate::tlv::FromTLV::from_tlv(&data)?,
                )#sawait?,
            )
        }
    } else if let Some((field_resp_cmd_code, field_resp_builder)) = field_resp {
        if field_resp_builder {
            quote!(
                CommandId::#cmd_name => {
                    let mut writer = encoder.with_command(#field_resp_cmd_code)?;

                    self.0.#cmd_method_name(
                        exchange,
                        #krate::tlv::TLVBuilder::new(
                            #krate::tlv::TLVWriteParent::new(writer.writer()),
                            &#krate::data_model::objects::AttrDataWriter::TAG,
                        )?,
                    )#sawait?;

                    writer.complete()?
                }
            )
        } else {
            quote!(quote!(
                CommandId::#cmd_name => {
                    encoder
                        .with_command(#field_resp_cmd_code)?
                        .set(self.0.#cmd_method_name(exchange)#sawait?)?
                }
            ))
        }
    } else {
        quote!(
            CommandId::#cmd_name => self.0.#cmd_method_name(exchange)#sawait?,
        )
    }
}
