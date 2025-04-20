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
use rs_matter_data_model::{Cluster, DataType, StructType};

use super::field::{field_type, field_type_out};
use super::id::{idl_attribute_name_to_enum_variant_name, idl_field_name_to_rs_name};
use super::IdlGenerateContext;

pub fn handler(cluster: &Cluster, context: &IdlGenerateContext) -> TokenStream {
    let krate = context.rs_matter_crate.clone();

    let handler_name = Ident::new(&format!("{}Handler", cluster.id), Span::call_site());

    let handler_attribute_methods = cluster.attributes
        .iter()
        .filter(|attr| attr.field.field.code < 0xf000) // TODO: Figure out the global attributes start
        .map(|attr| {
            let attr_name = Ident::new(
                &idl_field_name_to_rs_name(&attr.field.field.id),
                Span::call_site(),
            );

            let parent = quote!(P);

            let (attr_type, builder) = field_type_out(
                &attr.field.field.data_type,
                attr.field.is_nullable,
                attr.field.is_optional,
                true,
                parent,
                cluster,
                &krate,
            );

            if builder {
                if attr.field.is_optional {
                    quote!(
                        fn #attr_name<P: #krate::tlv::TLVBuilderParent>(&self, exchange: &#krate::transport::exchange::Exchange<'_>, builder: #attr_type) -> Result<P, #krate::error::Error> {
                            Ok(builder.none())
                        }
                    )
                } else {
                    quote!(
                        fn #attr_name<P: #krate::tlv::TLVBuilderParent>(&self, exchange: &#krate::transport::exchange::Exchange<'_>, builder: #attr_type) -> Result<P, #krate::error::Error>;
                    )
                }
            } else if attr.field.is_optional {
                quote!(
                    fn #attr_name(&self, exchange: &#krate::transport::exchange::Exchange<'_>, ) -> Result<#attr_type, #krate::error::Error> {
                        Ok(None)
                    }
                )
            } else {
                quote!(
                    fn #attr_name(&self, exchange: &#krate::transport::exchange::Exchange<'_>, ) -> Result<#attr_type, #krate::error::Error>;
                )
            }
        });

    let handler_attribute_write_methods = cluster
        .attributes
        .iter()
        .filter(|attr| attr.field.field.code < 0xf000) // TODO: Figure out the global attributes start
        .filter(|attr| !attr.is_read_only)
        .map(|attr| {
            let attr_name = Ident::new(
                &format!("set_{}", &idl_field_name_to_rs_name(&attr.field.field.id)),
                Span::call_site(),
            );

            let attr_type = field_type(
                &attr.field.field.data_type,
                attr.field.is_nullable,
                attr.field.is_optional,
                &krate,
            );

            if attr.field.is_optional {
                quote!(
                    fn #attr_name(&self, exchange: &#krate::transport::exchange::Exchange<'_>, value: #attr_type) -> Result<(), #krate::error::Error> {
                        Ok(())
                    }
                )
            } else {
                quote!(
                    fn #attr_name(&self, exchange: &#krate::transport::exchange::Exchange<'_>, value: #attr_type) -> Result<(), #krate::error::Error>;
                )
            }
        });

    let handler_command_methods = cluster.commands.iter().map(|cmd| {
        let cmd_name = Ident::new(
            &format!("handle_{}", &idl_field_name_to_rs_name(&cmd.id)),
            Span::call_site(),
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
                &krate,
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
                &krate,
            )
        });

        if let Some(field_req) = field_req {
            if let Some((field_resp, field_resp_builder)) = field_resp {
                if field_resp_builder {
                    quote!(
                        fn #cmd_name<P: #krate::tlv::TLVBuilderParent>(
                            &self,
                            exchange: &#krate::transport::exchange::Exchange<'_>,
                            request: #field_req,
                            response: #field_resp,
                        ) -> Result<P, #krate::error::Error>;
                    )
                } else {
                    quote!(
                        fn #cmd_name(
                            &self,
                            exchange: &#krate::transport::exchange::Exchange<'_>,
                            request: #field_req,
                        ) -> Result<#field_resp, #krate::error::Error>;
                    )
                }
            } else {
                quote!(
                    fn #cmd_name(
                        &self,
                        exchange: &#krate::transport::exchange::Exchange<'_>,
                        request: #field_req,
                    ) -> Result<(), #krate::error::Error>;
                )
            }
        } else if let Some((field_resp, field_resp_builder)) = field_resp {
            if field_resp_builder {
                quote!(
                    fn #cmd_name<P: #krate::tlv::TLVBuilderParent>(
                        &self,
                        exchange: &#krate::transport::exchange::Exchange<'_>,
                        response: #field_resp,
                    ) -> Result<P, #krate::error::Error>;
                )
            } else {
                quote!(
                    fn #cmd_name(
                        &self,
                        exchange: &#krate::transport::exchange::Exchange<'_>,
                    ) -> Result<#field_resp, #krate::error::Error>;
                )
            }
        } else {
            quote!(
                fn #cmd_name(
                    &self,
                    exchange: &#krate::transport::exchange::Exchange<'_>,
                ) -> Result<(), #krate::error::Error>;
            )
        }
    });

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

pub fn handler_adaptor(cluster: &Cluster, context: &IdlGenerateContext) -> TokenStream {
    let krate = context.rs_matter_crate.clone();

    let handler_name = Ident::new(&format!("{}Handler", cluster.id), Span::call_site());

    let handler_adaptor_attribute_match = cluster
        .attributes
        .iter()
        .filter(|attr| attr.field.field.code < 0xf000) // TODO: Figure out the global attributes start
        .map(|attr| {
            let attr_name = Ident::new(
                &idl_attribute_name_to_enum_variant_name(&attr.field.field.id),
                Span::call_site(),
            );

            let attr_method_name = Ident::new(
                &idl_field_name_to_rs_name(&attr.field.field.id),
                Span::call_site(),
            );

            let parent = quote!(P);

            let (_, builder) = field_type_out(
                &attr.field.field.data_type,
                attr.field.is_nullable,
                attr.field.is_optional,
                true,
                parent,
                cluster,
                &krate,
            );

            if builder {
                quote!(
                    AttributeId::#attr_name => {
                        self.0.#attr_method_name(exchange, #krate::tlv::TLVBuilder::new(
                            #krate::tlv::TLVWriteParent::new(writer.writer()),
                            &#krate::data_model::objects::AttrDataWriter::TAG,
                        )?)?;

                        writer.complete()
                    }
                )
            } else {
                quote!(
                    AttributeId::#attr_name => writer.set(self.0.#attr_method_name(exchange)?),
                )
            }
        });

    let handler_adaptor_attribute_write_match = cluster.attributes
        .iter()
        .filter(|attr| attr.field.field.code < 0xf000) // TODO: Figure out the global attributes start
        .filter(|attr| !attr.is_read_only)
        .map(|attr| {
            let attr_name = Ident::new(
                &idl_attribute_name_to_enum_variant_name(&attr.field.field.id),
                Span::call_site(),
            );

            let attr_method_name = Ident::new(
                &format!("set_{}", &idl_field_name_to_rs_name(&attr.field.field.id)),
                Span::call_site(),
            );

            quote!(
                AttributeId::#attr_name => self.0.#attr_method_name(exchange, #krate::tlv::FromTLV::from_tlv(&data)?)?,
            )
        });

    let handler_adaptor_command_match = cluster.commands.iter().map(|cmd| {
        let cmd_name = Ident::new(
            &idl_attribute_name_to_enum_variant_name(&cmd.id),
            Span::call_site(),
        );

        let cmd_method_name = Ident::new(
            &format!("handle_{}", &idl_field_name_to_rs_name(&cmd.id)),
            Span::call_site(),
        );

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
                    &krate,
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
                &krate,
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
                            )?;

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
                                )?)?
                        }
                    )
                }
            } else {
                quote!(
                    CommandId::#cmd_name => self.0.#cmd_method_name(
                        exchange,
                        #krate::tlv::FromTLV::from_tlv(&data)?,
                    )?,
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
                        )?;

                        writer.complete()?
                    }
                )
            } else {
                quote!(quote!(
                    CommandId::#cmd_name => {
                        encoder
                            .with_command(#field_resp_cmd_code)?
                            .set(self.0.#cmd_method_name(exchange)?)?
                    }
                ))
            }
        } else {
            quote!(
                CommandId::#cmd_name => self.0.#cmd_method_name(exchange)?,
            )
        }
    });

    let handler_adaptor_name =
        Ident::new(&format!("{}HandlerAdaptor", cluster.id), Span::call_site());

    quote!(
        pub struct #handler_adaptor_name<T>(T);

        impl<T> #handler_adaptor_name<T> {
            pub const fn new(handler: T) -> Self {
                Self(handler)
            }
        }

        impl<T> #krate::data_model::objects::Handler for #handler_adaptor_name<T>
        where
            T: #handler_name,
        {
            fn read(
                &self,
                exchange: &#krate::transport::exchange::Exchange,
                attr: &#krate::data_model::objects::AttrDetails,
                encoder: #krate::data_model::objects::AttrDataEncoder,
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
            fn write(
                &self,
                exchange: &#krate::transport::exchange::Exchange,
                attr: &#krate::data_model::objects::AttrDetails,
                data: #krate::data_model::objects::AttrData,
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
            fn invoke(
                &self,
                exchange: &#krate::transport::exchange::Exchange,
                cmd: &#krate::data_model::objects::CmdDetails,
                data: &#krate::tlv::TLVElement,
                encoder: #krate::data_model::objects::CmdDataEncoder,
            ) -> Result<(), #krate::error::Error> {
                match CommandId::try_from(cmd.cmd_id)? {
                    #(#handler_adaptor_command_match)*
                    _ => return Err(#krate::error::ErrorCode::CommandNotFound.into()),
                }

                self.0.dataver_changed();

                Ok(())
            }
        }

        impl<T> #krate::data_model::objects::NonBlockingHandler for #handler_adaptor_name<T>
        where
            T: #handler_name,
        {}
    )
}
