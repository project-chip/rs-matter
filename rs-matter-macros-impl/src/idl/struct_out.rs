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

use proc_macro2::{Ident, Literal, Span, TokenStream};
use quote::quote;

use rs_matter_data_model::{Cluster, Struct, StructField};

use super::field::field_type_out;
use super::id::idl_field_name_to_rs_name;
use super::struct_in::struct_field_comment;
use super::IdlGenerateContext;

pub fn struct_builders(cluster: &Cluster, context: &IdlGenerateContext) -> TokenStream {
    let struct_builders = cluster
        .structs
        .iter()
        .map(|s| struct_builder(s, cluster, context));

    quote!(
        #(#struct_builders)*
    )
}

pub fn struct_builder(s: &Struct, cluster: &Cluster, context: &IdlGenerateContext) -> TokenStream {
    let krate = context.rs_matter_crate.clone();

    let name = Ident::new(&format!("{}Builder", s.id), Span::call_site());
    let name_array = Ident::new(&format!("{}ArrayBuilder", s.id), Span::call_site());

    let start_code = s
        .fields
        .iter()
        .map(|field| field.field.code as usize)
        .next()
        .unwrap_or(0);
    let finish_code = s
        .fields
        .iter()
        .map(|field| field.field.code as usize)
        .max()
        .map(|code| code + 1)
        .unwrap_or(0);

    let fields = s
        .fields
        .iter()
        .zip(
            s.fields
                .iter()
                .skip(1)
                .map(|f| f.field.code as usize)
                .chain(core::iter::once(finish_code)),
        )
        .map(|(f, next_code)| struct_field_builder(f, cluster, name.clone(), next_code, context));

    quote!(
        pub struct #name<P, const F: usize = #start_code>(P);

        impl<P> #name<P>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            #[doc="Create a new instance of #name"]
            pub fn new(mut parent: P, tag: &#krate::tlv::TLVTag) -> Result<Self, #krate::error::Error> {
                use #krate::tlv::TLVWrite;

                parent.writer().start_struct(tag)?;

                Ok(Self(parent))
            }
        }

        #(#fields)*

        impl<P> #name<P, #finish_code>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            #[doc="Finish the builder"]
            pub fn finish(mut self) -> Result<P, #krate::error::Error> {
                use #krate::tlv::TLVWrite;

                self.0.writer().end_container()?;

                Ok(self.0)
            }
        }

        impl<P, const F: usize> #krate::tlv::TLVBuilderParent for #name<P, F>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            type Write = P::Write;

            fn writer(&mut self) -> &mut P::Write {
                self.0.writer()
            }

            fn into_writer(self) -> Self::Write {
                self.0.into_writer()
            }
        }

        impl<P> #krate::tlv::TLVBuilder<P> for #name<P>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            fn new(parent: P, tag: &#krate::tlv::TLVTag) -> Result<Self, #krate::error::Error> {
                Self::new(parent, tag)
            }

            fn into_writer(self) -> P::Write {
                self.0.into_writer()
            }
        }

        pub struct #name_array<P>(P);

        impl<P> #name_array<P>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            #[doc="Create a new instance of #name_array"]
            pub fn new(mut parent: P, tag: &#krate::tlv::TLVTag) -> Result<Self, #krate::error::Error> {
                use #krate::tlv::TLVWrite;

                parent.writer().start_array(tag)?;

                Ok(Self(parent))
            }

            #[doc="Push a new element into the array"]
            pub fn push(self) -> Result<#name<#name_array<P>>, #krate::error::Error> {
                #krate::tlv::TLVBuilder::new(#name_array(self.0), &#krate::tlv::TLVTag::Anonymous)
            }

            #[doc="Finish the array and return the parent"]
            pub fn finish(mut self) -> Result<P, #krate::error::Error> {
                use #krate::tlv::TLVWrite;

                self.0.writer().end_container()?;

                Ok(self.0)
            }
        }

        impl<P> #krate::tlv::TLVBuilderParent for #name_array<P>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            type Write = P::Write;

            fn writer(&mut self) -> &mut P::Write {
                self.0.writer()
            }

            fn into_writer(self) -> Self::Write {
                self.0.into_writer()
            }
        }

        impl<P> #krate::tlv::TLVBuilder<P> for #name_array<P>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            fn new(parent: P, tag: &#krate::tlv::TLVTag) -> Result<Self, #krate::error::Error> {
                Self::new(parent, tag)
            }

            fn into_writer(self) -> P::Write {
                self.0.into_writer()
            }
        }
    )
}

fn struct_field_builder(
    f: &StructField,
    cluster: &Cluster,
    parent_name: Ident,
    next_code: usize,
    context: &IdlGenerateContext,
) -> TokenStream {
    let doc_comment = struct_field_comment(f);
    let krate = context.rs_matter_crate.clone();

    let code = Literal::u8_unsuffixed(f.field.code as u8);

    let parent = quote!(#parent_name<P, #code>);
    let next_parent = quote!(#parent_name<P, #next_code>);

    let name = Ident::new(&idl_field_name_to_rs_name(&f.field.id), Span::call_site());

    let (field_type, builder) = field_type_out(
        &f.field.data_type,
        f.is_nullable,
        f.is_optional,
        false,
        quote!(P),
        cluster,
        &krate,
    );

    if builder {
        quote!(
            impl<P> #parent
            where
                P: #krate::tlv::TLVBuilderParent,
            {
                #doc_comment
                pub fn #name(self) -> Result<#field_type, #krate::error::Error> {
                    #krate::tlv::TLVBuilder::new(
                        #parent_name(self.0),
                        &#krate::tlv::TLVTag::Context(#code),
                    )
                }
            }
        )
    } else {
        quote!(
            impl<P> #parent
            where
                P: #krate::tlv::TLVBuilderParent,
            {
                #doc_comment
                pub fn #name(mut self, value: #field_type) -> Result<#next_parent, #krate::error::Error> {
                    #krate::tlv::ToTLV::to_tlv(
                        &value,
                        &#krate::tlv::TLVTag::Context(#code),
                        self.0.writer(),
                    )?;

                    Ok(#parent_name(self.0))
                }
            }
        )
    }
}
