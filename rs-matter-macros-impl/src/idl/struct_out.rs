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

//! A module for generating Rust builder types corresponding to structures
//! in an IDL cluster.

use proc_macro2::{Ident, Literal, Span, TokenStream};
use quote::quote;

use rs_matter_data_model::{Cluster, Struct, StructField};

use super::field::{field_type_builder, BuilderPolicy};
use super::id::idl_field_name_to_rs_name;
use super::struct_in::struct_field_comment;
use super::IdlGenerateContext;

/// Return the token stream of all structure builders corresponding
/// to the structures defined by the provided IDL cluster.
pub fn struct_builders(cluster: &Cluster, context: &IdlGenerateContext) -> TokenStream {
    let struct_builders = cluster
        .structs
        .iter()
        .map(|s| struct_builder(s, cluster, context));

    quote!(
        #(#struct_builders)*
    )
}

/// Return the token stream of the structure builder corresponding
/// to the provided IDL structure.
///
/// This function also returns a builder for an array of elements of type this structure.
///
/// # Arguments
/// - `s`: The IDL structure.
/// - `cluster`: The IDL cluster to which the structure belongs.
/// - `context`: The IDL generation context.
pub fn struct_builder(s: &Struct, cluster: &Cluster, context: &IdlGenerateContext) -> TokenStream {
    let krate = context.rs_matter_crate.clone();

    let name = Ident::new(&format!("{}Builder", s.id), Span::call_site());
    let name_str = Literal::string(&s.id);
    let name_array = Ident::new(&format!("{}ArrayBuilder", s.id), Span::call_site());
    let name_array_str = Literal::string(&format!("{}[]", s.id));

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
            #[doc="Create a new instance"]
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
            #[doc="Finish the struct and return the parent"]
            pub fn end(mut self) -> Result<P, #krate::error::Error> {
                use #krate::tlv::TLVWrite;

                self.0.writer().end_container()?;

                Ok(self.0)
            }
        }

        impl<P, const F: usize> core::fmt::Debug for #name<P, F>
        where
            P: core::fmt::Debug,
        {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{:?}::{}", self.0, #name_str)
            }
        }

        #[cfg(feature = "defmt")]
        impl<P, const F: usize> defmt::Format for #name<P, F>
        where
            P: defmt::Format,
        {
            fn format(&self, f: defmt::Formatter<'_>) {
                defmt::write!(f, "{:?}::{}", self.0, #name_str)
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
        }

        impl<P> #krate::tlv::TLVBuilder<P> for #name<P>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            fn new(parent: P, tag: &#krate::tlv::TLVTag) -> Result<Self, #krate::error::Error> {
                Self::new(parent, tag)
            }

            fn unchecked_into_parent(self) -> P {
                self.0
            }
        }

        pub struct #name_array<P>(P);

        impl<P> #name_array<P>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            #[doc="Create a new instance"]
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
            pub fn end(mut self) -> Result<P, #krate::error::Error> {
                use #krate::tlv::TLVWrite;

                self.0.writer().end_container()?;

                Ok(self.0)
            }
        }

        impl<P> core::fmt::Debug for #name_array<P>
        where
            P: core::fmt::Debug,
        {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{:?}::{}", self.0, #name_array_str)
            }
        }

        #[cfg(feature = "defmt")]
        impl<P> defmt::Format for #name_array<P>
        where
            P: defmt::Format,
        {
            fn format(&self, f: defmt::Formatter<'_>) {
                defmt::write!(f, "{:?}::{}", self.0, #name_array_str)
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
        }

        impl<P> #krate::tlv::TLVBuilder<P> for #name_array<P>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            fn new(parent: P, tag: &#krate::tlv::TLVTag) -> Result<Self, #krate::error::Error> {
                Self::new(parent, tag)
            }

            fn unchecked_into_parent(self) -> P {
                self.0
            }
        }
    )
}

/// Return the token stream of the structure field builder corresponding
/// to the provided IDL structure field.
///
/// # Arguments
/// - `f`: The IDL structure field.
/// - `cluster`: The IDL cluster to which the structure of this field belongs.
/// - `parent_name`: The name of the parent structure builder.
/// - `next_code`: The code (tag context ID) of the next field in the structure.
/// - `context`: The IDL generation context.
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
    let name_str = Literal::string(&f.field.id);

    let (field_type, builder) = field_type_builder(
        &f.field.data_type,
        f.is_nullable,
        f.is_optional,
        BuilderPolicy::NonCopy,
        next_parent.clone(),
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
            #[cfg(feature = "defmt")]
            impl<P> #parent
            where
                P: #krate::tlv::TLVBuilderParent + core::fmt::Debug + defmt::Format,
            {
                #doc_comment
                pub fn #name(mut self, value: #field_type) -> Result<#next_parent, #krate::error::Error> {
                    #[cfg(feature = "defmt")]
                    defmt::info!("{:?}::{} -> {:?} +", self, #name_str, value);
                    #[cfg(feature = "log")]
                    ::log::info!("{:?}::{} -> {:?} +", self, #name_str, value);

                    #krate::tlv::ToTLV::to_tlv(
                        &value,
                        &#krate::tlv::TLVTag::Context(#code),
                        self.0.writer(),
                    )?;

                    Ok(#parent_name(self.0))
                }
            }

            #[cfg(not(feature = "defmt"))]
            impl<P> #parent
            where
                P: #krate::tlv::TLVBuilderParent + core::fmt::Debug,
            {
                #doc_comment
                pub fn #name(mut self, value: #field_type) -> Result<#next_parent, #krate::error::Error> {
                    #[cfg(feature = "log")]
                    ::log::info!("{:?}::{} -> {:?} +", self, #name_str, value);

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

#[cfg(test)]
mod tests {
    use crate::idl::tests::{get_cluster_named, parse_idl};
    use crate::idl::IdlGenerateContext;

    use assert_tokenstreams_eq::assert_tokenstreams_eq;
    use quote::quote;

    use super::struct_builders;

    #[test]
    fn test_structs() {
        let idl = parse_idl(
            "
              cluster TestForStructs = 1 {

                // a somewhat complex struct
                struct NetworkInfoStruct {
                  boolean connected = 1;
                  optional int8u test_optional = 2;
                  nullable int16u test_nullable = 3;
                  optional nullable int32u test_both = 4;
                }

                // Some varying requests
                request struct IdentifyRequest {
                  int16u identifyTime = 0;
                }

                request struct SomeRequest {
                  group_id group = 0;
                }

                // Some responses
                response struct TestResponse = 0 {
                  int8u capacity = 0;
                }

                response struct AnotherResponse = 1 {
                  enum8 status = 0;
                  group_id groupID = 12;
                }
              }
            ",
        );

        let cluster = get_cluster_named(&idl, "TestForStructs").expect("Cluster exists");
        let context = IdlGenerateContext::new("rs_matter_crate");

        // panic!("====\n{}\n====", &struct_builders(cluster, &context));

        assert_tokenstreams_eq!(
            &struct_builders(cluster, &context),
            &quote!(
                pub struct NetworkInfoStructBuilder<P, const F: usize = 1usize>(P);

                impl<P> NetworkInfoStructBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    #[doc = "Create a new instance"]
                    pub fn new(
                        mut parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        parent.writer().start_struct(tag)?;
                        Ok(Self(parent))
                    }
                }

                impl<P> NetworkInfoStructBuilder<P, 1>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    pub fn connected(
                        mut self,
                        value: bool,
                    ) -> Result<NetworkInfoStructBuilder<P, 2usize>, rs_matter_crate::error::Error>
                    {
                        rs_matter_crate::tlv::ToTLV::to_tlv(
                            &value,
                            &rs_matter_crate::tlv::TLVTag::Context(1),
                            self.0.writer(),
                        )?;
                        Ok(NetworkInfoStructBuilder(self.0))
                    }
                }

                impl<P> NetworkInfoStructBuilder<P, 2>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    pub fn test_optional(
                        mut self,
                        value: Option<u8>,
                    ) -> Result<NetworkInfoStructBuilder<P, 3usize>, rs_matter_crate::error::Error>
                    {
                        rs_matter_crate::tlv::ToTLV::to_tlv(
                            &value,
                            &rs_matter_crate::tlv::TLVTag::Context(2),
                            self.0.writer(),
                        )?;
                        Ok(NetworkInfoStructBuilder(self.0))
                    }
                }

                impl<P> NetworkInfoStructBuilder<P, 3>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    pub fn test_nullable(
                        mut self,
                        value: rs_matter_crate::tlv::Nullable<u16>,
                    ) -> Result<NetworkInfoStructBuilder<P, 4usize>, rs_matter_crate::error::Error>
                    {
                        rs_matter_crate::tlv::ToTLV::to_tlv(
                            &value,
                            &rs_matter_crate::tlv::TLVTag::Context(3),
                            self.0.writer(),
                        )?;
                        Ok(NetworkInfoStructBuilder(self.0))
                    }
                }

                impl<P> NetworkInfoStructBuilder<P, 4>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    pub fn test_both(
                        mut self,
                        value: Option<rs_matter_crate::tlv::Nullable<u32>>,
                    ) -> Result<NetworkInfoStructBuilder<P, 5usize>, rs_matter_crate::error::Error>
                    {
                        rs_matter_crate::tlv::ToTLV::to_tlv(
                            &value,
                            &rs_matter_crate::tlv::TLVTag::Context(4),
                            self.0.writer(),
                        )?;
                        Ok(NetworkInfoStructBuilder(self.0))
                    }
                }

                impl<P> NetworkInfoStructBuilder<P, 5usize>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    #[doc = "Finish the struct and return the parent"]
                    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        self.0.writer().end_container()?;
                        Ok(self.0)
                    }
                }

                impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent for NetworkInfoStructBuilder<P, F>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    type Write = P::Write;
                    fn writer(&mut self) -> &mut P::Write {
                        self.0.writer()
                    }
                }

                impl<P> rs_matter_crate::tlv::TLVBuilder<P> for NetworkInfoStructBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn new(
                        parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        Self::new(parent, tag)
                    }
                    fn unchecked_into_parent(self) -> P {
                        self.0
                    }
                }

                pub struct NetworkInfoStructArrayBuilder<P>(P);

                impl<P> NetworkInfoStructArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    #[doc = "Create a new instance"]
                    pub fn new(
                        mut parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        parent.writer().start_array(tag)?;
                        Ok(Self(parent))
                    }

                    #[doc = "Push a new element into the array"]
                    pub fn push(
                        self,
                    ) -> Result<
                        NetworkInfoStructBuilder<NetworkInfoStructArrayBuilder<P>>,
                        rs_matter_crate::error::Error,
                    > {
                        rs_matter_crate::tlv::TLVBuilder::new(
                            NetworkInfoStructArrayBuilder(self.0),
                            &rs_matter_crate::tlv::TLVTag::Anonymous,
                        )
                    }

                    #[doc = "Finish the array and return the parent"]
                    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        self.0.writer().end_container()?;
                        Ok(self.0)
                    }
                }

                impl<P> rs_matter_crate::tlv::TLVBuilderParent for NetworkInfoStructArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    type Write = P::Write;
                    fn writer(&mut self) -> &mut P::Write {
                        self.0.writer()
                    }
                }

                impl<P> rs_matter_crate::tlv::TLVBuilder<P> for NetworkInfoStructArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn new(
                        parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        Self::new(parent, tag)
                    }
                    fn unchecked_into_parent(self) -> P {
                        self.0
                    }
                }

                pub struct IdentifyRequestBuilder<P, const F: usize = 0usize>(P);

                impl<P> IdentifyRequestBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    #[doc = "Create a new instance"]
                    pub fn new(
                        mut parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        parent.writer().start_struct(tag)?;
                        Ok(Self(parent))
                    }
                }

                impl<P> IdentifyRequestBuilder<P, 0>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    pub fn identify_time(
                        mut self,
                        value: u16,
                    ) -> Result<IdentifyRequestBuilder<P, 1usize>, rs_matter_crate::error::Error>
                    {
                        rs_matter_crate::tlv::ToTLV::to_tlv(
                            &value,
                            &rs_matter_crate::tlv::TLVTag::Context(0),
                            self.0.writer(),
                        )?;
                        Ok(IdentifyRequestBuilder(self.0))
                    }
                }

                impl<P> IdentifyRequestBuilder<P, 1usize>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    #[doc = "Finish the struct and return the parent"]
                    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        self.0.writer().end_container()?;
                        Ok(self.0)
                    }
                }

                impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent for IdentifyRequestBuilder<P, F>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    type Write = P::Write;
                    fn writer(&mut self) -> &mut P::Write {
                        self.0.writer()
                    }
                }

                impl<P> rs_matter_crate::tlv::TLVBuilder<P> for IdentifyRequestBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn new(
                        parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        Self::new(parent, tag)
                    }
                    fn unchecked_into_parent(self) -> P {
                        self.0
                    }
                }

                pub struct IdentifyRequestArrayBuilder<P>(P);

                impl<P> IdentifyRequestArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    #[doc = "Create a new instance"]
                    pub fn new(
                        mut parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        parent.writer().start_array(tag)?;
                        Ok(Self(parent))
                    }

                    #[doc = "Push a new element into the array"]
                    pub fn push(
                        self,
                    ) -> Result<
                        IdentifyRequestBuilder<IdentifyRequestArrayBuilder<P>>,
                        rs_matter_crate::error::Error,
                    > {
                        rs_matter_crate::tlv::TLVBuilder::new(
                            IdentifyRequestArrayBuilder(self.0),
                            &rs_matter_crate::tlv::TLVTag::Anonymous,
                        )
                    }

                    #[doc = "Finish the array and return the parent"]
                    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        self.0.writer().end_container()?;
                        Ok(self.0)
                    }
                }

                impl<P> rs_matter_crate::tlv::TLVBuilderParent for IdentifyRequestArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    type Write = P::Write;
                    fn writer(&mut self) -> &mut P::Write {
                        self.0.writer()
                    }
                }

                impl<P> rs_matter_crate::tlv::TLVBuilder<P> for IdentifyRequestArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn new(
                        parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        Self::new(parent, tag)
                    }
                    fn unchecked_into_parent(self) -> P {
                        self.0
                    }
                }

                pub struct SomeRequestBuilder<P, const F: usize = 0usize>(P);

                impl<P> SomeRequestBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    #[doc = "Create a new instance"]
                    pub fn new(
                        mut parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        parent.writer().start_struct(tag)?;
                        Ok(Self(parent))
                    }
                }

                impl<P> SomeRequestBuilder<P, 0>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    pub fn group(
                        mut self,
                        value: u16,
                    ) -> Result<SomeRequestBuilder<P, 1usize>, rs_matter_crate::error::Error>
                    {
                        rs_matter_crate::tlv::ToTLV::to_tlv(
                            &value,
                            &rs_matter_crate::tlv::TLVTag::Context(0),
                            self.0.writer(),
                        )?;
                        Ok(SomeRequestBuilder(self.0))
                    }
                }

                impl<P> SomeRequestBuilder<P, 1usize>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    #[doc = "Finish the struct and return the parent"]
                    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        self.0.writer().end_container()?;
                        Ok(self.0)
                    }
                }

                impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent for SomeRequestBuilder<P, F>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    type Write = P::Write;
                    fn writer(&mut self) -> &mut P::Write {
                        self.0.writer()
                    }
                }

                impl<P> rs_matter_crate::tlv::TLVBuilder<P> for SomeRequestBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn new(
                        parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        Self::new(parent, tag)
                    }
                    fn unchecked_into_parent(self) -> P {
                        self.0
                    }
                }

                pub struct SomeRequestArrayBuilder<P>(P);

                impl<P> SomeRequestArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    #[doc = "Create a new instance"]
                    pub fn new(
                        mut parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        parent.writer().start_array(tag)?;
                        Ok(Self(parent))
                    }

                    #[doc = "Push a new element into the array"]
                    pub fn push(
                        self,
                    ) -> Result<
                        SomeRequestBuilder<SomeRequestArrayBuilder<P>>,
                        rs_matter_crate::error::Error,
                    > {
                        rs_matter_crate::tlv::TLVBuilder::new(
                            SomeRequestArrayBuilder(self.0),
                            &rs_matter_crate::tlv::TLVTag::Anonymous,
                        )
                    }

                    #[doc = "Finish the array and return the parent"]
                    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        self.0.writer().end_container()?;
                        Ok(self.0)
                    }
                }

                impl<P> rs_matter_crate::tlv::TLVBuilderParent for SomeRequestArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    type Write = P::Write;
                    fn writer(&mut self) -> &mut P::Write {
                        self.0.writer()
                    }
                }

                impl<P> rs_matter_crate::tlv::TLVBuilder<P> for SomeRequestArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn new(
                        parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        Self::new(parent, tag)
                    }
                    fn unchecked_into_parent(self) -> P {
                        self.0
                    }
                }

                pub struct TestResponseBuilder<P, const F: usize = 0usize>(P);

                impl<P> TestResponseBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    #[doc = "Create a new instance"]
                    pub fn new(
                        mut parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        parent.writer().start_struct(tag)?;
                        Ok(Self(parent))
                    }
                }

                impl<P> TestResponseBuilder<P, 0>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    pub fn capacity(
                        mut self,
                        value: u8,
                    ) -> Result<TestResponseBuilder<P, 1usize>, rs_matter_crate::error::Error>
                    {
                        rs_matter_crate::tlv::ToTLV::to_tlv(
                            &value,
                            &rs_matter_crate::tlv::TLVTag::Context(0),
                            self.0.writer(),
                        )?;
                        Ok(TestResponseBuilder(self.0))
                    }
                }

                impl<P> TestResponseBuilder<P, 1usize>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    #[doc = "Finish the struct and return the parent"]
                    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        self.0.writer().end_container()?;
                        Ok(self.0)
                    }
                }

                impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent for TestResponseBuilder<P, F>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    type Write = P::Write;
                    fn writer(&mut self) -> &mut P::Write {
                        self.0.writer()
                    }
                }

                impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestResponseBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn new(
                        parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        Self::new(parent, tag)
                    }
                    fn unchecked_into_parent(self) -> P {
                        self.0
                    }
                }

                pub struct TestResponseArrayBuilder<P>(P);

                impl<P> TestResponseArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    #[doc = "Create a new instance"]
                    pub fn new(
                        mut parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        parent.writer().start_array(tag)?;
                        Ok(Self(parent))
                    }

                    #[doc = "Push a new element into the array"]
                    pub fn push(
                        self,
                    ) -> Result<
                        TestResponseBuilder<TestResponseArrayBuilder<P>>,
                        rs_matter_crate::error::Error,
                    > {
                        rs_matter_crate::tlv::TLVBuilder::new(
                            TestResponseArrayBuilder(self.0),
                            &rs_matter_crate::tlv::TLVTag::Anonymous,
                        )
                    }

                    #[doc = "Finish the array and return the parent"]
                    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        self.0.writer().end_container()?;
                        Ok(self.0)
                    }
                }

                impl<P> rs_matter_crate::tlv::TLVBuilderParent for TestResponseArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    type Write = P::Write;
                    fn writer(&mut self) -> &mut P::Write {
                        self.0.writer()
                    }
                }

                impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestResponseArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn new(
                        parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        Self::new(parent, tag)
                    }

                    fn unchecked_into_parent(self) -> P {
                        self.0
                    }
                }

                pub struct AnotherResponseBuilder<P, const F: usize = 0usize>(P);

                impl<P> AnotherResponseBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    #[doc = "Create a new instance"]
                    pub fn new(
                        mut parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        parent.writer().start_struct(tag)?;
                        Ok(Self(parent))
                    }
                }

                impl<P> AnotherResponseBuilder<P, 0>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    pub fn status(
                        mut self,
                        value: u8,
                    ) -> Result<AnotherResponseBuilder<P, 12usize>, rs_matter_crate::error::Error>
                    {
                        rs_matter_crate::tlv::ToTLV::to_tlv(
                            &value,
                            &rs_matter_crate::tlv::TLVTag::Context(0),
                            self.0.writer(),
                        )?;
                        Ok(AnotherResponseBuilder(self.0))
                    }
                }

                impl<P> AnotherResponseBuilder<P, 12>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    pub fn group_id(
                        mut self,
                        value: u16,
                    ) -> Result<AnotherResponseBuilder<P, 13usize>, rs_matter_crate::error::Error>
                    {
                        rs_matter_crate::tlv::ToTLV::to_tlv(
                            &value,
                            &rs_matter_crate::tlv::TLVTag::Context(12),
                            self.0.writer(),
                        )?;
                        Ok(AnotherResponseBuilder(self.0))
                    }
                }

                impl<P> AnotherResponseBuilder<P, 13usize>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    #[doc = "Finish the struct and return the parent"]
                    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        self.0.writer().end_container()?;
                        Ok(self.0)
                    }
                }

                impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent for AnotherResponseBuilder<P, F>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    type Write = P::Write;
                    fn writer(&mut self) -> &mut P::Write {
                        self.0.writer()
                    }
                }

                impl<P> rs_matter_crate::tlv::TLVBuilder<P> for AnotherResponseBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn new(
                        parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        Self::new(parent, tag)
                    }
                    fn unchecked_into_parent(self) -> P {
                        self.0
                    }
                }

                pub struct AnotherResponseArrayBuilder<P>(P);

                impl<P> AnotherResponseArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    #[doc = "Create a new instance"]
                    pub fn new(
                        mut parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        parent.writer().start_array(tag)?;
                        Ok(Self(parent))
                    }

                    #[doc = "Push a new element into the array"]
                    pub fn push(
                        self,
                    ) -> Result<
                        AnotherResponseBuilder<AnotherResponseArrayBuilder<P>>,
                        rs_matter_crate::error::Error,
                    > {
                        rs_matter_crate::tlv::TLVBuilder::new(
                            AnotherResponseArrayBuilder(self.0),
                            &rs_matter_crate::tlv::TLVTag::Anonymous,
                        )
                    }

                    #[doc = "Finish the array and return the parent"]
                    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        self.0.writer().end_container()?;
                        Ok(self.0)
                    }
                }

                impl<P> rs_matter_crate::tlv::TLVBuilderParent for AnotherResponseArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    type Write = P::Write;

                    fn writer(&mut self) -> &mut P::Write {
                        self.0.writer()
                    }
                }

                impl<P> rs_matter_crate::tlv::TLVBuilder<P> for AnotherResponseArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn new(
                        parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        Self::new(parent, tag)
                    }

                    fn unchecked_into_parent(self) -> P {
                        self.0
                    }
                }
            )
        );
    }

    #[test]
    fn test_on_off_structs() {
        let idl = parse_idl(
            "
              cluster OnOff = 6 {
                revision 6;

                request struct OffWithEffectRequest {
                  EffectIdentifierEnum effectIdentifier = 0;
                  enum8 effectVariant = 1;
                }

                request struct OnWithTimedOffRequest {
                  OnOffControlBitmap onOffControl = 0;
                  int16u onTime = 1;
                  int16u offWaitTime = 2;
                }
              }
        ",
        );

        let cluster = get_cluster_named(&idl, "OnOff").expect("Cluster exists");
        let context = IdlGenerateContext::new("rs_matter_crate");

        // panic!("====\n{}\n====", &struct_builders(cluster, &context));

        assert_tokenstreams_eq!(
            &struct_builders(cluster, &context),
            &quote!(
                pub struct OffWithEffectRequestBuilder<P, const F: usize = 0usize>(P);
                impl<P> OffWithEffectRequestBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    #[doc = "Create a new instance"]
                    pub fn new(
                        mut parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        parent.writer().start_struct(tag)?;
                        Ok(Self(parent))
                    }
                }
                impl<P> OffWithEffectRequestBuilder<P, 0>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    pub fn effect_identifier(
                        mut self,
                        value: EffectIdentifierEnum,
                    ) -> Result<OffWithEffectRequestBuilder<P, 1usize>, rs_matter_crate::error::Error>
                    {
                        rs_matter_crate::tlv::ToTLV::to_tlv(
                            &value,
                            &rs_matter_crate::tlv::TLVTag::Context(0),
                            self.0.writer(),
                        )?;
                        Ok(OffWithEffectRequestBuilder(self.0))
                    }
                }
                impl<P> OffWithEffectRequestBuilder<P, 1>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    pub fn effect_variant(
                        mut self,
                        value: u8,
                    ) -> Result<OffWithEffectRequestBuilder<P, 2usize>, rs_matter_crate::error::Error>
                    {
                        rs_matter_crate::tlv::ToTLV::to_tlv(
                            &value,
                            &rs_matter_crate::tlv::TLVTag::Context(1),
                            self.0.writer(),
                        )?;
                        Ok(OffWithEffectRequestBuilder(self.0))
                    }
                }
                impl<P> OffWithEffectRequestBuilder<P, 2usize>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    #[doc = "Finish the struct and return the parent"]
                    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        self.0.writer().end_container()?;
                        Ok(self.0)
                    }
                }
                impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent for OffWithEffectRequestBuilder<P, F>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    type Write = P::Write;
                    fn writer(&mut self) -> &mut P::Write {
                        self.0.writer()
                    }
                }
                impl<P> rs_matter_crate::tlv::TLVBuilder<P> for OffWithEffectRequestBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn new(
                        parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        Self::new(parent, tag)
                    }
                    fn unchecked_into_parent(self) -> P {
                        self.0
                    }
                }
                pub struct OffWithEffectRequestArrayBuilder<P>(P);
                impl<P> OffWithEffectRequestArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    #[doc = "Create a new instance"]
                    pub fn new(
                        mut parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        parent.writer().start_array(tag)?;
                        Ok(Self(parent))
                    }
                    #[doc = "Push a new element into the array"]
                    pub fn push(
                        self,
                    ) -> Result<
                        OffWithEffectRequestBuilder<OffWithEffectRequestArrayBuilder<P>>,
                        rs_matter_crate::error::Error,
                    > {
                        rs_matter_crate::tlv::TLVBuilder::new(
                            OffWithEffectRequestArrayBuilder(self.0),
                            &rs_matter_crate::tlv::TLVTag::Anonymous,
                        )
                    }
                    #[doc = "Finish the array and return the parent"]
                    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        self.0.writer().end_container()?;
                        Ok(self.0)
                    }
                }
                impl<P> rs_matter_crate::tlv::TLVBuilderParent for OffWithEffectRequestArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    type Write = P::Write;
                    fn writer(&mut self) -> &mut P::Write {
                        self.0.writer()
                    }
                }
                impl<P> rs_matter_crate::tlv::TLVBuilder<P> for OffWithEffectRequestArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn new(
                        parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        Self::new(parent, tag)
                    }
                    fn unchecked_into_parent(self) -> P {
                        self.0
                    }
                }
                pub struct OnWithTimedOffRequestBuilder<P, const F: usize = 0usize>(P);
                impl<P> OnWithTimedOffRequestBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    #[doc = "Create a new instance"]
                    pub fn new(
                        mut parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        parent.writer().start_struct(tag)?;
                        Ok(Self(parent))
                    }
                }
                impl<P> OnWithTimedOffRequestBuilder<P, 0>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    pub fn on_off_control(
                        mut self,
                        value: OnOffControlBitmap,
                    ) -> Result<
                        OnWithTimedOffRequestBuilder<P, 1usize>,
                        rs_matter_crate::error::Error,
                    > {
                        rs_matter_crate::tlv::ToTLV::to_tlv(
                            &value,
                            &rs_matter_crate::tlv::TLVTag::Context(0),
                            self.0.writer(),
                        )?;
                        Ok(OnWithTimedOffRequestBuilder(self.0))
                    }
                }
                impl<P> OnWithTimedOffRequestBuilder<P, 1>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    pub fn on_time(
                        mut self,
                        value: u16,
                    ) -> Result<
                        OnWithTimedOffRequestBuilder<P, 2usize>,
                        rs_matter_crate::error::Error,
                    > {
                        rs_matter_crate::tlv::ToTLV::to_tlv(
                            &value,
                            &rs_matter_crate::tlv::TLVTag::Context(1),
                            self.0.writer(),
                        )?;
                        Ok(OnWithTimedOffRequestBuilder(self.0))
                    }
                }
                impl<P> OnWithTimedOffRequestBuilder<P, 2>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    pub fn off_wait_time(
                        mut self,
                        value: u16,
                    ) -> Result<
                        OnWithTimedOffRequestBuilder<P, 3usize>,
                        rs_matter_crate::error::Error,
                    > {
                        rs_matter_crate::tlv::ToTLV::to_tlv(
                            &value,
                            &rs_matter_crate::tlv::TLVTag::Context(2),
                            self.0.writer(),
                        )?;
                        Ok(OnWithTimedOffRequestBuilder(self.0))
                    }
                }
                impl<P> OnWithTimedOffRequestBuilder<P, 3usize>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    #[doc = "Finish the struct and return the parent"]
                    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        self.0.writer().end_container()?;
                        Ok(self.0)
                    }
                }
                impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
                    for OnWithTimedOffRequestBuilder<P, F>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    type Write = P::Write;
                    fn writer(&mut self) -> &mut P::Write {
                        self.0.writer()
                    }
                }
                impl<P> rs_matter_crate::tlv::TLVBuilder<P> for OnWithTimedOffRequestBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn new(
                        parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        Self::new(parent, tag)
                    }
                    fn unchecked_into_parent(self) -> P {
                        self.0
                    }
                }
                pub struct OnWithTimedOffRequestArrayBuilder<P>(P);
                impl<P> OnWithTimedOffRequestArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    #[doc = "Create a new instance"]
                    pub fn new(
                        mut parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        parent.writer().start_array(tag)?;
                        Ok(Self(parent))
                    }
                    #[doc = "Push a new element into the array"]
                    pub fn push(
                        self,
                    ) -> Result<
                        OnWithTimedOffRequestBuilder<OnWithTimedOffRequestArrayBuilder<P>>,
                        rs_matter_crate::error::Error,
                    > {
                        rs_matter_crate::tlv::TLVBuilder::new(
                            OnWithTimedOffRequestArrayBuilder(self.0),
                            &rs_matter_crate::tlv::TLVTag::Anonymous,
                        )
                    }
                    #[doc = "Finish the array and return the parent"]
                    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        self.0.writer().end_container()?;
                        Ok(self.0)
                    }
                }
                impl<P> rs_matter_crate::tlv::TLVBuilderParent for OnWithTimedOffRequestArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    type Write = P::Write;
                    fn writer(&mut self) -> &mut P::Write {
                        self.0.writer()
                    }
                }
                impl<P> rs_matter_crate::tlv::TLVBuilder<P> for OnWithTimedOffRequestArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn new(
                        parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        Self::new(parent, tag)
                    }
                    fn unchecked_into_parent(self) -> P {
                        self.0
                    }
                }
            )
        );
    }

    #[test]
    fn struct_fields_string() {
        let idl = parse_idl(
            "
              cluster TestForStructs = 1 {
                struct WithStringMember {
                  char_string<16> short_string = 1;
                  long_char_string<512> long_string = 2;
                  optional char_string<32> opt_str = 3;
                  optional nullable long_char_string<512> opt_nul_str = 4;
                }
              }
            ",
        );

        let cluster = get_cluster_named(&idl, "TestForStructs").expect("Cluster exists");
        let context = IdlGenerateContext::new("rs_matter_crate");

        // panic!("====\n{}\n====", &struct_builders(cluster, &context));

        assert_tokenstreams_eq!(
            &struct_builders(cluster, &context),
            &quote!(
                pub struct WithStringMemberBuilder<P, const F: usize = 1usize>(P);
                impl<P> WithStringMemberBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    #[doc = "Create a new instance"]
                    pub fn new(
                        mut parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        parent.writer().start_struct(tag)?;
                        Ok(Self(parent))
                    }
                }
                impl<P> WithStringMemberBuilder<P, 1>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    pub fn short_string(
                        mut self,
                        value: rs_matter_crate::tlv::Utf8Str<'_>,
                    ) -> Result<WithStringMemberBuilder<P, 2usize>, rs_matter_crate::error::Error>
                    {
                        rs_matter_crate::tlv::ToTLV::to_tlv(
                            &value,
                            &rs_matter_crate::tlv::TLVTag::Context(1),
                            self.0.writer(),
                        )?;
                        Ok(WithStringMemberBuilder(self.0))
                    }
                }
                impl<P> WithStringMemberBuilder<P, 2>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    pub fn long_string(
                        mut self,
                        value: rs_matter_crate::tlv::Utf8Str<'_>,
                    ) -> Result<WithStringMemberBuilder<P, 3usize>, rs_matter_crate::error::Error>
                    {
                        rs_matter_crate::tlv::ToTLV::to_tlv(
                            &value,
                            &rs_matter_crate::tlv::TLVTag::Context(2),
                            self.0.writer(),
                        )?;
                        Ok(WithStringMemberBuilder(self.0))
                    }
                }
                impl<P> WithStringMemberBuilder<P, 3>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    pub fn opt_str(
                        mut self,
                        value: Option<rs_matter_crate::tlv::Utf8Str<'_>>,
                    ) -> Result<WithStringMemberBuilder<P, 4usize>, rs_matter_crate::error::Error>
                    {
                        rs_matter_crate::tlv::ToTLV::to_tlv(
                            &value,
                            &rs_matter_crate::tlv::TLVTag::Context(3),
                            self.0.writer(),
                        )?;
                        Ok(WithStringMemberBuilder(self.0))
                    }
                }
                impl<P> WithStringMemberBuilder<P, 4>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    pub fn opt_nul_str(
                        mut self,
                        value: Option<
                            rs_matter_crate::tlv::Nullable<rs_matter_crate::tlv::Utf8Str<'_>>,
                        >,
                    ) -> Result<WithStringMemberBuilder<P, 5usize>, rs_matter_crate::error::Error>
                    {
                        rs_matter_crate::tlv::ToTLV::to_tlv(
                            &value,
                            &rs_matter_crate::tlv::TLVTag::Context(4),
                            self.0.writer(),
                        )?;
                        Ok(WithStringMemberBuilder(self.0))
                    }
                }
                impl<P> WithStringMemberBuilder<P, 5usize>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    #[doc = "Finish the struct and return the parent"]
                    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        self.0.writer().end_container()?;
                        Ok(self.0)
                    }
                }
                impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent for WithStringMemberBuilder<P, F>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    type Write = P::Write;
                    fn writer(&mut self) -> &mut P::Write {
                        self.0.writer()
                    }
                }
                impl<P> rs_matter_crate::tlv::TLVBuilder<P> for WithStringMemberBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn new(
                        parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        Self::new(parent, tag)
                    }
                    fn unchecked_into_parent(self) -> P {
                        self.0
                    }
                }
                pub struct WithStringMemberArrayBuilder<P>(P);
                impl<P> WithStringMemberArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    #[doc = "Create a new instance"]
                    pub fn new(
                        mut parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        parent.writer().start_array(tag)?;
                        Ok(Self(parent))
                    }
                    #[doc = "Push a new element into the array"]
                    pub fn push(
                        self,
                    ) -> Result<
                        WithStringMemberBuilder<WithStringMemberArrayBuilder<P>>,
                        rs_matter_crate::error::Error,
                    > {
                        rs_matter_crate::tlv::TLVBuilder::new(
                            WithStringMemberArrayBuilder(self.0),
                            &rs_matter_crate::tlv::TLVTag::Anonymous,
                        )
                    }
                    #[doc = "Finish the array and return the parent"]
                    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        self.0.writer().end_container()?;
                        Ok(self.0)
                    }
                }
                impl<P> rs_matter_crate::tlv::TLVBuilderParent for WithStringMemberArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    type Write = P::Write;
                    fn writer(&mut self) -> &mut P::Write {
                        self.0.writer()
                    }
                }
                impl<P> rs_matter_crate::tlv::TLVBuilder<P> for WithStringMemberArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn new(
                        parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        Self::new(parent, tag)
                    }
                    fn unchecked_into_parent(self) -> P {
                        self.0
                    }
                }
            )
        );
    }

    #[test]
    fn struct_fields_octet_string() {
        let idl = parse_idl(
            "
              cluster TestForStructs = 1 {
                struct WithStringMember {
                  octet_string<16> short_string = 1;
                  long_octet_string<512> long_string = 2;
                  optional octet_string<32> opt_str = 3;
                  optional nullable long_octet_string<512> opt_nul_str = 4;
                }
              }
            ",
        );

        let cluster = get_cluster_named(&idl, "TestForStructs").expect("Cluster exists");
        let context = IdlGenerateContext::new("rs_matter_crate");

        // panic!("====\n{}\n====", &struct_builders(cluster, &context));

        assert_tokenstreams_eq!(
            &struct_builders(cluster, &context),
            &quote!(
                pub struct WithStringMemberBuilder<P, const F: usize = 1usize>(P);
                impl<P> WithStringMemberBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    #[doc = "Create a new instance"]
                    pub fn new(
                        mut parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        parent.writer().start_struct(tag)?;
                        Ok(Self(parent))
                    }
                }
                impl<P> WithStringMemberBuilder<P, 1>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    pub fn short_string(
                        mut self,
                        value: rs_matter_crate::tlv::OctetStr<'_>,
                    ) -> Result<WithStringMemberBuilder<P, 2usize>, rs_matter_crate::error::Error>
                    {
                        rs_matter_crate::tlv::ToTLV::to_tlv(
                            &value,
                            &rs_matter_crate::tlv::TLVTag::Context(1),
                            self.0.writer(),
                        )?;
                        Ok(WithStringMemberBuilder(self.0))
                    }
                }
                impl<P> WithStringMemberBuilder<P, 2>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    pub fn long_string(
                        mut self,
                        value: rs_matter_crate::tlv::OctetStr<'_>,
                    ) -> Result<WithStringMemberBuilder<P, 3usize>, rs_matter_crate::error::Error>
                    {
                        rs_matter_crate::tlv::ToTLV::to_tlv(
                            &value,
                            &rs_matter_crate::tlv::TLVTag::Context(2),
                            self.0.writer(),
                        )?;
                        Ok(WithStringMemberBuilder(self.0))
                    }
                }
                impl<P> WithStringMemberBuilder<P, 3>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    pub fn opt_str(
                        mut self,
                        value: Option<rs_matter_crate::tlv::OctetStr<'_>>,
                    ) -> Result<WithStringMemberBuilder<P, 4usize>, rs_matter_crate::error::Error>
                    {
                        rs_matter_crate::tlv::ToTLV::to_tlv(
                            &value,
                            &rs_matter_crate::tlv::TLVTag::Context(3),
                            self.0.writer(),
                        )?;
                        Ok(WithStringMemberBuilder(self.0))
                    }
                }
                impl<P> WithStringMemberBuilder<P, 4>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    pub fn opt_nul_str(
                        mut self,
                        value: Option<
                            rs_matter_crate::tlv::Nullable<rs_matter_crate::tlv::OctetStr<'_>>,
                        >,
                    ) -> Result<WithStringMemberBuilder<P, 5usize>, rs_matter_crate::error::Error>
                    {
                        rs_matter_crate::tlv::ToTLV::to_tlv(
                            &value,
                            &rs_matter_crate::tlv::TLVTag::Context(4),
                            self.0.writer(),
                        )?;
                        Ok(WithStringMemberBuilder(self.0))
                    }
                }
                impl<P> WithStringMemberBuilder<P, 5usize>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    #[doc = "Finish the struct and return the parent"]
                    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        self.0.writer().end_container()?;
                        Ok(self.0)
                    }
                }
                impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent for WithStringMemberBuilder<P, F>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    type Write = P::Write;
                    fn writer(&mut self) -> &mut P::Write {
                        self.0.writer()
                    }
                }
                impl<P> rs_matter_crate::tlv::TLVBuilder<P> for WithStringMemberBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn new(
                        parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        Self::new(parent, tag)
                    }
                    fn unchecked_into_parent(self) -> P {
                        self.0
                    }
                }
                pub struct WithStringMemberArrayBuilder<P>(P);
                impl<P> WithStringMemberArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    #[doc = "Create a new instance"]
                    pub fn new(
                        mut parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        parent.writer().start_array(tag)?;
                        Ok(Self(parent))
                    }
                    #[doc = "Push a new element into the array"]
                    pub fn push(
                        self,
                    ) -> Result<
                        WithStringMemberBuilder<WithStringMemberArrayBuilder<P>>,
                        rs_matter_crate::error::Error,
                    > {
                        rs_matter_crate::tlv::TLVBuilder::new(
                            WithStringMemberArrayBuilder(self.0),
                            &rs_matter_crate::tlv::TLVTag::Anonymous,
                        )
                    }
                    #[doc = "Finish the array and return the parent"]
                    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
                        use rs_matter_crate::tlv::TLVWrite;
                        self.0.writer().end_container()?;
                        Ok(self.0)
                    }
                }
                impl<P> rs_matter_crate::tlv::TLVBuilderParent for WithStringMemberArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    type Write = P::Write;
                    fn writer(&mut self) -> &mut P::Write {
                        self.0.writer()
                    }
                }
                impl<P> rs_matter_crate::tlv::TLVBuilder<P> for WithStringMemberArrayBuilder<P>
                where
                    P: rs_matter_crate::tlv::TLVBuilderParent,
                {
                    fn new(
                        parent: P,
                        tag: &rs_matter_crate::tlv::TLVTag,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        Self::new(parent, tag)
                    }
                    fn unchecked_into_parent(self) -> P {
                        self.0
                    }
                }
            )
        );
    }
}
