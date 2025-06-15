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

use std::collections::HashSet;

use proc_macro2::{Ident, Literal, Span, TokenStream};
use quote::{format_ident, quote};
use syn::meta::ParseNestedMeta;
use syn::parse::ParseStream;
use syn::token::{Gt, Lt};
use syn::{DeriveInput, Lifetime, LifetimeParam, LitInt, LitStr, Type};

#[derive(PartialEq, Debug)]
struct TlvArgs {
    rs_matter_crate: String,
    start: u8,
    datatype: String,
    unordered: bool,
    lifetime: syn::Lifetime,
    lifetime_explicit: bool,
}

impl Default for TlvArgs {
    fn default() -> Self {
        Self {
            start: 0,
            rs_matter_crate: "".to_string(),
            datatype: "struct".to_string(),
            unordered: false,
            lifetime: Lifetime::new("'_", Span::call_site()),
            lifetime_explicit: false,
        }
    }
}

impl TlvArgs {
    /// Update individual state based on data from nested meta information.
    ///
    /// Can be used to incrementally parse and update a TlvArgs structure.
    fn parse(&mut self, meta: ParseNestedMeta) -> syn::Result<()> {
        if meta.path.is_ident("start") {
            self.start = meta.value()?.parse::<LitInt>()?.base10_parse()?;
        } else if meta.path.is_ident("lifetime") {
            self.lifetime =
                Lifetime::new(&meta.value()?.parse::<LitStr>()?.value(), Span::call_site());
            self.lifetime_explicit = true;
        } else if meta.path.is_ident("datatype") {
            self.datatype = meta.value()?.parse::<LitStr>()?.value();
        } else if meta.path.is_ident("unordered") {
            assert!(meta.input.is_empty());
            self.unordered = true;
        } else {
            return Err(meta.error(format!("unsupported attribute: {:?}", meta.path)));
        }

        Ok(())
    }
}

fn parse_tlvargs(ast: &DeriveInput, rs_matter_crate: String) -> TlvArgs {
    let mut tlvargs = TlvArgs {
        rs_matter_crate,
        ..Default::default()
    };

    for attr in ast.attrs.iter().filter(|a| a.path().is_ident("tlvargs")) {
        attr.parse_nested_meta(|meta| tlvargs.parse(meta)).unwrap();
    }

    tlvargs
}

fn parse_enum_val(attrs: &[syn::Attribute]) -> Option<u16> {
    attrs
        .iter()
        .filter(|attr| attr.path().is_ident("enumval"))
        .map(|attr| {
            attr.parse_args_with(|parser: ParseStream| {
                parser.parse::<LitInt>()?.base10_parse::<u16>()
            })
            .unwrap()
        })
        .next()
}

fn parse_tag_val(attrs: &[syn::Attribute]) -> Option<u8> {
    attrs
        .iter()
        .filter(|attr| attr.path().is_ident("tagval"))
        .map(|attr| {
            attr.parse_args_with(|parser: ParseStream| {
                parser.parse::<LitInt>()?.base10_parse::<u8>()
            })
            .unwrap()
        })
        .next()
}

/// Given a data type and existing tags, convert them into
/// a function to call for read/write (like u8/u16) and a list
/// of numeric literals of tags (which may be u8 or u16)
///
/// Ideally we would also be able to figure out the writing type using "repr" data
/// however for now we require a "datatype" to be valid
fn get_unit_enum_func_and_tags(
    enum_name: &Ident,
    data_type: &str,
    tags: Vec<u16>,
) -> (Ident, Vec<Literal>) {
    match data_type {
        // "struct" is the default, so we make it equivalent to u8 for convenience
        "struct" | "u8" => {
            if tags.iter().any(|v| *v > 0xFF) {
                panic!("Enum discriminator value larger that 0xFF for {enum_name:?}")
            }
            (
                Ident::new("u8", Span::call_site()),
                tags.into_iter()
                    .map(|v| Literal::u8_suffixed(v as u8))
                    .collect(),
            )
        }
        "u16" => (
            Ident::new("u16", Span::call_site()),
            tags.into_iter().map(Literal::u16_suffixed).collect(),
        ),
        _ => panic!("Invalid data type {data_type:?} for enum {enum_name:?}"),
    }
}

/// Generate a ToTlv implementation for a structure
fn gen_totlv_for_struct(
    data_struct: &syn::DataStruct,
    struct_name: &proc_macro2::Ident,
    tlvargs: &TlvArgs,
    generics: &syn::Generics,
) -> TokenStream {
    match &data_struct.fields {
        syn::Fields::Named(fields) => {
            gen_totlv_for_struct_named(fields, struct_name, tlvargs, generics)
        }
        syn::Fields::Unnamed(fields) => {
            gen_totlv_for_struct_unnamed(fields, struct_name, tlvargs, generics)
        }
        _ => panic!("Union structs are not supported"),
    }
}

/// Generate a ToTlv implementation for a structure with a single unnamed field
/// The structure is behaving as a Newtype over the unnamed field
fn gen_totlv_for_struct_unnamed(
    fields: &syn::FieldsUnnamed,
    struct_name: &proc_macro2::Ident,
    tlvargs: &TlvArgs,
    generics: &syn::Generics,
) -> TokenStream {
    if fields.unnamed.len() != 1 {
        panic!("Only a single unnamed field supported for unnamed structures");
    }

    let krate = Ident::new(&tlvargs.rs_matter_crate, Span::call_site());

    quote! {
        impl #generics #krate::tlv::ToTLV for #struct_name #generics {
            fn to_tlv<W: #krate::tlv::TLVWrite>(&self, tag: &#krate::tlv::TLVTag, mut tw: W) -> Result<(), #krate::error::Error> {
                #krate::tlv::ToTLV::to_tlv(&self.0, tag, &mut tw)
            }

            fn tlv_iter(&self, tag: #krate::tlv::TLVTag) -> impl Iterator<Item = Result<#krate::tlv::TLV, #krate::error::Error>> {
                #krate::tlv::ToTLV::tlv_iter(&self.0, tag)
            }
        }
    }
}

/// Generate a ToTlv implementation for a structure with named fields
fn gen_totlv_for_struct_named(
    fields: &syn::FieldsNamed,
    struct_name: &proc_macro2::Ident,
    tlvargs: &TlvArgs,
    generics: &syn::Generics,
) -> TokenStream {
    let mut tag_start = tlvargs.start;
    let datatype = format_ident!("start_{}", tlvargs.datatype);

    let mut idents = Vec::new();
    let mut tags = Vec::new();

    for field in fields.named.iter() {
        idents.push(&field.ident);
        if let Some(a) = parse_tag_val(&field.attrs) {
            tags.push(a);
        } else {
            tags.push(tag_start);
            tag_start += 1;
        }
    }

    let krate = Ident::new(&tlvargs.rs_matter_crate, Span::call_site());

    quote! {
        impl #generics #krate::tlv::ToTLV for #struct_name #generics {
            fn to_tlv<W: #krate::tlv::TLVWrite>(&self, tag: &#krate::tlv::TLVTag, mut tw: W) -> Result<(), #krate::error::Error> {
                let anchor = tw.get_tail();

                if let Err(err) = (|| {
                    tw.#datatype(tag)?;
                    #(
                        #krate::tlv::ToTLV::to_tlv(&self.#idents, &#krate::tlv::TLVTag::Context(#tags), &mut tw)?;
                    )*
                    tw.end_container()
                })() {
                    tw.rewind_to(anchor);
                    Err(err)
                } else {
                    Ok(())
                }
            }

            fn tlv_iter(&self, tag: #krate::tlv::TLVTag) -> impl Iterator<Item = Result<#krate::tlv::TLV, #krate::error::Error>> {
                let iter = #krate::tlv::TLV::structure(tag).into_tlv_iter();

                #(let iter = Iterator::chain(iter, #krate::tlv::ToTLV::tlv_iter(&self.#idents, #krate::tlv::TLVTag::Context(#tags)));)*

                Iterator::chain(iter, #krate::tlv::TLV::end_container().into_tlv_iter())
            }
        }
    }
}

/// Generate a ToTlv implementation for an enum
fn gen_totlv_for_enum(
    data_enum: &syn::DataEnum,
    enum_name: &proc_macro2::Ident,
    tlvargs: &TlvArgs,
    generics: &syn::Generics,
) -> TokenStream {
    // Enum values are allowed to be enum16 in the spec,
    // so we need to support "tags" up to u16 for those cases
    let mut tag_start = tlvargs.start as u16;

    let mut variant_names = Vec::new();
    let mut tags = Vec::new();

    #[derive(PartialEq, Eq, Hash)]
    enum FieldTypes {
        Named,
        Unnamed,
        Unit,
    }

    let variant_types = data_enum
        .variants
        .iter()
        .map(|v| match v.fields {
            syn::Fields::Unnamed(_) => FieldTypes::Unnamed,
            syn::Fields::Named(_) => FieldTypes::Named,
            syn::Fields::Unit => FieldTypes::Unit,
        })
        .collect::<HashSet<_>>();

    if variant_types.contains(&FieldTypes::Named) {
        panic!("Named items in enums not supported.");
    }

    if variant_types.contains(&FieldTypes::Unnamed) && variant_types.contains(&FieldTypes::Unit) {
        // You should have enum Foo {A,B,C} OR Foo{A(X), B(Y), ...}
        // Combining them does not work
        panic!("Enum contains both unit and unnamed fields. This is not supported.");
    }

    for v in data_enum.variants.iter() {
        variant_names.push(&v.ident);
        if let Some(a) = parse_enum_val(&v.attrs) {
            tags.push(a);
        } else {
            tags.push(tag_start);
            tag_start += 1;
        }
    }

    let krate = Ident::new(&tlvargs.rs_matter_crate, Span::call_site());

    if variant_types.contains(&FieldTypes::Unit) {
        let (write_func, tags) =
            get_unit_enum_func_and_tags(enum_name, tlvargs.datatype.as_str(), tags);

        quote! {
            impl #generics #krate::tlv::ToTLV for #enum_name #generics {
                fn to_tlv<W: #krate::tlv::TLVWrite>(&self, tag: &#krate::tlv::TLVTag, mut tw: W) -> Result<(), #krate::error::Error> {
                    let anchor = tw.get_tail();

                    if let Err(err) = (|| {
                        match self {
                            #( Self::#variant_names => tw.#write_func(tag, #tags), )*
                        }
                    })() {
                        tw.rewind_to(anchor);
                        Err(err)
                    } else {
                        Ok(())
                    }
                }

                fn tlv_iter(&self, tag: #krate::tlv::TLVTag) -> impl Iterator<Item = Result<#krate::tlv::TLV, #krate::error::Error>> {
                    match self {
                        #( Self::#variant_names => #krate::tlv::TLV::#write_func(tag, #tags).into_tlv_iter(), )*
                    }
                }
            }
        }
    } else {
        // tags MUST be context-tags (up to u8 range)
        if tags.iter().any(|v| *v > u8::MAX as _) {
            panic!("Enum discriminator value larger that 0xFF for {enum_name:?}")
        }

        if tags.len() > 6 {
            panic!("More than 6 enum variants for {enum_name:?}")
        }

        let either_ident = if tags.len() != 2 {
            format_ident!("Either{}Iter", tags.len())
        } else {
            format_ident!("EitherIter")
        };

        let either_variants = (0..tags.len())
            .map(|t| match t {
                0 => "First",
                1 => "Second",
                2 => "Third",
                3 => "Fourth",
                4 => "Fifth",
                5 => "Sixth",
                _ => unreachable!(),
            })
            .map(|t| format_ident!("{}", t))
            .collect::<Vec<_>>();

        let tags = tags
            .into_iter()
            .map(|v| Literal::u8_suffixed(v as u8))
            .collect::<Vec<_>>();

        if tlvargs.datatype == "naked" {
            quote! {
                impl #generics #krate::tlv::ToTLV for #enum_name #generics {
                    fn to_tlv<W: #krate::tlv::TLVWrite>(&self, tag: &#krate::tlv::TLVTag, mut tw: W) -> Result<(), #krate::error::Error> {
                        let anchor = tw.get_tail();

                        if let Err(err) = (|| {
                            match self {
                                #(
                                    Self::#variant_names(c) => { #krate::tlv::ToTLV::to_tlv(c, &#krate::tlv::TLVTag::Context(#tags), &mut tw) }
                                )*
                            }
                        })() {
                            tw.rewind_to(anchor);
                            Err(err)
                        } else {
                            Ok(())
                        }
                    }

                    fn tlv_iter(&self, tag: #krate::tlv::TLVTag) -> impl Iterator<Item = Result<#krate::tlv::TLV, #krate::error::Error>> {
                        match self {
                            #(
                                Self::#variant_names(c) => #krate::tlv::#either_ident::#either_variants(#krate::tlv::ToTLV::tlv_iter(c, #krate::tlv::TLVTag::Context(#tags))),
                            )*
                        }
                    }
                }
            }
        } else {
            quote! {
                impl #generics #krate::tlv::ToTLV for #enum_name #generics {
                    fn to_tlv<W: #krate::tlv::TLVWrite>(&self, tag: &#krate::tlv::TLVTag, mut tw: W) -> Result<(), #krate::error::Error> {
                        let anchor = tw.get_tail();

                        if let Err(err) = (|| {
                            tw.start_struct(tag)?;
                            match self {
                                #(
                                    Self::#variant_names(c) => #krate::tlv::ToTLV::to_tlv(c, &#krate::tlv::TLVTag::Context(#tags), &mut tw),
                                )*
                            }?;
                            tw.end_container()
                        })() {
                            tw.rewind_to(anchor);
                            Err(err)
                        } else {
                            Ok(())
                        }
                    }

                    fn tlv_iter(&self, tag: #krate::tlv::TLVTag) -> impl Iterator<Item = Result<#krate::tlv::TLV, #krate::error::Error>> {
                        let iter = #krate::tlv::TLV::structure(tag).into_tlv_iter();

                        let iter = Iterator::chain(iter, match self {
                            #(
                                Self::#variant_names(c) => #krate::tlv::#either_ident::#either_variants(#krate::tlv::ToTLV::tlv_iter(c, #krate::tlv::TLVTag::Context(#tags))),
                            )*
                        });

                        Iterator::chain(iter, #krate::tlv::TLV::end_container().into_tlv_iter())
                    }
                }
            }
        }
    }
}

/// Derive ToTLV Macro
///
/// This macro works for structures. It will create an implementation
/// of the ToTLV trait for that structure.  All the members of the
/// structure, sequentially, will get Context tags starting from 0
/// Some configurations are possible through the 'tlvargs' attributes.
/// For example:
///  #[tlvargs(start = 1, datatype = "list")]
///
/// start: This can be used to override the default tag from which the
///        encoding starts (Default: 0)
/// datatype: This can be used to define whether this data structure is
///        to be encoded as a structure or list. Possible values: list
///        (Default: struct)
///
/// Additionally, structure members can use the tagval attribute to
/// define a specific tag to be used
/// For example:
///  #[tagval(22)]
///  name: u8,
/// In the above case, the 'name' attribute will be encoded/decoded with
/// the tag 22
///
/// Enumeration values can use `enumval` attribute to specify what numeric
/// value a specific element corresponds to.
pub fn derive_totlv(ast: DeriveInput, rs_matter_crate: String) -> TokenStream {
    let name = &ast.ident;

    let tlvargs = parse_tlvargs(&ast, rs_matter_crate);
    let generics = ast.generics;

    match &ast.data {
        syn::Data::Struct(data_struct) => {
            gen_totlv_for_struct(data_struct, name, &tlvargs, &generics)
        }
        syn::Data::Enum(data_enum) => gen_totlv_for_enum(data_enum, name, &tlvargs, &generics),
        _ => panic!("Derive ToTLV - Only supported struct and enum for now"),
    }
}

/// Generate a FromTlv implementation for a structure
fn gen_fromtlv_for_struct(
    data_struct: &syn::DataStruct,
    struct_name: &proc_macro2::Ident,
    tlvargs: TlvArgs,
    generics: &syn::Generics,
) -> TokenStream {
    match &data_struct.fields {
        syn::Fields::Named(fields) => {
            gen_fromtlv_for_struct_named(fields, struct_name, tlvargs, generics)
        }
        syn::Fields::Unnamed(fields) => {
            gen_fromtlv_for_struct_unnamed(fields, struct_name, tlvargs, generics)
        }
        _ => panic!("Union structs are not supported"),
    }
}

/// Generate a FromTlv implementation for a structure with a single unnamed field
/// The structure is behaving as a Newtype over the unnamed field
fn gen_fromtlv_for_struct_unnamed(
    fields: &syn::FieldsUnnamed,
    struct_name: &proc_macro2::Ident,
    tlvargs: TlvArgs,
    generics: &syn::Generics,
) -> TokenStream {
    if fields.unnamed.len() != 1 {
        panic!("Only a single unnamed field supported for unnamed structures");
    }

    let krate = Ident::new(&tlvargs.rs_matter_crate, Span::call_site());
    let lifetime = tlvargs.lifetime;
    let ty = normalize_fromtlv_type(&fields.unnamed[0].ty);

    quote! {
        impl #generics #krate::tlv::FromTLV<#lifetime> for #struct_name #generics {
            fn from_tlv(element: &#krate::tlv::TLVElement<#lifetime>) -> Result<Self, #krate::error::Error> {
                Ok(Self(#ty::from_tlv(element)?))
            }
        }

        impl #generics TryFrom<&#krate::tlv::TLVElement<#lifetime>> for #struct_name #generics {
            type Error = #krate::error::Error;

            fn try_from(element: &#krate::tlv::TLVElement<#lifetime>) -> Result<Self, Self::Error> {
                use #krate::tlv::FromTLV;

                Self::from_tlv(element)
            }
        }
    }
}

/// Generate a ToTlv implementation for a structure with named fields
fn gen_fromtlv_for_struct_named(
    fields: &syn::FieldsNamed,
    struct_name: &proc_macro2::Ident,
    tlvargs: TlvArgs,
    generics: &syn::Generics,
) -> TokenStream {
    let mut tag_start = tlvargs.start;

    let (lifetime, impl_generics) = if tlvargs.lifetime_explicit {
        (tlvargs.lifetime, generics.clone())
    } else {
        // The `'_` default lifetime from tlvargs won't do.
        // We need a named lifetime that has to be part of the `impl<>` block.

        let lifetime = Lifetime::new("'__from_tlv", Span::call_site());

        let mut impl_generics = generics.clone();

        if impl_generics.gt_token.is_none() {
            impl_generics.gt_token = Some(Gt::default());
            impl_generics.lt_token = Some(Lt::default());
        }

        impl_generics
            .params
            .push(syn::GenericParam::Lifetime(LifetimeParam::new(
                lifetime.clone(),
            )));

        (lifetime, impl_generics)
    };

    let datatype = format_ident!("r#{}", tlvargs.datatype);

    let mut idents = Vec::new();
    let mut types = Vec::new();
    let mut tags = Vec::new();

    for field in fields.named.iter() {
        if let Some(a) = parse_tag_val(&field.attrs) {
            // TODO: The current limitation with this is that a hard-coded integer
            // value has to be mentioned in the tagval attribute. This is because
            // our tags vector is for integers, and pushing an 'identifier' on it
            // wouldn't work.
            tags.push(a);
        } else {
            tags.push(tag_start);
            tag_start += 1;
        }
        idents.push(&field.ident);

        types.push(normalize_fromtlv_type(&field.ty));
    }

    let krate = Ident::new(&tlvargs.rs_matter_crate, Span::call_site());
    let seq_method = format_ident!("{}_ctx", if tlvargs.unordered { "find" } else { "scan" });

    quote! {
        impl #impl_generics #krate::tlv::FromTLV<#lifetime> for #struct_name #generics {
            fn from_tlv(element: &#krate::tlv::TLVElement<#lifetime>) -> Result<Self, #krate::error::Error> {
                #[allow(unused_mut)]
                let mut seq = element.#datatype()?;

                Ok(Self {
                    #(#idents: #types::from_tlv(&seq.#seq_method(#tags)?)?,
                    )*
                })
            }

            fn init_from_tlv(element: #krate::tlv::TLVElement<#lifetime>) -> impl #krate::utils::init::Init<Self, #krate::error::Error> {
                #krate::utils::init::into_init(move || {
                    #[allow(unused_mut)]
                    let mut seq = element.#datatype()?;

                    let init = #krate::utils::init::try_init!(Self {
                        #(#idents <- #types::init_from_tlv(seq.#seq_method(#tags)?),
                        )*
                    }? #krate::error::Error);

                    Ok(init)
                })
            }
        }

        impl #impl_generics TryFrom<&#krate::tlv::TLVElement<#lifetime>> for #struct_name #generics {
            type Error = #krate::error::Error;

            fn try_from(element: &#krate::tlv::TLVElement<#lifetime>) -> Result<Self, Self::Error> {
                use #krate::tlv::FromTLV;

                Self::from_tlv(element)
            }
        }
    }
}

/// Generate a FromTlv implementation for an enum
fn gen_fromtlv_for_enum(
    data_enum: &syn::DataEnum,
    enum_name: &proc_macro2::Ident,
    tlvargs: TlvArgs,
    generics: &syn::Generics,
) -> TokenStream {
    // Enum values are allowed to be enum16 in the spec,
    // so we need to support "tags" up to u16 for those cases
    let mut tag_start = tlvargs.start as u16;

    let lifetime = tlvargs.lifetime;

    let mut variant_names = Vec::new();
    let mut tags = Vec::new();

    #[derive(PartialEq, Eq, Hash)]
    enum FieldTypes {
        Named,
        Unnamed,
        Unit,
    }

    let variant_types = data_enum
        .variants
        .iter()
        .map(|v| match v.fields {
            syn::Fields::Unnamed(_) => FieldTypes::Unnamed,
            syn::Fields::Named(_) => FieldTypes::Named,
            syn::Fields::Unit => FieldTypes::Unit,
        })
        .collect::<HashSet<_>>();

    if variant_types.contains(&FieldTypes::Named) {
        panic!("Named items in enums not supported.");
    }

    if variant_types.contains(&FieldTypes::Unnamed) && variant_types.contains(&FieldTypes::Unit) {
        // You should have enum Foo { A, B, C } OR Foo { A(X), B(Y), .. }
        // Combining them does not work
        panic!("Enum contains both unit and unnamed fields. This is not supported.");
    }

    for v in data_enum.variants.iter() {
        variant_names.push(&v.ident);
        if let Some(a) = parse_enum_val(&v.attrs) {
            tags.push(a);
        } else {
            tags.push(tag_start);
            tag_start += 1;
        }
    }

    let krate = Ident::new(&tlvargs.rs_matter_crate, Span::call_site());
    if variant_types.contains(&FieldTypes::Unit) {
        let (elem_read_method, tags) =
            get_unit_enum_func_and_tags(enum_name, tlvargs.datatype.as_str(), tags);

        quote! {
            impl #generics #krate::tlv::FromTLV<#lifetime> for #enum_name #generics {
                fn from_tlv(element: &#krate::tlv::TLVElement<#lifetime>) -> Result<Self, #krate::error::Error> {
                    Ok(match element.#elem_read_method()? {
                        #(#tags => Self::#variant_names,
                        )*
                        _ => Err(#krate::error::ErrorCode::Invalid)?,
                    })
                }
            }

            impl #generics TryFrom<&#krate::tlv::TLVElement<#lifetime>> for #enum_name #generics {
                type Error = #krate::error::Error;

                fn try_from(element: &#krate::tlv::TLVElement<#lifetime>) -> Result<Self, Self::Error> {
                    use #krate::tlv::FromTLV;

                    Self::from_tlv(element)
                }
            }
        }
    } else {
        // tags MUST be context-tags (up to u8 range)
        if tags.iter().any(|v| *v > 0xFF) {
            panic!("Enum discriminator value larger that 0xFF for {enum_name:?}")
        }
        let tags = tags
            .into_iter()
            .map(|v| Literal::u8_suffixed(v as u8))
            .collect::<Vec<_>>();

        let mut types = Vec::new();

        for v in data_enum.variants.iter() {
            if let syn::Fields::Unnamed(fields) = &v.fields {
                if let Type::Path(path) = &fields.unnamed[0].ty {
                    types.push(&path.path.segments[0].ident);
                } else {
                    panic!("Path not found {:?}", v.fields);
                }
            } else {
                panic!("Unnamed field not found {:?}", v.fields);
            }
        }

        let enter = if tlvargs.datatype != "naked" {
            quote! {
                let element = element
                    .r#struct()?
                    .iter()
                    .next()
                    .ok_or(#krate::error::ErrorCode::TLVTypeMismatch)??;
            }
        } else {
            TokenStream::new()
        };

        quote! {
            impl #generics #krate::tlv::FromTLV<#lifetime> for #enum_name #generics {
                fn from_tlv(element: &#krate::tlv::TLVElement<#lifetime>) -> Result<Self, #krate::error::Error> {
                    #enter

                    let tag = element
                        .try_ctx()?
                        .ok_or(#krate::error::ErrorCode::TLVTypeMismatch)?;

                    Ok(match tag {
                        #(#tags => Self::#variant_names(#types::from_tlv(&element)?),
                        )*
                        _ => Err(#krate::error::ErrorCode::Invalid)?,
                    })
                }
            }

            impl #generics TryFrom<&#krate::tlv::TLVElement<#lifetime>> for #enum_name #generics {
                type Error = #krate::error::Error;

                fn try_from(element: &#krate::tlv::TLVElement<#lifetime>) -> Result<Self, Self::Error> {
                    use #krate::tlv::FromTLV;

                    Self::from_tlv(element)
                }
            }
        }
    }
}

fn normalize_fromtlv_type(ty: &syn::Type) -> TokenStream {
    let Type::Path(type_path) = ty else {
        panic!("Don't know what to do {ty:?}");
    };

    // When paths are like `matter_rs::tlv::Nullable<u32>`
    // this ignores the arguments and just does:
    // `matter_rs::tlv::Nullable`
    let type_idents = type_path
        .path
        .segments
        .iter()
        .map(|s| s.ident.clone())
        .collect::<Vec<_>>();

    quote!(#(#type_idents)::*)
}

/// Derive FromTLV Macro
///
/// This macro works for structures. It will create an implementation
/// of the FromTLV trait for that structure.  All the members of the
/// structure, sequentially, will get Context tags starting from 0
/// Some configurations are possible through the 'tlvargs' attributes.
/// For example:
///  #[tlvargs(lifetime = "'a", start = 1, datatype = "list", unordered)]
///
/// start: This can be used to override the default tag from which the
///        decoding starts (Default: 0)
/// datatype: This can be used to define whether this data structure is
///        to be decoded as a structure or list. Possible values: list
///        (Default: struct)
/// lifetime: If the structure has a lifetime annotation, use this variable
///        to indicate that. The 'impl' will then use that lifetime
///        indicator.
/// unordered: By default, the decoder expects that the tags are in
///        sequentially increasing order. Set this if that is not the case.
///
/// Additionally, structure members can use the tagval attribute to
/// define a specific tag to be used
/// For example:
///  #[tagval(22)]
///  name: u8,
/// In the above case, the 'name' attribute will be encoded/decoded with
/// the tag 22
pub fn derive_fromtlv(ast: DeriveInput, rs_matter_crate: String) -> TokenStream {
    let name = &ast.ident;

    let tlvargs = parse_tlvargs(&ast, rs_matter_crate);

    let generics = ast.generics;

    match &ast.data {
        syn::Data::Struct(data_struct) => {
            gen_fromtlv_for_struct(data_struct, name, tlvargs, &generics)
        }
        syn::Data::Enum(data_enum) => gen_fromtlv_for_enum(data_enum, name, tlvargs, &generics),
        _ => panic!("Derive FromTLV - Only supported struct and enum for now"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_tokenstreams_eq::assert_tokenstreams_eq;
    use quote::quote;

    #[test]
    fn tlvargs_parse() {
        let ast: DeriveInput = syn::parse2(quote!(
            #[tlvargs(datatype = "list")]
            enum Unused {}
        ))
        .unwrap();
        assert_eq!(
            parse_tlvargs(&ast, "test".to_string()),
            TlvArgs {
                rs_matter_crate: "test".to_string(),
                datatype: "list".to_string(),
                ..Default::default()
            }
        );

        let ast: DeriveInput = syn::parse2(quote!(
            #[tlvargs(unordered)]
            enum Unused {}
        ))
        .unwrap();
        assert_eq!(
            parse_tlvargs(&ast, "crate".to_string()),
            TlvArgs {
                rs_matter_crate: "crate".to_string(),
                unordered: true,
                ..Default::default()
            }
        );

        let ast: DeriveInput = syn::parse2(quote!(
            #[tlvargs(start = 123)]
            enum Unused {}
        ))
        .unwrap();
        assert_eq!(
            parse_tlvargs(&ast, "crate".to_string()),
            TlvArgs {
                rs_matter_crate: "crate".to_string(),
                start: 123,
                ..Default::default()
            }
        );

        let ast: DeriveInput = syn::parse2(quote!(
            #[tlvargs(lifetime = "'foo")]
            enum Unused {}
        ))
        .unwrap();
        assert_eq!(parse_tlvargs(&ast, "abc".to_string()).lifetime.ident, "foo");
    }

    #[test]
    fn test_to_tlv_for_struct() {
        let ast: DeriveInput = syn::parse2(quote!(
            struct TestS {
                field1: u8,
                field2: u32,
            }
        ))
        .unwrap();

        assert_tokenstreams_eq!(
            &derive_totlv(ast, "rs_matter_maybe_renamed".to_string()),
            &quote!(
                impl rs_matter_maybe_renamed::tlv::ToTLV for TestS {
                    fn to_tlv<W: rs_matter_maybe_renamed::tlv::TLVWrite>(
                        &self,
                        tag: &rs_matter_maybe_renamed::tlv::TLVTag,
                        mut tw: W,
                    ) -> Result<(), rs_matter_maybe_renamed::error::Error> {
                        let anchor = tw.get_tail();
                        if let Err(err) = (|| {
                            tw.start_struct(tag)?;
                            rs_matter_maybe_renamed::tlv::ToTLV::to_tlv(&self.field1, &rs_matter_maybe_renamed::tlv::TLVTag::Context(0u8), &mut tw)?;
                            rs_matter_maybe_renamed::tlv::ToTLV::to_tlv(&self.field2, &rs_matter_maybe_renamed::tlv::TLVTag::Context(1u8), &mut tw)?;
                            tw.end_container()
                        })() {
                            tw.rewind_to(anchor);
                            Err(err)
                        } else {
                            Ok(())
                        }
                    }

                    fn tlv_iter(
                        &self,
                        tag: rs_matter_maybe_renamed::tlv::TLVTag,
                    ) -> impl Iterator<Item = Result<rs_matter_maybe_renamed::tlv::TLV, rs_matter_maybe_renamed::error::Error>> {
                        let iter = rs_matter_maybe_renamed::tlv::TLV::structure(tag).into_tlv_iter();

                        let iter = Iterator::chain(
                            iter,
                            rs_matter_maybe_renamed::tlv::ToTLV::tlv_iter(&self.field1,rs_matter_maybe_renamed::tlv::TLVTag::Context(0u8)),
                        );

                        let iter = Iterator::chain(
                            iter,
                            rs_matter_maybe_renamed::tlv::ToTLV::tlv_iter(&self.field2, rs_matter_maybe_renamed::tlv::TLVTag::Context(1u8)),
                        );

                        Iterator::chain(iter, rs_matter_maybe_renamed::tlv::TLV::end_container().into_tlv_iter())
                    }
                }
            )
        );
    }

    #[test]
    fn test_from_tlv_for_struct() {
        let ast: DeriveInput = syn::parse2(quote!(
            struct TestS {
                field1: u8,
                field2: u32,
                field_opt: Option<u32>,
                field_null: rs_matter_maybe_renamed::tlv::Nullable<u32>,
            }
        ))
        .unwrap();

        assert_tokenstreams_eq!(
            &derive_fromtlv(ast, "rs_matter_maybe_renamed".to_string()),
            &quote!(
                impl<'__from_tlv> rs_matter_maybe_renamed::tlv::FromTLV<'__from_tlv> for TestS {
                    fn from_tlv(
                        element: &rs_matter_maybe_renamed::tlv::TLVElement<'__from_tlv>,
                    ) -> Result<Self, rs_matter_maybe_renamed::error::Error> {
                        #[allow(unused_mut)]
                        let mut seq = element.r#struct()?;

                        Ok(Self {
                            field1: u8::from_tlv(&seq.scan_ctx(0u8)?)?,
                            field2: u32::from_tlv(&seq.scan_ctx(1u8)?)?,
                            field_opt: Option::from_tlv(&seq.scan_ctx(2u8)?)?,
                            field_null: rs_matter_maybe_renamed::tlv::Nullable::from_tlv(
                                &seq.scan_ctx(3u8)?,
                            )?,
                        })
                    }

                    fn init_from_tlv(
                        element: rs_matter_maybe_renamed::tlv::TLVElement<'__from_tlv>,
                    ) -> impl rs_matter_maybe_renamed::utils::init::Init<
                        Self,
                        rs_matter_maybe_renamed::error::Error,
                    > {
                        rs_matter_maybe_renamed::utils::init::into_init(move || {
                            #[allow(unused_mut)]
                            let mut seq = element.r#struct()?;

                            let init = rs_matter_maybe_renamed::utils::init::try_init!(Self {
                                field1 <- u8::init_from_tlv(seq.scan_ctx(0u8)?),
                                field2 <- u32::init_from_tlv(seq.scan_ctx(1u8)?),
                                field_opt <- Option::init_from_tlv(seq.scan_ctx(2u8)?),
                                field_null <- rs_matter_maybe_renamed::tlv::Nullable::init_from_tlv(seq.scan_ctx(3u8)?),
                            }? rs_matter_maybe_renamed::error::Error);

                            Ok(init)
                        })
                    }
                }

                impl<'__from_tlv> TryFrom<&rs_matter_maybe_renamed::tlv::TLVElement<'__from_tlv>> for TestS {
                    type Error = rs_matter_maybe_renamed::error::Error;

                    fn try_from(
                        element: &rs_matter_maybe_renamed::tlv::TLVElement<'__from_tlv>,
                    ) -> Result<Self, Self::Error> {
                        use rs_matter_maybe_renamed::tlv::FromTLV;
                        Self::from_tlv(element)
                    }
                }
            )
        );
    }

    #[test]
    fn test_to_tlv_for_enum() {
        let ast: DeriveInput = syn::parse2(quote!(
            enum TestEnum {
                ValueA(u32),
                ValueB(u32),
            }
        ))
        .unwrap();

        assert_tokenstreams_eq!(
            &derive_totlv(ast, "rs_matter_maybe_renamed".to_string()),
            &quote!(
                impl rs_matter_maybe_renamed::tlv::ToTLV for TestEnum {
                    fn to_tlv<W: rs_matter_maybe_renamed::tlv::TLVWrite>(
                        &self,
                        tag: &rs_matter_maybe_renamed::tlv::TLVTag,
                        mut tw: W,
                    ) -> Result<(), rs_matter_maybe_renamed::error::Error> {
                        let anchor = tw.get_tail();
                        if let Err(err) = (|| {
                            tw.start_struct(tag)?;
                            match self {
                                Self::ValueA(c) => rs_matter_maybe_renamed::tlv::ToTLV::to_tlv(c, &rs_matter_maybe_renamed::tlv::TLVTag::Context(0u8), &mut tw),
                                Self::ValueB(c) => rs_matter_maybe_renamed::tlv::ToTLV::to_tlv(c, &rs_matter_maybe_renamed::tlv::TLVTag::Context(1u8), &mut tw),
                            }?;
                            tw.end_container()
                        })() {
                            tw.rewind_to(anchor);
                            Err(err)
                        } else {
                            Ok(())
                        }
                    }

                    fn tlv_iter(
                        &self,
                        tag: rs_matter_maybe_renamed::tlv::TLVTag,
                    ) -> impl Iterator<Item = Result<rs_matter_maybe_renamed::tlv::TLV, rs_matter_maybe_renamed::error::Error>> {
                        let iter = rs_matter_maybe_renamed::tlv::TLV::structure(tag).into_tlv_iter();

                        let iter = Iterator::chain(
                            iter,
                            match self {
                                Self::ValueA(c) => rs_matter_maybe_renamed::tlv::EitherIter::First(
                                    rs_matter_maybe_renamed::tlv::ToTLV::tlv_iter(c, rs_matter_maybe_renamed::tlv::TLVTag::Context(0u8)),
                                ),
                                Self::ValueB(c) => rs_matter_maybe_renamed::tlv::EitherIter::Second(
                                    rs_matter_maybe_renamed::tlv::ToTLV::tlv_iter(c, rs_matter_maybe_renamed::tlv::TLVTag::Context(1u8)),
                                ),
                            },
                        );

                        Iterator::chain(iter, rs_matter_maybe_renamed::tlv::TLV::end_container().into_tlv_iter())
                    }
                }
            )
        );
    }

    #[test]
    fn test_to_tlv_for_unit_defaults() {
        let ast: DeriveInput = syn::parse2(quote!(
            enum TestEnum {
                ValueA,
                ValueB,
            }
        ))
        .unwrap();

        assert_tokenstreams_eq!(
            &derive_totlv(ast, "rs_matter_maybe_renamed".to_string()),
            &quote!(
                impl rs_matter_maybe_renamed::tlv::ToTLV for TestEnum {
                    fn to_tlv<W: rs_matter_maybe_renamed::tlv::TLVWrite>(
                        &self,
                        tag: &rs_matter_maybe_renamed::tlv::TLVTag,
                        mut tw: W,
                    ) -> Result<(), rs_matter_maybe_renamed::error::Error> {
                        let anchor = tw.get_tail();
                        if let Err(err) = (|| {
                            match self {
                                Self::ValueA => tw.u8(tag, 0u8),
                                Self::ValueB => tw.u8(tag, 1u8),
                            }
                        })() {
                            tw.rewind_to(anchor);
                            Err(err)
                        } else {
                            Ok(())
                        }
                    }

                    fn tlv_iter(
                        &self,
                        tag: rs_matter_maybe_renamed::tlv::TLVTag,
                    ) -> impl Iterator<Item = Result<rs_matter_maybe_renamed::tlv::TLV, rs_matter_maybe_renamed::error::Error>> {
                        match self {
                            Self::ValueA => rs_matter_maybe_renamed::tlv::TLV::u8(tag, 0u8).into_tlv_iter(),
                            Self::ValueB => rs_matter_maybe_renamed::tlv::TLV::u8(tag, 1u8).into_tlv_iter(),
                        }
                    }
                }
            )
        );
    }

    #[test]
    fn test_to_tlv_for_unit_enum() {
        let ast: DeriveInput = syn::parse2(quote!(
            #[tlvargs(datatype = "u16")]
            enum TestEnum {
                ValueA,
                ValueB,
                #[enumval(100)]
                ValueC,
                #[enumval(0x1234)]
                ValueD,
            }
        ))
        .unwrap();

        assert_tokenstreams_eq!(
            &derive_totlv(ast, "rs_matter_maybe_renamed".to_string()),
            &quote!(
                impl rs_matter_maybe_renamed::tlv::ToTLV for TestEnum {
                    fn to_tlv<W: rs_matter_maybe_renamed::tlv::TLVWrite>(
                        &self,
                        tag: &rs_matter_maybe_renamed::tlv::TLVTag,
                        mut tw: W,
                    ) -> Result<(), rs_matter_maybe_renamed::error::Error> {
                        let anchor = tw.get_tail();
                        if let Err(err) = (|| {
                            match self {
                                Self::ValueA => tw.u16(tag, 0u16),
                                Self::ValueB => tw.u16(tag, 1u16),
                                Self::ValueC => tw.u16(tag, 100u16),
                                Self::ValueD => tw.u16(tag, 4660u16),
                            }
                        })() {
                            tw.rewind_to(anchor);
                            Err(err)
                        } else {
                            Ok(())
                        }
                    }

                    fn tlv_iter(
                        &self,
                        tag: rs_matter_maybe_renamed::tlv::TLVTag,
                    ) -> impl Iterator<Item = Result<rs_matter_maybe_renamed::tlv::TLV, rs_matter_maybe_renamed::error::Error>> {
                        match self {
                            Self::ValueA => rs_matter_maybe_renamed::tlv::TLV::u16(tag, 0u16).into_tlv_iter(),
                            Self::ValueB => rs_matter_maybe_renamed::tlv::TLV::u16(tag, 1u16).into_tlv_iter(),
                            Self::ValueC => rs_matter_maybe_renamed::tlv::TLV::u16(tag, 100u16).into_tlv_iter(),
                            Self::ValueD => rs_matter_maybe_renamed::tlv::TLV::u16(tag, 4660u16).into_tlv_iter(),
                        }
                    }
                }
            )
        );
    }

    #[test]
    fn test_from_tlv_for_enum() {
        let ast: DeriveInput = syn::parse2(quote!(
            enum TestEnum {
                ValueA(u32),
                ValueB(u32),
            }
        ))
        .unwrap();

        assert_tokenstreams_eq!(
            &derive_fromtlv(ast, "rs_matter_maybe_renamed".to_string()),
            &quote!(
                impl rs_matter_maybe_renamed::tlv::FromTLV<'_> for TestEnum {
                    fn from_tlv(
                        element: &rs_matter_maybe_renamed::tlv::TLVElement<'_>,
                    ) -> Result<Self, rs_matter_maybe_renamed::error::Error> {
                        let element = element
                            .r#struct()?
                            .iter()
                            .next()
                            .ok_or(rs_matter_maybe_renamed::error::ErrorCode::TLVTypeMismatch)??;

                        let tag = element
                            .try_ctx()?
                            .ok_or(rs_matter_maybe_renamed::error::ErrorCode::TLVTypeMismatch)?;

                        Ok(match tag {
                            0u8 => Self::ValueA(u32::from_tlv(&element)?),
                            1u8 => Self::ValueB(u32::from_tlv(&element)?),
                            _ => Err(rs_matter_maybe_renamed::error::ErrorCode::Invalid)?,
                        })
                    }
                }

                impl TryFrom<&rs_matter_maybe_renamed::tlv::TLVElement<'_>> for TestEnum {
                    type Error = rs_matter_maybe_renamed::error::Error;

                    fn try_from(
                        element: &rs_matter_maybe_renamed::tlv::TLVElement<'_>,
                    ) -> Result<Self, Self::Error> {
                        use rs_matter_maybe_renamed::tlv::FromTLV;
                        Self::from_tlv(element)
                    }
                }
            )
        );
    }

    #[test]
    fn test_from_tlv_for_unit_enum() {
        let ast: DeriveInput = syn::parse2(quote!(
            enum TestEnum {
                ValueA,
                ValueB,
            }
        ))
        .unwrap();

        assert_tokenstreams_eq!(
            &derive_fromtlv(ast, "rs_matter_maybe_renamed".to_string()),
            &quote!(
                impl rs_matter_maybe_renamed::tlv::FromTLV<'_> for TestEnum {
                   fn from_tlv(
                        element: &rs_matter_maybe_renamed::tlv::TLVElement<'_>,
                    ) -> Result<Self, rs_matter_maybe_renamed::error::Error> {
                        Ok(match element.u8()? {
                            0u8 => Self::ValueA,
                            1u8 => Self::ValueB,
                            _ => Err(rs_matter_maybe_renamed::error::ErrorCode::Invalid)?,
                        })
                    }
                }

                impl TryFrom<&rs_matter_maybe_renamed::tlv::TLVElement<'_>> for TestEnum {
                    type Error = rs_matter_maybe_renamed::error::Error;

                    fn try_from(
                        element: &rs_matter_maybe_renamed::tlv::TLVElement<'_>,
                    ) -> Result<Self, Self::Error> {
                        use rs_matter_maybe_renamed::tlv::FromTLV;
                        Self::from_tlv(element)
                    }
                }
            )
        );
    }

    #[test]
    fn test_from_tlv_for_unit_enum_complex() {
        let ast: DeriveInput = syn::parse2(quote!(
            #[tlvargs(datatype = "u16")]
            enum TestEnum {
                A,
                B,
                #[enumval(100)]
                C,
                #[enumval(0x1234)]
                D,
            }
        ))
        .unwrap();

        assert_tokenstreams_eq!(
            &derive_fromtlv(ast, "rs_matter_maybe_renamed".to_string()),
            &quote!(
                impl rs_matter_maybe_renamed::tlv::FromTLV<'_> for TestEnum {
                    fn from_tlv(
                        element: &rs_matter_maybe_renamed::tlv::TLVElement<'_>,
                    ) -> Result<Self, rs_matter_maybe_renamed::error::Error> {
                        Ok(match element.u16()? {
                            0u16 => Self::A,
                            1u16 => Self::B,
                            100u16 => Self::C,
                            4660u16 => Self::D,
                            _ => Err(rs_matter_maybe_renamed::error::ErrorCode::Invalid)?,
                       })
                    }
                }

                impl TryFrom<&rs_matter_maybe_renamed::tlv::TLVElement<'_>> for TestEnum {
                    type Error = rs_matter_maybe_renamed::error::Error;

                    fn try_from(
                        element: &rs_matter_maybe_renamed::tlv::TLVElement<'_>,
                    ) -> Result<Self, Self::Error> {
                        use rs_matter_maybe_renamed::tlv::FromTLV;
                        Self::from_tlv(element)
                    }
                }
            )
        );
    }
}
