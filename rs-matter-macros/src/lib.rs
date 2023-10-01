/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

use proc_macro::TokenStream;
use proc_macro2::{Ident, Span};
use quote::{format_ident, quote};
use syn::Type;
use syn::{parse_macro_input, DeriveInput, Lifetime, LitInt, LitStr};

struct TlvArgs {
    start: u8,
    datatype: String,
    unordered: bool,
    lifetime: syn::Lifetime,
}

impl Default for TlvArgs {
    fn default() -> Self {
        Self {
            start: 0,
            datatype: "struct".to_string(),
            unordered: false,
            lifetime: Lifetime::new("'_", Span::call_site()),
        }
    }
}

fn parse_tlvargs(ast: &DeriveInput) -> syn::Result<TlvArgs> {
    let mut tlvargs: TlvArgs = Default::default();
    if let Some(attr) = ast.attrs.first() {
        if attr.path().is_ident("tlvargs") {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("start") {
                    let litint: LitInt = meta.value()?.parse()?;
                    tlvargs.start = litint.base10_parse::<u8>()?;
                } else if meta.path.is_ident("lifetime") {
                    let litstr: LitStr = meta.value()?.parse()?;
                    tlvargs.lifetime = Lifetime::new(&litstr.value(), Span::call_site());
                } else if meta.path.is_ident("datatype") {
                    let litstr: LitStr = meta.value()?.parse()?;
                    tlvargs.datatype = litstr.value();
                } else if meta.path.is_ident("unordered") {
                    tlvargs.unordered = true;
                } else {
                    return Err(meta.error("unsupported tlv argument"));
                }

                Ok(())
            })?;
        }
    }
    Ok(tlvargs)
}

fn parse_tag_val(field: &syn::Field) -> syn::Result<Option<u8>> {
    if let Some(attr) = field.attrs.first() {
        if attr.path().is_ident("tagval") {
            let litint: LitInt = attr.parse_args()?;
            return Ok(Some(litint.base10_parse::<u8>()?));
        }
    }

    Ok(None)
}

fn get_crate_name() -> String {
    let found_crate = proc_macro_crate::crate_name("rs-matter").unwrap_or_else(|err| {
        eprintln!("Warning: defaulting to `crate` {err}");
        proc_macro_crate::FoundCrate::Itself
    });

    match found_crate {
        proc_macro_crate::FoundCrate::Itself => String::from("crate"),
        proc_macro_crate::FoundCrate::Name(name) => name,
    }
}

/// Generate a ToTlv implementation for a structure
fn gen_totlv_for_struct(
    fields: &syn::FieldsNamed,
    struct_name: &proc_macro2::Ident,
    tlvargs: &TlvArgs,
    generics: &syn::Generics,
) -> syn::Result<TokenStream> {
    let mut tag_start = tlvargs.start;
    let datatype = format_ident!("start_{}", tlvargs.datatype);

    let mut idents = Vec::new();
    let mut tags = Vec::new();

    for field in fields.named.iter() {
        //        let field_name: &syn::Ident = field.ident.as_ref().unwrap();
        //        let name: String = field_name.to_string();
        //        let literal_key_str = syn::LitStr::new(&name, field.span());
        //        let type_name = &field.ty;
        //        keys.push(quote! { #literal_key_str });
        idents.push(&field.ident);
        //        types.push(type_name.to_token_stream());
        if let Some(a) = parse_tag_val(field)? {
            tags.push(a);
        } else {
            tags.push(tag_start);
            tag_start += 1;
        }
    }

    let expanded = quote! {
        impl #generics ToTLV for #struct_name #generics {
            fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
                let anchor = tw.get_tail();

                if let Err(err) = (|| {
                    tw. #datatype (tag_type)?;
                    #(
                        self.#idents.to_tlv(tw, TagType::Context(#tags))?;
                    )*
                    tw.end_container()
                })() {
                    tw.rewind_to(anchor);
                    Err(err)
                } else {
                    Ok(())
                }
            }
        }
    };
    //    panic!("The generated code is {}", expanded);
    Ok(expanded.into())
}

/// Generate a ToTlv implementation for an enum
fn gen_totlv_for_enum(
    data_enum: &syn::DataEnum,
    enum_name: &proc_macro2::Ident,
    tlvargs: &TlvArgs,
    generics: &syn::Generics,
) -> TokenStream {
    let mut tag_start = tlvargs.start;

    let mut variant_names = Vec::new();
    let mut types = Vec::new();
    let mut tags = Vec::new();

    for v in data_enum.variants.iter() {
        variant_names.push(&v.ident);
        if let syn::Fields::Unnamed(fields) = &v.fields {
            if let Type::Path(path) = &fields.unnamed[0].ty {
                types.push(&path.path.segments[0].ident);
            } else {
                panic!("Path not found {:?}", v.fields);
            }
        } else {
            panic!("Unnamed field not found {:?}", v.fields);
        }
        tags.push(tag_start);
        tag_start += 1;
    }

    let krate = Ident::new(&get_crate_name(), Span::call_site());

    let expanded = quote! {
        impl #generics #krate::tlv::ToTLV for #enum_name #generics {
            fn to_tlv(&self, tw: &mut #krate::tlv::TLVWriter, tag_type: #krate::tlv::TagType) -> Result<(), #krate::error::Error> {
                let anchor = tw.get_tail();

                if let Err(err) = (|| {
                    tw.start_struct(tag_type)?;
                    match self {
                        #(
                            Self::#variant_names(c) => { c.to_tlv(tw, #krate::tlv::TagType::Context(#tags))?; },
                        )*
                    }
                    tw.end_container()
                })() {
                    tw.rewind_to(anchor);
                    Err(err)
                } else {
                    Ok(())
                }
            }
        }
    };

    //    panic!("Expanded to {}", expanded);
    expanded.into()
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
///  #[argval(22)]
///  name: u8,
/// In the above case, the 'name' attribute will be encoded/decoded with
/// the tag 22

#[proc_macro_derive(ToTLV, attributes(tlvargs, tagval))]
pub fn derive_totlv(item: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(item as DeriveInput);
    let name = &ast.ident;

    let tlvargs = match parse_tlvargs(&ast) {
        Ok(tlvargs) => tlvargs,
        Err(e) => return e.to_compile_error().into(),
    };
    let generics = ast.generics;

    if let syn::Data::Struct(syn::DataStruct {
        fields: syn::Fields::Named(ref fields),
        ..
    }) = ast.data
    {
        gen_totlv_for_struct(fields, name, &tlvargs, &generics)
            .unwrap_or_else(|e| e.to_compile_error().into())
    } else if let syn::Data::Enum(data_enum) = ast.data {
        gen_totlv_for_enum(&data_enum, name, &tlvargs, &generics)
    } else {
        panic!(
            "Derive ToTLV - Only supported Struct for now {:?}",
            ast.data
        );
    }
}

/// Generate a FromTlv implementation for a structure
fn gen_fromtlv_for_struct(
    fields: &syn::FieldsNamed,
    struct_name: &proc_macro2::Ident,
    tlvargs: TlvArgs,
    generics: &syn::Generics,
) -> syn::Result<TokenStream> {
    let mut tag_start = tlvargs.start;
    let lifetime = tlvargs.lifetime;
    let datatype = format_ident!("confirm_{}", tlvargs.datatype);

    let mut idents = Vec::new();
    let mut types = Vec::new();
    let mut tags = Vec::new();

    for field in fields.named.iter() {
        let type_name = &field.ty;
        if let Some(a) = parse_tag_val(field)? {
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

        if let Type::Path(path) = type_name {
            types.push(&path.path.segments[0].ident);
        } else {
            panic!("Don't know what to do {:?}", type_name);
        }
    }

    let krate = Ident::new(&get_crate_name(), Span::call_site());

    // Currently we don't use find_tag() because the tags come in sequential
    // order. If ever the tags start coming out of order, we can use find_tag()
    // instead
    let expanded = if !tlvargs.unordered {
        quote! {
           impl #generics #krate::tlv::FromTLV <#lifetime> for #struct_name #generics {
               fn from_tlv(t: &#krate::tlv::TLVElement<#lifetime>) -> Result<Self, #krate::error::Error> {
                   let mut t_iter = t.#datatype ()?.enter().ok_or_else(|| #krate::error::Error::new(#krate::error::ErrorCode::Invalid))?;
                   let mut item = t_iter.next();
                   #(
                       let #idents = if Some(true) == item.as_ref().map(|x| x.check_ctx_tag(#tags)) {
                           let backup = item;
                           item = t_iter.next();
                           #types::from_tlv(&backup.unwrap())
                       } else {
                           #types::tlv_not_found()
                       }?;
                   )*
                   Ok(Self {
                       #(#idents,
                       )*
                   })
               }
           }
        }
    } else {
        quote! {
           impl #generics #krate::tlv::FromTLV <#lifetime> for #struct_name #generics {
               fn from_tlv(t: &#krate::tlv::TLVElement<#lifetime>) -> Result<Self, #krate::error::Error> {
                   #(
                       let #idents = if let Ok(s) = t.find_tag(#tags as u32) {
                           #types::from_tlv(&s)
                       } else {
                           #types::tlv_not_found()
                       }?;
                   )*

                   Ok(Self {
                       #(#idents,
                       )*
                   })
               }
           }
        }
    };
    //        panic!("The generated code is {}", expanded);
    Ok(expanded.into())
}

/// Generate a FromTlv implementation for an enum
fn gen_fromtlv_for_enum(
    data_enum: &syn::DataEnum,
    enum_name: &proc_macro2::Ident,
    tlvargs: TlvArgs,
    generics: &syn::Generics,
) -> TokenStream {
    let mut tag_start = tlvargs.start;
    let lifetime = tlvargs.lifetime;

    let mut variant_names = Vec::new();
    let mut types = Vec::new();
    let mut tags = Vec::new();

    for v in data_enum.variants.iter() {
        variant_names.push(&v.ident);
        if let syn::Fields::Unnamed(fields) = &v.fields {
            if let Type::Path(path) = &fields.unnamed[0].ty {
                types.push(&path.path.segments[0].ident);
            } else {
                panic!("Path not found {:?}", v.fields);
            }
        } else {
            panic!("Unnamed field not found {:?}", v.fields);
        }
        tags.push(tag_start);
        tag_start += 1;
    }

    let krate = Ident::new(&get_crate_name(), Span::call_site());

    let expanded = quote! {
           impl #generics #krate::tlv::FromTLV <#lifetime> for #enum_name #generics {
               fn from_tlv(t: &#krate::tlv::TLVElement<#lifetime>) -> Result<Self, #krate::error::Error> {
                   let mut t_iter = t.confirm_struct()?.enter().ok_or_else(|| #krate::error::Error::new(#krate::error::ErrorCode::Invalid))?;
                   let mut item = t_iter.next().ok_or_else(|| Error::new(#krate::error::ErrorCode::Invalid))?;
                   if let TagType::Context(tag) = item.get_tag() {
                       match tag {
                           #(
                               #tags => Ok(Self::#variant_names(#types::from_tlv(&item)?)),
                           )*
                           _ => Err(#krate::error::Error::new(#krate::error::ErrorCode::Invalid)),
                       }
                   } else {
                       Err(#krate::error::Error::new(#krate::error::ErrorCode::TLVTypeMismatch))
                   }
               }
           }
    };

    //        panic!("Expanded to {}", expanded);
    expanded.into()
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
///  #[argval(22)]
///  name: u8,
/// In the above case, the 'name' attribute will be encoded/decoded with
/// the tag 22

#[proc_macro_derive(FromTLV, attributes(tlvargs, tagval))]
pub fn derive_fromtlv(item: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(item as DeriveInput);
    let name = &ast.ident;

    let tlvargs = match parse_tlvargs(&ast) {
        Ok(tlvargs) => tlvargs,
        Err(e) => return e.to_compile_error().into(),
    };

    let generics = ast.generics;

    if let syn::Data::Struct(syn::DataStruct {
        fields: syn::Fields::Named(ref fields),
        ..
    }) = ast.data
    {
        gen_fromtlv_for_struct(fields, name, tlvargs, &generics)
            .unwrap_or_else(|e| e.to_compile_error().into())
    } else if let syn::Data::Enum(data_enum) = ast.data {
        gen_fromtlv_for_enum(&data_enum, name, tlvargs, &generics)
    } else {
        panic!(
            "Derive FromTLV - Only supported Struct for now {:?}",
            ast.data
        )
    }
}
