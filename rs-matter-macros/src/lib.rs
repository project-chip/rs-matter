use std::collections::HashSet;
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
use proc_macro2::{Group, Ident, Punct, Span};
use quote::{format_ident, quote};
use rs_matter_data_model::CSA_STANDARD_CLUSTERS_IDL;
use rs_matter_macros_impl::server_side_cluster_generate;
use syn::meta::ParseNestedMeta;
use syn::parse::{Parse, ParseStream};
use syn::{parse_macro_input, DeriveInput, Lifetime, LitInt, LitStr, Type};

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

fn parse_tlvargs(ast: &DeriveInput) -> TlvArgs {
    let mut tlvargs = TlvArgs::default();

    for attr in ast.attrs.iter().filter(|a| a.path().is_ident("tlvargs")) {
        attr.parse_nested_meta(|meta| tlvargs.parse(meta)).unwrap();
    }

    tlvargs
}

fn parse_tag_val(field: &syn::Field) -> Option<u8> {
    field
        .attrs
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
) -> TokenStream {
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
        if let Some(a) = parse_tag_val(field) {
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
    expanded.into()
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
///  #[tagval(22)]
///  name: u8,
/// In the above case, the 'name' attribute will be encoded/decoded with
/// the tag 22

#[proc_macro_derive(ToTLV, attributes(tlvargs, tagval))]
pub fn derive_totlv(item: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(item as DeriveInput);
    let name = &ast.ident;

    let tlvargs = parse_tlvargs(&ast);
    let generics = ast.generics;

    if let syn::Data::Struct(syn::DataStruct {
        fields: syn::Fields::Named(ref fields),
        ..
    }) = ast.data
    {
        gen_totlv_for_struct(fields, name, &tlvargs, &generics)
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
) -> TokenStream {
    let mut tag_start = tlvargs.start;
    let lifetime = tlvargs.lifetime;
    let datatype = format_ident!("confirm_{}", tlvargs.datatype);

    let mut idents = Vec::new();
    let mut types = Vec::new();
    let mut tags = Vec::new();

    for field in fields.named.iter() {
        let type_name = &field.ty;
        if let Some(a) = parse_tag_val(field) {
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
    expanded.into()
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
///  #[tagval(22)]
///  name: u8,
/// In the above case, the 'name' attribute will be encoded/decoded with
/// the tag 22

#[proc_macro_derive(FromTLV, attributes(tlvargs, tagval))]
pub fn derive_fromtlv(item: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(item as DeriveInput);
    let name = &ast.ident;

    let tlvargs = parse_tlvargs(&ast);

    let generics = ast.generics;

    if let syn::Data::Struct(syn::DataStruct {
        fields: syn::Fields::Named(ref fields),
        ..
    }) = ast.data
    {
        gen_fromtlv_for_struct(fields, name, tlvargs, &generics)
    } else if let syn::Data::Enum(data_enum) = ast.data {
        gen_fromtlv_for_enum(&data_enum, name, tlvargs, &generics)
    } else {
        panic!(
            "Derive FromTLV - Only supported Struct for now {:?}",
            ast.data
        )
    }
}

#[derive(Debug)]
struct MatterIdlImportArgs {
    // What clusters to import. Non-empty list if
    // a clusters argument was given
    clusters: Option<HashSet<String>>,
}

impl Parse for MatterIdlImportArgs {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let clusters = if !input.is_empty() {
            // Argument is "clusters = [....]"
            //
            // Token stream looks like:
            //
            // TokenStream [
            //     Ident {
            //         ident: "clusters",
            //         span: #0 bytes(224041..224049),
            //     },
            //     Punct {
            //         ch: '=',
            //         spacing: Alone,
            //         span: #0 bytes(224050..224051),
            //     },
            //     Group {
            //         delimiter: Bracket,
            //         stream: TokenStream [
            //             Literal {
            //                 kind: Str,
            //                 symbol: "OnOff",
            //                 suffix: None,
            //                 span: #0 bytes(224053..224060),
            //             },
            //         ],
            //         span: #0 bytes(224052..224061),
            //     },
            //  ]

            assert_eq!(input.parse::<Ident>()?.to_string(), "clusters");
            assert_eq!(input.parse::<Punct>()?.as_char(), '=');

            Some(
                input
                    .parse::<Group>()?
                    .stream()
                    .into_iter()
                    .map(|item| match item {
                        proc_macro2::TokenTree::Literal(l) => {
                            let repr = l.to_string();
                            // Representation  includes quotes. Remove them
                            // TODO: this does NOT support `r"..."` or similar, however
                            //       those should generally not be needed
                            repr[1..(repr.len() - 1)].to_owned()
                        }
                        _ => panic!("Expected a token"),
                    })
                    .collect::<HashSet<_>>(),
            )
        } else {
            None
        };

        if let Some(ref values) = clusters {
            if values.is_empty() {
                panic!("Input clusters MUST be non-empty. If you want no filtering, omit this argument.");
            }
        }

        Ok(MatterIdlImportArgs { clusters })
    }
}

/// Imports a matter IDL and generates code for it
///
/// Files are assumed to be located inside `RS_MATTER_IDL_DIR` from the environment.
/// Generally this means that `.cargo/config.toml` should include something like
/// `RS_MATTER_IDL_DIR = { value="idl", relative=true }`
///
/// `idl_import!("file.matter")` imports the entire file.
///
/// `idl_import!("file.matter", clusters=["A", "B", "C"])` restricts the
/// import to the given clusters
#[proc_macro]
pub fn idl_import(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as MatterIdlImportArgs);

    let idl = rs_matter_data_model::idl::Idl::parse(CSA_STANDARD_CLUSTERS_IDL.into()).unwrap();

    let streams = idl
        .clusters
        .iter()
        .filter(|c| match input.clusters {
            Some(ref v) => v.contains(&c.id),
            None => true,
        })
        .map(server_side_cluster_generate);

    quote!(
        // IDL-generated code:
        #(#streams)*
    )
    .into()
}
