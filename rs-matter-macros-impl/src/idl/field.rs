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

use rs_matter_data_model::{Cluster, DataType};

pub fn field_type(f: &DataType, nullable: bool, optional: bool, krate: &Ident) -> TokenStream {
    let mut field_type = field_type_scalar(f, krate, true).unwrap_or_else(|| {
        let ident = Ident::new(f.name.as_str(), Span::call_site());
        quote!(#ident)
    });

    if f.is_list {
        field_type = quote!(#krate::tlv::TLVArray<#field_type>);
    }

    if nullable {
        field_type = quote!(#krate::tlv::Nullable<#field_type>)
    }

    if optional {
        field_type = quote!(Option<#field_type>);
    }

    field_type
}

pub fn field_type_out(
    data_type: &DataType,
    nullable: bool,
    optional: bool,
    strings_as_builders: bool,
    parent: TokenStream,
    cluster: &Cluster,
    krate: &Ident,
) -> (TokenStream, bool) {
    let (mut typ, builder) =
        if data_type.is_octet_string() && (strings_as_builders || data_type.is_list) {
            (
                if data_type.is_list {
                    quote!(#krate::tlv::OctetsArrayBuilder<#parent>)
                } else {
                    quote!(#krate::tlv::OctetsBuilder<#parent>)
                },
                true,
            )
        } else if data_type.is_utf8_string() && (strings_as_builders || data_type.is_list) {
            (
                if data_type.is_list {
                    quote!(#krate::tlv::Utf8StrArrayBuilder<#parent>)
                } else {
                    quote!(#krate::tlv::Utf8StrBuilder<#parent>)
                },
                true,
            )
        } else if let Some(copy) = field_type_copy(data_type, cluster, krate) {
            if data_type.is_list {
                (quote!(#krate::tlv::ToTLVArrayBuilder<#parent, #copy>), true)
            } else {
                (quote!(#copy), false)
            }
        } else {
            let ident = Ident::new(
                &format!(
                    "{}{}Builder",
                    data_type.name.as_str(),
                    if data_type.is_list { "Array" } else { "" }
                ),
                Span::call_site(),
            );

            (quote!(#ident<#parent>), true)
        };

    if builder {
        if nullable {
            typ = quote!(#krate::tlv::NullableBuilder<#parent, #typ>);
        }

        if optional {
            typ = quote!(#krate::tlv::OptionalBuilder<#parent, #typ>);
        }
    } else {
        if nullable {
            typ = quote!(#krate::tlv::Nullable<#typ>);
        }

        if optional {
            typ = quote!(Option<#typ>);
        }
    }

    (typ, builder)
}

fn field_type_copy(f: &DataType, cluster: &Cluster, krate: &Ident) -> Option<TokenStream> {
    if let Some(stream) = field_type_scalar(f, krate, true) {
        return Some(stream);
    }

    if cluster.structs.iter().all(|s| s.id != f.name) {
        let ident = Ident::new(f.name.as_str(), Span::call_site());
        return Some(quote!(#ident));
    }

    None
}

fn field_type_scalar(f: &DataType, krate: &Ident, anon_lifetime: bool) -> Option<TokenStream> {
    // NOTE: f.max_length is not used (i.e. we do not limit or check string length limit)

    Some(match f.name.as_str() {
        "enum8" | "int8u" | "bitmap8" => quote!(u8),
        "enum16" | "int16u" | "bitmap16" => quote!(u16),
        "int32u" | "bitmap32" => quote!(u32),
        "int64u" | "bitmap64" => quote!(u64),
        "int8s" => quote!(i8),
        "int16s" => quote!(i16),
        "int32s" => quote!(i32),
        "int64s" => quote!(i64),
        "single" => quote!(f32),
        "double" => quote!(f64),
        "boolean" => quote!(bool),

        // Spec section 7.19.2 - derived data types
        "priority" => quote!(u8),
        "status" => quote!(u8),
        "percent" => quote!(u8),
        "percent100ths" => quote!(u16),
        "epoch_us" => quote!(u64),
        "epoch_s" => quote!(u32),
        "utc" => quote!(u32), // deprecated in the spec
        "posix_ms" => quote!(u64),
        "systime_us" => quote!(u64),
        "systime_ms" => quote!(u64),
        "elapsed_s" => quote!(u32),
        "temperature" => quote!(i16),
        "group_id" => quote!(u16),
        "endpoint_no" => quote!(u16),
        "vendor_id" => quote!(u16),
        "devtype_id" => quote!(u32),
        "fabric_id" => quote!(u64),
        "fabric_idx" => quote!(u8),
        "cluster_id" => quote!(u32),
        "attrib_id" => quote!(u32),
        "field_id" => quote!(u32),
        "event_id" => quote!(u32),
        "command_id" => quote!(u32),
        "action_id" => quote!(u8),
        "trans_id" => quote!(u32),
        "node_id" => quote!(u64),
        "entry_idx" => quote!(u16),
        "data_ver" => quote!(u32),
        "event_no" => quote!(u64),
        "namespace" => quote!(u8),
        "tag" => quote!(u8),

        // Items with lifetime. If updating this, remember to add things to
        // [needs_lifetime]
        "char_string" | "long_char_string" => {
            if anon_lifetime {
                quote!(#krate::tlv::Utf8Str<'_>)
            } else {
                quote!(#krate::tlv::Utf8Str<'a>)
            }
        }
        "octet_string" | "long_octet_string" => {
            if anon_lifetime {
                quote!(#krate::tlv::OctetStr<'_>)
            } else {
                quote!(#krate::tlv::OctetStr<'a>)
            }
        }

        // Unsupported bits.
        "ipadr" | "ipv4adr" | "ipv6adr" | "ipv6pre" | "hwadr" | "semtag" | "tod" | "date" => {
            panic!("Unsupported field type {}", f.name)
        }

        // Assume anything else is some struct/enum/bitmap and report as-is
        _ => return None,
    })
}
