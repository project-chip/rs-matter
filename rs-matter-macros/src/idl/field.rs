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

//! A module for converting IDL field types to Rust types.

use proc_macro2::{Ident, TokenStream};
use quote::quote;

use super::id::ident;
use super::parser::{DataType, EntityContext};

/// Return a stream representing the Rust type that corresponds to the given
/// IDL type.
///
/// # Arguments
/// - `f`: The IDL type.
/// - `nullable`: Whether the type is nullable.
/// - `optional`: Whether the type is optional (applicable only for struct members and attributes).
/// - `entities`: The context of entities to which the type belongs.
/// - `krate`: The crate name.
pub fn field_type(
    f: &DataType,
    nullable: bool,
    optional: bool,
    entities: &EntityContext,
    krate: &Ident,
) -> TokenStream {
    let mut field_type = field_type_builtin(f, krate, true).unwrap_or_else(|| {
        let ident = ident(f.name.as_str());

        let structure = entities.structs().any(|s| s.id == f.name);
        if structure {
            quote!(#ident<'_>)
        } else {
            quote!(#ident)
        }
    });

    if f.is_list {
        field_type = quote!(#krate::tlv::TLVArray<'_, #field_type>);
    }

    if nullable {
        field_type = quote!(#krate::tlv::Nullable<#field_type>)
    }

    if optional {
        field_type = quote!(Option<#field_type>);
    }

    field_type
}

/// A policy for determining how to convert an IDL type to a Rust builder.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum BuilderPolicy {
    /// Use builders for types that are not `Copy` (i.e. structs and arrays).
    NonCopy,
    /// Use builders for types that are not `Copy` or strings (i.e. octet and UTF8 strings).
    NonCopyAndStrings,
    /// Use builders for all types.
    All,
}

/// Return a stream representing the Rust type builder that corresponds to the given
/// IDL type.
///
/// # Arguments
/// - `data_type`: The IDL type.
/// - `nullable`: Whether the type is nullable.
/// - `optional`: Whether the type is optional (applicable only for struct members and attributes).
/// - `policy`: The policy for determining how to convert the IDL type to a Rust builder.
/// - `parent`: The parent type for the returned builder (usually `P`)
/// - `entities`: Entities scoped to the type.
/// - `krate`: The crate name.
///
/// # Returns
/// A tuple containing the Rust type and a boolean indicating whether the returned type is actually a builder.
///
/// IDL types which are scalar (like bitmaps, enums, integers and so on) do not need to use the Rust
/// builder pattern, because they implement `Copy`, have a small memory footprint and can be passed
/// by value.
pub fn field_type_builder(
    data_type: &DataType,
    nullable: bool,
    optional: bool,
    policy: BuilderPolicy,
    parent: TokenStream,
    entities: &EntityContext,
    krate: &Ident,
) -> (TokenStream, bool) {
    let (mut typ, builder) = if data_type.is_octet_string()
        && (matches!(
            policy,
            BuilderPolicy::All | BuilderPolicy::NonCopyAndStrings
        ) || data_type.is_list)
    {
        (
            if data_type.is_list {
                quote!(#krate::tlv::OctetsArrayBuilder<#parent>)
            } else {
                quote!(#krate::tlv::OctetsBuilder<#parent>)
            },
            true,
        )
    } else if data_type.is_utf8_string()
        && (matches!(
            policy,
            BuilderPolicy::All | BuilderPolicy::NonCopyAndStrings
        ) || data_type.is_list)
    {
        (
            if data_type.is_list {
                quote!(#krate::tlv::Utf8StrArrayBuilder<#parent>)
            } else {
                quote!(#krate::tlv::Utf8StrBuilder<#parent>)
            },
            true,
        )
    } else if let Some(copy) = field_type_copy(data_type, entities, krate) {
        if data_type.is_list {
            (quote!(#krate::tlv::ToTLVArrayBuilder<#parent, #copy>), true)
        } else if matches!(policy, BuilderPolicy::All) {
            (quote!(#krate::tlv::ToTLVBuilder<#parent, #copy>), true)
        } else {
            (quote!(#copy), false)
        }
    } else {
        let ident = ident(&format!(
            "{}{}Builder",
            data_type.name.as_str(),
            if data_type.is_list { "Array" } else { "" }
        ));

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

/// Return a stream representing the Rust type that corresponds to the given
/// IDL type.
///
/// # Arguments
/// - `f`: The IDL type.
/// - `cluster`: The cluster to which the type belongs.
/// - `krate`: The crate name.
///
/// # Returns
/// `Some` stream representing the Rust type that corresponds to the given IDL type,
/// or `None` if the IDL type is not a `Copy` type (i.e. a container type like a struct or an array)
///
/// Note that this function always treats IDL Utf8 and octet strings as `Copy` types,
/// however callers should be careful as in some contexts this is fine, while in others - it isn't.
fn field_type_copy(f: &DataType, entities: &EntityContext, krate: &Ident) -> Option<TokenStream> {
    if let Some(stream) = field_type_builtin(f, krate, true) {
        return Some(stream);
    }

    if entities.structs().all(|s| s.id != f.name) {
        let ident = ident(f.name.as_str());
        return Some(quote!(#ident));
    }

    None
}

/// Return a stream representing the Rust type that corresponds to the given
/// IDL built-in type.
///
/// # Arguments
/// - `f`: The IDL type.
/// - `krate`: The crate name.
/// - `anon_lifetime`: Whether to use an anonymous (`'_`) lifetime for the returned Rust type or
///   a regular one (`'a`)
///   Only relevant when the built-in type is a Utf string or octet string.
///
/// # Returns
/// `Some` stream representing the Rust type that corresponds to the given IDL built-in type,
/// or `None` if the IDL type is not a built-in type.
fn field_type_builtin(f: &DataType, krate: &Ident, anon_lifetime: bool) -> Option<TokenStream> {
    // NOTE: f.max_length is not used (i.e. we do not limit or check string length limit)

    Some(match f.name.to_ascii_lowercase().as_str() {
        "enum8" | "int8u" | "bitmap8" => quote!(u8),
        "enum16" | "int16u" | "bitmap16" => quote!(u16),
        "int24u" | "int32u" | "bitmap32" => quote!(u32),
        "int40u" | "int48u" | "int56u" | "int64u" | "bitmap64" => quote!(u64),
        "int8s" => quote!(i8),
        "int16s" => quote!(i16),
        "int24s" | "int32s" => quote!(i32),
        "int40s" | "int48s" | "int56s" | "int64s" => quote!(i64),
        "single" => quote!(f32),
        "double" => quote!(f64),
        "boolean" => quote!(bool),

        // Spec section 7.19.2 - derived data types
        "priority" => quote!(u8),
        "status" => quote!(u8),
        "percent" => quote!(#krate::im::Percent),
        "percent100ths" => quote!(#krate::im::Percent100ths),
        "epoch_us" => quote!(u64),
        "epoch_s" => quote!(u32),
        "utc" => quote!(u32), // deprecated in the spec
        "posix_ms" => quote!(u64),
        "systime_us" => quote!(u64),
        "systime_ms" => quote!(u64),
        "elapsed_s" => quote!(u32),
        "temperature" => quote!(i16),
        "group_id" => quote!(u16),
        "endpoint_no" => quote!(#krate::im::EndptId),
        "vendor_id" => quote!(u16),
        "devtype_id" => quote!(u32),
        "fabric_id" => quote!(#krate::im::FabricId),
        "fabric_idx" => quote!(#krate::im::FabricIndex),
        "cluster_id" => quote!(#krate::im::ClusterId),
        "attrib_id" => quote!(#krate::im::AttrId),
        "field_id" => quote!(#krate::im::FieldId),
        "event_id" => quote!(u32),
        "command_id" => quote!(#krate::im::CmdId),
        "action_id" => quote!(u8),
        "trans_id" => quote!(u32),
        "node_id" => quote!(u64),
        "entry_idx" => quote!(u16),
        "data_ver" => quote!(u32),
        "event_no" => quote!(u64),
        "namespace" => quote!(u8),
        "tag" => quote!(u8),
        "energy_mwh" => quote!(#krate::im::EnergyMilliWh),
        "Energy_mvah" => quote!(#krate::im::EnergyMilliVAh),
        "Energy_mvarh" => quote!(#krate::im::EnergyMilliVARh),
        "amperage_ma" => quote!(#krate::im::AmperageMilliA),
        "power_mw" => quote!(#krate::im::PowerMilliW),
        "power_mva" => quote!(#krate::im::PowerMilliVA),
        "power_mvar" => quote!(#krate::im::PowerMilliVAR),
        "voltage_mv" => quote!(#krate::im::VoltageMilliV),
        "money" => quote!(#krate::im::Money),

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

        // Everything else is a struct, enum or bitmap which are not built-in types
        _ => return None,
    })
}
