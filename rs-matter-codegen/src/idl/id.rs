/*
 * Copyright (c) 2025-2026 Project CHIP Authors
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

//! A collection of utilities for converting IDL identifiers to Rust identifiers.

use convert_case::{Case, Casing};
use proc_macro2::{Ident, Span};

/// Convert an IDL identifier (like `kFoo`) into a name suitable for
/// constants based on Rust guidelines
///
/// Examples:
///
/// ```ignore
/// use rs_matter_macros_impl::idl::id::idl_id_to_constant_name;
///
/// assert_eq!(idl_id_to_constant_name("kAbc"), "ABC");
/// assert_eq!(idl_id_to_constant_name("kAbcXyz"), "ABC_XYZ");
/// assert_eq!(idl_id_to_constant_name("ThisIsATest"), "THIS_IS_A_TEST");
/// assert_eq!(idl_id_to_constant_name("k2G5"), "C2G5");
/// ```
pub fn idl_id_to_constant_name(s: &str) -> String {
    let str = s.strip_prefix('k').unwrap_or(s).to_case(Case::UpperSnake);
    let char = str.chars().next().unwrap();
    if !char.is_alphabetic() {
        format!("C{str}")
    } else {
        str
    }
}

/// Convert an IDL identifier (like `kFoo`) into a name suitable for
/// Rust enum variants
///
/// Examples:
///
/// ```ignore
/// use rs_matter_macros_impl::idl::id::idl_id_to_enum_variant_name;
///
/// assert_eq!(idl_id_to_enum_variant_name("kAbc"), "Abc");
/// assert_eq!(idl_id_to_enum_variant_name("kAbcXyz"), "AbcXyz");
/// assert_eq!(idl_id_to_enum_variant_name("k2G5"), "V2G5");
/// ```
pub fn idl_id_to_enum_variant_name(s: &str) -> String {
    let str = s.strip_prefix('k').unwrap_or(s).to_string();
    let char = str.chars().next().unwrap();
    // Error is used by core::convert::TryFrom & causes a collision
    if !char.is_alphabetic() || str.eq("Error") {
        format!("V{str}")
    } else {
        str
    }
}

/// Convert an IDL identifier (like `anotherTest`) into a name suitable for
/// fields based on Rust guidelines
///
/// Examples:
///
/// ```ignore
/// use rs_matter_macros_impl::idl::id::idl_field_name_to_rs_name;
///
/// assert_eq!(idl_field_name_to_rs_name("test"), "test");
/// assert_eq!(idl_field_name_to_rs_name("anotherTest"), "another_test");
/// assert_eq!(idl_field_name_to_rs_name("NOCs"), "nocs");
/// ```
pub fn idl_field_name_to_rs_name(s: &str) -> String {
    s.replace("NOCs", "nocs-").to_case(Case::Snake)
}

/// Convert an IDL identifier (like `anotherTest`) into a name suitable for
/// types based on Rust guidelines
///
/// Examples:
///
/// ```ignore
/// use rs_matter_macros_impl::idl::id::idl_field_name_to_rs_type_name;
///
/// assert_eq!(idl_field_name_to_rs_type_name("test"), "Test");
/// assert_eq!(idl_field_name_to_rs_type_name("anotherTest"), "AnotherTest");
/// assert_eq!(idl_field_name_to_rs_type_name("another_test"), "AnotherTest");
/// assert_eq!(idl_field_name_to_rs_type_name("Identity"), "Identity");
/// ```
pub fn idl_field_name_to_rs_type_name(s: &str) -> String {
    let s = s.to_case(Case::Camel);
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

/// Convert an IDL attribute identifier (like `anotherTest`) into a name suitable for
/// enum variants based on Rust guidelines
///
/// Examples:
///
/// ```ingore
/// use rs_matter_macros_impl::idl::id::idl_attribute_name_to_enum_variant_name;
///
/// assert_eq!(idl_attribute_name_to_enum_variant_name("test"), "Test");
/// assert_eq!(idl_attribute_name_to_enum_variant_name("anotherTest"), "AnotherTest");
/// assert_eq!(idl_attribute_name_to_enum_variant_name("Identity"), "Identity");
/// ```
pub fn idl_attribute_name_to_enum_variant_name(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

/// Rust keywords that require raw identifier syntax (`r#name`) when used as identifiers.
const RUST_KEYWORDS: &[&str] = &[
    "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern",
    "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub",
    "ref", "return", "self", "Self", "static", "struct", "super", "trait", "true", "type",
    "unsafe", "use", "where", "while", "yield",
];

/// Create a new proc-macro identifier from a string, with `call_site` span.
pub fn ident(name: &str) -> Ident {
    if RUST_KEYWORDS.contains(&name) {
        Ident::new_raw(name, Span::call_site())
    } else {
        Ident::new(name, Span::call_site())
    }
}
