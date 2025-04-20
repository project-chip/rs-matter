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

use convert_case::{Case, Casing};

/// Converts a idl identifier (like `kFoo`) into a name suitable for
/// constants based on rust guidelines
///
/// Examples:
///
/// ```
/// use rs_matter_macros_impl::idl::idl_id_to_constant_name;
///
/// assert_eq!(idl_id_to_constant_name("kAbc"), "ABC");
/// assert_eq!(idl_id_to_constant_name("kAbcXyz"), "ABC_XYZ");
/// assert_eq!(idl_id_to_constant_name("ThisIsATest"), "THIS_IS_A_TEST");
/// ```
pub fn idl_id_to_constant_name(s: &str) -> String {
    let str = s.strip_prefix('k').unwrap_or(s).to_case(Case::UpperSnake);
    let char = str.chars().next().unwrap();
    if !char.is_alphabetic() {
        format!("C{}", str)
    } else {
        str
    }
}

/// Converts a idl identifier (like `kFoo`) into a name suitable for
/// constants based on rust guidelines
///
/// Examples:
///
/// ```
/// use rs_matter_macros_impl::idl::idl_field_name_to_rs_name;
///
/// assert_eq!(idl_field_name_to_rs_name("test"), "test");
/// assert_eq!(idl_field_name_to_rs_name("anotherTest"), "another_test");
/// ```
pub fn idl_field_name_to_rs_name(s: &str) -> String {
    s.to_case(Case::Snake)
}

pub fn idl_field_name_to_rs_type_name(s: &str) -> String {
    s.to_case(Case::Camel)
}

pub fn idl_attribute_name_to_enum_variant_name(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

/// Converts a idl identifier (like `kFoo`) into a name suitable for
/// enum names
///
/// Examples:
///
/// ```
/// use rs_matter_macros_impl::idl::idl_id_to_enum_name;
///
/// assert_eq!(idl_id_to_enum_name("kAbc"), "Abc");
/// assert_eq!(idl_id_to_enum_name("kAbcXyz"), "AbcXyz");
/// assert_eq!(idl_id_to_enum_name("ThisIsATest"), "ThisIsATest");
/// ```
pub fn idl_id_to_enum_name(s: &str) -> String {
    let str = s.strip_prefix('k').unwrap_or(s).to_string();
    let char = str.chars().next().unwrap();
    if !char.is_alphabetic() {
        format!("V{}", str)
    } else {
        str
    }
}
