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

use rs_matter_data_model::Cluster;

mod bitmap;
mod cluster;
mod enumeration;
mod field;
mod handler;
mod id;
mod struct_in;
mod struct_out;

/// Some context data for IDL generation
///
/// Data that is necessary to be able to code generate various bits.
/// In particular, matter_rs types (e.g. TLV or traits) are needed,
/// hence the crate name is provided
pub struct IdlGenerateContext {
    rs_matter_crate: Ident,
}

impl IdlGenerateContext {
    pub fn new(rs_matter_crate: impl AsRef<str>) -> Self {
        Self {
            rs_matter_crate: Ident::new(rs_matter_crate.as_ref(), Span::call_site()),
        }
    }
}

pub fn cluster(cluster: &Cluster, context: &IdlGenerateContext) -> TokenStream {
    //let cluster_module_name = Ident::new(&cluster.id.to_case(Case::Snake), Span::call_site());

    let bitmaps = bitmap::bitmaps(cluster, context);
    let enums = enumeration::enums(cluster, context);
    let struct_tags = struct_in::struct_tags(cluster);
    let structs = struct_in::structs(cluster, context);
    let struct_builders = struct_out::struct_builders(cluster, context);

    let attribute_id = cluster::attribute_id(cluster, context);
    let command_id = cluster::command_id(cluster, context);
    let command_response_id = cluster::command_response_id(cluster, context);
    let cluster_meta = cluster::cluster(cluster, context);

    let handler = handler::handler(cluster, context);
    let handler_adaptor = handler::handler_adaptor(cluster, context);

    let cluster_code = Literal::u32_unsuffixed(cluster.code as u32);

    quote!(
        pub const ID: u32 = #cluster_code;

        #bitmaps

        #enums

        #struct_tags

        #structs

        #struct_builders

        #attribute_id

        #command_id

        #command_response_id

        #cluster_meta

        #handler

        #handler_adaptor
    )
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use assert_tokenstreams_eq::assert_tokenstreams_eq;
//     use quote::quote;
//     use rs_matter_data_model::idl::Idl;
//     use rs_matter_data_model::Cluster;

//     fn parse_idl(input: &str) -> Idl {
//         Idl::parse(input.into()).expect("valid input")
//     }

//     fn get_cluster_named<'a>(idl: &'a Idl, name: &str) -> Option<&'a Cluster> {
//         idl.clusters.iter().find(|&cluster| cluster.id == name)
//     }

//     #[test]
//     fn struct_generation_works() {
//         let idl = parse_idl(
//             "
//               cluster TestForStructs = 1 {

//                 // a somewhat complex struct
//                 struct NetworkInfoStruct {
//                   boolean connected = 1;
//                   optional int8u test_optional = 2;
//                   nullable int16u test_nullable = 3;
//                   optional nullable int32u test_both = 4;
//                 }

//                 // Some varying requests
//                 request struct IdentifyRequest {
//                   int16u identifyTime = 0;
//                 }

//                 request struct SomeRequest {
//                   group_id group = 0;
//                 }

//                 // Some responses
//                 response struct TestResponse = 0 {
//                   int8u capacity = 0;
//                 }

//                 response struct AnotherResponse = 1 {
//                   enum8 status = 0;
//                   group_id groupID = 12;
//                 }
//               }
//             ",
//         );

//         let cluster = get_cluster_named(&idl, "TestForStructs").expect("Cluster exists");
//         let context = IdlGenerateContext::new("rs_matter_crate");

//         let defs: TokenStream = cluster
//             .structs
//             .iter()
//             .map(|c| struct_definition(c, &context))
//             .collect();

//         assert_tokenstreams_eq!(
//             &defs,
//             &quote!(
//                 #[derive(
//                     Debug,
//                     PartialEq,
//                     Eq,
//                     Clone,
//                     Hash,
//                     rs_matter_crate::tlv::FromTLV,
//                     rs_matter_crate::tlv::ToTLV,
//                 )]
//                 pub struct NetworkInfoStruct {
//                     connected: bool,
//                     test_optional: Option<u8>,
//                     test_nullable: rs_matter_crate::tlv::Nullable<u16>,
//                     test_both: Option<rs_matter_crate::tlv::Nullable<u32>>,
//                 }

//                 #[derive(
//                     Debug,
//                     PartialEq,
//                     Eq,
//                     Clone,
//                     Hash,
//                     rs_matter_crate::tlv::FromTLV,
//                     rs_matter_crate::tlv::ToTLV,
//                 )]
//                 pub struct IdentifyRequest {
//                     identify_time: u16,
//                 }

//                 #[derive(
//                     Debug,
//                     PartialEq,
//                     Eq,
//                     Clone,
//                     Hash,
//                     rs_matter_crate::tlv::FromTLV,
//                     rs_matter_crate::tlv::ToTLV,
//                 )]
//                 pub struct SomeRequest {
//                     group: u16,
//                 }

//                 #[derive(
//                     Debug,
//                     PartialEq,
//                     Eq,
//                     Clone,
//                     Hash,
//                     rs_matter_crate::tlv::FromTLV,
//                     rs_matter_crate::tlv::ToTLV,
//                 )]
//                 pub struct TestResponse {
//                     capacity: u8,
//                 }

//                 #[derive(
//                     Debug,
//                     PartialEq,
//                     Eq,
//                     Clone,
//                     Hash,
//                     rs_matter_crate::tlv::FromTLV,
//                     rs_matter_crate::tlv::ToTLV,
//                 )]
//                 pub struct AnotherResponse {
//                     status: u8,
//                     group_id: u16,
//                 }
//             )
//         );
//     }

//     #[test]
//     fn generation_works() {
//         let idl = parse_idl(
//             "
//               cluster OnOff = 6 {
//                 revision 6;

//                 enum DelayedAllOffEffectVariantEnum : enum8 {
//                   kDelayedOffFastFade = 0;
//                   kNoFade = 1;
//                   kDelayedOffSlowFade = 2;
//                 }

//                 enum DyingLightEffectVariantEnum : enum8 {
//                   kDyingLightFadeOff = 0;
//                 }

//                 enum EffectIdentifierEnum : enum8 {
//                   kDelayedAllOff = 0;
//                   kDyingLight = 1;
//                 }

//                 enum StartUpOnOffEnum : enum8 {
//                   kOff = 0;
//                   kOn = 1;
//                   kToggle = 2;
//                 }

//                 bitmap Feature : bitmap32 {
//                   kLighting = 0x1;
//                   kDeadFrontBehavior = 0x2;
//                   kOffOnly = 0x4;
//                 }

//                 bitmap OnOffControlBitmap : bitmap8 {
//                   kAcceptOnlyWhenOn = 0x1;
//                 }

//                 readonly attribute boolean onOff = 0;
//                 readonly attribute optional boolean globalSceneControl = 16384;
//                 attribute optional int16u onTime = 16385;
//                 attribute optional int16u offWaitTime = 16386;
//                 attribute access(write: manage) optional nullable StartUpOnOffEnum startUpOnOff = 16387;
//                 readonly attribute command_id generatedCommandList[] = 65528;
//                 readonly attribute command_id acceptedCommandList[] = 65529;
//                 readonly attribute event_id eventList[] = 65530;
//                 readonly attribute attrib_id attributeList[] = 65531;
//                 readonly attribute bitmap32 featureMap = 65532;
//                 readonly attribute int16u clusterRevision = 65533;

//                 request struct OffWithEffectRequest {
//                   EffectIdentifierEnum effectIdentifier = 0;
//                   enum8 effectVariant = 1;
//                 }

//                 request struct OnWithTimedOffRequest {
//                   OnOffControlBitmap onOffControl = 0;
//                   int16u onTime = 1;
//                   int16u offWaitTime = 2;
//                 }

//                 /** On receipt of this command, a device SHALL enter its ‘Off’ state. This state is device dependent, but it is recommended that it is used for power off or similar functions. On receipt of the Off command, the OnTime attribute SHALL be set to 0. */
//                 command Off(): DefaultSuccess = 0;
//                 /** On receipt of this command, a device SHALL enter its ‘On’ state. This state is device dependent, but it is recommended that it is used for power on or similar functions. On receipt of the On command, if the value of the OnTime attribute is equal to 0, the device SHALL set the OffWaitTime attribute to 0. */
//                 command On(): DefaultSuccess = 1;
//                 /** On receipt of this command, if a device is in its ‘Off’ state it SHALL enter its ‘On’ state. Otherwise, if it is in its ‘On’ state it SHALL enter its ‘Off’ state. On receipt of the Toggle command, if the value of the OnOff attribute is equal to FALSE and if the value of the OnTime attribute is equal to 0, the device SHALL set the OffWaitTime attribute to 0. If the value of the OnOff attribute is equal to TRUE, the OnTime attribute SHALL be set to 0. */
//                 command Toggle(): DefaultSuccess = 2;
//                 /** The OffWithEffect command allows devices to be turned off using enhanced ways of fading. */
//                 command OffWithEffect(OffWithEffectRequest): DefaultSuccess = 64;
//                 /** The OnWithRecallGlobalScene command allows the recall of the settings when the device was turned off. */
//                 command OnWithRecallGlobalScene(): DefaultSuccess = 65;
//                 /** The OnWithTimedOff command allows devices to be turned on for a specific duration with a guarded off duration so that SHOULD the device be subsequently switched off, further OnWithTimedOff commands, received during this time, are prevented from turning the devices back on. */
//                 command OnWithTimedOff(OnWithTimedOffRequest): DefaultSuccess = 66;
//               }
//         ",
//         );
//         let cluster = get_cluster_named(&idl, "OnOff").expect("Cluster exists");
//         let context = IdlGenerateContext::new("rs_matter_crate");

//         assert_tokenstreams_eq!(
//             &server_side_cluster_generate(cluster, &context),
//             &quote!(
//                 mod on_off {
//                     pub const ID: u32 = 6;

//                     use rs_matter_crate::error::Error;
//                     use rs_matter_crate::tlv::{FromTLV, TLVElement, TLVWriter, TagType, ToTLV};

//                     bitflags::bitflags! {
//                       #[repr(transparent)]
//                       #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
//                       pub struct Feature : u32 {
//                         const LIGHTING = 1;
//                         const DEAD_FRONT_BEHAVIOR = 2;
//                         const OFF_ONLY = 4;
//                       }
//                     }
//                     rs_matter_crate::bitflags_tlv!(Feature, u32);

//                     bitflags::bitflags! {
//                       #[repr(transparent)]
//                       #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
//                       pub struct OnOffControlBitmap : u8 {
//                         const ACCEPT_ONLY_WHEN_ON = 1;
//                       }
//                     }
//                     rs_matter_crate::bitflags_tlv!(OnOffControlBitmap, u8);

//                     #[derive(
//                         Debug,
//                         PartialEq,
//                         Eq,
//                         Copy,
//                         Clone,
//                         Hash,
//                         rs_matter_crate::tlv::FromTLV,
//                         rs_matter_crate::tlv::ToTLV,
//                     )]
//                     #[repr(u8)]
//                     pub enum DelayedAllOffEffectVariantEnum {
//                         #[enumval(0)]
//                         DelayedOffFastFade = 0,
//                         #[enumval(1)]
//                         NoFade = 1,
//                         #[enumval(2)]
//                         DelayedOffSlowFade = 2,
//                     }

//                     #[derive(
//                         Debug,
//                         PartialEq,
//                         Eq,
//                         Copy,
//                         Clone,
//                         Hash,
//                         rs_matter_crate::tlv::FromTLV,
//                         rs_matter_crate::tlv::ToTLV,
//                     )]
//                     #[repr(u8)]
//                     pub enum DyingLightEffectVariantEnum {
//                         #[enumval(0)]
//                         DyingLightFadeOff = 0,
//                     }

//                     #[derive(
//                         Debug,
//                         PartialEq,
//                         Eq,
//                         Copy,
//                         Clone,
//                         Hash,
//                         rs_matter_crate::tlv::FromTLV,
//                         rs_matter_crate::tlv::ToTLV,
//                     )]
//                     #[repr(u8)]
//                     pub enum EffectIdentifierEnum {
//                         #[enumval(0)]
//                         DelayedAllOff = 0,
//                         #[enumval(1)]
//                         DyingLight = 1,
//                     }

//                     #[derive(
//                         Debug,
//                         PartialEq,
//                         Eq,
//                         Copy,
//                         Clone,
//                         Hash,
//                         rs_matter_crate::tlv::FromTLV,
//                         rs_matter_crate::tlv::ToTLV,
//                     )]
//                     #[repr(u8)]
//                     pub enum StartUpOnOffEnum {
//                         #[enumval(0)]
//                         Off = 0,
//                         #[enumval(1)]
//                         On = 1,
//                         #[enumval(2)]
//                         Toggle = 2,
//                     }

//                     #[derive(
//                         Debug,
//                         PartialEq,
//                         Eq,
//                         Clone,
//                         Hash,
//                         rs_matter_crate::tlv::FromTLV,
//                         rs_matter_crate::tlv::ToTLV,
//                     )]
//                     pub struct OffWithEffectRequest {
//                         effect_identifier: EffectIdentifierEnum,
//                         effect_variant: u8,
//                     }

//                     #[derive(
//                         Debug,
//                         PartialEq,
//                         Eq,
//                         Clone,
//                         Hash,
//                         rs_matter_crate::tlv::FromTLV,
//                         rs_matter_crate::tlv::ToTLV,
//                     )]
//                     pub struct OnWithTimedOffRequest {
//                         on_off_control: OnOffControlBitmap,
//                         on_time: u16,
//                         off_wait_time: u16,
//                     }

//                     #[derive(strum::FromRepr, strum::EnumDiscriminants)]
//                     #[repr(u32)]
//                     pub enum Commands {
//                         Off = 0,
//                         On = 1,
//                         Toggle = 2,
//                         OffWithEffect = 64,
//                         OnWithRecallGlobalScene = 65,
//                         OnWithTimedOff = 66,
//                     }
//                 }
//             )
//         );
//     }

//     #[test]
//     fn struct_fields_string() {
//         let idl = parse_idl(
//             "
//               cluster TestForStructs = 1 {
//                 struct WithStringMember {
//                   char_string<16> short_string = 1;
//                   long_char_string<512> long_string = 2;
//                   optional char_string<32> opt_str = 3;
//                   optional nullable long_char_string<512> opt_nul_str = 4;
//                 }
//               }
//             ",
//         );

//         let cluster = get_cluster_named(&idl, "TestForStructs").expect("Cluster exists");
//         let context = IdlGenerateContext::new("rs_matter_crate");

//         let defs: TokenStream = cluster
//             .structs
//             .iter()
//             .map(|c| struct_definition(c, &context))
//             .collect();

//         assert_tokenstreams_eq!(
//             &defs,
//             &quote!(
//                 #[derive(
//                     Debug,
//                     PartialEq,
//                     Eq,
//                     Clone,
//                     Hash,
//                     rs_matter_crate::tlv::FromTLV,
//                     rs_matter_crate::tlv::ToTLV,
//                 )]
//                 #[tlvargs(lifetime = "'a")]
//                 pub struct WithStringMember<'a> {
//                     short_string: rs_matter_crate::tlv::Utf8Str<'a>,
//                     long_string: rs_matter_crate::tlv::Utf8Str<'a>,
//                     opt_str: Option<rs_matter_crate::tlv::Utf8Str<'a>>,
//                     opt_nul_str:
//                         Option<rs_matter_crate::tlv::Nullable<rs_matter_crate::tlv::Utf8Str<'a>>>,
//                 }
//             )
//         );
//     }

//     #[test]
//     fn struct_fields_octet_string() {
//         let idl = parse_idl(
//             "
//               cluster TestForStructs = 1 {
//                 struct WithStringMember {
//                   octet_string<16> short_string = 1;
//                   long_octet_string<512> long_string = 2;
//                   optional octet_string<32> opt_str = 3;
//                   optional nullable long_octet_string<512> opt_nul_str = 4;
//                 }
//               }
//             ",
//         );

//         let cluster = get_cluster_named(&idl, "TestForStructs").expect("Cluster exists");
//         let context = IdlGenerateContext::new("rs_matter_crate");

//         let defs: TokenStream = cluster
//             .structs
//             .iter()
//             .map(|c| struct_definition(c, &context))
//             .collect();

//         assert_tokenstreams_eq!(
//             &defs,
//             &quote!(
//                 #[derive(
//                     Debug,
//                     PartialEq,
//                     Eq,
//                     Clone,
//                     Hash,
//                     rs_matter_crate::tlv::FromTLV,
//                     rs_matter_crate::tlv::ToTLV,
//                 )]
//                 #[tlvargs(lifetime = "'a")]
//                 pub struct WithStringMember<'a> {
//                     short_string: rs_matter_crate::tlv::OctetStr<'a>,
//                     long_string: rs_matter_crate::tlv::OctetStr<'a>,
//                     opt_str: Option<rs_matter_crate::tlv::OctetStr<'a>>,
//                     opt_nul_str:
//                         Option<rs_matter_crate::tlv::Nullable<rs_matter_crate::tlv::OctetStr<'a>>>,
//                 }
//             )
//         );
//     }
// }
