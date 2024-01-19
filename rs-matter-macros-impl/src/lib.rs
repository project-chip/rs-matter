use convert_case::{Case, Casing};
use proc_macro2::{Ident, Literal, Span, TokenStream};
use quote::quote;
use rs_matter_data_model::{Bitmap, Cluster, Enum};

pub const CSA_STANDARD_CLUSTERS_IDL: &str = include_str!("idl/controller-clusters.matter");

/// Converts a idl identifier (like `kFoo`) into a name suitable for
/// constants based on rust guidelines
///
/// Examples:
///
/// ```
/// use rs_matter_macros_impl::idl_id_to_constant_name;
///
/// assert_eq!(idl_id_to_constant_name("kAbc"), "ABC");
/// assert_eq!(idl_id_to_constant_name("kAbcXyz"), "ABC_XYZ");
/// assert_eq!(idl_id_to_constant_name("ThisIsATest"), "THIS_IS_A_TEST");
/// ```
pub fn idl_id_to_constant_name(s: &str) -> String {
    s.strip_prefix('k').unwrap_or(s).to_case(Case::UpperSnake)
}

/// Converts a idl identifier (like `kFoo`) into a name suitable for
/// enum names
///
/// Examples:
///
/// ```
/// use rs_matter_macros_impl::idl_id_to_enum_name;
///
/// assert_eq!(idl_id_to_enum_name("kAbc"), "Abc");
/// assert_eq!(idl_id_to_enum_name("kAbcXyz"), "AbcXyz");
/// assert_eq!(idl_id_to_enum_name("ThisIsATest"), "ThisIsATest");
/// ```
pub fn idl_id_to_enum_name(s: &str) -> String {
    s.strip_prefix('k').unwrap_or(s).into()
}

/// Creates the token stream corresponding to a bitmap definition.
fn bitmap_definition(b: &Bitmap) -> TokenStream {
    let base_type = match b.base_type.as_ref() {
        "bitmap8" => quote!(u8),
        "bitmap16" => quote!(u16),
        "bitmap32" => quote!(u32),
        "bitmap64" => quote!(u64),
        other => panic!("Unknown bitmap base type {}", other),
    };
    let name = Ident::new(&b.id, Span::call_site());

    let items = b.entries.iter().map(|c| {
        let constant_name = Ident::new(&idl_id_to_constant_name(&c.id), Span::call_site());
        let constant_value = Literal::i64_unsuffixed(c.code as i64);
        quote!(
          const #constant_name = #constant_value;
        )
    });

    quote!(bitflags::bitflags! {
      pub struct #name : #base_type {
        #(#items)*
      }
    })
}

/// Creates the token stream corresponding to an enum definition.
///
/// Essentially `enum Foo { kValue.... = ...}`
fn enum_definition(e: &Enum) -> TokenStream {
    let base_type = match e.base_type.as_ref() {
        "enum8" => quote!(u8),
        "enum16" => quote!(u16),
        other => panic!("Unknown enumeration base type {}", other),
    };
    let name = Ident::new(&e.id, Span::call_site());

    let items = e.entries.iter().map(|c| {
        let constant_name = Ident::new(&idl_id_to_enum_name(&c.id), Span::call_site());
        let constant_value = Literal::i64_unsuffixed(c.code as i64);
        quote!(
          #constant_name = #constant_value
        )
    });

    quote!(
      #[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
      #[repr(#base_type)]
      pub enum #name {
        #(#items),*
      }
    )
}

pub fn server_side_cluster_generate(cluster: &Cluster) -> TokenStream {
    let cluster_module_name = Ident::new(&cluster.id.to_case(Case::Snake), Span::call_site());

    let mut commands = Vec::new();

    for cmd in cluster.commands.iter() {
        let command_name = Ident::new(&cmd.id, Span::call_site());
        let command_code = Literal::i64_unsuffixed(cmd.code as i64);
        commands.push(quote!(
            #command_name = #command_code
        ));
    }

    let cluster_code = Literal::u32_unsuffixed(cluster.code as u32);

    let bitmap_declarations = cluster.bitmaps.iter().map(bitmap_definition);
    let enum_declarations = cluster.enums.iter().map(enum_definition);

    quote!(
        mod #cluster_module_name {
            pub const ID: u32 = #cluster_code;

            #(#bitmap_declarations)*

            #(#enum_declarations)*

            #[derive(strum::FromRepr, strum::EnumDiscriminants)]
            #[repr(u32)]
            pub enum Commands {
                #(#commands),*
            }
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_tokenstreams_eq::assert_tokenstreams_eq;
    use quote::quote;
    use rs_matter_data_model::idl::Idl;
    use rs_matter_data_model::Cluster;

    fn parse_idl(input: &str) -> Idl {
        Idl::parse(input.into()).expect("valid input")
    }

    fn get_cluster_named<'a>(idl: &'a Idl, name: &str) -> Option<&'a Cluster> {
        idl.clusters.iter().find(|&cluster| cluster.id == name)
    }

    #[test]
    fn generation_works() {
        let idl = parse_idl(
            "
              cluster OnOff = 6 {
                revision 6;
              
                enum DelayedAllOffEffectVariantEnum : enum8 {
                  kDelayedOffFastFade = 0;
                  kNoFade = 1;
                  kDelayedOffSlowFade = 2;
                }
              
                enum DyingLightEffectVariantEnum : enum8 {
                  kDyingLightFadeOff = 0;
                }
              
                enum EffectIdentifierEnum : enum8 {
                  kDelayedAllOff = 0;
                  kDyingLight = 1;
                }
              
                enum StartUpOnOffEnum : enum8 {
                  kOff = 0;
                  kOn = 1;
                  kToggle = 2;
                }
              
                bitmap Feature : bitmap32 {
                  kLighting = 0x1;
                  kDeadFrontBehavior = 0x2;
                  kOffOnly = 0x4;
                }
              
                bitmap OnOffControlBitmap : bitmap8 {
                  kAcceptOnlyWhenOn = 0x1;
                }
              
                readonly attribute boolean onOff = 0;
                readonly attribute optional boolean globalSceneControl = 16384;
                attribute optional int16u onTime = 16385;
                attribute optional int16u offWaitTime = 16386;
                attribute access(write: manage) optional nullable StartUpOnOffEnum startUpOnOff = 16387;
                readonly attribute command_id generatedCommandList[] = 65528;
                readonly attribute command_id acceptedCommandList[] = 65529;
                readonly attribute event_id eventList[] = 65530;
                readonly attribute attrib_id attributeList[] = 65531;
                readonly attribute bitmap32 featureMap = 65532;
                readonly attribute int16u clusterRevision = 65533;
              
                request struct OffWithEffectRequest {
                  EffectIdentifierEnum effectIdentifier = 0;
                  enum8 effectVariant = 1;
                }
              
                request struct OnWithTimedOffRequest {
                  OnOffControlBitmap onOffControl = 0;
                  int16u onTime = 1;
                  int16u offWaitTime = 2;
                }
              
                /** On receipt of this command, a device SHALL enter its ‘Off’ state. This state is device dependent, but it is recommended that it is used for power off or similar functions. On receipt of the Off command, the OnTime attribute SHALL be set to 0. */
                command Off(): DefaultSuccess = 0;
                /** On receipt of this command, a device SHALL enter its ‘On’ state. This state is device dependent, but it is recommended that it is used for power on or similar functions. On receipt of the On command, if the value of the OnTime attribute is equal to 0, the device SHALL set the OffWaitTime attribute to 0. */
                command On(): DefaultSuccess = 1;
                /** On receipt of this command, if a device is in its ‘Off’ state it SHALL enter its ‘On’ state. Otherwise, if it is in its ‘On’ state it SHALL enter its ‘Off’ state. On receipt of the Toggle command, if the value of the OnOff attribute is equal to FALSE and if the value of the OnTime attribute is equal to 0, the device SHALL set the OffWaitTime attribute to 0. If the value of the OnOff attribute is equal to TRUE, the OnTime attribute SHALL be set to 0. */
                command Toggle(): DefaultSuccess = 2;
                /** The OffWithEffect command allows devices to be turned off using enhanced ways of fading. */
                command OffWithEffect(OffWithEffectRequest): DefaultSuccess = 64;
                /** The OnWithRecallGlobalScene command allows the recall of the settings when the device was turned off. */
                command OnWithRecallGlobalScene(): DefaultSuccess = 65;
                /** The OnWithTimedOff command allows devices to be turned on for a specific duration with a guarded off duration so that SHOULD the device be subsequently switched off, further OnWithTimedOff commands, received during this time, are prevented from turning the devices back on. */
                command OnWithTimedOff(OnWithTimedOffRequest): DefaultSuccess = 66;
              }
        ",
        );
        let cluster = get_cluster_named(&idl, "OnOff").expect("Cluster exists");

        assert_tokenstreams_eq!(
            &server_side_cluster_generate(cluster),
            &quote!(
                mod on_off {
                    pub const ID: u32 = 6;

                    bitflags::bitflags! {
                      pub struct Feature : u32 {
                        const LIGHTING = 1;
                        const DEAD_FRONT_BEHAVIOR = 2;
                        const OFF_ONLY = 4;
                      }
                    }

                    bitflags::bitflags! {
                      pub struct OnOffControlBitmap : u8 {
                        const ACCEPT_ONLY_WHEN_ON = 1;
                      }
                    }

                    #[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
                    #[repr(u8)]
                    pub enum DelayedAllOffEffectVariantEnum {
                        DelayedOffFastFade = 0,
                        NoFade = 1,
                        DelayedOffSlowFade = 2,
                    }

                    #[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
                    #[repr(u8)]
                    pub enum DyingLightEffectVariantEnum {
                        DyingLightFadeOff = 0,
                    }

                    #[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
                    #[repr(u8)]
                    pub enum EffectIdentifierEnum {
                        DelayedAllOff = 0,
                        DyingLight = 1,
                    }

                    #[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
                    #[repr(u8)]
                    pub enum StartUpOnOffEnum {
                        Off = 0,
                        On = 1,
                        Toggle = 2,
                    }

                    #[derive(strum::FromRepr, strum::EnumDiscriminants)]
                    #[repr(u32)]
                    pub enum Commands {
                        Off = 0,
                        On = 1,
                        Toggle = 2,
                        OffWithEffect = 64,
                        OnWithRecallGlobalScene = 65,
                        OnWithTimedOff = 66,
                    }
                }
            )
        );
    }
}
