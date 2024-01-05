use matter_data_model::Cluster;
use proc_macro2::{Ident, Literal, Span, TokenStream};
use quote::quote;

pub fn server_side_cluster_generate(cluster: &Cluster) -> TokenStream {
    let cluster_name = Ident::new(&cluster.id, Span::call_site());

    let mut commands = Vec::new();

    for cmd in cluster.commands.iter() {
        let command_name = Ident::new(&cmd.id, Span::call_site());
        let command_code = Literal::i64_unsuffixed(cmd.code as i64);
        commands.push(quote!(
            #command_name = #command_code
        ));
    }

    let cluster_code = Literal::u32_unsuffixed(cluster.code as u32);

    quote!(
        mod #cluster_name {
            pub const ID: u32 = #cluster_code;


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
    use matter_data_model::Cluster;
    use matter_idl_parser::Idl;
    use quote::quote;

    fn parse_idl(input: &str) -> Idl {
        Idl::parse(input.into()).expect("valid input")
    }

    fn get_cluster_named<'a>(idl: &'a Idl, name: &str) -> Option<&'a Cluster> {
        for cluster in idl.clusters.iter() {
            if cluster.id == name {
                return Some(cluster);
            }
        }
        None
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
                mod OnOff {
                    pub const ID: u32 = 6;

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
