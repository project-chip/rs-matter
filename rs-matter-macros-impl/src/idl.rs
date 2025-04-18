use convert_case::{Case, Casing};
use proc_macro2::{Ident, Literal, Span, TokenStream};
use quote::quote;
use rs_matter_data_model::{Bitmap, Cluster, DataType, Enum, Struct, StructField};

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

/// Creates the token stream corresponding to a bitmap definition.
fn bitmap_definition(b: &Bitmap, context: &IdlGenerateContext) -> TokenStream {
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
    let krate = context.rs_matter_crate.clone();

    quote!(
       bitflags::bitflags! {
         #[repr(transparent)]
         #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
         pub struct #name : #base_type {
           #(#items)*
         }
       }
       #krate::bitflags_tlv!(#name, #base_type);
    )
}

/// Creates the token stream corresponding to an enum definition.
///
/// Essentially `enum Foo { kValue.... = ...}`
fn enum_definition(e: &Enum, context: &IdlGenerateContext) -> TokenStream {
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
          #[enumval(#constant_value)]
          #constant_name = #constant_value
        )
    });
    let krate = context.rs_matter_crate.clone();

    quote!(
      #[derive(Debug, PartialEq, Eq, Copy, Clone, Hash, #krate::tlv::FromTLV, #krate::tlv::ToTLV)]
      #[repr(#base_type)]
      pub enum #name {
        #(#items),*
      }
    )
}

fn field_type(f: &DataType, krate: &Ident) -> TokenStream {
    let field_type_scalar = field_type_scalar(f, krate);

    if f.is_list {
        quote!(#krate::tlv::TLVArray<#field_type_scalar>)
    } else {
        field_type_scalar
    }
}

fn field_type_scalar(f: &DataType, krate: &Ident) -> TokenStream {
    // NOTE: f.max_length is not used (i.e. we do not limit or check string length limit)

    match f.name.as_str() {
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
        "char_string" => quote!(#krate::tlv::UtfStr<'a>),
        "long_char_string" => quote!(#krate::tlv::UtfStr<'a>),
        "octet_string" => quote!(#krate::tlv::OctetStr<'a>),
        "long_octet_string" => quote!(#krate::tlv::OctetStr<'a>),

        // Several structs and unsupported bits.
        // TODO: at least strings should be supported
        "ipadr" | "ipv4adr" | "ipv6adr" | "ipv6pre" | "hwadr" | "semtag" | "tod" | "date" => {
            panic!("Unsupported field type {}", f.name)
        }

        // Assume anything else is some struct/enum/bitmap and report as-is
        other => {
            let ident = Ident::new(other, Span::call_site());
            quote!(#ident)
        }
    }
}

fn struct_field_definition(f: &StructField, context: &IdlGenerateContext) -> TokenStream {
    // f.fabric_sensitive does not seem to have any specific meaning so we ignore it
    // fabric_sensitive seems to be specific to fabric_scoped structs

    let doc_comment = struct_field_comment(f);
    let krate = context.rs_matter_crate.clone();

    let code = Literal::u8_unsuffixed(f.field.code as u8);
    let field_type = field_type(&f.field.data_type, &krate);
    let name = Ident::new(&idl_field_name_to_rs_name(&f.field.id), Span::call_site());

    let field_type = if f.is_nullable {
        quote!(#krate::tlv::Nullable<#field_type>)
    } else {
        field_type
    };

    let field_type = if f.is_optional {
        quote!(Option<#field_type>)
    } else {
        field_type
    };

    if f.is_optional {
        quote!(
            #doc_comment
            pub fn #name(&self) -> Result<#field_type, #krate::error::Error> {
                let element = self.0.structure()?.find_ctx(#code)?;

                if element.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(#krate::tlv::FromTLV::from_tlv(&element)?))
                }
            }
        )
    } else {
        quote!(
            #doc_comment
            pub fn #name(&self) -> Result<#field_type, #krate::error::Error> {
                #krate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(#code)?)
            }
        )
    }
}

fn struct_tag_field_definition(f: &StructField) -> TokenStream {
    // f.fabric_sensitive does not seem to have any specific meaning so we ignore it
    // fabric_sensitive seems to be specific to fabric_scoped structs

    let doc_comment = struct_field_comment(f);

    let code = Literal::u8_unsuffixed(f.field.code as u8);
    let name = Ident::new(
        &idl_field_name_to_rs_type_name(&f.field.id),
        Span::call_site(),
    );

    quote!(
        #doc_comment
        #name = #code,
    )
}

fn struct_field_comment(f: &StructField) -> TokenStream {
    match f.maturity {
        rs_matter_data_model::ApiMaturity::Provisional => quote!(#[doc="provisional"]),
        rs_matter_data_model::ApiMaturity::Internal => quote!(#[doc="internal"]),
        rs_matter_data_model::ApiMaturity::Deprecated => quote!(#[doc="deprecated"]),
        _ => quote!(),
    }
}

/// Creates the token stream corresponding to a structure
/// definition.
///
/// Provides the raw `struct Foo<'a>(TLVElement<'a>); impl<'a> Foo<'a> { ... }` declaration.
fn struct_definition(s: &Struct, context: &IdlGenerateContext) -> TokenStream {
    // NOTE: s.is_fabric_scoped not directly handled as the IDL
    //       will have fabric_idx with ID 254 automatically added.

    let name = Ident::new(&s.id, Span::call_site());

    let fields = s.fields.iter().map(|f| struct_field_definition(f, context));
    let krate = context.rs_matter_crate.clone();

    quote!(
        #[derive(Debug, PartialEq, Eq, Clone, Hash)]
        pub struct #name<'a>(#krate::tlv::TLVElement<'a>);

        impl<'a> #name<'a> {
            #[doc="Create a new instance of #name"]
            pub const fn new(element: #krate::tlv::TLVElement<'a>) -> Self {
                Self(element)
            }

            pub const fn tlv_element(&self) -> &TLVElement<'a> {
                &self.0
            }

            #(#fields)*
        }

        impl<'a> #krate::tlv::FromTLV<'a> for #name<'a> {
            fn from_tlv(element: &#krate::tlv::TLVElement<'a>) -> Result<Self, #krate::error::Error> {
                Ok(Self::new(element.clone()))
            }
        }

        impl #krate::tlv::ToTLV for #name<'_> {
            fn to_tlv<W: #krate::tlv::TLVWrite>(&self, tag: &#krate::tlv::TLVTag, tw: W) -> Result<(), Error> {
                self.0.to_tlv(tag, tw)
            }

            fn tlv_iter(&self, tag: #krate::tlv::TLVTag) -> impl Iterator<Item = Result<#krate::tlv::TLV, Error>> {
                self.0.tlv_iter(tag)
            }
        }
    )
}

/// Creates the token stream corresponding to a structure
/// tag definition.
///
/// Provides the raw `enum FooTag { }` declaration.
fn struct_tag_definition(s: &Struct) -> TokenStream {
    // NOTE: s.is_fabric_scoped not directly handled as the IDL
    //       will have fabric_idx with ID 254 automatically added.

    let name = Ident::new(&format!("{}Tag", s.id), Span::call_site());

    let fields = s.fields.iter().map(struct_tag_field_definition);

    quote!(
        #[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
        #[repr(u8)]
        pub enum #name { #(#fields)* }
    )
}

pub fn server_side_cluster_generate(
    cluster: &Cluster,
    context: &IdlGenerateContext,
) -> TokenStream {
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

    let bitmap_declarations = cluster
        .bitmaps
        .iter()
        .map(|c| bitmap_definition(c, context));

    let enum_declarations = cluster.enums.iter().map(|c| enum_definition(c, context));

    let struct_declarations = cluster
        .structs
        .iter()
        .map(|s| struct_definition(s, context));

    let struct_tag_declarations = cluster.structs.iter().map(struct_tag_definition);

    let krate = context.rs_matter_crate.clone();

    quote!(
        mod #cluster_module_name {
            pub const ID: u32 = #cluster_code;

            // USE declarations because bitflags_tlv! macro has no crate context
            use #krate::error::Error;
            use #krate::tlv::{TLVElement, ToTLV, FromTLV, TLVWriter, TagType};

            #(#bitmap_declarations)*

            #(#enum_declarations)*

            #(#struct_declarations)*

            #(#struct_tag_declarations)*

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
    fn struct_generation_works() {
        let idl = parse_idl(
            "
              cluster TestForStructs = 1 {

                // a somewhat complex struct
                struct NetworkInfoStruct {
                  boolean connected = 1;
                  optional int8u test_optional = 2;
                  nullable int16u test_nullable = 3;
                  optional nullable int32u test_both = 4;
                }

                // Some varying requests
                request struct IdentifyRequest {
                  int16u identifyTime = 0;
                }

                request struct SomeRequest {
                  group_id group = 0;
                }

                // Some responses
                response struct TestResponse = 0 {
                  int8u capacity = 0;
                }

                response struct AnotherResponse = 1 {
                  enum8 status = 0;
                  group_id groupID = 12;
                }
              }
            ",
        );

        let cluster = get_cluster_named(&idl, "TestForStructs").expect("Cluster exists");
        let context = IdlGenerateContext::new("rs_matter_crate");

        let defs: TokenStream = cluster
            .structs
            .iter()
            .map(|c| struct_definition(c, &context))
            .collect();

        assert_tokenstreams_eq!(
            &defs,
            &quote!(
                #[derive(
                    Debug,
                    PartialEq,
                    Eq,
                    Clone,
                    Hash,
                    rs_matter_crate::tlv::FromTLV,
                    rs_matter_crate::tlv::ToTLV,
                )]
                pub struct NetworkInfoStruct {
                    connected: bool,
                    test_optional: Option<u8>,
                    test_nullable: rs_matter_crate::tlv::Nullable<u16>,
                    test_both: Option<rs_matter_crate::tlv::Nullable<u32>>,
                }

                #[derive(
                    Debug,
                    PartialEq,
                    Eq,
                    Clone,
                    Hash,
                    rs_matter_crate::tlv::FromTLV,
                    rs_matter_crate::tlv::ToTLV,
                )]
                pub struct IdentifyRequest {
                    identify_time: u16,
                }

                #[derive(
                    Debug,
                    PartialEq,
                    Eq,
                    Clone,
                    Hash,
                    rs_matter_crate::tlv::FromTLV,
                    rs_matter_crate::tlv::ToTLV,
                )]
                pub struct SomeRequest {
                    group: u16,
                }

                #[derive(
                    Debug,
                    PartialEq,
                    Eq,
                    Clone,
                    Hash,
                    rs_matter_crate::tlv::FromTLV,
                    rs_matter_crate::tlv::ToTLV,
                )]
                pub struct TestResponse {
                    capacity: u8,
                }

                #[derive(
                    Debug,
                    PartialEq,
                    Eq,
                    Clone,
                    Hash,
                    rs_matter_crate::tlv::FromTLV,
                    rs_matter_crate::tlv::ToTLV,
                )]
                pub struct AnotherResponse {
                    status: u8,
                    group_id: u16,
                }
            )
        );
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
        let context = IdlGenerateContext::new("rs_matter_crate");

        assert_tokenstreams_eq!(
            &server_side_cluster_generate(cluster, &context),
            &quote!(
                mod on_off {
                    pub const ID: u32 = 6;

                    use rs_matter_crate::error::Error;
                    use rs_matter_crate::tlv::{FromTLV, TLVElement, TLVWriter, TagType, ToTLV};

                    bitflags::bitflags! {
                      #[repr(transparent)]
                      #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
                      pub struct Feature : u32 {
                        const LIGHTING = 1;
                        const DEAD_FRONT_BEHAVIOR = 2;
                        const OFF_ONLY = 4;
                      }
                    }
                    rs_matter_crate::bitflags_tlv!(Feature, u32);

                    bitflags::bitflags! {
                      #[repr(transparent)]
                      #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
                      pub struct OnOffControlBitmap : u8 {
                        const ACCEPT_ONLY_WHEN_ON = 1;
                      }
                    }
                    rs_matter_crate::bitflags_tlv!(OnOffControlBitmap, u8);

                    #[derive(
                        Debug,
                        PartialEq,
                        Eq,
                        Copy,
                        Clone,
                        Hash,
                        rs_matter_crate::tlv::FromTLV,
                        rs_matter_crate::tlv::ToTLV,
                    )]
                    #[repr(u8)]
                    pub enum DelayedAllOffEffectVariantEnum {
                        #[enumval(0)]
                        DelayedOffFastFade = 0,
                        #[enumval(1)]
                        NoFade = 1,
                        #[enumval(2)]
                        DelayedOffSlowFade = 2,
                    }

                    #[derive(
                        Debug,
                        PartialEq,
                        Eq,
                        Copy,
                        Clone,
                        Hash,
                        rs_matter_crate::tlv::FromTLV,
                        rs_matter_crate::tlv::ToTLV,
                    )]
                    #[repr(u8)]
                    pub enum DyingLightEffectVariantEnum {
                        #[enumval(0)]
                        DyingLightFadeOff = 0,
                    }

                    #[derive(
                        Debug,
                        PartialEq,
                        Eq,
                        Copy,
                        Clone,
                        Hash,
                        rs_matter_crate::tlv::FromTLV,
                        rs_matter_crate::tlv::ToTLV,
                    )]
                    #[repr(u8)]
                    pub enum EffectIdentifierEnum {
                        #[enumval(0)]
                        DelayedAllOff = 0,
                        #[enumval(1)]
                        DyingLight = 1,
                    }

                    #[derive(
                        Debug,
                        PartialEq,
                        Eq,
                        Copy,
                        Clone,
                        Hash,
                        rs_matter_crate::tlv::FromTLV,
                        rs_matter_crate::tlv::ToTLV,
                    )]
                    #[repr(u8)]
                    pub enum StartUpOnOffEnum {
                        #[enumval(0)]
                        Off = 0,
                        #[enumval(1)]
                        On = 1,
                        #[enumval(2)]
                        Toggle = 2,
                    }

                    #[derive(
                        Debug,
                        PartialEq,
                        Eq,
                        Clone,
                        Hash,
                        rs_matter_crate::tlv::FromTLV,
                        rs_matter_crate::tlv::ToTLV,
                    )]
                    pub struct OffWithEffectRequest {
                        effect_identifier: EffectIdentifierEnum,
                        effect_variant: u8,
                    }

                    #[derive(
                        Debug,
                        PartialEq,
                        Eq,
                        Clone,
                        Hash,
                        rs_matter_crate::tlv::FromTLV,
                        rs_matter_crate::tlv::ToTLV,
                    )]
                    pub struct OnWithTimedOffRequest {
                        on_off_control: OnOffControlBitmap,
                        on_time: u16,
                        off_wait_time: u16,
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

    #[test]
    fn struct_fields_string() {
        let idl = parse_idl(
            "
              cluster TestForStructs = 1 {
                struct WithStringMember {
                  char_string<16> short_string = 1;
                  long_char_string<512> long_string = 2;
                  optional char_string<32> opt_str = 3;
                  optional nullable long_char_string<512> opt_nul_str = 4;
                }
              }
            ",
        );

        let cluster = get_cluster_named(&idl, "TestForStructs").expect("Cluster exists");
        let context = IdlGenerateContext::new("rs_matter_crate");

        let defs: TokenStream = cluster
            .structs
            .iter()
            .map(|c| struct_definition(c, &context))
            .collect();

        assert_tokenstreams_eq!(
            &defs,
            &quote!(
                #[derive(
                    Debug,
                    PartialEq,
                    Eq,
                    Clone,
                    Hash,
                    rs_matter_crate::tlv::FromTLV,
                    rs_matter_crate::tlv::ToTLV,
                )]
                #[tlvargs(lifetime = "'a")]
                pub struct WithStringMember<'a> {
                    short_string: rs_matter_crate::tlv::UtfStr<'a>,
                    long_string: rs_matter_crate::tlv::UtfStr<'a>,
                    opt_str: Option<rs_matter_crate::tlv::UtfStr<'a>>,
                    opt_nul_str:
                        Option<rs_matter_crate::tlv::Nullable<rs_matter_crate::tlv::UtfStr<'a>>>,
                }
            )
        );
    }

    #[test]
    fn struct_fields_octet_string() {
        let idl = parse_idl(
            "
              cluster TestForStructs = 1 {
                struct WithStringMember {
                  octet_string<16> short_string = 1;
                  long_octet_string<512> long_string = 2;
                  optional octet_string<32> opt_str = 3;
                  optional nullable long_octet_string<512> opt_nul_str = 4;
                }
              }
            ",
        );

        let cluster = get_cluster_named(&idl, "TestForStructs").expect("Cluster exists");
        let context = IdlGenerateContext::new("rs_matter_crate");

        let defs: TokenStream = cluster
            .structs
            .iter()
            .map(|c| struct_definition(c, &context))
            .collect();

        assert_tokenstreams_eq!(
            &defs,
            &quote!(
                #[derive(
                    Debug,
                    PartialEq,
                    Eq,
                    Clone,
                    Hash,
                    rs_matter_crate::tlv::FromTLV,
                    rs_matter_crate::tlv::ToTLV,
                )]
                #[tlvargs(lifetime = "'a")]
                pub struct WithStringMember<'a> {
                    short_string: rs_matter_crate::tlv::OctetStr<'a>,
                    long_string: rs_matter_crate::tlv::OctetStr<'a>,
                    opt_str: Option<rs_matter_crate::tlv::OctetStr<'a>>,
                    opt_nul_str:
                        Option<rs_matter_crate::tlv::Nullable<rs_matter_crate::tlv::OctetStr<'a>>>,
                }
            )
        );
    }
}
