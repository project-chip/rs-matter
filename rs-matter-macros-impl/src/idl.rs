use core::panic;

use convert_case::{Case, Casing};
use proc_macro2::{Ident, Literal, Span, TokenStream};
use quote::quote;
use rs_matter_data_model::{Bitmap, Cluster, DataType, Enum, Struct, StructField, StructType};

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

    let items = b
        .entries
        .iter()
        .map(|c| {
            let constant_name = Ident::new(&idl_id_to_constant_name(&c.id), Span::call_site());
            let constant_value = Literal::i64_unsuffixed(c.code as i64);
            quote!(
              const #constant_name = #constant_value;
            )
        })
        .collect::<Vec<_>>();

    let krate = context.rs_matter_crate.clone();

    quote!(
        #[cfg(not(feature = "defmt"))]
        bitflags::bitflags! {
            #[repr(transparent)]
            #[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash)]
            pub struct #name: #base_type {
                #(#items)*
            }
        }

        #[cfg(feature = "defmt")]
        defmt::bitflags! {
            #[repr(transparent)]
            #[derive(Default)]
            pub struct #name: #base_type {
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
        #[cfg_attr(feature = "defmt", derive(defmt::Format))]
        #[repr(#base_type)]
        pub enum #name {
            #(#items),*
        }
    )
}

fn field_type_req(f: &DataType, krate: &Ident, anon_lifetime: bool) -> TokenStream {
    let field_type_scalar = field_type_scalar(f, krate, anon_lifetime);

    if f.is_list {
        quote!(#krate::tlv::TLVArray<#field_type_scalar>)
    } else {
        field_type_scalar
    }
}

fn field_type_scalar(f: &DataType, krate: &Ident, anon_lifetime: bool) -> TokenStream {
    field_type_builtin_scalar(f, krate, anon_lifetime).unwrap_or_else(|| {
        let ident = Ident::new(f.name.as_str(), Span::call_site());
        quote!(#ident)
    })
}

fn field_type_builtin_scalar(
    f: &DataType,
    krate: &Ident,
    anon_lifetime: bool,
) -> Option<TokenStream> {
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

fn field_type_copy(f: &DataType, cluster: &Cluster, krate: &Ident) -> Option<TokenStream> {
    if f.is_octet_string() || f.is_utf8_string() {
        return None;
    }

    if let Some(stream) = field_type_builtin_scalar(f, krate, false) {
        return Some(stream);
    }

    if cluster.structs.iter().all(|s| s.id != f.name) {
        let ident = Ident::new(f.name.as_str(), Span::call_site());
        return Some(quote!(#ident));
    }

    None
}

fn field_type_resp(
    data_type: &DataType,
    nullable: bool,
    optional: bool,
    parent: TokenStream,
    cluster: &Cluster,
    krate: &Ident,
) -> (TokenStream, bool) {
    let (mut typ, builder) = if let Some(copy) = field_type_copy(data_type, cluster, krate) {
        if data_type.is_list {
            (quote!(#krate::tlv::ToTLVArrayBuilder<#parent, #copy>), true)
        } else {
            (quote!(#copy), false)
        }
    } else if data_type.is_octet_string() {
        (
            if data_type.is_list {
                quote!(#krate::tlv::OctetsArrayBuilder<#parent>)
            } else {
                quote!(#krate::tlv::OctetsBuilder<#parent>)
            },
            true,
        )
    } else if data_type.is_utf8_string() {
        (
            if data_type.is_list {
                quote!(#krate::tlv::Utf8StrArrayBuilder<#parent>)
            } else {
                quote!(#krate::tlv::Utf8StrBuilder<#parent>)
            },
            true,
        )
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

fn struct_field_definition(f: &StructField, context: &IdlGenerateContext) -> TokenStream {
    // f.fabric_sensitive does not seem to have any specific meaning so we ignore it
    // fabric_sensitive seems to be specific to fabric_scoped structs

    let doc_comment = struct_field_comment(f);
    let krate = context.rs_matter_crate.clone();

    let code = Literal::u8_unsuffixed(f.field.code as u8);
    let field_type = field_type_req(&f.field.data_type, &krate, false);
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

fn struct_field_builder_definition(
    f: &StructField,
    cluster: &Cluster,
    parent_name: Ident,
    next_code: usize,
    context: &IdlGenerateContext,
) -> TokenStream {
    let doc_comment = struct_field_comment(f);
    let krate = context.rs_matter_crate.clone();

    let code = Literal::u8_unsuffixed(f.field.code as u8);

    let parent = quote!(#parent_name<P, #code>);
    let next_parent = quote!(#parent_name<P, #next_code>);

    let name = Ident::new(&idl_field_name_to_rs_name(&f.field.id), Span::call_site());

    if cluster
        .structs
        .iter()
        .all(|s| s.id != f.field.data_type.name)
    {
        // TODO: Arrays

        let mut field_type = field_type_scalar(&f.field.data_type, &krate, true);

        if f.is_nullable {
            field_type = quote!(#krate::tlv::Nullable<#field_type>);
        }

        if f.is_optional {
            field_type = quote!(Option<#field_type>);
        }

        quote!(
            impl<P> #parent
            where
                P: #krate::tlv::TLVBuilderParent,
            {
                #doc_comment
                pub fn #name(mut self, value: #field_type) -> Result<#next_parent, #krate::error::Error> {
                    use #krate::tlv::ToTLV;

                    value.to_tlv(
                        &#krate::tlv::TLVTag::Context(#code),
                        self.0.writer(),
                    )?;

                    Ok(#parent_name(self.0))
                }
            }
        )
    } else {
        let ident = Ident::new(
            &format!(
                "{}{}Builder",
                f.field.data_type.name.as_str(),
                if f.field.data_type.is_list {
                    "Array"
                } else {
                    ""
                }
            ),
            Span::call_site(),
        );

        let mut field_type = quote!(#ident<#next_parent>);

        if f.is_nullable {
            field_type = quote!(#krate::tlv::NullableBuilder<#field_type>);
        }

        if f.is_optional {
            field_type = quote!(#krate::tlv::OptionalBuilder<#field_type>);
        }

        quote!(
            impl<P> #parent
            where
                P: #krate::tlv::TLVBuilderParent,
            {
                #doc_comment
                pub fn #name(self) -> Result<#field_type, #krate::error::Error> {
                    #krate::tlv::TLVBuilder::new(
                        #parent_name(self.0),
                        &#krate::tlv::TLVTag::Context(#code),
                    )
                }
            }
        )
    }
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
        #[cfg_attr(feature = "defmt", derive(defmt::Format))]
        pub struct #name<'a>(#krate::tlv::TLVElement<'a>);

        impl<'a> #name<'a> {
            #[doc="Create a new instance of #name"]
            pub const fn new(element: #krate::tlv::TLVElement<'a>) -> Self {
                Self(element)
            }

            pub const fn tlv_element(&self) -> &#krate::tlv::TLVElement<'a> {
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
            fn to_tlv<W: #krate::tlv::TLVWrite>(&self, tag: &#krate::tlv::TLVTag, tw: W) -> Result<(), #krate::error::Error> {
                self.0.to_tlv(tag, tw)
            }

            fn tlv_iter(&self, tag: #krate::tlv::TLVTag) -> impl Iterator<Item = Result<#krate::tlv::TLV, #krate::error::Error>> {
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
    let name = Ident::new(&format!("{}Tag", s.id), Span::call_site());

    let fields = s.fields.iter().map(struct_tag_field_definition);

    quote!(
        #[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
        #[cfg_attr(feature = "defmt", derive(defmt::Format))]
        #[repr(u8)]
        pub enum #name { #(#fields)* }
    )
}

fn struct_builder_definition(
    s: &Struct,
    cluster: &Cluster,
    context: &IdlGenerateContext,
) -> TokenStream {
    let name = Ident::new(&format!("{}Builder", s.id), Span::call_site());
    let name_array = Ident::new(&format!("{}ArrayBuilder", s.id), Span::call_site());

    let start_code = s
        .fields
        .iter()
        .map(|field| field.field.code as usize)
        .next()
        .unwrap_or(0);
    let finish_code = s
        .fields
        .iter()
        .map(|field| field.field.code as usize)
        .max()
        .map(|code| code + 1)
        .unwrap_or(0);

    let fields = s
        .fields
        .iter()
        .zip(
            s.fields
                .iter()
                .skip(1)
                .map(|f| f.field.code as usize)
                .chain(core::iter::once(finish_code)),
        )
        .map(|(f, next_code)| {
            struct_field_builder_definition(f, cluster, name.clone(), next_code, context)
        });
    let krate = context.rs_matter_crate.clone();

    quote!(
        pub struct #name<P, const F: usize = #start_code>(P);

        impl<P> #name<P>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            #[doc="Create a new instance of #name"]
            pub fn new(mut parent: P, tag: &#krate::tlv::TLVTag) -> Result<Self, #krate::error::Error> {
                use #krate::tlv::TLVWrite;

                parent.writer().start_struct(tag)?;

                Ok(Self(parent))
            }
        }

        #(#fields)*

        impl<P> #name<P, #finish_code>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            #[doc="Finish the builder"]
            pub fn finish(mut self) -> Result<P, #krate::error::Error> {
                use #krate::tlv::TLVWrite;

                self.0.writer().end_container()?;

                Ok(self.0)
            }
        }

        impl<P, const F: usize> #krate::tlv::TLVBuilderParent for #name<P, F>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            type Write = P::Write;

            fn writer(&mut self) -> &mut P::Write {
                self.0.writer()
            }

            fn into_writer(self) -> Self::Write {
                self.0.into_writer()
            }
        }

        impl<P> #krate::tlv::TLVBuilder<P> for #name<P>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            fn new(parent: P, tag: &#krate::tlv::TLVTag) -> Result<Self, #krate::error::Error> {
                Self::new(parent, tag)
            }

            fn into_writer(self) -> P::Write {
                self.0.into_writer()
            }
        }

        pub struct #name_array<P>(P);

        impl<P> #name_array<P>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            #[doc="Create a new instance of #name_array"]
            pub fn new(mut parent: P, tag: &#krate::tlv::TLVTag) -> Result<Self, #krate::error::Error> {
                use #krate::tlv::TLVWrite;

                parent.writer().start_array(tag)?;

                Ok(Self(parent))
            }

            #[doc="Push a new element into the array"]
            pub fn push(self) -> Result<#name<#name_array<P>>, #krate::error::Error> {
                #krate::tlv::TLVBuilder::new(#name_array(self.0), &#krate::tlv::TLVTag::Anonymous)
            }

            #[doc="Finish the array and return the parent"]
            pub fn finish(mut self) -> Result<P, #krate::error::Error> {
                use #krate::tlv::TLVWrite;

                self.0.writer().end_container()?;

                Ok(self.0)
            }
        }

        impl<P> #krate::tlv::TLVBuilderParent for #name_array<P>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            type Write = P::Write;

            fn writer(&mut self) -> &mut P::Write {
                self.0.writer()
            }

            fn into_writer(self) -> Self::Write {
                self.0.into_writer()
            }
        }

        impl<P> #krate::tlv::TLVBuilder<P> for #name_array<P>
        where
            P: #krate::tlv::TLVBuilderParent,
        {
            fn new(parent: P, tag: &#krate::tlv::TLVTag) -> Result<Self, #krate::error::Error> {
                Self::new(parent, tag)
            }

            fn into_writer(self) -> P::Write {
                self.0.into_writer()
            }
        }
    )
}

pub fn server_side_cluster_generate(
    cluster: &Cluster,
    context: &IdlGenerateContext,
) -> TokenStream {
    //let cluster_module_name = Ident::new(&cluster.id.to_case(Case::Snake), Span::call_site());

    let krate = context.rs_matter_crate.clone();

    let attributes = cluster
        .attributes
        .iter()
        .map(|attr| {
            let attr_name = Ident::new(
                &idl_attribute_name_to_enum_variant_name(&attr.field.field.id),
                Span::call_site(),
            );
            let attr_code = Literal::i64_unsuffixed(attr.field.field.code as i64);

            quote!(
                #attr_name = #attr_code
            )
        })
        .collect::<Vec<_>>();

    let attributes = if attributes.is_empty() {
        quote!()
    } else {
        quote!(
            #[derive(strum::FromRepr)]
            #[repr(u32)]
            pub enum AttributeId {
                #(#attributes),*
            }

            impl core::convert::TryFrom<#krate::data_model::objects::AttrId> for AttributeId {
                type Error = #krate::error::Error;

                fn try_from(id: #krate::data_model::objects::CmdId) -> Result<Self, Self::Error> {
                    AttributeId::from_repr(id).ok_or_else(|| #krate::error::ErrorCode::AttributeNotFound.into())
                }
            }
        )
    };

    let commands = cluster
        .commands
        .iter()
        .map(|cmd| {
            let command_name = Ident::new(&cmd.id, Span::call_site());
            let command_code = Literal::i64_unsuffixed(cmd.code as i64);

            quote!(
                #command_name = #command_code
            )
        })
        .collect::<Vec<_>>();

    let commands = if commands.is_empty() {
        quote!()
    } else {
        quote!(
            #[derive(strum::FromRepr)]
            #[repr(u32)]
            pub enum CommandId {
                #(#commands),*
            }

            impl core::convert::TryFrom<#krate::data_model::objects::CmdId> for CommandId {
                type Error = #krate::error::Error;

                fn try_from(id: #krate::data_model::objects::CmdId) -> Result<Self, Self::Error> {
                    CommandId::from_repr(id).ok_or_else(|| #krate::error::ErrorCode::CommandNotFound.into())
                }
            }
        )
    };

    let command_responses = cluster
        .structs
        .iter()
        .filter_map(|s| {
            if let StructType::Response(code) = s.struct_type {
                let command_name = Ident::new(&s.id, Span::call_site());
                let command_code = Literal::i64_unsuffixed(code as i64);
                Some(quote!(
                    #command_name = #command_code
                ))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let command_responses = if command_responses.is_empty() {
        quote!()
    } else {
        quote!(
            #[derive(strum::FromRepr)]
            #[repr(u32)]
            pub enum CommandResponseId {
                #(#command_responses),*
            }

            impl core::convert::TryFrom<#krate::data_model::objects::CmdId> for CommandResponseId {
                type Error = #krate::error::Error;

                fn try_from(id: #krate::data_model::objects::CmdId) -> Result<Self, Self::Error> {
                    CommandResponseId::from_repr(id).ok_or_else(|| #krate::error::ErrorCode::CommandNotFound.into())
                }
            }
        )
    };

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

    let struct_builder_declarations = cluster
        .structs
        .iter()
        .map(|s| struct_builder_definition(s, cluster, context));

    let attributes_meta_data = cluster.attributes.iter().map(|attr| {
        let attr_name = Ident::new(
            &idl_attribute_name_to_enum_variant_name(&attr.field.field.id),
            Span::call_site(),
        );

        quote!(
            #krate::data_model::objects::Attribute::new(
                AttributeId::#attr_name as _,
                #krate::data_model::objects::Access::RV,
                #krate::data_model::objects::Quality::SN,
            ),
        )
    });

    let commands_meta_data = cluster.commands.iter().map(|cmd| {
        let command_name = Ident::new(&cmd.id, Span::call_site());

        quote!(CommandId::#command_name as _,)
    });

    let command_responses_meta_data = cluster.structs.iter().filter_map(|s| {
        if matches!(s.struct_type, StructType::Response(_)) {
            let command_name = Ident::new(&s.id, Span::call_site());

            Some(quote!(CommandResponseId::#command_name as _,))
        } else {
            None
        }
    });

    let cluster_revision = Literal::u16_unsuffixed(cluster.revision as u16);

    let cluster_meta_data = quote!(
        pub const CLUSTER: #krate::data_model::objects::Cluster<'static> = #krate::data_model::objects::Cluster {
            id: ID as _,
            revision: #cluster_revision,
            feature_map: 0, // TODO
            attributes: &[#(#attributes_meta_data)*],
            accepted_commands: &[#(#commands_meta_data)*],
            generated_commands: &[#(#command_responses_meta_data)*],
        };
    );

    let handler_name = Ident::new(&format!("{}Handler", cluster.id), Span::call_site());

    let handler_attribute_methods = cluster.attributes
        .iter()
        .filter(|attr| attr.field.field.code < 0xf000) // TODO: Figure out the global attributes start
        .map(|attr| {
            let attr_name = Ident::new(
                &idl_field_name_to_rs_name(&attr.field.field.id),
                Span::call_site(),
            );

            let parent = quote!(P);

            let (attr_type, builder) = field_type_resp(&attr.field.field.data_type, attr.field.is_nullable, attr.field.is_optional, parent, cluster, &krate);

            if builder {
                if attr.field.is_optional {
                    quote!(
                        fn #attr_name<P: #krate::tlv::TLVBuilderParent>(&self, exchange: &#krate::transport::exchange::Exchange<'_>, builder: #attr_type) -> Result<P, #krate::error::Error> {
                            Ok(builder.none())
                        }
                    )
                } else {
                    quote!(
                        fn #attr_name<P: #krate::tlv::TLVBuilderParent>(&self, exchange: &#krate::transport::exchange::Exchange<'_>, builder: #attr_type) -> Result<P, #krate::error::Error>;
                    )
                }
            } else if attr.field.is_optional {
                quote!(
                    fn #attr_name(&self, exchange: &#krate::transport::exchange::Exchange<'_>, ) -> Result<#attr_type, #krate::error::Error> {
                        Ok(None)
                    }
                )
            } else {
                quote!(
                    fn #attr_name(&self, exchange: &#krate::transport::exchange::Exchange<'_>, ) -> Result<#attr_type, #krate::error::Error>;
                )
            }
        });

    let handler_attribute_write_methods = cluster
        .attributes
        .iter()
        .filter(|attr| attr.field.field.code < 0xf000) // TODO: Figure out the global attributes start
        .filter(|attr| !attr.is_read_only)
        .map(|attr| {
            let attr_name = Ident::new(
                &format!("set_{}", &idl_field_name_to_rs_name(&attr.field.field.id)),
                Span::call_site(),
            );

            let attr_type = field_type_req(&attr.field.field.data_type, &krate, true);

            if attr.field.is_optional {
                quote!(
                    fn #attr_name(&self, exchange: &#krate::transport::exchange::Exchange<'_>, value: #attr_type) -> Result<(), #krate::error::Error> {
                        Ok(())
                    }
                )
            } else {
                quote!(
                    fn #attr_name(&self, exchange: &#krate::transport::exchange::Exchange<'_>, value: #attr_type) -> Result<(), #krate::error::Error>;
                )
            }
        });

    let handler_command_methods = cluster.commands.iter().map(|cmd| {
        let cmd_name = Ident::new(
            &format!("handle_{}", &idl_field_name_to_rs_name(&cmd.id)),
            Span::call_site(),
        );

        let field_req = cmd.input.as_ref().map(|id| {
            field_type_req(
                &DataType {
                    name: id.clone(),
                    is_list: false,
                    max_length: None,
                },
                &krate,
                false,
            )
        });

        let cmd_output = (cmd.output != "DefaultSuccess").then(|| cmd.output.clone());

        let field_resp = cmd_output.map(|output| {
            field_type_resp(
                &DataType {
                    name: output.clone(),
                    is_list: false,
                    max_length: None,
                },
                false,
                false,
                quote!(P),
                cluster,
                &krate,
            )
        });

        if let Some(field_req) = field_req {
            if let Some((field_resp, field_resp_builder)) = field_resp {
                if field_resp_builder {
                    quote!(
                        fn #cmd_name<P: #krate::tlv::TLVBuilderParent>(
                            &self,
                            exchange: &#krate::transport::exchange::Exchange<'_>,
                            request: #field_req,
                            response: #field_resp,
                        ) -> Result<P, #krate::error::Error>;
                    )
                } else {
                    quote!(
                        fn #cmd_name(
                            &self,
                            exchange: &#krate::transport::exchange::Exchange<'_>,
                            request: #field_req,
                        ) -> Result<#field_resp, #krate::error::Error>;
                    )
                }
            } else {
                quote!(
                    fn #cmd_name(
                        &self,
                        exchange: &#krate::transport::exchange::Exchange<'_>,
                        request: #field_req,
                    ) -> Result<(), #krate::error::Error>;
                )
            }
        } else if let Some((field_resp, field_resp_builder)) = field_resp {
            if field_resp_builder {
                quote!(
                    fn #cmd_name<P: #krate::tlv::TLVBuilderParent>(
                        &self,
                        exchange: &#krate::transport::exchange::Exchange<'_>,
                        response: #field_resp,
                    ) -> Result<P, #krate::error::Error>;
                )
            } else {
                quote!(
                    fn #cmd_name(
                        &self,
                        exchange: &#krate::transport::exchange::Exchange<'_>,
                    ) -> Result<#field_resp, #krate::error::Error>;
                )
            }
        } else {
            quote!(
                fn #cmd_name(
                    &self,
                    exchange: &#krate::transport::exchange::Exchange<'_>,
                ) -> Result<(), #krate::error::Error>;
            )
        }
    });

    let handler = quote!(
        pub trait #handler_name {
            fn dataver(&self) -> u32;
            fn dataver_changed(&self);

            #(#handler_attribute_methods)*

            #(#handler_attribute_write_methods)*

            #(#handler_command_methods)*
        }
    );

    let handler_adaptor_attribute_match = cluster
        .attributes
        .iter()
        .filter(|attr| attr.field.field.code < 0xf000) // TODO: Figure out the global attributes start
        .map(|attr| {
            let attr_name = Ident::new(
                &idl_attribute_name_to_enum_variant_name(&attr.field.field.id),
                Span::call_site(),
            );

            let attr_method_name = Ident::new(
                &idl_field_name_to_rs_name(&attr.field.field.id),
                Span::call_site(),
            );

            let parent = quote!(P);

            let (_, builder) = field_type_resp(
                &attr.field.field.data_type,
                attr.field.is_nullable,
                attr.field.is_optional,
                parent,
                cluster,
                &krate,
            );

            if builder {
                quote!(
                    AttributeId::#attr_name => {
                        self.0.#attr_method_name(exchange, #krate::tlv::TLVBuilder::new(
                            #krate::tlv::TLVWriteParent::new(writer.writer()),
                            &#krate::data_model::objects::AttrDataWriter::TAG,
                        )?)?;

                        writer.complete()
                    }
                )
            } else {
                quote!(
                    AttributeId::#attr_name => writer.set(self.0.#attr_method_name(exchange)?),
                )
            }
        });

    let handler_adaptor_attribute_write_match = cluster.attributes
        .iter()
        .filter(|attr| attr.field.field.code < 0xf000) // TODO: Figure out the global attributes start
        .filter(|attr| !attr.is_read_only)
        .map(|attr| {
            let attr_name = Ident::new(
                &idl_attribute_name_to_enum_variant_name(&attr.field.field.id),
                Span::call_site(),
            );

            let attr_method_name = Ident::new(
                &format!("set_{}", &idl_field_name_to_rs_name(&attr.field.field.id)),
                Span::call_site(),
            );

            quote!(
                AttributeId::#attr_name => self.0.#attr_method_name(exchange, #krate::tlv::FromTLV::from_tlv(&data)?)?,
            )
        });

    let handler_adaptor_command_match = cluster.commands.iter().map(|cmd| {
        let cmd_name = Ident::new(
            &idl_attribute_name_to_enum_variant_name(&cmd.id),
            Span::call_site(),
        );

        let cmd_method_name = Ident::new(
            &format!("handle_{}", &idl_field_name_to_rs_name(&cmd.id)),
            Span::call_site(),
        );

        let field_req = cmd
            .input
            .as_ref()
            .map(|id| {
                field_type_req(
                    &DataType {
                        name: id.clone(),
                        is_list: false,
                        max_length: None,
                    },
                    &krate,
                    false,
                )
            })
            .is_some();

        let cmd_output = (cmd.output != "DefaultSuccess")
            .then(|| {
                cluster
                    .structs
                    .iter()
                    .filter(|s| s.id == cmd.output)
                    .filter_map(|s| {
                        if let StructType::Response(code) = s.struct_type {
                            Some(code)
                        } else {
                            None
                        }
                    })
                    .next()
                    .map(|code| (cmd.output.clone(), code))
            })
            .flatten();

        let field_resp = cmd_output.map(|(output, code)| {
            let (_, builder) = field_type_resp(
                &DataType {
                    name: output.clone(),
                    is_list: false,
                    max_length: None,
                },
                false,
                false,
                quote!(P),
                cluster,
                &krate,
            );

            (code as u32, builder)
        });

        if field_req {
            if let Some((field_resp_cmd_code, field_resp_builder)) = field_resp {
                if field_resp_builder {
                    quote!(
                        CommandId::#cmd_name => {
                            let mut writer = encoder.with_command(#field_resp_cmd_code)?;

                            self.0.#cmd_method_name(
                                exchange,
                                #krate::tlv::FromTLV::from_tlv(&data)?,
                                #krate::tlv::TLVBuilder::new(
                                    #krate::tlv::TLVWriteParent::new(writer.writer()),
                                    &#krate::data_model::objects::AttrDataWriter::TAG,
                                )?
                            )?;

                            writer.complete()?
                        }
                    )
                } else {
                    quote!(
                        CommandId::#cmd_name => {
                            encoder
                                .with_command(#field_resp_cmd_code)?
                                .set(self.0.#cmd_method_name(
                                    exchange
                                    #krate::tlv::FromTLV::from_tlv(&data)?,
                                )?)?
                        }
                    )
                }
            } else {
                quote!(
                    CommandId::#cmd_name => self.0.#cmd_method_name(
                        exchange,
                        #krate::tlv::FromTLV::from_tlv(&data)?,
                    )?,
                )
            }
        } else if let Some((field_resp_cmd_code, field_resp_builder)) = field_resp {
            if field_resp_builder {
                quote!(
                    CommandId::#cmd_name => {
                        let mut writer = encoder.with_command(#field_resp_cmd_code)?;

                        self.0.#cmd_method_name(
                            exchange,
                            #krate::tlv::TLVBuilder::new(
                                #krate::tlv::TLVWriteParent::new(writer.writer()),
                                &#krate::data_model::objects::AttrDataWriter::TAG,
                            )?,
                        )?;

                        writer.complete()?
                    }
                )
            } else {
                quote!(quote!(
                    CommandId::#cmd_name => {
                        encoder
                            .with_command(#field_resp_cmd_code)?
                            .set(self.0.#cmd_method_name(exchange)?)?
                    }
                ))
            }
        } else {
            quote!(
                CommandId::#cmd_name => self.0.#cmd_method_name(exchange)?,
            )
        }
    });

    let handler_adaptor_name =
        Ident::new(&format!("{}HandlerAdaptor", cluster.id), Span::call_site());

    let handler_adaptor = quote!(
        pub struct #handler_adaptor_name<T>(T);

        impl<T> #handler_adaptor_name<T> {
            pub const fn new(handler: T) -> Self {
                Self(handler)
            }
        }

        impl<T> #krate::data_model::objects::Handler for #handler_adaptor_name<T>
        where
            T: #handler_name,
        {
            fn read(
                &self,
                exchange: &#krate::transport::exchange::Exchange,
                attr: &#krate::data_model::objects::AttrDetails,
                encoder: #krate::data_model::objects::AttrDataEncoder,
            ) -> Result<(), #krate::error::Error> {
                if let Some(mut writer) = encoder.with_dataver(self.0.dataver())? {
                    if attr.is_system() {
                        CLUSTER.read(attr.attr_id, writer)
                    } else {
                        match AttributeId::try_from(attr.attr_id)? {
                            #(#handler_adaptor_attribute_match)*
                            #[allow(unreachable_code)]
                            _ => Err(#krate::error::ErrorCode::AttributeNotFound.into()),
                        }
                    }
                } else {
                    Ok(())
                }
            }

            #[allow(unreachable_code)]
            fn write(
                &self,
                exchange: &#krate::transport::exchange::Exchange,
                attr: &#krate::data_model::objects::AttrDetails,
                data: #krate::data_model::objects::AttrData,
            ) -> Result<(), #krate::error::Error> {
                let data = data.with_dataver(self.0.dataver())?;

                if attr.is_system() {
                    return Err(#krate::error::ErrorCode::InvalidAction.into())
                }

                match AttributeId::try_from(attr.attr_id)? {
                    #(#handler_adaptor_attribute_write_match)*
                    _ => return Err(#krate::error::ErrorCode::AttributeNotFound.into()),
                }

                self.0.dataver_changed();

                Ok(())
            }

            #[allow(unreachable_code)]
            fn invoke(
                &self,
                exchange: &#krate::transport::exchange::Exchange,
                cmd: &#krate::data_model::objects::CmdDetails,
                data: &#krate::tlv::TLVElement,
                encoder: #krate::data_model::objects::CmdDataEncoder,
            ) -> Result<(), #krate::error::Error> {
                match CommandId::try_from(cmd.cmd_id)? {
                    #(#handler_adaptor_command_match)*
                    _ => return Err(#krate::error::ErrorCode::CommandNotFound.into()),
                }

                self.0.dataver_changed();

                Ok(())
            }
        }

        impl<T> #krate::data_model::objects::NonBlockingHandler for #handler_adaptor_name<T>
        where
            T: #handler_name,
        {}
    );

    quote!(
        pub const ID: u32 = #cluster_code;

        #(#bitmap_declarations)*

        #(#enum_declarations)*

        #(#struct_declarations)*

        #(#struct_tag_declarations)*

        #(#struct_builder_declarations)*

        #attributes

        #commands

        #command_responses

        #cluster_meta_data

        #handler

        #handler_adaptor
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
                    short_string: rs_matter_crate::tlv::Utf8Str<'a>,
                    long_string: rs_matter_crate::tlv::Utf8Str<'a>,
                    opt_str: Option<rs_matter_crate::tlv::Utf8Str<'a>>,
                    opt_nul_str:
                        Option<rs_matter_crate::tlv::Nullable<rs_matter_crate::tlv::Utf8Str<'a>>>,
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
