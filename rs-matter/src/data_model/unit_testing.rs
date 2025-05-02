use crate::data_model::objects::{
    ArrayAttributeRead, ArrayAttributeWrite, Cluster, InvokeContext, ReadContext, WriteContext,
};
use crate::error::{Error, ErrorCode};
use crate::tlv::{
    Nullable, NullableBuilder, OctetStr, Octets, OctetsArrayBuilder, OctetsBuilder, TLVArray,
    TLVBuilder, TLVBuilderParent, TLVTag, TLVWrite, ToTLVArrayBuilder, ToTLVBuilder, Utf8Str,
    Utf8StrBuilder,
};
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init, IntoFallibleInit};
use crate::utils::storage::Vec;

use super::objects::Dataver;

pub use crate::data_model::clusters::unit_testing::*;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct TestListStructOctetOwned {
    member_1: u64,
    member_2: Vec<u8, 32>,
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct SimpleStructOwned {
    a: u8,
    b: bool,
    c: SimpleEnum,
    d: Vec<u8, 10>,
    e: heapless::String<10>,
    f: SimpleBitmap,
    g: f32,
    h: f64,
}

impl SimpleStructOwned {
    pub fn init() -> impl Init<Self> {
        init!(Self {
            a: 0,
            b: false,
            c: SimpleEnum::ValueA,
            d <- Vec::init(),
            e: heapless::String::new(),
            f: SimpleBitmap::empty(),
            g: 0.0,
            h: 0.0,
        })
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct NullablesAndOptionalsStructOwned {
    nullable_int: Nullable<u16>,
    optional_int: Option<u16>,
    nullable_optional_int: Option<Nullable<u16>>,
    nullable_string: Nullable<heapless::String<10>>,
    optional_string: Option<heapless::String<10>>,
    nullable_optional_string: Option<Nullable<heapless::String<10>>>,
    nullable_struct: Nullable<SimpleStructOwned>,
    optional_struct: Option<SimpleStructOwned>,
    nullable_optional_struct: Option<Nullable<SimpleStructOwned>>,
    nullable_list: Nullable<Vec<SimpleEnum, 16>>,
    optional_list: Option<Vec<SimpleEnum, 16>>,
    nullable_optional_list: Option<Nullable<Vec<SimpleEnum, 16>>>,
}

impl NullablesAndOptionalsStructOwned {
    pub fn init() -> impl Init<Self> {
        init!(Self {
            nullable_int <- Nullable::init_none(),
            optional_int: None,
            nullable_optional_int: None,
            nullable_string <- Nullable::init_none(),
            optional_string: None,
            nullable_optional_string: None,
            nullable_struct <- Nullable::init_none(),
            optional_struct: None,
            nullable_optional_struct: None,
            nullable_list <- Nullable::init_none(),
            optional_list: None,
            nullable_optional_list: None,
        })
    }

    pub fn update(&mut self, s: &NullablesAndOptionalsStruct) -> Result<(), Error> {
        self.nullable_int = s.nullable_int()?.clone();
        self.optional_int = s.optional_int()?;
        self.nullable_optional_int = s.nullable_optional_int()?.clone();
        self.nullable_string = Nullable::new(
            s.nullable_string()?
                .into_option()
                .map(|s| s.try_into().map_err(|_| ErrorCode::InvalidAction))
                .transpose()?,
        );
        self.optional_string = s
            .optional_string()?
            .map(|s| s.try_into().map_err(|_| ErrorCode::InvalidAction))
            .transpose()?;
        self.nullable_optional_string = if let Some(ss) = s.nullable_optional_string()? {
            Some(Nullable::new(
                ss.into_option()
                    .map(|s| s.try_into().map_err(|_| ErrorCode::InvalidAction))
                    .transpose()?,
            ))
        } else {
            None
        };
        self.nullable_struct = if let Some(s) = s.nullable_struct()?.as_opt_ref() {
            Nullable::some(SimpleStructOwned {
                a: s.a()?,
                b: s.b()?,
                c: s.c()?,
                d: s.d()?.0.try_into().map_err(|_| ErrorCode::InvalidAction)?,
                e: s.e()?.try_into().map_err(|_| ErrorCode::InvalidAction)?,
                f: s.f()?,
                g: s.g()?,
                h: s.h()?,
            })
        } else {
            Nullable::none()
        };
        self.optional_struct = if let Some(s) = s.optional_struct()?.as_ref() {
            Some(SimpleStructOwned {
                a: s.a()?,
                b: s.b()?,
                c: s.c()?,
                d: s.d()?.0.try_into().map_err(|_| ErrorCode::InvalidAction)?,
                e: s.e()?.try_into().map_err(|_| ErrorCode::InvalidAction)?,
                f: s.f()?,
                g: s.g()?,
                h: s.h()?,
            })
        } else {
            None
        };
        self.nullable_optional_struct = if let Some(s) = s.nullable_optional_struct()?.as_ref() {
            Some(if let Some(s) = s.as_opt_ref() {
                Nullable::some(SimpleStructOwned {
                    a: s.a()?,
                    b: s.b()?,
                    c: s.c()?,
                    d: s.d()?.0.try_into().map_err(|_| ErrorCode::InvalidAction)?,
                    e: s.e()?.try_into().map_err(|_| ErrorCode::InvalidAction)?,
                    f: s.f()?,
                    g: s.g()?,
                    h: s.h()?,
                })
            } else {
                Nullable::none()
            })
        } else {
            None
        };
        self.optional_list = if let Some(l) = s.optional_list()?.as_ref() {
            Some(l.iter().collect::<Result<Vec<_, 16>, _>>()?)
        } else {
            None
        };
        self.nullable_list = if let Some(l) = s.nullable_list()?.as_opt_ref() {
            Nullable::some(l.iter().collect::<Result<Vec<_, 16>, _>>()?)
        } else {
            Nullable::none()
        };
        self.nullable_optional_list = if let Some(l) = s.nullable_optional_list()?.as_ref() {
            Some(if let Some(l) = l.as_opt_ref() {
                Nullable::some(l.iter().collect::<Result<Vec<_, 16>, _>>()?)
            } else {
                Nullable::none()
            })
        } else {
            None
        };

        Ok(())
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct UnitTestingHandlerData {
    boolean: bool,
    bitmap_8: Bitmap8MaskMap,
    bitmap_16: Bitmap16MaskMap,
    bitmap_32: Bitmap32MaskMap,
    bitmap_64: Bitmap64MaskMap,
    int_8_u: u8,
    int_16_u: u16,
    int_24_u: u32,
    int_32_u: u32,
    int_40_u: u64,
    int_48_u: u64,
    int_56_u: u64,
    int_64_u: u64,
    int_8_s: i8,
    int_16_s: i16,
    int_24_s: i32,
    int_32_s: i32,
    int_40_s: i64,
    int_48_s: i64,
    int_56_s: i64,
    int_64_s: i64,
    enum_8: u8,
    enum_16: u16,
    float_single: f32,
    float_double: f64,
    octet_string: Vec<u8, 10>,
    list_int_8_u: Vec<u8, 16>,
    list_octet_string: Vec<Vec<u8, 10>, 16>,
    list_struct_octet_string: Vec<TestListStructOctetOwned, 16>,
    long_octet_string: Vec<u8, 1000>,
    char_string: heapless::String<10>,
    long_char_string: heapless::String<1000>,
    epoch_us: u64,
    epoch_s: u32,
    vendor_id: u16,
    list_nullables_and_optionals_struct: Vec<NullablesAndOptionalsStructOwned, 16>,
    enum_attr: SimpleEnum,
    struct_attr: SimpleStructOwned,
    range_restricted_int_8_u: u8,
    range_restricted_int_8_s: i8,
    range_restricted_int_16_u: u16,
    range_restricted_int_16_s: i16,
    list_long_octet_string: Vec<Vec<u8, 1000>, 16>,
    list_fabric_scoped: Vec<TestFabricScoped<'static>, 16>,
    timed_write_boolean: bool,
    general_error_boolean: bool,
    cluster_error_boolean: bool,
    nullable_boolean: Nullable<bool>,
    nullable_bitmap_8: Nullable<Bitmap8MaskMap>,
    nullable_bitmap_16: Nullable<Bitmap16MaskMap>,
    nullable_bitmap_32: Nullable<Bitmap32MaskMap>,
    nullable_bitmap_64: Nullable<Bitmap64MaskMap>,
    nullable_int_8_u: Nullable<u8>,
    nullable_int_16_u: Nullable<u16>,
    nullable_int_24_u: Nullable<u32>,
    nullable_int_32_u: Nullable<u32>,
    nullable_int_40_u: Nullable<u64>,
    nullable_int_48_u: Nullable<u64>,
    nullable_int_56_u: Nullable<u64>,
    nullable_int_64_u: Nullable<u64>,
    nullable_int_8_s: Nullable<i8>,
    nullable_int_16_s: Nullable<i16>,
    nullable_int_24_s: Nullable<i32>,
    nullable_int_32_s: Nullable<i32>,
    nullable_int_40_s: Nullable<i64>,
    nullable_int_48_s: Nullable<i64>,
    nullable_int_56_s: Nullable<i64>,
    nullable_int_64_s: Nullable<i64>,
    nullable_enum_8: Nullable<u8>,
    nullable_enum_16: Nullable<u16>,
    nullable_float_single: Nullable<f32>,
    nullable_float_double: Nullable<f64>,
    nullable_octet_string: Nullable<Vec<u8, 10>>,
    nullable_char_string: Nullable<heapless::String<10>>,
    nullable_enum_attr: Nullable<SimpleEnum>,
    nullable_struct: Nullable<SimpleStructOwned>,
    nullable_range_restricted_int_8_u: Nullable<u8>,
    nullable_range_restricted_int_8_s: Nullable<i8>,
    nullable_range_restricted_int_16_u: Nullable<u16>,
    nullable_range_restricted_int_16_s: Nullable<i16>,
}

impl UnitTestingHandlerData {
    pub fn init() -> impl Init<Self> {
        init!(Self {
            boolean: false,
            bitmap_8: Bitmap8MaskMap::empty(),
            bitmap_16: Bitmap16MaskMap::empty(),
            bitmap_32: Bitmap32MaskMap::empty(),
            bitmap_64: Bitmap64MaskMap::empty(),
            int_8_u: 0,
            int_16_u: 0,
            int_24_u: 0,
            int_32_u: 0,
            int_40_u: 0,
            int_48_u: 0,
            int_56_u: 0,
            int_64_u: 0,
            int_8_s: 0,
            int_16_s: 0,
            int_24_s: 0,
            int_32_s: 0,
            int_40_s: 0,
            int_48_s: 0,
            int_56_s: 0,
            int_64_s: 0,
            enum_8: 0,
            enum_16: 0,
            float_single: 0.0,
            float_double: 0.0,
            octet_string <- Vec::init(),
            list_int_8_u <- Vec::init(),
            list_octet_string <- Vec::init(),
            list_struct_octet_string <- Vec::init(),
            long_octet_string <- Vec::init(),
            char_string: heapless::String::new(),
            long_char_string: heapless::String::new(),
            epoch_us: 0,
            epoch_s: 0,
            vendor_id: 0xFFFF,
            list_nullables_and_optionals_struct <- Vec::init(),
            enum_attr: SimpleEnum::ValueA,
            struct_attr <- SimpleStructOwned::init(),
            range_restricted_int_8_u: 1,
            range_restricted_int_8_s: -1,
            range_restricted_int_16_u: 1,
            range_restricted_int_16_s: -1,
            list_long_octet_string <- Vec::init(),
            list_fabric_scoped <- Vec::init(),
            timed_write_boolean: false,
            general_error_boolean: false,
            cluster_error_boolean: false,
            nullable_boolean <- Nullable::init_none(),
            nullable_bitmap_8 <- Nullable::init_none(),
            nullable_bitmap_16 <- Nullable::init_none(),
            nullable_bitmap_32 <- Nullable::init_none(),
            nullable_bitmap_64 <- Nullable::init_none(),
            nullable_int_8_u <- Nullable::init_none(),
            nullable_int_16_u <- Nullable::init_none(),
            nullable_int_24_u <- Nullable::init_none(),
            nullable_int_32_u <- Nullable::init_none(),
            nullable_int_40_u <- Nullable::init_none(),
            nullable_int_48_u <- Nullable::init_none(),
            nullable_int_56_u <- Nullable::init_none(),
            nullable_int_64_u <- Nullable::init_none(),
            nullable_int_8_s <- Nullable::init_none(),
            nullable_int_16_s <- Nullable::init_none(),
            nullable_int_24_s <- Nullable::init_none(),
            nullable_int_32_s <- Nullable::init_none(),
            nullable_int_40_s <- Nullable::init_none(),
            nullable_int_48_s <- Nullable::init_none(),
            nullable_int_56_s <- Nullable::init_none(),
            nullable_int_64_s <- Nullable::init_none(),
            nullable_enum_8 <- Nullable::init_none(),
            nullable_enum_16 <- Nullable::init_none(),
            nullable_float_single <- Nullable::init_none(),
            nullable_float_double <- Nullable::init_none(),
            nullable_octet_string <- Nullable::init_none(),
            nullable_char_string <- Nullable::init_none(),
            nullable_enum_attr <- Nullable::init_none(),
            nullable_struct <- Nullable::init_none(),
            nullable_range_restricted_int_8_u <- Nullable::init_none(),
            nullable_range_restricted_int_8_s <- Nullable::init_none(),
            nullable_range_restricted_int_16_u <- Nullable::init_none(),
            nullable_range_restricted_int_16_s <- Nullable::init_none(),
        })
    }
}

pub struct UnitTestingHandler<'a> {
    dataver: Dataver,
    data: &'a RefCell<UnitTestingHandlerData>,
}

impl<'a> UnitTestingHandler<'a> {
    pub const fn new(dataver: Dataver, data: &'a RefCell<UnitTestingHandlerData>) -> Self {
        Self { dataver, data }
    }

    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }
}

impl ClusterHandler for UnitTestingHandler<'_> {
    const CLUSTER: Cluster<'static> = FULL_CLUSTER;

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn boolean(&self, _ctx: &ReadContext<'_>) -> Result<bool, Error> {
        Ok(self.data.borrow().boolean)
    }

    fn bitmap_8(&self, _ctx: &ReadContext<'_>) -> Result<Bitmap8MaskMap, Error> {
        Ok(self.data.borrow().bitmap_8)
    }

    fn bitmap_16(&self, _ctx: &ReadContext<'_>) -> Result<Bitmap16MaskMap, Error> {
        Ok(self.data.borrow().bitmap_16)
    }

    fn bitmap_32(&self, _ctx: &ReadContext<'_>) -> Result<Bitmap32MaskMap, Error> {
        Ok(self.data.borrow().bitmap_32)
    }

    fn bitmap_64(&self, _ctx: &ReadContext<'_>) -> Result<Bitmap64MaskMap, Error> {
        Ok(self.data.borrow().bitmap_64)
    }

    fn int_8_u(&self, _ctx: &ReadContext<'_>) -> Result<u8, Error> {
        Ok(self.data.borrow().int_8_u)
    }

    fn int_16_u(&self, _ctx: &ReadContext<'_>) -> Result<u16, Error> {
        Ok(self.data.borrow().int_16_u)
    }

    fn int_24_u(&self, _ctx: &ReadContext<'_>) -> Result<u32, Error> {
        Ok(self.data.borrow().int_24_u)
    }

    fn int_32_u(&self, _ctx: &ReadContext<'_>) -> Result<u32, Error> {
        Ok(self.data.borrow().int_32_u)
    }

    fn int_40_u(&self, _ctx: &ReadContext<'_>) -> Result<u64, Error> {
        Ok(self.data.borrow().int_40_u)
    }

    fn int_48_u(&self, _ctx: &ReadContext<'_>) -> Result<u64, Error> {
        Ok(self.data.borrow().int_48_u)
    }

    fn int_56_u(&self, _ctx: &ReadContext<'_>) -> Result<u64, Error> {
        Ok(self.data.borrow().int_56_u)
    }

    fn int_64_u(&self, _ctx: &ReadContext<'_>) -> Result<u64, Error> {
        Ok(self.data.borrow().int_64_u)
    }

    fn int_8_s(&self, _ctx: &ReadContext<'_>) -> Result<i8, Error> {
        Ok(self.data.borrow().int_8_s)
    }

    fn int_16_s(&self, _ctx: &ReadContext<'_>) -> Result<i16, Error> {
        Ok(self.data.borrow().int_16_s)
    }

    fn int_24_s(&self, _ctx: &ReadContext<'_>) -> Result<i32, Error> {
        Ok(self.data.borrow().int_24_s)
    }

    fn int_32_s(&self, _ctx: &ReadContext<'_>) -> Result<i32, Error> {
        Ok(self.data.borrow().int_32_s)
    }

    fn int_40_s(&self, _ctx: &ReadContext<'_>) -> Result<i64, Error> {
        Ok(self.data.borrow().int_40_s)
    }

    fn int_48_s(&self, _ctx: &ReadContext<'_>) -> Result<i64, Error> {
        Ok(self.data.borrow().int_48_s)
    }

    fn int_56_s(&self, _ctx: &ReadContext<'_>) -> Result<i64, Error> {
        Ok(self.data.borrow().int_56_s)
    }

    fn int_64_s(&self, _ctx: &ReadContext<'_>) -> Result<i64, Error> {
        Ok(self.data.borrow().int_64_s)
    }

    fn enum_8(&self, _ctx: &ReadContext<'_>) -> Result<u8, Error> {
        Ok(self.data.borrow().enum_8)
    }

    fn enum_16(&self, _ctx: &ReadContext<'_>) -> Result<u16, Error> {
        Ok(self.data.borrow().enum_16)
    }

    fn float_single(&self, _ctx: &ReadContext<'_>) -> Result<f32, Error> {
        Ok(self.data.borrow().float_single)
    }

    fn float_double(&self, _ctx: &ReadContext<'_>) -> Result<f64, Error> {
        Ok(self.data.borrow().float_double)
    }

    fn octet_string<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: OctetsBuilder<P>,
    ) -> Result<P, Error> {
        builder.set(Octets(self.data.borrow().octet_string.as_slice()))
    }

    fn list_int_8_u<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: ArrayAttributeRead<ToTLVArrayBuilder<P, u8>, ToTLVBuilder<P, u8>>,
    ) -> Result<P, Error> {
        match builder {
            ArrayAttributeRead::ReadOne(index, builder) => {
                let data = self.data.borrow();
                if index < data.list_int_8_u.len() as u16 {
                    builder.set(&data.list_int_8_u[index as usize])
                } else {
                    Err(ErrorCode::InvalidAction.into())
                }
            }
            ArrayAttributeRead::ReadAll(mut builder) => {
                let data = self.data.borrow();

                for i in &data.list_int_8_u {
                    builder = builder.push(i)?;
                }

                builder.end()
            }
        }
    }

    fn list_octet_string<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: ArrayAttributeRead<OctetsArrayBuilder<P>, OctetsBuilder<P>>,
    ) -> Result<P, Error> {
        match builder {
            ArrayAttributeRead::ReadOne(index, builder) => {
                let data = self.data.borrow();
                if index < data.list_octet_string.len() as u16 {
                    builder.set(Octets(data.list_octet_string[index as usize].as_slice()))
                } else {
                    Err(ErrorCode::InvalidAction.into())
                }
            }
            ArrayAttributeRead::ReadAll(mut builder) => {
                let data = self.data.borrow();

                for i in &data.list_octet_string {
                    builder = builder.push(Octets(i.as_slice()))?;
                }

                builder.end()
            }
        }
    }

    fn list_struct_octet_string<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: ArrayAttributeRead<
            TestListStructOctetArrayBuilder<P>,
            TestListStructOctetBuilder<P>,
        >,
    ) -> Result<P, Error> {
        match builder {
            ArrayAttributeRead::ReadOne(index, builder) => {
                let data = self.data.borrow();
                if index < data.list_struct_octet_string.len() as u16 {
                    let s = &data.list_struct_octet_string[index as usize];

                    builder
                        .member_1(s.member_1)?
                        .member_2(Octets(&s.member_2))?
                        .end()
                } else {
                    Err(ErrorCode::InvalidAction.into())
                }
            }
            ArrayAttributeRead::ReadAll(mut builder) => {
                let data = self.data.borrow();

                for s in &data.list_struct_octet_string {
                    builder = builder
                        .push()?
                        .member_1(s.member_1)?
                        .member_2(Octets(&s.member_2))?
                        .end()?;
                }

                builder.end()
            }
        }
    }

    fn long_octet_string<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: OctetsBuilder<P>,
    ) -> Result<P, Error> {
        builder.set(Octets(self.data.borrow().long_octet_string.as_slice()))
    }

    fn char_string<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        builder.set(self.data.borrow().char_string.as_str())
    }

    fn long_char_string<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        builder.set(self.data.borrow().long_char_string.as_str())
    }

    fn epoch_us(&self, _ctx: &ReadContext<'_>) -> Result<u64, Error> {
        Ok(self.data.borrow().epoch_us)
    }

    fn epoch_s(&self, _ctx: &ReadContext<'_>) -> Result<u32, Error> {
        Ok(self.data.borrow().epoch_s)
    }

    fn vendor_id(&self, _ctx: &ReadContext<'_>) -> Result<u16, Error> {
        Ok(self.data.borrow().vendor_id)
    }

    fn list_nullables_and_optionals_struct<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: ArrayAttributeRead<
            NullablesAndOptionalsStructArrayBuilder<P>,
            NullablesAndOptionalsStructBuilder<P>,
        >,
    ) -> Result<P, Error> {
        fn read_one<PP: TLVBuilderParent>(
            builder: NullablesAndOptionalsStructBuilder<PP>,
            s: &NullablesAndOptionalsStructOwned,
        ) -> Result<PP, Error> {
            builder
                .nullable_int(s.nullable_int.clone())?
                .optional_int(s.optional_int)?
                .nullable_optional_int(s.nullable_optional_int.clone())?
                .nullable_string(s.nullable_string.as_deref())?
                .optional_string(s.optional_string.as_deref())?
                .nullable_optional_string(
                    s.nullable_optional_string.as_ref().map(|s| s.as_deref()),
                )?
                .nullable_struct()?
                .with_non_null(s.nullable_struct.as_ref(), |ss, builder| {
                    builder
                        .a(ss.a)?
                        .b(ss.b)?
                        .c(ss.c)?
                        .d(Octets(&ss.d))?
                        .e(ss.e.as_str())?
                        .f(ss.f)?
                        .g(ss.g)?
                        .h(ss.h)?
                        .end()
                })?
                .optional_struct()?
                .with_some(s.optional_struct.as_ref(), |ss, builder| {
                    builder
                        .a(ss.a)?
                        .b(ss.b)?
                        .c(ss.c)?
                        .d(Octets(&ss.d))?
                        .e(ss.e.as_str())?
                        .f(ss.f)?
                        .g(ss.g)?
                        .h(ss.h)?
                        .end()
                })?
                .nullable_optional_struct()?
                .with_some(s.nullable_optional_struct.as_ref(), |ss, builder| {
                    builder.with_non_null(ss.as_ref(), |ss, builder| {
                        builder
                            .a(ss.a)?
                            .b(ss.b)?
                            .c(ss.c)?
                            .d(Octets(&ss.d))?
                            .e(ss.e.as_str())?
                            .f(ss.f)?
                            .g(ss.g)?
                            .h(ss.h)?
                            .end()
                    })
                })?
                .nullable_list()?
                .with_non_null(s.nullable_list.as_ref(), |l, mut builder| {
                    for s in *l {
                        builder = builder.push(s)?;
                    }

                    builder.end()
                })?
                .optional_list()?
                .with_some(s.optional_list.as_ref(), |l, mut builder| {
                    for s in *l {
                        builder = builder.push(s)?;
                    }

                    builder.end()
                })?
                .nullable_optional_list()?
                .with_some(s.nullable_optional_list.as_ref(), |l, builder| {
                    builder.with_non_null(l.as_ref(), |l, mut builder| {
                        for s in *l {
                            builder = builder.push(s)?;
                        }

                        builder.end()
                    })
                })?
                .end()
        }

        match builder {
            ArrayAttributeRead::ReadOne(index, builder) => {
                let data = self.data.borrow();
                if index < data.list_nullables_and_optionals_struct.len() as u16 {
                    let s = &data.list_nullables_and_optionals_struct[index as usize];

                    read_one(builder, s)
                } else {
                    Err(ErrorCode::InvalidAction.into())
                }
            }
            ArrayAttributeRead::ReadAll(mut builder) => {
                let data = self.data.borrow();

                for s in &data.list_nullables_and_optionals_struct {
                    builder = read_one(builder.push()?, s)?;
                }

                builder.end()
            }
        }
    }

    fn enum_attr(&self, _ctx: &ReadContext<'_>) -> Result<SimpleEnum, Error> {
        Ok(self.data.borrow().enum_attr)
    }

    fn struct_attr<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: SimpleStructBuilder<P>,
    ) -> Result<P, Error> {
        let data = self.data.borrow();
        let s = &data.struct_attr;

        builder
            .a(s.a)?
            .b(s.b)?
            .c(s.c)?
            .d(Octets(&s.d))?
            .e(s.e.as_str())?
            .f(s.f)?
            .g(s.g)?
            .h(s.h)?
            .end()
    }

    fn range_restricted_int_8_u(&self, _ctx: &ReadContext<'_>) -> Result<u8, Error> {
        Ok(self.data.borrow().range_restricted_int_8_u)
    }

    fn range_restricted_int_8_s(&self, _ctx: &ReadContext<'_>) -> Result<i8, Error> {
        Ok(self.data.borrow().range_restricted_int_8_s)
    }

    fn range_restricted_int_16_u(&self, _ctx: &ReadContext<'_>) -> Result<u16, Error> {
        Ok(self.data.borrow().range_restricted_int_16_u)
    }

    fn range_restricted_int_16_s(&self, _ctx: &ReadContext<'_>) -> Result<i16, Error> {
        Ok(self.data.borrow().range_restricted_int_16_s)
    }

    fn list_long_octet_string<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: ArrayAttributeRead<OctetsArrayBuilder<P>, OctetsBuilder<P>>,
    ) -> Result<P, Error> {
        match builder {
            ArrayAttributeRead::ReadOne(index, builder) => {
                let data = self.data.borrow();
                if index < data.list_long_octet_string.len() as u16 {
                    builder.set(Octets(
                        data.list_long_octet_string[index as usize].as_slice(),
                    ))
                } else {
                    Err(ErrorCode::InvalidAction.into())
                }
            }
            ArrayAttributeRead::ReadAll(mut builder) => {
                let data = self.data.borrow();

                for i in &data.list_long_octet_string {
                    builder = builder.push(Octets(i.as_slice()))?;
                }

                builder.end()
            }
        }
    }

    fn list_fabric_scoped<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        _builder: ArrayAttributeRead<TestFabricScopedArrayBuilder<P>, TestFabricScopedBuilder<P>>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn timed_write_boolean(&self, _ctx: &ReadContext<'_>) -> Result<bool, Error> {
        todo!()
    }

    fn general_error_boolean(&self, _ctx: &ReadContext<'_>) -> Result<bool, Error> {
        todo!()
    }

    fn cluster_error_boolean(&self, _ctx: &ReadContext<'_>) -> Result<bool, Error> {
        todo!()
    }

    fn nullable_boolean(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<bool>, Error> {
        Ok(self.data.borrow().nullable_boolean.clone())
    }

    fn nullable_bitmap_8(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<Bitmap8MaskMap>, Error> {
        Ok(self.data.borrow().nullable_bitmap_8.clone())
    }

    fn nullable_bitmap_16(
        &self,
        _ctx: &ReadContext<'_>,
    ) -> Result<Nullable<Bitmap16MaskMap>, Error> {
        Ok(self.data.borrow().nullable_bitmap_16.clone())
    }

    fn nullable_bitmap_32(
        &self,
        _ctx: &ReadContext<'_>,
    ) -> Result<Nullable<Bitmap32MaskMap>, Error> {
        Ok(self.data.borrow().nullable_bitmap_32.clone())
    }

    fn nullable_bitmap_64(
        &self,
        _ctx: &ReadContext<'_>,
    ) -> Result<Nullable<Bitmap64MaskMap>, Error> {
        Ok(self.data.borrow().nullable_bitmap_64.clone())
    }

    fn nullable_int_8_u(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<u8>, Error> {
        Ok(self.data.borrow().nullable_int_8_u.clone())
    }

    fn nullable_int_16_u(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<u16>, Error> {
        Ok(self.data.borrow().nullable_int_16_u.clone())
    }

    fn nullable_int_24_u(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<u32>, Error> {
        Ok(self.data.borrow().nullable_int_24_u.clone())
    }

    fn nullable_int_32_u(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<u32>, Error> {
        Ok(self.data.borrow().nullable_int_32_u.clone())
    }

    fn nullable_int_40_u(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<u64>, Error> {
        Ok(self.data.borrow().nullable_int_40_u.clone())
    }

    fn nullable_int_48_u(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<u64>, Error> {
        Ok(self.data.borrow().nullable_int_48_u.clone())
    }

    fn nullable_int_56_u(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<u64>, Error> {
        Ok(self.data.borrow().nullable_int_56_u.clone())
    }

    fn nullable_int_64_u(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<u64>, Error> {
        Ok(self.data.borrow().nullable_int_64_u.clone())
    }

    fn nullable_int_8_s(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<i8>, Error> {
        Ok(self.data.borrow().nullable_int_8_s.clone())
    }

    fn nullable_int_16_s(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<i16>, Error> {
        Ok(self.data.borrow().nullable_int_16_s.clone())
    }

    fn nullable_int_24_s(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<i32>, Error> {
        Ok(self.data.borrow().nullable_int_24_s.clone())
    }

    fn nullable_int_32_s(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<i32>, Error> {
        Ok(self.data.borrow().nullable_int_32_s.clone())
    }

    fn nullable_int_40_s(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<i64>, Error> {
        Ok(self.data.borrow().nullable_int_40_s.clone())
    }

    fn nullable_int_48_s(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<i64>, Error> {
        Ok(self.data.borrow().nullable_int_48_s.clone())
    }

    fn nullable_int_56_s(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<i64>, Error> {
        Ok(self.data.borrow().nullable_int_56_s.clone())
    }

    fn nullable_int_64_s(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<i64>, Error> {
        Ok(self.data.borrow().nullable_int_64_s.clone())
    }

    fn nullable_enum_8(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<u8>, Error> {
        Ok(self.data.borrow().nullable_enum_8.clone())
    }

    fn nullable_enum_16(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<u16>, Error> {
        Ok(self.data.borrow().nullable_enum_16.clone())
    }

    fn nullable_float_single(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<f32>, Error> {
        Ok(self.data.borrow().nullable_float_single.clone())
    }

    fn nullable_float_double(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<f64>, Error> {
        Ok(self.data.borrow().nullable_float_double.clone())
    }

    fn nullable_octet_string<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: NullableBuilder<P, OctetsBuilder<P>>,
    ) -> Result<P, Error> {
        if let Some(o) = self.data.borrow().nullable_octet_string.as_opt_deref() {
            builder.non_null()?.set(Octets(o))
        } else {
            builder.null()
        }
    }

    fn nullable_char_string<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: NullableBuilder<P, Utf8StrBuilder<P>>,
    ) -> Result<P, Error> {
        if let Some(o) = self.data.borrow().nullable_char_string.as_opt_deref() {
            builder.non_null()?.set(o)
        } else {
            builder.null()
        }
    }

    fn nullable_enum_attr(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<SimpleEnum>, Error> {
        Ok(self.data.borrow().nullable_enum_attr.clone())
    }

    fn nullable_struct<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: NullableBuilder<P, SimpleStructBuilder<P>>,
    ) -> Result<P, Error> {
        if let Some(s) = self.data.borrow().nullable_struct.as_opt_ref() {
            let builder = builder.non_null()?;

            builder
                .a(s.a)?
                .b(s.b)?
                .c(s.c)?
                .d(Octets(&s.d))?
                .e(s.e.as_str())?
                .f(s.f)?
                .g(s.g)?
                .h(s.h)?
                .end()
        } else {
            builder.null()
        }
    }

    fn nullable_range_restricted_int_8_u(
        &self,
        _ctx: &ReadContext<'_>,
    ) -> Result<Nullable<u8>, Error> {
        Ok(self.data.borrow().nullable_range_restricted_int_8_u.clone())
    }

    fn nullable_range_restricted_int_8_s(
        &self,
        _ctx: &ReadContext<'_>,
    ) -> Result<Nullable<i8>, Error> {
        Ok(self.data.borrow().nullable_range_restricted_int_8_s.clone())
    }

    fn nullable_range_restricted_int_16_u(
        &self,
        _ctx: &ReadContext<'_>,
    ) -> Result<Nullable<u16>, Error> {
        Ok(self
            .data
            .borrow()
            .nullable_range_restricted_int_16_u
            .clone())
    }

    fn nullable_range_restricted_int_16_s(
        &self,
        _ctx: &ReadContext<'_>,
    ) -> Result<Nullable<i16>, Error> {
        Ok(self
            .data
            .borrow()
            .nullable_range_restricted_int_16_s
            .clone())
    }

    fn set_boolean(&self, _ctx: &WriteContext<'_>, value: bool) -> Result<(), Error> {
        self.data.borrow_mut().boolean = value;
        Ok(())
    }

    fn set_bitmap_8(&self, _ctx: &WriteContext<'_>, value: Bitmap8MaskMap) -> Result<(), Error> {
        self.data.borrow_mut().bitmap_8 = value;
        Ok(())
    }

    fn set_bitmap_16(&self, _ctx: &WriteContext<'_>, value: Bitmap16MaskMap) -> Result<(), Error> {
        self.data.borrow_mut().bitmap_16 = value;
        Ok(())
    }

    fn set_bitmap_32(&self, _ctx: &WriteContext<'_>, value: Bitmap32MaskMap) -> Result<(), Error> {
        self.data.borrow_mut().bitmap_32 = value;
        Ok(())
    }

    fn set_bitmap_64(&self, _ctx: &WriteContext<'_>, value: Bitmap64MaskMap) -> Result<(), Error> {
        self.data.borrow_mut().bitmap_64 = value;
        Ok(())
    }

    fn set_int_8_u(&self, _ctx: &WriteContext<'_>, value: u8) -> Result<(), Error> {
        self.data.borrow_mut().int_8_u = value;
        Ok(())
    }

    fn set_int_16_u(&self, _ctx: &WriteContext<'_>, value: u16) -> Result<(), Error> {
        self.data.borrow_mut().int_16_u = value;
        Ok(())
    }

    fn set_int_24_u(&self, _ctx: &WriteContext<'_>, value: u32) -> Result<(), Error> {
        self.data.borrow_mut().int_24_u = value;
        Ok(())
    }

    fn set_int_32_u(&self, _ctx: &WriteContext<'_>, value: u32) -> Result<(), Error> {
        self.data.borrow_mut().int_32_u = value;
        Ok(())
    }

    fn set_int_40_u(&self, _ctx: &WriteContext<'_>, value: u64) -> Result<(), Error> {
        self.data.borrow_mut().int_40_u = value;
        Ok(())
    }

    fn set_int_48_u(&self, _ctx: &WriteContext<'_>, value: u64) -> Result<(), Error> {
        self.data.borrow_mut().int_48_u = value;
        Ok(())
    }

    fn set_int_56_u(&self, _ctx: &WriteContext<'_>, value: u64) -> Result<(), Error> {
        self.data.borrow_mut().int_56_u = value;
        Ok(())
    }

    fn set_int_64_u(&self, _ctx: &WriteContext<'_>, value: u64) -> Result<(), Error> {
        self.data.borrow_mut().int_64_u = value;
        Ok(())
    }

    fn set_int_8_s(&self, _ctx: &WriteContext<'_>, value: i8) -> Result<(), Error> {
        self.data.borrow_mut().int_8_s = value;
        Ok(())
    }

    fn set_int_16_s(&self, _ctx: &WriteContext<'_>, value: i16) -> Result<(), Error> {
        self.data.borrow_mut().int_16_s = value;
        Ok(())
    }

    fn set_int_24_s(&self, _ctx: &WriteContext<'_>, value: i32) -> Result<(), Error> {
        self.data.borrow_mut().int_24_s = value;
        Ok(())
    }

    fn set_int_32_s(&self, _ctx: &WriteContext<'_>, value: i32) -> Result<(), Error> {
        self.data.borrow_mut().int_32_s = value;
        Ok(())
    }

    fn set_int_40_s(&self, _ctx: &WriteContext<'_>, value: i64) -> Result<(), Error> {
        self.data.borrow_mut().int_40_s = value;
        Ok(())
    }

    fn set_int_48_s(&self, _ctx: &WriteContext<'_>, value: i64) -> Result<(), Error> {
        self.data.borrow_mut().int_48_s = value;
        Ok(())
    }

    fn set_int_56_s(&self, _ctx: &WriteContext<'_>, value: i64) -> Result<(), Error> {
        self.data.borrow_mut().int_56_s = value;
        Ok(())
    }

    fn set_int_64_s(&self, _ctx: &WriteContext<'_>, value: i64) -> Result<(), Error> {
        self.data.borrow_mut().int_64_s = value;
        Ok(())
    }

    fn set_enum_8(&self, _ctx: &WriteContext<'_>, value: u8) -> Result<(), Error> {
        self.data.borrow_mut().enum_8 = value;
        Ok(())
    }

    fn set_enum_16(&self, _ctx: &WriteContext<'_>, value: u16) -> Result<(), Error> {
        self.data.borrow_mut().enum_16 = value;
        Ok(())
    }

    fn set_float_single(&self, _ctx: &WriteContext<'_>, value: f32) -> Result<(), Error> {
        self.data.borrow_mut().float_single = value;
        Ok(())
    }

    fn set_float_double(&self, _ctx: &WriteContext<'_>, value: f64) -> Result<(), Error> {
        self.data.borrow_mut().float_double = value;
        Ok(())
    }

    fn set_octet_string(&self, _ctx: &WriteContext<'_>, value: OctetStr<'_>) -> Result<(), Error> {
        self.data.borrow_mut().octet_string =
            value.0.try_into().map_err(|_| ErrorCode::InvalidAction)?;
        Ok(())
    }

    fn set_list_int_8_u(
        &self,
        _ctx: &WriteContext<'_>,
        value: ArrayAttributeWrite<TLVArray<'_, u8>, u8>,
    ) -> Result<(), Error> {
        match value {
            ArrayAttributeWrite::Replace(arr) => {
                if arr.iter().count() > 16 {
                    return Err(ErrorCode::InvalidAction.into());
                }

                let mut data = self.data.borrow_mut();
                data.list_int_8_u.clear();
                for i in arr {
                    unwrap!(data.list_int_8_u.push(i?));
                }

                Ok(())
            }
            ArrayAttributeWrite::Add(item) => {
                let mut data = self.data.borrow_mut();
                if data.list_int_8_u.len() < 16 {
                    unwrap!(data.list_int_8_u.push(item));
                    Ok(())
                } else {
                    Err(ErrorCode::InvalidAction.into())
                }
            }
            ArrayAttributeWrite::Update(index, item) => {
                let mut data = self.data.borrow_mut();
                if index < data.list_int_8_u.len() as u16 {
                    data.list_int_8_u[index as usize] = item;
                    Ok(())
                } else {
                    Err(ErrorCode::InvalidAction.into())
                }
            }
            ArrayAttributeWrite::Remove(index) => {
                let mut data = self.data.borrow_mut();
                if index < data.list_int_8_u.len() as u16 {
                    let _ = data.list_int_8_u.remove(index as usize);
                    Ok(())
                } else {
                    Err(ErrorCode::InvalidAction.into())
                }
            }
        }
    }

    fn set_list_octet_string(
        &self,
        _ctx: &WriteContext<'_>,
        value: ArrayAttributeWrite<TLVArray<'_, OctetStr<'_>>, OctetStr<'_>>,
    ) -> Result<(), Error> {
        match value {
            ArrayAttributeWrite::Replace(arr) => {
                if arr.iter().count() > 16 {
                    return Err(ErrorCode::InvalidAction.into());
                }

                let mut data = self.data.borrow_mut();
                data.list_octet_string.clear();
                for i in arr {
                    unwrap!(data
                        .list_octet_string
                        .push(i?.0.try_into().map_err(|_| ErrorCode::InvalidAction)?));
                }

                Ok(())
            }
            ArrayAttributeWrite::Add(item) => {
                let mut data = self.data.borrow_mut();
                if data.list_octet_string.len() < 16 {
                    unwrap!(data
                        .list_octet_string
                        .push(item.0.try_into().map_err(|_| ErrorCode::InvalidAction)?));
                    Ok(())
                } else {
                    Err(ErrorCode::InvalidAction.into())
                }
            }
            ArrayAttributeWrite::Update(index, item) => {
                let mut data = self.data.borrow_mut();
                if index < data.list_octet_string.len() as u16 {
                    data.list_octet_string[index as usize] =
                        item.0.try_into().map_err(|_| ErrorCode::InvalidAction)?;
                    Ok(())
                } else {
                    Err(ErrorCode::InvalidAction.into())
                }
            }
            ArrayAttributeWrite::Remove(index) => {
                let mut data = self.data.borrow_mut();
                if index < data.list_octet_string.len() as u16 {
                    let _ = data.list_octet_string.remove(index as usize);
                    Ok(())
                } else {
                    Err(ErrorCode::InvalidAction.into())
                }
            }
        }
    }

    fn set_list_struct_octet_string(
        &self,
        _ctx: &WriteContext<'_>,
        value: ArrayAttributeWrite<TLVArray<'_, TestListStructOctet<'_>>, TestListStructOctet<'_>>,
    ) -> Result<(), Error> {
        match value {
            ArrayAttributeWrite::Replace(arr) => {
                if arr.iter().count() > 16 {
                    return Err(ErrorCode::InvalidAction.into());
                }

                let mut data = self.data.borrow_mut();
                data.list_struct_octet_string.clear();
                for i in arr {
                    let s = i?;

                    unwrap!(data
                        .list_struct_octet_string
                        .push(TestListStructOctetOwned {
                            member_1: s.member_1()?,
                            member_2: s
                                .member_2()?
                                .0
                                .try_into()
                                .map_err(|_| ErrorCode::InvalidAction)?,
                        }));
                }

                Ok(())
            }
            ArrayAttributeWrite::Add(item) => {
                let mut data = self.data.borrow_mut();
                if data.list_struct_octet_string.len() < 16 {
                    unwrap!(data
                        .list_struct_octet_string
                        .push(TestListStructOctetOwned {
                            member_1: item.member_1()?,
                            member_2: item
                                .member_2()?
                                .0
                                .try_into()
                                .map_err(|_| ErrorCode::InvalidAction)?,
                        }));
                    Ok(())
                } else {
                    Err(ErrorCode::InvalidAction.into())
                }
            }
            ArrayAttributeWrite::Update(index, item) => {
                let mut data = self.data.borrow_mut();
                if index < data.list_struct_octet_string.len() as u16 {
                    data.list_struct_octet_string[index as usize] = TestListStructOctetOwned {
                        member_1: item.member_1()?,
                        member_2: item
                            .member_2()?
                            .0
                            .try_into()
                            .map_err(|_| ErrorCode::InvalidAction)?,
                    };
                    Ok(())
                } else {
                    Err(ErrorCode::InvalidAction.into())
                }
            }
            ArrayAttributeWrite::Remove(index) => {
                let mut data = self.data.borrow_mut();
                if index < data.list_struct_octet_string.len() as u16 {
                    let _ = data.list_struct_octet_string.remove(index as usize);
                    Ok(())
                } else {
                    Err(ErrorCode::InvalidAction.into())
                }
            }
        }
    }

    fn set_long_octet_string(
        &self,
        _ctx: &WriteContext<'_>,
        value: OctetStr<'_>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().long_octet_string =
            value.0.try_into().map_err(|_| ErrorCode::InvalidAction)?;
        Ok(())
    }

    fn set_char_string(&self, _ctx: &WriteContext<'_>, value: Utf8Str<'_>) -> Result<(), Error> {
        self.data.borrow_mut().char_string =
            value.try_into().map_err(|_| ErrorCode::InvalidAction)?;
        Ok(())
    }

    fn set_long_char_string(
        &self,
        _ctx: &WriteContext<'_>,
        value: Utf8Str<'_>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().long_char_string =
            value.try_into().map_err(|_| ErrorCode::InvalidAction)?;
        Ok(())
    }

    fn set_epoch_us(&self, _ctx: &WriteContext<'_>, value: u64) -> Result<(), Error> {
        self.data.borrow_mut().epoch_us = value;
        Ok(())
    }

    fn set_epoch_s(&self, _ctx: &WriteContext<'_>, value: u32) -> Result<(), Error> {
        self.data.borrow_mut().epoch_s = value;
        Ok(())
    }

    fn set_vendor_id(&self, _ctx: &WriteContext<'_>, value: u16) -> Result<(), Error> {
        self.data.borrow_mut().vendor_id = value;
        Ok(())
    }

    fn set_list_nullables_and_optionals_struct(
        &self,
        _ctx: &WriteContext<'_>,
        value: ArrayAttributeWrite<
            TLVArray<'_, NullablesAndOptionalsStruct<'_>>,
            NullablesAndOptionalsStruct<'_>,
        >,
    ) -> Result<(), Error> {
        fn to_owned<'a>(
            s: &'a NullablesAndOptionalsStruct<'a>,
        ) -> impl Init<NullablesAndOptionalsStructOwned, Error> + 'a {
            NullablesAndOptionalsStructOwned::init()
                .into_fallible()
                .chain(|o| o.update(s))
        }

        let no_space = || ErrorCode::NoSpace.into(); // TODO

        match value {
            ArrayAttributeWrite::Replace(arr) => {
                if arr.iter().count() > 16 {
                    return Err(ErrorCode::InvalidAction.into());
                }

                let mut data = self.data.borrow_mut();
                data.list_nullables_and_optionals_struct.clear();
                for i in arr {
                    let s = i?;

                    data.list_nullables_and_optionals_struct
                        .push_init(to_owned(&s), no_space)?;
                }

                Ok(())
            }
            ArrayAttributeWrite::Add(item) => {
                let mut data = self.data.borrow_mut();
                if data.list_nullables_and_optionals_struct.len() < 16 {
                    data.list_nullables_and_optionals_struct
                        .push_init(to_owned(&item), no_space)
                } else {
                    Err(ErrorCode::InvalidAction.into())
                }
            }
            ArrayAttributeWrite::Update(index, item) => {
                let mut data = self.data.borrow_mut();
                if index < data.list_nullables_and_optionals_struct.len() as u16 {
                    data.list_nullables_and_optionals_struct[index as usize].update(&item)?;
                    Ok(())
                } else {
                    Err(ErrorCode::InvalidAction.into())
                }
            }
            ArrayAttributeWrite::Remove(index) => {
                let mut data = self.data.borrow_mut();
                if index < data.list_nullables_and_optionals_struct.len() as u16 {
                    let _ = data
                        .list_nullables_and_optionals_struct
                        .remove(index as usize);
                    Ok(())
                } else {
                    Err(ErrorCode::InvalidAction.into())
                }
            }
        }
    }

    fn set_enum_attr(&self, _ctx: &WriteContext<'_>, value: SimpleEnum) -> Result<(), Error> {
        self.data.borrow_mut().enum_attr = value;
        Ok(())
    }

    fn set_struct_attr(
        &self,
        _ctx: &WriteContext<'_>,
        value: SimpleStruct<'_>,
    ) -> Result<(), Error> {
        let mut data = self.data.borrow_mut();

        let s = &mut data.struct_attr;
        s.a = value.a()?;
        s.b = value.b()?;
        s.c = value.c()?;
        s.d = value
            .d()?
            .0
            .try_into()
            .map_err(|_| ErrorCode::InvalidAction)?;
        s.e = value
            .e()?
            .try_into()
            .map_err(|_| ErrorCode::InvalidAction)?;
        s.f = value.f()?;
        s.g = value.g()?;
        s.h = value.h()?;

        Ok(())
    }

    fn set_range_restricted_int_8_u(
        &self,
        _ctx: &WriteContext<'_>,
        value: u8,
    ) -> Result<(), Error> {
        self.data.borrow_mut().range_restricted_int_8_u = value;
        Ok(())
    }

    fn set_range_restricted_int_8_s(
        &self,
        _ctx: &WriteContext<'_>,
        value: i8,
    ) -> Result<(), Error> {
        self.data.borrow_mut().range_restricted_int_8_s = value;
        Ok(())
    }

    fn set_range_restricted_int_16_u(
        &self,
        _ctx: &WriteContext<'_>,
        value: u16,
    ) -> Result<(), Error> {
        self.data.borrow_mut().range_restricted_int_16_u = value;
        Ok(())
    }

    fn set_range_restricted_int_16_s(
        &self,
        _ctx: &WriteContext<'_>,
        value: i16,
    ) -> Result<(), Error> {
        self.data.borrow_mut().range_restricted_int_16_s = value;
        Ok(())
    }

    fn set_list_long_octet_string(
        &self,
        _ctx: &WriteContext<'_>,
        value: ArrayAttributeWrite<TLVArray<'_, OctetStr<'_>>, OctetStr<'_>>,
    ) -> Result<(), Error> {
        match value {
            ArrayAttributeWrite::Replace(arr) => {
                if arr.iter().count() > 16 {
                    return Err(ErrorCode::InvalidAction.into());
                }

                let mut data = self.data.borrow_mut();
                data.list_long_octet_string.clear();
                for i in arr {
                    unwrap!(data
                        .list_long_octet_string
                        .push(i?.0.try_into().map_err(|_| ErrorCode::InvalidAction)?));
                }

                Ok(())
            }
            ArrayAttributeWrite::Add(item) => {
                let mut data = self.data.borrow_mut();
                if data.list_long_octet_string.len() < 16 {
                    unwrap!(data
                        .list_long_octet_string
                        .push(item.0.try_into().map_err(|_| ErrorCode::InvalidAction)?));
                    Ok(())
                } else {
                    Err(ErrorCode::InvalidAction.into())
                }
            }
            ArrayAttributeWrite::Update(index, item) => {
                let mut data = self.data.borrow_mut();
                if index < data.list_long_octet_string.len() as u16 {
                    data.list_long_octet_string[index as usize] =
                        item.0.try_into().map_err(|_| ErrorCode::InvalidAction)?;
                    Ok(())
                } else {
                    Err(ErrorCode::InvalidAction.into())
                }
            }
            ArrayAttributeWrite::Remove(index) => {
                let mut data = self.data.borrow_mut();
                if index < data.list_long_octet_string.len() as u16 {
                    let _ = data.list_long_octet_string.remove(index as usize);
                    Ok(())
                } else {
                    Err(ErrorCode::InvalidAction.into())
                }
            }
        }
    }

    fn set_list_fabric_scoped(
        &self,
        _ctx: &WriteContext<'_>,
        _value: ArrayAttributeWrite<TLVArray<'_, TestFabricScoped<'_>>, TestFabricScoped<'_>>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_timed_write_boolean(&self, _ctx: &WriteContext<'_>, _value: bool) -> Result<(), Error> {
        todo!()
    }

    fn set_general_error_boolean(
        &self,
        _ctx: &WriteContext<'_>,
        _value: bool,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_cluster_error_boolean(
        &self,
        _ctx: &WriteContext<'_>,
        _value: bool,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_boolean(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<bool>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_boolean = value;
        Ok(())
    }

    fn set_nullable_bitmap_8(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<Bitmap8MaskMap>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_bitmap_8 = value;
        Ok(())
    }

    fn set_nullable_bitmap_16(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<Bitmap16MaskMap>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_bitmap_16 = value;
        Ok(())
    }

    fn set_nullable_bitmap_32(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<Bitmap32MaskMap>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_bitmap_32 = value;
        Ok(())
    }

    fn set_nullable_bitmap_64(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<Bitmap64MaskMap>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_bitmap_64 = value;
        Ok(())
    }

    fn set_nullable_int_8_u(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<u8>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_int_8_u = value;
        Ok(())
    }

    fn set_nullable_int_16_u(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<u16>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_int_16_u = value;
        Ok(())
    }

    fn set_nullable_int_24_u(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<u32>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_int_24_u = value;
        Ok(())
    }

    fn set_nullable_int_32_u(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<u32>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_int_32_u = value;
        Ok(())
    }

    fn set_nullable_int_40_u(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<u64>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_int_40_u = value;
        Ok(())
    }

    fn set_nullable_int_48_u(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<u64>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_int_48_u = value;
        Ok(())
    }

    fn set_nullable_int_56_u(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<u64>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_int_56_u = value;
        Ok(())
    }

    fn set_nullable_int_64_u(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<u64>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_int_64_u = value;
        Ok(())
    }

    fn set_nullable_int_8_s(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<i8>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_int_8_s = value;
        Ok(())
    }

    fn set_nullable_int_16_s(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<i16>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_int_16_s = value;
        Ok(())
    }

    fn set_nullable_int_24_s(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<i32>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_int_24_s = value;
        Ok(())
    }

    fn set_nullable_int_32_s(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<i32>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_int_32_s = value;
        Ok(())
    }

    fn set_nullable_int_40_s(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<i64>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_int_40_s = value;
        Ok(())
    }

    fn set_nullable_int_48_s(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<i64>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_int_48_s = value;
        Ok(())
    }

    fn set_nullable_int_56_s(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<i64>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_int_56_s = value;
        Ok(())
    }

    fn set_nullable_int_64_s(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<i64>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_int_64_s = value;
        Ok(())
    }

    fn set_nullable_enum_8(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<u8>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_enum_8 = value;
        Ok(())
    }

    fn set_nullable_enum_16(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<u16>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_enum_16 = value;
        Ok(())
    }

    fn set_nullable_float_single(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<f32>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_float_single = value;
        Ok(())
    }

    fn set_nullable_float_double(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<f64>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_float_double = value;
        Ok(())
    }

    fn set_nullable_octet_string(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<OctetStr<'_>>,
    ) -> Result<(), Error> {
        if let Some(value) = value.into_option() {
            self.data.borrow_mut().nullable_octet_string =
                Nullable::some(value.0.try_into().map_err(|_| ErrorCode::InvalidAction)?);
        } else {
            self.data.borrow_mut().nullable_octet_string = Nullable::none();
        }

        Ok(())
    }

    fn set_nullable_char_string(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<Utf8Str<'_>>,
    ) -> Result<(), Error> {
        if let Some(value) = value.into_option() {
            self.data.borrow_mut().nullable_char_string =
                Nullable::some(value.try_into().map_err(|_| ErrorCode::InvalidAction)?);
        } else {
            self.data.borrow_mut().nullable_char_string = Nullable::none();
        }

        Ok(())
    }

    fn set_nullable_enum_attr(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<SimpleEnum>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_enum_attr = value;
        Ok(())
    }

    fn set_nullable_struct(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<SimpleStruct<'_>>,
    ) -> Result<(), Error> {
        if let Some(s) = value.into_option() {
            let mut data = self.data.borrow_mut();
            let ns = SimpleStructOwned {
                a: s.a()?,
                b: s.b()?,
                c: s.c()?,
                d: s.d()?.0.try_into().map_err(|_| ErrorCode::InvalidAction)?,
                e: s.e()?.try_into().map_err(|_| ErrorCode::InvalidAction)?,
                f: s.f()?,
                g: s.g()?,
                h: s.h()?,
            };

            data.nullable_struct = Nullable::some(ns);
        } else {
            self.data.borrow_mut().nullable_struct = Nullable::none();
        }

        Ok(())
    }

    fn set_nullable_range_restricted_int_8_u(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<u8>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_range_restricted_int_8_u = value;
        Ok(())
    }

    fn set_nullable_range_restricted_int_8_s(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<i8>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_range_restricted_int_8_s = value;
        Ok(())
    }

    fn set_nullable_range_restricted_int_16_u(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<u16>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_range_restricted_int_16_u = value;
        Ok(())
    }

    fn set_nullable_range_restricted_int_16_s(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<i16>,
    ) -> Result<(), Error> {
        self.data.borrow_mut().nullable_range_restricted_int_16_s = value;
        Ok(())
    }

    fn handle_test(&self, _ctx: &InvokeContext<'_>) -> Result<(), Error> {
        Ok(())
    }

    fn handle_test_not_handled(&self, _ctx: &InvokeContext<'_>) -> Result<(), Error> {
        todo!()
    }

    fn handle_test_specific<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        response: TestSpecificResponseBuilder<P>,
    ) -> Result<P, Error> {
        response.return_value(7)?.end()
    }

    fn handle_test_unknown_command(&self, _ctx: &InvokeContext<'_>) -> Result<(), Error> {
        todo!()
    }

    fn handle_test_add_arguments<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestAddArgumentsRequest<'_>,
        response: TestAddArgumentsResponseBuilder<P>,
    ) -> Result<P, Error> {
        let result = request.arg_1()? as u16 + request.arg_2()? as u16;
        if result <= u8::MAX as u16 {
            response.return_value(result as _)?.end()
        } else {
            Err(ErrorCode::InvalidCommand.into())
        }
    }

    fn handle_test_simple_argument_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestSimpleArgumentRequestRequest<'_>,
        response: TestSimpleArgumentResponseBuilder<P>,
    ) -> Result<P, Error> {
        response.return_value(request.arg_1()? as _)?.end()
    }

    fn handle_test_struct_array_argument_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        _request: TestStructArrayArgumentRequestRequest<'_>,
        _response: TestStructArrayArgumentResponseBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn handle_test_struct_argument_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestStructArgumentRequestRequest<'_>,
        response: BooleanResponseBuilder<P>,
    ) -> Result<P, Error> {
        let s = request.arg_1()?;

        let result = s.a()? == 0
            && s.b()?
            && s.c()? == SimpleEnum::ValueB
            && s.d()?.0 == b"octet_string"
            && s.e()? == "char_string"
            && s.f()? == SimpleBitmap::VALUE_B
            && s.g()? == 0f32
            && s.h()? == 0f64;

        response.value(result)?.end()
    }

    fn handle_test_nested_struct_argument_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestNestedStructArgumentRequestRequest<'_>,
        response: BooleanResponseBuilder<P>,
    ) -> Result<P, Error> {
        let s = request.arg_1()?;

        let result = s.a()? == 0 && s.b()? && {
            let s = s.c()?;

            s.a()? == 0
                && s.b()?
                && s.c()? == SimpleEnum::ValueB
                && s.d()?.0 == b"octet_string"
                && s.e()? == "char_string"
                && s.f()? == SimpleBitmap::VALUE_B
                && s.g()? == 0f32
                && s.h()? == 0f64
        };

        response.value(result)?.end()
    }

    fn handle_test_list_struct_argument_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestListStructArgumentRequestRequest<'_>,
        response: BooleanResponseBuilder<P>,
    ) -> Result<P, Error> {
        let l = request.arg_1()?;

        let mut result = l.iter().count() == 2;

        if result {
            let mut iter = l.iter();

            let s1 = unwrap!(iter.next())?;
            let s2 = unwrap!(iter.next())?;

            result = s1.a()? == 0
                && s1.b()?
                && s1.c()? == SimpleEnum::ValueB
                && s1.d()?.0 == b"first_octet_string"
                && s1.e()? == "first_char_string"
                && s1.f()? == SimpleBitmap::VALUE_B
                && s1.g()? == 0f32
                && s1.h()? == 0f64
                && s2.a()? == 1
                && s2.b()?
                && s2.c()? == SimpleEnum::ValueC
                && s2.d()?.0 == b"second_octet_string"
                && s2.e()? == "second_char_string"
                && s2.f()? == SimpleBitmap::VALUE_B
                && s2.g()? == 0f32
                && s2.h()? == 0f64;
        }

        response.value(result)?.end()
    }

    fn handle_test_list_int_8_u_argument_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestListInt8UArgumentRequestRequest<'_>,
        response: BooleanResponseBuilder<P>,
    ) -> Result<P, Error> {
        let l = request.arg_1()?;

        let result = l.iter().count() == 9 && {
            let mut result = true;

            for (i, j) in l.iter().zip(1_u8..10) {
                result = result || i? == j;
            }

            result
        };

        response.value(result)?.end()
    }

    fn handle_test_nested_struct_list_argument_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestNestedStructListArgumentRequestRequest<'_>,
        response: BooleanResponseBuilder<P>,
    ) -> Result<P, Error> {
        let s = request.arg_1()?;

        let result = s.a()? == 0
            && s.b()?
            && {
                let ss = s.c()?;

                ss.a()? == 0
                    && ss.b()?
                    && ss.c()? == SimpleEnum::ValueB
                    && ss.d()?.0 == b"octet_string"
                    && ss.e()? == "char_string"
                    && ss.f()? == SimpleBitmap::VALUE_B
                    && ss.g()? == 0f32
                    && ss.h()? == 0f64
            }
            && {
                let l = s.d()?;

                l.iter().count() == 2 && {
                    let mut iter = l.iter();
                    let ls1 = unwrap!(iter.next())?;
                    let ls2 = unwrap!(iter.next())?;

                    ls1.a()? == 1
                        && ls1.b()?
                        && ls1.c()? == SimpleEnum::ValueC
                        && ls1.d()?.0 == b"nested_octet_string"
                        && ls1.e()? == "nested_char_string"
                        && ls1.f()? == SimpleBitmap::VALUE_B
                        && ls1.g()? == 0f32
                        && ls1.h()? == 0f64
                        && ls2.a()? == 2
                        && ls2.b()?
                        && ls2.c()? == SimpleEnum::ValueC
                        && ls2.d()?.0 == b"nested_octet_string"
                        && ls2.e()? == "nested_char_string"
                        && ls2.f()? == SimpleBitmap::VALUE_B
                        && ls2.g()? == 0f32
                        && ls2.h()? == 0f64
                }
            };

        response.value(result)?.end()
    }

    fn handle_test_list_nested_struct_list_argument_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestListNestedStructListArgumentRequestRequest<'_>,
        response: BooleanResponseBuilder<P>,
    ) -> Result<P, Error> {
        let l = request.arg_1()?;

        let result = l.iter().count() == 1 && {
            let s = unwrap!(l.iter().next())?;

            s.a()? == 0
                && s.b()?
                && {
                    let c = s.c()?;

                    c.a()? == 0
                        && c.b()?
                        && c.c()? == SimpleEnum::ValueB
                        && c.d()?.0 == b"octet_string"
                        && c.e()? == "char_string"
                        && c.f()? == SimpleBitmap::VALUE_B
                        && c.g()? == 0f32
                        && c.h()? == 0f64
                }
                && {
                    let d = s.d()?;

                    d.iter().count() == 2 && {
                        let mut iter = d.iter();
                        let ls1 = unwrap!(iter.next())?;
                        let ls2 = unwrap!(iter.next())?;

                        ls1.a()? == 1
                            && ls1.b()?
                            && ls1.c()? == SimpleEnum::ValueC
                            && ls1.d()?.0 == b"nested_octet_string"
                            && ls1.e()? == "nested_char_string"
                            && ls1.f()? == SimpleBitmap::VALUE_B
                            && ls1.g()? == 0f32
                            && ls1.h()? == 0f64
                            && ls2.a()? == 2
                            && ls2.b()?
                            && ls2.c()? == SimpleEnum::ValueC
                            && ls2.d()?.0 == b"nested_octet_string"
                            && ls2.e()? == "nested_char_string"
                            && ls2.f()? == SimpleBitmap::VALUE_B
                            && ls2.g()? == 0f32
                            && ls2.h()? == 0f64
                    }
                }
                && {
                    let e = s.e()?;

                    e.iter().count() == 2 && {
                        let mut result = true;

                        for (i, j) in e.iter().zip(1_u32..4) {
                            result = result || i? == j;
                        }

                        result
                    }
                }
                && {
                    let f = s.f()?;

                    f.iter().count() == 3 && {
                        let mut result = true;

                        for (i, j) in f.iter().zip(
                            [b"octet_string_1", b"octet_string_2", b"octet_string_3"].into_iter(),
                        ) {
                            result = result || i?.0 == j;
                        }

                        result
                    }
                }
                && {
                    let g = s.g()?;

                    g.iter().count() == 2 && {
                        let mut result = true;

                        for (i, j) in g.iter().zip([0u8, 255].into_iter()) {
                            result = result || i? == j;
                        }

                        result
                    }
                }
        };

        response.value(result)?.end()
    }

    fn handle_test_list_int_8_u_reverse_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestListInt8UReverseRequestRequest<'_>,
        response: TestListInt8UReverseResponseBuilder<P>,
    ) -> Result<P, Error> {
        // Iterating TLV containers backwards is not possible,
        // so for once here we'll on-stack allocate a temp buffer

        let l = request.arg_1()?;
        let mut tmp = heapless::Vec::<u8, 16>::new();
        for i in l.iter() {
            unwrap!(tmp.push(i?));
        }

        let mut lo = response.arg_1()?;
        for i in tmp.iter().rev() {
            lo = lo.push(i)?;
        }

        lo.end()?.end()
    }

    fn handle_test_enums_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestEnumsRequestRequest<'_>,
        response: TestEnumsResponseBuilder<P>,
    ) -> Result<P, Error> {
        response
            .arg_1(request.arg_1()?)?
            .arg_2(request.arg_2()?)?
            .end()
    }

    fn handle_test_nullable_optional_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestNullableOptionalRequestRequest<'_>,
        response: TestNullableOptionalResponseBuilder<P>,
    ) -> Result<P, Error> {
        response
            .was_present(request.arg_1()?.is_some())?
            .was_null(request.arg_1()?.as_ref().map(Nullable::is_none))?
            .value(request.arg_1()?.and_then(|value| value.into_option()))?
            .original_value(request.arg_1()?)?
            .end()
    }

    fn handle_test_complex_nullable_optional_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestComplexNullableOptionalRequestRequest<'_>,
        response: TestComplexNullableOptionalResponseBuilder<P>,
    ) -> Result<P, Error> {
        response
            .nullable_int_was_null(request.nullable_int()?.is_none())?
            .nullable_int_value(request.nullable_int()?.into_option())?
            .optional_int_was_present(request.optional_int()?.is_some())?
            .optional_int_value(request.optional_int()?)?
            .nullable_optional_int_was_present(request.nullable_optional_int()?.is_some())?
            .nullable_optional_int_was_null(
                request
                    .nullable_optional_int()?
                    .as_ref()
                    .map(Nullable::is_none),
            )?
            .nullable_optional_int_value(
                request
                    .nullable_optional_int()?
                    .and_then(Nullable::into_option),
            )?
            .nullable_string_was_null(request.nullable_string()?.is_none())?
            .nullable_string_value(request.nullable_string()?.into_option())?
            .optional_string_was_present(request.optional_string()?.is_some())?
            .optional_string_value(request.optional_string()?)?
            .nullable_optional_string_was_present(request.nullable_optional_string()?.is_some())?
            .nullable_optional_string_was_null(
                request
                    .nullable_optional_string()?
                    .as_ref()
                    .map(Nullable::is_none),
            )?
            .nullable_optional_string_value(
                request
                    .nullable_optional_string()?
                    .and_then(Nullable::into_option),
            )?
            .nullable_struct_was_null(request.nullable_struct()?.is_none())?
            .nullable_struct_value()?
            .with_some(request.nullable_struct()?.into_option(), |i, o| {
                o.a(i.a()?)?
                    .b(i.b()?)?
                    .c(i.c()?)?
                    .d(i.d()?)?
                    .e(i.e()?)?
                    .f(i.f()?)?
                    .g(i.g()?)?
                    .h(i.h()?)?
                    .end()
            })?
            .optional_struct_was_present(request.optional_struct()?.is_some())?
            .optional_struct_value()?
            .with_some(request.optional_struct()?, |i, o| {
                o.a(i.a()?)?
                    .b(i.b()?)?
                    .c(i.c()?)?
                    .d(i.d()?)?
                    .e(i.e()?)?
                    .f(i.f()?)?
                    .g(i.g()?)?
                    .h(i.h()?)?
                    .end()
            })?
            .nullable_optional_struct_was_present(request.nullable_optional_struct()?.is_some())?
            .nullable_optional_struct_was_null(
                request
                    .nullable_optional_struct()?
                    .as_ref()
                    .map(Nullable::is_none),
            )?
            .nullable_optional_struct_value()?
            .with_some(
                request
                    .nullable_optional_struct()?
                    .and_then(Nullable::into_option),
                |i, o| {
                    o.a(i.a()?)?
                        .b(i.b()?)?
                        .c(i.c()?)?
                        .d(i.d()?)?
                        .e(i.e()?)?
                        .f(i.f()?)?
                        .g(i.g()?)?
                        .h(i.h()?)?
                        .end()
                },
            )?
            .nullable_list_was_null(request.nullable_list()?.is_none())?
            .nullable_list_value()?
            .with_some(request.nullable_list()?.as_opt_ref(), |i, mut o| {
                for i in i.iter() {
                    o = o.push(&i?)?;
                }

                o.end()
            })?
            .optional_list_was_present(request.optional_list()?.is_some())?
            .optional_list_value()?
            .with_some(request.optional_list()?, |i, mut o| {
                for i in i.iter() {
                    o = o.push(&i?)?;
                }

                o.end()
            })?
            .nullable_optional_list_was_present(request.nullable_optional_list()?.is_some())?
            .nullable_optional_list_was_null(
                request
                    .nullable_optional_list()?
                    .as_ref()
                    .map(Nullable::is_none),
            )?
            .nullable_optional_list_value()?
            .with_some(
                request
                    .nullable_optional_list()?
                    .and_then(Nullable::into_option),
                |i, mut o| {
                    for i in i.iter() {
                        o = o.push(&i?)?;
                    }

                    o.end()
                },
            )?
            .end()
    }

    fn handle_simple_struct_echo_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: SimpleStructEchoRequestRequest<'_>,
        response: SimpleStructResponseBuilder<P>,
    ) -> Result<P, Error> {
        let s = request.arg_1()?;

        response
            .arg_1()?
            .a(s.a()?)?
            .b(s.b()?)?
            .c(s.c()?)?
            .d(s.d()?)?
            .e(s.e()?)?
            .f(s.f()?)?
            .g(s.g()?)?
            .h(s.h()?)?
            .end()?
            .end()
    }

    fn handle_timed_invoke_request(&self, _ctx: &InvokeContext<'_>) -> Result<(), Error> {
        todo!()
    }

    fn handle_test_simple_optional_argument_request(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestSimpleOptionalArgumentRequestRequest<'_>,
    ) -> Result<(), Error> {
        if request.arg_1()?.is_some() {
            Ok(())
        } else {
            Err(ErrorCode::InvalidAction.into()) // TODO: constraint error
        }
    }

    fn handle_test_emit_test_event_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        _request: TestEmitTestEventRequestRequest<'_>,
        _response: TestEmitTestEventResponseBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn handle_test_emit_test_fabric_scoped_event_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        _request: TestEmitTestFabricScopedEventRequestRequest<'_>,
        _response: TestEmitTestFabricScopedEventResponseBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn handle_test_batch_helper_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestBatchHelperRequestRequest<'_>,
        response: TestBatchHelperResponseBuilder<P>,
    ) -> Result<P, Error> {
        // Demonstrates how to skip the builder framework and write raw, unchecked TLV
        let byte = request.fill_character()?;
        let len = request.size_of_response_buffer()? as _;

        let mut parent = response.unchecked_into_parent();

        let writer = parent.writer();

        writer.stri(
            &TLVTag::Context(TestBatchHelperResponseTag::Buffer as _),
            len,
            core::iter::repeat_n(byte, len),
        )?;
        writer.end_container()?; // TestBatchHelperResponse struct

        Ok(parent)
    }

    fn handle_test_second_batch_helper_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestSecondBatchHelperRequestRequest<'_>,
        response: TestBatchHelperResponseBuilder<P>,
    ) -> Result<P, Error> {
        // Demonstrates how to skip the builder framework and write raw, unchecked TLV
        let byte = request.fill_character()?;
        let len = request.size_of_response_buffer()? as _;

        let mut parent = response.unchecked_into_parent();

        let writer = parent.writer();

        writer.stri(
            &TLVTag::Context(TestBatchHelperResponseTag::Buffer as _),
            len,
            core::iter::repeat_n(byte, len),
        )?;
        writer.end_container()?; // TestBatchHelperResponse struct

        Ok(parent)
    }
}
