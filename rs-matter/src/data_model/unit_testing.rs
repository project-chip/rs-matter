use rs_matter_macros::idl_import;

use crate::data_model::objects::{
    ArrayAttributeRead, ArrayAttributeWrite, InvokeContext, ReadContext, WriteContext,
};
use crate::error::Error;
use crate::tlv::{
    Nullable, NullableBuilder, OctetStr, OctetsArrayBuilder, OctetsBuilder, TLVArray,
    TLVBuilderParent, ToTLVArrayBuilder, ToTLVBuilder, Utf8Str, Utf8StrBuilder,
};

use super::objects::Dataver;

idl_import!(clusters = ["UnitTesting"]);

pub struct UnitTestingCluster {
    dataver: Dataver,
}

impl UnitTestingHandler for UnitTestingCluster {
    fn dataver(&self) -> u32 {
        todo!()
    }

    fn dataver_changed(&self) {
        todo!()
    }

    fn boolean(&self, _ctx: &ReadContext<'_>) -> Result<bool, Error> {
        todo!()
    }

    fn bitmap_8(&self, _ctx: &ReadContext<'_>) -> Result<Bitmap8MaskMap, Error> {
        todo!()
    }

    fn bitmap_16(&self, _ctx: &ReadContext<'_>) -> Result<Bitmap16MaskMap, Error> {
        todo!()
    }

    fn bitmap_32(&self, _ctx: &ReadContext<'_>) -> Result<Bitmap32MaskMap, Error> {
        todo!()
    }

    fn bitmap_64(&self, _ctx: &ReadContext<'_>) -> Result<Bitmap64MaskMap, Error> {
        todo!()
    }

    fn int_8_u(&self, _ctx: &ReadContext<'_>) -> Result<u8, Error> {
        todo!()
    }

    fn int_16_u(&self, _ctx: &ReadContext<'_>) -> Result<u16, Error> {
        todo!()
    }

    fn int_24_u(&self, _ctx: &ReadContext<'_>) -> Result<u32, Error> {
        todo!()
    }

    fn int_32_u(&self, _ctx: &ReadContext<'_>) -> Result<u32, Error> {
        todo!()
    }

    fn int_40_u(&self, _ctx: &ReadContext<'_>) -> Result<u64, Error> {
        todo!()
    }

    fn int_48_u(&self, _ctx: &ReadContext<'_>) -> Result<u64, Error> {
        todo!()
    }

    fn int_56_u(&self, _ctx: &ReadContext<'_>) -> Result<u64, Error> {
        todo!()
    }

    fn int_64_u(&self, _ctx: &ReadContext<'_>) -> Result<u64, Error> {
        todo!()
    }

    fn int_8_s(&self, _ctx: &ReadContext<'_>) -> Result<i8, Error> {
        todo!()
    }

    fn int_16_s(&self, _ctx: &ReadContext<'_>) -> Result<i16, Error> {
        todo!()
    }

    fn int_24_s(&self, _ctx: &ReadContext<'_>) -> Result<i32, Error> {
        todo!()
    }

    fn int_32_s(&self, _ctx: &ReadContext<'_>) -> Result<i32, Error> {
        todo!()
    }

    fn int_40_s(&self, _ctx: &ReadContext<'_>) -> Result<i64, Error> {
        todo!()
    }

    fn int_48_s(&self, _ctx: &ReadContext<'_>) -> Result<i64, Error> {
        todo!()
    }

    fn int_56_s(&self, _ctx: &ReadContext<'_>) -> Result<i64, Error> {
        todo!()
    }

    fn int_64_s(&self, _ctx: &ReadContext<'_>) -> Result<i64, Error> {
        todo!()
    }

    fn enum_8(&self, _ctx: &ReadContext<'_>) -> Result<u8, Error> {
        todo!()
    }

    fn enum_16(&self, _ctx: &ReadContext<'_>) -> Result<u16, Error> {
        todo!()
    }

    fn float_single(&self, _ctx: &ReadContext<'_>) -> Result<f32, Error> {
        todo!()
    }

    fn float_double(&self, _ctx: &ReadContext<'_>) -> Result<f64, Error> {
        todo!()
    }

    fn octet_string<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: OctetsBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn list_int_8_u<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: ArrayAttributeRead<ToTLVArrayBuilder<P, u8>, ToTLVBuilder<P, u8>>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn list_octet_string<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: ArrayAttributeRead<OctetsArrayBuilder<P>, OctetsBuilder<P>>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn list_struct_octet_string<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: ArrayAttributeRead<
            TestListStructOctetArrayBuilder<P>,
            TestListStructOctetBuilder<P>,
        >,
    ) -> Result<P, Error> {
        todo!()
    }

    fn long_octet_string<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: OctetsBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn char_string<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn long_char_string<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn epoch_us(&self, _ctx: &ReadContext<'_>) -> Result<u64, Error> {
        todo!()
    }

    fn epoch_s(&self, _ctx: &ReadContext<'_>) -> Result<u32, Error> {
        todo!()
    }

    fn vendor_id(&self, _ctx: &ReadContext<'_>) -> Result<u16, Error> {
        todo!()
    }

    fn list_nullables_and_optionals_struct<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: ArrayAttributeRead<
            NullablesAndOptionalsStructArrayBuilder<P>,
            NullablesAndOptionalsStructBuilder<P>,
        >,
    ) -> Result<P, Error> {
        todo!()
    }

    fn enum_attr(&self, _ctx: &ReadContext<'_>) -> Result<SimpleEnum, Error> {
        todo!()
    }

    fn struct_attr<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: SimpleStructBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn range_restricted_int_8_u(&self, _ctx: &ReadContext<'_>) -> Result<u8, Error> {
        todo!()
    }

    fn range_restricted_int_8_s(&self, _ctx: &ReadContext<'_>) -> Result<i8, Error> {
        todo!()
    }

    fn range_restricted_int_16_u(&self, _ctx: &ReadContext<'_>) -> Result<u16, Error> {
        todo!()
    }

    fn range_restricted_int_16_s(&self, _ctx: &ReadContext<'_>) -> Result<i16, Error> {
        todo!()
    }

    fn list_long_octet_string<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: ArrayAttributeRead<OctetsArrayBuilder<P>, OctetsBuilder<P>>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn list_fabric_scoped<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: ArrayAttributeRead<TestFabricScopedArrayBuilder<P>, TestFabricScopedBuilder<P>>,
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
        todo!()
    }

    fn nullable_bitmap_8(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<Bitmap8MaskMap>, Error> {
        todo!()
    }

    fn nullable_bitmap_16(
        &self,
        _ctx: &ReadContext<'_>,
    ) -> Result<Nullable<Bitmap16MaskMap>, Error> {
        todo!()
    }

    fn nullable_bitmap_32(
        &self,
        _ctx: &ReadContext<'_>,
    ) -> Result<Nullable<Bitmap32MaskMap>, Error> {
        todo!()
    }

    fn nullable_bitmap_64(
        &self,
        _ctx: &ReadContext<'_>,
    ) -> Result<Nullable<Bitmap64MaskMap>, Error> {
        todo!()
    }

    fn nullable_int_8_u(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<u8>, Error> {
        todo!()
    }

    fn nullable_int_16_u(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<u16>, Error> {
        todo!()
    }

    fn nullable_int_24_u(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<u32>, Error> {
        todo!()
    }

    fn nullable_int_32_u(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<u32>, Error> {
        todo!()
    }

    fn nullable_int_40_u(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<u64>, Error> {
        todo!()
    }

    fn nullable_int_48_u(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<u64>, Error> {
        todo!()
    }

    fn nullable_int_56_u(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<u64>, Error> {
        todo!()
    }

    fn nullable_int_64_u(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<u64>, Error> {
        todo!()
    }

    fn nullable_int_8_s(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<i8>, Error> {
        todo!()
    }

    fn nullable_int_16_s(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<i16>, Error> {
        todo!()
    }

    fn nullable_int_24_s(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<i32>, Error> {
        todo!()
    }

    fn nullable_int_32_s(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<i32>, Error> {
        todo!()
    }

    fn nullable_int_40_s(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<i64>, Error> {
        todo!()
    }

    fn nullable_int_48_s(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<i64>, Error> {
        todo!()
    }

    fn nullable_int_56_s(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<i64>, Error> {
        todo!()
    }

    fn nullable_int_64_s(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<i64>, Error> {
        todo!()
    }

    fn nullable_enum_8(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<u8>, Error> {
        todo!()
    }

    fn nullable_enum_16(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<u16>, Error> {
        todo!()
    }

    fn nullable_float_single(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<f32>, Error> {
        todo!()
    }

    fn nullable_float_double(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<f64>, Error> {
        todo!()
    }

    fn nullable_octet_string<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: NullableBuilder<P, OctetsBuilder<P>>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn nullable_char_string<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: NullableBuilder<P, Utf8StrBuilder<P>>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn nullable_enum_attr(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<SimpleEnum>, Error> {
        todo!()
    }

    fn nullable_struct<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: NullableBuilder<P, SimpleStructBuilder<P>>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn nullable_range_restricted_int_8_u(
        &self,
        _ctx: &ReadContext<'_>,
    ) -> Result<Nullable<u8>, Error> {
        todo!()
    }

    fn nullable_range_restricted_int_8_s(
        &self,
        _ctx: &ReadContext<'_>,
    ) -> Result<Nullable<i8>, Error> {
        todo!()
    }

    fn nullable_range_restricted_int_16_u(
        &self,
        _ctx: &ReadContext<'_>,
    ) -> Result<Nullable<u16>, Error> {
        todo!()
    }

    fn nullable_range_restricted_int_16_s(
        &self,
        _ctx: &ReadContext<'_>,
    ) -> Result<Nullable<i16>, Error> {
        todo!()
    }

    fn set_boolean(&self, _ctx: &WriteContext<'_>, value: bool) -> Result<(), Error> {
        todo!()
    }

    fn set_bitmap_8(&self, _ctx: &WriteContext<'_>, value: Bitmap8MaskMap) -> Result<(), Error> {
        todo!()
    }

    fn set_bitmap_16(&self, _ctx: &WriteContext<'_>, value: Bitmap16MaskMap) -> Result<(), Error> {
        todo!()
    }

    fn set_bitmap_32(&self, _ctx: &WriteContext<'_>, value: Bitmap32MaskMap) -> Result<(), Error> {
        todo!()
    }

    fn set_bitmap_64(&self, _ctx: &WriteContext<'_>, value: Bitmap64MaskMap) -> Result<(), Error> {
        todo!()
    }

    fn set_int_8_u(&self, _ctx: &WriteContext<'_>, value: u8) -> Result<(), Error> {
        todo!()
    }

    fn set_int_16_u(&self, _ctx: &WriteContext<'_>, value: u16) -> Result<(), Error> {
        todo!()
    }

    fn set_int_24_u(&self, _ctx: &WriteContext<'_>, value: u32) -> Result<(), Error> {
        todo!()
    }

    fn set_int_32_u(&self, _ctx: &WriteContext<'_>, value: u32) -> Result<(), Error> {
        todo!()
    }

    fn set_int_40_u(&self, _ctx: &WriteContext<'_>, value: u64) -> Result<(), Error> {
        todo!()
    }

    fn set_int_48_u(&self, _ctx: &WriteContext<'_>, value: u64) -> Result<(), Error> {
        todo!()
    }

    fn set_int_56_u(&self, _ctx: &WriteContext<'_>, value: u64) -> Result<(), Error> {
        todo!()
    }

    fn set_int_64_u(&self, _ctx: &WriteContext<'_>, value: u64) -> Result<(), Error> {
        todo!()
    }

    fn set_int_8_s(&self, _ctx: &WriteContext<'_>, value: i8) -> Result<(), Error> {
        todo!()
    }

    fn set_int_16_s(&self, _ctx: &WriteContext<'_>, value: i16) -> Result<(), Error> {
        todo!()
    }

    fn set_int_24_s(&self, _ctx: &WriteContext<'_>, value: i32) -> Result<(), Error> {
        todo!()
    }

    fn set_int_32_s(&self, _ctx: &WriteContext<'_>, value: i32) -> Result<(), Error> {
        todo!()
    }

    fn set_int_40_s(&self, _ctx: &WriteContext<'_>, value: i64) -> Result<(), Error> {
        todo!()
    }

    fn set_int_48_s(&self, _ctx: &WriteContext<'_>, value: i64) -> Result<(), Error> {
        todo!()
    }

    fn set_int_56_s(&self, _ctx: &WriteContext<'_>, value: i64) -> Result<(), Error> {
        todo!()
    }

    fn set_int_64_s(&self, _ctx: &WriteContext<'_>, value: i64) -> Result<(), Error> {
        todo!()
    }

    fn set_enum_8(&self, _ctx: &WriteContext<'_>, value: u8) -> Result<(), Error> {
        todo!()
    }

    fn set_enum_16(&self, _ctx: &WriteContext<'_>, value: u16) -> Result<(), Error> {
        todo!()
    }

    fn set_float_single(&self, _ctx: &WriteContext<'_>, value: f32) -> Result<(), Error> {
        todo!()
    }

    fn set_float_double(&self, _ctx: &WriteContext<'_>, value: f64) -> Result<(), Error> {
        todo!()
    }

    fn set_octet_string(&self, _ctx: &WriteContext<'_>, value: OctetStr<'_>) -> Result<(), Error> {
        todo!()
    }

    fn set_list_int_8_u(
        &self,
        _ctx: &WriteContext<'_>,
        value: ArrayAttributeWrite<TLVArray<'_, u8>, u8>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_list_octet_string(
        &self,
        _ctx: &WriteContext<'_>,
        value: ArrayAttributeWrite<TLVArray<'_, OctetStr<'_>>, OctetStr<'_>>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_list_struct_octet_string(
        &self,
        _ctx: &WriteContext<'_>,
        value: ArrayAttributeWrite<TLVArray<'_, TestListStructOctet<'_>>, TestListStructOctet<'_>>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_long_octet_string(
        &self,
        _ctx: &WriteContext<'_>,
        value: OctetStr<'_>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_char_string(&self, _ctx: &WriteContext<'_>, value: Utf8Str<'_>) -> Result<(), Error> {
        todo!()
    }

    fn set_long_char_string(
        &self,
        _ctx: &WriteContext<'_>,
        value: Utf8Str<'_>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_epoch_us(&self, _ctx: &WriteContext<'_>, value: u64) -> Result<(), Error> {
        todo!()
    }

    fn set_epoch_s(&self, _ctx: &WriteContext<'_>, value: u32) -> Result<(), Error> {
        todo!()
    }

    fn set_vendor_id(&self, _ctx: &WriteContext<'_>, value: u16) -> Result<(), Error> {
        todo!()
    }

    fn set_list_nullables_and_optionals_struct(
        &self,
        _ctx: &WriteContext<'_>,
        value: ArrayAttributeWrite<
            TLVArray<'_, NullablesAndOptionalsStruct<'_>>,
            NullablesAndOptionalsStruct<'_>,
        >,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_enum_attr(&self, _ctx: &WriteContext<'_>, value: SimpleEnum) -> Result<(), Error> {
        todo!()
    }

    fn set_struct_attr(
        &self,
        _ctx: &WriteContext<'_>,
        value: SimpleStruct<'_>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_range_restricted_int_8_u(
        &self,
        _ctx: &WriteContext<'_>,
        value: u8,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_range_restricted_int_8_s(
        &self,
        _ctx: &WriteContext<'_>,
        value: i8,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_range_restricted_int_16_u(
        &self,
        _ctx: &WriteContext<'_>,
        value: u16,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_range_restricted_int_16_s(
        &self,
        _ctx: &WriteContext<'_>,
        value: i16,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_list_long_octet_string(
        &self,
        _ctx: &WriteContext<'_>,
        value: ArrayAttributeWrite<TLVArray<'_, OctetStr<'_>>, OctetStr<'_>>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_list_fabric_scoped(
        &self,
        _ctx: &WriteContext<'_>,
        value: ArrayAttributeWrite<TLVArray<'_, TestFabricScoped<'_>>, TestFabricScoped<'_>>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_timed_write_boolean(&self, _ctx: &WriteContext<'_>, value: bool) -> Result<(), Error> {
        todo!()
    }

    fn set_general_error_boolean(&self, _ctx: &WriteContext<'_>, value: bool) -> Result<(), Error> {
        todo!()
    }

    fn set_cluster_error_boolean(&self, _ctx: &WriteContext<'_>, value: bool) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_boolean(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<bool>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_bitmap_8(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<Bitmap8MaskMap>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_bitmap_16(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<Bitmap16MaskMap>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_bitmap_32(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<Bitmap32MaskMap>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_bitmap_64(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<Bitmap64MaskMap>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_int_8_u(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<u8>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_int_16_u(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<u16>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_int_24_u(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<u32>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_int_32_u(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<u32>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_int_40_u(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<u64>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_int_48_u(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<u64>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_int_56_u(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<u64>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_int_64_u(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<u64>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_int_8_s(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<i8>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_int_16_s(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<i16>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_int_24_s(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<i32>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_int_32_s(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<i32>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_int_40_s(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<i64>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_int_48_s(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<i64>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_int_56_s(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<i64>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_int_64_s(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<i64>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_enum_8(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<u8>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_enum_16(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<u16>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_float_single(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<f32>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_float_double(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<f64>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_octet_string(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<OctetStr<'_>>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_char_string(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<Utf8Str<'_>>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_enum_attr(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<SimpleEnum>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_struct(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<SimpleStruct<'_>>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_range_restricted_int_8_u(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<u8>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_range_restricted_int_8_s(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<i8>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_range_restricted_int_16_u(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<u16>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn set_nullable_range_restricted_int_16_s(
        &self,
        _ctx: &WriteContext<'_>,
        value: Nullable<i16>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn handle_test(&self, _ctx: &InvokeContext<'_>) -> Result<(), Error> {
        todo!()
    }

    fn handle_test_not_handled(&self, _ctx: &InvokeContext<'_>) -> Result<(), Error> {
        todo!()
    }

    fn handle_test_specific<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        response: TestSpecificResponseBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
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
        todo!()
    }

    fn handle_test_simple_argument_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestSimpleArgumentRequestRequest<'_>,
        response: TestSimpleArgumentResponseBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn handle_test_struct_array_argument_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestStructArrayArgumentRequestRequest<'_>,
        response: TestStructArrayArgumentResponseBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn handle_test_struct_argument_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestStructArgumentRequestRequest<'_>,
        response: BooleanResponseBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn handle_test_nested_struct_argument_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestNestedStructArgumentRequestRequest<'_>,
        response: BooleanResponseBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn handle_test_list_struct_argument_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestListStructArgumentRequestRequest<'_>,
        response: BooleanResponseBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn handle_test_list_int_8_u_argument_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestListInt8UArgumentRequestRequest<'_>,
        response: BooleanResponseBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn handle_test_nested_struct_list_argument_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestNestedStructListArgumentRequestRequest<'_>,
        response: BooleanResponseBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn handle_test_list_nested_struct_list_argument_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestListNestedStructListArgumentRequestRequest<'_>,
        response: BooleanResponseBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn handle_test_list_int_8_u_reverse_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestListInt8UReverseRequestRequest<'_>,
        response: TestListInt8UReverseResponseBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn handle_test_enums_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestEnumsRequestRequest<'_>,
        response: TestEnumsResponseBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn handle_test_nullable_optional_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestNullableOptionalRequestRequest<'_>,
        response: TestNullableOptionalResponseBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn handle_test_complex_nullable_optional_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestComplexNullableOptionalRequestRequest<'_>,
        response: TestComplexNullableOptionalResponseBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn handle_simple_struct_echo_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: SimpleStructEchoRequestRequest<'_>,
        response: SimpleStructResponseBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn handle_timed_invoke_request(&self, _ctx: &InvokeContext<'_>) -> Result<(), Error> {
        todo!()
    }

    fn handle_test_simple_optional_argument_request(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestSimpleOptionalArgumentRequestRequest<'_>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn handle_test_emit_test_event_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestEmitTestEventRequestRequest<'_>,
        response: TestEmitTestEventResponseBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn handle_test_emit_test_fabric_scoped_event_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestEmitTestFabricScopedEventRequestRequest<'_>,
        response: TestEmitTestFabricScopedEventResponseBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn handle_test_batch_helper_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestBatchHelperRequestRequest<'_>,
        response: TestBatchHelperResponseBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn handle_test_second_batch_helper_request<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestSecondBatchHelperRequestRequest<'_>,
        response: TestBatchHelperResponseBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
    }
}
