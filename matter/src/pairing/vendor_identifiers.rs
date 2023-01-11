#[repr(u16)]
pub enum VendorId {
    CommonOrUnspecified = 0x0000,
    Apple = 0x1349,
    Google = 0x6006,
    TestVendor1 = 0xFFF1,
    TestVendor2 = 0xFFF2,
    TestVendor3 = 0xFFF3,
    TestVendor4 = 0xFFF4,
    NotSpecified = 0xFFFF,
}

pub fn is_vendor_id_valid_operationally(vendor_id: u16) -> bool {
    (vendor_id != VendorId::CommonOrUnspecified as u16)
        && (vendor_id <= VendorId::TestVendor4 as u16)
}
