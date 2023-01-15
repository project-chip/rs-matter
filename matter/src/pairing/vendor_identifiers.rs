#[repr(u16)]
pub enum VendorId {
    CommonOrUnspecified = 0x0000,
    TestVendor4 = 0xFFF4,
}

pub fn is_vendor_id_valid_operationally(vendor_id: u16) -> bool {
    (vendor_id != VendorId::CommonOrUnspecified as u16)
        && (vendor_id <= VendorId::TestVendor4 as u16)
}
