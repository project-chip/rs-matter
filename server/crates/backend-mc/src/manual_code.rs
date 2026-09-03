//! 11-digit manual pairing code construction (Matter Core Spec §5.1.4) for
//! `commission_on_network` with a long-discriminator filter (WIRE_PROTOCOL.md §9's `filter_type`
//! 2): HA hands us `(setup_pin_code, discriminator)` separately, but `MatterController::commission`
//! only accepts a QR/manual code *string*, so this backend has to build one.
//!
//! Delegates the actual packing (including the Verhoeff check digit) to
//! `matter_commissioning::setup::encode_manual_code` rather than re-deriving it: that is the same
//! function `matter-controller`'s own `Node::open_commissioning_window` uses to hand a manual code
//! back to HA (`admin.rs::onboarding_payload`), so a device commissioned via one path and a window
//! opened via the other describe codes in byte-identical format -- reimplementing Verhoeff
//! ourselves would risk a subtle mismatch for zero benefit.

use matter_commissioning::{
    encode_manual_code, CommissioningFlow, DiscoveryCapabilities, Discriminator, Passcode,
    SetupPayload,
};
use ws_protocol::ServerError;

/// Build the 11-digit manual pairing code for `pin` (the 27-bit setup passcode) and
/// `long_discriminator` (the full 12-bit discriminator). `vendor_id` is accepted for symmetry with
/// a QR-code helper this backend does not need (a manual code never carries VID/PID -- Matter Core
/// Spec §5.1.4 -- so it does not affect the output).
pub fn manual_code(
    pin: u32,
    long_discriminator: u16,
    vendor_id: Option<u16>,
) -> Result<String, ServerError> {
    let _ = vendor_id; // documented above: manual codes carry no VID/PID field to set.
    let discriminator = Discriminator::new(long_discriminator)
        .map_err(|e| ServerError::invalid_arguments(format!("bad discriminator: {e}")))?;
    let passcode = Passcode::new(pin)
        .map_err(|e| ServerError::invalid_arguments(format!("bad setup_pin_code: {e}")))?;
    let payload = SetupPayload {
        version: 0,
        vendor_id: None,
        product_id: None,
        commissioning_flow: CommissioningFlow::Standard,
        discovery_capabilities: DiscoveryCapabilities::empty(),
        discriminator,
        passcode,
    };
    Ok(encode_manual_code(&payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact vector PLAN.md T4 and WIRE_PROTOCOL.md §10 both cite.
    #[test]
    fn matches_wire_protocol_vector() {
        assert_eq!(manual_code(20_202_021, 3840, None).unwrap(), "34970112332");
    }

    #[test]
    fn vendor_id_is_accepted_but_does_not_change_the_code() {
        assert_eq!(
            manual_code(20_202_021, 3840, Some(0xFFF1)).unwrap(),
            manual_code(20_202_021, 3840, None).unwrap()
        );
    }

    #[test]
    fn out_of_range_discriminator_is_invalid_arguments() {
        let err = manual_code(20_202_021, 0x1000, None).unwrap_err();
        assert_eq!(u16::from(err.code), 8);
    }

    #[test]
    fn disallowed_trivial_passcode_is_invalid_arguments() {
        // 0 is spec-disallowed (Matter Core Spec §5.1.7.1's trivial-value list).
        let err = manual_code(0, 3840, None).unwrap_err();
        assert_eq!(u16::from(err.code), 8);
    }
}
