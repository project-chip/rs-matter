/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

//! A Wi-Fi network controller over the Native Wifi API of Windows (`wlanapi`).
//!
//! It connects with temporary profiles, so it leaves no profiles in the system.
//!
//! Since Windows 11 24H2, scanning and the details of the current connection
//! need the user to let desktop apps access the location.

use core::fmt::Write;

use crate::dm::clusters::net_comm::WiFiSecurityBitmap;

#[cfg(windows)]
pub use ctl::Win32WifiCtl;

#[cfg(windows)]
mod ctl;

/// The ID of the RSN information element.
const IE_RSN: u8 = 48;
/// The ID of a vendor-specific information element, of which one is WPA.
const IE_VENDOR: u8 = 221;
/// The OUI and type of the WPA information element.
const WPA_OUI_TYPE: [u8; 4] = [0x00, 0x50, 0xf2, 0x01];

/// The AKM suites of WPA-Personal, WPA2-Personal and WPA3-Personal.
const AKM_WPA_PSK: [u8; 4] = [0x00, 0x50, 0xf2, 0x02];
const AKM_PSK: [u8; 4] = [0x00, 0x0f, 0xac, 0x02];
const AKM_PSK_SHA256: [u8; 4] = [0x00, 0x0f, 0xac, 0x06];
const AKM_SAE: [u8; 4] = [0x00, 0x0f, 0xac, 0x08];
const AKM_SAE_EXT_KEY: [u8; 4] = [0x00, 0x0f, 0xac, 0x18];

/// The authentication of a network, as a WLAN profile has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum Auth {
    Open,
    WpaPsk,
    Wpa2Psk,
    Wpa3Sae,
}

impl Auth {
    /// The `authentication` and `encryption` values of the profile.
    const fn profile(&self) -> (&'static str, &'static str) {
        match self {
            Self::Open => ("open", "none"),
            Self::WpaPsk => ("WPAPSK", "TKIP"),
            Self::Wpa2Psk => ("WPA2PSK", "AES"),
            Self::Wpa3Sae => ("WPA3SAE", "AES"),
        }
    }
}

/// The XML of a WLAN profile for network `ssid` with key `pass`.
///
/// Return `None` if the key is not text that XML can carry.
fn profile_xml(ssid: &[u8], pass: &[u8], auth: Auth) -> Option<String> {
    let pass = core::str::from_utf8(pass).ok()?;
    if pass.chars().any(char::is_control) {
        return None;
    }

    let (authentication, encryption) = auth.profile();

    let mut xml = String::new();

    xml.push_str("<?xml version=\"1.0\"?>");
    xml.push_str("<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">");

    xml.push_str("<name>");
    match core::str::from_utf8(ssid) {
        Ok(name) if !name.is_empty() && !name.chars().any(char::is_control) => {
            push_escaped(&mut xml, name)
        }
        _ => push_hex(&mut xml, ssid),
    }
    xml.push_str("</name>");

    xml.push_str("<SSIDConfig><SSID><hex>");
    push_hex(&mut xml, ssid);
    xml.push_str("</hex></SSID></SSIDConfig>");

    xml.push_str("<connectionType>ESS</connectionType>");
    xml.push_str("<connectionMode>manual</connectionMode>");

    xml.push_str("<MSM><security><authEncryption>");
    write!(
        xml,
        "<authentication>{authentication}</authentication><encryption>{encryption}</encryption>"
    )
    .ok()?;
    xml.push_str("<useOneX>false</useOneX></authEncryption>");

    if auth != Auth::Open {
        // A raw PSK is 64 hex digits; anything else is a passphrase
        let key_type = if is_raw_psk(pass) {
            "networkKey"
        } else {
            "passPhrase"
        };

        write!(
            xml,
            "<sharedKey><keyType>{key_type}</keyType><protected>false</protected><keyMaterial>"
        )
        .ok()?;
        push_escaped(&mut xml, pass);
        xml.push_str("</keyMaterial></sharedKey>");
    }

    xml.push_str("</security></MSM></WLANProfile>");

    Some(xml)
}

/// Whether `pass` is a raw PSK rather than a passphrase.
fn is_raw_psk(pass: &str) -> bool {
    pass.len() == 64 && pass.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The personal security of a BSS, from the privacy bit of its capabilities
/// and its information elements.
///
/// A BSS with only enterprise or OWE key management gets an empty bitmap.
fn security(privacy: bool, ies: &[u8]) -> WiFiSecurityBitmap {
    let mut security = WiFiSecurityBitmap::empty();
    let mut rsn_or_wpa = false;

    let mut rest = ies;
    while let [id, len, tail @ ..] = rest {
        let Some((body, next)) = tail.split_at_checked(*len as usize) else {
            break;
        };

        if *id == IE_RSN {
            rsn_or_wpa = true;

            // After the version
            for akm in akm_suites(body.get(2..).unwrap_or(&[])) {
                match akm {
                    AKM_PSK | AKM_PSK_SHA256 => security |= WiFiSecurityBitmap::WPA_2_PERSONAL,
                    AKM_SAE | AKM_SAE_EXT_KEY => security |= WiFiSecurityBitmap::WPA_3_PERSONAL,
                    _ => (),
                }
            }
        } else if *id == IE_VENDOR && body.starts_with(&WPA_OUI_TYPE) {
            rsn_or_wpa = true;

            // After the OUI, the type and the version
            for akm in akm_suites(body.get(6..).unwrap_or(&[])) {
                if akm == AKM_WPA_PSK {
                    security |= WiFiSecurityBitmap::WPA_PERSONAL;
                }
            }
        }

        rest = next;
    }

    if !rsn_or_wpa {
        security = if privacy {
            WiFiSecurityBitmap::WEP
        } else {
            WiFiSecurityBitmap::UNENCRYPTED
        };
    }

    security
}

/// The AKM suites of an RSN or WPA element, from its group cipher suite on.
///
/// The list is empty if the element ends before it, as it then defaults to
/// 802.1X, which is not personal.
fn akm_suites(body: &[u8]) -> impl Iterator<Item = [u8; 4]> + '_ {
    fn count(body: &[u8]) -> Option<usize> {
        Some(u16::from_le_bytes([*body.first()?, *body.get(1)?]) as usize)
    }

    let suites = (|| {
        // The group cipher suite, then the pairwise cipher suites
        let rest = body.get(4..)?;
        let rest = rest.get(2 + count(rest)? * 4..)?;

        rest.get(2..2 + count(rest)? * 4)
    })()
    .unwrap_or(&[]);

    suites.as_chunks::<4>().0.iter().copied()
}

/// Append `text` with the characters that XML reserves escaped.
fn push_escaped(xml: &mut String, text: &str) {
    for c in text.chars() {
        match c {
            '&' => xml.push_str("&amp;"),
            '<' => xml.push_str("&lt;"),
            '>' => xml.push_str("&gt;"),
            '"' => xml.push_str("&quot;"),
            '\'' => xml.push_str("&apos;"),
            c => xml.push(c),
        }
    }
}

/// Append `bytes` in upper-case hex.
fn push_hex(xml: &mut String, bytes: &[u8]) {
    for b in bytes {
        let _ = write!(xml, "{b:02X}");
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// An RSN element with CCMP and the given AKM suites.
    fn rsn(akms: &[[u8; 4]]) -> Vec<u8> {
        let mut body = vec![0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00];
        body.extend_from_slice(&[0x00, 0x0f, 0xac, 0x04]);
        body.extend_from_slice(&(akms.len() as u16).to_le_bytes());
        for akm in akms {
            body.extend_from_slice(akm);
        }
        body.extend_from_slice(&[0x00, 0x00]);

        element(IE_RSN, &body)
    }

    fn element(id: u8, body: &[u8]) -> Vec<u8> {
        let mut ie = vec![id, body.len() as u8];
        ie.extend_from_slice(body);
        ie
    }

    #[test]
    fn security_without_rsn_or_wpa() {
        let ssid = element(0, b"net");

        assert_eq!(security(false, &ssid), WiFiSecurityBitmap::UNENCRYPTED);
        assert_eq!(security(true, &ssid), WiFiSecurityBitmap::WEP);
        assert_eq!(security(false, &[]), WiFiSecurityBitmap::UNENCRYPTED);
    }

    #[test]
    fn security_from_rsn() {
        let mut ies = element(0, b"net");
        ies.extend(rsn(&[AKM_PSK]));
        assert_eq!(security(true, &ies), WiFiSecurityBitmap::WPA_2_PERSONAL);

        assert_eq!(
            security(true, &rsn(&[AKM_SAE])),
            WiFiSecurityBitmap::WPA_3_PERSONAL
        );
        assert_eq!(
            security(true, &rsn(&[AKM_PSK, AKM_SAE])),
            WiFiSecurityBitmap::WPA_2_PERSONAL | WiFiSecurityBitmap::WPA_3_PERSONAL
        );
        assert_eq!(
            security(true, &rsn(&[AKM_PSK_SHA256, AKM_SAE_EXT_KEY])),
            WiFiSecurityBitmap::WPA_2_PERSONAL | WiFiSecurityBitmap::WPA_3_PERSONAL
        );

        // 802.1X only
        assert_eq!(
            security(true, &rsn(&[[0x00, 0x0f, 0xac, 0x01]])),
            WiFiSecurityBitmap::empty()
        );

        // Ends after the group cipher suite: 802.1X
        assert_eq!(
            security(
                true,
                &element(IE_RSN, &[0x01, 0x00, 0x00, 0x0f, 0xac, 0x04])
            ),
            WiFiSecurityBitmap::empty()
        );
    }

    #[test]
    fn security_from_wpa() {
        let mut body = WPA_OUI_TYPE.to_vec();
        body.extend_from_slice(&[0x01, 0x00, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x00]);
        body.extend_from_slice(&[0x00, 0x50, 0xf2, 0x02, 0x01, 0x00]);
        body.extend_from_slice(&AKM_WPA_PSK);

        let mut ies = element(IE_VENDOR, &body);
        assert_eq!(security(true, &ies), WiFiSecurityBitmap::WPA_PERSONAL);

        ies.extend(rsn(&[AKM_PSK]));
        assert_eq!(
            security(true, &ies),
            WiFiSecurityBitmap::WPA_PERSONAL | WiFiSecurityBitmap::WPA_2_PERSONAL
        );

        // Another vendor element is not WPA
        let other = element(IE_VENDOR, &[0x00, 0x50, 0xf2, 0x04, 0x10]);
        assert_eq!(security(true, &other), WiFiSecurityBitmap::WEP);
    }

    #[test]
    fn security_of_truncated_elements() {
        let mut ies = rsn(&[AKM_PSK, AKM_SAE]);

        // An AKM count larger than the element
        ies[14] = 5;
        assert_eq!(security(true, &ies), WiFiSecurityBitmap::empty());

        // An element longer than the data
        let ies = [IE_RSN, 20, 0x01, 0x00];
        assert_eq!(security(true, &ies), WiFiSecurityBitmap::WEP);
    }

    #[test]
    fn profile_with_passphrase() {
        let xml = profile_xml(b"Home <&> 'net'", b"pa\"ss&<word>", Auth::Wpa2Psk).unwrap();

        assert!(xml.contains("<name>Home &lt;&amp;&gt; &apos;net&apos;</name>"));
        assert!(xml.contains("<hex>486F6D65203C263E20276E657427</hex>"));
        assert!(xml.contains("<authentication>WPA2PSK</authentication>"));
        assert!(xml.contains("<encryption>AES</encryption>"));
        assert!(xml.contains("<keyType>passPhrase</keyType>"));
        assert!(xml.contains("<keyMaterial>pa&quot;ss&amp;&lt;word&gt;</keyMaterial>"));
    }

    #[test]
    fn profile_with_raw_psk() {
        let psk = [b'a'; 64];
        let xml = profile_xml(b"net", &psk, Auth::Wpa3Sae).unwrap();

        assert!(xml.contains("<authentication>WPA3SAE</authentication>"));
        assert!(xml.contains("<keyType>networkKey</keyType>"));

        // 64 characters which are not all hex digits are a passphrase
        let mut pass = psk;
        pass[0] = b'x';
        let xml = profile_xml(b"net", &pass, Auth::Wpa2Psk).unwrap();
        assert!(xml.contains("<keyType>passPhrase</keyType>"));
    }

    #[test]
    fn open_profile() {
        let xml = profile_xml(b"net", b"", Auth::Open).unwrap();

        assert!(xml.contains("<authentication>open</authentication>"));
        assert!(xml.contains("<encryption>none</encryption>"));
        assert!(!xml.contains("sharedKey"));
        assert!(xml.ends_with("</security></MSM></WLANProfile>"));
    }

    #[test]
    fn profile_of_binary_ssid() {
        let xml = profile_xml(&[0xff, 0x00, 0x41], b"password", Auth::WpaPsk).unwrap();

        assert!(xml.contains("<name>FF0041</name>"));
        assert!(xml.contains("<hex>FF0041</hex>"));
        assert!(xml.contains("<encryption>TKIP</encryption>"));
    }

    #[test]
    fn profile_of_unsupported_key() {
        assert!(profile_xml(b"net", &[0xff, 0xfe, 0x41], Auth::Wpa2Psk).is_none());
        assert!(profile_xml(b"net", b"pass\nword", Auth::Wpa2Psk).is_none());
    }
}
