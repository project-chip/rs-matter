/*
 *
 *    Copyright (c) 2025-2026 Project CHIP Authors
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

use core::fmt::Write;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

use domain::base::name::{Label, ToLabelIter};

use crate::dm::clusters::basic_info::BasicInfoConfig;
use crate::dm::clusters::icd_mgmt::OperatingModeEnum;
use crate::error::{Error, ErrorCode};
use crate::tlv::EitherIter;
use crate::utils::storage::{write_split, Vec, WriteBuf};
use crate::Matter;

use super::{MatterLocalService, MatterRemoteService};

#[cfg(feature = "astro-dnssd")]
pub mod astro;
#[cfg(feature = "zbus")]
pub mod avahi;
pub mod builtin;
#[cfg(feature = "zbus")]
pub mod resolve;
#[cfg(feature = "zeroconf")]
pub mod zeroconf;

/// The standard mDNS IPv6 broadcast address
pub const MDNS_IPV6_BROADCAST_ADDR: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb);

/// The standard mDNS IPv4 broadcast address
pub const MDNS_IPV4_BROADCAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// The standard mDNS port
pub const MDNS_PORT: u16 = 5353;

/// A default bind address for mDNS sockets. Binds to all available interfaces
pub const MDNS_SOCKET_DEFAULT_BIND_ADDR: SocketAddr =
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MDNS_PORT, 0, 0));

impl MatterLocalService {
    /// Build a full mDNS service description for this Matter service, including
    /// the service name, type, protocol, port, subtypes, and TXT records.
    ///
    /// Pulls everything it needs (device details, port, ICD operating mode) from
    /// `matter`, so callers don't have to keep their argument lists in sync as
    /// the advertised record grows.
    #[allow(clippy::type_complexity)]
    pub fn service<'a>(
        &self,
        matter: &Matter<'_>,
        buf: &'a mut [u8],
    ) -> Result<
        (
            MdnsLocalService<
                'a,
                impl Iterator<Item = &'a str> + Clone,
                impl Iterator<Item = (&'a str, &'a str)> + Clone,
            >,
            &'a mut [u8],
        ),
        Error,
    > {
        self.service_internal(matter.dev_det(), matter.port(), matter.icd_mode(), buf)
    }

    /// The implementation behind [`Self::service`], taking the advertised inputs
    /// explicitly.
    #[allow(clippy::type_complexity)]
    fn service_internal<'a>(
        &self,
        dev_det: &BasicInfoConfig<'_>,
        matter_port: u16,
        icd_mode: Option<OperatingModeEnum>,
        buf: &'a mut [u8],
    ) -> Result<
        (
            MdnsLocalService<
                'a,
                impl Iterator<Item = &'a str> + Clone,
                impl Iterator<Item = (&'a str, &'a str)> + Clone,
            >,
            &'a mut [u8],
        ),
        Error,
    > {
        match self {
            Self::Commissioned {
                compressed_fabric_id,
                node_id,
            } => {
                let mut wb = WriteBuf::new(buf);

                let (name, mut wb) =
                    write_split!(wb, "{:016X}-{:016X}", compressed_fabric_id, node_id)?;

                // Operational fabric subtype per Matter Core Spec:
                // `_I<compressed_fabric_id>._sub._matter._tcp.local.` lets a
                // controller browse for nodes of a given fabric without
                // already knowing each node's id.
                let (subtype_i, mut wb) = write_split!(wb, "_I{:016X}", compressed_fabric_id)?;
                let (txt_sai, mut wb) = if let Some(sai) = dev_det.sai {
                    write_split!(wb, "{}", sai)?
                } else {
                    ("", wb)
                };
                let (txt_sii, wb) = if let Some(sii) = dev_det.sii {
                    write_split!(wb, "{}", sii)?
                } else {
                    ("", wb)
                };

                // The `ICD` key is advertised only by Long-Idle-Time-capable
                // devices: "0" while operating as SIT, "1" as LIT. A non-ICD
                // device omits it (empty value, dropped by the filter below).
                let txt_icd = match icd_mode {
                    Some(OperatingModeEnum::LIT) => "1",
                    Some(OperatingModeEnum::SIT) => "0",
                    None => "",
                };

                // Per Matter Core Spec, T is a bitmap:
                // bit 1 (value 2) = TCP client, bit 2 (value 4) = TCP server
                let txt_kvs = [
                    ("SAI", txt_sai),
                    ("SII", txt_sii),
                    ("T", if dev_det.tcp_supported { "6" } else { "" }),
                    ("ICD", txt_icd),
                    // Some mDNS responders do not accept empty TXT records
                    ("DUMMY", "DUMMY"),
                ]
                .into_iter()
                .filter(|(_, v)| !v.is_empty());

                Ok((
                    MdnsLocalService {
                        name,
                        service: "_matter",
                        protocol: "_tcp",
                        service_protocol: "_matter._tcp",
                        port: matter_port,
                        service_subtypes: EitherIter::First(core::iter::once(subtype_i)),
                        txt_kvs: EitherIter::First(txt_kvs),
                    },
                    wb.into_buf(),
                ))
            }
            Self::Commissionable {
                id,
                discriminator,
                enhanced,
            } => {
                let mut wb = WriteBuf::new(buf);

                let (name, mut wb) = write_split!(wb, "{:016X}", id)?;

                let (subtype_discr, mut wb) = write_split!(wb, "_L{}", *discriminator)?;
                let (subtype_short_discr, mut wb) = write_split!(
                    wb,
                    "_S{}",
                    Self::compute_short_discriminator(*discriminator)
                )?;
                let (subtype_v, mut wb) = write_split!(wb, "_V{}", dev_det.vid)?;
                let (subtype_t, mut wb) = if let Some(dt) = dev_det.device_type {
                    write_split!(wb, "_T{}", dt)?
                } else {
                    ("", wb)
                };

                let service_subtypes = [
                    subtype_discr,
                    subtype_short_discr,
                    subtype_v,
                    subtype_t,
                    "_CM",
                ]
                .into_iter()
                .filter(|s| !s.is_empty());

                let (txt_discr, mut wb) = write_split!(wb, "{}", *discriminator)?;
                let (txt_vid_pid, mut wb) = write_split!(wb, "{}+{}", dev_det.vid, dev_det.pid)?;
                let (txt_sai, mut wb) = if let Some(sai) = dev_det.sai {
                    write_split!(wb, "{}", sai)?
                } else {
                    ("", wb)
                };
                let (txt_sii, mut wb) = if let Some(sii) = dev_det.sii {
                    write_split!(wb, "{}", sii)?
                } else {
                    ("", wb)
                };
                let (txt_dn, mut wb) = write_split!(wb, "{}", dev_det.device_name)?;
                let (txt_pi, mut wb) = write_split!(wb, "{}", dev_det.pairing_instruction)?;
                let (txt_ph, mut wb) = write_split!(wb, "{}", dev_det.pairing_hint.bits())?;
                let (txt_dt, mut wb) = if let Some(dt) = dev_det.device_type {
                    write_split!(wb, "{}", dt)?
                } else {
                    ("", wb)
                };
                let (txt_tcp, wb) = if dev_det.tcp_supported {
                    write_split!(wb, "6")?
                } else {
                    ("", wb)
                };

                // As on the operational service, a Long-Idle-Time-capable device
                // advertises its current mode here too ("0"=SIT, "1"=LIT); a
                // non-ICD device omits the key.
                let txt_icd = match icd_mode {
                    Some(OperatingModeEnum::LIT) => "1",
                    Some(OperatingModeEnum::SIT) => "0",
                    None => "",
                };

                let txt_kvs = [
                    ("D", txt_discr),
                    ("CM", if *enhanced { "2" } else { "1" }),
                    ("VP", txt_vid_pid),
                    ("SAI", txt_sai),
                    ("SII", txt_sii),
                    ("DN", txt_dn),
                    ("PI", txt_pi),
                    ("PH", txt_ph),
                    ("DT", txt_dt),
                    ("T", txt_tcp),
                    ("ICD", txt_icd),
                ]
                .into_iter()
                .filter(|(_, v)| !v.is_empty());

                Ok((
                    MdnsLocalService {
                        name,
                        service: "_matterc",
                        protocol: "_udp",
                        service_protocol: "_matterc._udp",
                        port: matter_port,
                        service_subtypes: EitherIter::Second(service_subtypes),
                        txt_kvs: EitherIter::Second(txt_kvs),
                    },
                    wb.into_buf(),
                ))
            }
        }
    }

    fn compute_short_discriminator(discriminator: u16) -> u16 {
        const SHORT_DISCRIMINATOR_MASK: u16 = 0xF00;
        const SHORT_DISCRIMINATOR_SHIFT: u16 = 8;

        (discriminator & SHORT_DISCRIMINATOR_MASK) >> SHORT_DISCRIMINATOR_SHIFT
    }
}

impl MatterRemoteService {
    /// The DNS-SD service type (without domain) this remote service lives under:
    /// `_matter._tcp` for operational nodes, `_matterc._udp` for commissionable
    /// ones. Used by OS-backed responders that resolve via a `(name, type, domain)`
    /// API rather than a fully-qualified instance name.
    pub fn service_type(&self) -> &'static str {
        match self {
            Self::Operational { .. } => "_matter._tcp",
            Self::Commissionable { .. } => "_matterc._udp",
        }
    }

    /// Write the fully-qualified mDNS instance name for this service into `buf`.
    ///
    /// This is the name to issue SRV/TXT/A/AAAA queries against when resolving.
    pub fn instance_name(&self, buf: &mut heapless::String<128>) {
        buf.clear();

        match self {
            Self::Operational {
                compressed_fabric_id,
                node_id,
            } => {
                write_unwrap!(
                    buf,
                    "{:016X}-{:016X}._matter._tcp.local",
                    compressed_fabric_id,
                    node_id
                );
            }
            Self::Commissionable { id } => {
                write_unwrap!(buf, "{:016X}._matterc._udp.local", id);
            }
        }
    }

    /// The service-type suffix labels that follow the leading instance label:
    /// `_matter`/`_tcp`/`local` for operational nodes, `_matterc`/`_udp`/`local`
    /// for commissionable ones.
    fn suffix_labels(&self) -> &'static [&'static str] {
        match self {
            Self::Operational { .. } => &["_matter", "_tcp", "local"],
            Self::Commissionable { .. } => &["_matterc", "_udp", "local"],
        }
    }

    /// The mDNS instance-name labels for this service: the leading hex id label
    /// (written into `buf`) followed by the static service-type labels. Used to
    /// build a query name directly from labels (via `NameSlice`), avoiding a
    /// full-name buffer + re-parse.
    pub(crate) fn query_name_labels<'b>(&self, buf: &'b mut heapless::String<33>) -> [&'b str; 4] {
        buf.clear();

        match self {
            Self::Operational {
                compressed_fabric_id,
                node_id,
            } => {
                write_unwrap!(buf, "{:016X}-{:016X}", compressed_fabric_id, node_id);
                [buf.as_str(), "_matter", "_tcp", "local"]
            }
            Self::Commissionable { id } => {
                write_unwrap!(buf, "{:016X}", id);
                [buf.as_str(), "_matterc", "_udp", "local"]
            }
        }
    }

    /// Whether the given mDNS instance (as a label iterator) refers to this
    /// service. Walks the labels directly: the first label must hold the matching
    /// hex id(s), and the remaining labels the service-type suffix (compared
    /// case-insensitively). No name is ever rendered into a buffer - it reads the
    /// `domain` (or OS) name's labels in place.
    pub fn matches_instance<I: ToLabelIter>(&self, instance: &I) -> bool {
        // Skip the empty root label that absolute names carry.
        let mut labels = instance.iter_labels().filter(|l| !l.is_empty());

        let Some(first) = labels.next() else {
            return false;
        };

        // The remaining labels must be exactly the service-type suffix.
        let mut suffix = self.suffix_labels().iter();
        for label in labels {
            match suffix.next() {
                Some(expected) if label.as_slice().eq_ignore_ascii_case(expected.as_bytes()) => {}
                _ => return false,
            }
        }
        if suffix.next().is_some() {
            return false;
        }

        // The first label holds the hex id(s).
        let Ok(first) = core::str::from_utf8(first.as_slice()) else {
            return false;
        };

        match self {
            Self::Operational {
                compressed_fabric_id,
                node_id,
            } => {
                let Some((fabric, node)) = first.split_once('-') else {
                    return false;
                };

                parse_hex_u64(fabric) == Some(*compressed_fabric_id)
                    && parse_hex_u64(node) == Some(*node_id)
            }
            Self::Commissionable { id } => parse_hex_u64(first) == Some(*id),
        }
    }
}

/// A utility type for expanding a `MatterLocalService` type into a full mDNS service description
///
/// Useful as an implementation detail when interfacing with OS-specific mDNS libraries.
pub struct MdnsLocalService<'a, S, T>
where
    S: Iterator<Item = &'a str> + Clone,
    T: Iterator<Item = (&'a str, &'a str)> + Clone,
{
    /// The name of the service, typically the mDNS name
    pub name: &'a str,
    /// The service type, e.g. "_matter" or "_matterc"
    pub service: &'a str,
    /// The protocol used, e.g. "_tcp" or "_udp"
    pub protocol: &'a str,
    /// The service and protocol combined, e.g. "_matter._tcp" or "_matterc._udp"
    pub service_protocol: &'a str,
    /// The port number the service is running on
    pub port: u16,
    /// Optional service subtypes, e.g. "_L1234" or "_S12"
    pub service_subtypes: S,
    /// Key-value pairs for TXT records, e.g. ("D", "1234")
    pub txt_kvs: T,
}

/// A borrowed, lazily-evaluated view of a single Matter service discovered over
/// mDNS - the *query-side* analog of the publish-side [`MdnsLocalService`].
///
/// Mirroring `MdnsLocalService`, it carries `addrs` and `txt` as **iterators**
/// rather than collected buffers, so neither the builtin parser nor the OS-backed
/// responders need a fixed-size, upper-bounded scratch `Vec`.
///
/// Type parameters (bounds applied at the use sites, not here):
/// - `I`: the instance name as a label iterator (`domain`'s `ToLabelIter`) - a
///   `ParsedName` straight from the packet for the builtin parser, a [`DottedName`]
///   over the OS backends' native `&str`. Matched label-by-label, never rendered
///   to a buffer.
/// - `A`: an `Iterator<Item = IpAddr>` over the service's addresses.
/// - `T`: an `Iterator<Item = (&str, &str)>` over the raw TXT key/value pairs.
#[derive(Debug, Clone, Copy)]
pub struct MdnsRemoteService<I, A, T> {
    /// The mDNS instance name, e.g. `ABCD1234._matterc._udp.local` for a
    /// commissionable node or `<fab>-<node>._matter._tcp.local` for an
    /// operational one.
    pub instance_name: I,
    /// The port from the SRV record, if present.
    pub port: Option<u16>,
    /// The service's addresses (A/AAAA records).
    pub addrs: A,
    /// The raw TXT key/value pairs.
    pub txt: T,
    /// The IPv6 scope (zone) id — the interface index the service was discovered
    /// on. Required to make a **link-local** (`fe80::/10`) address routable: the
    /// kernel cannot pick an egress interface for a link-local destination
    /// without it. `0` (the kernel's own "unscoped" sentinel) when the backend
    /// can't supply it; only relevant for link-local IPv6 results.
    pub scope_id: u32,
}

impl<'a, I, A, T> MdnsRemoteService<I, A, T>
where
    T: Iterator<Item = (&'a str, &'a str)> + Clone,
{
    /// Parse the peer's MRP/session parameters from this answer's TXT records
    /// (Matter Core spec), returned as `(SII, SAI, SAT)` in milliseconds
    /// (session idle interval / active interval / active threshold).
    pub fn session_params(&self) -> (Option<u32>, Option<u32>, Option<u16>) {
        let (mut sii, mut sai, mut sat) = (None, None, None);

        for (key, value) in self.txt.clone() {
            if key.eq_ignore_ascii_case("SII") {
                sii = value.parse().ok();
            } else if key.eq_ignore_ascii_case("SAI") {
                sai = value.parse().ok();
            } else if key.eq_ignore_ascii_case("SAT") {
                sat = value.parse().ok();
            }
        }

        (sii, sai, sat)
    }
}

/// Filter criteria for discovering commissionable devices.
///
/// This filter is used by mDNS discovery implementations to narrow down
/// the search for commissionable Matter devices on the local network.
///
/// The mDNS subtype filtering supports discriminator, short discriminator,
/// vendor ID, device type, and commissioning mode. Product ID filtering
/// is done post-discovery by checking TXT records.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CommissionableFilter {
    /// Filter by long discriminator (12-bit)
    pub discriminator: Option<u16>,
    /// Filter by short discriminator (4-bit, derived from long discriminator)
    pub short_discriminator: Option<u8>,
    /// Filter by vendor ID
    pub vendor_id: Option<u16>,
    /// Filter by product ID (applied post-discovery via TXT record check)
    pub product_id: Option<u16>,
    /// Filter by device type (uses `_T{type}` subtype)
    pub device_type: Option<u32>,
    /// Filter to only find devices in commissioning mode (uses `_CM` subtype)
    pub commissioning_mode_only: bool,
}

impl CommissionableFilter {
    /// Build the mDNS service type string for browsing commissionable devices.
    ///
    /// If the filter specifies a discriminator, short discriminator, vendor ID,
    /// device type, or commissioning mode, the service type will include the
    /// appropriate subtype for more efficient discovery.
    ///
    /// The priority order for subtypes is:
    /// 1. Long discriminator (`_L{disc}`)
    /// 2. Short discriminator (`_S{short}`)
    /// 3. Vendor ID (`_V{vid}`)
    /// 4. Device type (`_T{type}`)
    /// 5. Commissioning mode (`_CM`)
    ///
    /// Note: Product ID is not included in the service type because the Matter
    /// specification only defines it as part of the VP TXT record, not as a subtype.
    ///
    /// # Arguments
    /// * `buf` - A mutable string buffer to write the service type into
    /// * `include_local` - Whether to append `.local` suffix (needed for raw DNS queries)
    pub fn service_type(&self, buf: &mut heapless::String<64>, include_local: bool) {
        buf.clear();
        let suffix = if include_local { ".local" } else { "" };

        let mut sbuf = heapless::String::<24>::new();
        if let Some(sub) = self.subtype(&mut sbuf) {
            write_unwrap!(buf, "{}._sub._matterc._udp{}", sub, suffix);
        } else {
            write_unwrap!(buf, "_matterc._udp{}", suffix);
        }
    }

    /// The single most-selective browse subtype label this filter offers,
    /// written into `buf`, in the priority order `_L` > `_S` > `_V` > `_T` >
    /// `_CM` (see [`CommissionableFilter::service_type`]), or `None` for an
    /// unfiltered browse. Used to build the browse query name directly from
    /// labels (via `NameSlice`), and as the single source of the priority logic.
    pub(crate) fn subtype<'b>(&self, buf: &'b mut heapless::String<24>) -> Option<&'b str> {
        buf.clear();

        if let Some(disc) = self.discriminator {
            write_unwrap!(buf, "_L{}", disc);
        } else if let Some(short_disc) = self.short_discriminator {
            write_unwrap!(buf, "_S{}", short_disc);
        } else if let Some(vid) = self.vendor_id {
            write_unwrap!(buf, "_V{}", vid);
        } else if let Some(dt) = self.device_type {
            write_unwrap!(buf, "_T{}", dt);
        } else if self.commissioning_mode_only {
            write_unwrap!(buf, "_CM");
        } else {
            return None;
        }

        Some(buf.as_str())
    }

    /// Whether a discovered [`MdnsRemoteService`] matches this filter (AND over
    /// all non-`None` fields).
    pub fn matches<'a, I, A, T>(&self, service: &MdnsRemoteService<I, A, T>) -> bool
    where
        T: Iterator<Item = (&'a str, &'a str)> + Clone,
    {
        self.matches_txt(service.txt.clone())
    }

    /// Whether a discovered commissionable node matches **all** of this filter's
    /// non-`None` fields (AND semantics); an empty filter matches everything.
    ///
    /// The single, allocation-free filter primitive - it reads the relevant
    /// Matter commissionable TXT records (`D`, `VP`, `CM`, `DT`) straight off an
    /// iterator of `(key, value)` pairs, so both the builtin browse path (via
    /// [`CommissionableFilter::matches`]) and the OS-backed responders
    /// (which hand it their native TXT records) share one implementation.
    fn matches_txt<'a, I>(&self, txt: I) -> bool
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut discriminator: Option<u16> = None;
        let mut vendor_id: Option<u16> = None;
        let mut product_id: Option<u16> = None;
        let mut device_type: Option<u32> = None;
        let mut commissioning = CommissioningMode::Disabled;

        for (key, value) in txt {
            if key.eq_ignore_ascii_case("D") {
                discriminator = value.parse::<u16>().ok().filter(|d| *d <= 0xFFF);
            } else if key.eq_ignore_ascii_case("VP") {
                if let Some(plus) = value.find('+') {
                    vendor_id = value[..plus].parse::<u16>().ok();
                    product_id = value[plus + 1..].parse::<u16>().ok();
                } else {
                    vendor_id = value.parse::<u16>().ok();
                }
            } else if key.eq_ignore_ascii_case("CM") {
                commissioning = CommissioningMode::from_txt_value(value);
            } else if key.eq_ignore_ascii_case("DT") {
                device_type = value.parse::<u32>().ok();
            }
        }

        if let Some(want) = self.discriminator {
            if discriminator != Some(want) {
                return false;
            }
        }

        if let Some(want) = self.short_discriminator {
            // Short discriminator is the upper 4 bits of the 12-bit discriminator.
            if discriminator.map(|d| (d >> 8) as u8) != Some(want) {
                return false;
            }
        }

        if let Some(want) = self.vendor_id {
            if vendor_id != Some(want) {
                return false;
            }
        }

        if let Some(want) = self.product_id {
            if product_id != Some(want) {
                return false;
            }
        }

        if let Some(want) = self.device_type {
            if device_type != Some(want) {
                return false;
            }
        }

        if self.commissioning_mode_only && !commissioning.is_commissionable() {
            return false;
        }

        true
    }
}

/// Commissioning mode values for Matter devices.
///
/// This indicates whether a device is in commissioning mode and what type
/// of commissioning window is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
enum CommissioningMode {
    /// Device is not in commissioning mode
    #[default]
    Disabled = 0,
    /// Basic commissioning window is open
    Basic = 1,
    /// Enhanced commissioning window is open (with passcode verifier)
    Enhanced = 2,
}

impl CommissioningMode {
    /// Parse a commissioning mode from a string value.
    fn from_txt_value(value: &str) -> Self {
        match value {
            "1" => Self::Basic,
            "2" => Self::Enhanced,
            _ => Self::Disabled,
        }
    }

    /// Returns true if the device is in any commissioning mode.
    fn is_commissionable(&self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

/// A textual, dotted mDNS name (e.g. `ABCD1234._matterc._udp.local`) viewed as a
/// sequence of labels, **borrowing** the string - no allocation.
///
/// Lets the OS-backed responders hand their native `&str` instance names to the
/// shared [`MdnsRemoteService`] machinery (which matches label-by-label via
/// [`ToLabelIter`]) without rendering anything.
#[derive(Debug, Clone, Copy)]
pub struct DottedName<'a>(pub &'a str);

impl ToLabelIter for DottedName<'_> {
    type LabelIter<'t>
        = core::iter::Map<core::str::Split<'t, char>, fn(&str) -> &Label>
    where
        Self: 't;

    fn iter_labels(&self) -> Self::LabelIter<'_> {
        /// Reinterpret a single textual label as a `domain` [`Label`]; an over-long
        /// (invalid) label folds to the empty root label, which won't match anything.
        fn str_to_label(s: &str) -> &Label {
            Label::from_slice(s.as_bytes()).unwrap_or_else(|_| Label::root())
        }

        self.0
            .trim_end_matches('.')
            .split('.')
            .map(str_to_label as fn(&str) -> &Label)
    }
}

/// The result of a successful [`Matter::resolve`](crate::Matter::resolve): the
/// peer's address plus its advertised MRP/session parameters (`SII`/`SAI`/`SAT`
/// = session idle interval / active interval / active threshold, milliseconds).
///
/// The params are carried out so the CASE initiator can seed the new session's
/// MRP backoff from the peer's advertised values rather than local defaults.
#[derive(Debug, Clone)]
pub struct ResolvedNode {
    /// The resolved peer addresses, **best-scored first** (see
    /// [`score_ip_address`]), each already carrying its IPv6 scope where one
    /// applies. Never empty.
    ///
    /// More than one is carried because the best-scored address is not
    /// necessarily the reachable one, so the CASE initiator walks the list until
    /// a handshake completes - see [`MAX_RESOLVE_CANDIDATES`].
    pub addrs: Vec<SocketAddr, MAX_RESOLVE_CANDIDATES>,
    /// Session Idle Interval (`SII`), milliseconds.
    pub sii: Option<u32>,
    /// Session Active Interval (`SAI`), milliseconds.
    pub sai: Option<u32>,
    /// Session Active Threshold (`SAT`), milliseconds.
    pub sat: Option<u16>,
}

impl ResolvedNode {
    /// The best-scored candidate address.
    ///
    /// [`Self::addrs`] is never empty, so this only returns `None` for a
    /// hand-constructed value.
    pub fn addr(&self) -> Option<SocketAddr> {
        self.addrs.first().copied()
    }
}

/// Maximum number of candidate peer addresses kept for a single resolve.
///
/// A node advertises an AAAA record for every address it accepts operational
/// messages on, and the Matter Core Specification requires support for at least
/// three routable addresses on top of the link-local one, so a single answer can
/// easily carry several. Keeping a few of them - rather than only the
/// best-scored one - is what lets the CASE initiator recover when the top
/// candidate turns out to be unreachable, which is exactly the failure mode of a
/// link-local address relayed across a subnet boundary. See
/// [`score_ip_address_on_link`] for why the ranking cannot decide that on its
/// own.
pub const MAX_RESOLVE_CANDIDATES: usize = 3;

/// A single ranked candidate address for a resolved peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResolvedAddr {
    /// The peer address.
    pub ip: IpAddr,
    /// IPv6 scope (zone) id for a link-local `ip`; 0 otherwise. See
    /// [`MdnsRemoteService::scope_id`].
    pub scope_id: u32,
    /// The score `ip` was ranked by (see [`score_ip_address_on_link`]).
    /// Candidates are kept in descending score order.
    pub score: u8,
}

/// Merge one address into a ranked candidate list, keeping it sorted by
/// descending score, free of duplicates, and bounded to
/// [`MAX_RESOLVE_CANDIDATES`].
///
/// Returns `true` if the list changed. A duplicate, or an address that scores
/// below every candidate in an already-full list, is dropped.
pub(crate) fn merge_resolve_candidate(
    addrs: &mut Vec<ResolvedAddr, MAX_RESOLVE_CANDIDATES>,
    candidate: ResolvedAddr,
) -> bool {
    if addrs.iter().any(|c| c.ip == candidate.ip) {
        return false;
    }

    let pos = addrs
        .iter()
        .position(|c| c.score < candidate.score)
        .unwrap_or(addrs.len());

    if pos >= MAX_RESOLVE_CANDIDATES {
        // Worse than every candidate already kept, and there is no room.
        return false;
    }

    if addrs.is_full() {
        addrs.pop();
    }

    // `pos <= addrs.len()` and the list has room, so this cannot fail.
    let _ = addrs.insert(pos, candidate);

    true
}

/// The state of the single in-flight mDNS resolve "rendezvous" shared between
/// [`Matter::resolve`](crate::Matter::resolve) callers and the running mDNS
/// responder.
///
/// At most one resolve is in flight at a time; callers serialize on the `Idle`
/// state. See `Matter::resolve` for the protocol.
#[derive(Debug, Clone)]
pub(crate) enum MdnsResolveState {
    /// No resolve in progress; a caller may place a request.
    Idle,
    /// A caller has placed a request; the responder has not yet picked it up.
    Requested { service: MatterRemoteService },
    /// The responder picked up the request and sent the query; awaiting an answer.
    InFlight { service: MatterRemoteService },
    /// The responder deposited the resolved addresses + MRP/session params.
    ///
    /// No `service` is carried: the rendezvous is single-slot, so the only waiter
    /// that can observe this is the one whose request the responder resolved.
    Resolved {
        /// The candidate addresses, best-scored first and never empty. Further
        /// deposits for the same in-flight target merge into this list, so a
        /// backend that surfaces one address per callback (Avahi, zeroconf)
        /// accumulates candidates the same way a backend that hands over a whole
        /// packet (the builtin responder) does.
        addrs: Vec<ResolvedAddr, MAX_RESOLVE_CANDIDATES>,
        port: u16,
        sii: Option<u32>,
        sai: Option<u32>,
        sat: Option<u16>,
    },
}

/// Maximum number of already-tried commissionable instance ids a single
/// [`Transport::browse_commissionable`](crate::transport::Transport::browse_commissionable)
/// request can exclude - i.e. how many short-discriminator-collision candidates
/// a caller can step through before giving up. Small and fixed (no heap).
pub(crate) const MAX_BROWSE_EXCLUDE: usize = 6;

/// The set of commissionable instance ids to skip on a browse (already tried).
pub(crate) type BrowseExclude = Vec<u64, MAX_BROWSE_EXCLUDE>;

/// The state of the single in-flight mDNS commissionable-**browse** "rendezvous"
/// shared between
/// [`Transport::browse_commissionable`](crate::transport::Transport::browse_commissionable)
/// callers and the running mDNS responder.
///
/// Prototype: at most one browse in flight at a time, returning the *first*
/// matching node whose id is not in the request's exclude set (so a caller can
/// step to the "next" candidate on a short-discriminator collision). See
/// `Transport::browse_commissionable` for the protocol.
#[derive(Debug, Clone)]
pub(crate) enum MdnsBrowseState {
    /// No browse in progress; a caller may place a request.
    Idle,
    /// A caller has placed a request (filter + ids to skip); not yet picked up.
    Requested {
        filter: CommissionableFilter,
        exclude: BrowseExclude,
    },
    /// The responder picked up the request and sent the browse query; awaiting a match.
    InFlight {
        filter: CommissionableFilter,
        exclude: BrowseExclude,
    },
    /// The responder deposited the first matching, non-excluded commissionable node.
    Found {
        ip: IpAddr,
        port: u16,
        /// IPv6 scope (zone) id for a link-local `ip`; 0 otherwise. See
        /// [`MdnsRemoteService::scope_id`].
        scope_id: u32,
        id: u64,
    },
}

/// Score an IP address for prioritization; higher is more preferred.
///
/// Convenience wrapper over [`score_ip_address_on_link`] for callers that have no
/// knowledge of the local interface addresses.
pub fn score_ip_address(addr: &IpAddr) -> u8 {
    score_ip_address_on_link(addr, &[])
}

/// Score an IP address for prioritization; higher is more preferred.
///
/// The Matter Core Specification prescribes no ordering: it accepts a global
/// unicast, a link-local or a unique local address equally as an operational
/// address, and the only related requirement is that a peer must not be assumed
/// reachable at a single address. The ladder below therefore encodes reachability
/// heuristics rather than a spec rule, and follows the ordering the CHIP SDK
/// resolves with, so both stacks pick the same address for the same
/// advertisement:
///
/// 1. Link-local IPv6 - reachability is implied by the discovery itself: mDNS is
///    link-scoped, so an answer received over multicast DNS proves the peer is on
///    the link. It also never renumbers and depends on no router.
/// 2. Global unicast sharing a prefix with a local address - provably on-link
///    too, without depending on the answer having arrived over the link.
/// 3. Unique local sharing a prefix with a local address - likewise on-link.
/// 4. Global unicast - routable, but possibly only via a router.
/// 5. Unique local - routable, but possibly only via a router.
/// 6. IPv4 - outside the Matter operational addressing model; last resort.
/// 7. Any other IPv6 (multicast, unspecified, IPv4-mapped) - unusable.
///
/// Ranking link-local first is only safe together with the candidate list the
/// resolver keeps: an answer relayed across a subnet boundary - by an mDNS
/// reflector, or by the DNS-SD proxy of a Thread border router - carries a
/// link-local address that scores highest yet cannot be reached, so the initiator
/// must be able to fall back to the next candidate. See
/// [`MAX_RESOLVE_CANDIDATES`].
///
/// `local_ipv6` are the IPv6 addresses configured on the local interface, used
/// for the two "shares a prefix" tiers. Pass `&[]` when they are unknown - which
/// is the case for every OS-backed responder, as those delegate the host records
/// to a daemon and never see the addresses themselves.
pub fn score_ip_address_on_link(addr: &IpAddr, local_ipv6: &[Ipv6Addr]) -> u8 {
    match addr {
        IpAddr::V6(ipv6) => {
            if ipv6.is_unicast_link_local() {
                70
            } else if is_ipv6_global_unicast(ipv6) {
                if shares_prefix(ipv6, local_ipv6) {
                    60
                } else {
                    40
                }
            } else if ipv6.is_unique_local() {
                if shares_prefix(ipv6, local_ipv6) {
                    50
                } else {
                    30
                }
            } else {
                10
            }
        }
        IpAddr::V4(_) => 20,
    }
}

/// Whether `addr` sits in the same /64 as any of `local_ipv6` - i.e. the peer
/// address belongs to a prefix this node is itself configured on, and is
/// therefore reachable without traversing a router.
///
/// /64 is the only prefix length worth checking: both the on-link prefixes a
/// Wi-Fi / Ethernet interface autoconfigures from a Router Advertisement and the
/// on-mesh prefixes carried in the Thread Network Data are /64.
///
/// Local link-local addresses are skipped: every link-local address shares the
/// `fe80::/64` prefix, so matching against them would promote every peer
/// link-local address into a tier it does not belong to (and link-local is
/// already the top tier anyway).
fn shares_prefix(addr: &Ipv6Addr, local_ipv6: &[Ipv6Addr]) -> bool {
    let prefix = &addr.octets()[..8];

    local_ipv6
        .iter()
        .any(|local| !local.is_unicast_link_local() && &local.octets()[..8] == prefix)
}

/// Check if an IPv6 address is global unicast (2000::/3)
fn is_ipv6_global_unicast(addr: &Ipv6Addr) -> bool {
    let segments = addr.segments();
    (segments[0] & 0xe000) == 0x2000
}

/// The commissionable instance id (the leading label, parsed as hex) of a
/// discovered instance, or `None` if the first label isn't a single hex id.
/// Used to dedup/exclude browse candidates by id.
pub(crate) fn commissionable_instance_id<I: ToLabelIter>(instance: &I) -> Option<u64> {
    let first = instance.iter_labels().find(|l| !l.is_empty())?;
    parse_hex_u64(core::str::from_utf8(first.as_slice()).ok()?)
}

/// Parse a hex string as a `u64` (case-insensitive). `None` on empty/overflow/
/// non-hex input. Used to read the hex id label out of an mDNS instance name.
fn parse_hex_u64(s: &str) -> Option<u64> {
    // `from_str_radix` accepts a leading `+`/`-`; reject those so a malformed
    // label can't masquerade as a valid id.
    if s.bytes().all(|b| b.is_ascii_hexdigit()) {
        u64::from_str_radix(s, 16).ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_compute_short_discriminator() {
        let discriminator: u16 = 0b0000_1111_0000_0000;
        let short = MatterLocalService::compute_short_discriminator(discriminator);
        assert_eq!(short, 0b1111);

        let discriminator: u16 = 840;
        let short = MatterLocalService::compute_short_discriminator(discriminator);
        assert_eq!(short, 3);
    }

    // --- CommissionableFilter::matches_txt (AND over all non-None fields) ---

    #[test]
    fn matches_txt_empty_filter_matches_all() {
        let filter = CommissionableFilter::default();
        assert!(filter.matches_txt([("D", "1234"), ("VP", "65521+32768"), ("CM", "1")]));
        assert!(filter.matches_txt(core::iter::empty::<(&str, &str)>())); // even an empty advertisement
    }

    #[test]
    fn matches_txt_discriminator_and_short() {
        let filter = CommissionableFilter {
            discriminator: Some(1234),
            ..Default::default()
        };
        assert!(filter.matches_txt([("D", "1234")]));
        assert!(!filter.matches_txt([("D", "5678")]));

        // Short discriminator = top 4 bits of the 12-bit discriminator (840 -> 3).
        let filter = CommissionableFilter {
            short_discriminator: Some(3),
            ..Default::default()
        };
        assert!(filter.matches_txt([("D", "840")]));
        assert!(!filter.matches_txt([("D", "1024")])); // 0x400 -> short 4
    }

    #[test]
    fn matches_txt_vendor_product_and_combined() {
        let filter = CommissionableFilter {
            vendor_id: Some(0xFFF1),
            product_id: Some(0x8000),
            ..Default::default()
        };
        assert!(filter.matches_txt([("VP", "65521+32768")]));
        assert!(!filter.matches_txt([("VP", "65521+1")])); // wrong product
        assert!(!filter.matches_txt([("VP", "1+32768")])); // wrong vendor

        // All non-None fields must match (AND).
        let filter = CommissionableFilter {
            discriminator: Some(1234),
            vendor_id: Some(0xFFF1),
            ..Default::default()
        };
        assert!(filter.matches_txt([("D", "1234"), ("VP", "65521+1")]));
        assert!(!filter.matches_txt([("D", "1234"), ("VP", "1+1")]));
        assert!(!filter.matches_txt([("D", "9999"), ("VP", "65521+1")]));
    }

    #[test]
    fn matches_txt_device_type_and_commissioning_mode() {
        let filter = CommissionableFilter {
            device_type: Some(257),
            ..Default::default()
        };
        assert!(filter.matches_txt([("DT", "257")]));
        assert!(!filter.matches_txt([("DT", "256")]));

        let filter = CommissionableFilter {
            commissioning_mode_only: true,
            ..Default::default()
        };
        assert!(filter.matches_txt([("CM", "1")]));
        assert!(filter.matches_txt([("CM", "2")]));
        assert!(!filter.matches_txt([("CM", "0")]));
        assert!(!filter.matches_txt(core::iter::empty::<(&str, &str)>())); // no CM advertised -> not commissionable
    }

    // --- CommissionableFilter::service_type (most-selective subtype query) ---

    #[test]
    fn service_type_no_filter() {
        let filter = CommissionableFilter::default();
        let mut buf = heapless::String::<64>::new();

        filter.service_type(&mut buf, false);
        assert_eq!(buf.as_str(), "_matterc._udp");

        filter.service_type(&mut buf, true);
        assert_eq!(buf.as_str(), "_matterc._udp.local");
    }

    #[test]
    fn service_type_with_discriminator() {
        let filter = CommissionableFilter {
            discriminator: Some(1234),
            ..Default::default()
        };
        let mut buf = heapless::String::<64>::new();

        filter.service_type(&mut buf, false);
        assert_eq!(buf.as_str(), "_L1234._sub._matterc._udp");

        filter.service_type(&mut buf, true);
        assert_eq!(buf.as_str(), "_L1234._sub._matterc._udp.local");
    }

    #[test]
    fn service_type_with_short_discriminator() {
        let filter = CommissionableFilter {
            short_discriminator: Some(3),
            ..Default::default()
        };
        let mut buf = heapless::String::<64>::new();

        filter.service_type(&mut buf, false);
        assert_eq!(buf.as_str(), "_S3._sub._matterc._udp");
    }

    #[test]
    fn service_type_with_vendor_id() {
        let filter = CommissionableFilter {
            vendor_id: Some(0xFFF1),
            ..Default::default()
        };
        let mut buf = heapless::String::<64>::new();

        filter.service_type(&mut buf, false);
        assert_eq!(buf.as_str(), "_V65521._sub._matterc._udp");
    }

    #[test]
    fn service_type_with_device_type() {
        let filter = CommissionableFilter {
            device_type: Some(257),
            ..Default::default()
        };
        let mut buf = heapless::String::<64>::new();

        filter.service_type(&mut buf, false);
        assert_eq!(buf.as_str(), "_T257._sub._matterc._udp");
    }

    #[test]
    fn service_type_with_commissioning_mode_only() {
        let filter = CommissionableFilter {
            commissioning_mode_only: true,
            ..Default::default()
        };
        let mut buf = heapless::String::<64>::new();

        filter.service_type(&mut buf, false);
        assert_eq!(buf.as_str(), "_CM._sub._matterc._udp");
    }

    #[test]
    fn service_type_priority_order() {
        // discriminator > short_discriminator > vendor_id > device_type > CM
        let mut buf = heapless::String::<64>::new();

        CommissionableFilter {
            discriminator: Some(1234),
            short_discriminator: Some(3),
            vendor_id: Some(0xFFF1),
            device_type: Some(257),
            commissioning_mode_only: true,
            product_id: Some(0x8000),
        }
        .service_type(&mut buf, false);
        assert_eq!(buf.as_str(), "_L1234._sub._matterc._udp");

        CommissionableFilter {
            short_discriminator: Some(3),
            vendor_id: Some(0xFFF1),
            ..Default::default()
        }
        .service_type(&mut buf, false);
        assert_eq!(buf.as_str(), "_S3._sub._matterc._udp");

        CommissionableFilter {
            vendor_id: Some(0xFFF1),
            device_type: Some(257),
            ..Default::default()
        }
        .service_type(&mut buf, false);
        assert_eq!(buf.as_str(), "_V65521._sub._matterc._udp");

        CommissionableFilter {
            device_type: Some(257),
            commissioning_mode_only: true,
            ..Default::default()
        }
        .service_type(&mut buf, false);
        assert_eq!(buf.as_str(), "_T257._sub._matterc._udp");

        // Product ID alone is never a subtype (no VP subtype without vendor).
        CommissionableFilter {
            product_id: Some(0x8000),
            ..Default::default()
        }
        .service_type(&mut buf, false);
        assert_eq!(buf.as_str(), "_matterc._udp");
    }

    // --- small helpers ---

    #[test]
    fn commissioning_mode_from_txt_value() {
        assert_eq!(
            CommissioningMode::from_txt_value("0"),
            CommissioningMode::Disabled
        );
        assert_eq!(
            CommissioningMode::from_txt_value("1"),
            CommissioningMode::Basic
        );
        assert_eq!(
            CommissioningMode::from_txt_value("2"),
            CommissioningMode::Enhanced
        );
        assert_eq!(
            CommissioningMode::from_txt_value("x"),
            CommissioningMode::Disabled
        );

        assert!(!CommissioningMode::Disabled.is_commissionable());
        assert!(CommissioningMode::Basic.is_commissionable());
        assert!(CommissioningMode::Enhanced.is_commissionable());
    }

    #[test]
    fn score_ip_address_priority_order() {
        let link_local = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let ula = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        let global = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc0a8, 1));

        // Link-local first: an answer received over (link-scoped) mDNS proves the
        // peer is on the link. Global unicast outranks unique local, matching how
        // the CHIP SDK orders the same advertisement.
        assert!(score_ip_address(&link_local) > score_ip_address(&global));
        assert!(score_ip_address(&global) > score_ip_address(&ula));
        assert!(score_ip_address(&ula) > score_ip_address(&ipv4));
        assert!(score_ip_address(&ipv4) > score_ip_address(&mapped));
    }

    /// A peer address on a prefix the node is itself configured on is reachable
    /// without a router, so it outranks one of the same kind that is not - but
    /// never outranks link-local.
    #[test]
    fn score_ip_address_prefers_on_link_prefixes() {
        let local = [
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xaa),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0xaa),
            Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 0xaa),
        ];

        let on_link_gua = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0xbb));
        let off_link_gua = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 9, 0, 0, 0, 0xbb));
        let on_link_ula = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 0xbb));
        let off_link_ula = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 9, 0, 0, 0, 0xbb));
        let link_local = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xbb));

        assert!(
            score_ip_address_on_link(&on_link_gua, &local)
                > score_ip_address_on_link(&off_link_gua, &local)
        );
        assert!(
            score_ip_address_on_link(&on_link_ula, &local)
                > score_ip_address_on_link(&off_link_ula, &local)
        );
        // On-link ULA still ranks under any GUA that is also on-link.
        assert!(
            score_ip_address_on_link(&on_link_gua, &local)
                > score_ip_address_on_link(&on_link_ula, &local)
        );
        assert!(
            score_ip_address_on_link(&link_local, &local)
                > score_ip_address_on_link(&on_link_gua, &local)
        );

        // Every link-local address shares the `fe80::/64` prefix, so the local
        // link-local address must not promote an off-link peer ULA/GUA.
        assert_eq!(
            score_ip_address_on_link(&off_link_gua, &local),
            score_ip_address(&off_link_gua)
        );
    }

    /// The candidate list stays sorted by descending score, deduped, and bounded.
    #[test]
    fn merge_resolve_candidate_ranks_dedups_and_bounds() {
        fn candidate(addr: Ipv6Addr) -> ResolvedAddr {
            let ip = IpAddr::V6(addr);

            ResolvedAddr {
                ip,
                scope_id: 0,
                score: score_ip_address(&ip),
            }
        }

        let link_local = candidate(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let global = candidate(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let ula = candidate(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        let ipv4 = ResolvedAddr {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            scope_id: 0,
            score: score_ip_address(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        };

        let mut addrs = Vec::new();

        // Deposited worst-first; the list still comes out best-first.
        assert!(merge_resolve_candidate(&mut addrs, ula));
        assert!(merge_resolve_candidate(&mut addrs, global));
        assert!(merge_resolve_candidate(&mut addrs, link_local));

        assert_eq!(addrs.as_slice(), &[link_local, global, ula]);

        // A duplicate is dropped.
        assert!(!merge_resolve_candidate(&mut addrs, global));
        assert_eq!(addrs.len(), 3);

        // The list is full and IPv4 scores below everything in it, so it is
        // dropped rather than evicting a better candidate.
        assert!(!merge_resolve_candidate(&mut addrs, ipv4));
        assert_eq!(addrs.as_slice(), &[link_local, global, ula]);

        // A better candidate evicts the worst one.
        let on_link_global = ResolvedAddr {
            score: global.score + 1,
            ..candidate(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1))
        };
        assert!(merge_resolve_candidate(&mut addrs, on_link_global));
        assert_eq!(addrs.as_slice(), &[link_local, on_link_global, global]);
    }

    #[test]
    fn is_ipv6_global_unicast_correct() {
        assert!(is_ipv6_global_unicast(&Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
        )));
        assert!(is_ipv6_global_unicast(&Ipv6Addr::new(
            0x3fff, 0xffff, 0, 0, 0, 0, 0, 1
        )));
        assert!(!is_ipv6_global_unicast(&Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        )));
        assert!(!is_ipv6_global_unicast(&Ipv6Addr::new(
            0xfc00, 0, 0, 0, 0, 0, 0, 1
        )));
    }
}
