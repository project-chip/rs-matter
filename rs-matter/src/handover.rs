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

//! Commissioning handover: suspend a half-done commissioning on one node and
//! resume it on another.

use core::fmt::{self, Debug};
use core::marker::PhantomData;

use crate::acl::AclEntry;
use crate::crypto::{CanonAeadKey, CanonPkcSecretKey};
use crate::dm::clusters::decl::general_commissioning::RegulatoryLocationTypeEnum;
use crate::dm::clusters::net_comm::{Networks, NetworksAccess, NetworksError, WirelessCreds};
use crate::error::{Error, ErrorCode};
use crate::fabric::Fabric;
use crate::tlv::{
    EitherIter, FromTLV, OctetStr, Octets, TLVArray, TLVArrayOrSlice, TLVElement, TLVTag, TLVWrite,
    ToTLV, Utf8Str, TLV,
};

/// The envelope version.
pub const HANDOVER_VERSION: u8 = 1;

/// A borrowed view of one staged network, convertible from and to
/// [`WirelessCreds`].
pub trait HandoverNetwork: Copy {
    /// This view type at lifetime `'c`.
    type Borrowed<'c>: HandoverNetwork + FromTLV<'c> + ToTLV;

    /// The view of `creds`, if of this kind.
    fn from_creds<'c>(creds: &WirelessCreds<'c>) -> Option<Self::Borrowed<'c>>;

    /// The credentials of this view.
    fn creds(&self) -> WirelessCreds<'_>;
}

/// A staged Wi-Fi network; same tags as the `AddOrUpdateWiFiNetwork` arguments.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct HandoverWifi<'a> {
    pub ssid: OctetStr<'a>,
    pub credentials: OctetStr<'a>,
}

impl HandoverNetwork for HandoverWifi<'_> {
    type Borrowed<'c> = HandoverWifi<'c>;

    fn from_creds<'c>(creds: &WirelessCreds<'c>) -> Option<Self::Borrowed<'c>> {
        match creds {
            WirelessCreds::Wifi { ssid, pass } => Some(HandoverWifi {
                ssid: Octets(ssid),
                credentials: Octets(pass),
            }),
            WirelessCreds::Thread { .. } => None,
        }
    }

    fn creds(&self) -> WirelessCreds<'_> {
        WirelessCreds::Wifi {
            ssid: self.ssid.0,
            pass: self.credentials.0,
        }
    }
}

/// A staged Thread network; same tag as the `AddOrUpdateThreadNetwork` argument.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct HandoverThread<'a> {
    pub operational_dataset: OctetStr<'a>,
}

impl HandoverNetwork for HandoverThread<'_> {
    type Borrowed<'c> = HandoverThread<'c>;

    fn from_creds<'c>(creds: &WirelessCreds<'c>) -> Option<Self::Borrowed<'c>> {
        match creds {
            WirelessCreds::Thread { dataset_tlv } => Some(HandoverThread {
                operational_dataset: Octets(dataset_tlv),
            }),
            WirelessCreds::Wifi { .. } => None,
        }
    }

    fn creds(&self) -> WirelessCreds<'_> {
        WirelessCreds::Thread {
            dataset_tlv: self.operational_dataset.0,
        }
    }
}

/// The staged networks of kind `T` ([`HandoverWifi`] or [`HandoverThread`]),
/// serialized as a TLV array of `T`.
///
/// Never materialized: read lazily from the TLV, a slice, or the live
/// [`Networks`] store, whose credentials are only reachable via callbacks.
/// Hence [`for_each`](Self::for_each) instead of an iterator, and hence
/// `tlv_iter` errors with `InvalidState` for a store-backed instance
/// (`to_tlv` always works).
pub struct HandoverNetworks<'a, T> {
    source: NetworksSource<'a, T>,
    _kind: PhantomData<fn() -> T>,
}

enum NetworksSource<'a, T> {
    Tlv(TLVElement<'a>),
    Slice(&'a [T]),
    Store(&'a dyn Networks),
}

impl<'a, T> HandoverNetworks<'a, T>
where
    T: HandoverNetwork,
{
    /// The networks in `slice`.
    pub const fn from_slice(slice: &'a [T]) -> Self {
        Self {
            source: NetworksSource::Slice(slice),
            _kind: PhantomData,
        }
    }

    /// The networks of kind `T` in the store.
    pub const fn from_store(networks: &'a dyn Networks) -> Self {
        Self {
            source: NetworksSource::Store(networks),
            _kind: PhantomData,
        }
    }

    /// Call `f` with each network's credentials, in order.
    pub fn for_each(
        &self,
        f: &mut dyn FnMut(&WirelessCreds<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        match &self.source {
            NetworksSource::Tlv(element) => {
                for network in TLVArray::<T::Borrowed<'a>>::new(element.clone())?.iter() {
                    f(&network?.creds())?;
                }

                Ok(())
            }
            NetworksSource::Slice(slice) => {
                for network in *slice {
                    f(&network.creds())?;
                }

                Ok(())
            }
            NetworksSource::Store(networks) => networks.networks(&mut |network_id| {
                networks
                    .creds(network_id, &mut |creds| {
                        if T::from_creds(creds).is_some() {
                            f(creds)?;
                        }

                        Ok(())
                    })
                    .map(|_| ())
                    .map_err(networks_error)
            }),
        }
    }

    /// Whether there are no networks.
    pub fn is_empty(&self) -> Result<bool, Error> {
        let mut empty = true;

        self.for_each(&mut |_| {
            empty = false;
            Ok(())
        })?;

        Ok(empty)
    }
}

impl<'a, T> FromTLV<'a> for HandoverNetworks<'a, T>
where
    T: HandoverNetwork + 'a,
{
    fn from_tlv(element: &TLVElement<'a>) -> Result<Self, Error> {
        Ok(Self {
            source: NetworksSource::Tlv(
                TLVArray::<T::Borrowed<'a>>::new(element.clone())?
                    .element()
                    .clone(),
            ),
            _kind: PhantomData,
        })
    }
}

impl<'a, T> ToTLV for HandoverNetworks<'a, T>
where
    T: HandoverNetwork + ToTLV,
{
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, mut tw: W) -> Result<(), Error> {
        tw.start_array(tag)?;

        self.for_each(&mut |creds| {
            // `for_each` only yields networks of kind `T`
            let network = unwrap!(T::from_creds(creds));

            network.to_tlv(&TLVTag::Anonymous, &mut tw)
        })?;

        tw.end_container()
    }

    fn tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<TLV<'_>, Error>> {
        match &self.source {
            NetworksSource::Tlv(element) => {
                EitherIter::First(EitherIter::First(element.tlv_iter(tag)))
            }
            NetworksSource::Slice(slice) => {
                EitherIter::First(EitherIter::Second(slice.tlv_iter(tag)))
            }
            // Callbacks cannot drive an iterator; use `to_tlv`
            NetworksSource::Store(_) => {
                EitherIter::Second(core::iter::once(Err(ErrorCode::InvalidState.into())))
            }
        }
    }
}

impl<T> Debug for HandoverNetworks<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.source {
            NetworksSource::Tlv(element) => f.debug_tuple("Tlv").field(element).finish(),
            NetworksSource::Slice(slice) => f.debug_tuple("Slice").field(&slice.len()).finish(),
            NetworksSource::Store(_) => f.debug_tuple("Store").finish(),
        }
    }
}

#[cfg(feature = "defmt")]
impl<T> defmt::Format for HandoverNetworks<'_, T> {
    fn format(&self, f: defmt::Formatter<'_>) {
        match &self.source {
            NetworksSource::Tlv(element) => defmt::write!(f, "Tlv({})", element),
            NetworksSource::Slice(slice) => defmt::write!(f, "Slice({})", slice.len()),
            NetworksSource::Store(_) => defmt::write!(f, "Store"),
        }
    }
}

/// The regulatory configuration, as set by `SetRegulatoryConfig`.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct HandoverRegulatory<'a> {
    /// Two-letter ISO 3166-1 country code.
    pub country_code: Utf8Str<'a>,
    pub location_type: RegulatoryLocationTypeEnum,
}

/// The commissioning handover envelope.
///
/// Needed for NFC (NTL) commissioning, where phase 1 - PASE, `ArmFailSafe`,
/// `AddNOC`, the ACL writes, `AddOrUpdate*Network` - runs on the NFC subsystem
/// with the main CPU off, and phase 2 - operational discovery, CASE,
/// `CommissioningComplete` - runs on the host once it boots. The outcome of
/// phase 1 travels between the two as a [`CommissioningHandover`]: a
/// versioned TLV envelope, mostly made of spec-defined TLV, so a vendor NFC
/// stack can produce it without `rs-matter`.
///
/// # Security
///
/// The envelope carries the node's operational private key, the IPK and the
/// network credentials. The channel it travels over is the security boundary.
#[derive(Debug, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct CommissioningHandover<'a> {
    pub version: u8,
    pub root_ca: OctetStr<'a>,
    pub icac: Option<OctetStr<'a>>,
    pub noc: OctetStr<'a>,
    pub secret_key: CanonPkcSecretKey,
    pub ipk: CanonAeadKey,
    pub admin_vendor_id: u16,
    pub label: Utf8Str<'a>,
    /// `FabricIndex` is ignored on import.
    pub acl: TLVArrayOrSlice<'a, AclEntry>,
    pub wifi_networks: HandoverNetworks<'a, HandoverWifi<'a>>,
    pub thread_networks: HandoverNetworks<'a, HandoverThread<'a>>,
    pub regulatory: Option<HandoverRegulatory<'a>>,
    pub fail_safe_remaining_secs: u16,
    pub breadcrumb: u64,
}

impl CommissioningHandover<'_> {
    /// Structural validation: version, non-empty ACL, well-formed regulatory
    /// config. Certificates and keys are checked on import.
    pub fn validate(&self) -> Result<(), Error> {
        if self.version != HANDOVER_VERSION {
            error!(
                "Unsupported commissioning handover version {} (expected {})",
                self.version, HANDOVER_VERSION
            );
            Err(ErrorCode::InvalidData)?;
        }

        if self.acl.iter()?.next().is_none() {
            error!("Commissioning handover carries no ACL entries");
            Err(ErrorCode::InvalidData)?;
        }

        if let Some(regulatory) = &self.regulatory {
            if regulatory.country_code.len() != 2 {
                error!("Commissioning handover carries an invalid country code");
                Err(ErrorCode::InvalidData)?;
            }
        }

        Ok(())
    }

    /// Build the envelope for the pending `fabric` and hand it to `f`.
    ///
    /// A callback rather than a constructor because the envelope borrows the
    /// networks store, reachable only inside [`NetworksAccess::access`].
    pub(crate) fn with_pending<N, F, R>(
        fabric: &Fabric,
        networks: N,
        regulatory: Option<HandoverRegulatory<'_>>,
        fail_safe_remaining_secs: u16,
        breadcrumb: u64,
        f: F,
    ) -> Result<R, Error>
    where
        N: NetworksAccess,
        F: FnOnce(&CommissioningHandover<'_>) -> Result<R, Error>,
    {
        networks.access(|networks| {
            let networks: &dyn Networks = networks;

            let handover = CommissioningHandover {
                version: HANDOVER_VERSION,
                root_ca: Octets(fabric.root_ca()),
                icac: (!fabric.icac().is_empty()).then(|| Octets(fabric.icac())),
                noc: Octets(fabric.noc()),
                secret_key: CanonPkcSecretKey::new_from_ref(fabric.secret_key()),
                ipk: CanonAeadKey::new_from_ref(fabric.ipk().epoch_key()),
                admin_vendor_id: fabric.vendor_id(),
                label: fabric.label(),
                acl: TLVArrayOrSlice::new_slice(fabric.acl()),
                wifi_networks: HandoverNetworks::from_store(networks),
                thread_networks: HandoverNetworks::from_store(networks),
                regulatory,
                fail_safe_remaining_secs,
                breadcrumb,
            };

            f(&handover)
        })
    }
}

/// Stage the networks of `handover` into `networks`, as `AddOrUpdate*Network`
/// would.
pub(crate) fn stage_networks<N>(
    handover: &CommissioningHandover<'_>,
    networks: N,
) -> Result<(), Error>
where
    N: NetworksAccess,
{
    networks.access(|networks| {
        let mut staged = false;

        let mut stage = |creds: &WirelessCreds<'_>| {
            networks.add_or_update(creds).map_err(networks_error)?;
            staged = true;

            Ok(())
        };

        handover.wifi_networks.for_each(&mut stage)?;
        handover.thread_networks.for_each(&mut stage)?;

        // No `ConnectNetwork` will follow: the node must connect by itself,
        // so hand the store to the connectivity manager right away
        if staged {
            networks.set_managed(true)?;
        }

        Ok(())
    })
}

fn networks_error(err: NetworksError) -> Error {
    match err {
        NetworksError::Other(err) => err,
        NetworksError::NetworkIdNotFound => ErrorCode::NotFound.into(),
        NetworksError::DuplicateNetworkId
        | NetworksError::OutOfRange
        | NetworksError::BoundsExceeded => ErrorCode::InvalidData.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::acl::{AuthMode, Target};
    use crate::dm::Privilege;
    use crate::utils::storage::WriteBuf;

    fn collect_acl<const N: usize>(
        acl: &TLVArrayOrSlice<'_, AclEntry>,
    ) -> heapless::Vec<AclEntry, N> {
        acl.iter().unwrap().map(|item| item.unwrap()).collect()
    }

    /// The network IDs of all networks, in order.
    fn collect_network_ids<T: HandoverNetwork, const N: usize>(
        networks: &HandoverNetworks<'_, T>,
    ) -> heapless::Vec<heapless::Vec<u8, 64>, N> {
        let mut collected = heapless::Vec::new();

        networks
            .for_each(&mut |creds| {
                collected
                    .push(heapless::Vec::from_slice(creds.id()?).unwrap())
                    .map_err(|_| ErrorCode::ResourceExhausted)?;
                Ok(())
            })
            .unwrap();

        collected
    }

    #[test]
    fn round_trip() {
        let mut admin = AclEntry::new(None, Privilege::ADMIN, AuthMode::Case);
        admin.add_subject(112233).unwrap();

        let mut operate = AclEntry::new(None, Privilege::OPERATE, AuthMode::Case);
        operate.add_subject(0xFFFF_FFFD_0001_0001).unwrap();
        operate
            .add_target(Target::new(Some(1), None, None))
            .unwrap();

        let acl = [admin, operate];
        let wifi = [HandoverWifi {
            ssid: Octets(b"home"),
            credentials: Octets(b"secret"),
        }];
        // Just an Extended PAN ID TLV
        let thread = [HandoverThread {
            operational_dataset: Octets(&[0x02, 0x08, 1, 2, 3, 4, 5, 6, 7, 8]),
        }];

        let handover = CommissioningHandover {
            version: HANDOVER_VERSION,
            root_ca: Octets(&[1, 2, 3]),
            icac: None,
            noc: Octets(&[4, 5, 6]),
            secret_key: CanonPkcSecretKey::from([7u8; 32]),
            ipk: CanonAeadKey::from([8u8; 16]),
            admin_vendor_id: 0xfff1,
            label: "lab",
            acl: TLVArrayOrSlice::new_slice(&acl),
            wifi_networks: HandoverNetworks::from_slice(&wifi),
            thread_networks: HandoverNetworks::from_slice(&thread),
            regulatory: Some(HandoverRegulatory {
                country_code: "BG",
                location_type: RegulatoryLocationTypeEnum::IndoorOutdoor,
            }),
            fail_safe_remaining_secs: 42,
            breadcrumb: 7,
        };

        let mut buf = [0u8; 512];
        let mut wb = WriteBuf::new(&mut buf);
        handover.to_tlv(&TLVTag::Anonymous, &mut wb).unwrap();
        let len = wb.get_tail();

        let parsed = CommissioningHandover::from_tlv(&TLVElement::new(&buf[..len])).unwrap();
        parsed.validate().unwrap();

        assert_eq!(parsed.version, HANDOVER_VERSION);
        assert_eq!(parsed.root_ca.0, &[1, 2, 3]);
        assert!(parsed.icac.is_none());
        assert_eq!(parsed.noc.0, &[4, 5, 6]);
        assert_eq!(parsed.secret_key.access(), &[7u8; 32]);
        assert_eq!(parsed.ipk.access(), &[8u8; 16]);
        assert_eq!(parsed.admin_vendor_id, 0xfff1);
        assert_eq!(parsed.label, "lab");
        assert_eq!(parsed.fail_safe_remaining_secs, 42);
        assert_eq!(parsed.breadcrumb, 7);
        assert_eq!(parsed.regulatory.unwrap().country_code, "BG");
        assert_eq!(collect_acl::<4>(&parsed.acl).as_slice(), &acl);

        let wifi_ids = collect_network_ids::<_, 2>(&parsed.wifi_networks);
        assert_eq!(wifi_ids.len(), 1);
        assert_eq!(wifi_ids[0], b"home");

        let thread_ids = collect_network_ids::<_, 2>(&parsed.thread_networks);
        assert_eq!(thread_ids.len(), 1);
        assert_eq!(thread_ids[0], &[1, 2, 3, 4, 5, 6, 7, 8]);

        // `tlv_iter` must agree with `to_tlv`
        let mut buf2 = [0u8; 512];
        let mut wb2 = WriteBuf::new(&mut buf2);
        for tlv in handover.tlv_iter(TLVTag::Anonymous) {
            let tlv = tlv.unwrap();
            wb2.tlv(&tlv.tag, &tlv.value).unwrap();
        }
        let len2 = wb2.get_tail();
        assert_eq!(&buf[..len], &buf2[..len2]);
    }

    #[test]
    fn rejects_empty_acl_and_bad_version() {
        let handover = CommissioningHandover {
            version: HANDOVER_VERSION + 1,
            root_ca: Octets(&[]),
            icac: None,
            noc: Octets(&[]),
            secret_key: CanonPkcSecretKey::new(),
            ipk: CanonAeadKey::new(),
            admin_vendor_id: 0,
            label: "",
            acl: TLVArrayOrSlice::new_slice(&[]),
            wifi_networks: HandoverNetworks::from_slice(&[]),
            thread_networks: HandoverNetworks::from_slice(&[]),
            regulatory: None,
            fail_safe_remaining_secs: 0,
            breadcrumb: 0,
        };

        assert!(handover.validate().is_err());

        let handover = CommissioningHandover {
            version: HANDOVER_VERSION,
            ..handover
        };
        assert!(handover.validate().is_err());

        let admin = [AclEntry::new(None, Privilege::ADMIN, AuthMode::Case)];
        let handover = CommissioningHandover {
            acl: TLVArrayOrSlice::new_slice(&admin),
            ..handover
        };
        assert!(handover.validate().is_ok());
        assert!(handover.wifi_networks.is_empty().unwrap());
    }
}
