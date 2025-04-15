/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
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
use core::mem::MaybeUninit;
use core::num::NonZeroU8;

use heapless::String;

use crate::acl::{self, AccessReq, AclEntry, AuthMode};
use crate::cert::{CertRef, MAX_CERT_TLV_LEN};
use crate::crypto::{self, hkdf_sha256, HmacSha256, KeyPair};
use crate::data_model::objects::Privilege;
use crate::error::{Error, ErrorCode};
use crate::group_keys::KeySet;
use crate::mdns::{Mdns, ServiceMode};
use crate::tlv::{FromTLV, OctetStr, TLVElement, TLVTag, TLVWrite, TagType, ToTLV, UtfStr};
use crate::utils::init::{init, Init, InitMaybeUninit, IntoFallibleInit};
use crate::utils::storage::{Vec, WriteBuf};

const COMPRESSED_FABRIC_ID_LEN: usize = 8;

#[derive(Debug, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a", start = 1)]
pub struct FabricDescriptor<'a> {
    root_public_key: OctetStr<'a>,
    vendor_id: u16,
    fabric_id: u64,
    node_id: u64,
    label: UtfStr<'a>,
    // TODO: Instead of the direct value, we should consider GlobalElements::FabricIndex
    #[tagval(0xFE)]
    pub fab_idx: NonZeroU8,
}

/// Fabric type
#[derive(Debug, ToTLV, FromTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Fabric {
    /// Fabric local index
    fab_idx: NonZeroU8,
    /// Fabric node ID
    node_id: u64,
    /// Fabric ID
    fabric_id: u64,
    /// Vendor ID
    vendor_id: u16,
    /// Fabric key pair
    key_pair: KeyPair,
    /// Root CA certificate to be used when verifying the node's certificate
    ///
    /// Note that we deviate from the Matter spec here, in that we store the
    /// root certificate in the Fabric type itself, rather than - as the
    /// spec mandates - in a separate Root CA store
    ///
    /// This simplifies the implementation, but results in potentially multiple
    /// copies of the same Root CA used accross multiple fabrics.
    root_ca: Vec<u8, { MAX_CERT_TLV_LEN }>,
    /// Intermediate CA certificate
    icac: Vec<u8, { MAX_CERT_TLV_LEN }>,
    /// Node Operational Certificate
    noc: Vec<u8, { MAX_CERT_TLV_LEN }>,
    /// Intermediate Public Key
    ipk: KeySet,
    /// Fabric label; unique accross all fabrics on the device
    label: String<32>,
    /// Fabric mDNS service name
    mdns_service_name: String<33>,
    /// Access Control List
    acl: Vec<AclEntry, { acl::ENTRIES_PER_FABRIC }>,
}

impl Fabric {
    /// Return an in-place-initializer for a Fabric type, with the
    /// provided Fabric Index and KeyPair
    ///
    /// All other fields are initialized to default values, which are NOT
    /// valid for the operation of the fabric.
    ///
    /// The Fabric must be updated with the correct values before it can be
    /// used, via `Fabric::update`.
    fn init(fab_idx: NonZeroU8, key_pair: KeyPair) -> impl Init<Self> {
        init!(Self {
            fab_idx,
            node_id: 0,
            fabric_id: 0,
            vendor_id: 0,
            key_pair,
            root_ca <- Vec::init(),
            icac <- Vec::init(),
            noc <- Vec::init(),
            ipk <- KeySet::init(),
            label: String::new(),
            mdns_service_name: String::new(),
            acl <- Vec::init(),
        })
    }

    /// Update the fabric with the provided data so that it can operate.
    ///
    /// This method is supposed to be called right after `Fabric::init` or
    /// when the NOC of the fabric needs to be updated.
    #[allow(clippy::too_many_arguments)]
    fn update(
        &mut self,
        root_ca: &[u8],
        noc: &[u8],
        icac: &[u8],
        ipk: &[u8],
        vendor_id: u16,
        case_admin_subject: Option<u64>,
        mdns: &dyn Mdns,
    ) -> Result<(), Error> {
        if !self.mdns_service_name.is_empty() {
            mdns.remove(&self.mdns_service_name)?;
        }

        self.root_ca
            .extend_from_slice(root_ca)
            .map_err(|_| ErrorCode::NoSpace)?;
        self.icac
            .extend_from_slice(icac)
            .map_err(|_| ErrorCode::NoSpace)?;
        self.noc
            .extend_from_slice(noc)
            .map_err(|_| ErrorCode::NoSpace)?;

        let noc_p = CertRef::new(TLVElement::new(noc));

        self.node_id = noc_p.get_node_id()?;
        self.fabric_id = noc_p.get_fabric_id()?;
        self.vendor_id = vendor_id;

        let root_ca_p = CertRef::new(TLVElement::new(root_ca));

        let mut compressed_id = [0_u8; COMPRESSED_FABRIC_ID_LEN];
        Fabric::compute_compressed_id(root_ca_p.pubkey()?, self.fabric_id, &mut compressed_id)?;

        self.ipk = KeySet::new(ipk, &compressed_id)?;

        self.mdns_service_name.clear();
        for c in compressed_id {
            let mut hex = heapless::String::<4>::new();
            write_unwrap!(&mut hex, "{:02X}", c);
            unwrap!(self.mdns_service_name.push_str(&hex));
        }
        unwrap!(self.mdns_service_name.push('-'));
        for c in self.node_id.to_be_bytes() {
            let mut hex = heapless::String::<4>::new();
            write_unwrap!(&mut hex, "{:02X}", c);
            unwrap!(self.mdns_service_name.push_str(&hex));
        }

        info!("mDNS Service name: {}", self.mdns_service_name);

        mdns.add(&self.mdns_service_name, ServiceMode::Commissioned)?;

        if let Some(case_admin_subject) = case_admin_subject {
            self.acl.clear();
            self.acl.push_init(
                AclEntry::init(None, Privilege::ADMIN, AuthMode::Case)
                    .into_fallible()
                    .chain(|e| {
                        e.fab_idx = Some(self.fab_idx);
                        e.add_subject(case_admin_subject)
                    }),
                || ErrorCode::NoSpace.into(),
            )?;
        }

        Ok(())
    }

    /// Is the fabric matching the privided destination ID
    pub fn is_dest_id(&self, random: &[u8], target: &[u8]) -> Result<(), Error> {
        let mut mac = HmacSha256::new(self.ipk.op_key())?;

        mac.update(random)?;
        mac.update(CertRef::new(TLVElement::new(self.root_ca())).pubkey()?)?;

        mac.update(&self.fabric_id.to_le_bytes())?;
        mac.update(&self.node_id.to_le_bytes())?;

        let mut id = MaybeUninit::<[u8; crypto::SHA256_HASH_LEN_BYTES]>::uninit(); // TODO MEDIUM BUFFER
        let id = id.init_zeroed();
        mac.finish(id)?;
        if id.as_slice() == target {
            Ok(())
        } else {
            Err(ErrorCode::NotFound.into())
        }
    }

    /// Sign a message with the fabric's key pair
    pub fn sign_msg(&self, msg: &[u8], signature: &mut [u8]) -> Result<usize, Error> {
        self.key_pair.sign_msg(msg, signature)
    }

    /// Return the key pair of the fabric
    pub fn key_pair(&self) -> &KeyPair {
        &self.key_pair
    }

    /// Return the fabric's node ID
    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    /// Return the fabric's fabric ID
    pub fn fabric_id(&self) -> u64 {
        self.fabric_id
    }

    /// Return the fabric's local index
    pub fn fab_idx(&self) -> NonZeroU8 {
        self.fab_idx
    }

    /// Return the fabric's Root CA in encoded TLV form
    ///
    /// Use `CertRef` to decode on the fly
    pub fn root_ca(&self) -> &[u8] {
        &self.root_ca
    }

    /// Return the fabric's ICAC in encoded TLV form
    ///
    /// Use `CertRef` to decode on the fly.
    ///
    /// Note that this method might return an empty slice,
    /// which indicates that this fabric does not have an ICAC.
    pub fn icac(&self) -> &[u8] {
        &self.icac
    }

    /// Return the fabric's NOC
    pub fn noc(&self) -> &[u8] {
        &self.noc
    }

    /// Return the fabric's IPK
    pub fn ipk(&self) -> &KeySet {
        &self.ipk
    }

    /// Return the fabric's descriptor
    pub fn descriptor<'a>(
        &'a self,
        root_ca_cert: &'a CertRef<'a>,
    ) -> Result<FabricDescriptor<'a>, Error> {
        let desc = FabricDescriptor {
            root_public_key: OctetStr::new(root_ca_cert.pubkey()?),
            vendor_id: self.vendor_id,
            fabric_id: self.fabric_id,
            node_id: self.node_id,
            label: self.label.as_str(),
            fab_idx: self.fab_idx,
        };

        Ok(desc)
    }

    /// Return an iterator over the ACL entries of the fabric
    pub fn acl_iter(&self) -> impl Iterator<Item = &AclEntry> {
        self.acl.iter()
    }

    /// Add a new ACL entry to the fabric.
    ///
    /// Return the index of the added entry.
    fn acl_add(&mut self, mut entry: AclEntry) -> Result<usize, Error> {
        if entry.auth_mode() == AuthMode::Pase {
            // Reserved for future use
            Err(ErrorCode::ConstraintError)?;
        }

        // Overwrite the fabric index with our accessing fabric index
        entry.fab_idx = Some(self.fab_idx);

        self.acl.push(entry).map_err(|_| ErrorCode::NoSpace)?;

        Ok(self.acl.len() - 1)
    }

    /// Update an existing ACL entry in the fabric
    fn acl_update(&mut self, idx: usize, mut entry: AclEntry) -> Result<(), Error> {
        if self.acl.len() <= idx {
            return Err(ErrorCode::NotFound.into());
        }

        // Overwrite the fabric index with our accessing fabric index
        entry.fab_idx = Some(self.fab_idx);

        self.acl[idx] = entry;

        Ok(())
    }

    /// Remove an ACL entry from the fabric
    fn acl_remove(&mut self, idx: usize) -> Result<(), Error> {
        if self.acl.len() <= idx {
            return Err(ErrorCode::NotFound.into());
        }

        self.acl.remove(idx);

        Ok(())
    }

    /// Remove all ACL entries from the fabric
    pub fn acl_remove_all(&mut self) {
        // pub for tests
        self.acl.clear();
    }

    /// Check if the fabric allows the given access request
    ///
    /// Note that the fabric index in the access request needs to be checked before that.
    fn allow(&self, req: &AccessReq) -> bool {
        for e in &self.acl {
            if e.allow(req) {
                return true;
            }
        }

        error!(
            "ACL Disallow for subjects {} fab idx {}",
            req.accessor().subjects(),
            req.accessor().fab_idx
        );

        false
    }

    /// Compute the compressed fabric ID
    fn compute_compressed_id(
        root_pubkey: &[u8],
        fabric_id: u64,
        out: &mut [u8],
    ) -> Result<(), Error> {
        let root_pubkey = &root_pubkey[1..];
        const COMPRESSED_FABRIC_ID_INFO: [u8; 16] = [
            0x43, 0x6f, 0x6d, 0x70, 0x72, 0x65, 0x73, 0x73, 0x65, 0x64, 0x46, 0x61, 0x62, 0x72,
            0x69, 0x63,
        ];
        hkdf_sha256(
            &fabric_id.to_be_bytes(),
            root_pubkey,
            &COMPRESSED_FABRIC_ID_INFO,
            out,
        )
        .map_err(|_| Error::from(ErrorCode::NoSpace))
    }
}

/// Max number of supported fabrics
// TODO: Make this configurable via a cargo feature
pub const MAX_SUPPORTED_FABRICS: usize = 3;

/// Fabric manager type
pub struct FabricMgr {
    fabrics: Vec<Fabric, MAX_SUPPORTED_FABRICS>,
    changed: bool,
}

impl Default for FabricMgr {
    fn default() -> Self {
        Self::new()
    }
}

impl FabricMgr {
    /// Create a new Fabric Manager
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            fabrics: Vec::new(),
            changed: false,
        }
    }

    /// Return an in-place-initializer for a Fabric Manager
    pub fn init() -> impl Init<Self> {
        init!(Self {
            fabrics <- Vec::init(),
            changed: false,
        })
    }

    /// Removes all fabrics
    pub fn reset(&mut self) {
        self.fabrics.clear();
        self.changed = false;
    }

    /// Load the fabrics from the provided TLV data
    pub fn load(&mut self, data: &[u8], mdns: &dyn Mdns) -> Result<(), Error> {
        for fabric in self.iter() {
            mdns.remove(&fabric.mdns_service_name)?;
        }

        self.fabrics.clear();

        for entry in TLVElement::new(data).array()?.iter() {
            let entry = entry?;

            self.fabrics
                .push_init(Fabric::init_from_tlv(entry), || ErrorCode::NoSpace.into())?;
        }

        for fabric in &self.fabrics {
            mdns.add(&fabric.mdns_service_name, ServiceMode::Commissioned)?;
        }

        self.changed = false;

        Ok(())
    }

    /// Store the fabrics into the provided buffer as TLV data
    ///
    /// If the fabrics have not changed since the last store operation, the
    /// function returns `None` and does not store the fabrics.
    pub fn store<'a>(&mut self, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, Error> {
        if !self.changed {
            return Ok(None);
        }

        let mut wb = WriteBuf::new(buf);

        wb.start_array(&TLVTag::Anonymous)?;

        for fabric in self.iter() {
            fabric
                .to_tlv(&TagType::Anonymous, &mut wb)
                .map_err(|_| ErrorCode::NoSpace)?;
        }

        wb.end_container()?;

        self.changed = false;

        let len = wb.get_tail();

        Ok(Some(&buf[..len]))
    }

    /// Check if the fabrics have changed since the last store operation
    pub fn is_changed(&self) -> bool {
        self.changed
    }

    /// Add a new fabric to the manager with the provided data and immediately updates it with the provided post-init updater.
    ///
    /// This method is unlikely to be useful outside of tests.
    ///
    /// If this operation succeeds, the fabric immediately becomes operational.
    pub fn add_with_post_init<F>(
        &mut self,
        key_pair: KeyPair,
        post_init: F,
    ) -> Result<&mut Fabric, Error>
    where
        F: FnOnce(&mut Fabric) -> Result<(), Error>,
    {
        let max_fab_idx = self
            .iter()
            .map(|fabric| fabric.fab_idx().get())
            .max()
            .unwrap_or(0);
        let fab_idx = unwrap!(NonZeroU8::new(if max_fab_idx < u8::MAX - 1 {
            // First try with the next available fabric index larger than all currently used
            max_fab_idx + 1
        } else {
            // If there is already a fabric with index 254, try to find the first unused one
            let Some(fab_idx) = (1..u8::MAX)
                .find(|fab_idx| self.iter().all(|fabric| fabric.fab_idx().get() != *fab_idx))
            else {
                return Err(ErrorCode::NoSpace.into());
            };

            fab_idx
        })); // We never use 0 as a fabric index, nor u8::MAX

        self.fabrics.push_init(
            Fabric::init(fab_idx, key_pair)
                .into_fallible::<Error>()
                .chain(post_init),
            || ErrorCode::NoSpace.into(),
        )?;

        let fabric = unwrap!(self.fabrics.last_mut());
        self.changed = true;

        Ok(fabric)
    }

    /// Add a new fabric to the manager with the provided data.
    ///
    /// If this operation succeeds, the fabric immediately becomes operational.
    #[allow(clippy::too_many_arguments)]
    pub fn add(
        &mut self,
        key_pair: KeyPair,
        root_ca: &[u8],
        noc: &[u8],
        icac: &[u8],
        ipk: &[u8],
        vendor_id: u16,
        case_admin_subject: u64,
        mdns: &dyn Mdns,
    ) -> Result<&mut Fabric, Error> {
        self.add_with_post_init(key_pair, |fabric| {
            fabric.update(
                root_ca,
                noc,
                icac,
                ipk,
                vendor_id,
                Some(case_admin_subject),
                mdns,
            )
        })
    }

    /// Update an existing fabric with the provided data (usually, as a result of an `UpdateNOC` IM command).
    ///
    /// If this operation succeeds, the fabric immediately becomes operational.
    /// Note however, that the caller is expected to remove all sessions associated with the fabric, as they would
    /// contain invalid keys after the NOC update.
    #[allow(clippy::too_many_arguments)]
    pub fn update(
        &mut self,
        fab_idx: NonZeroU8,
        key_pair: KeyPair,
        root_ca: &[u8],
        noc: &[u8],
        icac: &[u8],
        ipk: &[u8],
        vendor_id: u16,
        mdns: &dyn Mdns,
    ) -> Result<&mut Fabric, Error> {
        let Some(fabric) = self
            .fabrics
            .iter_mut()
            .find(|fabric| fabric.fab_idx == fab_idx)
        else {
            return Err(ErrorCode::NotFound.into());
        };

        fabric.key_pair = key_pair;

        fabric.update(root_ca, noc, icac, ipk, vendor_id, None, mdns)?;

        self.changed = true;

        Ok(fabric)
    }

    pub fn update_label(&mut self, fab_idx: NonZeroU8, label: &str) -> Result<(), Error> {
        if self.iter().any(|fabric| {
            fabric.fab_idx != fab_idx && !fabric.label.is_empty() && fabric.label == label
        }) {
            return Err(ErrorCode::Invalid.into());
        }

        let fabric = self.get_mut(fab_idx).ok_or(ErrorCode::NotFound)?;
        fabric.label.clear();
        fabric
            .label
            .push_str(label)
            .map_err(|_| ErrorCode::NoSpace)?;

        Ok(())
    }

    /// Remove a fabric from the manager
    pub fn remove(&mut self, fab_idx: NonZeroU8, mdns: &dyn Mdns) -> Result<(), Error> {
        let Some(fabric) = self.get(fab_idx) else {
            return Ok(());
        };

        mdns.remove(&fabric.mdns_service_name)?;

        self.fabrics.retain(|fabric| fabric.fab_idx != fab_idx);

        Ok(())
    }

    /// Get a fabric that matches the provided destination ID
    pub fn get_by_dest_id(&self, random: &[u8], target: &[u8]) -> Option<&Fabric> {
        self.iter()
            .find(|fabric| fabric.is_dest_id(random, target).is_ok())
    }

    /// Get a fabric by its local index
    pub fn get(&self, fab_idx: NonZeroU8) -> Option<&Fabric> {
        self.iter().find(|fabric| fabric.fab_idx == fab_idx)
    }

    /// Get a mutable fabric reference by its local index
    pub fn get_mut(&mut self, fab_idx: NonZeroU8) -> Option<&mut Fabric> {
        // pub for testing
        self.fabrics
            .iter_mut()
            .find(|fabric| fabric.fab_idx == fab_idx)
    }

    /// Iterate over the fabrics
    pub fn iter(&self) -> impl Iterator<Item = &Fabric> {
        self.fabrics.iter()
    }

    /// Check if the given access request should be allowed, based on all operational fabrics
    /// and their ACLs
    pub fn allow(&self, req: &AccessReq) -> bool {
        // PASE Sessions with no fabric index have implicit access grant,
        // but only as long as the ACL list is empty
        //
        // As per the spec:
        // The Access Control List is able to have an initial entry added because the Access Control Privilege
        // Granting algorithm behaves as if, over a PASE commissioning channel during the commissioning
        // phase, the following implicit Access Control Entry were present on the Commissionee (but not on
        // the Commissioner):
        // Access Control Cluster: {
        //     ACL: [
        //         0: {
        //             // implicit entry only; does not explicitly exist!
        //             FabricIndex: 0, // not fabric-specific
        //             Privilege: Administer,
        //             AuthMode: PASE,
        //             Subjects: [],
        //             Targets: [] // entire node
        //         }
        //     ],
        //     Extension: []
        // }
        if req.accessor().auth_mode() == AuthMode::Pase {
            return true;
        }

        let Some(fab_idx) = NonZeroU8::new(req.accessor().fab_idx) else {
            return false;
        };

        let Some(fabric) = self.get(fab_idx) else {
            return false;
        };

        fabric.allow(req)
    }

    /// Add a new ACL entry to the fabric with the provided local index
    ///
    /// Return the index of the added entry.
    pub fn acl_add(&mut self, fab_idx: NonZeroU8, entry: AclEntry) -> Result<usize, Error> {
        let index = self
            .get_mut(fab_idx)
            .ok_or(ErrorCode::NotFound)?
            .acl_add(entry)?;
        self.changed = true;

        Ok(index)
    }

    /// Update an existing ACL entry in the fabric with the provided local index
    pub fn acl_update(
        &mut self,
        fab_idx: NonZeroU8,
        idx: usize,
        entry: AclEntry,
    ) -> Result<(), Error> {
        self.get_mut(fab_idx)
            .ok_or(ErrorCode::NotFound)?
            .acl_update(idx, entry)?;
        self.changed = true;

        Ok(())
    }

    /// Remove an ACL entry from the fabric with the provided local index
    pub fn acl_remove(&mut self, fab_idx: NonZeroU8, idx: usize) -> Result<(), Error> {
        self.get_mut(fab_idx)
            .ok_or(ErrorCode::NotFound)?
            .acl_remove(idx)?;
        self.changed = true;

        Ok(())
    }

    /// Remove all ACL entries from the fabric with the provided local index
    pub fn acl_remove_all(&mut self, fab_idx: NonZeroU8) -> Result<(), Error> {
        self.get_mut(fab_idx)
            .ok_or(ErrorCode::NotFound)?
            .acl_remove_all();
        self.changed = true;

        Ok(())
    }
}
