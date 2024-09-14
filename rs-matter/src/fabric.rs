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
use core::num::NonZeroU8;

use byteorder::{BigEndian, ByteOrder, LittleEndian};

use heapless::String;

use log::info;

use crate::cert::{Cert, MAX_CERT_TLV_LEN};
use crate::crypto::{self, hkdf_sha256, HmacSha256, KeyPair};
use crate::error::{Error, ErrorCode};
use crate::group_keys::KeySet;
use crate::mdns::{Mdns, ServiceMode};
use crate::tlv::{self, FromTLV, OctetStr, TLVList, TLVWriter, TagType, ToTLV, UtfStr};
use crate::utils::init::{init, Init};
use crate::utils::storage::{Vec, WriteBuf};

const COMPRESSED_FABRIC_ID_LEN: usize = 8;

#[derive(Debug, ToTLV)]
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

#[derive(Debug, ToTLV, FromTLV)]
pub struct Fabric {
    node_id: u64,
    fabric_id: u64,
    vendor_id: u16,
    key_pair: KeyPair,
    pub root_ca: Vec<u8, { MAX_CERT_TLV_LEN }>,
    pub icac: Option<Vec<u8, { MAX_CERT_TLV_LEN }>>,
    pub noc: Vec<u8, { MAX_CERT_TLV_LEN }>,
    pub ipk: KeySet,
    label: String<32>,
    mdns_service_name: String<33>,
}

impl Fabric {
    pub fn new(
        key_pair: KeyPair,
        root_ca: Vec<u8, { MAX_CERT_TLV_LEN }>,
        icac: Option<Vec<u8, { MAX_CERT_TLV_LEN }>>,
        noc: Vec<u8, { MAX_CERT_TLV_LEN }>,
        ipk: &[u8],
        vendor_id: u16,
        label: &str,
    ) -> Result<Self, Error> {
        let (node_id, fabric_id) = {
            let noc_p = Cert::new(&noc)?;
            (noc_p.get_node_id()?, noc_p.get_fabric_id()?)
        };

        let mut compressed_id = [0_u8; COMPRESSED_FABRIC_ID_LEN];

        let ipk = {
            let root_ca_p = Cert::new(&root_ca)?;
            Fabric::get_compressed_id(root_ca_p.get_pubkey(), fabric_id, &mut compressed_id)?;
            KeySet::new(ipk, &compressed_id)?
        };

        let mut mdns_service_name = heapless::String::<33>::new();
        for c in compressed_id {
            let mut hex = heapless::String::<4>::new();
            write!(&mut hex, "{:02X}", c).unwrap();
            mdns_service_name.push_str(&hex).unwrap();
        }
        mdns_service_name.push('-').unwrap();
        let mut node_id_be: [u8; 8] = [0; 8];
        BigEndian::write_u64(&mut node_id_be, node_id);
        for c in node_id_be {
            let mut hex = heapless::String::<4>::new();
            write!(&mut hex, "{:02X}", c).unwrap();
            mdns_service_name.push_str(&hex).unwrap();
        }
        info!("MDNS Service Name: {}", mdns_service_name);

        Ok(Self {
            node_id,
            fabric_id,
            vendor_id,
            key_pair,
            root_ca,
            icac,
            noc,
            ipk,
            label: label.try_into().unwrap(),
            mdns_service_name,
        })
    }

    fn get_compressed_id(root_pubkey: &[u8], fabric_id: u64, out: &mut [u8]) -> Result<(), Error> {
        let root_pubkey = &root_pubkey[1..];
        let mut fabric_id_be: [u8; 8] = [0; 8];
        BigEndian::write_u64(&mut fabric_id_be, fabric_id);
        const COMPRESSED_FABRIC_ID_INFO: [u8; 16] = [
            0x43, 0x6f, 0x6d, 0x70, 0x72, 0x65, 0x73, 0x73, 0x65, 0x64, 0x46, 0x61, 0x62, 0x72,
            0x69, 0x63,
        ];
        hkdf_sha256(&fabric_id_be, root_pubkey, &COMPRESSED_FABRIC_ID_INFO, out)
            .map_err(|_| Error::from(ErrorCode::NoSpace))
    }

    pub fn match_dest_id(&self, random: &[u8], target: &[u8]) -> Result<(), Error> {
        let mut mac = HmacSha256::new(self.ipk.op_key())?;

        mac.update(random)?;
        mac.update(self.get_root_ca()?.get_pubkey())?;

        let mut buf: [u8; 8] = [0; 8];
        LittleEndian::write_u64(&mut buf, self.fabric_id);
        mac.update(&buf)?;

        LittleEndian::write_u64(&mut buf, self.node_id);
        mac.update(&buf)?;

        let mut id = [0_u8; crypto::SHA256_HASH_LEN_BYTES];
        mac.finish(&mut id)?;
        if id.as_slice() == target {
            Ok(())
        } else {
            Err(ErrorCode::NotFound.into())
        }
    }

    pub fn sign_msg(&self, msg: &[u8], signature: &mut [u8]) -> Result<usize, Error> {
        self.key_pair.sign_msg(msg, signature)
    }

    pub fn get_node_id(&self) -> u64 {
        self.node_id
    }

    pub fn get_fabric_id(&self) -> u64 {
        self.fabric_id
    }

    pub fn get_root_ca(&self) -> Result<Cert<'_>, Error> {
        Cert::new(&self.root_ca)
    }

    pub fn get_fabric_desc<'a>(
        &'a self,
        fab_idx: NonZeroU8,
        root_ca_cert: &'a Cert,
    ) -> Result<FabricDescriptor<'a>, Error> {
        let desc = FabricDescriptor {
            root_public_key: OctetStr::new(root_ca_cert.get_pubkey()),
            vendor_id: self.vendor_id,
            fabric_id: self.fabric_id,
            node_id: self.node_id,
            label: UtfStr(self.label.as_bytes()),
            fab_idx,
        };

        Ok(desc)
    }
}

pub const MAX_SUPPORTED_FABRICS: usize = 3;

type FabricEntries = Vec<Option<Fabric>, MAX_SUPPORTED_FABRICS>;

pub struct FabricMgr {
    fabrics: FabricEntries,
    changed: bool,
}

impl Default for FabricMgr {
    fn default() -> Self {
        Self::new()
    }
}

impl FabricMgr {
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            fabrics: FabricEntries::new(),
            changed: false,
        }
    }

    pub fn init() -> impl Init<Self> {
        init!(Self {
            fabrics <- FabricEntries::init(),
            changed: false,
        })
    }

    pub fn load(&mut self, data: &[u8], mdns: &dyn Mdns) -> Result<(), Error> {
        for fabric in self.fabrics.iter().flatten() {
            mdns.remove(&fabric.mdns_service_name)?;
        }

        let root = TLVList::new(data).iter().next().ok_or(ErrorCode::Invalid)?;

        tlv::vec_from_tlv(&mut self.fabrics, &root)?;

        for fabric in self.fabrics.iter().flatten() {
            mdns.add(&fabric.mdns_service_name, ServiceMode::Commissioned)?;
        }

        self.changed = false;

        Ok(())
    }

    pub fn store<'a>(&mut self, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, Error> {
        if self.changed {
            let mut wb = WriteBuf::new(buf);
            let mut tw = TLVWriter::new(&mut wb);

            self.fabrics
                .as_slice()
                .to_tlv(&mut tw, TagType::Anonymous)?;

            self.changed = false;

            let len = tw.get_tail();

            Ok(Some(&buf[..len]))
        } else {
            Ok(None)
        }
    }

    pub fn is_changed(&self) -> bool {
        self.changed
    }

    pub fn add(&mut self, f: Fabric, mdns: &dyn Mdns) -> Result<NonZeroU8, Error> {
        // Do not re-use slots (if possible) because currently we use the
        // position of the fabric in the array as a `fabric_index` as per the Matter Core spec
        // TODO: In future introduce a new field in Fabric to store the fabric index, as
        // we do for session indexes.
        let slot = (self.fabrics.len() == MAX_SUPPORTED_FABRICS)
            .then(|| self.fabrics.iter().position(|x| x.is_none()))
            .flatten();

        if slot.is_some() || self.fabrics.len() < MAX_SUPPORTED_FABRICS {
            mdns.add(&f.mdns_service_name, ServiceMode::Commissioned)?;
            self.changed = true;

            if let Some(index) = slot {
                self.fabrics[index] = Some(f);

                // Unwrapping is safe because we explicitly add + 1 here
                Ok(NonZeroU8::new(index as u8 + 1).unwrap())
            } else {
                self.fabrics
                    .push(Some(f))
                    .map_err(|_| ErrorCode::NoSpace)
                    .unwrap();

                // Unwrapping is safe because we just added the entry
                Ok(NonZeroU8::new(self.fabrics.len() as u8).unwrap())
            }
        } else {
            Err(ErrorCode::NoSpace.into())
        }
    }

    pub fn remove(&mut self, fab_idx: NonZeroU8, mdns: &dyn Mdns) -> Result<(), Error> {
        if fab_idx.get() as usize <= self.fabrics.len() {
            if let Some(f) = self.fabrics[(fab_idx.get() - 1) as usize].take() {
                mdns.remove(&f.mdns_service_name)?;
                self.changed = true;
                Ok(())
            } else {
                Err(ErrorCode::NotFound.into())
            }
        } else {
            Err(ErrorCode::NotFound.into())
        }
    }

    pub fn match_dest_id(&self, random: &[u8], target: &[u8]) -> Result<NonZeroU8, Error> {
        for (index, fabric) in self.fabrics.iter().enumerate() {
            if let Some(fabric) = fabric {
                if fabric.match_dest_id(random, target).is_ok() {
                    // Unwrapping is safe because we explicitly add + 1 here
                    return Ok(NonZeroU8::new(index as u8 + 1).unwrap());
                }
            }
        }
        Err(ErrorCode::NotFound.into())
    }

    pub fn get_fabric(&self, idx: NonZeroU8) -> Option<&Fabric> {
        self.fabrics[idx.get() as usize - 1].as_ref()
    }

    pub fn is_empty(&self) -> bool {
        !self.fabrics.iter().any(Option::is_some)
    }

    pub fn used_count(&self) -> usize {
        self.fabrics.iter().filter(|f| f.is_some()).count()
    }

    // Parameters to T are the Fabric and its Fabric Index
    pub fn for_each<T>(&self, mut f: T) -> Result<(), Error>
    where
        T: FnMut(&Fabric, NonZeroU8) -> Result<(), Error>,
    {
        for (index, fabric) in self.fabrics.iter().enumerate() {
            if let Some(fabric) = fabric {
                f(fabric, NonZeroU8::new(index as u8 + 1).unwrap())?;
            }
        }
        Ok(())
    }

    pub fn set_label(&mut self, index: NonZeroU8, label: &str) -> Result<(), Error> {
        if !label.is_empty()
            && self
                .fabrics
                .iter()
                .filter_map(|f| f.as_ref())
                .any(|f| f.label == label)
        {
            return Err(ErrorCode::Invalid.into());
        }

        let index = (index.get() - 1) as usize;
        if let Some(fabric) = &mut self.fabrics[index] {
            fabric.label = label.try_into().unwrap();
            self.changed = true;
        }
        Ok(())
    }
}
