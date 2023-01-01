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

use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use byteorder::{BigEndian, ByteOrder, LittleEndian};
use log::info;
use owning_ref::RwLockReadGuardRef;

use crate::{
    cert::Cert,
    crypto::{self, crypto_dummy::KeyPairDummy, hkdf_sha256, CryptoKeyPair, HmacSha256, KeyPair},
    error::Error,
    group_keys::KeySet,
    mdns::{self, Mdns},
    sys::{Psm, SysMdnsService},
    tlv::{OctetStr, TLVWriter, TagType, ToTLV, UtfStr},
};

const MAX_CERT_TLV_LEN: usize = 300;
const COMPRESSED_FABRIC_ID_LEN: usize = 8;

macro_rules! fb_key {
    ($index:ident, $key:ident) => {
        &format!("fb{}{}", $index, $key)
    };
}

const ST_VID: &str = "vid";
const ST_RCA: &str = "rca";
const ST_ICA: &str = "ica";
const ST_NOC: &str = "noc";
const ST_IPK: &str = "ipk";
const ST_PBKEY: &str = "pubkey";
const ST_PRKEY: &str = "privkey";

#[allow(dead_code)]
pub struct Fabric {
    node_id: u64,
    fabric_id: u64,
    vendor_id: u16,
    key_pair: Box<dyn CryptoKeyPair>,
    pub root_ca: Cert,
    pub icac: Cert,
    pub noc: Cert,
    pub ipk: KeySet,
    compressed_id: [u8; COMPRESSED_FABRIC_ID_LEN],
    mdns_service: Option<SysMdnsService>,
}

#[derive(ToTLV)]
#[tlvargs(lifetime = "'a", start = 1)]
pub struct FabricDescriptor<'a> {
    root_public_key: OctetStr<'a>,
    vendor_id: u16,
    fabric_id: u64,
    node_id: u64,
    label: UtfStr<'a>,
    // TODO: Instead of the direct value, we should consider GlobalElements::FabricIndex
    #[tagval(0xFE)]
    pub fab_idx: Option<u8>,
}

impl Fabric {
    pub fn new(
        key_pair: KeyPair,
        root_ca: Cert,
        icac: Cert,
        noc: Cert,
        ipk: &[u8],
        vendor_id: u16,
    ) -> Result<Self, Error> {
        let node_id = noc.get_node_id()?;
        let fabric_id = noc.get_fabric_id()?;

        let mut f = Self {
            node_id,
            fabric_id,
            vendor_id,
            key_pair: Box::new(key_pair),
            root_ca,
            icac,
            noc,
            ipk: KeySet::default(),
            compressed_id: [0; COMPRESSED_FABRIC_ID_LEN],
            mdns_service: None,
        };
        Fabric::get_compressed_id(f.root_ca.get_pubkey(), fabric_id, &mut f.compressed_id)?;
        f.ipk = KeySet::new(ipk, &f.compressed_id)?;

        let mut mdns_service_name = String::with_capacity(33);
        for c in f.compressed_id {
            mdns_service_name.push_str(&format!("{:02X}", c));
        }
        mdns_service_name.push('-');
        let mut node_id_be: [u8; 8] = [0; 8];
        BigEndian::write_u64(&mut node_id_be, node_id);
        for c in node_id_be {
            mdns_service_name.push_str(&format!("{:02X}", c));
        }
        info!("MDNS Service Name: {}", mdns_service_name);
        f.mdns_service = Some(
            Mdns::get()?.publish_service(&mdns_service_name, mdns::ServiceMode::Commissioned)?,
        );
        Ok(f)
    }

    pub fn dummy() -> Result<Self, Error> {
        Ok(Self {
            node_id: 0,
            fabric_id: 0,
            vendor_id: 0,
            key_pair: Box::new(KeyPairDummy::new()?),
            root_ca: Cert::default(),
            icac: Cert::default(),
            noc: Cert::default(),
            ipk: KeySet::default(),
            compressed_id: [0; COMPRESSED_FABRIC_ID_LEN],
            mdns_service: None,
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
            .map_err(|_| Error::NoSpace)
    }

    pub fn match_dest_id(&self, random: &[u8], target: &[u8]) -> Result<(), Error> {
        let mut mac = HmacSha256::new(self.ipk.op_key())?;

        mac.update(random)?;
        mac.update(self.root_ca.get_pubkey())?;

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
            Err(Error::NotFound)
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

    pub fn get_fabric_desc(&self, fab_idx: u8) -> FabricDescriptor {
        FabricDescriptor {
            root_public_key: OctetStr::new(self.root_ca.get_pubkey()),
            vendor_id: self.vendor_id,
            fabric_id: self.fabric_id,
            node_id: self.node_id,
            label: UtfStr::new(b""),
            fab_idx: Some(fab_idx),
        }
    }

    fn store(&self, index: usize, psm: &MutexGuard<Psm>) -> Result<(), Error> {
        let mut key = [0u8; MAX_CERT_TLV_LEN];
        let len = self.root_ca.as_tlv(&mut key)?;
        psm.set_kv_slice(fb_key!(index, ST_RCA), &key[..len])?;
        let len = self.icac.as_tlv(&mut key)?;
        psm.set_kv_slice(fb_key!(index, ST_ICA), &key[..len])?;
        let len = self.noc.as_tlv(&mut key)?;
        psm.set_kv_slice(fb_key!(index, ST_NOC), &key[..len])?;
        psm.set_kv_slice(fb_key!(index, ST_IPK), self.ipk.epoch_key())?;

        let mut key = [0_u8; crypto::EC_POINT_LEN_BYTES];
        let len = self.key_pair.get_public_key(&mut key)?;
        let key = &key[..len];
        psm.set_kv_slice(fb_key!(index, ST_PBKEY), key)?;

        let mut key = [0_u8; crypto::BIGNUM_LEN_BYTES];
        let len = self.key_pair.get_private_key(&mut key)?;
        let key = &key[..len];
        psm.set_kv_slice(fb_key!(index, ST_PRKEY), key)?;

        psm.set_kv_u64(ST_VID, self.vendor_id.into())?;
        Ok(())
    }

    fn load(index: usize, psm: &MutexGuard<Psm>) -> Result<Self, Error> {
        let mut root_ca = Vec::new();
        psm.get_kv_slice(fb_key!(index, ST_RCA), &mut root_ca)?;
        let root_ca = Cert::new(root_ca.as_slice())?;

        let mut icac = Vec::new();
        psm.get_kv_slice(fb_key!(index, ST_ICA), &mut icac)?;
        let icac = Cert::new(icac.as_slice())?;

        let mut noc = Vec::new();
        psm.get_kv_slice(fb_key!(index, ST_NOC), &mut noc)?;
        let noc = Cert::new(noc.as_slice())?;

        let mut ipk = Vec::new();
        psm.get_kv_slice(fb_key!(index, ST_IPK), &mut ipk)?;

        let mut pub_key = Vec::new();
        psm.get_kv_slice(fb_key!(index, ST_PBKEY), &mut pub_key)?;
        let mut priv_key = Vec::new();
        psm.get_kv_slice(fb_key!(index, ST_PRKEY), &mut priv_key)?;
        let keypair = KeyPair::new_from_components(pub_key.as_slice(), priv_key.as_slice())?;

        let mut vendor_id = 0;
        psm.get_kv_u64(ST_VID, &mut vendor_id)?;

        Fabric::new(
            keypair,
            root_ca,
            icac,
            noc,
            ipk.as_slice(),
            vendor_id as u16,
        )
    }
}

pub const MAX_SUPPORTED_FABRICS: usize = 3;
#[derive(Default)]
pub struct FabricMgrInner {
    // The outside world expects Fabric Index to be one more than the actual one
    // since 0 is not allowed. Need to handle this cleanly somehow
    pub fabrics: [Option<Fabric>; MAX_SUPPORTED_FABRICS],
}

pub struct FabricMgr {
    inner: RwLock<FabricMgrInner>,
    psm: Arc<Mutex<Psm>>,
}

impl FabricMgr {
    pub fn new() -> Result<Self, Error> {
        let dummy_fabric = Fabric::dummy()?;
        let mut mgr = FabricMgrInner::default();
        mgr.fabrics[0] = Some(dummy_fabric);
        let mut fm = Self {
            inner: RwLock::new(mgr),
            psm: Psm::get()?,
        };
        fm.load()?;
        Ok(fm)
    }

    fn store(&self, index: usize, fabric: &Fabric) -> Result<(), Error> {
        let psm = self.psm.lock().unwrap();
        fabric.store(index, &psm)
    }

    fn load(&mut self) -> Result<(), Error> {
        let mut mgr = self.inner.write()?;
        let psm = self.psm.lock().unwrap();
        for i in 0..MAX_SUPPORTED_FABRICS {
            let result = Fabric::load(i, &psm);
            if let Ok(fabric) = result {
                info!("Adding new fabric at index {}", i);
                mgr.fabrics[i] = Some(fabric);
            }
        }
        Ok(())
    }

    pub fn add(&self, f: Fabric) -> Result<u8, Error> {
        let mut mgr = self.inner.write()?;
        let index = mgr
            .fabrics
            .iter()
            .position(|f| f.is_none())
            .ok_or(Error::NoSpace)?;

        self.store(index, &f)?;

        mgr.fabrics[index] = Some(f);
        Ok(index as u8)
    }

    pub fn match_dest_id(&self, random: &[u8], target: &[u8]) -> Result<usize, Error> {
        let mgr = self.inner.read()?;
        for i in 0..MAX_SUPPORTED_FABRICS {
            if let Some(fabric) = &mgr.fabrics[i] {
                if fabric.match_dest_id(random, target).is_ok() {
                    return Ok(i);
                }
            }
        }
        Err(Error::NotFound)
    }

    pub fn get_fabric<'ret, 'me: 'ret>(
        &'me self,
        idx: usize,
    ) -> Result<RwLockReadGuardRef<'ret, FabricMgrInner, Option<Fabric>>, Error> {
        Ok(RwLockReadGuardRef::new(self.inner.read()?).map(|fm| &fm.fabrics[idx]))
    }

    pub fn is_empty(&self) -> bool {
        let mgr = self.inner.read().unwrap();
        for i in 1..MAX_SUPPORTED_FABRICS {
            if mgr.fabrics[i].is_some() {
                return false;
            }
        }
        true
    }

    // Parameters to T are the Fabric and its Fabric Index
    pub fn for_each<T>(&self, mut f: T) -> Result<(), Error>
    where
        T: FnMut(&Fabric, u8),
    {
        let mgr = self.inner.read().unwrap();
        for i in 1..MAX_SUPPORTED_FABRICS {
            if let Some(fabric) = &mgr.fabrics[i] {
                f(fabric, i as u8)
            }
        }
        Ok(())
    }
}
