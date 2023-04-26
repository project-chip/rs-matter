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

use byteorder::{BigEndian, ByteOrder, LittleEndian};
use log::{error, info};

use crate::{
    cert::{Cert, MAX_CERT_TLV_LEN},
    crypto::{self, hkdf_sha256, HmacSha256, KeyPair},
    error::Error,
    group_keys::KeySet,
    mdns::{MdnsMgr, ServiceMode},
    persist::Psm,
    tlv::{OctetStr, TLVWriter, TagType, ToTLV, UtfStr},
};

const COMPRESSED_FABRIC_ID_LEN: usize = 8;

macro_rules! fb_key {
    ($index:ident, $key:ident, $buf:expr) => {{
        use core::fmt::Write;

        $buf = "".into();
        write!(&mut $buf, "fb{}{}", $index, $key).unwrap();

        &$buf
    }};
}

const ST_VID: &str = "vid";
const ST_RCA: &str = "rca";
const ST_ICA: &str = "ica";
const ST_NOC: &str = "noc";
const ST_IPK: &str = "ipk";
const ST_LBL: &str = "label";
const ST_PBKEY: &str = "pubkey";
const ST_PRKEY: &str = "privkey";

#[allow(dead_code)]
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
    pub fab_idx: Option<u8>,
}

#[derive(Debug)]
pub struct Fabric {
    node_id: u64,
    fabric_id: u64,
    vendor_id: u16,
    key_pair: KeyPair,
    pub root_ca: heapless::Vec<u8, { MAX_CERT_TLV_LEN }>,
    pub icac: Option<heapless::Vec<u8, { MAX_CERT_TLV_LEN }>>,
    pub noc: heapless::Vec<u8, { MAX_CERT_TLV_LEN }>,
    pub ipk: KeySet,
    label: heapless::String<32>,
    mdns_service_name: heapless::String<33>,
}

impl Fabric {
    pub fn new(
        key_pair: KeyPair,
        root_ca: heapless::Vec<u8, { MAX_CERT_TLV_LEN }>,
        icac: Option<heapless::Vec<u8, { MAX_CERT_TLV_LEN }>>,
        noc: heapless::Vec<u8, { MAX_CERT_TLV_LEN }>,
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
            label: label.into(),
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
            .map_err(|_| Error::NoSpace)
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

    pub fn get_root_ca(&self) -> Result<Cert<'_>, Error> {
        Cert::new(&self.root_ca)
    }

    pub fn get_fabric_desc<'a>(
        &'a self,
        fab_idx: u8,
        root_ca_cert: &'a Cert,
    ) -> Result<FabricDescriptor<'a>, Error> {
        let desc = FabricDescriptor {
            root_public_key: OctetStr::new(root_ca_cert.get_pubkey()),
            vendor_id: self.vendor_id,
            fabric_id: self.fabric_id,
            node_id: self.node_id,
            label: UtfStr(self.label.as_bytes()),
            fab_idx: Some(fab_idx),
        };

        Ok(desc)
    }

    fn store<T>(&self, index: usize, mut psm: T) -> Result<(), Error>
    where
        T: Psm,
    {
        let mut _kb = heapless::String::<32>::new();

        psm.set_kv_slice(fb_key!(index, ST_RCA, _kb), &self.root_ca)?;
        psm.set_kv_slice(
            fb_key!(index, ST_ICA, _kb),
            self.icac.as_deref().unwrap_or(&[]),
        )?;

        psm.set_kv_slice(fb_key!(index, ST_NOC, _kb), &self.noc)?;
        psm.set_kv_slice(fb_key!(index, ST_IPK, _kb), self.ipk.epoch_key())?;
        psm.set_kv_slice(fb_key!(index, ST_LBL, _kb), self.label.as_bytes())?;

        let mut buf = [0_u8; crypto::EC_POINT_LEN_BYTES];
        let len = self.key_pair.get_public_key(&mut buf)?;
        let key = &buf[..len];
        psm.set_kv_slice(fb_key!(index, ST_PBKEY, _kb), key)?;

        let mut buf = [0_u8; crypto::BIGNUM_LEN_BYTES];
        let len = self.key_pair.get_private_key(&mut buf)?;
        let key = &buf[..len];
        psm.set_kv_slice(fb_key!(index, ST_PRKEY, _kb), key)?;

        psm.set_kv_u64(fb_key!(index, ST_VID, _kb), self.vendor_id.into())?;
        Ok(())
    }

    fn load<T>(index: usize, psm: T) -> Result<Self, Error>
    where
        T: Psm,
    {
        let mut _kb = heapless::String::<32>::new();

        let mut buf = [0u8; MAX_CERT_TLV_LEN];

        let root_ca =
            heapless::Vec::from_slice(psm.get_kv_slice(fb_key!(index, ST_RCA, _kb), &mut buf)?)
                .unwrap();

        let icac = psm.get_kv_slice(fb_key!(index, ST_ICA, _kb), &mut buf)?;
        let icac = if !icac.is_empty() {
            Some(heapless::Vec::from_slice(icac).unwrap())
        } else {
            None
        };

        let noc =
            heapless::Vec::from_slice(psm.get_kv_slice(fb_key!(index, ST_NOC, _kb), &mut buf)?)
                .unwrap();

        let label = psm.get_kv_slice(fb_key!(index, ST_LBL, _kb), &mut buf)?;
        let label: heapless::String<32> = core::str::from_utf8(label)
            .map_err(|_| {
                error!("Couldn't read label");
                Error::Invalid
            })?
            .into();

        let ipk = psm.get_kv_slice(fb_key!(index, ST_IPK, _kb), &mut buf)?;

        let mut buf = [0_u8; crypto::EC_POINT_LEN_BYTES];
        let pub_key = psm.get_kv_slice(fb_key!(index, ST_PBKEY, _kb), &mut buf)?;

        let mut buf = [0_u8; crypto::BIGNUM_LEN_BYTES];
        let priv_key = psm.get_kv_slice(fb_key!(index, ST_PRKEY, _kb), &mut buf)?;
        let keypair = KeyPair::new_from_components(pub_key, priv_key)?;

        let vendor_id = psm.get_kv_u64(fb_key!(index, ST_VID, _kb))?;

        Fabric::new(keypair, root_ca, icac, noc, ipk, vendor_id as u16, &label)
    }

    fn remove<T>(index: usize, mut psm: T) -> Result<(), Error>
    where
        T: Psm,
    {
        let mut _kb = heapless::String::<32>::new();

        psm.remove(fb_key!(index, ST_RCA, _kb))?;
        psm.remove(fb_key!(index, ST_ICA, _kb))?;

        psm.remove(fb_key!(index, ST_NOC, _kb))?;

        psm.remove(fb_key!(index, ST_LBL, _kb))?;

        psm.remove(fb_key!(index, ST_IPK, _kb))?;

        psm.remove(fb_key!(index, ST_PBKEY, _kb))?;
        psm.remove(fb_key!(index, ST_PRKEY, _kb))?;

        psm.remove(fb_key!(index, ST_VID, _kb))?;

        Ok(())
    }

    #[cfg(feature = "nightly")]
    async fn store_async<T>(&self, index: usize, mut psm: T) -> Result<(), Error>
    where
        T: crate::persist::asynch::AsyncPsm,
    {
        let mut _kb = heapless::String::<32>::new();

        psm.set_kv_slice(fb_key!(index, ST_RCA, _kb), &self.root_ca)
            .await?;

        psm.set_kv_slice(
            fb_key!(index, ST_ICA, _kb),
            self.icac.as_deref().unwrap_or(&[]),
        )
        .await?;

        psm.set_kv_slice(fb_key!(index, ST_NOC, _kb), &self.noc)
            .await?;
        psm.set_kv_slice(fb_key!(index, ST_IPK, _kb), self.ipk.epoch_key())
            .await?;
        psm.set_kv_slice(fb_key!(index, ST_LBL, _kb), self.label.as_bytes())
            .await?;

        let mut buf = [0_u8; crypto::EC_POINT_LEN_BYTES];
        let len = self.key_pair.get_public_key(&mut buf)?;
        let key = &buf[..len];
        psm.set_kv_slice(fb_key!(index, ST_PBKEY, _kb), key).await?;

        let mut buf = [0_u8; crypto::BIGNUM_LEN_BYTES];
        let len = self.key_pair.get_private_key(&mut buf)?;
        let key = &buf[..len];
        psm.set_kv_slice(fb_key!(index, ST_PRKEY, _kb), key).await?;

        psm.set_kv_u64(fb_key!(index, ST_VID, _kb), self.vendor_id.into())
            .await?;
        Ok(())
    }

    #[cfg(feature = "nightly")]
    async fn load_async<T>(index: usize, psm: T) -> Result<Self, Error>
    where
        T: crate::persist::asynch::AsyncPsm,
    {
        let mut _kb = heapless::String::<32>::new();

        let mut buf = [0u8; MAX_CERT_TLV_LEN];

        let root_ca = heapless::Vec::from_slice(
            psm.get_kv_slice(fb_key!(index, ST_RCA, _kb), &mut buf)
                .await?,
        )
        .unwrap();

        let icac = psm
            .get_kv_slice(fb_key!(index, ST_ICA, _kb), &mut buf)
            .await?;
        let icac = if !icac.is_empty() {
            Some(heapless::Vec::from_slice(icac).unwrap())
        } else {
            None
        };

        let noc = heapless::Vec::from_slice(
            psm.get_kv_slice(fb_key!(index, ST_NOC, _kb), &mut buf)
                .await?,
        )
        .unwrap();

        let label = psm
            .get_kv_slice(fb_key!(index, ST_LBL, _kb), &mut buf)
            .await?;
        let label: heapless::String<32> = core::str::from_utf8(label)
            .map_err(|_| {
                error!("Couldn't read label");
                Error::Invalid
            })?
            .into();

        let ipk = psm
            .get_kv_slice(fb_key!(index, ST_IPK, _kb), &mut buf)
            .await?;

        let mut buf = [0_u8; crypto::EC_POINT_LEN_BYTES];
        let pub_key = psm
            .get_kv_slice(fb_key!(index, ST_PBKEY, _kb), &mut buf)
            .await?;

        let mut buf = [0_u8; crypto::BIGNUM_LEN_BYTES];
        let priv_key = psm
            .get_kv_slice(fb_key!(index, ST_PRKEY, _kb), &mut buf)
            .await?;
        let keypair = KeyPair::new_from_components(pub_key, priv_key)?;

        let vendor_id = psm.get_kv_u64(fb_key!(index, ST_VID, _kb)).await?;

        Fabric::new(keypair, root_ca, icac, noc, ipk, vendor_id as u16, &label)
    }

    #[cfg(feature = "nightly")]
    async fn remove_async<T>(index: usize, mut psm: T) -> Result<(), Error>
    where
        T: crate::persist::asynch::AsyncPsm,
    {
        let mut _kb = heapless::String::<32>::new();

        psm.remove(fb_key!(index, ST_RCA, _kb)).await?;
        psm.remove(fb_key!(index, ST_ICA, _kb)).await?;

        psm.remove(fb_key!(index, ST_NOC, _kb)).await?;

        psm.remove(fb_key!(index, ST_LBL, _kb)).await?;

        psm.remove(fb_key!(index, ST_IPK, _kb)).await?;

        psm.remove(fb_key!(index, ST_PBKEY, _kb)).await?;
        psm.remove(fb_key!(index, ST_PRKEY, _kb)).await?;

        psm.remove(fb_key!(index, ST_VID, _kb)).await?;

        Ok(())
    }
}

pub const MAX_SUPPORTED_FABRICS: usize = 3;

pub struct FabricMgr {
    // The outside world expects Fabric Index to be one more than the actual one
    // since 0 is not allowed. Need to handle this cleanly somehow
    fabrics: [Option<Fabric>; MAX_SUPPORTED_FABRICS],
    changed: bool,
}

impl FabricMgr {
    pub const fn new() -> Self {
        const INIT: Option<Fabric> = None;

        Self {
            fabrics: [INIT; MAX_SUPPORTED_FABRICS],
            changed: false,
        }
    }

    pub fn store<T>(&mut self, mut psm: T) -> Result<(), Error>
    where
        T: Psm,
    {
        if self.changed {
            for i in 1..MAX_SUPPORTED_FABRICS {
                if let Some(fabric) = self.fabrics[i].as_mut() {
                    info!("Storing fabric at index {}", i);
                    fabric.store(i, &mut psm)?;
                } else {
                    let _ = Fabric::remove(i, &mut psm);
                }
            }

            self.changed = false;
        }

        Ok(())
    }

    pub fn load<T>(&mut self, mut psm: T, mdns_mgr: &mut MdnsMgr) -> Result<(), Error>
    where
        T: Psm,
    {
        for i in 1..MAX_SUPPORTED_FABRICS {
            let result = Fabric::load(i, &mut psm);
            if let Ok(fabric) = result {
                info!("Adding new fabric at index {}", i);
                self.fabrics[i] = Some(fabric);
                mdns_mgr.publish_service(
                    &self.fabrics[i].as_ref().unwrap().mdns_service_name,
                    ServiceMode::Commissioned,
                )?;
            } else {
                self.fabrics[i] = None;
            }
        }

        self.changed = false;

        Ok(())
    }

    #[cfg(feature = "nightly")]
    pub async fn store_async<T>(&mut self, mut psm: T) -> Result<(), Error>
    where
        T: crate::persist::asynch::AsyncPsm,
    {
        if self.changed {
            for i in 1..MAX_SUPPORTED_FABRICS {
                if let Some(fabric) = self.fabrics[i].as_mut() {
                    info!("Storing fabric at index {}", i);
                    fabric.store_async(i, &mut psm).await?;
                } else {
                    let _ = Fabric::remove_async(i, &mut psm).await;
                }
            }

            self.changed = false;
        }

        Ok(())
    }

    #[cfg(feature = "nightly")]
    pub async fn load_async<T>(
        &mut self,
        mut psm: T,
        mdns_mgr: &mut MdnsMgr<'_>,
    ) -> Result<(), Error>
    where
        T: crate::persist::asynch::AsyncPsm,
    {
        for i in 1..MAX_SUPPORTED_FABRICS {
            let result = Fabric::load_async(i, &mut psm).await;
            if let Ok(fabric) = result {
                info!("Adding new fabric at index {}", i);
                self.fabrics[i] = Some(fabric);
                mdns_mgr.publish_service(
                    &self.fabrics[i].as_ref().unwrap().mdns_service_name,
                    ServiceMode::Commissioned,
                )?;
            } else {
                self.fabrics[i] = None;
            }
        }

        self.changed = false;

        Ok(())
    }

    pub fn add(&mut self, f: Fabric, mdns_mgr: &mut MdnsMgr) -> Result<u8, Error> {
        for i in 1..MAX_SUPPORTED_FABRICS {
            if self.fabrics[i].is_none() {
                self.fabrics[i] = Some(f);
                mdns_mgr.publish_service(
                    &self.fabrics[i].as_ref().unwrap().mdns_service_name,
                    ServiceMode::Commissioned,
                )?;

                self.changed = true;

                return Ok(i as u8);
            }
        }

        Err(Error::NoSpace)
    }

    pub fn remove(&mut self, fab_idx: u8, mdns_mgr: &mut MdnsMgr) -> Result<(), Error> {
        if let Some(f) = self.fabrics[fab_idx as usize].take() {
            mdns_mgr.unpublish_service(&f.mdns_service_name, ServiceMode::Commissioned)?;
            self.changed = true;
            Ok(())
        } else {
            Err(Error::NotFound)
        }
    }

    pub fn match_dest_id(&self, random: &[u8], target: &[u8]) -> Result<usize, Error> {
        for i in 1..MAX_SUPPORTED_FABRICS {
            if let Some(fabric) = &self.fabrics[i] {
                if fabric.match_dest_id(random, target).is_ok() {
                    return Ok(i);
                }
            }
        }
        Err(Error::NotFound)
    }

    pub fn get_fabric(&self, idx: usize) -> Result<Option<&Fabric>, Error> {
        Ok(self.fabrics[idx].as_ref())
    }

    pub fn is_empty(&self) -> bool {
        for i in 1..MAX_SUPPORTED_FABRICS {
            if self.fabrics[i].is_some() {
                return false;
            }
        }
        true
    }

    pub fn used_count(&self) -> usize {
        let mut count = 0;
        for i in 1..MAX_SUPPORTED_FABRICS {
            if self.fabrics[i].is_some() {
                count += 1;
            }
        }
        count
    }

    // Parameters to T are the Fabric and its Fabric Index
    pub fn for_each<T>(&self, mut f: T) -> Result<(), Error>
    where
        T: FnMut(&Fabric, u8) -> Result<(), Error>,
    {
        for i in 1..MAX_SUPPORTED_FABRICS {
            if let Some(fabric) = &self.fabrics[i] {
                f(fabric, i as u8)?;
            }
        }
        Ok(())
    }

    pub fn set_label(&mut self, index: u8, label: &str) -> Result<(), Error> {
        let index = index as usize;
        if !label.is_empty() {
            for i in 1..MAX_SUPPORTED_FABRICS {
                if let Some(fabric) = &self.fabrics[i] {
                    if fabric.label == label {
                        return Err(Error::Invalid);
                    }
                }
            }
        }
        if let Some(fabric) = &mut self.fabrics[index] {
            fabric.label = label.into();
            self.changed = true;
        }
        Ok(())
    }
}
