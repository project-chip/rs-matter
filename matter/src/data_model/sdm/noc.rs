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

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::acl::{AclEntry, AclMgr, AuthMode};
use crate::cert::Cert;
use crate::crypto::{self, CryptoKeyPair, KeyPair};
use crate::data_model::objects::*;
use crate::data_model::sdm::dev_att;
use crate::fabric::{Fabric, FabricMgr, MAX_SUPPORTED_FABRICS};
use crate::interaction_model::command::CommandReq;
use crate::interaction_model::core::IMStatusCode;
use crate::interaction_model::messages::ib;
use crate::tlv::{FromTLV, OctetStr, TLVElement, TLVWriter, TagType, ToTLV, UtfStr};
use crate::transport::session::SessionMode;
use crate::utils::writebuf::WriteBuf;
use crate::{cmd_enter, error::*};
use log::{error, info};
use num_derive::FromPrimitive;

use super::dev_att::{DataType, DevAttDataFetcher};
use super::failsafe::FailSafe;

// Node Operational Credentials Cluster

#[derive(Clone, Copy)]
#[allow(dead_code)]
enum NocStatus {
    Ok = 0,
    InvalidPublicKey = 1,
    InvalidNodeOpId = 2,
    InvalidNOC = 3,
    MissingCsr = 4,
    TableFull = 5,
    MissingAcl = 6,
    MissingIpk = 7,
    InsufficientPrivlege = 8,
    FabricConflict = 9,
    LabelConflict = 10,
    InvalidFabricIndex = 11,
}

// Some placeholder value for now
const MAX_CERT_DECLARATION_LEN: usize = 600;
// Some placeholder value for now
const MAX_CSR_LEN: usize = 300;
// As defined in the Matter Spec
const RESP_MAX: usize = 900;

pub const ID: u32 = 0x003E;

#[derive(FromPrimitive)]
pub enum Commands {
    AttReq = 0x00,
    AttReqResp = 0x01,
    CertChainReq = 0x02,
    CertChainResp = 0x03,
    CSRReq = 0x04,
    CSRResp = 0x05,
    AddNOC = 0x06,
    NOCResp = 0x08,
    UpdateFabricLabel = 0x09,
    RemoveFabric = 0x0a,
    AddTrustedRootCert = 0x0b,
}

#[derive(FromPrimitive)]
pub enum Attributes {
    NOCs = 0,
    Fabrics = 1,
    SupportedFabrics = 2,
    CommissionedFabrics = 3,
    TrustedRootCerts = 4,
    CurrentFabricIndex = 5,
}

pub struct NocCluster {
    base: Cluster,
    dev_att: Box<dyn DevAttDataFetcher>,
    fabric_mgr: Arc<FabricMgr>,
    acl_mgr: Arc<AclMgr>,
    failsafe: Arc<FailSafe>,
}
struct NocData {
    pub key_pair: KeyPair,
    pub root_ca: Cert,
}

impl NocData {
    pub fn new(key_pair: KeyPair) -> Self {
        Self {
            key_pair,
            root_ca: Cert::default(),
        }
    }
}

impl NocCluster {
    pub fn new(
        dev_att: Box<dyn DevAttDataFetcher>,
        fabric_mgr: Arc<FabricMgr>,
        acl_mgr: Arc<AclMgr>,
        failsafe: Arc<FailSafe>,
    ) -> Result<Box<Self>, Error> {
        let mut c = Box::new(Self {
            dev_att,
            fabric_mgr,
            acl_mgr,
            failsafe,
            base: Cluster::new(ID)?,
        });
        let attrs = [
            Attribute::new(
                Attributes::CurrentFabricIndex as u16,
                AttrValue::Custom,
                Access::RV,
                Quality::NONE,
            )?,
            Attribute::new(
                Attributes::Fabrics as u16,
                AttrValue::Custom,
                Access::RV | Access::FAB_SCOPED,
                Quality::NONE,
            )?,
            Attribute::new(
                Attributes::SupportedFabrics as u16,
                AttrValue::Uint8(MAX_SUPPORTED_FABRICS as u8),
                Access::RV,
                Quality::FIXED,
            )?,
            Attribute::new(
                Attributes::CommissionedFabrics as u16,
                AttrValue::Custom,
                Access::RV,
                Quality::NONE,
            )?,
        ];
        c.base.add_attributes(&attrs[..])?;
        Ok(c)
    }

    fn add_acl(&self, fab_idx: u8, admin_subject: u64) -> Result<(), Error> {
        let mut acl = AclEntry::new(fab_idx, Privilege::ADMIN, AuthMode::Case);
        acl.add_subject(admin_subject)?;
        self.acl_mgr.add(acl)
    }

    fn _handle_command_addnoc(&mut self, cmd_req: &mut CommandReq) -> Result<(), NocStatus> {
        let noc_data = cmd_req
            .trans
            .session
            .take_data::<NocData>()
            .ok_or(NocStatus::MissingCsr)?;

        if !self
            .failsafe
            .allow_noc_change()
            .map_err(|_| NocStatus::InsufficientPrivlege)?
        {
            error!("AddNOC not allowed by Fail Safe");
            return Err(NocStatus::InsufficientPrivlege);
        }

        let r = AddNocReq::from_tlv(&cmd_req.data).map_err(|_| NocStatus::InvalidNOC)?;

        let noc_value = Cert::new(r.noc_value.0).map_err(|_| NocStatus::InvalidNOC)?;
        info!("Received NOC as: {}", noc_value);
        let icac_value = if !r.icac_value.0.is_empty() {
            let cert = Cert::new(r.icac_value.0).map_err(|_| NocStatus::InvalidNOC)?;
            info!("Received ICAC as: {}", cert);
            Some(cert)
        } else {
            None
        };

        let fabric = Fabric::new(
            noc_data.key_pair,
            noc_data.root_ca,
            icac_value,
            noc_value,
            r.ipk_value.0,
            r.vendor_id,
        )
        .map_err(|_| NocStatus::TableFull)?;
        let fab_idx = self
            .fabric_mgr
            .add(fabric)
            .map_err(|_| NocStatus::TableFull)?;

        if self.add_acl(fab_idx, r.case_admin_subject).is_err() {
            error!("Failed to add ACL, what to do?");
        }

        if self.failsafe.record_add_noc(fab_idx).is_err() {
            error!("Failed to record NoC in the FailSafe, what to do?");
        }
        NocCluster::create_nocresponse(cmd_req.resp, NocStatus::Ok, fab_idx, "".to_owned());
        cmd_req.trans.complete();
        Ok(())
    }

    fn create_nocresponse(
        tw: &mut TLVWriter,
        status_code: NocStatus,
        fab_idx: u8,
        debug_txt: String,
    ) {
        let cmd_data = NocResp {
            status_code: status_code as u8,
            fab_idx,
            debug_txt,
        };
        let invoke_resp = ib::InvResp::cmd_new(
            0,
            ID,
            Commands::NOCResp as u16,
            EncodeValue::Value(&cmd_data),
        );
        let _ = invoke_resp.to_tlv(tw, TagType::Anonymous);
    }

    fn handle_command_updatefablabel(
        &mut self,
        cmd_req: &mut CommandReq,
    ) -> Result<(), IMStatusCode> {
        cmd_enter!("Update Fabric Label");
        let req = UpdateFabricLabelReq::from_tlv(&cmd_req.data)
            .map_err(|_| IMStatusCode::InvalidDataType)?;
        let label = req
            .label
            .to_string()
            .map_err(|_| IMStatusCode::InvalidDataType)?;

        let (result, fab_idx) =
            if let SessionMode::Case(c) = cmd_req.trans.session.get_session_mode() {
                if self.fabric_mgr.set_label(c.fab_idx, label).is_err() {
                    (NocStatus::LabelConflict, c.fab_idx)
                } else {
                    (NocStatus::Ok, c.fab_idx)
                }
            } else {
                // Update Fabric Label not allowed
                (NocStatus::InvalidFabricIndex, 0)
            };
        NocCluster::create_nocresponse(cmd_req.resp, result, fab_idx, "".to_string());
        cmd_req.trans.complete();
        Ok(())
    }

    fn handle_command_rmfabric(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        cmd_enter!("Remove Fabric");
        let req =
            RemoveFabricReq::from_tlv(&cmd_req.data).map_err(|_| IMStatusCode::InvalidCommand)?;
        if self.fabric_mgr.remove(req.fab_idx).is_ok() {
            let _ = self.acl_mgr.delete_for_fabric(req.fab_idx);
            cmd_req.trans.terminate();
        } else {
            NocCluster::create_nocresponse(
                cmd_req.resp,
                NocStatus::InvalidFabricIndex,
                req.fab_idx,
                "".to_string(),
            );
        }
        Ok(())
    }

    fn handle_command_addnoc(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        cmd_enter!("AddNOC");
        if let Err(e) = self._handle_command_addnoc(cmd_req) {
            //TODO: Fab-idx 0?
            NocCluster::create_nocresponse(cmd_req.resp, e, 0, "".to_owned());
            cmd_req.trans.complete();
        }
        Ok(())
    }

    fn handle_command_attrequest(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        cmd_enter!("AttestationRequest");

        let req = CommonReq::from_tlv(&cmd_req.data).map_err(|_| IMStatusCode::InvalidCommand)?;
        info!("Received Attestation Nonce:{:?}", req.str);

        let mut attest_challenge = [0u8; crypto::SYMM_KEY_LEN_BYTES];
        attest_challenge.copy_from_slice(cmd_req.trans.session.get_att_challenge());

        let cmd_data = |tag: TagType, t: &mut TLVWriter| {
            let mut buf: [u8; RESP_MAX] = [0; RESP_MAX];
            let mut attest_element = WriteBuf::new(&mut buf, RESP_MAX);
            let _ = t.start_struct(tag);
            let _ =
                add_attestation_element(self.dev_att.as_ref(), req.str.0, &mut attest_element, t);
            let _ = add_attestation_signature(
                self.dev_att.as_ref(),
                &mut attest_element,
                &attest_challenge,
                t,
            );
            let _ = t.end_container();
        };
        let resp = ib::InvResp::cmd_new(
            0,
            ID,
            Commands::AttReqResp as u16,
            EncodeValue::Closure(&cmd_data),
        );
        let _ = resp.to_tlv(cmd_req.resp, TagType::Anonymous);
        cmd_req.trans.complete();
        Ok(())
    }

    fn handle_command_certchainrequest(
        &mut self,
        cmd_req: &mut CommandReq,
    ) -> Result<(), IMStatusCode> {
        cmd_enter!("CertChainRequest");

        info!("Received data: {}", cmd_req.data);
        let cert_type =
            get_certchainrequest_params(&cmd_req.data).map_err(|_| IMStatusCode::InvalidCommand)?;

        let mut buf: [u8; RESP_MAX] = [0; RESP_MAX];
        let len = self
            .dev_att
            .get_devatt_data(cert_type, &mut buf)
            .map_err(|_| IMStatusCode::Failure)?;
        let buf = &buf[0..len];

        let cmd_data = CertChainResp {
            cert: OctetStr::new(buf),
        };
        let resp = ib::InvResp::cmd_new(
            0,
            ID,
            Commands::CertChainResp as u16,
            EncodeValue::Value(&cmd_data),
        );
        let _ = resp.to_tlv(cmd_req.resp, TagType::Anonymous);
        cmd_req.trans.complete();
        Ok(())
    }

    fn handle_command_csrrequest(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        cmd_enter!("CSRRequest");

        let req = CommonReq::from_tlv(&cmd_req.data).map_err(|_| IMStatusCode::InvalidCommand)?;
        info!("Received CSR Nonce:{:?}", req.str);

        if !self.failsafe.is_armed() {
            return Err(IMStatusCode::UnsupportedAccess);
        }

        let noc_keypair = KeyPair::new().map_err(|_| IMStatusCode::Failure)?;
        let mut attest_challenge = [0u8; crypto::SYMM_KEY_LEN_BYTES];
        attest_challenge.copy_from_slice(cmd_req.trans.session.get_att_challenge());

        let cmd_data = |tag: TagType, t: &mut TLVWriter| {
            let mut buf: [u8; RESP_MAX] = [0; RESP_MAX];
            let mut nocsr_element = WriteBuf::new(&mut buf, RESP_MAX);
            let _ = t.start_struct(tag);
            let _ = add_nocsrelement(&noc_keypair, req.str.0, &mut nocsr_element, t);
            let _ = add_attestation_signature(
                self.dev_att.as_ref(),
                &mut nocsr_element,
                &attest_challenge,
                t,
            );
            let _ = t.end_container();
        };
        let resp = ib::InvResp::cmd_new(
            0,
            ID,
            Commands::CSRResp as u16,
            EncodeValue::Closure(&cmd_data),
        );

        let _ = resp.to_tlv(cmd_req.resp, TagType::Anonymous);
        let noc_data = Box::new(NocData::new(noc_keypair));
        // Store this in the session data instead of cluster data, so it gets cleared
        // if the session goes away for some reason
        cmd_req.trans.session.set_data(noc_data);
        cmd_req.trans.complete();
        Ok(())
    }

    fn handle_command_addtrustedrootcert(
        &mut self,
        cmd_req: &mut CommandReq,
    ) -> Result<(), IMStatusCode> {
        cmd_enter!("AddTrustedRootCert");
        if !self.failsafe.is_armed() {
            return Err(IMStatusCode::UnsupportedAccess);
        }

        // This may happen on CASE or PASE. For PASE, the existence of NOC Data is necessary
        match cmd_req.trans.session.get_session_mode() {
            SessionMode::Case(_) => error!("CASE: AddTrustedRootCert handling pending"), // For a CASE Session, we just return success for now,
            SessionMode::Pase => {
                let noc_data = cmd_req
                    .trans
                    .session
                    .get_data::<NocData>()
                    .ok_or(IMStatusCode::Failure)?;

                let req =
                    CommonReq::from_tlv(&cmd_req.data).map_err(|_| IMStatusCode::InvalidCommand)?;
                info!("Received Trusted Cert:{:x?}", req.str);

                noc_data.root_ca = Cert::new(req.str.0).map_err(|_| IMStatusCode::Failure)?;
            }
            _ => (),
        }
        cmd_req.trans.complete();

        Err(IMStatusCode::Success)
    }
}

impl ClusterType for NocCluster {
    fn base(&self) -> &Cluster {
        &self.base
    }
    fn base_mut(&mut self) -> &mut Cluster {
        &mut self.base
    }

    fn handle_command(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        let cmd = cmd_req
            .cmd
            .path
            .leaf
            .map(num::FromPrimitive::from_u32)
            .ok_or(IMStatusCode::UnsupportedCommand)?
            .ok_or(IMStatusCode::UnsupportedCommand)?;
        match cmd {
            Commands::AddNOC => self.handle_command_addnoc(cmd_req),
            Commands::CSRReq => self.handle_command_csrrequest(cmd_req),
            Commands::AddTrustedRootCert => self.handle_command_addtrustedrootcert(cmd_req),
            Commands::AttReq => self.handle_command_attrequest(cmd_req),
            Commands::CertChainReq => self.handle_command_certchainrequest(cmd_req),
            Commands::UpdateFabricLabel => self.handle_command_updatefablabel(cmd_req),
            Commands::RemoveFabric => self.handle_command_rmfabric(cmd_req),
            _ => Err(IMStatusCode::UnsupportedCommand),
        }
    }

    fn read_custom_attribute(&self, encoder: &mut dyn Encoder, attr: &AttrDetails) {
        match num::FromPrimitive::from_u16(attr.attr_id) {
            Some(Attributes::CurrentFabricIndex) => {
                encoder.encode(EncodeValue::Value(&attr.fab_idx))
            }
            Some(Attributes::Fabrics) => encoder.encode(EncodeValue::Closure(&|tag, tw| {
                let _ = tw.start_array(tag);
                let _ = self.fabric_mgr.for_each(|entry, fab_idx| {
                    if !attr.fab_filter || attr.fab_idx == fab_idx {
                        let _ = entry
                            .get_fabric_desc(fab_idx)
                            .to_tlv(tw, TagType::Anonymous);
                    }
                });
                let _ = tw.end_container();
            })),
            Some(Attributes::CommissionedFabrics) => {
                let count = self.fabric_mgr.used_count() as u8;
                encoder.encode(EncodeValue::Value(&count))
            }
            _ => {
                error!("Attribute not supported: this shouldn't happen");
            }
        }
    }
}

fn add_attestation_element(
    dev_att: &dyn DevAttDataFetcher,
    att_nonce: &[u8],
    write_buf: &mut WriteBuf,
    t: &mut TLVWriter,
) -> Result<(), Error> {
    let mut cert_dec: [u8; MAX_CERT_DECLARATION_LEN] = [0; MAX_CERT_DECLARATION_LEN];
    let len = dev_att.get_devatt_data(dev_att::DataType::CertDeclaration, &mut cert_dec)?;
    let cert_dec = &cert_dec[0..len];

    let epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;
    let mut writer = TLVWriter::new(write_buf);
    writer.start_struct(TagType::Anonymous)?;
    writer.str16(TagType::Context(1), cert_dec)?;
    writer.str8(TagType::Context(2), att_nonce)?;
    writer.u32(TagType::Context(3), epoch)?;
    writer.end_container()?;

    t.str16(TagType::Context(0), write_buf.as_borrow_slice())?;
    Ok(())
}

fn add_attestation_signature(
    dev_att: &dyn DevAttDataFetcher,
    attest_element: &mut WriteBuf,
    attest_challenge: &[u8],
    resp: &mut TLVWriter,
) -> Result<(), Error> {
    let dac_key = {
        let mut pubkey = [0_u8; crypto::EC_POINT_LEN_BYTES];
        let mut privkey = [0_u8; crypto::BIGNUM_LEN_BYTES];
        dev_att.get_devatt_data(dev_att::DataType::DACPubKey, &mut pubkey)?;
        dev_att.get_devatt_data(dev_att::DataType::DACPrivKey, &mut privkey)?;
        KeyPair::new_from_components(&pubkey, &privkey)
    }?;
    attest_element.copy_from_slice(attest_challenge)?;
    let mut signature = [0u8; crypto::EC_SIGNATURE_LEN_BYTES];
    dac_key.sign_msg(attest_element.as_borrow_slice(), &mut signature)?;
    resp.str8(TagType::Context(1), &signature)
}

fn add_nocsrelement(
    noc_keypair: &KeyPair,
    csr_nonce: &[u8],
    write_buf: &mut WriteBuf,
    resp: &mut TLVWriter,
) -> Result<(), Error> {
    let mut csr: [u8; MAX_CSR_LEN] = [0; MAX_CSR_LEN];
    let csr = noc_keypair.get_csr(&mut csr)?;
    let mut writer = TLVWriter::new(write_buf);
    writer.start_struct(TagType::Anonymous)?;
    writer.str8(TagType::Context(1), csr)?;
    writer.str8(TagType::Context(2), csr_nonce)?;
    writer.end_container()?;

    resp.str8(TagType::Context(0), write_buf.as_borrow_slice())?;
    Ok(())
}

#[derive(ToTLV)]
struct CertChainResp<'a> {
    cert: OctetStr<'a>,
}

#[derive(ToTLV)]
struct NocResp {
    status_code: u8,
    fab_idx: u8,
    debug_txt: String,
}

#[derive(FromTLV)]
#[tlvargs(lifetime = "'a")]
struct AddNocReq<'a> {
    noc_value: OctetStr<'a>,
    icac_value: OctetStr<'a>,
    ipk_value: OctetStr<'a>,
    case_admin_subject: u64,
    vendor_id: u16,
}

#[derive(FromTLV)]
#[tlvargs(lifetime = "'a")]
struct CommonReq<'a> {
    str: OctetStr<'a>,
}

#[derive(FromTLV)]
#[tlvargs(lifetime = "'a")]
struct UpdateFabricLabelReq<'a> {
    label: UtfStr<'a>,
}

#[derive(FromTLV)]
struct CertChainReq {
    cert_type: u8,
}

#[derive(FromTLV)]
struct RemoveFabricReq {
    fab_idx: u8,
}

fn get_certchainrequest_params(data: &TLVElement) -> Result<DataType, Error> {
    let cert_type = CertChainReq::from_tlv(data)?.cert_type;

    const CERT_TYPE_DAC: u8 = 1;
    const CERT_TYPE_PAI: u8 = 2;
    info!("Received Cert Type:{:?}", cert_type);
    match cert_type {
        CERT_TYPE_DAC => Ok(dev_att::DataType::DAC),
        CERT_TYPE_PAI => Ok(dev_att::DataType::PAI),
        _ => Err(Error::Invalid),
    }
}
