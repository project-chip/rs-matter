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

use core::cell::Cell;
use core::num::NonZeroU8;

use log::{error, info, warn};

use strum::{EnumDiscriminants, FromRepr};

use crate::acl::{AclEntry, AuthMode};
use crate::cert::{Cert, MAX_CERT_TLV_LEN};
use crate::crypto::{self, KeyPair};
use crate::data_model::objects::*;
use crate::data_model::sdm::dev_att;
use crate::fabric::{Fabric, MAX_SUPPORTED_FABRICS};
use crate::tlv::{FromTLV, OctetStr, TLVElement, TLVWriter, TagType, ToTLV, UtfStr};
use crate::transport::exchange::Exchange;
use crate::transport::session::SessionMode;
use crate::utils::epoch::Epoch;
use crate::utils::storage::WriteBuf;
use crate::{attribute_enum, cmd_enter, command_enum, error::*};

use super::dev_att::{DataType, DevAttDataFetcher};

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

enum NocError {
    Status(NocStatus),
    Error(Error),
}

impl From<NocStatus> for NocError {
    fn from(value: NocStatus) -> Self {
        Self::Status(value)
    }
}

impl From<Error> for NocError {
    fn from(value: Error) -> Self {
        Self::Error(value)
    }
}

// Some placeholder value for now
const MAX_CERT_DECLARATION_LEN: usize = 600;
// Some placeholder value for now
const MAX_CSR_LEN: usize = 300;
// As defined in the Matter Spec
const RESP_MAX: usize = 900;

pub const ID: u32 = 0x003E;

#[derive(FromRepr)]
#[repr(u32)]
pub enum Commands {
    AttReq = 0x00,
    CertChainReq = 0x02,
    CSRReq = 0x04,
    AddNOC = 0x06,
    UpdateFabricLabel = 0x09,
    RemoveFabric = 0x0a,
    AddTrustedRootCert = 0x0b,
}

command_enum!(Commands);

#[repr(u16)]
pub enum RespCommands {
    AttReqResp = 0x01,
    CertChainResp = 0x03,
    CSRResp = 0x05,
    NOCResp = 0x08,
}

#[derive(FromRepr, EnumDiscriminants)]
#[repr(u16)]
pub enum Attributes {
    NOCs = 0,
    Fabrics(()) = 1,
    SupportedFabrics(AttrType<u8>) = 2,
    CommissionedFabrics(AttrType<u8>) = 3,
    TrustedRootCerts = 4,
    CurrentFabricIndex(AttrType<u8>) = 5,
}

attribute_enum!(Attributes);

pub const CLUSTER: Cluster<'static> = Cluster {
    id: ID as _,
    feature_map: 0,
    attributes: &[
        FEATURE_MAP,
        ATTRIBUTE_LIST,
        Attribute::new(
            AttributesDiscriminants::CurrentFabricIndex as u16,
            Access::RV,
            Quality::NONE,
        ),
        Attribute::new(
            AttributesDiscriminants::Fabrics as u16,
            Access::RV.union(Access::FAB_SCOPED),
            Quality::NONE,
        ),
        Attribute::new(
            AttributesDiscriminants::SupportedFabrics as u16,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::CommissionedFabrics as u16,
            Access::RV,
            Quality::NONE,
        ),
    ],
    commands: &[
        Commands::AttReq as _,
        Commands::CertChainReq as _,
        Commands::CSRReq as _,
        Commands::AddNOC as _,
        Commands::UpdateFabricLabel as _,
        Commands::RemoveFabric as _,
        Commands::AddTrustedRootCert as _,
    ],
};

pub struct NocData {
    pub key_pair: KeyPair,
    pub root_ca: crate::utils::storage::Vec<u8, { MAX_CERT_TLV_LEN }>,
}

impl NocData {
    pub fn new(key_pair: KeyPair) -> Self {
        Self {
            key_pair,
            root_ca: crate::utils::storage::Vec::new(),
        }
    }
}

#[derive(ToTLV)]
struct CertChainResp<'a> {
    cert: OctetStr<'a>,
}

#[derive(ToTLV)]
struct NocResp<'a> {
    status_code: u8,
    fab_idx: u8,
    debug_txt: UtfStr<'a>,
}

#[derive(FromTLV)]
#[tlvargs(lifetime = "'a")]
struct AddNocReq<'a> {
    noc_value: OctetStr<'a>,
    icac_value: Option<OctetStr<'a>>,
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
    fab_idx: NonZeroU8,
}

#[derive(Debug, Clone)]
pub struct NocCluster {
    data_ver: Dataver,
}

impl NocCluster {
    pub const fn new(data_ver: Dataver) -> Self {
        Self { data_ver }
    }

    pub fn read(
        &self,
        exchange: &Exchange,
        attr: &AttrDetails,
        encoder: AttrDataEncoder,
    ) -> Result<(), Error> {
        if let Some(mut writer) = encoder.with_dataver(self.data_ver.get())? {
            if attr.is_system() {
                CLUSTER.read(attr.attr_id, writer)
            } else {
                match attr.attr_id.try_into()? {
                    Attributes::SupportedFabrics(codec) => {
                        codec.encode(writer, MAX_SUPPORTED_FABRICS as _)
                    }
                    Attributes::CurrentFabricIndex(codec) => codec.encode(writer, attr.fab_idx),
                    Attributes::Fabrics(_) => {
                        writer.start_array(AttrDataWriter::TAG)?;
                        exchange
                            .matter()
                            .fabric_mgr
                            .borrow()
                            .for_each(|entry, fab_idx| {
                                if !attr.fab_filter || attr.fab_idx == fab_idx.get() {
                                    let root_ca_cert = entry.get_root_ca()?;

                                    entry
                                        .get_fabric_desc(fab_idx, &root_ca_cert)?
                                        .to_tlv(&mut writer, TagType::Anonymous)?;
                                }

                                Ok(())
                            })?;
                        writer.end_container()?;

                        writer.complete()
                    }
                    Attributes::CommissionedFabrics(codec) => codec.encode(
                        writer,
                        exchange.matter().fabric_mgr.borrow().used_count() as _,
                    ),
                    _ => {
                        error!("Attribute not supported: this shouldn't happen");
                        Err(ErrorCode::AttributeNotFound.into())
                    }
                }
            }
        } else {
            Ok(())
        }
    }

    pub fn invoke(
        &self,
        exchange: &Exchange,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        match cmd.cmd_id.try_into()? {
            Commands::AddNOC => self.handle_command_addnoc(exchange, data, encoder)?,
            Commands::CSRReq => self.handle_command_csrrequest(exchange, data, encoder)?,
            Commands::AddTrustedRootCert => {
                self.handle_command_addtrustedrootcert(exchange, data)?
            }
            Commands::AttReq => self.handle_command_attrequest(exchange, data, encoder)?,
            Commands::CertChainReq => {
                self.handle_command_certchainrequest(exchange, data, encoder)?
            }
            Commands::UpdateFabricLabel => {
                self.handle_command_updatefablabel(exchange, data, encoder)?;
            }
            Commands::RemoveFabric => self.handle_command_rmfabric(exchange, data, encoder)?,
        }

        self.data_ver.changed();

        Ok(())
    }

    fn _handle_command_addnoc(
        &self,
        exchange: &Exchange,
        data: &TLVElement,
    ) -> Result<NonZeroU8, NocError> {
        let noc_data = exchange
            .with_session(|sess| Ok(sess.take_noc_data()))?
            .ok_or(NocStatus::MissingCsr)?;

        if !exchange
            .matter()
            .failsafe
            .borrow_mut()
            .allow_noc_change()
            .map_err(|_| NocStatus::InsufficientPrivlege)?
        {
            error!("AddNOC not allowed by Fail Safe");
            Err(NocStatus::InsufficientPrivlege)?;
        }

        let r = AddNocReq::from_tlv(data).map_err(|_| NocStatus::InvalidNOC)?;

        let noc_cert = Cert::new(r.noc_value.0).map_err(|_| NocStatus::InvalidNOC)?;
        info!("Received NOC as: {}", noc_cert);

        let noc = crate::utils::storage::Vec::from_slice(r.noc_value.0)
            .map_err(|_| NocStatus::InvalidNOC)?;

        let icac = if let Some(icac_value) = r.icac_value {
            if !icac_value.0.is_empty() {
                let icac_cert = Cert::new(icac_value.0).map_err(|_| NocStatus::InvalidNOC)?;
                info!("Received ICAC as: {}", icac_cert);

                let icac = crate::utils::storage::Vec::from_slice(icac_value.0)
                    .map_err(|_| NocStatus::InvalidNOC)?;
                Some(icac)
            } else {
                None
            }
        } else {
            None
        };

        let fabric = Fabric::new(
            noc_data.key_pair,
            noc_data.root_ca,
            icac,
            noc,
            r.ipk_value.0,
            r.vendor_id,
            "",
        )
        .map_err(|_| NocStatus::TableFull)?;

        let fab_idx = exchange
            .matter()
            .fabric_mgr
            .borrow_mut()
            .add(fabric, &exchange.matter().transport_mgr.mdns)
            .map_err(|_| NocStatus::TableFull)?;

        let succeeded = Cell::new(false);

        let _fab_guard = scopeguard::guard(fab_idx, |fab_idx| {
            if !succeeded.get() {
                // Remove the fabric if we fail further down this function
                warn!("Removing fabric {} due to failure", fab_idx.get());

                exchange
                    .matter()
                    .fabric_mgr
                    .borrow_mut()
                    .remove(fab_idx, &exchange.matter().transport_mgr.mdns)
                    .unwrap();
            }
        });

        let mut acl = AclEntry::new(fab_idx, Privilege::ADMIN, AuthMode::Case);
        acl.add_subject(r.case_admin_subject)?;
        let acl_entry_index = exchange.matter().acl_mgr.borrow_mut().add(acl)?;

        let _acl_guard = scopeguard::guard(fab_idx, |fab_idx| {
            if !succeeded.get() {
                // Remove the ACL entry if we fail further down this function
                warn!(
                    "Removing ACL entry {}/{} due to failure",
                    acl_entry_index,
                    fab_idx.get()
                );

                exchange
                    .matter()
                    .acl_mgr
                    .borrow_mut()
                    .delete(acl_entry_index, fab_idx)
                    .unwrap();
            }
        });

        exchange
            .matter()
            .failsafe
            .borrow_mut()
            .record_add_noc(fab_idx)?;

        // Finally, upgrade our session with the new fabric index
        exchange.with_session(|sess| {
            if matches!(sess.get_session_mode(), SessionMode::Pase { .. }) {
                sess.upgrade_fabric_idx(fab_idx)?;
            }

            Ok(())
        })?;

        // Leave the fabric and its ACLs in place now that we've updated everything
        succeeded.set(true);

        Ok(fab_idx)
    }

    fn create_nocresponse(
        encoder: CmdDataEncoder,
        status_code: NocStatus,
        fab_idx: u8,
        debug_txt: &str,
    ) -> Result<(), Error> {
        let cmd_data = NocResp {
            status_code: status_code as u8,
            fab_idx,
            debug_txt: UtfStr::new(debug_txt.as_bytes()),
        };

        encoder
            .with_command(RespCommands::NOCResp as _)?
            .set(cmd_data)
    }

    fn handle_command_updatefablabel(
        &self,
        exchange: &Exchange,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        cmd_enter!("Update Fabric Label");
        let req = UpdateFabricLabelReq::from_tlv(data).map_err(Error::map_invalid_data_type)?;
        let (result, fab_idx) = if let SessionMode::Case { fab_idx, .. } =
            exchange.with_session(|sess| Ok(sess.get_session_mode().clone()))?
        {
            if exchange
                .matter()
                .fabric_mgr
                .borrow_mut()
                .set_label(
                    fab_idx,
                    req.label.as_str().map_err(Error::map_invalid_data_type)?,
                )
                .is_err()
            {
                (NocStatus::LabelConflict, fab_idx.get())
            } else {
                (NocStatus::Ok, fab_idx.get())
            }
        } else {
            // Update Fabric Label not allowed
            (NocStatus::InvalidFabricIndex, 0)
        };

        Self::create_nocresponse(encoder, result, fab_idx, "")?;

        Ok(())
    }

    fn handle_command_rmfabric(
        &self,
        exchange: &Exchange,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        cmd_enter!("Remove Fabric");
        let req = RemoveFabricReq::from_tlv(data).map_err(Error::map_invalid_data_type)?;
        if exchange
            .matter()
            .fabric_mgr
            .borrow_mut()
            .remove(req.fab_idx, &exchange.matter().transport_mgr.mdns)
            .is_ok()
        {
            let _ = exchange
                .matter()
                .acl_mgr
                .borrow_mut()
                .delete_for_fabric(req.fab_idx);
            exchange
                .matter()
                .transport_mgr
                .session_mgr
                .borrow_mut()
                .remove_for_fabric(req.fab_idx);
            exchange.matter().transport_mgr.session_removed.notify();

            // Note that since we might have removed our own session, the exchange
            // will terminate with a "NoSession" error, but that's OK and handled properly

            Ok(())
        } else {
            Self::create_nocresponse(
                encoder,
                NocStatus::InvalidFabricIndex,
                req.fab_idx.get(),
                "",
            )
        }
    }

    fn handle_command_addnoc(
        &self,
        exchange: &Exchange,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        cmd_enter!("AddNOC");

        let (status, fab_idx) = match self._handle_command_addnoc(exchange, data) {
            Ok(fab_idx) => (NocStatus::Ok, fab_idx.get()),
            Err(NocError::Status(status)) => (status, 0),
            Err(NocError::Error(error)) => Err(error)?,
        };

        Self::create_nocresponse(encoder, status, fab_idx, "")?;

        Ok(())
    }

    fn handle_command_attrequest(
        &self,
        exchange: &Exchange,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        cmd_enter!("AttestationRequest");

        let req = CommonReq::from_tlv(data).map_err(Error::map_invalid_command)?;
        info!("Received Attestation Nonce:{:?}", req.str);

        let mut attest_challenge = [0u8; crypto::SYMM_KEY_LEN_BYTES];
        exchange.with_session(|sess| {
            attest_challenge.copy_from_slice(sess.get_att_challenge());
            Ok(())
        })?;

        let mut writer = encoder.with_command(RespCommands::AttReqResp as _)?;

        let mut buf: [u8; RESP_MAX] = [0; RESP_MAX];
        let mut attest_element = WriteBuf::new(&mut buf);
        writer.start_struct(CmdDataWriter::TAG)?;
        add_attestation_element(
            exchange.matter().epoch(),
            exchange.matter().dev_att(),
            req.str.0,
            &mut attest_element,
            &mut writer,
        )?;
        add_attestation_signature(
            exchange.matter().dev_att(),
            &mut attest_element,
            &attest_challenge,
            &mut writer,
        )?;
        writer.end_container()?;

        writer.complete()?;

        Ok(())
    }

    fn handle_command_certchainrequest(
        &self,
        exchange: &Exchange,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        cmd_enter!("CertChainRequest");

        info!("Received data: {}", data);
        let cert_type = get_certchainrequest_params(data).map_err(Error::map_invalid_command)?;

        let mut buf: [u8; RESP_MAX] = [0; RESP_MAX];
        let len = exchange
            .matter()
            .dev_att()
            .get_devatt_data(cert_type, &mut buf)?;
        let buf = &buf[0..len];

        let cmd_data = CertChainResp {
            cert: OctetStr::new(buf),
        };

        encoder
            .with_command(RespCommands::CertChainResp as _)?
            .set(cmd_data)?;

        Ok(())
    }

    fn handle_command_csrrequest(
        &self,
        exchange: &Exchange,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        cmd_enter!("CSRRequest");

        let req = CommonReq::from_tlv(data).map_err(Error::map_invalid_command)?;
        info!("Received CSR Nonce:{:?}", req.str);

        if !exchange.matter().failsafe.borrow().is_armed() {
            Err(ErrorCode::UnsupportedAccess)?;
        }

        let noc_keypair = KeyPair::new(exchange.matter().rand())?;
        let mut attest_challenge = [0u8; crypto::SYMM_KEY_LEN_BYTES];
        exchange.with_session(|sess| {
            attest_challenge.copy_from_slice(sess.get_att_challenge());
            Ok(())
        })?;

        let mut writer = encoder.with_command(RespCommands::CSRResp as _)?;

        let mut buf: [u8; RESP_MAX] = [0; RESP_MAX];
        let mut nocsr_element = WriteBuf::new(&mut buf);
        writer.start_struct(CmdDataWriter::TAG)?;
        add_nocsrelement(&noc_keypair, req.str.0, &mut nocsr_element, &mut writer)?;
        add_attestation_signature(
            exchange.matter().dev_att(),
            &mut nocsr_element,
            &attest_challenge,
            &mut writer,
        )?;
        writer.end_container()?;

        writer.complete()?;

        let noc_data = NocData::new(noc_keypair);
        // Store this in the session data instead of cluster data, so it gets cleared
        // if the session goes away for some reason
        exchange.with_session(|sess| {
            sess.set_noc_data(noc_data);
            Ok(())
        })?;

        Ok(())
    }

    fn add_rca_to_session_noc_data(exchange: &Exchange, data: &TLVElement) -> Result<(), Error> {
        exchange.with_session(|sess| {
            let noc_data = sess.get_noc_data().ok_or(ErrorCode::NoSession)?;

            let req = CommonReq::from_tlv(data).map_err(Error::map_invalid_command)?;
            info!("Received Trusted Cert:{:x?}", req.str);

            noc_data.root_ca = crate::utils::storage::Vec::from_slice(req.str.0)
                .map_err(|_| ErrorCode::BufferTooSmall)?;

            Ok(())
        })
    }

    fn handle_command_addtrustedrootcert(
        &self,
        exchange: &Exchange,
        data: &TLVElement,
    ) -> Result<(), Error> {
        cmd_enter!("AddTrustedRootCert");
        if !exchange.matter().failsafe.borrow().is_armed() {
            Err(ErrorCode::UnsupportedAccess)?;
        }

        // This may happen on CASE or PASE. For PASE, the existence of NOC Data is necessary
        match exchange.with_session(|sess| Ok(sess.get_session_mode().clone()))? {
            SessionMode::Case { .. } => {
                // TODO - Updating the Trusted RCA of an existing Fabric
                Self::add_rca_to_session_noc_data(exchange, data)?;
            }
            SessionMode::Pase { .. } => {
                Self::add_rca_to_session_noc_data(exchange, data)?;
            }
            _ => (),
        }

        Ok(())
    }
}

impl Handler for NocCluster {
    fn read(
        &self,
        exchange: &Exchange,
        attr: &AttrDetails,
        encoder: AttrDataEncoder,
    ) -> Result<(), Error> {
        NocCluster::read(self, exchange, attr, encoder)
    }

    fn invoke(
        &self,
        exchange: &Exchange,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        NocCluster::invoke(self, exchange, cmd, data, encoder)
    }
}

impl NonBlockingHandler for NocCluster {}

impl ChangeNotifier<()> for NocCluster {
    fn consume_change(&mut self) -> Option<()> {
        self.data_ver.consume_change(())
    }
}

fn add_attestation_element(
    epoch: Epoch,
    dev_att: &dyn DevAttDataFetcher,
    att_nonce: &[u8],
    write_buf: &mut WriteBuf,
    t: &mut TLVWriter,
) -> Result<(), Error> {
    let mut cert_dec: [u8; MAX_CERT_DECLARATION_LEN] = [0; MAX_CERT_DECLARATION_LEN];
    let len = dev_att.get_devatt_data(dev_att::DataType::CertDeclaration, &mut cert_dec)?;
    let cert_dec = &cert_dec[0..len];

    let epoch = epoch().as_secs() as u32;
    let mut writer = TLVWriter::new(write_buf);
    writer.start_struct(TagType::Anonymous)?;
    writer.str16(TagType::Context(1), cert_dec)?;
    writer.str8(TagType::Context(2), att_nonce)?;
    writer.u32(TagType::Context(3), epoch)?;
    writer.end_container()?;

    t.str16(TagType::Context(0), write_buf.as_slice())
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
    dac_key.sign_msg(attest_element.as_slice(), &mut signature)?;
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

    resp.str8(TagType::Context(0), write_buf.as_slice())
}

fn get_certchainrequest_params(data: &TLVElement) -> Result<DataType, Error> {
    let cert_type = CertChainReq::from_tlv(data)?.cert_type;

    const CERT_TYPE_DAC: u8 = 1;
    const CERT_TYPE_PAI: u8 = 2;
    info!("Received Cert Type:{:?}", cert_type);
    match cert_type {
        CERT_TYPE_DAC => Ok(dev_att::DataType::DAC),
        CERT_TYPE_PAI => Ok(dev_att::DataType::PAI),
        _ => Err(ErrorCode::Invalid.into()),
    }
}
