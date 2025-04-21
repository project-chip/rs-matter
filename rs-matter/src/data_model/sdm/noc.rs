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
use core::mem::MaybeUninit;
use core::num::NonZeroU8;

use strum::{EnumDiscriminants, FromRepr};

use crate::cert::CertRef;
use crate::crypto::{self, KeyPair};
use crate::data_model::objects::*;
use crate::data_model::sdm::dev_att;
use crate::fabric::MAX_SUPPORTED_FABRICS;
use crate::fmt::Bytes;
use crate::tlv::{FromTLV, OctetStr, TLVElement, TLVTag, TLVWrite, ToTLV, UtfStr};
use crate::transport::exchange::Exchange;
use crate::transport::session::SessionMode;
use crate::utils::init::InitMaybeUninit;
use crate::utils::storage::WriteBuf;
use crate::{
    accepted_commands, alloc, attribute_enum, attributes_access, cmd_enter, command_enum, error::*,
    generated_commands, supported_attributes,
};

use super::dev_att::{DataType, DevAttDataFetcher};

// Node Operational Credentials Cluster

#[derive(Clone, Copy)]
#[allow(dead_code)]
pub enum NocStatus {
    Ok = 0,
    InvalidPublicKey = 1,
    InvalidNodeOpId = 2,
    InvalidNOC = 3,
    MissingCsr = 4,
    TableFull = 5,
    InvalidAdminSubject = 6,
    Reserved1 = 7,
    Reserved2 = 8,
    FabricConflict = 9,
    LabelConflict = 10,
    InvalidFabricIndex = 11,
}

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

#[repr(u32)]
pub enum RespCommands {
    AttReqResp = 0x01,
    CertChainResp = 0x03,
    CSRResp = 0x05,
    NOCResp = 0x08,
}

#[derive(FromRepr, EnumDiscriminants)]
#[repr(u32)]
pub enum Attributes {
    NOCs = 0,
    Fabrics(()) = 1,
    SupportedFabrics(AttrType<u8>) = 2,
    CommissionedFabrics(AttrType<u8>) = 3,
    TrustedRootCerts = 4,
    CurrentFabricIndex(AttrType<u8>) = 5,
}

attribute_enum!(Attributes);

#[derive(Debug, Clone, FromTLV, ToTLV, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
struct NocResp<'a> {
    status_code: u8,
    fab_idx: u8,
    debug_txt: UtfStr<'a>,
}

#[derive(Debug, Clone, FromTLV, ToTLV, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
struct AddNocReq<'a> {
    noc_value: OctetStr<'a>,
    icac_value: Option<OctetStr<'a>>,
    ipk_value: OctetStr<'a>,
    case_admin_subject: u64,
    vendor_id: u16,
}

#[derive(Debug, Clone, FromTLV, ToTLV, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
struct CsrReq<'a> {
    nonce: OctetStr<'a>,
    for_update_noc: Option<bool>,
}

#[derive(Debug, Clone, FromTLV, ToTLV, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
struct CommonReq<'a> {
    str: OctetStr<'a>,
}

#[derive(Debug, Clone, FromTLV, ToTLV, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
struct UpdateFabricLabelReq<'a> {
    label: UtfStr<'a>,
}

#[derive(Debug, Clone, FromTLV, ToTLV, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct CertChainReq {
    cert_type: u8,
}

#[derive(Debug, Clone, FromTLV, ToTLV, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct RemoveFabricReq {
    fab_idx: NonZeroU8,
}

impl NocStatus {
    fn map(result: Result<(), Error>) -> Result<Self, Error> {
        match result {
            Ok(()) => Ok(NocStatus::Ok),
            Err(err) => match err.code() {
                ErrorCode::NocFabricTableFull => Ok(NocStatus::TableFull),
                ErrorCode::NocInvalidFabricIndex => Ok(NocStatus::InvalidFabricIndex),
                ErrorCode::ConstraintError => Ok(NocStatus::MissingCsr),
                _ => Err(err),
            },
        }
    }
}

pub const CLUSTER: Cluster<'static> = Cluster {
    id: ID as _,
    revision: 1,
    feature_map: 0,
    attributes_access: attributes_access!(
        Attribute::new(
            AttributesDiscriminants::CurrentFabricIndex as _,
            Access::RV,
            Quality::NONE,
        ),
        Attribute::new(
            AttributesDiscriminants::Fabrics as _,
            Access::RV.union(Access::FAB_SCOPED),
            Quality::NONE,
        ),
        Attribute::new(
            AttributesDiscriminants::SupportedFabrics as _,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::CommissionedFabrics as _,
            Access::RV,
            Quality::NONE,
        ),
    ),
    supported_attributes: supported_attributes!(
        AttributesDiscriminants::CurrentFabricIndex,
        AttributesDiscriminants::Fabrics,
        AttributesDiscriminants::SupportedFabrics,
        AttributesDiscriminants::CommissionedFabrics,
    ),
    accepted_commands: accepted_commands!(
        Commands::AttReq,
        Commands::CertChainReq,
        Commands::CSRReq,
        Commands::AddNOC,
        Commands::UpdateFabricLabel,
        Commands::RemoveFabric,
        Commands::AddTrustedRootCert,
    ),
    generated_commands: generated_commands!(),
};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
                        writer.start_array(&AttrDataWriter::TAG)?;
                        for fabric in exchange.matter().fabric_mgr.borrow().iter() {
                            if (!attr.fab_filter || attr.fab_idx == fabric.fab_idx().get())
                                && !fabric.root_ca().is_empty()
                            {
                                // Empty `root_ca` might happen in the E2E tests
                                let root_ca_cert = CertRef::new(TLVElement::new(fabric.root_ca()));

                                fabric
                                    .descriptor(&root_ca_cert)?
                                    .to_tlv(&TLVTag::Anonymous, &mut *writer)?;
                            }
                        }

                        writer.end_container()?;

                        writer.complete()
                    }
                    Attributes::CommissionedFabrics(codec) => codec.encode(
                        writer,
                        exchange.matter().fabric_mgr.borrow().iter().count() as _,
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

    fn handle_command_updatefablabel(
        &self,
        exchange: &Exchange,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        cmd_enter!("Update Fabric Label");
        let req = UpdateFabricLabelReq::from_tlv(data).map_err(Error::map_invalid_command)?;
        info!("Received Fabric Label: {:?}", req);

        let mut updated_fab_idx = 0;

        let status = NocStatus::map(exchange.with_session(|sess| {
            let SessionMode::Case { fab_idx, .. } = sess.get_session_mode() else {
                return Err(ErrorCode::GennCommInvalidAuthentication.into());
            };

            updated_fab_idx = fab_idx.get();

            exchange
                .matter()
                .fabric_mgr
                .borrow_mut()
                .update_label(*fab_idx, req.label)
                .map_err(|e| {
                    if e.code() == ErrorCode::Invalid {
                        ErrorCode::NocLabelConflict.into()
                    } else {
                        e
                    }
                })
        }))?;

        Self::create_nocresponse(encoder, status as _, updated_fab_idx, "")
    }

    fn handle_command_rmfabric(
        &self,
        exchange: &Exchange,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        cmd_enter!("Remove Fabric");
        let req = RemoveFabricReq::from_tlv(data).map_err(Error::map_invalid_command)?;
        info!("Received Fabric Index: {:?}", req);

        if exchange
            .matter()
            .fabric_mgr
            .borrow_mut()
            .remove(req.fab_idx, &exchange.matter().transport_mgr.mdns)
            .is_ok()
        {
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

        let r = AddNocReq::from_tlv(data).map_err(Error::map_invalid_command)?;

        info!(
            "Received NOC as: {}",
            CertRef::new(TLVElement::new(r.noc_value.0))
        );

        let icac = r
            .icac_value
            .as_ref()
            .map(|icac| icac.0)
            .filter(|icac| !icac.is_empty());
        if let Some(icac) = icac {
            info!("Received ICAC as: {}", CertRef::new(TLVElement::new(icac)));
        }

        let mut added_fab_idx = 0;

        let mut buf = alloc!([0; 800]); // TODO LARGE BUFFER
        let buf = &mut buf[..];

        let status = NocStatus::map(exchange.with_session(|sess| {
            let fab_idx = exchange.matter().failsafe.borrow_mut().add_noc(
                &exchange.matter().fabric_mgr,
                sess.get_session_mode(),
                r.vendor_id,
                icac,
                r.noc_value.0,
                r.ipk_value.0,
                r.case_admin_subject,
                buf,
                &exchange.matter().transport_mgr.mdns,
            )?;

            let succeeded = Cell::new(false);

            let _fab_guard = scopeguard::guard(fab_idx, |fab_idx| {
                if !succeeded.get() {
                    // Remove the fabric if we fail further down this function
                    warn!("Removing fabric {} due to failure", fab_idx.get());

                    unwrap!(exchange
                        .matter()
                        .fabric_mgr
                        .borrow_mut()
                        .remove(fab_idx, &exchange.matter().transport_mgr.mdns));
                }
            });

            if matches!(sess.get_session_mode(), SessionMode::Pase { .. }) {
                sess.upgrade_fabric_idx(fab_idx)?;
            }

            succeeded.set(true);

            added_fab_idx = fab_idx.get();

            Ok(())
        }))?;

        Self::create_nocresponse(encoder, status, added_fab_idx, "")?;

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

        exchange.with_session(|sess| {
            let mut writer = encoder.with_command(RespCommands::AttReqResp as _)?;

            writer.start_struct(&CmdDataWriter::TAG)?;

            let epoch = (exchange.matter().epoch())().as_secs() as u32;

            let mut signature_buf = MaybeUninit::<[u8; crypto::EC_SIGNATURE_LEN_BYTES]>::uninit(); // TODO MEDIUM BUFFER
            let signature_buf = signature_buf.init_zeroed();
            let mut signature_len = 0;

            writer.str_cb(&TLVTag::Context(0), |buf| {
                let dev_att = exchange.matter().dev_att();

                let mut wb = WriteBuf::new(buf);
                wb.start_struct(&TLVTag::Anonymous)?;
                wb.str_cb(&TLVTag::Context(1), |buf| {
                    dev_att.get_devatt_data(dev_att::DataType::CertDeclaration, buf)
                })?;
                wb.str(&TLVTag::Context(2), req.str.0)?;
                wb.u32(&TLVTag::Context(3), epoch)?;
                wb.end_container()?;

                let len = wb.get_tail();

                signature_len = Self::compute_attestation_signature(
                    dev_att,
                    &mut wb,
                    sess.get_att_challenge(),
                    signature_buf,
                )?
                .len();

                Ok(len)
            })?;
            writer.str(&TLVTag::Context(1), &signature_buf[..signature_len])?;

            writer.end_container()?;

            writer.complete()
        })
    }

    fn handle_command_certchainrequest(
        &self,
        exchange: &Exchange,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        cmd_enter!("CertChainRequest");

        info!("Received data: {}", data);
        let cert_type =
            Self::get_certchainrequest_params(data).map_err(Error::map_invalid_command)?;

        let mut writer = encoder.with_command(RespCommands::CertChainResp as _)?;

        writer.start_struct(&CmdDataWriter::TAG)?;
        writer.str_cb(&TLVTag::Context(0), |buf| {
            exchange.matter().dev_att().get_devatt_data(cert_type, buf)
        })?;
        writer.end_container()?;

        writer.complete()
    }

    fn handle_command_csrrequest(
        &self,
        exchange: &Exchange,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        cmd_enter!("CSRRequest");

        let req = CsrReq::from_tlv(data).map_err(Error::map_invalid_command)?;
        info!("Received CSR: {:?}", req);

        exchange.with_session(|sess| {
            let mut failsafe = exchange.matter().failsafe.borrow_mut();

            let key_pair = if req.for_update_noc.unwrap_or(false) {
                failsafe.update_csr_req(sess.get_session_mode())
            } else {
                failsafe.add_csr_req(sess.get_session_mode())
            }?;

            let mut writer = encoder.with_command(RespCommands::CSRResp as _)?;

            writer.start_struct(&CmdDataWriter::TAG)?;

            let mut signature_buf = MaybeUninit::<[u8; crypto::EC_SIGNATURE_LEN_BYTES]>::uninit(); // TODO MEDIUM BUFFER
            let signature_buf = signature_buf.init_zeroed();
            let mut signature_len = 0;

            writer.str_cb(&TLVTag::Context(0), |buf| {
                let mut wb = WriteBuf::new(buf);

                wb.start_struct(&TLVTag::Anonymous)?;
                wb.str_cb(&TLVTag::Context(1), |buf| Ok(key_pair.get_csr(buf)?.len()))?;
                wb.str(&TLVTag::Context(2), req.nonce.0)?;
                wb.end_container()?;

                let len = wb.get_tail();

                signature_len = Self::compute_attestation_signature(
                    exchange.matter().dev_att(),
                    &mut wb,
                    sess.get_att_challenge(),
                    signature_buf,
                )?
                .len();

                Ok(len)
            })?;
            writer.str(&TLVTag::Context(1), &signature_buf[..signature_len])?;

            writer.end_container()?;

            writer.complete()
        })
    }

    fn handle_command_addtrustedrootcert(
        &self,
        exchange: &Exchange,
        data: &TLVElement,
    ) -> Result<(), Error> {
        cmd_enter!("AddTrustedRootCert");

        let req = CommonReq::from_tlv(data).map_err(Error::map_invalid_command)?;
        info!("Received Trusted Cert: {}", Bytes(&req.str));

        exchange.with_session(|sess| {
            exchange
                .matter()
                .failsafe
                .borrow_mut()
                .add_trusted_root_cert(sess.get_session_mode(), req.str.0)
        })
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
            debug_txt,
        };

        encoder
            .with_command(RespCommands::NOCResp as _)?
            .set(cmd_data)
    }

    fn compute_attestation_signature<'a>(
        dev_att: &dyn DevAttDataFetcher,
        attest_element: &mut WriteBuf,
        attest_challenge: &[u8],
        signature_buf: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let dac_key = {
            let mut pubkey_buf = MaybeUninit::<[u8; crypto::EC_POINT_LEN_BYTES]>::uninit(); // TODO MEDIUM BUFFER
            let pubkey_buf = pubkey_buf.init_zeroed();

            let mut privkey_buf = MaybeUninit::<[u8; crypto::BIGNUM_LEN_BYTES]>::uninit(); // TODO MEDIUM BUFFER
            let privkey_buf = privkey_buf.init_zeroed();

            let pubkey_len = dev_att.get_devatt_data(dev_att::DataType::DACPubKey, pubkey_buf)?;
            let privkey_len =
                dev_att.get_devatt_data(dev_att::DataType::DACPrivKey, privkey_buf)?;

            KeyPair::new_from_components(&pubkey_buf[..pubkey_len], &privkey_buf[..privkey_len])
        }?;

        attest_element.copy_from_slice(attest_challenge)?;
        let len = dac_key.sign_msg(attest_element.as_slice(), signature_buf)?;

        Ok(&signature_buf[..len])
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
