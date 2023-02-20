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

use crate::data_model::{core::DataModel, objects::*};
use crate::{
    acl::{AccessReq, Accessor},
    error::*,
    interaction_model::{
        core::IMStatusCode,
        messages::{
            ib::{self, DataVersionFilter},
            msg::{self, ReadReq, ReportDataTag::MoreChunkedMsgs, ReportDataTag::SupressResponse},
            GenericPath,
        },
        Transaction,
    },
    tlv::{TLVArray, TLVWriter, TagType, ToTLV},
};

/// Encoder for generating a response to a read request
pub struct AttrReadEncoder<'a, 'b, 'c> {
    tw: &'a mut TLVWriter<'b, 'c>,
    data_ver: u32,
    path: GenericPath,
    skip_error: bool,
    data_ver_filters: Option<&'a TLVArray<'a, DataVersionFilter>>,
    is_buffer_full: bool,
}

impl<'a, 'b, 'c> AttrReadEncoder<'a, 'b, 'c> {
    pub fn new(tw: &'a mut TLVWriter<'b, 'c>) -> Self {
        Self {
            tw,
            data_ver: 0,
            skip_error: false,
            path: Default::default(),
            data_ver_filters: None,
            is_buffer_full: false,
        }
    }

    pub fn skip_error(&mut self, skip: bool) {
        self.skip_error = skip;
    }

    pub fn set_data_ver(&mut self, data_ver: u32) {
        self.data_ver = data_ver;
    }

    pub fn set_data_ver_filters(&mut self, filters: &'a TLVArray<'a, DataVersionFilter>) {
        self.data_ver_filters = Some(filters);
    }

    pub fn set_path(&mut self, path: GenericPath) {
        self.path = path;
    }

    pub fn is_buffer_full(&self) -> bool {
        self.is_buffer_full
    }
}

impl<'a, 'b, 'c> Encoder for AttrReadEncoder<'a, 'b, 'c> {
    fn encode(&mut self, value: EncodeValue) {
        let resp = ib::AttrResp::Data(ib::AttrData::new(
            Some(self.data_ver),
            ib::AttrPath::new(&self.path),
            value,
        ));

        let anchor = self.tw.get_tail();
        if resp.to_tlv(self.tw, TagType::Anonymous).is_err() {
            self.is_buffer_full = true;
            self.tw.rewind_to(anchor);
        }
    }

    fn encode_status(&mut self, status: IMStatusCode, cluster_status: u16) {
        if !self.skip_error {
            let resp =
                ib::AttrResp::Status(ib::AttrStatus::new(&self.path, status, cluster_status));
            let _ = resp.to_tlv(self.tw, TagType::Anonymous);
        }
    }
}

/// State to maintain when a Read Request needs to be resumed
/// resumed - the next chunk of the read needs to be returned
#[derive(Default)]
pub struct ResumeReadReq {
    /// The Read Request Attribute Path that caused chunking, and this is the path
    /// that needs to be resumed.
    ///
    /// TODO: Ideally, the entire ReadRequest (with any subsequent AttrPaths) should also
    /// be maintained. But for now, we just store the AttrPath that caused the overflow
    /// and chunking. Hopefully, the other end requests any pending paths when it sees no
    /// more chunks.
    pending_path: GenericPath,

    /// The Attribute that couldn't be encoded because our buffer got full. The next chunk
    /// will start encoding from this attribute onwards.
    /// Note that given wildcard reads, one PendingPath in the member above can generated
    /// multiple encode paths. Hence this has to be maintained separately.
    resume_encode: Option<GenericPath>,
}

impl DataModel {
    pub fn read_attribute_raw(
        &self,
        endpoint: u16,
        cluster: u32,
        attr: u16,
    ) -> Result<AttrValue, IMStatusCode> {
        let node = self.node.read().unwrap();
        let cluster = node.get_cluster(endpoint, cluster)?;
        cluster.base().read_attribute_raw(attr).map(|a| a.clone())
    }
    /// Encode a read attribute from a path that may or may not be wildcard
    ///
    /// If the buffer gets full while generating the read response, we will return
    /// an Err(path), where the path is the path that we should resume from, for the next chunk.
    /// This facilitates chunk management
    fn handle_read_attr_path(
        node: &Node,
        accessor: &Accessor,
        attr_encoder: &mut AttrReadEncoder,
        attr_details: &mut AttrDetails,
        resume_from: &mut Option<GenericPath>,
    ) -> Result<(), Error> {
        let mut status = Ok(());
        let path = attr_encoder.path;

        // Skip error reporting for wildcard paths, don't for concrete paths
        attr_encoder.skip_error(path.is_wildcard());

        let result = node.for_each_attribute(&path, |path, c| {
            // Ignore processing if data filter matches.
            // For a wildcard attribute, this may end happening unnecessarily for all attributes, although
            // a single skip for the cluster is sufficient. That requires us to replace this for_each with a
            // for_each_cluster
            let cluster_data_ver = c.base().get_dataver();
            if Self::data_filter_matches(&attr_encoder.data_ver_filters, path, cluster_data_ver) {
                return Ok(());
            }

            // The resume_from indicates that this is the next chunk of a previous Read Request. In such cases, we
            // need to skip until we hit this path.
            if let Some(r) = resume_from {
                // If resume_from is valid, and we haven't hit the resume_from yet, skip encoding
                if r != path {
                    return Ok(());
                } else {
                    // Else, wipe out the resume_from so subsequent paths can be encoded
                    *resume_from = None;
                }
            }

            attr_details.attr_id = path.leaf.unwrap_or_default() as u16;
            // Overwrite the previous path with the concrete path
            attr_encoder.set_path(*path);
            // Set the cluster's data version
            attr_encoder.set_data_ver(cluster_data_ver);
            let mut access_req = AccessReq::new(accessor, path, Access::READ);
            Cluster::read_attribute(c, &mut access_req, attr_encoder, attr_details);
            if attr_encoder.is_buffer_full() {
                // Buffer is full, next time resume from this attribute
                *resume_from = Some(*path);
                status = Err(Error::NoSpace);
            }
            Ok(())
        });
        if let Err(e) = result {
            // We hit this only if this is a non-wildcard path
            attr_encoder.encode_status(e, 0);
        }
        status
    }

    /// Process an array of Attribute Read Requests
    pub(super) fn handle_read_attr_array(
        &self,
        read_req: &ReadReq,
        trans: &mut Transaction,
        tw: &mut TLVWriter,
    ) -> Result<(), Error> {
        let mut resume_read_req: ResumeReadReq = Default::default();

        let mut attr_encoder = AttrReadEncoder::new(tw);
        if let Some(filters) = &read_req.dataver_filters {
            attr_encoder.set_data_ver_filters(filters);
        }

        if let Some(attr_requests) = &read_req.attr_requests {
            let accessor = self.sess_to_accessor(trans.session);
            let mut attr_details = AttrDetails::new(accessor.fab_idx, read_req.fabric_filtered);
            let node = self.node.read().unwrap();
            attr_encoder
                .tw
                .start_array(TagType::Context(msg::ReportDataTag::AttributeReports as u8))?;

            let mut result = Ok(());
            for attr_path in attr_requests.iter() {
                attr_encoder.set_path(attr_path.to_gp());
                // Extract the attr_path fields into various structures
                attr_details.list_index = attr_path.list_index;
                result = DataModel::handle_read_attr_path(
                    &node,
                    &accessor,
                    &mut attr_encoder,
                    &mut attr_details,
                    &mut resume_read_req.resume_encode,
                );
                if result.is_err() {
                    resume_read_req.pending_path = attr_path.to_gp();
                    break;
                }
            }
            tw.end_container()?;
            if result.is_err() {
                // If there was an error, indicate chunking. The resume_read_req would have been
                // already populated from in the loop above.
                tw.bool(TagType::Context(MoreChunkedMsgs as u8), true)?;
                tw.bool(TagType::Context(SupressResponse as u8), false)?;
                // Don't complete the transaction
            } else {
                tw.bool(TagType::Context(SupressResponse as u8), true)?;
                trans.complete();
            }
        }
        Ok(())
    }
}
