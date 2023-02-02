use core::time;
use std::thread;

use log::{info, warn};
use matter::{
    interaction_model::{
        core::{IMStatusCode, OpCode},
        messages::{
            ib::{AttrData, AttrPath, AttrResp, AttrStatus, CmdData, DataVersionFilter},
            msg::{
                self, InvReq, ReadReq, ReportDataMsg, StatusResp, TimedReq, WriteReq, WriteResp,
                WriteRespTag,
            },
        },
    },
    tlv::{self, FromTLV, TLVArray, ToTLV},
    transport::{
        exchange::{self, Exchange},
        session::NocCatIds,
    },
    Matter,
};

use super::{
    attributes::assert_attr_report,
    commands::{assert_inv_response, ExpectedInvResp},
    im_engine::{ImEngine, ImInput, IM_ENGINE_PEER_ID},
};

pub enum WriteResponse<'a> {
    TransactionError,
    TransactionSuccess(&'a [AttrStatus]),
}

pub enum TimedInvResponse<'a> {
    TransactionError(IMStatusCode),
    TransactionSuccess(&'a [ExpectedInvResp]),
}

impl<'a> ImEngine<'a> {
    // Helper for handling Read Req sequences for this file
    pub fn handle_read_reqs(
        &mut self,
        peer_node_id: u64,
        input: &[AttrPath],
        expected: &[AttrResp],
    ) {
        let mut out_buf = [0u8; 400];
        let received = self.gen_read_reqs_output(peer_node_id, input, None, &mut out_buf);
        assert_attr_report(&received, expected)
    }

    pub fn new_with_read_reqs(
        matter: &'a Matter<'a>,
        input: &[AttrPath],
        expected: &[AttrResp],
    ) -> Self {
        let mut im = Self::new(matter);

        let mut out_buf = [0u8; 400];
        let received = im.gen_read_reqs_output(IM_ENGINE_PEER_ID, input, None, &mut out_buf);
        assert_attr_report(&received, expected);

        im
    }

    pub fn gen_read_reqs_output<'b>(
        &mut self,
        peer_node_id: u64,
        input: &[AttrPath],
        dataver_filters: Option<TLVArray<'b, DataVersionFilter>>,
        out_buf: &'b mut [u8],
    ) -> ReportDataMsg<'b> {
        let mut read_req = ReadReq::new(true).set_attr_requests(input);
        read_req.dataver_filters = dataver_filters;

        let mut input = ImInput::new(OpCode::ReadRequest, &read_req);
        input.set_peer_node_id(peer_node_id);

        let (_, out_buf) = self.process(&input, out_buf);

        tlv::print_tlv_list(out_buf);
        let root = tlv::get_root_node_struct(out_buf).unwrap();
        ReportDataMsg::from_tlv(&root).unwrap()
    }

    pub fn handle_write_reqs(
        &mut self,
        peer_node_id: u64,
        peer_cat_ids: Option<&NocCatIds>,
        input: &[AttrData],
        expected: &[AttrStatus],
    ) {
        let mut out_buf = [0u8; 400];
        let write_req = WriteReq::new(false, input);

        let mut input = ImInput::new(OpCode::WriteRequest, &write_req);
        input.set_peer_node_id(peer_node_id);
        if let Some(cat_ids) = peer_cat_ids {
            input.set_cat_ids(cat_ids);
        }

        let (_, out_buf) = self.process(&input, &mut out_buf);

        tlv::print_tlv_list(out_buf);
        let root = tlv::get_root_node_struct(out_buf).unwrap();

        let mut index = 0;
        let response_iter = root
            .find_tag(WriteRespTag::WriteResponses as u32)
            .unwrap()
            .confirm_array()
            .unwrap()
            .enter()
            .unwrap();

        for response in response_iter {
            info!("Validating index {}", index);
            let status = AttrStatus::from_tlv(&response).unwrap();
            assert_eq!(expected[index], status);
            info!("Index {} success", index);
            index += 1;
        }
        assert_eq!(index, expected.len());
    }

    pub fn new_with_write_reqs(
        matter: &'a Matter<'a>,
        input: &[AttrData],
        expected: &[AttrStatus],
    ) -> Self {
        let mut im = Self::new(matter);

        im.handle_write_reqs(IM_ENGINE_PEER_ID, None, input, expected);

        im
    }

    // Helper for handling Invoke Command sequences
    pub fn handle_commands(
        &mut self,
        peer_node_id: u64,
        input: &[CmdData],
        expected: &[ExpectedInvResp],
    ) {
        let mut out_buf = [0u8; 400];
        let req = InvReq {
            suppress_response: Some(false),
            timed_request: Some(false),
            inv_requests: Some(TLVArray::Slice(input)),
        };

        let mut input = ImInput::new(OpCode::InvokeRequest, &req);
        input.set_peer_node_id(peer_node_id);

        let (_, out_buf) = self.process(&input, &mut out_buf);
        tlv::print_tlv_list(out_buf);
        let root = tlv::get_root_node_struct(out_buf).unwrap();
        let resp = msg::InvResp::from_tlv(&root).unwrap();
        assert_inv_response(&resp, expected)
    }

    pub fn new_with_commands(
        matter: &'a Matter<'a>,
        input: &[CmdData],
        expected: &[ExpectedInvResp],
    ) -> Self {
        let mut im = ImEngine::new(matter);

        im.handle_commands(IM_ENGINE_PEER_ID, input, expected);

        im
    }

    fn handle_timed_reqs<'b>(
        &mut self,
        opcode: OpCode,
        request: &dyn ToTLV,
        timeout: u16,
        delay: u16,
        output: &'b mut [u8],
    ) -> (u8, &'b [u8]) {
        // Use the same exchange for all parts of the transaction
        self.exch = Some(Exchange::new(1, 0, exchange::Role::Responder));

        if timeout != 0 {
            // Send Timed Req
            let mut tmp_buf = [0u8; 400];
            let timed_req = TimedReq { timeout };
            let im_input = ImInput::new(OpCode::TimedRequest, &timed_req);
            let (_, out_buf) = self.process(&im_input, &mut tmp_buf);
            tlv::print_tlv_list(out_buf);
        } else {
            warn!("Skipping timed request");
        }

        // Process any delays
        let delay = time::Duration::from_millis(delay.into());
        thread::sleep(delay);

        // Send Write Req
        let input = ImInput::new(opcode, request);
        let (resp_opcode, output) = self.process(&input, output);
        (resp_opcode, output)
    }

    // Helper for handling Write Attribute sequences
    pub fn handle_timed_write_reqs(
        &mut self,
        input: &[AttrData],
        expected: &WriteResponse,
        timeout: u16,
        delay: u16,
    ) {
        let mut out_buf = [0u8; 400];
        let write_req = WriteReq::new(false, input);

        let (resp_opcode, out_buf) = self.handle_timed_reqs(
            OpCode::WriteRequest,
            &write_req,
            timeout,
            delay,
            &mut out_buf,
        );
        tlv::print_tlv_list(out_buf);
        let root = tlv::get_root_node_struct(out_buf).unwrap();

        match expected {
            WriteResponse::TransactionSuccess(t) => {
                assert_eq!(
                    num::FromPrimitive::from_u8(resp_opcode),
                    Some(OpCode::WriteResponse)
                );
                let resp = WriteResp::from_tlv(&root).unwrap();
                assert_eq!(resp.write_responses, t);
            }
            WriteResponse::TransactionError => {
                assert_eq!(
                    num::FromPrimitive::from_u8(resp_opcode),
                    Some(OpCode::StatusResponse)
                );
                let status_resp = StatusResp::from_tlv(&root).unwrap();
                assert_eq!(status_resp.status, IMStatusCode::Timeout);
            }
        }
    }

    pub fn new_with_timed_write_reqs(
        matter: &'a Matter<'a>,
        input: &[AttrData],
        expected: &WriteResponse,
        timeout: u16,
        delay: u16,
    ) -> Self {
        let mut im = ImEngine::new(matter);

        im.handle_timed_write_reqs(input, expected, timeout, delay);

        im
    }

    // Helper for handling Invoke Command sequences
    pub fn handle_timed_commands(
        &mut self,
        input: &[CmdData],
        expected: &TimedInvResponse,
        timeout: u16,
        delay: u16,
        set_timed_request: bool,
    ) {
        let mut out_buf = [0u8; 400];
        let req = InvReq {
            suppress_response: Some(false),
            timed_request: Some(set_timed_request),
            inv_requests: Some(TLVArray::Slice(input)),
        };

        let (resp_opcode, out_buf) =
            self.handle_timed_reqs(OpCode::InvokeRequest, &req, timeout, delay, &mut out_buf);
        tlv::print_tlv_list(out_buf);
        let root = tlv::get_root_node_struct(out_buf).unwrap();

        match expected {
            TimedInvResponse::TransactionSuccess(t) => {
                assert_eq!(
                    num::FromPrimitive::from_u8(resp_opcode),
                    Some(OpCode::InvokeResponse)
                );
                let resp = msg::InvResp::from_tlv(&root).unwrap();
                assert_inv_response(&resp, t)
            }
            TimedInvResponse::TransactionError(e) => {
                assert_eq!(
                    num::FromPrimitive::from_u8(resp_opcode),
                    Some(OpCode::StatusResponse)
                );
                let status_resp = StatusResp::from_tlv(&root).unwrap();
                assert_eq!(status_resp.status, *e);
            }
        }
    }

    pub fn new_with_timed_commands(
        matter: &'a Matter<'a>,
        input: &[CmdData],
        expected: &TimedInvResponse,
        timeout: u16,
        delay: u16,
        set_timed_request: bool,
    ) -> Self {
        let mut im = ImEngine::new(matter);

        im.handle_timed_commands(input, expected, timeout, delay, set_timed_request);

        im
    }
}
