use log::{info, warn};
use rs_matter::{
    error::ErrorCode,
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
};

use super::{
    attributes::assert_attr_report,
    commands::{assert_inv_response, ExpectedInvResp},
    im_engine::{ImEngine, ImEngineHandler, ImInput, ImOutput},
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
    pub fn read_reqs(input: &[AttrPath], expected: &[AttrResp]) {
        let im = ImEngine::new_default();

        im.add_default_acl();
        im.handle_read_reqs(&im.handler(), input, expected);
    }

    // Helper for handling Read Req sequences for this file
    pub fn handle_read_reqs(
        &self,
        handler: &ImEngineHandler,
        input: &[AttrPath],
        expected: &[AttrResp],
    ) {
        let mut out = heapless::Vec::<_, 1>::new();
        let received = self.gen_read_reqs_output(handler, input, None, &mut out);
        assert_attr_report(&received, expected)
    }

    pub fn gen_read_reqs_output<'c, const N: usize>(
        &self,
        handler: &ImEngineHandler,
        input: &[AttrPath],
        dataver_filters: Option<TLVArray<'_, DataVersionFilter>>,
        out: &'c mut heapless::Vec<ImOutput, N>,
    ) -> ReportDataMsg<'c> {
        let mut read_req = ReadReq::new(true).set_attr_requests(input);
        read_req.dataver_filters = dataver_filters;

        let input = ImInput::new(OpCode::ReadRequest, &read_req);

        self.process(handler, &[&input], out).unwrap();

        for o in &*out {
            tlv::print_tlv_list(&o.data);
        }

        let root = tlv::get_root_node_struct(&out[0].data).unwrap();
        ReportDataMsg::from_tlv(&root).unwrap()
    }

    pub fn write_reqs(input: &[AttrData], expected: &[AttrStatus]) {
        let im = ImEngine::new_default();

        im.add_default_acl();
        im.handle_write_reqs(&im.handler(), input, expected);
    }

    pub fn handle_write_reqs(
        &self,
        handler: &ImEngineHandler,
        input: &[AttrData],
        expected: &[AttrStatus],
    ) {
        let write_req = WriteReq::new(false, input);

        let input = ImInput::new(OpCode::WriteRequest, &write_req);
        let mut out = heapless::Vec::<_, 1>::new();
        self.process(handler, &[&input], &mut out).unwrap();

        for o in &out {
            tlv::print_tlv_list(&o.data);
        }

        let root = tlv::get_root_node_struct(&out[0].data).unwrap();

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

    pub fn commands(input: &[CmdData], expected: &[ExpectedInvResp]) {
        let im = ImEngine::new_default();

        im.add_default_acl();
        im.handle_commands(&im.handler(), input, expected)
    }

    // Helper for handling Invoke Command sequences
    pub fn handle_commands(
        &self,
        handler: &ImEngineHandler,
        input: &[CmdData],
        expected: &[ExpectedInvResp],
    ) {
        let req = InvReq {
            suppress_response: Some(false),
            timed_request: Some(false),
            inv_requests: Some(TLVArray::Slice(input)),
        };

        let input = ImInput::new(OpCode::InvokeRequest, &req);

        let mut out = heapless::Vec::<_, 1>::new();
        self.process(handler, &[&input], &mut out).unwrap();

        for o in &out {
            tlv::print_tlv_list(&o.data);
        }

        let root = tlv::get_root_node_struct(&out[0].data).unwrap();
        let resp = msg::InvResp::from_tlv(&root).unwrap();
        assert_inv_response(&resp, expected)
    }

    fn gen_timed_reqs_output<const N: usize>(
        &self,
        handler: &ImEngineHandler,
        opcode: OpCode,
        request: &dyn ToTLV,
        timeout: u16,
        delay: u16,
        out: &mut heapless::Vec<ImOutput, N>,
    ) {
        let mut inp = heapless::Vec::<_, 2>::new();

        let timed_req = TimedReq { timeout };
        let im_input = ImInput::new_delayed(OpCode::TimedRequest, &timed_req, Some(delay));

        if timeout != 0 {
            // Send Timed Req
            inp.push(&im_input).map_err(|_| ErrorCode::NoSpace).unwrap();
        } else {
            warn!("Skipping timed request");
        }

        // Send Write Req
        let input = ImInput::new(opcode, request);
        inp.push(&input).map_err(|_| ErrorCode::NoSpace).unwrap();

        self.process(handler, &inp, out).unwrap();

        drop(inp);

        for o in out {
            tlv::print_tlv_list(&o.data);
        }
    }

    pub fn timed_write_reqs(
        input: &[AttrData],
        expected: &WriteResponse,
        timeout: u16,
        delay: u16,
    ) {
        let im = ImEngine::new_default();

        im.add_default_acl();
        im.handle_timed_write_reqs(&im.handler(), input, expected, timeout, delay);
    }

    // Helper for handling Write Attribute sequences
    pub fn handle_timed_write_reqs(
        &self,
        handler: &ImEngineHandler,
        input: &[AttrData],
        expected: &WriteResponse,
        timeout: u16,
        delay: u16,
    ) {
        let mut out = heapless::Vec::<_, 2>::new();
        let write_req = WriteReq::new(false, input);

        self.gen_timed_reqs_output(
            handler,
            OpCode::WriteRequest,
            &write_req,
            timeout,
            delay,
            &mut out,
        );

        let out = &out[out.len() - 1];
        let root = tlv::get_root_node_struct(&out.data).unwrap();

        match *expected {
            WriteResponse::TransactionSuccess(t) => {
                assert_eq!(out.action, OpCode::WriteResponse);
                let resp = WriteResp::from_tlv(&root).unwrap();
                assert_eq!(resp.write_responses, t);
            }
            WriteResponse::TransactionError => {
                assert_eq!(out.action, OpCode::StatusResponse);
                let status_resp = StatusResp::from_tlv(&root).unwrap();
                assert_eq!(status_resp.status, IMStatusCode::Timeout);
            }
        }
    }

    pub fn timed_commands(
        input: &[CmdData],
        expected: &TimedInvResponse,
        timeout: u16,
        delay: u16,
        set_timed_request: bool,
    ) {
        let im = ImEngine::new_default();

        im.add_default_acl();
        im.handle_timed_commands(
            &im.handler(),
            input,
            expected,
            timeout,
            delay,
            set_timed_request,
        );
    }

    // Helper for handling Invoke Command sequences
    pub fn handle_timed_commands(
        &self,
        handler: &ImEngineHandler,
        input: &[CmdData],
        expected: &TimedInvResponse,
        timeout: u16,
        delay: u16,
        set_timed_request: bool,
    ) {
        let mut out = heapless::Vec::<_, 2>::new();
        let req = InvReq {
            suppress_response: Some(false),
            timed_request: Some(set_timed_request),
            inv_requests: Some(TLVArray::Slice(input)),
        };

        self.gen_timed_reqs_output(
            handler,
            OpCode::InvokeRequest,
            &req,
            timeout,
            delay,
            &mut out,
        );

        let out = &out[out.len() - 1];
        let root = tlv::get_root_node_struct(&out.data).unwrap();

        match expected {
            TimedInvResponse::TransactionSuccess(t) => {
                assert_eq!(out.action, OpCode::InvokeResponse);
                let resp = msg::InvResp::from_tlv(&root).unwrap();
                assert_inv_response(&resp, t)
            }
            TimedInvResponse::TransactionError(e) => {
                assert_eq!(out.action, OpCode::StatusResponse);
                let status_resp = StatusResp::from_tlv(&root).unwrap();
                assert_eq!(status_resp.status, *e);
            }
        }
    }
}
