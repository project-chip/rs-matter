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

use super::objects::*;
use crate::{
    error::*,
    interaction_model::{
        command::CommandReq,
        core::IMStatusCode,
        messages::ib::{self},
    },
    tlv::{TLVWriter, TagType, ToTLV},
};
use chrono::{DateTime, NaiveDate};
use num_derive::FromPrimitive;
use rs_matter_macros::idl_import;

idl_import!(clusters = ["MediaPlayback"]);

pub use media_playback::Commands;
pub use media_playback::ID;

#[derive(FromPrimitive)]
pub enum Attributes {
    CurrentState = 0x0,
    StartTime = 0x1,
    Duration = 0x2,
    SampledPosition = 0x3,
    PlaybackSpeed = 0x4,
    SeekRangeEnd = 0x5,
    SeekRangeStart = 0x6,
}

struct ClusterCallback {
    name: Commands,
    callback: Box<dyn FnMut()>,
}

enum _FeatureMap {
    AdvancedSeek = 0,
    VariableSpeed = 1,
}
#[derive(FromPrimitive)]

enum PlaybackState {
    Playing = 0,
    Paused = 1,
    NotPlaying = 2,
    Buffering = 3,
}
#[derive(FromPrimitive)]
enum CommandStatus {
    Success = 0,
    InvalidStateForCommand = 1,
    NotAllowed = 2,
    NotActive = 3,
    SpeedOutOfRange = 4,
    SeekOutOfRange = 5,
}

impl CommandStatus {
    fn u8(&self) -> u8 {
        match self {
            CommandStatus::Success => 0,
            CommandStatus::InvalidStateForCommand => 1,
            CommandStatus::NotAllowed => 2,
            CommandStatus::NotActive => 3,
            CommandStatus::SpeedOutOfRange => 4,
            CommandStatus::SeekOutOfRange => 5,
        }
    }
}

struct PlaybackPosition {
    updated_at: u64,
    position: u64,
}
// Get microseconds since 2000, Jan 1, 00:00:00
pub fn get_epoch_us() -> u64 {
    let epoch_start = unwrap!(unwrap!(unwrap!(NaiveDate::from_ymd_opt(2000, 1, 1))
        .and_hms_micro_opt(0, 0, 0, 0))
        .and_local_timezone(chrono::Utc));
    DateTime::timestamp_micros(&epoch_start) as u64
}

pub struct MediaPlaybackCluster {
    base: Cluster,
    sampled_position: PlaybackPosition,
    callbacks: Vec<ClusterCallback>,
}

impl MediaPlaybackCluster {
    pub fn new() -> Result<Box<Self>, Error> {
        let mut cluster = Box::new(MediaPlaybackCluster {
            base: Cluster::new(ID)?,
            sampled_position: PlaybackPosition {
                updated_at: 0,
                position: 0,
            },
            callbacks: vec![],
        });

        // List should be a Vec<
        let attrs = [
            Attribute::new(
                Attributes::CurrentState as u16,
                AttrValue::Uint8(PlaybackState::NotPlaying as u8),
                Access::RV,
                Quality::PERSISTENT,
            ),
            // epoch-us
            Attribute::new(
                Attributes::StartTime as u16,
                AttrValue::Uint64(0),
                Access::RV,
                Quality::PERSISTENT,
            ),
            Attribute::new(
                Attributes::Duration as u16,
                AttrValue::Uint64(1),
                Access::RV,
                Quality::PERSISTENT,
            ),
            // Playback-Position
            Attribute::new(
                Attributes::SampledPosition as u16,
                AttrValue::Custom,
                Access::RV,
                Quality::PERSISTENT,
            ),
            // Float
            Attribute::new(
                Attributes::PlaybackSpeed as u16,
                AttrValue::Custom,
                Access::RV,
                Quality::PERSISTENT,
            ),
            Attribute::new(
                Attributes::SeekRangeEnd as u16,
                AttrValue::Uint64(0),
                Access::RV,
                Quality::PERSISTENT,
            ),
            Attribute::new(
                Attributes::SeekRangeStart as u16,
                AttrValue::Uint64(0),
                Access::RV,
                Quality::PERSISTENT,
            ),
            // Options - probably want a custom type here for mapping cluster options to TLV bitmask
        ];
        cluster.base.add_attributes(&attrs)?;

        // For now disable all features by default
        cluster.base.set_feature_map(0)?;
        Ok(cluster)
    }

    pub fn add_callback(&mut self, name: Commands, callback: Box<dyn FnMut()>) {
        self.callbacks.push(ClusterCallback { name, callback });
    }

    fn run_callback(&mut self, name: Commands) {
        for cmd in self.callbacks.iter_mut() {
            if cmd.name == name {
                (cmd.callback)()
            }
        }
    }

    fn _set_state_buffering(&mut self) -> Result<(), IMStatusCode> {
        self.base.write_attribute_raw(
            Attributes::CurrentState as u16,
            AttrValue::Uint8(PlaybackState::Playing as u8),
        )?;
        Err(IMStatusCode::Success)
    }

    fn _set_duration(&mut self, duration: u64) -> Result<(), IMStatusCode> {
        self.base
            .write_attribute_raw(Attributes::Duration as u16, AttrValue::Uint64(duration))?;
        Err(IMStatusCode::Success)
    }

    // When rewinding / changing stream / etc we need to change absolute position and updateAt
    fn update_position(&mut self, new_pos: u64) -> Result<(), IMStatusCode> {
        let now = get_epoch_us();

        self.sampled_position.position = new_pos;
        self.sampled_position.updated_at = now;

        Err(IMStatusCode::Success)
    }

    fn enocde_sampled_position(&self, tag: TagType, tw: &mut TLVWriter) {
        let _ = tw.start_struct(tag);
        let _ = tw.u64(TagType::Context(0), self.sampled_position.position);
        let _ = tw.u64(TagType::Context(1), self.sampled_position.updated_at);
        let _ = tw.end_container();
    }
}

// Commmands
impl MediaPlaybackCluster {
    fn handle_play(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        self.base.write_attribute_raw(
            Attributes::CurrentState as u16,
            AttrValue::Uint8(PlaybackState::Playing as u8),
        )?;

        self.run_callback(Commands::Play);
        self.send_playback_response(CommandStatus::Success, cmd_req);
        Err(IMStatusCode::Success)
    }
    fn handle_pause(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        self.base.write_attribute_raw(
            Attributes::CurrentState as u16,
            AttrValue::Uint8(PlaybackState::Paused as u8),
        )?;

        self.run_callback(Commands::Pause);
        self.send_playback_response(CommandStatus::Success, cmd_req);
        Err(IMStatusCode::Success)
    }
    fn handle_stop(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        self.base.write_attribute_raw(
            Attributes::CurrentState as u16,
            AttrValue::Uint8(PlaybackState::NotPlaying as u8),
        )?;

        self.run_callback(Commands::Stop);
        self.send_playback_response(CommandStatus::Success, cmd_req);
        Err(IMStatusCode::Success)
    }

    // Start current thinbg over
    fn handle_start_over(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        self.base.write_attribute_raw(
            Attributes::CurrentState as u16,
            AttrValue::Uint8(PlaybackState::Playing as u8),
        )?;

        self.update_position(0)?;
        self.run_callback(Commands::StartOver);
        self.send_playback_response(CommandStatus::Success, cmd_req);
        Err(IMStatusCode::Success)
    }

    fn handle_next(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        self.base.write_attribute_raw(
            Attributes::CurrentState as u16,
            AttrValue::Uint8(PlaybackState::Playing as u8),
        )?;
        // self.update_position(0)?;
        self.send_playback_response(CommandStatus::NotAllowed, cmd_req);
        Err(IMStatusCode::UnsupportedCommand)
    }

    fn handle_previous(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        self.base.write_attribute_raw(
            Attributes::CurrentState as u16,
            AttrValue::Uint8(PlaybackState::Playing as u8),
        )?;
        // self.update_position(0)?;
        self.send_playback_response(CommandStatus::NotAllowed, cmd_req);
        Err(IMStatusCode::UnsupportedCommand)
    }

    fn handle_rewind(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        self.base.write_attribute_raw(
            Attributes::CurrentState as u16,
            AttrValue::Uint8(PlaybackState::Playing as u8),
        )?;
        self.send_playback_response(CommandStatus::NotAllowed, cmd_req);
        Err(IMStatusCode::UnsupportedCommand)
    }

    fn handle_ff(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        self.base.write_attribute_raw(
            Attributes::CurrentState as u16,
            AttrValue::Uint8(PlaybackState::Playing as u8),
        )?;
        self.send_playback_response(CommandStatus::NotAllowed, cmd_req);
        Err(IMStatusCode::UnsupportedCommand)
    }

    fn handle_skip_forward(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        self.base.write_attribute_raw(
            Attributes::CurrentState as u16,
            AttrValue::Uint8(PlaybackState::Playing as u8),
        )?;
        self.send_playback_response(CommandStatus::NotAllowed, cmd_req);
        Err(IMStatusCode::UnsupportedCommand)
    }

    fn handle_skip_backward(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        self.base.write_attribute_raw(
            Attributes::CurrentState as u16,
            AttrValue::Uint8(PlaybackState::Playing as u8),
        )?;
        self.send_playback_response(CommandStatus::NotAllowed, cmd_req);
        Err(IMStatusCode::UnsupportedCommand)
    }

    fn handle_seek(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        self.base.write_attribute_raw(
            Attributes::CurrentState as u16,
            AttrValue::Uint8(PlaybackState::Playing as u8),
        )?;
        self.send_playback_response(CommandStatus::NotAllowed, cmd_req);
        Err(IMStatusCode::UnsupportedCommand)
    }

    // TODO: We send this to client
    fn send_playback_response(&mut self, status: CommandStatus, cmd_req: &mut CommandReq) {
        let mut playback_response = cmd_req.cmd;
        playback_response.path.leaf = Some(Commands::PlaybackResponse as u32);

        let resp = status.u8();
        let cmd_data = |tag: TagType, t: &mut TLVWriter| {
            let _ = t.start_struct(tag);
            let _ = t.u8(TagType::Context(0), resp);
            let _ = t.end_container();
        };

        let invoke_resp = ib::InvResp::Cmd(ib::CmdData::new(
            playback_response,
            EncodeValue::Closure(&cmd_data),
        ));
        let _ = invoke_resp.to_tlv(cmd_req.resp, TagType::Anonymous);
        cmd_req.trans.complete();
    }
}

impl ClusterType for MediaPlaybackCluster {
    fn base(&self) -> &Cluster {
        &self.base
    }
    fn base_mut(&mut self) -> &mut Cluster {
        &mut self.base
    }

    fn read_custom_attribute(&self, encoder: &mut dyn Encoder, attr: &AttrDetails) {
        match num::FromPrimitive::from_u16(attr.attr_id) {
            Some(Attributes::SampledPosition) => {
                encoder.encode(EncodeValue::Closure(&|tag, tw| {
                    log::warn!("Encoding sampled position of self!");
                    self.enocde_sampled_position(tag, tw)
                }))
            }
            _ => log::error!("Attribute not supported!"),
        }
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
            Commands::Play => self.handle_play(cmd_req),
            Commands::Pause => self.handle_pause(cmd_req),
            Commands::Stop => self.handle_stop(cmd_req),
            Commands::StartOver => self.handle_start_over(cmd_req),
            Commands::Previous => self.handle_previous(cmd_req),
            Commands::Next => self.handle_next(cmd_req),
            Commands::Rewind => self.handle_rewind(cmd_req),
            Commands::FastForward => self.handle_ff(cmd_req),
            Commands::SkipForward => self.handle_skip_forward(cmd_req),
            Commands::SkipBackward => self.handle_skip_backward(cmd_req),
            Commands::PlaybackResponse => Err(IMStatusCode::InvalidCommand),
            Commands::Seek => self.handle_seek(cmd_req),
        }
    }
}
