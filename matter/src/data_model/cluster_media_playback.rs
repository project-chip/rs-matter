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
     interaction_model::{command::CommandReq, core::IMStatusCode},
     tlv::{TagType, TLVWriter},
    };
 use num_derive::FromPrimitive;
 use chrono::{NaiveDate, DateTime};

 pub const ID: u32 = 0x0506;
 #[derive(FromPrimitive)]
 pub enum Attributes {
     CurrentState = 0x0,
     StartTime = 0x1,
     Duration = 0x2,
     SampledPosition = 0x3,
     PlaybackSpeed = 0x4,
     SeekRangeEnd = 0x5,
     SeekRangeStart = 0x6
 }

struct ClusterCallback {
    name: Commands,
    callback: Box<dyn FnMut()>
 }

 enum FeatureMap {
    AdvancedSeek = 0,
    VariableSpeed = 1
 }
 #[derive(FromPrimitive)]

 enum PlaybackState {
    Playing = 0,
    Paused = 1,
    NotPlaying = 2,
    BUFFERING = 3
 }
 #[derive(FromPrimitive)]
 enum CommandStatus {
    Success = 0,
    InvalidStateForCommand = 1,
    NotAllowed = 2,
    NotActive = 3,
    SpeedOutOfRange = 4,
    SeekOutOfRange = 5
 }

 #[derive(FromPrimitive, PartialEq)]
 pub enum Commands {
    Play = 0x0,
    Pause = 0x1,
    Stop = 0x2,
    StartOver = 0x3,
    Previous = 0x4,
    Next = 0x5,
    Rewind = 0x6,
    FastForward = 0x7,
    SkipForward = 0x8,
    SkipBackward = 0x9,
    // Response is from us to server
    PlaybackResponse = 0xa,
    Seek = 0x0b
 }
 
 struct PlaybackPosition {
    updated_at: u64,
    position: u64
 }
// Get microseconds since 2000, Jan 1, 00:00:00
 pub fn get_epoch_us() -> u64 {
    let epoch_start = NaiveDate::from_ymd_opt(2000, 1, 1).unwrap().and_hms_micro_opt(0, 0, 0, 0).unwrap().and_local_timezone(chrono::Utc).unwrap();
    DateTime::timestamp_micros(&epoch_start) as u64
 }

 pub struct MediaPlaybackCluster {
    base: Cluster,
    sampled_position: PlaybackPosition,
    callbacks: Vec<ClusterCallback>
 }
 
 impl MediaPlaybackCluster {
     pub fn new() -> Result<Box<Self>, Error> {
         let mut cluster = Box::new(MediaPlaybackCluster {
             base: Cluster::new(ID)?,
             sampled_position: PlaybackPosition { updated_at: 0, position: 0 },
             callbacks: vec!()
         });
 
         // List should be a Vec<
         let attrs = [
             Attribute::new(
                 Attributes::CurrentState as u16,
                 AttrValue::Uint8(PlaybackState::NotPlaying as u8),
                 Access::RV,
                 Quality::PERSISTENT,
             )?,

             // epoch-us
             Attribute::new(
                 Attributes::StartTime as u16,
                 AttrValue::Uint64(0),
                 Access::RV,
                 Quality::PERSISTENT,
             )?,
             Attribute::new(
                Attributes::Duration as u16,
                AttrValue::Uint64(1),
                Access::RV,
                Quality::PERSISTENT,
            )?,

            // Playback-Position
            Attribute::new(
                Attributes::SampledPosition as u16,
                AttrValue::Custom,
                Access::RV,
                Quality::PERSISTENT,
            )?,

            // Float
            Attribute::new(
                Attributes::PlaybackSpeed as u16,
                AttrValue::Custom,
                Access::RV,
                Quality::PERSISTENT,
            )?,
            Attribute::new(
                Attributes::SeekRangeEnd as u16,
                AttrValue::Uint64(0),
                Access::RV,
                Quality::PERSISTENT,
            )?,
            Attribute::new(
                Attributes::SeekRangeStart as u16,
                AttrValue::Uint64(0),
                Access::RV,
                Quality::PERSISTENT,
            )?,
             // Options - probably want a custom type here for mapping cluster options to TLV bitmask
         ];
         cluster.base.add_attributes(&attrs)?;

        // For now disable all features by default
        cluster.base.set_feature_map(0)?;
         Ok(cluster)
     }

     pub fn add_callback(&mut self, name: Commands, callback: Box<dyn FnMut()>) {
        self.callbacks.push(ClusterCallback { name, callback: callback});
     }

     fn run_callback(&mut self, name: Commands) {
        for cmd in self.callbacks.iter_mut() {
            if cmd.name == name {
                (cmd.callback)()
            }
        }
     }
    
     fn _set_state_buffering(&mut self)-> Result<(), IMStatusCode>{
        self.base.write_attribute_raw(Attributes::CurrentState as u16, AttrValue::Uint8(PlaybackState::Playing as u8))?;
        Err(IMStatusCode::Sucess)
     }

     fn _set_duration(&mut self, duration: u64)-> Result<(), IMStatusCode>{
        self.base.write_attribute_raw(Attributes::Duration as u16, AttrValue::Uint64(duration))?;
        Err(IMStatusCode::Sucess)
     }

     // When rewinding / changing stream / etc we need to change absolute position and updateAt
     fn update_position(&mut self, new_pos: u64)  -> Result<(), IMStatusCode>{
         let now = get_epoch_us();

        self.sampled_position.position = new_pos;
        self.sampled_position.updated_at = now;

        Err(IMStatusCode::Sucess)
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
    fn handle_play(&mut self) -> Result<(), IMStatusCode>{
        self.base.write_attribute_raw(Attributes::CurrentState as u16, AttrValue::Uint8(PlaybackState::Playing as u8))?;
        self.run_callback(Commands::Play);
        self.send_playback_response(CommandStatus::Success);
        Err(IMStatusCode::Sucess)
    }
    fn handle_pause(&mut self) -> Result<(), IMStatusCode>{
        self.base.write_attribute_raw(Attributes::CurrentState as u16, AttrValue::Uint8(PlaybackState::Paused as u8))?;

        self.run_callback(Commands::Pause);
        self.send_playback_response(CommandStatus::Success);
        Err(IMStatusCode::Sucess)
    }   
    fn handle_stop(&mut self) -> Result<(), IMStatusCode>{
        self.base.write_attribute_raw(Attributes::CurrentState as u16, AttrValue::Uint8(PlaybackState::NotPlaying as u8))?;
        
        self.run_callback(Commands::Stop);
        self.send_playback_response(CommandStatus::Success);
        Err(IMStatusCode::Sucess)
    }

    // Start current thinbg over
    fn handle_start_over(&mut self) -> Result<(), IMStatusCode>{
        self.base.write_attribute_raw(Attributes::CurrentState as u16, AttrValue::Uint8(PlaybackState::Playing as u8))?;
        self.update_position(0)?;

        self.run_callback(Commands::StartOver);
        self.send_playback_response(CommandStatus::Success);
        Err(IMStatusCode::Sucess)
    }   

    fn handle_next(&mut self) -> Result<(), IMStatusCode>{
        self.base.write_attribute_raw(Attributes::CurrentState as u16, AttrValue::Uint8(PlaybackState::Playing as u8))?;
        // self.update_position(0)?;
        self.send_playback_response(CommandStatus::NotAllowed);
        Err(IMStatusCode::UnsupportedCommand)
    }   

    fn handle_previous(&mut self) -> Result<(), IMStatusCode>{

        self.base.write_attribute_raw(Attributes::CurrentState as u16, AttrValue::Uint8(PlaybackState::Playing as u8))?;
        // self.update_position(0)?;
        self.send_playback_response(CommandStatus::NotAllowed);
        Err(IMStatusCode::UnsupportedCommand)
    } 

    fn handle_rewind(&mut self) -> Result<(), IMStatusCode>{
        self.base.write_attribute_raw(Attributes::CurrentState as u16, AttrValue::Uint8(PlaybackState::Playing as u8))?;
        self.send_playback_response(CommandStatus::NotAllowed);
        Err(IMStatusCode::UnsupportedCommand)
    } 

    fn handle_ff(&mut self) -> Result<(), IMStatusCode>{
        self.base.write_attribute_raw(Attributes::CurrentState as u16, AttrValue::Uint8(PlaybackState::Playing as u8))?;
        self.send_playback_response(CommandStatus::NotAllowed);
        Err(IMStatusCode::UnsupportedCommand)
    } 

    fn handle_skip_forward(&mut self) -> Result<(), IMStatusCode>{
        self.base.write_attribute_raw(Attributes::CurrentState as u16, AttrValue::Uint8(PlaybackState::Playing as u8))?;
        self.send_playback_response(CommandStatus::NotAllowed);
        Err(IMStatusCode::UnsupportedCommand)
    } 

    fn handle_skip_backward(&mut self) -> Result<(), IMStatusCode>{
        self.base.write_attribute_raw(Attributes::CurrentState as u16, AttrValue::Uint8(PlaybackState::Playing as u8))?;
        self.send_playback_response(CommandStatus::NotAllowed);
        Err(IMStatusCode::UnsupportedCommand)
    } 
    

    fn handle_seek(&mut self) -> Result<(), IMStatusCode>{
        self.base.write_attribute_raw(Attributes::CurrentState as u16, AttrValue::Uint8(PlaybackState::Playing as u8))?;
        self.send_playback_response(CommandStatus::NotAllowed);
        Err(IMStatusCode::UnsupportedCommand)
    } 

    // TODO: We send this to client
    fn send_playback_response(&mut self, _status: CommandStatus) {
        // Write status as u8
        // Err(IMStatusCode::Sucess)
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
            Some(Attributes::SampledPosition) => encoder.encode(EncodeValue::Closure(&|tag, tw| {
                log::warn!("Encoding sampled position of self!");
                self.enocde_sampled_position(tag, tw)
            })),
            _ => log::error!("Attribute not supported!")    
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
                Commands::Play => self.handle_play(),
                Commands::Pause =>  self.handle_pause(),
                Commands::Stop => self.handle_stop(),
                Commands::StartOver => self.handle_start_over(),
                Commands::Previous =>  self.handle_previous(),
                Commands::Next =>  self.handle_next(),
                Commands::Rewind => self.handle_rewind(),
                Commands::FastForward => self.handle_ff(),
                Commands::SkipForward => self.handle_skip_forward(),
                Commands::SkipBackward => self.handle_skip_backward(),
                Commands::PlaybackResponse => Err(IMStatusCode::InvalidCommand),
                Commands::Seek => self.handle_seek(),
            }
     }
 }