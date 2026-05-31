/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
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

//! ColorControl cluster — placeholder.
//!
//! A full ColorControl cluster handler is not yet shipped. The
//! previous wrapper-based Scenes integration (`pub mod scenes` with
//! a `ColorControlSceneClusterHandler<'a>` that proxied through the
//! `SceneContext` IM-routed read/invoke shim) is removed: the Scenes
//! cluster now talks to scene-able cluster handlers via direct
//! typed method calls on the handler type itself (see
//! [`crate::dm::clusters::scenes::SceneClusterHandler`]).
//!
//! When a real `ColorControlHandler` lands here, the scenes
//! integration will be added back as
//! `impl SceneClusterHandler for ColorControlHandler<...>`,
//! mirroring how [`crate::dm::clusters::app::on_off::OnOffHandler`]
//! and [`crate::dm::clusters::app::level_control::LevelControlHandler`]
//! do it today.
