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

use cfg_if::cfg_if;

use crate::utils::storage::Vec;

cfg_if! {
    if #[cfg(feature = "large-buffers-1048576")] {
        /// The size of an [`IMBuffer`]: that of the largest message an exchange can
        /// receive (a Matter-over-TCP one with a `large-buffers-*` feature).
        pub const IM_BUFFER_SIZE: usize = 1024 * 1024;
    } else if #[cfg(feature = "large-buffers-524288")] {
        /// The size of an [`IMBuffer`]: that of the largest message an exchange can
        /// receive (a Matter-over-TCP one with a `large-buffers-*` feature).
        pub const IM_BUFFER_SIZE: usize = 512 * 1024;
    } else if #[cfg(feature = "large-buffers-262144")] {
        /// The size of an [`IMBuffer`]: that of the largest message an exchange can
        /// receive (a Matter-over-TCP one with a `large-buffers-*` feature).
        pub const IM_BUFFER_SIZE: usize = 256 * 1024;
    } else if #[cfg(feature = "large-buffers-131072")] {
        /// The size of an [`IMBuffer`]: that of the largest message an exchange can
        /// receive (a Matter-over-TCP one with a `large-buffers-*` feature).
        pub const IM_BUFFER_SIZE: usize = 128 * 1024;
    } else if #[cfg(feature = "large-buffers-65536")] {
        /// The size of an [`IMBuffer`]: that of the largest message an exchange can
        /// receive (a Matter-over-TCP one with a `large-buffers-*` feature).
        pub const IM_BUFFER_SIZE: usize = 64 * 1024;
    } else if #[cfg(feature = "large-buffers-32768")] {
        /// The size of an [`IMBuffer`]: that of the largest message an exchange can
        /// receive (a Matter-over-TCP one with a `large-buffers-*` feature).
        pub const IM_BUFFER_SIZE: usize = 32 * 1024;
    } else if #[cfg(feature = "large-buffers-16384")] {
        /// The size of an [`IMBuffer`]: that of the largest message an exchange can
        /// receive (a Matter-over-TCP one with a `large-buffers-*` feature).
        pub const IM_BUFFER_SIZE: usize = 16 * 1024;
    } else if #[cfg(feature = "large-buffers-8192")] {
        /// The size of an [`IMBuffer`]: that of the largest message an exchange can
        /// receive (a Matter-over-TCP one with a `large-buffers-*` feature).
        pub const IM_BUFFER_SIZE: usize = 8 * 1024;
    } else if #[cfg(feature = "large-buffers-4096")] {
        /// The size of an [`IMBuffer`]: that of the largest message an exchange can
        /// receive (a Matter-over-TCP one with a `large-buffers-*` feature).
        pub const IM_BUFFER_SIZE: usize = 4 * 1024;
    } else {
        /// The size of an [`IMBuffer`]: that of the largest message an exchange can
        /// receive (UDP-sized when no `large-buffers-*` feature is enabled).
        pub const IM_BUFFER_SIZE: usize = 1583;
    }
}

/// The buffer type used by the Interaction Model and the handlers for the
/// payloads of messages.
pub type IMBuffer = Vec<u8, IM_BUFFER_SIZE>;
