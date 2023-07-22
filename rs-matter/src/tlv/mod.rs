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

/* Tag Types */
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum TagType {
    Anonymous,
    Context(u8),
    CommonPrf16(u16),
    CommonPrf32(u32),
    ImplPrf16(u16),
    ImplPrf32(u32),
    FullQual48(u64),
    FullQual64(u64),
}
pub const TAG_SHIFT_BITS: u8 = 5;
pub const TAG_MASK: u8 = 0xe0;
pub const TYPE_MASK: u8 = 0x1f;
pub const MAX_TAG_INDEX: usize = 8;

pub static TAG_SIZE_MAP: [usize; MAX_TAG_INDEX] = [
    0, // Anonymous
    1, // Context
    2, // CommonPrf16
    4, // CommonPrf32
    2, // ImplPrf16
    4, // ImplPrf32
    6, // FullQual48
    8, // FullQual64
];

mod parser;
mod traits;
mod writer;

pub use parser::*;
pub use rs_matter_macros::{FromTLV, ToTLV};
pub use traits::*;
pub use writer::*;
