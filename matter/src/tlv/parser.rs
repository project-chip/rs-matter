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

use crate::error::Error;

use byteorder::{ByteOrder, LittleEndian};
use log::{error, info};
use std::fmt;

use super::{TagType, MAX_TAG_INDEX, TAG_MASK, TAG_SHIFT_BITS, TAG_SIZE_MAP, TYPE_MASK};

pub struct TLVList<'a> {
    buf: &'a [u8],
}

impl<'a> TLVList<'a> {
    pub fn new(buf: &'a [u8]) -> TLVList<'a> {
        TLVList { buf }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Pointer<'a> {
    buf: &'a [u8],
    current: usize,
    left: usize,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ElementType<'a> {
    S8(i8),
    S16(i16),
    S32(i32),
    S64(i64),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    False,
    True,
    F32(f32),
    F64(f64),
    Utf8l(&'a [u8]),
    Utf16l(&'a [u8]),
    Utf32l,
    Utf64l,
    Str8l(&'a [u8]),
    Str16l(&'a [u8]),
    Str32l,
    Str64l,
    Null,
    Struct(Pointer<'a>),
    Array(Pointer<'a>),
    List(Pointer<'a>),
    EndCnt,
    Last,
}

const MAX_VALUE_INDEX: usize = 25;

// This is a function that takes a TLVListIterator and returns the tag type
type ExtractTag = for<'a> fn(&TLVListIterator<'a>) -> TagType;
static TAG_EXTRACTOR: [ExtractTag; 8] = [
    // Anonymous 0
    |_t| TagType::Anonymous,
    // Context 1
    |t| TagType::Context(t.buf[t.current]),
    // CommonPrf16 2
    |t| TagType::CommonPrf16(LittleEndian::read_u16(&t.buf[t.current..])),
    // CommonPrf32 3
    |t| TagType::CommonPrf32(LittleEndian::read_u32(&t.buf[t.current..])),
    // ImplPrf16 4
    |t| TagType::ImplPrf16(LittleEndian::read_u16(&t.buf[t.current..])),
    // ImplPrf32 5
    |t| TagType::ImplPrf32(LittleEndian::read_u32(&t.buf[t.current..])),
    // FullQual48 6
    |t| TagType::FullQual48(LittleEndian::read_u48(&t.buf[t.current..]) as u64),
    // FullQual64 7
    |t| TagType::FullQual64(LittleEndian::read_u64(&t.buf[t.current..])),
];

// This is a function that takes a TLVListIterator and returns the element type
// Some elements (like strings), also consume additional size, than that mentioned
// if this is the case, the additional size is returned
type ExtractValue = for<'a> fn(&TLVListIterator<'a>) -> (usize, ElementType<'a>);

static VALUE_EXTRACTOR: [ExtractValue; MAX_VALUE_INDEX] = [
    // S8   0
    { |t| (0, ElementType::S8(t.buf[t.current] as i8)) },
    // S16  1
    {
        |t| {
            (
                0,
                ElementType::S16(LittleEndian::read_i16(&t.buf[t.current..])),
            )
        }
    },
    // S32  2
    {
        |t| {
            (
                0,
                ElementType::S32(LittleEndian::read_i32(&t.buf[t.current..])),
            )
        }
    },
    // S64  3
    {
        |t| {
            (
                0,
                ElementType::S64(LittleEndian::read_i64(&t.buf[t.current..])),
            )
        }
    },
    // U8   4
    { |t| (0, ElementType::U8(t.buf[t.current])) },
    // U16  5
    {
        |t| {
            (
                0,
                ElementType::U16(LittleEndian::read_u16(&t.buf[t.current..])),
            )
        }
    },
    // U32  6
    {
        |t| {
            (
                0,
                ElementType::U32(LittleEndian::read_u32(&t.buf[t.current..])),
            )
        }
    },
    // U64  7
    {
        |t| {
            (
                0,
                ElementType::U64(LittleEndian::read_u64(&t.buf[t.current..])),
            )
        }
    },
    // False 8
    { |_t| (0, ElementType::False) },
    // True 9
    { |_t| (0, ElementType::True) },
    // F32  10
    { |_t| (0, ElementType::Last) },
    // F64  11
    { |_t| (0, ElementType::Last) },
    // Utf8l 12
    {
        |t| match read_length_value(1, t) {
            Err(_) => (0, ElementType::Last),
            Ok((size, string)) => (size, ElementType::Utf8l(string)),
        }
    },
    // Utf16l  13
    {
        |t| match read_length_value(2, t) {
            Err(_) => (0, ElementType::Last),
            Ok((size, string)) => (size, ElementType::Utf16l(string)),
        }
    },
    // Utf32l 14
    { |_t| (0, ElementType::Last) },
    // Utf64l 15
    { |_t| (0, ElementType::Last) },
    // Str8l 16
    {
        |t| match read_length_value(1, t) {
            Err(_) => (0, ElementType::Last),
            Ok((size, string)) => (size, ElementType::Str8l(string)),
        }
    },
    // Str16l 17
    {
        |t| match read_length_value(2, t) {
            Err(_) => (0, ElementType::Last),
            Ok((size, string)) => (size, ElementType::Str16l(string)),
        }
    },
    // Str32l 18
    { |_t| (0, ElementType::Last) },
    // Str64l 19
    { |_t| (0, ElementType::Last) },
    // Null  20
    { |_t| (0, ElementType::Null) },
    // Struct 21
    {
        |t| {
            (
                0,
                ElementType::Struct(Pointer {
                    buf: t.buf,
                    current: t.current,
                    left: t.left,
                }),
            )
        }
    },
    // Array  22
    {
        |t| {
            (
                0,
                ElementType::Array(Pointer {
                    buf: t.buf,
                    current: t.current,
                    left: t.left,
                }),
            )
        }
    },
    // List  23
    {
        |t| {
            (
                0,
                ElementType::List(Pointer {
                    buf: t.buf,
                    current: t.current,
                    left: t.left,
                }),
            )
        }
    },
    // EndCnt  24
    { |_t| (0, ElementType::EndCnt) },
];

// The array indices here correspond to the numeric value of the Element Type as defined in the Matter Spec
static VALUE_SIZE_MAP: [usize; MAX_VALUE_INDEX] = [
    1, // S8   0
    2, // S16  1
    4, // S32  2
    8, // S64  3
    1, // U8   4
    2, // U16  5
    4, // U32  6
    8, // U64  7
    0, // False 8
    0, // True 9
    4, // F32  10
    8, // F64  11
    1, // Utf8l 12
    2, // Utf16l  13
    4, // Utf32l 14
    8, // Utf64l 15
    1, // Str8l 16
    2, // Str16l 17
    4, // Str32l 18
    8, // Str64l 19
    0, // Null  20
    0, // Struct 21
    0, // Array  22
    0, // List  23
    0, // EndCnt  24
];

fn read_length_value<'a>(
    size_of_length_field: usize,
    t: &TLVListIterator<'a>,
) -> Result<(usize, &'a [u8]), Error> {
    // The current offset is the string size
    let length: usize = LittleEndian::read_uint(&t.buf[t.current..], size_of_length_field) as usize;
    // We'll consume the current offset (len) + the entire string
    if length + size_of_length_field > t.left {
        // Return Error
        Err(Error::NoSpace)
    } else {
        Ok((
            // return the additional size only
            length,
            &t.buf[(t.current + size_of_length_field)..(t.current + size_of_length_field + length)],
        ))
    }
}

#[derive(Debug, Copy, Clone)]
pub struct TLVElement<'a> {
    tag_type: TagType,
    element_type: ElementType<'a>,
}

impl<'a> PartialEq for TLVElement<'a> {
    fn eq(&self, other: &Self) -> bool {
        match self.element_type {
            ElementType::Struct(a) | ElementType::Array(a) | ElementType::List(a) => {
                let mut our_iter = TLVListIterator::from_pointer(a);
                let mut their = match other.element_type {
                    ElementType::Struct(b) | ElementType::Array(b) | ElementType::List(b) => {
                        TLVListIterator::from_pointer(b)
                    }
                    _ => {
                        // If we are a container, the other must be a container, else this is a mismatch
                        return false;
                    }
                };
                let mut nest_level = 0_u8;
                loop {
                    let ours = our_iter.next();
                    let theirs = their.next();
                    if std::mem::discriminant(&ours) != std::mem::discriminant(&theirs) {
                        // One of us reached end of list, but the other didn't, that's a mismatch
                        return false;
                    }
                    if ours.is_none() {
                        // End of list
                        break;
                    }
                    // guaranteed to work
                    let ours = ours.unwrap();
                    let theirs = theirs.unwrap();

                    match ours.element_type {
                        ElementType::EndCnt => {
                            if nest_level == 0 {
                                break;
                            } else {
                                nest_level -= 1;
                            }
                        }
                        _ => {
                            if is_container(ours.element_type) {
                                nest_level += 1;
                                // Only compare the discriminants in case of array/list/structures,
                                // instead of actual element values. Those will be subsets within this same
                                // list that will get validated anyway
                                if std::mem::discriminant(&ours.element_type)
                                    != std::mem::discriminant(&theirs.element_type)
                                {
                                    return false;
                                }
                            } else if ours.element_type != theirs.element_type {
                                return false;
                            }

                            if ours.tag_type != theirs.tag_type {
                                return false;
                            }
                        }
                    }
                }
                true
            }
            _ => self.tag_type == other.tag_type && self.element_type == other.element_type,
        }
    }
}

impl<'a> TLVElement<'a> {
    pub fn enter(&self) -> Option<TLVContainerIterator<'a>> {
        let ptr = match self.element_type {
            ElementType::Struct(a) | ElementType::Array(a) | ElementType::List(a) => a,
            _ => return None,
        };
        let list_iter = TLVListIterator {
            buf: ptr.buf,
            current: ptr.current,
            left: ptr.left,
        };
        Some(TLVContainerIterator {
            list_iter,
            prev_container: false,
            iterator_consumed: false,
        })
    }

    pub fn new(tag: TagType, value: ElementType<'a>) -> Self {
        Self {
            tag_type: tag,
            element_type: value,
        }
    }

    pub fn i8(&self) -> Result<i8, Error> {
        match self.element_type {
            ElementType::S8(a) => Ok(a),
            _ => Err(Error::TLVTypeMismatch),
        }
    }

    pub fn u8(&self) -> Result<u8, Error> {
        match self.element_type {
            ElementType::U8(a) => Ok(a),
            _ => Err(Error::TLVTypeMismatch),
        }
    }

    pub fn u16(&self) -> Result<u16, Error> {
        match self.element_type {
            ElementType::U8(a) => Ok(a.into()),
            ElementType::U16(a) => Ok(a),
            _ => Err(Error::TLVTypeMismatch),
        }
    }

    pub fn u32(&self) -> Result<u32, Error> {
        match self.element_type {
            ElementType::U8(a) => Ok(a.into()),
            ElementType::U16(a) => Ok(a.into()),
            ElementType::U32(a) => Ok(a),
            _ => Err(Error::TLVTypeMismatch),
        }
    }

    pub fn u64(&self) -> Result<u64, Error> {
        match self.element_type {
            ElementType::U8(a) => Ok(a.into()),
            ElementType::U16(a) => Ok(a.into()),
            ElementType::U32(a) => Ok(a.into()),
            ElementType::U64(a) => Ok(a),
            _ => Err(Error::TLVTypeMismatch),
        }
    }

    pub fn slice(&self) -> Result<&'a [u8], Error> {
        match self.element_type {
            ElementType::Str8l(s)
            | ElementType::Utf8l(s)
            | ElementType::Str16l(s)
            | ElementType::Utf16l(s) => Ok(s),
            _ => Err(Error::TLVTypeMismatch),
        }
    }

    pub fn bool(&self) -> Result<bool, Error> {
        match self.element_type {
            ElementType::False => Ok(false),
            ElementType::True => Ok(true),
            _ => Err(Error::TLVTypeMismatch),
        }
    }

    pub fn null(&self) -> Result<(), Error> {
        match self.element_type {
            ElementType::Null => Ok(()),
            _ => Err(Error::TLVTypeMismatch),
        }
    }

    pub fn confirm_struct(&self) -> Result<TLVElement<'a>, Error> {
        match self.element_type {
            ElementType::Struct(_) => Ok(*self),
            _ => Err(Error::TLVTypeMismatch),
        }
    }

    pub fn confirm_array(&self) -> Result<TLVElement<'a>, Error> {
        match self.element_type {
            ElementType::Array(_) => Ok(*self),
            _ => Err(Error::TLVTypeMismatch),
        }
    }

    pub fn confirm_list(&self) -> Result<TLVElement<'a>, Error> {
        match self.element_type {
            ElementType::List(_) => Ok(*self),
            _ => Err(Error::TLVTypeMismatch),
        }
    }

    pub fn find_tag(&self, tag: u32) -> Result<TLVElement<'a>, Error> {
        let match_tag: TagType = TagType::Context(tag as u8);

        let iter = self.enter().ok_or(Error::TLVTypeMismatch)?;
        for a in iter {
            if match_tag == a.tag_type {
                return Ok(a);
            }
        }
        Err(Error::NoTagFound)
    }

    pub fn get_tag(&self) -> TagType {
        self.tag_type
    }

    pub fn check_ctx_tag(&self, tag: u8) -> bool {
        if let TagType::Context(our_tag) = self.tag_type {
            if our_tag == tag {
                return true;
            }
        }
        false
    }

    pub fn get_element_type(&self) -> ElementType {
        self.element_type
    }
}

impl<'a> fmt::Display for TLVElement<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.tag_type {
            TagType::Anonymous => (),
            TagType::Context(tag) => write!(f, "{}: ", tag)?,
            _ => write!(f, "Other Context Tag")?,
        }
        match self.element_type {
            ElementType::Struct(_) => write!(f, "{{"),
            ElementType::Array(_) => write!(f, "["),
            ElementType::List(_) => write!(f, "["),
            ElementType::EndCnt => write!(f, ">"),
            ElementType::True => write!(f, "True"),
            ElementType::False => write!(f, "False"),
            ElementType::Str8l(a)
            | ElementType::Utf8l(a)
            | ElementType::Str16l(a)
            | ElementType::Utf16l(a) => {
                if let Ok(s) = std::str::from_utf8(a) {
                    write!(f, "len[{}]\"{}\"", s.len(), s)
                } else {
                    write!(f, "len[{}]{:x?}", a.len(), a)
                }
            }
            _ => write!(f, "{:?}", self.element_type),
        }
    }
}

// This is a TLV List iterator, it only iterates over the individual TLVs in a TLV list
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct TLVListIterator<'a> {
    buf: &'a [u8],
    current: usize,
    left: usize,
}

impl<'a> TLVListIterator<'a> {
    fn from_pointer(p: Pointer<'a>) -> Self {
        Self {
            buf: p.buf,
            current: p.current,
            left: p.left,
        }
    }

    fn advance(&mut self, len: usize) {
        self.current += len;
        self.left -= len;
    }

    // Caller should ensure they are reading the _right_ tag at the _right_ place
    fn read_this_tag(&mut self, tag_type: u8) -> Option<TagType> {
        if tag_type as usize >= MAX_TAG_INDEX {
            return None;
        }
        let tag_size = TAG_SIZE_MAP[tag_type as usize];
        if tag_size > self.left {
            return None;
        }
        let tag = (TAG_EXTRACTOR[tag_type as usize])(self);
        self.advance(tag_size);
        Some(tag)
    }

    fn read_this_value(&mut self, element_type: u8) -> Option<ElementType<'a>> {
        if element_type as usize >= MAX_VALUE_INDEX {
            return None;
        }
        let mut size = VALUE_SIZE_MAP[element_type as usize];
        if size > self.left {
            error!(
                "Invalid value found: {} self {:?} size {}",
                element_type, self, size
            );
            return None;
        }

        let (extra_size, element) = (VALUE_EXTRACTOR[element_type as usize])(self);
        if element != ElementType::Last {
            size += extra_size;
            self.advance(size);
            Some(element)
        } else {
            None
        }
    }
}

impl<'a> Iterator for TLVListIterator<'a> {
    type Item = TLVElement<'a>;
    /* Code for going to the next Element */
    fn next(&mut self) -> Option<TLVElement<'a>> {
        if self.left < 1 {
            return None;
        }
        /* Read Control */
        let control = self.buf[self.current];
        let tag_type = (control & TAG_MASK) >> TAG_SHIFT_BITS;
        let element_type = control & TYPE_MASK;
        self.advance(1);

        /* Consume Tag */
        let tag_type = self.read_this_tag(tag_type)?;

        /* Consume Value */
        let element_type = self.read_this_value(element_type)?;

        Some(TLVElement {
            tag_type,
            element_type,
        })
    }
}

impl<'a> TLVList<'a> {
    pub fn iter(&self) -> TLVListIterator<'a> {
        TLVListIterator {
            current: 0,
            left: self.buf.len(),
            buf: self.buf,
        }
    }
}

fn is_container(element_type: ElementType) -> bool {
    matches!(
        element_type,
        ElementType::Struct(_) | ElementType::Array(_) | ElementType::List(_)
    )
}

// This is a Container iterator, it iterates over containers in a TLV list
#[derive(Debug, PartialEq)]
pub struct TLVContainerIterator<'a> {
    list_iter: TLVListIterator<'a>,
    prev_container: bool,
    iterator_consumed: bool,
}

impl<'a> TLVContainerIterator<'a> {
    fn skip_to_end_of_container(&mut self) -> Option<TLVElement<'a>> {
        let mut nest_level = 0;
        while let Some(element) = self.list_iter.next() {
            // We know we are already in a container, we have to keep looking for end-of-container
            //            println!("Skip: element: {:x?} nest_level: {}", element, nest_level);
            match element.element_type {
                ElementType::EndCnt => {
                    if nest_level == 0 {
                        // Return the element following this element
                        //                        println!("Returning");
                        // The final next() may be the end of the top-level container itself, if so, we must return None
                        let last_elem = self.list_iter.next()?;
                        match last_elem.element_type {
                            ElementType::EndCnt => {
                                self.iterator_consumed = true;
                                return None;
                            }
                            _ => return Some(last_elem),
                        }
                    } else {
                        nest_level -= 1;
                    }
                }
                _ => {
                    if is_container(element.element_type) {
                        nest_level += 1;
                    }
                }
            }
        }
        None
    }
}

impl<'a> Iterator for TLVContainerIterator<'a> {
    type Item = TLVElement<'a>;
    /* Code for going to the next Element */
    fn next(&mut self) -> Option<TLVElement<'a>> {
        // This iterator may be consumed, but the underlying might not. This protects it from such occurrences
        if self.iterator_consumed {
            return None;
        }
        let element: TLVElement = if self.prev_container {
            //            println!("Calling skip to end of container");
            self.skip_to_end_of_container()?
        } else {
            self.list_iter.next()?
        };
        //        println!("Found element: {:x?}", element);
        /* If we found end of container, that means our own container is over */
        if element.element_type == ElementType::EndCnt {
            self.iterator_consumed = true;
            return None;
        }

        if is_container(element.element_type) {
            self.prev_container = true;
        } else {
            self.prev_container = false;
        }
        Some(element)
    }
}

pub fn get_root_node(b: &[u8]) -> Result<TLVElement, Error> {
    TLVList::new(b).iter().next().ok_or(Error::InvalidData)
}

pub fn get_root_node_struct(b: &[u8]) -> Result<TLVElement, Error> {
    TLVList::new(b)
        .iter()
        .next()
        .ok_or(Error::InvalidData)?
        .confirm_struct()
}

pub fn get_root_node_list(b: &[u8]) -> Result<TLVElement, Error> {
    TLVList::new(b)
        .iter()
        .next()
        .ok_or(Error::InvalidData)?
        .confirm_list()
}

pub fn print_tlv_list(b: &[u8]) {
    let tlvlist = TLVList::new(b);

    const MAX_DEPTH: usize = 9;
    info!("TLV list:");
    let space_buf = "                                ";
    let space: [&str; MAX_DEPTH] = [
        &space_buf[0..0],
        &space_buf[0..4],
        &space_buf[0..8],
        &space_buf[0..12],
        &space_buf[0..16],
        &space_buf[0..20],
        &space_buf[0..24],
        &space_buf[0..28],
        &space_buf[0..32],
    ];
    let mut stack: [char; MAX_DEPTH] = [' '; MAX_DEPTH];
    let mut index = 0_usize;
    let iter = tlvlist.iter();
    for a in iter {
        match a.element_type {
            ElementType::Struct(_) => {
                if index < MAX_DEPTH {
                    println!("{}{}", space[index], a);
                    stack[index] = '}';
                    index += 1;
                } else {
                    error!("Too Deep");
                }
            }
            ElementType::Array(_) | ElementType::List(_) => {
                if index < MAX_DEPTH {
                    println!("{}{}", space[index], a);
                    stack[index] = ']';
                    index += 1;
                } else {
                    error!("Too Deep");
                }
            }
            ElementType::EndCnt => {
                if index > 0 {
                    index -= 1;
                    println!("{}{}", space[index], stack[index]);
                } else {
                    error!("Incorrect TLV List");
                }
            }
            _ => println!("{}{}", space[index], a),
        }
    }
    println!("---------");
}

#[cfg(test)]
mod tests {
    use super::{
        get_root_node_list, get_root_node_struct, ElementType, Pointer, TLVElement, TLVList,
        TagType,
    };
    use crate::error::Error;

    #[test]
    fn test_short_length_tag() {
        // The 0x36 is an array with a tag, but we leave out the tag field
        let b = [0x15, 0x36];
        let tlvlist = TLVList::new(&b);
        let mut tlv_iter = tlvlist.iter();
        // Skip the 0x15
        tlv_iter.next();
        assert_eq!(tlv_iter.next(), None);
    }

    #[test]
    fn test_invalid_value_type() {
        // The 0x24 is a a tagged integer, here we leave out the integer value
        let b = [0x15, 0x1f, 0x0];
        let tlvlist = TLVList::new(&b);
        let mut tlv_iter = tlvlist.iter();
        // Skip the 0x15
        tlv_iter.next();
        assert_eq!(tlv_iter.next(), None);
    }

    #[test]
    fn test_short_length_value_immediate() {
        // The 0x24 is a a tagged integer, here we leave out the integer value
        let b = [0x15, 0x24, 0x0];
        let tlvlist = TLVList::new(&b);
        let mut tlv_iter = tlvlist.iter();
        // Skip the 0x15
        tlv_iter.next();
        assert_eq!(tlv_iter.next(), None);
    }

    #[test]
    fn test_short_length_value_string() {
        // This is a tagged string, with tag 0 and length 0xb, but we only have 4 bytes in the string
        let b = [0x15, 0x30, 0x00, 0x0b, 0x73, 0x6d, 0x61, 0x72];
        let tlvlist = TLVList::new(&b);
        let mut tlv_iter = tlvlist.iter();
        // Skip the 0x15
        tlv_iter.next();
        assert_eq!(tlv_iter.next(), None);
    }

    #[test]
    fn test_valid_tag() {
        // The 0x36 is an array with a tag, here tag is 0
        let b = [0x15, 0x36, 0x0];
        let tlvlist = TLVList::new(&b);
        let mut tlv_iter = tlvlist.iter();
        // Skip the 0x15
        tlv_iter.next();
        assert_eq!(
            tlv_iter.next(),
            Some(TLVElement {
                tag_type: TagType::Context(0),
                element_type: ElementType::Array(Pointer {
                    buf: &[21, 54, 0],
                    current: 3,
                    left: 0
                }),
            })
        );
    }

    #[test]
    fn test_valid_value_immediate() {
        // The 0x24 is a a tagged integer, here the integer is 2
        let b = [0x15, 0x24, 0x1, 0x2];
        let tlvlist = TLVList::new(&b);
        let mut tlv_iter = tlvlist.iter();
        // Skip the 0x15
        tlv_iter.next();
        assert_eq!(
            tlv_iter.next(),
            Some(TLVElement {
                tag_type: TagType::Context(1),
                element_type: ElementType::U8(2),
            })
        );
    }

    #[test]
    fn test_valid_value_string() {
        // This is a tagged string, with tag 0 and length 4, and we have 4 bytes in the string
        let b = [0x15, 0x30, 0x5, 0x04, 0x73, 0x6d, 0x61, 0x72];
        let tlvlist = TLVList::new(&b);
        let mut tlv_iter = tlvlist.iter();
        // Skip the 0x15
        tlv_iter.next();
        assert_eq!(
            tlv_iter.next(),
            Some(TLVElement {
                tag_type: TagType::Context(5),
                element_type: ElementType::Str8l(&[0x73, 0x6d, 0x61, 0x72]),
            })
        );
    }

    #[test]
    fn test_valid_value_string16() {
        // This is a tagged string, with tag 0 and length 4, and we have 4 bytes in the string
        let b = [
            0x15, 0x31, 0x1, 0xd8, 0x1, 0x30, 0x82, 0x1, 0xd4, 0x30, 0x82, 0x1, 0x7a, 0xa0, 0x3,
            0x2, 0x1, 0x2, 0x2, 0x8, 0x3e, 0x6c, 0xe6, 0x50, 0x9a, 0xd8, 0x40, 0xcd, 0x30, 0xa,
            0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x4, 0x3, 0x2, 0x30, 0x30, 0x31, 0x18, 0x30,
            0x16, 0x6, 0x3, 0x55, 0x4, 0x3, 0xc, 0xf, 0x4d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x20,
            0x54, 0x65, 0x73, 0x74, 0x20, 0x50, 0x41, 0x41, 0x31, 0x14, 0x30, 0x12, 0x6, 0xa, 0x2b,
            0x6, 0x1, 0x4, 0x1, 0x82, 0xa2, 0x7c, 0x2, 0x1, 0xc, 0x4, 0x46, 0x46, 0x46, 0x31, 0x30,
            0x20, 0x17, 0xd, 0x32, 0x31, 0x30, 0x36, 0x32, 0x38, 0x31, 0x34, 0x32, 0x33, 0x34,
            0x33, 0x5a, 0x18, 0xf, 0x39, 0x39, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33,
            0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x46, 0x31, 0x18, 0x30, 0x16, 0x6, 0x3, 0x55, 0x4,
            0x3, 0xc, 0xf, 0x4d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20,
            0x50, 0x41, 0x49, 0x31, 0x14, 0x30, 0x12, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82,
            0xa2, 0x7c, 0x2, 0x1, 0xc, 0x4, 0x46, 0x46, 0x46, 0x31, 0x31, 0x14, 0x30, 0x12, 0x6,
            0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0xa2, 0x7c, 0x2, 0x2, 0xc, 0x4, 0x38, 0x30, 0x30,
            0x30, 0x30, 0x59, 0x30, 0x13, 0x6, 0x7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x2, 0x1, 0x6,
            0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0x3, 0x42, 0x0, 0x4, 0x80, 0xdd,
            0xf1, 0x1b, 0x22, 0x8f, 0x3e, 0x31, 0xf6, 0x3b, 0xcf, 0x57, 0x98, 0xda, 0x14, 0x62,
            0x3a, 0xeb, 0xbd, 0xe8, 0x2e, 0xf3, 0x78, 0xee, 0xad, 0xbf, 0xb1, 0x8f, 0xe1, 0xab,
            0xce, 0x31, 0xd0, 0x8e, 0xd4, 0xb2, 0x6, 0x4, 0xb6, 0xcc, 0xc6, 0xd9, 0xb5, 0xfa, 0xb6,
            0x4e, 0x7d, 0xe1, 0xc, 0xb7, 0x4b, 0xe0, 0x17, 0xc9, 0xec, 0x15, 0x16, 0x5, 0x6d, 0x70,
            0xf2, 0xcd, 0xb, 0x22, 0xa3, 0x66, 0x30, 0x64, 0x30, 0x12, 0x6, 0x3, 0x55, 0x1d, 0x13,
            0x1, 0x1, 0xff, 0x4, 0x8, 0x30, 0x6, 0x1, 0x1, 0xff, 0x2, 0x1, 0x0, 0x30, 0xe, 0x6,
            0x3, 0x55, 0x1d, 0xf, 0x1, 0x1, 0xff, 0x4, 0x4, 0x3, 0x2, 0x1, 0x6, 0x30, 0x1d, 0x6,
            0x3, 0x55, 0x1d, 0xe, 0x4, 0x16, 0x4, 0x14, 0xaf, 0x42, 0xb7, 0x9, 0x4d, 0xeb, 0xd5,
            0x15, 0xec, 0x6e, 0xcf, 0x33, 0xb8, 0x11, 0x15, 0x22, 0x5f, 0x32, 0x52, 0x88, 0x30,
            0x1f, 0x6, 0x3, 0x55, 0x1d, 0x23, 0x4, 0x18, 0x30, 0x16, 0x80, 0x14, 0x6a, 0xfd, 0x22,
            0x77, 0x1f, 0x51, 0x1f, 0xec, 0xbf, 0x16, 0x41, 0x97, 0x67, 0x10, 0xdc, 0xdc, 0x31,
            0xa1, 0x71, 0x7e, 0x30, 0xa, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x4, 0x3, 0x2,
            0x3, 0x48, 0x0, 0x30, 0x45, 0x2, 0x21, 0x0, 0x96, 0xc9, 0xc8, 0xcf, 0x2e, 0x1, 0x88,
            0x60, 0x5, 0xd8, 0xf5, 0xbc, 0x72, 0xc0, 0x7b, 0x75, 0xfd, 0x9a, 0x57, 0x69, 0x5a,
            0xc4, 0x91, 0x11, 0x31, 0x13, 0x8b, 0xea, 0x3, 0x3c, 0xe5, 0x3, 0x2, 0x20, 0x25, 0x54,
            0x94, 0x3b, 0xe5, 0x7d, 0x53, 0xd6, 0xc4, 0x75, 0xf7, 0xd2, 0x3e, 0xbf, 0xcf, 0xc2,
            0x3, 0x6c, 0xd2, 0x9b, 0xa6, 0x39, 0x3e, 0xc7, 0xef, 0xad, 0x87, 0x14, 0xab, 0x71,
            0x82, 0x19, 0x26, 0x2, 0x3e, 0x0, 0x0, 0x0,
        ];
        let tlvlist = TLVList::new(&b);
        let mut tlv_iter = tlvlist.iter();
        // Skip the 0x15
        tlv_iter.next();
        assert_eq!(
            tlv_iter.next(),
            Some(TLVElement {
                tag_type: TagType::Context(1),
                element_type: ElementType::Str16l(&[
                    0x30, 0x82, 0x1, 0xd4, 0x30, 0x82, 0x1, 0x7a, 0xa0, 0x3, 0x2, 0x1, 0x2, 0x2,
                    0x8, 0x3e, 0x6c, 0xe6, 0x50, 0x9a, 0xd8, 0x40, 0xcd, 0x30, 0xa, 0x6, 0x8, 0x2a,
                    0x86, 0x48, 0xce, 0x3d, 0x4, 0x3, 0x2, 0x30, 0x30, 0x31, 0x18, 0x30, 0x16, 0x6,
                    0x3, 0x55, 0x4, 0x3, 0xc, 0xf, 0x4d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x20, 0x54,
                    0x65, 0x73, 0x74, 0x20, 0x50, 0x41, 0x41, 0x31, 0x14, 0x30, 0x12, 0x6, 0xa,
                    0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0xa2, 0x7c, 0x2, 0x1, 0xc, 0x4, 0x46, 0x46,
                    0x46, 0x31, 0x30, 0x20, 0x17, 0xd, 0x32, 0x31, 0x30, 0x36, 0x32, 0x38, 0x31,
                    0x34, 0x32, 0x33, 0x34, 0x33, 0x5a, 0x18, 0xf, 0x39, 0x39, 0x39, 0x39, 0x31,
                    0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x46, 0x31,
                    0x18, 0x30, 0x16, 0x6, 0x3, 0x55, 0x4, 0x3, 0xc, 0xf, 0x4d, 0x61, 0x74, 0x74,
                    0x65, 0x72, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x50, 0x41, 0x49, 0x31, 0x14,
                    0x30, 0x12, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0xa2, 0x7c, 0x2, 0x1,
                    0xc, 0x4, 0x46, 0x46, 0x46, 0x31, 0x31, 0x14, 0x30, 0x12, 0x6, 0xa, 0x2b, 0x6,
                    0x1, 0x4, 0x1, 0x82, 0xa2, 0x7c, 0x2, 0x2, 0xc, 0x4, 0x38, 0x30, 0x30, 0x30,
                    0x30, 0x59, 0x30, 0x13, 0x6, 0x7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x2, 0x1, 0x6,
                    0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0x3, 0x42, 0x0, 0x4, 0x80,
                    0xdd, 0xf1, 0x1b, 0x22, 0x8f, 0x3e, 0x31, 0xf6, 0x3b, 0xcf, 0x57, 0x98, 0xda,
                    0x14, 0x62, 0x3a, 0xeb, 0xbd, 0xe8, 0x2e, 0xf3, 0x78, 0xee, 0xad, 0xbf, 0xb1,
                    0x8f, 0xe1, 0xab, 0xce, 0x31, 0xd0, 0x8e, 0xd4, 0xb2, 0x6, 0x4, 0xb6, 0xcc,
                    0xc6, 0xd9, 0xb5, 0xfa, 0xb6, 0x4e, 0x7d, 0xe1, 0xc, 0xb7, 0x4b, 0xe0, 0x17,
                    0xc9, 0xec, 0x15, 0x16, 0x5, 0x6d, 0x70, 0xf2, 0xcd, 0xb, 0x22, 0xa3, 0x66,
                    0x30, 0x64, 0x30, 0x12, 0x6, 0x3, 0x55, 0x1d, 0x13, 0x1, 0x1, 0xff, 0x4, 0x8,
                    0x30, 0x6, 0x1, 0x1, 0xff, 0x2, 0x1, 0x0, 0x30, 0xe, 0x6, 0x3, 0x55, 0x1d, 0xf,
                    0x1, 0x1, 0xff, 0x4, 0x4, 0x3, 0x2, 0x1, 0x6, 0x30, 0x1d, 0x6, 0x3, 0x55, 0x1d,
                    0xe, 0x4, 0x16, 0x4, 0x14, 0xaf, 0x42, 0xb7, 0x9, 0x4d, 0xeb, 0xd5, 0x15, 0xec,
                    0x6e, 0xcf, 0x33, 0xb8, 0x11, 0x15, 0x22, 0x5f, 0x32, 0x52, 0x88, 0x30, 0x1f,
                    0x6, 0x3, 0x55, 0x1d, 0x23, 0x4, 0x18, 0x30, 0x16, 0x80, 0x14, 0x6a, 0xfd,
                    0x22, 0x77, 0x1f, 0x51, 0x1f, 0xec, 0xbf, 0x16, 0x41, 0x97, 0x67, 0x10, 0xdc,
                    0xdc, 0x31, 0xa1, 0x71, 0x7e, 0x30, 0xa, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce,
                    0x3d, 0x4, 0x3, 0x2, 0x3, 0x48, 0x0, 0x30, 0x45, 0x2, 0x21, 0x0, 0x96, 0xc9,
                    0xc8, 0xcf, 0x2e, 0x1, 0x88, 0x60, 0x5, 0xd8, 0xf5, 0xbc, 0x72, 0xc0, 0x7b,
                    0x75, 0xfd, 0x9a, 0x57, 0x69, 0x5a, 0xc4, 0x91, 0x11, 0x31, 0x13, 0x8b, 0xea,
                    0x3, 0x3c, 0xe5, 0x3, 0x2, 0x20, 0x25, 0x54, 0x94, 0x3b, 0xe5, 0x7d, 0x53,
                    0xd6, 0xc4, 0x75, 0xf7, 0xd2, 0x3e, 0xbf, 0xcf, 0xc2, 0x3, 0x6c, 0xd2, 0x9b,
                    0xa6, 0x39, 0x3e, 0xc7, 0xef, 0xad, 0x87, 0x14, 0xab, 0x71, 0x82, 0x19
                ]),
            })
        );
        assert_eq!(
            tlv_iter.next(),
            Some(TLVElement {
                tag_type: TagType::Context(2),
                element_type: ElementType::U32(62),
            })
        );
    }

    #[test]
    fn test_no_iterator_for_int() {
        // The 0x24 is a a tagged integer, here the integer is 2
        let b = [0x15, 0x24, 0x1, 0x2];
        let tlvlist = TLVList::new(&b);
        let mut tlv_iter = tlvlist.iter();
        // Skip the 0x15
        tlv_iter.next();
        assert_eq!(tlv_iter.next().unwrap().enter(), None);
    }

    #[test]
    fn test_struct_iteration_with_mix_values() {
        // This is a struct with 3 valid values
        let b = [
            0x15, 0x24, 0x0, 0x2, 0x26, 0x2, 0x4e, 0x10, 0x02, 0x00, 0x30, 0x3, 0x04, 0x73, 0x6d,
            0x61, 0x72,
        ];
        let mut root_iter = get_root_node_struct(&b).unwrap().enter().unwrap();
        assert_eq!(
            root_iter.next(),
            Some(TLVElement {
                tag_type: TagType::Context(0),
                element_type: ElementType::U8(2),
            })
        );
        assert_eq!(
            root_iter.next(),
            Some(TLVElement {
                tag_type: TagType::Context(2),
                element_type: ElementType::U32(135246),
            })
        );
        assert_eq!(
            root_iter.next(),
            Some(TLVElement {
                tag_type: TagType::Context(3),
                element_type: ElementType::Str8l(&[0x73, 0x6d, 0x61, 0x72]),
            })
        );
    }

    #[test]
    fn test_struct_find_element_mix_values() {
        // This is a struct with 3 valid values
        let b = [
            0x15, 0x30, 0x3, 0x04, 0x73, 0x6d, 0x61, 0x72, 0x24, 0x0, 0x2, 0x26, 0x2, 0x4e, 0x10,
            0x02, 0x00,
        ];
        let root = get_root_node_struct(&b).unwrap();

        assert_eq!(
            root.find_tag(0).unwrap(),
            TLVElement {
                tag_type: TagType::Context(0),
                element_type: ElementType::U8(2),
            }
        );
        assert_eq!(
            root.find_tag(2).unwrap(),
            TLVElement {
                tag_type: TagType::Context(2),
                element_type: ElementType::U32(135246),
            }
        );
        assert_eq!(
            root.find_tag(3).unwrap(),
            TLVElement {
                tag_type: TagType::Context(3),
                element_type: ElementType::Str8l(&[0x73, 0x6d, 0x61, 0x72]),
            }
        );
    }

    #[test]
    fn test_list_iteration_with_mix_values() {
        // This is a list with 3 valid values
        let b = [
            0x17, 0x24, 0x0, 0x2, 0x26, 0x2, 0x4e, 0x10, 0x02, 0x00, 0x30, 0x3, 0x04, 0x73, 0x6d,
            0x61, 0x72,
        ];
        let mut root_iter = get_root_node_list(&b).unwrap().enter().unwrap();
        assert_eq!(
            root_iter.next(),
            Some(TLVElement {
                tag_type: TagType::Context(0),
                element_type: ElementType::U8(2),
            })
        );
        assert_eq!(
            root_iter.next(),
            Some(TLVElement {
                tag_type: TagType::Context(2),
                element_type: ElementType::U32(135246),
            })
        );
        assert_eq!(
            root_iter.next(),
            Some(TLVElement {
                tag_type: TagType::Context(3),
                element_type: ElementType::Str8l(&[0x73, 0x6d, 0x61, 0x72]),
            })
        );
    }

    #[test]
    fn test_complex_structure_invoke_cmd() {
        // This is what we typically get in an invoke command
        let b = [
            0x15, 0x36, 0x0, 0x15, 0x37, 0x0, 0x24, 0x0, 0x2, 0x24, 0x2, 0x6, 0x24, 0x3, 0x1, 0x18,
            0x35, 0x1, 0x18, 0x18, 0x18, 0x18,
        ];

        let root = get_root_node_struct(&b).unwrap();

        let mut cmd_list_iter = root
            .find_tag(0)
            .unwrap()
            .confirm_array()
            .unwrap()
            .enter()
            .unwrap();
        println!("Command list iterator: {:?}", cmd_list_iter);

        // This is an array of CommandDataIB, but we'll only use the first element
        let cmd_data_ib = cmd_list_iter.next().unwrap();

        let cmd_path = cmd_data_ib.find_tag(0).unwrap().confirm_list().unwrap();
        assert_eq!(
            cmd_path.find_tag(0).unwrap(),
            TLVElement {
                tag_type: TagType::Context(0),
                element_type: ElementType::U8(2),
            }
        );
        assert_eq!(
            cmd_path.find_tag(2).unwrap(),
            TLVElement {
                tag_type: TagType::Context(2),
                element_type: ElementType::U8(6),
            }
        );
        assert_eq!(
            cmd_path.find_tag(3).unwrap(),
            TLVElement {
                tag_type: TagType::Context(3),
                element_type: ElementType::U8(1),
            }
        );
        assert_eq!(cmd_path.find_tag(1), Err(Error::NoTagFound));

        // This is the variable of the invoke command
        assert_eq!(
            cmd_data_ib.find_tag(1).unwrap().enter().unwrap().next(),
            None
        );
    }

    #[test]
    fn test_read_past_end_of_container() {
        let b = [0x15, 0x35, 0x0, 0x24, 0x1, 0x2, 0x18, 0x24, 0x0, 0x2, 0x18];

        let mut sub_root_iter = get_root_node_struct(&b)
            .unwrap()
            .find_tag(0)
            .unwrap()
            .enter()
            .unwrap();
        assert_eq!(
            sub_root_iter.next(),
            Some(TLVElement {
                tag_type: TagType::Context(1),
                element_type: ElementType::U8(2),
            })
        );
        assert_eq!(sub_root_iter.next(), None);
        // Call next, even after the first next returns None
        assert_eq!(sub_root_iter.next(), None);
        assert_eq!(sub_root_iter.next(), None);
    }

    #[test]
    fn test_basic_list_iterator() {
        // This is the input we have
        let b = [
            0x15, 0x36, 0x0, 0x15, 0x37, 0x0, 0x24, 0x0, 0x2, 0x24, 0x2, 0x6, 0x24, 0x3, 0x1, 0x18,
            0x35, 0x1, 0x18, 0x18, 0x18, 0x18,
        ];

        let dummy_pointer = Pointer {
            buf: &b,
            current: 1,
            left: 21,
        };
        // These are the decoded elements that we expect from this input
        let verify_matrix: [(TagType, ElementType); 13] = [
            (TagType::Anonymous, ElementType::Struct(dummy_pointer)),
            (TagType::Context(0), ElementType::Array(dummy_pointer)),
            (TagType::Anonymous, ElementType::Struct(dummy_pointer)),
            (TagType::Context(0), ElementType::List(dummy_pointer)),
            (TagType::Context(0), ElementType::U8(2)),
            (TagType::Context(2), ElementType::U8(6)),
            (TagType::Context(3), ElementType::U8(1)),
            (TagType::Anonymous, ElementType::EndCnt),
            (TagType::Context(1), ElementType::Struct(dummy_pointer)),
            (TagType::Anonymous, ElementType::EndCnt),
            (TagType::Anonymous, ElementType::EndCnt),
            (TagType::Anonymous, ElementType::EndCnt),
            (TagType::Anonymous, ElementType::EndCnt),
        ];

        let mut list_iter = TLVList::new(&b).iter();
        let mut index = 0;
        loop {
            let element = list_iter.next();
            match element {
                None => break,
                Some(a) => {
                    assert_eq!(a.tag_type, verify_matrix[index].0);
                    assert_eq!(
                        std::mem::discriminant(&a.element_type),
                        std::mem::discriminant(&verify_matrix[index].1)
                    );
                }
            }
            index += 1;
        }
        // After the end, purposefully try a few more next
        assert_eq!(list_iter.next(), None);
        assert_eq!(list_iter.next(), None);
    }
}
