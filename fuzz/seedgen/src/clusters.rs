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

//! The seeds of the `clusters` target. Each takes one or a few cluster handlers of its
//! node through their commands and their writable attributes, all on the CASE session.
//!
//! Where a command answers with an ID that a later command uses, such as the ID of a
//! zone or of a stream, the seed has the ID that the node gives, which is the same on
//! every run.

use rs_matter::tlv::{TLVTag, TLVWrite};
use rs_matter::utils::storage::WriteBuf;

use crate::{
    all_clusters, attr_data, c, invoke1, read_req, status_ok, subscribe_req, timed_req, write_req,
    Path3, Seed, A, ACK, BDX, I, IM, INVOKE, NODE_EXCH, R, READ, REL, STATUS_RESP, SUBSCRIBE,
    TIMED, WRITE,
};

const IDENTIFY: u32 = 0x0003;
const GROUPS: u32 = 0x0004;
const ON_OFF: u32 = 0x0006;
const LEVEL: u32 = 0x0008;
const BINDING: u32 = 0x001e;
const OTA_PROVIDER: u32 = 0x0029;
const OTA_REQUESTOR: u32 = 0x002a;
const DIAG_LOGS: u32 = 0x0032;
const TIME_SYNC: u32 = 0x0038;
const GROUP_KEYS: u32 = 0x003f;
const USER_LABEL: u32 = 0x0041;
const ICD: u32 = 0x0046;
const MODE_SELECT: u32 = 0x0050;
const WASHER_MODE: u32 = 0x0051;
const SCENES: u32 = 0x0062;
const GROUPCAST: u32 = 0x0065;
const THERMOSTAT: u32 = 0x0201;
const FAN: u32 = 0x0202;
const COLOR: u32 = 0x0300;
const ZONES: u32 = 0x0550;
const CAM_AV: u32 = 0x0551;
const CAM_SETTINGS: u32 = 0x0552;
const WEBRTC: u32 = 0x0553;
const PUSH_AV: u32 = 0x0555;
const UNIT_TESTING: u32 = 0xfff1_fc05;

// BDX opcodes
const SEND_ACCEPT: u8 = 0x02;
const BLOCK_QUERY: u8 = 0x10;
const BLOCK_ACK_EOF: u8 = 0x14;

pub fn seeds() -> Vec<(&'static str, Seed)> {
    let mut seeds = Vec::new();

    // A read of every attribute
    let mut r = Requests::new();
    r.read(&[(None, None, None)], &[]);
    seeds.push(("read-all", r.seed));

    // A subscription to the lights and the air conditioner, then changes to them, with
    // the answers to the reports
    let mut r = Requests::new();
    r.subscribe(
        &[
            (Some(1), Some(ON_OFF), None),
            (Some(1), Some(LEVEL), None),
            (Some(1), Some(COLOR), Some(0)),
            (Some(2), Some(FAN), None),
        ],
        &[(Some(1), None, None), (Some(2), None, None)],
    )
    .invoke(1, ON_OFF, 1, none)
    .reports()
    .invoke(1, LEVEL, 0, uints(&[50, 0, 0, 0]))
    .reports()
    .invoke(1, COLOR, 0, uints(&[100, 0, 0, 0, 0]))
    .reports()
    .write(2, FAN, 0, |w, t| Ok(w.u8(t, 3)?))
    .reports()
    .invoke(1, ON_OFF, 0, none)
    .reports();
    seeds.push(("subscribe", r.seed));

    // On/Off and Level Control: every command, and the writable attributes
    let mut r = Requests::new();
    r.invoke(1, ON_OFF, 1, none)
        .invoke(1, ON_OFF, 0, none)
        .invoke(1, ON_OFF, 2, none)
        .invoke(1, ON_OFF, 64, uints(&[0, 0]))
        .invoke(1, ON_OFF, 65, none)
        .invoke(1, ON_OFF, 66, uints(&[0, 50, 20]))
        .write(1, ON_OFF, 0x4001, |w, t| Ok(w.u16(t, 10)?))
        .write(1, ON_OFF, 0x4002, |w, t| Ok(w.u16(t, 5)?))
        .write(1, ON_OFF, 0x4003, |w, t| Ok(w.u8(t, 2)?))
        .write(1, ON_OFF, 0x4003, |w, t| Ok(w.null(t)?))
        .invoke(1, LEVEL, 0, uints(&[128, 0, 0, 0]))
        .invoke(1, LEVEL, 1, uints(&[0, 10, 0, 0]))
        .invoke(1, LEVEL, 3, uints(&[0, 0]))
        .invoke(1, LEVEL, 2, uints(&[1, 20, 0, 0, 0]))
        .invoke(1, LEVEL, 4, |w| {
            w.u8(&c(0), 200)?;
            w.null(&c(1))?;
            w.u8(&c(2), 1)?;
            w.u8(&c(3), 1)?;
            Ok(())
        })
        .invoke(1, LEVEL, 5, uints(&[1, 5, 0, 0]))
        .invoke(1, LEVEL, 6, uints(&[0, 10, 0, 0, 0]))
        .invoke(1, LEVEL, 7, uints(&[0, 0]))
        .write(1, LEVEL, 15, |w, t| Ok(w.u8(t, 1)?))
        .write(1, LEVEL, 17, |w, t| Ok(w.u8(t, 100)?))
        .write(1, LEVEL, 17, |w, t| Ok(w.null(t)?));
    seeds.push(("on-off-level", r.seed));

    // Transitions of Level Control and Color Control, Identify, and a timed on, as time
    // passes, with a subscription to them and the answers to its reports
    let mut r = Requests::new();
    r.subscribe(
        &[
            (Some(1), Some(ON_OFF), None),
            (Some(1), Some(LEVEL), None),
            (Some(1), Some(COLOR), Some(0)),
            (Some(1), Some(IDENTIFY), None),
        ],
        &[],
    )
    .invoke(1, ON_OFF, 1, none)
    .reports()
    .invoke(1, LEVEL, 0, uints(&[200, 20, 0, 0]))
    .reports()
    .wait(5)
    .reports()
    .wait(5)
    .reports()
    .wait(10)
    .reports()
    .invoke(1, LEVEL, 1, uints(&[0, 50, 0, 0]))
    .reports()
    .wait(10)
    .reports()
    .invoke(1, LEVEL, 3, uints(&[0, 0]))
    .reports()
    .invoke(1, COLOR, 0, uints(&[100, 0, 10, 0, 0]))
    .reports()
    .wait(5)
    .reports()
    .wait(10)
    .reports()
    .invoke(1, IDENTIFY, 0, uints(&[3]))
    .reports()
    .wait(10)
    .reports()
    .wait(30)
    .reports()
    .invoke(1, ON_OFF, 66, uints(&[0, 10, 10]))
    .reports()
    .wait(15)
    .reports()
    .wait(15)
    .reports();
    seeds.push(("transitions", r.seed));

    // Color Control: every command, after the light is turned on
    let mut r = Requests::new();
    r.invoke(1, ON_OFF, 1, none)
        .invoke(1, COLOR, 0, uints(&[100, 0, 0, 0, 0]))
        .invoke(1, COLOR, 1, uints(&[1, 10, 0, 0]))
        .invoke(1, COLOR, 2, uints(&[1, 10, 0, 0, 0]))
        .invoke(1, COLOR, 3, uints(&[200, 0, 0, 0]))
        .invoke(1, COLOR, 4, uints(&[3, 10, 0, 0]))
        .invoke(1, COLOR, 5, uints(&[3, 20, 0, 0, 0]))
        .invoke(1, COLOR, 6, uints(&[50, 60, 0, 0, 0]))
        .invoke(1, COLOR, 7, uints(&[30000, 20000, 0, 0, 0]))
        .invoke(1, COLOR, 8, |w| {
            w.i16(&c(0), -10)?;
            w.i16(&c(1), 10)?;
            uints_from(w, 2, &[0, 0])
        })
        .invoke(1, COLOR, 9, |w| {
            w.i16(&c(0), 100)?;
            w.i16(&c(1), -100)?;
            uints_from(w, 2, &[0, 0, 0])
        })
        .invoke(1, COLOR, 10, uints(&[250, 0, 0, 0]))
        .invoke(1, COLOR, 64, uints(&[30000, 0, 0, 0, 0]))
        .invoke(1, COLOR, 65, uints(&[1, 100, 0, 0]))
        .invoke(1, COLOR, 66, uints(&[1, 1000, 0, 0, 0]))
        .invoke(1, COLOR, 67, uints(&[30000, 100, 0, 0, 0]))
        .invoke(1, COLOR, 68, uints(&[0x0f, 1, 1, 10, 0, 0, 0]))
        .invoke(1, COLOR, 68, uints(&[0x01, 0, 0, 0, 0, 0, 0]))
        .invoke(1, COLOR, 71, uints(&[0, 0]))
        .invoke(1, COLOR, 75, uints(&[1, 10, 150, 400, 0, 0]))
        .invoke(1, COLOR, 76, uints(&[3, 10, 0, 150, 400, 0, 0]))
        .write(1, COLOR, 0x0f, |w, t| Ok(w.u8(t, 1)?))
        .write(1, COLOR, 0x4010, |w, t| Ok(w.u16(t, 250)?));
    seeds.push(("color", r.seed));

    // Scenes Management: a scene with all three clusters, then every command on it
    let mut r = Requests::new();
    r.invoke(1, ON_OFF, 1, none)
        .invoke(1, LEVEL, 0, uints(&[100, 0, 0, 0]))
        .invoke(1, SCENES, 0, |w| add_scene(w, 0, 1))
        .invoke(1, SCENES, 1, uints(&[0, 1]))
        .invoke(1, SCENES, 4, uints(&[0, 2]))
        .invoke(1, SCENES, 5, |w| {
            uints_from(w, 0, &[0, 1])?;
            Ok(w.u32(&c(2), 0)?)
        })
        .invoke(1, SCENES, 6, uints(&[0]))
        .invoke(1, SCENES, 64, uints(&[0, 0, 1, 0, 3]))
        .invoke(1, SCENES, 64, uints(&[1, 0, 0, 0, 0]))
        .read(&[(Some(1), Some(SCENES), None)], &[])
        .invoke(1, ON_OFF, 64, uints(&[0, 0]))
        .invoke(1, ON_OFF, 65, none)
        .invoke(1, SCENES, 2, uints(&[0, 2]))
        .invoke(1, SCENES, 3, uints(&[0]));
    seeds.push(("scenes", r.seed));

    // Groups and Identify: two groups with keys, a scene in one of them, then every
    // command of Groups and Identify
    let mut r = Requests::new();
    r.invoke(0, GROUP_KEYS, 0, key_set)
        .write(0, GROUP_KEYS, 0, |w, t| {
            w.start_array(t)?;
            for group in [0x0101, 0x0102] {
                w.start_struct(&A)?;
                w.u16(&c(1), group)?;
                w.u16(&c(2), 1)?;
                w.end_container()?;
            }
            w.end_container()?;
            Ok(())
        })
        .invoke(1, GROUPS, 0, |w| group(w, 0x0101, "Kitchen"))
        .invoke(0, GROUPS, 0, |w| group(w, 0x0101, "Kitchen"))
        .invoke(1, GROUPS, 1, uints(&[0x0101]))
        .invoke(1, GROUPS, 2, |w| {
            w.start_array(&c(0))?;
            w.u16(&A, 0x0101)?;
            w.u16(&A, 0x0102)?;
            w.end_container()?;
            Ok(())
        })
        .invoke(1, SCENES, 0, |w| add_scene(w, 0x0101, 1))
        .invoke(1, IDENTIFY, 0, uints(&[10]))
        .invoke(1, GROUPS, 5, |w| group(w, 0x0102, "Hall"))
        .invoke(1, IDENTIFY, 64, uints(&[0, 0]))
        .invoke(1, IDENTIFY, 64, uints(&[0xff, 0]))
        .write(1, IDENTIFY, 0, |w, t| Ok(w.u16(t, 0)?))
        .read(
            &[
                (Some(0), Some(GROUP_KEYS), Some(1)),
                (Some(1), Some(GROUPS), None),
                (Some(1), Some(IDENTIFY), None),
            ],
            &[],
        )
        .invoke(1, GROUPS, 3, uints(&[0x0101]))
        .invoke(1, SCENES, 1, uints(&[0x0101, 1]))
        .invoke(1, GROUPS, 4, none)
        .invoke(0, GROUPS, 4, none);
    seeds.push(("groups", r.seed));

    // Groupcast: groups joined with and without a key, then every other command
    let mut r = Requests::new();
    r.invoke(0, GROUP_KEYS, 0, key_set)
        .invoke(0, GROUPCAST, 0, |w| {
            w.u16(&c(0), 0x0201)?;
            endpoints(w, 1, &[1])?;
            w.u16(&c(2), 1)?;
            w.bool(&c(4), true)?;
            w.bool(&c(5), false)?;
            Ok(w.u8(&c(6), 0)?)
        })
        .invoke(0, GROUPCAST, 0, |w| {
            w.u16(&c(0), 0x0202)?;
            endpoints(w, 1, &[1, 2])?;
            w.u16(&c(2), 2)?;
            w.str(&c(3), &[0xe0; 16])?;
            Ok(())
        })
        .read(
            &[
                (Some(0), Some(GROUPCAST), None),
                (Some(0), Some(0x1f), None),
            ],
            &[],
        )
        .invoke(0, GROUPCAST, 3, |w| {
            w.u16(&c(0), 0x0202)?;
            w.u16(&c(1), 3)?;
            Ok(w.str(&c(2), &[0xe1; 16])?)
        })
        .invoke(0, GROUPCAST, 4, |w| {
            w.u16(&c(0), 0x0201)?;
            Ok(w.bool(&c(1), false)?)
        })
        .invoke(0, GROUPCAST, 1, |w| {
            w.u16(&c(0), 0x0202)?;
            endpoints(w, 1, &[2])
        })
        .invoke(0, GROUPCAST, 1, uints(&[0x0201]))
        .invoke(0, GROUPCAST, 5, uints(&[0, 10]));
    seeds.push(("groupcast", r.seed));

    // User Label and Binding: lists written whole and by items, then read
    let mut r = Requests::new();
    r.write(0, USER_LABEL, 0, |w, t| {
        w.start_array(t)?;
        label(w, &A, "room", "hall")?;
        label(w, &A, "floor", "1")?;
        w.end_container()?;
        Ok(())
    })
    .append(0, USER_LABEL, 0, |w, t| label(w, t, "orientation", "north"))
    .write(1, BINDING, 0, |w, t| {
        w.start_array(t)?;
        w.start_struct(&A)?;
        w.u64(&c(1), 0x1234)?;
        w.u16(&c(3), 1)?;
        w.u32(&c(4), ON_OFF)?;
        w.end_container()?;
        w.start_struct(&A)?;
        w.u16(&c(2), 0x0101)?;
        w.end_container()?;
        w.end_container()?;
        Ok(())
    })
    .append(0, BINDING, 0, |w, t| {
        w.start_struct(t)?;
        w.u64(&c(1), 0x5678)?;
        w.u16(&c(3), 2)?;
        w.end_container()?;
        Ok(())
    })
    .read(
        &[(None, Some(USER_LABEL), None), (None, Some(BINDING), None)],
        &[],
    )
    .write(1, BINDING, 0, |w, t| {
        w.start_array(t)?;
        w.end_container()?;
        Ok(())
    });
    seeds.push(("labels-bindings", r.seed));

    // Mode Select and Laundry Washer Mode
    let mut r = Requests::new();
    r.invoke(1, MODE_SELECT, 0, uints(&[4]))
        .invoke(1, MODE_SELECT, 0, uints(&[5]))
        .write(1, MODE_SELECT, 4, |w, t| Ok(w.u8(t, 7)?))
        .write(1, MODE_SELECT, 5, |w, t| Ok(w.u8(t, 4)?))
        .invoke(1, ON_OFF, 0, none)
        .invoke(1, ON_OFF, 1, none)
        .write(1, MODE_SELECT, 5, |w, t| Ok(w.null(t)?))
        .invoke(1, WASHER_MODE, 0, uints(&[2]))
        .invoke(1, WASHER_MODE, 0, uints(&[5]))
        .read(
            &[
                (Some(1), Some(MODE_SELECT), None),
                (Some(1), Some(WASHER_MODE), None),
            ],
            &[],
        );
    seeds.push(("modes", r.seed));

    // Unit Testing: writes of attributes of each type
    let mut r = Requests::new();
    r.write(1, UNIT_TESTING, 0, |w, t| Ok(w.bool(t, true)?))
        .write(1, UNIT_TESTING, 2, |w, t| Ok(w.u16(t, 0xffff)?))
        .write(1, UNIT_TESTING, 7, |w, t| Ok(w.u32(t, 0x00ff_ffff)?))
        .write(1, UNIT_TESTING, 9, |w, t| Ok(w.u64(t, 0xff_ffff_ffff)?))
        .write(1, UNIT_TESTING, 15, |w, t| Ok(w.i32(t, -0x7f_ffff)?))
        .write(1, UNIT_TESTING, 20, |w, t| Ok(w.i64(t, i64::MIN)?))
        .write(1, UNIT_TESTING, 22, |w, t| Ok(w.u16(t, 0x1234)?))
        .write(1, UNIT_TESTING, 23, |w, t| Ok(w.f32(t, 0.5)?))
        .write(1, UNIT_TESTING, 24, |w, t| Ok(w.f64(t, -1e300)?))
        .write(1, UNIT_TESTING, 25, |w, t| Ok(w.str(t, b"\x00\x01ab")?))
        .write(1, UNIT_TESTING, 29, |w, t| Ok(w.str(t, &[0x5a; 300])?))
        .write(1, UNIT_TESTING, 30, |w, t| Ok(w.utf8(t, "\u{e9}t\u{e9}")?))
        .write(1, UNIT_TESTING, 31, |w, t| {
            Ok(w.utf8(t, &"long ".repeat(60))?)
        })
        .write(1, UNIT_TESTING, 32, |w, t| Ok(w.u64(t, 1 << 50)?))
        .write(1, UNIT_TESTING, 34, |w, t| Ok(w.u16(t, 0xfff1)?))
        .write(1, UNIT_TESTING, 36, |w, t| Ok(w.u8(t, 2)?))
        .write(1, UNIT_TESTING, 37, |w, t| simple_struct(w, t, 7))
        .write(1, UNIT_TESTING, 38, |w, t| Ok(w.u8(t, 20)?))
        .write(1, UNIT_TESTING, 41, |w, t| Ok(w.i16(t, -40)?))
        .write_timed(1, UNIT_TESTING, 48, |w, t| Ok(w.bool(t, true)?))
        .write(1, UNIT_TESTING, 48, |w, t| Ok(w.bool(t, true)?))
        .write(1, UNIT_TESTING, 49, |w, t| Ok(w.bool(t, true)?))
        .write(1, UNIT_TESTING, 50, |w, t| Ok(w.bool(t, true)?))
        .write(1, UNIT_TESTING, 51, |w, t| Ok(w.u8(t, 1)?))
        .write(1, UNIT_TESTING, 52, global_struct)
        .write(1, UNIT_TESTING, 0x4005, |w, t| Ok(w.null(t)?))
        .write(1, UNIT_TESTING, 0x4018, |w, t| Ok(w.f64(t, f64::NAN)?))
        .write(1, UNIT_TESTING, 0x4025, |w, t| Ok(w.null(t)?))
        .write(1, UNIT_TESTING, 0x4026, |w, t| Ok(w.u8(t, 255)?));
    seeds.push(("unit-testing-write", r.seed));

    // Unit Testing: writes of lists, whole and by items, of structures, and of a
    // fabric-scoped list, then a read of the attributes
    let mut r = Requests::new();
    r.write(1, UNIT_TESTING, 26, |w, t| {
        w.start_array(t)?;
        for i in 1..=4 {
            w.u8(&A, i)?;
        }
        w.end_container()?;
        Ok(())
    })
    .append(1, UNIT_TESTING, 26, |w, t| Ok(w.u8(t, 5)?))
    .write(1, UNIT_TESTING, 27, |w, t| {
        w.start_array(t)?;
        w.str(&A, b"first")?;
        w.str(&A, b"")?;
        w.end_container()?;
        Ok(())
    })
    .write(1, UNIT_TESTING, 28, |w, t| {
        w.start_array(t)?;
        w.start_struct(&A)?;
        w.u64(&c(0), 1)?;
        w.str(&c(1), b"member")?;
        w.end_container()?;
        w.end_container()?;
        Ok(())
    })
    .write(1, UNIT_TESTING, 35, |w, t| {
        w.start_array(t)?;
        w.start_struct(&A)?;
        nullables_and_optionals(w)?;
        w.end_container()?;
        w.end_container()?;
        Ok(())
    })
    .append(1, UNIT_TESTING, 42, |w, t| Ok(w.str(t, &[0x11; 200])?))
    .write(1, UNIT_TESTING, 43, |w, t| {
        w.start_array(t)?;
        fabric_scoped(w, &A)?;
        w.end_container()?;
        Ok(())
    })
    .append(1, UNIT_TESTING, 43, fabric_scoped)
    .read(
        &[
            (Some(1), Some(UNIT_TESTING), Some(26)),
            (Some(1), Some(UNIT_TESTING), Some(35)),
            (Some(1), Some(UNIT_TESTING), Some(43)),
        ],
        &[],
    );
    seeds.push(("unit-testing-lists", r.seed));

    // Unit Testing: the commands, then a read of their events
    let mut r = Requests::new();
    r.invoke(1, UNIT_TESTING, 0, none)
        .invoke(1, UNIT_TESTING, 1, none)
        .invoke(1, UNIT_TESTING, 2, none)
        .invoke(1, UNIT_TESTING, 3, none)
        .invoke(1, UNIT_TESTING, 4, uints(&[250, 10]))
        .invoke(1, UNIT_TESTING, 7, |w| simple_struct(w, &c(0), 3))
        .invoke(1, UNIT_TESTING, 8, |w| {
            w.start_struct(&c(0))?;
            w.u8(&c(0), 1)?;
            w.bool(&c(1), false)?;
            simple_struct(w, &c(2), 2)?;
            w.end_container()?;
            Ok(())
        })
        .invoke(1, UNIT_TESTING, 9, |w| {
            w.start_array(&c(0))?;
            simple_struct(w, &A, 1)?;
            simple_struct(w, &A, 2)?;
            w.end_container()?;
            Ok(())
        })
        .invoke(1, UNIT_TESTING, 10, |w| u8_list(w, &[1, 2, 3]))
        .invoke(1, UNIT_TESTING, 11, |w| nested_struct_list(w, &c(0)))
        .invoke(1, UNIT_TESTING, 12, |w| {
            w.start_array(&c(0))?;
            nested_struct_list(w, &A)?;
            w.end_container()?;
            Ok(())
        })
        .invoke(1, UNIT_TESTING, 13, |w| u8_list(w, &[1, 2, 3, 255]))
        .invoke(1, UNIT_TESTING, 14, uints(&[0xfff1, 1]))
        .invoke(1, UNIT_TESTING, 15, |w| Ok(w.null(&c(0))?))
        .invoke(1, UNIT_TESTING, 15, uints(&[5]))
        .invoke(1, UNIT_TESTING, 17, |w| simple_struct(w, &c(0), 4))
        .invoke_timed(1, UNIT_TESTING, 18, none)
        .invoke(1, UNIT_TESTING, 18, none)
        .invoke(1, UNIT_TESTING, 19, none)
        .invoke(1, UNIT_TESTING, 20, |w| {
            uints_from(w, 0, &[1, 2])?;
            Ok(w.bool(&c(2), true)?)
        })
        .invoke(1, UNIT_TESTING, 21, uints(&[1]))
        .invoke(1, UNIT_TESTING, 22, uints(&[0, 300, b'a' as u64]))
        .invoke(1, UNIT_TESTING, 23, uints(&[0, 10, b'b' as u64]))
        .invoke(1, UNIT_TESTING, 24, |w| Ok(w.str(&c(0), b"echo")?))
        .invoke(1, UNIT_TESTING, 25, |w| {
            global_struct(w, &c(0))?;
            Ok(w.u8(&c(1), 1)?)
        })
        .invoke(1, UNIT_TESTING, 0xfff2_00aa, uints(&[1]))
        .invoke_timed(1, UNIT_TESTING, 26, none)
        .read(&[], &[(Some(1), Some(UNIT_TESTING), None)]);
    seeds.push(("unit-testing-invoke", r.seed));

    // Thermostat and Fan Control, and On/Off on the same endpoint
    let mut r = Requests::new();
    r.invoke(2, ON_OFF, 1, none)
        .invoke(2, THERMOSTAT, 0, |w| {
            w.u8(&c(0), 0)?;
            Ok(w.i8(&c(1), 10)?)
        })
        .invoke(2, THERMOSTAT, 0, |w| {
            w.u8(&c(0), 2)?;
            Ok(w.i8(&c(1), -20)?)
        })
        .write(2, THERMOSTAT, 18, |w, t| Ok(w.i16(t, 2100)?))
        .write(2, THERMOSTAT, 21, |w, t| Ok(w.i16(t, 700)?))
        .write(2, THERMOSTAT, 22, |w, t| Ok(w.i16(t, 3000)?))
        .write(2, THERMOSTAT, 27, |w, t| Ok(w.u8(t, 2)?))
        .write(2, THERMOSTAT, 28, |w, t| Ok(w.u8(t, 4)?))
        .write(2, FAN, 0, |w, t| Ok(w.u8(t, 3)?))
        .write(2, FAN, 2, |w, t| Ok(w.u8(t, 50)?))
        .write(2, FAN, 2, |w, t| Ok(w.null(t)?))
        .write(2, FAN, 5, |w, t| Ok(w.u8(t, 3)?))
        .write(2, FAN, 8, |w, t| Ok(w.u8(t, 1)?))
        .write(2, FAN, 10, |w, t| Ok(w.u8(t, 1)?))
        .write(2, FAN, 11, |w, t| Ok(w.u8(t, 1)?))
        .invoke(2, FAN, 0, |w| {
            w.u8(&c(0), 0)?;
            w.bool(&c(1), true)?;
            Ok(w.bool(&c(2), true)?)
        })
        .invoke(2, FAN, 0, uints(&[1]))
        .write(2, FAN, 0, |w, t| Ok(w.u8(t, 0)?))
        .invoke(2, ON_OFF, 0, none);
    seeds.push(("thermostat-fan", r.seed));

    // Time Synchronization
    let mut r = Requests::new();
    r.invoke(0, TIME_SYNC, 0, |w| {
        w.u64(&c(0), 0x0002_d8a0_0000_0000)?;
        w.u8(&c(1), 4)?;
        Ok(w.u8(&c(2), 2)?)
    })
    .invoke(0, TIME_SYNC, 1, |w| {
        w.start_struct(&c(0))?;
        w.u64(&c(0), 0x1234)?;
        w.u16(&c(1), 0)?;
        w.end_container()?;
        Ok(())
    })
    .invoke(0, TIME_SYNC, 2, |w| {
        w.start_array(&c(0))?;
        w.start_struct(&A)?;
        w.i32(&c(0), 7200)?;
        w.u64(&c(1), 0)?;
        w.utf8(&c(2), "Europe/Sofia")?;
        w.end_container()?;
        w.start_struct(&A)?;
        w.i32(&c(0), 10800)?;
        w.u64(&c(1), 1 << 40)?;
        w.end_container()?;
        w.end_container()?;
        Ok(())
    })
    .invoke(0, TIME_SYNC, 4, |w| {
        w.start_array(&c(0))?;
        w.start_struct(&A)?;
        w.i32(&c(0), 3600)?;
        w.u64(&c(1), 0)?;
        w.null(&c(2))?;
        w.end_container()?;
        w.end_container()?;
        Ok(())
    })
    .invoke(0, TIME_SYNC, 1, |w| Ok(w.null(&c(0))?))
    .wait(100)
    .read(&[(Some(0), Some(TIME_SYNC), None)], &[]);
    seeds.push(("time-sync", r.seed));

    // OTA Provider and OTA Requestor
    let mut r = Requests::new();
    r.invoke(0, OTA_PROVIDER, 0, |w| {
        w.u16(&c(0), 0xfff1)?;
        w.u16(&c(1), 0x8000)?;
        w.u32(&c(2), 1)?;
        w.start_array(&c(3))?;
        w.u8(&A, 0)?;
        w.u8(&A, 2)?;
        w.end_container()?;
        w.u16(&c(4), 1)?;
        w.utf8(&c(5), "BG")?;
        w.bool(&c(6), true)?;
        Ok(w.str(&c(7), b"metadata")?)
    })
    .invoke(0, OTA_PROVIDER, 2, |w| {
        w.str(&c(0), &[0x10; 8])?;
        Ok(w.u32(&c(1), 2)?)
    })
    .invoke(0, OTA_PROVIDER, 4, |w| {
        w.str(&c(0), &[0x10; 8])?;
        Ok(w.u32(&c(1), 2)?)
    })
    .write(0, OTA_REQUESTOR, 0, |w, t| {
        w.start_array(t)?;
        w.start_struct(&A)?;
        w.u64(&c(1), 0x1234)?;
        w.u16(&c(2), 0)?;
        w.u8(&c(254), 1)?;
        w.end_container()?;
        w.end_container()?;
        Ok(())
    })
    .invoke(0, OTA_REQUESTOR, 0, |w| {
        w.u64(&c(0), 0x1234)?;
        w.u16(&c(1), 0xfff1)?;
        w.u8(&c(2), 1)?;
        w.str(&c(3), b"metadata")?;
        Ok(w.u16(&c(4), 0)?)
    })
    .read(&[(Some(0), Some(OTA_REQUESTOR), None)], &[]);
    seeds.push(("ota", r.seed));

    // ICD Management: a client registered twice, then the other commands
    let mut r = Requests::new();
    r.invoke(0, ICD, 0, |w| {
        w.u64(&c(0), crate::PEER_ID)?;
        w.u64(&c(1), crate::PEER_ID)?;
        w.str(&c(2), &[0x11; 16])?;
        Ok(w.u8(&c(4), 0)?)
    })
    .invoke(0, ICD, 0, |w| {
        w.u64(&c(0), crate::PEER_ID)?;
        w.u64(&c(1), 0x1234)?;
        w.str(&c(2), &[0x12; 16])?;
        w.str(&c(3), &[0x11; 16])?;
        Ok(w.u8(&c(4), 1)?)
    })
    .invoke(0, ICD, 3, uints(&[30000]))
    .wait(350)
    .read(&[(Some(0), Some(ICD), None)], &[])
    .invoke(0, ICD, 2, |w| {
        w.u64(&c(0), crate::PEER_ID)?;
        Ok(w.str(&c(1), &[0x12; 16])?)
    });
    seeds.push(("icd", r.seed));

    // Diagnostic Logs: logs in the response, then a log over BDX, which the node sends
    // as the BDX sender, with the requestor driving the transfer
    let mut r = Requests::new();
    r.invoke(0, DIAG_LOGS, 0, uints(&[1, 0]))
        .invoke(0, DIAG_LOGS, 0, uints(&[0, 0]))
        .invoke(0, DIAG_LOGS, 0, uints(&[2, 0]));
    let exch = r.next_exch();
    let request = invoke1(false, 0, DIAG_LOGS, 0, |w| {
        uints_from(w, 0, &[0, 1])?;
        Ok(w.utf8(&c(2), "log.txt")?)
    });
    r.seed
        .case(IM, INVOKE, exch, I | REL, &request)
        .case(
            BDX,
            SEND_ACCEPT,
            0,
            NODE_EXCH | REL | ACK,
            &[0x20, 0x00, 0x04],
        )
        .ack(exch)
        .case(
            BDX,
            BLOCK_QUERY,
            0,
            NODE_EXCH | REL | ACK,
            &0u32.to_le_bytes(),
        )
        .case(
            BDX,
            BLOCK_QUERY,
            0,
            NODE_EXCH | REL | ACK,
            &1u32.to_le_bytes(),
        )
        .case(
            BDX,
            BLOCK_QUERY,
            0,
            NODE_EXCH | REL | ACK,
            &2u32.to_le_bytes(),
        )
        .case(
            BDX,
            BLOCK_ACK_EOF,
            0,
            NODE_EXCH | REL | ACK,
            &2u32.to_le_bytes(),
        );
    let exch = r.next_exch();
    r.seed.case(IM, INVOKE, exch, I | REL, &request).wait(600);
    seeds.push(("diag-logs", r.seed));

    // Camera AV Stream Management: streams allocated, changed and removed, and the
    // writable attributes
    let mut r = Requests::new();
    r.invoke(3, CAM_AV, 3, |w| {
        uints_from(w, 0, &[3, 0, 1, 30])?;
        resolution(w, 4, 640, 360)?;
        resolution(w, 5, 1920, 1080)?;
        uints_from(w, 6, &[500_000, 4_000_000, 2000])
    })
    .invoke(3, CAM_AV, 5, |w| {
        w.u16(&c(0), 1)?;
        Ok(w.bool(&c(1), true)?)
    })
    .invoke(3, CAM_AV, 11, |w| {
        w.start_array(&c(0))?;
        w.u8(&A, 3)?;
        w.end_container()?;
        Ok(())
    })
    .read(&[(Some(3), Some(CAM_AV), None)], &[])
    .invoke(3, CAM_AV, 6, uints(&[1]))
    .invoke(3, CAM_AV, 11, |w| {
        w.start_array(&c(0))?;
        w.u8(&A, 3)?;
        w.end_container()?;
        Ok(())
    })
    .invoke(3, CAM_AV, 6, uints(&[0]));
    seeds.push(("camera-streams", r.seed));

    // Camera AV Settings User Level Management
    let mut r = Requests::new();
    r.invoke(3, CAM_SETTINGS, 5, |w| {
        w.u16(&c(0), 0)?;
        viewport(w, &c(1), 0, 0, 1280, 720)
    })
    .invoke(3, CAM_SETTINGS, 6, |w| {
        w.u16(&c(0), 0)?;
        w.i16(&c(1), 100)?;
        w.i16(&c(2), -50)?;
        Ok(w.i8(&c(3), 10)?)
    })
    .invoke(3, CAM_SETTINGS, 6, |w| {
        w.u16(&c(0), 0)?;
        Ok(w.i8(&c(3), -100)?)
    });
    seeds.push(("camera-settings", r.seed));

    // Zone Management: zones created, changed and removed, with a trigger
    let mut r = Requests::new();
    r.invoke(3, ZONES, 0, |w| {
        zone(w, &c(0), "door", &[(0, 0), (100, 0), (100, 100), (0, 100)])
    })
    .invoke(3, ZONES, 0, |w| {
        zone(
            w,
            &c(0),
            "bow tie",
            &[(0, 0), (100, 100), (100, 0), (0, 100)],
        )
    })
    .invoke(3, ZONES, 2, |w| {
        w.u16(&c(0), 1)?;
        zone(w, &c(1), "window", &[(10, 10), (1919, 10), (1000, 1079)])
    })
    .invoke(3, ZONES, 0, |w| {
        zone(w, &c(0), "copy", &[(10, 10), (1919, 10), (1000, 1079)])
    })
    .invoke(3, ZONES, 4, |w| {
        w.start_struct(&c(0))?;
        uints_from(w, 0, &[1, 10, 5, 60, 5, 3])?;
        w.end_container()?;
        Ok(())
    })
    .read(&[(Some(3), Some(ZONES), None)], &[])
    .invoke(3, ZONES, 3, uints(&[1]))
    .invoke(3, ZONES, 5, uints(&[1]))
    .invoke(3, ZONES, 3, uints(&[1]));
    seeds.push(("camera-zones", r.seed));

    // Push AV Stream Transport, whose commands need large messages, so over TCP: a
    // transport allocated, changed, triggered and removed
    let mut r = Requests::tcp();
    r.invoke(3, PUSH_AV, 0, |w| transport_options(w, &c(0), 0))
        .invoke(3, PUSH_AV, 6, |w| Ok(w.null(&c(0))?))
        .invoke(3, PUSH_AV, 4, |w| {
            w.null(&c(0))?;
            Ok(w.u8(&c(1), 0)?)
        })
        .invoke(3, PUSH_AV, 5, |w| {
            uints_from(w, 0, &[1, 0])?;
            w.start_struct(&c(2))?;
            uints_from(w, 0, &[10, 5, 60, 5])?;
            w.end_container()?;
            Ok(w.str(&c(3), b"user")?)
        })
        .invoke(3, PUSH_AV, 3, |w| {
            w.u16(&c(0), 1)?;
            transport_options(w, &c(1), 1)
        })
        .read(&[(Some(3), Some(PUSH_AV), None)], &[])
        .invoke(3, PUSH_AV, 2, uints(&[1]));
    seeds.push(("camera-push", r.seed));

    // WebRTC Transport Provider, whose commands need large messages, so over TCP: a
    // session solicited, then one offered, with an answer, ICE candidates and its end
    let mut r = Requests::tcp();
    r.invoke(3, WEBRTC, 0, |w| {
        uints_from(w, 0, &[3, 1])?;
        w.null(&c(2))?;
        w.null(&c(3))?;
        Ok(())
    })
    .invoke(3, WEBRTC, 2, |w| {
        w.null(&c(0))?;
        w.utf8(&c(1), SDP)?;
        uints_from(w, 2, &[3, 1, 0, 0])?;
        w.start_array(&c(6))?;
        w.start_struct(&A)?;
        w.start_array(&c(0))?;
        w.utf8(&A, "stun:stun.example.com:3478")?;
        w.end_container()?;
        w.end_container()?;
        w.end_container()?;
        Ok(w.utf8(&c(7), "all")?)
    })
    .invoke(3, WEBRTC, 4, |w| {
        w.u16(&c(0), 1)?;
        Ok(w.utf8(&c(1), SDP)?)
    })
    .invoke(3, WEBRTC, 5, |w| {
        w.u16(&c(0), 1)?;
        w.start_array(&c(1))?;
        w.start_struct(&A)?;
        w.utf8(
            &c(0),
            "candidate:1 1 UDP 2122252543 192.0.2.1 54400 typ host",
        )?;
        w.utf8(&c(1), "0")?;
        w.u16(&c(2), 0)?;
        w.end_container()?;
        w.end_container()?;
        Ok(())
    })
    .read(&[(Some(3), Some(WEBRTC), None)], &[])
    .invoke(3, WEBRTC, 6, uints(&[1, 2]));
    seeds.push(("camera-webrtc", r.seed));

    seeds
}

/// A seed of requests on the CASE session, or on the CASE session over TCP, each on a new
/// exchange
struct Requests {
    seed: Seed,
    exch: u8,
    tcp: bool,
}

impl Requests {
    fn new() -> Self {
        Self {
            seed: Seed::default(),
            exch: 0,
            tcp: false,
        }
    }

    /// Requests on the CASE session over TCP, without MRP
    fn tcp() -> Self {
        Self {
            tcp: true,
            ..Self::new()
        }
    }

    fn next_exch(&mut self) -> u8 {
        self.exch = self.exch.wrapping_add(1);
        self.exch
    }

    /// An IM message; over TCP, without the flags of MRP
    fn send(&mut self, opcode: u8, exch: u8, flags: u8, payload: &[u8]) {
        if self.tcp {
            self.seed
                .msg(4, IM, opcode, exch, flags & !(REL | ACK), payload);
        } else {
            self.seed.case(IM, opcode, exch, flags, payload);
        }
    }

    /// An acknowledgement of the latest message of the node on the exchange, if not over TCP
    fn ack(&mut self, exch: u8) {
        if !self.tcp {
            self.seed.ack(exch);
        }
    }

    /// Time that passes, in tenths of a second
    fn wait(&mut self, tenths: u16) -> &mut Self {
        self.seed.wait(tenths);
        self
    }

    /// A request on a new exchange, and the acknowledgement of the response
    fn request(&mut self, opcode: u8, payload: &[u8]) -> &mut Self {
        let exch = self.next_exch();
        self.send(opcode, exch, I | REL, payload);
        self.ack(exch);
        self
    }

    /// A timed request: `TimedRequest`, then the request on the same exchange
    fn timed(&mut self, opcode: u8, payload: &[u8]) -> &mut Self {
        let exch = self.next_exch();
        self.send(TIMED, exch, I | REL, &timed_req(5000));
        self.send(opcode, exch, I | REL | ACK, payload);
        self.ack(exch);
        self
    }

    /// One command
    fn invoke(
        &mut self,
        ep: u16,
        cl: u32,
        id: u32,
        fields: impl FnOnce(&mut WriteBuf) -> R,
    ) -> &mut Self {
        self.request(INVOKE, &invoke1(false, ep, cl, id, fields))
    }

    /// One command, in a timed invoke
    fn invoke_timed(
        &mut self,
        ep: u16,
        cl: u32,
        id: u32,
        fields: impl FnOnce(&mut WriteBuf) -> R,
    ) -> &mut Self {
        self.timed(INVOKE, &invoke1(true, ep, cl, id, fields))
    }

    /// A write of one attribute
    fn write(
        &mut self,
        ep: u16,
        cl: u32,
        at: u32,
        data: impl FnOnce(&mut WriteBuf, &TLVTag) -> R,
    ) -> &mut Self {
        self.request(
            WRITE,
            &write_req(false, |w| attr_data(w, ep, cl, at, false, data)),
        )
    }

    /// A write of one attribute, in a timed write
    fn write_timed(
        &mut self,
        ep: u16,
        cl: u32,
        at: u32,
        data: impl FnOnce(&mut WriteBuf, &TLVTag) -> R,
    ) -> &mut Self {
        self.timed(
            WRITE,
            &write_req(true, |w| attr_data(w, ep, cl, at, false, data)),
        )
    }

    /// A write of an item added to a list attribute
    fn append(
        &mut self,
        ep: u16,
        cl: u32,
        at: u32,
        data: impl FnOnce(&mut WriteBuf, &TLVTag) -> R,
    ) -> &mut Self {
        self.request(
            WRITE,
            &write_req(false, |w| attr_data(w, ep, cl, at, true, data)),
        )
    }

    /// A read, with a status response to each chunk of the report but the last
    fn read(&mut self, attrs: &[Path3], events: &[Path3]) -> &mut Self {
        let exch = self.next_exch();
        self.send(READ, exch, I | REL, &read_req(attrs, events, None, true));
        self.answer_chunks(exch);
        self.ack(exch);
        self
    }

    /// A subscription, with a status response to each chunk of the first report
    fn subscribe(&mut self, attrs: &[Path3], events: &[Path3]) -> &mut Self {
        let exch = self.next_exch();
        self.send(SUBSCRIBE, exch, I | REL, &subscribe_req(attrs, events, 60));
        self.answer_chunks(exch);
        self.ack(exch);
        self
    }

    /// A status response to each report of the node on an exchange that it opened
    fn reports(&mut self) -> &mut Self {
        while last_message(&self.seed) == Some((IM as u16, 0x05)) {
            self.send(STATUS_RESP, 0, NODE_EXCH | REL | ACK, &status_ok());
        }
        self
    }

    /// Adds a status response on the exchange for as long as the node answers it with
    /// another IM message
    fn answer_chunks(&mut self, exch: u8) {
        loop {
            let before = Seed(self.seed.0.clone());
            self.send(STATUS_RESP, exch, I | REL | ACK, &status_ok());

            if im_messages(&self.seed) == im_messages(&before) {
                self.seed = before;
                break;
            }
        }
    }
}

/// How many IM messages the node sends for a seed
fn im_messages(seed: &Seed) -> usize {
    let mut count = 0;
    all_clusters::run(&seed.0, |proto, _, _| {
        if proto == IM as u16 {
            count += 1;
        }
    });

    count
}

/// The protocol ID and the opcode of the latest message that the node sends for a seed
fn last_message(seed: &Seed) -> Option<(u16, u8)> {
    let mut last = None;
    all_clusters::run(&seed.0, |proto, opcode, _| last = Some((proto, opcode)));

    last
}

const SDP: &str = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=rtpmap:96 H264/90000\r\n";

/// No fields
fn none(_: &mut WriteBuf) -> R {
    Ok(())
}

/// Unsigned integer fields, tagged from 0
fn uints(values: &[u64]) -> impl FnOnce(&mut WriteBuf) -> R + '_ {
    move |w| uints_from(w, 0, values)
}

/// Unsigned integer fields, tagged from `tag`, each in the shortest encoding, which the
/// node reads as an integer of any width
fn uints_from(w: &mut WriteBuf, tag: u8, values: &[u64]) -> R {
    for (i, &value) in values.iter().enumerate() {
        let tag = &c(tag + i as u8);
        if let Ok(value) = u8::try_from(value) {
            w.u8(tag, value)?;
        } else if let Ok(value) = u16::try_from(value) {
            w.u16(tag, value)?;
        } else if let Ok(value) = u32::try_from(value) {
            w.u32(tag, value)?;
        } else {
            w.u64(tag, value)?;
        }
    }

    Ok(())
}

fn u8_list(w: &mut WriteBuf, values: &[u8]) -> R {
    w.start_array(&c(0))?;
    for &value in values {
        w.u8(&A, value)?;
    }
    w.end_container()?;

    Ok(())
}

fn endpoints(w: &mut WriteBuf, tag: u8, endpoints: &[u16]) -> R {
    w.start_array(&c(tag))?;
    for &ep in endpoints {
        w.u16(&A, ep)?;
    }
    w.end_container()?;

    Ok(())
}

/// The fields of `AddGroup` and `AddGroupIfIdentifying`
fn group(w: &mut WriteBuf, id: u16, name: &str) -> R {
    w.u16(&c(0), id)?;
    w.utf8(&c(1), name)?;

    Ok(())
}

/// The fields of `KeySetWrite`: key set 1 with three keys
fn key_set(w: &mut WriteBuf) -> R {
    w.start_struct(&c(0))?;
    w.u16(&c(0), 1)?;
    w.u8(&c(1), 0)?;
    w.str(&c(2), &[0xd0; 16])?;
    w.u64(&c(3), 1)?;
    w.str(&c(4), &[0xd1; 16])?;
    w.u64(&c(5), 2)?;
    w.str(&c(6), &[0xd2; 16])?;
    w.u64(&c(7), 3)?;
    w.end_container()?;

    Ok(())
}

/// The fields of `AddScene`: a scene with values for On/Off, Level Control and Color
/// Control
fn add_scene(w: &mut WriteBuf, group: u16, scene: u8) -> R {
    // The attribute ID, the tag of the value (by its type), and the value
    type Value = (u32, u8, u64);

    const SETS: &[(u32, &[Value])] = &[
        (ON_OFF, &[(0, 1, 1)]),
        (LEVEL, &[(0, 1, 50)]),
        (
            COLOR,
            &[
                (3, 3, 30000),
                (4, 3, 20000),
                (0x4001, 3, 30000),
                (1, 1, 100),
                (0x4002, 1, 1),
                (0x4003, 1, 0),
                (0x4004, 3, 10),
                (7, 3, 250),
                (0x4000, 1, 3),
            ],
        ),
    ];

    w.u16(&c(0), group)?;
    w.u8(&c(1), scene)?;
    w.u32(&c(2), 0)?;
    w.utf8(&c(3), "Evening")?;
    w.start_array(&c(4))?;
    for (cluster, values) in SETS {
        w.start_struct(&A)?;
        w.u32(&c(0), *cluster)?;
        w.start_array(&c(1))?;
        for &(attr, tag, value) in *values {
            w.start_struct(&A)?;
            w.u32(&c(0), attr)?;
            uints_from(w, tag, &[value])?;
            w.end_container()?;
        }
        w.end_container()?;
        w.end_container()?;
    }
    w.end_container()?;

    Ok(())
}

/// A `LabelStruct` of User Label
fn label(w: &mut WriteBuf, tag: &TLVTag, label: &str, value: &str) -> R {
    w.start_struct(tag)?;
    w.utf8(&c(0), label)?;
    w.utf8(&c(1), value)?;
    w.end_container()?;

    Ok(())
}

/// A `SimpleStruct` of Unit Testing
fn simple_struct(w: &mut WriteBuf, tag: &TLVTag, a: u8) -> R {
    w.start_struct(tag)?;
    w.u8(&c(0), a)?;
    w.bool(&c(1), true)?;
    w.u8(&c(2), 1)?;
    w.str(&c(3), b"octets")?;
    w.utf8(&c(4), "chars")?;
    w.u8(&c(5), 1)?;
    w.f32(&c(6), 1.5)?;
    w.f64(&c(7), 2.5)?;
    w.end_container()?;

    Ok(())
}

/// A `NestedStructList` of Unit Testing
fn nested_struct_list(w: &mut WriteBuf, tag: &TLVTag) -> R {
    w.start_struct(tag)?;
    w.u8(&c(0), 1)?;
    w.bool(&c(1), true)?;
    simple_struct(w, &c(2), 1)?;
    w.start_array(&c(3))?;
    simple_struct(w, &A, 2)?;
    w.end_container()?;
    w.start_array(&c(4))?;
    w.u32(&A, 1)?;
    w.u32(&A, u32::MAX)?;
    w.end_container()?;
    w.start_array(&c(5))?;
    w.str(&A, b"f")?;
    w.end_container()?;
    w.start_array(&c(6))?;
    w.u8(&A, 6)?;
    w.end_container()?;
    w.end_container()?;

    Ok(())
}

/// The fields of a `NullablesAndOptionalsStruct` of Unit Testing, which are also the fields
/// of `TestComplexNullableOptionalRequest`
fn nullables_and_optionals(w: &mut WriteBuf) -> R {
    w.null(&c(0))?;
    w.u16(&c(1), 1)?;
    w.null(&c(2))?;
    w.null(&c(3))?;
    w.utf8(&c(4), "optional")?;
    w.null(&c(5))?;
    w.null(&c(6))?;
    simple_struct(w, &c(7), 7)?;
    w.null(&c(8))?;
    w.null(&c(9))?;
    w.start_array(&c(10))?;
    w.u8(&A, 1)?;
    w.end_container()?;
    w.null(&c(11))?;

    Ok(())
}

/// A `TestFabricScoped` of Unit Testing
fn fabric_scoped(w: &mut WriteBuf, tag: &TLVTag) -> R {
    w.start_struct(tag)?;
    w.u8(&c(1), 1)?;
    w.u8(&c(2), 2)?;
    w.null(&c(3))?;
    w.utf8(&c(5), "fabric")?;
    simple_struct(w, &c(6), 6)?;
    w.start_array(&c(7))?;
    w.u8(&A, 7)?;
    w.end_container()?;
    w.u8(&c(254), 1)?;
    w.end_container()?;

    Ok(())
}

/// A `TestGlobalStruct` of Unit Testing
fn global_struct(w: &mut WriteBuf, tag: &TLVTag) -> R {
    w.start_struct(tag)?;
    w.utf8(&c(0), "global")?;
    w.u32(&c(1), 1)?;
    w.u8(&c(2), 0)?;
    w.end_container()?;

    Ok(())
}

/// A `VideoResolutionStruct`
fn resolution(w: &mut WriteBuf, tag: u8, width: u16, height: u16) -> R {
    w.start_struct(&c(tag))?;
    w.u16(&c(0), width)?;
    w.u16(&c(1), height)?;
    w.end_container()?;

    Ok(())
}

/// A `ViewportStruct`
fn viewport(w: &mut WriteBuf, tag: &TLVTag, x1: u16, y1: u16, x2: u16, y2: u16) -> R {
    w.start_struct(tag)?;
    uints_from(w, 0, &[x1.into(), y1.into(), x2.into(), y2.into()])?;
    w.end_container()?;

    Ok(())
}

/// A `TwoDCartesianZoneStruct` for motion
fn zone(w: &mut WriteBuf, tag: &TLVTag, name: &str, vertices: &[(u16, u16)]) -> R {
    w.start_struct(tag)?;
    w.utf8(&c(0), name)?;
    w.u8(&c(1), 0)?;
    w.start_array(&c(2))?;
    for &(x, y) in vertices {
        w.start_struct(&A)?;
        w.u16(&c(0), x)?;
        w.u16(&c(1), y)?;
        w.end_container()?;
    }
    w.end_container()?;
    w.utf8(&c(3), "#FF0000")?;
    w.end_container()?;

    Ok(())
}

/// A `TransportOptionsStruct` of Push AV Stream Transport, triggered by a command (0) or
/// by motion (1)
fn transport_options(w: &mut WriteBuf, tag: &TLVTag, trigger: u8) -> R {
    w.start_struct(tag)?;
    w.u8(&c(0), 3)?;
    w.u16(&c(1), 0)?;
    w.u16(&c(2), 0)?;
    w.u16(&c(3), 1)?;
    w.utf8(&c(4), "https://192.0.2.1/ingest/")?;
    w.start_struct(&c(5))?;
    w.u8(&c(0), trigger)?;
    if trigger == 1 {
        w.start_array(&c(1))?;
        w.start_struct(&A)?;
        w.u16(&c(0), 1)?;
        w.u8(&c(1), 5)?;
        w.end_container()?;
        w.end_container()?;
        w.start_struct(&c(3))?;
        uints_from(w, 0, &[10, 5, 60, 5])?;
        w.end_container()?;
        w.u16(&c(4), 1000)?;
    }
    w.end_container()?;
    w.u8(&c(6), 0)?;
    w.start_struct(&c(7))?;
    w.u8(&c(0), 0)?;
    w.start_struct(&c(1))?;
    uints_from(w, 0, &[0, 4000, 1000, 1])?;
    w.utf8(&c(4), "main")?;
    w.end_container()?;
    w.end_container()?;
    w.end_container()?;

    Ok(())
}
