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

//! The seeds of the `tcp` target, in the input format in `fuzz_targets/tcp.rs`.

/// The steps of an input of the `tcp` target
#[derive(Default)]
pub struct Steps(pub Vec<u8>);

impl Steps {
    /// A peer connects from port `port`
    fn accept(&mut self, port: u8) -> &mut Self {
        self.0.extend_from_slice(&[0, port]);
        self
    }

    /// A peer sends bytes on connection `conn`
    fn data(&mut self, conn: u8, bytes: &[u8]) -> &mut Self {
        self.0
            .extend_from_slice(&[1, conn, u8::try_from(bytes.len()).unwrap()]);
        self.0.extend_from_slice(bytes);
        self
    }

    /// A peer sends a frame of `len` bytes on connection `conn`
    fn frame(&mut self, conn: u8, len: u16, fill: u8) -> &mut Self {
        let len = len.to_le_bytes();
        self.0.extend_from_slice(&[2, conn, len[0], len[1], fill]);
        self
    }

    /// A peer closes its side of connection `conn`
    fn eof(&mut self, conn: u8) -> &mut Self {
        self.0.extend_from_slice(&[3, conn]);
        self
    }

    /// A peer resets connection `conn`
    fn reset(&mut self, conn: u8) -> &mut Self {
        self.0.extend_from_slice(&[4, conn]);
        self
    }

    /// A peer reads at most `budget` more bytes on connection `conn`, or all with 255
    fn budget(&mut self, conn: u8, budget: u8) -> &mut Self {
        self.0.extend_from_slice(&[5, conn, budget]);
        self
    }

    /// The node sends a message of `len + 1` bytes to port `port`
    fn send(&mut self, port: u8, len: u8, encrypted: bool) -> &mut Self {
        self.0.extend_from_slice(&[6, port, len, encrypted.into()]);
        self
    }

    /// Time passes, in tenths of a second
    fn wait(&mut self, tenths: u16) -> &mut Self {
        let tenths = tenths.to_le_bytes();
        self.0.extend_from_slice(&[7, tenths[0], tenths[1]]);
        self
    }

    /// The next accept (0), connect (1, 2) or keep-alive setting (3) fails, or a close
    /// never ends (4, with the connection)
    fn fault(&mut self, fault: u8, conn: Option<u8>) -> &mut Self {
        self.0.extend_from_slice(&[8, fault]);
        self.0.extend(conn);
        self
    }
}

pub fn seeds() -> Vec<(&'static str, Steps)> {
    let mut seeds = Vec::new();

    // Frames each way on one connection, among them an empty one
    let mut s = Steps::default();
    s.accept(0)
        .frame(0, 10, 1)
        .frame(0, 0, 0)
        .send(0, 20, true)
        .send(0, 127, false);
    seeds.push(("frames", s));

    // A frame in two pieces, then the end of the connection
    let mut s = Steps::default();
    s.accept(1)
        .data(0, &[5, 0, 0, 0, 1, 2])
        .data(0, &[3, 4, 5])
        .eof(0);
    seeds.push(("split-frame", s));

    // A frame that is too large while a frame of the node is partly written
    let mut s = Steps::default();
    s.accept(2)
        .budget(0, 3)
        .send(2, 9, false)
        .frame(0, 129, 7)
        .budget(0, 255)
        .wait(30);
    seeds.push(("too-large", s));

    // More peers than slots, so that an idle one is evicted for a new one
    let mut s = Steps::default();
    s.accept(0)
        .accept(1)
        .accept(2)
        .frame(0, 4, 0)
        .accept(3)
        .wait(60)
        .send(3, 30, true);
    seeds.push(("eviction", s));

    // A peer that reads slowly, so that the messages wait for room in the queue
    let mut s = Steps::default();
    s.accept(0)
        .budget(0, 3)
        .send(0, 100, true)
        .send(0, 100, true)
        .send(0, 100, true)
        .wait(30)
        .budget(0, 255)
        .wait(10);
    seeds.push(("backpressure", s));

    // Connections that the node opens: one that works, one that fails and one that
    // never ends
    let mut s = Steps::default();
    s.send(1, 40, true)
        .fault(1, None)
        .send(2, 10, false)
        .fault(2, None)
        .send(3, 10, false)
        .wait(60)
        .send(3, 10, false);
    seeds.push(("connect", s));

    // An idle connection whose close never ends, a reset, a failed accept and a failed
    // keep-alive setting
    let mut s = Steps::default();
    s.accept(0)
        .fault(4, Some(0))
        .wait(400)
        .accept(1)
        .reset(1)
        .fault(0, None)
        .accept(2)
        .fault(3, None)
        .accept(3)
        .wait(400);
    seeds.push(("timeouts", s));

    seeds
}
