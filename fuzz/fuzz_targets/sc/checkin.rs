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

//! The Check-In message, which an ICD client receives.
//!
//! Arbitrary bytes are almost never a message that decrypts, so the input is also
//! used as the counter and the application data of a message, which is generated
//! and then parsed back.

use rs_matter_crypto::{test_only_crypto, CanonAeadKeyRef};
use rs_matter_sc::checkin::CheckIn;

const KEY: [u8; 16] = [0x5a; 16];

pub fn fuzz(data: &[u8]) {
    let checkin = CheckIn::new(CanonAeadKeyRef::new(&KEY));

    let mut msg = data.to_vec();
    let _ = checkin.parse(test_only_crypto(), &mut msg);

    if let [c0, c1, c2, c3, app_data @ ..] = data {
        let counter = u32::from_le_bytes([*c0, *c1, *c2, *c3]);

        let mut msg = vec![0; CheckIn::payload_len(app_data.len())];
        let len = checkin
            .generate(test_only_crypto(), counter, app_data, &mut msg)
            .unwrap()
            .len();

        let payload = checkin.parse(test_only_crypto(), &mut msg[..len]).unwrap();
        assert_eq!(payload.counter, counter);
        assert_eq!(payload.app_data, app_data);
    }
}
