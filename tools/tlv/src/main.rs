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

use clap::{App, Arg};
use rs_matter::cert;
use rs_matter::tlv;
use simple_logger::SimpleLogger;

use parser::InputBase;

fn main() {
    SimpleLogger::new()
        .with_level(log::LevelFilter::Trace)
        .with_colors(true)
        .without_timestamps()
        .init()
        .unwrap();

    let mut base = InputBase::Hex;

    let m = App::new("tlv")
        .arg(
            Arg::with_name("hex")
                .short("h")
                .long("hex")
                .group("base")
                .help("The input is in Hexadecimal (Default)"),
        )
        .arg(
            Arg::with_name("dec")
                .short("d")
                .long("dec")
                .group("base")
                .help("The input is in Decimal"),
        )
        .arg(
            Arg::with_name("cert")
                .long("cert")
                .help("Decode a Matter-encoded Certificate"),
        )
        .arg(
            Arg::with_name("as-asn1")
                .long("as-asn1")
                .help("Decode a Matter-encoded Certificate and encode as ASN1"),
        )
        .arg(Arg::with_name("tlvs").help("List of TLVs").required(true))
        .get_matches();

    if m.is_present("dec") {
        base = InputBase::Dec;
    }

    let tlv_list = base.parse_list(m.value_of("tlvs").unwrap(), ',');

    //    println!("Decoding: {:x?}", tlv_list.as_slice());

    let tlv = tlv::TLVElement::new(tlv_list.as_slice());

    if m.is_present("cert") {
        let cert = cert::CertRef::new(tlv);
        println!("{cert}");
    } else if m.is_present("as-asn1") {
        let mut asn1_cert = [0_u8; 1024];
        let cert = cert::CertRef::new(tlv);
        let len = cert.as_asn1(&mut asn1_cert).unwrap();
        println!("{:02x?}", &asn1_cert[..len]);
    } else {
        println!("TLV {tlv}");
    }
}
