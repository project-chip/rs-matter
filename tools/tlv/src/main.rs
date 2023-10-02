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
use matter_rs::cert;
use matter_rs::tlv;
use simple_logger::SimpleLogger;
use std::process;

fn main() {
    SimpleLogger::new()
        .with_level(log::LevelFilter::Trace)
        .with_colors(true)
        .without_timestamps()
        .init()
        .unwrap();

    let m = App::new("tlv")
        .arg(
            Arg::with_name("hex")
                .short("h")
                .long("hex")
                .help("The input is in Hexadecimal (Default)"),
        )
        .arg(
            Arg::with_name("dec")
                .short("d")
                .long("dec")
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

    // Assume hexadecimal by-default
    let base = if m.is_present("hex") {
        16
    } else if m.is_present("dec") {
        10
    } else {
        16
    };

    let list: String = m
        .value_of("tlvs")
        .unwrap()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let list = list.split(',');
    let mut tlv_list: [u8; 1024] = [0; 1024];
    let mut index = 0;
    for byte in list {
        let byte = byte.strip_prefix("0x").unwrap_or(byte);
        if let Ok(b) = u8::from_str_radix(byte, base) {
            tlv_list[index] = b;
            index += 1;
        } else {
            eprintln!("Skipping unknown byte: {}", byte);
        }
        if index >= 1024 {
            eprintln!("Input too long");
            process::exit(1);
        }
    }

    //    println!("Decoding: {:x?}", &tlv_list[..index]);
    if m.is_present("cert") {
        let cert = cert::Cert::new(&tlv_list[..index]).unwrap();
        println!("{}", cert);
    } else if m.is_present("as-asn1") {
        let mut asn1_cert = [0_u8; 1024];
        let cert = cert::Cert::new(&tlv_list[..index]).unwrap();
        let len = cert.as_asn1(&mut asn1_cert).unwrap();
        println!("{:02x?}", &asn1_cert[..len]);
    } else {
        tlv::print_tlv_list(&tlv_list[..index]);
    }
}
