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

//! `xtask ota-image`: create, inspect and unpack Matter OTA image files.

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};

use clap::{Args, Subcommand};

use log::{info, warn};

use rs_matter::crypto::{default_crypto, Crypto, CryptoSensitive, Digest, HASH_LEN};
use rs_matter::dm::devices::test::DAC_PRIVKEY;
use rs_matter::error::ErrorCode;
use rs_matter::ota::{OtaImageHeader, OTA_IMAGE_DIGEST_SHA256};
use rs_matter::tlv::Octets;

/// Room for the prefix and the largest header the field length limits allow.
const MAX_HEADER_LEN: usize = 1024;

/// How much of a payload to read at a time.
const CHUNK_LEN: usize = 64 * 1024;

/// Actions of the `ota-image` command
#[derive(Subcommand, Debug, Clone)]
pub enum Action {
    /// Create an OTA image from one or more payload files, concatenated in order
    Create(CreateArgs),
    /// Show the header of an OTA image, and check its sizes and digest
    Show {
        /// The OTA image file
        image: PathBuf,
    },
    /// Extract the payload of an OTA image, after checking its size and digest
    Extract {
        /// The OTA image file
        image: PathBuf,
        /// Where to write the payload
        #[arg(long, short = 'o')]
        out: PathBuf,
    },
    /// Copy an OTA image with some header fields changed
    ChangeHeader(ChangeHeaderArgs),
}

/// Arguments of `ota-image create`
#[derive(Args, Debug, Clone)]
pub struct CreateArgs {
    /// Vendor ID the image is for, decimal or `0x`-prefixed hex; 0 for any vendor
    #[arg(long, value_parser = parse_num::<u16>)]
    vid: u16,
    /// Product ID the image is for, decimal or `0x`-prefixed hex; 0 for any product
    #[arg(long, value_parser = parse_num::<u16>)]
    pid: u16,
    /// Software version of the payload, as the firmware reports it; decimal or
    /// `0x`-prefixed hex
    #[arg(long, value_parser = parse_num::<u32>)]
    sw_version: u32,
    /// Displayable software version (1 to 64 characters), as the firmware
    /// reports it
    #[arg(long)]
    sw_version_str: String,
    #[command(flatten)]
    applicability: Applicability,
    /// The OTA image file to write
    #[arg(long, short = 'o')]
    out: PathBuf,
    /// The firmware payload: one file, or several to concatenate in order
    #[arg(required = true)]
    payload: Vec<PathBuf>,
}

/// Arguments of `ota-image change-header`
#[derive(Args, Debug, Clone)]
pub struct ChangeHeaderArgs {
    /// New Vendor ID, decimal or `0x`-prefixed hex
    #[arg(long, value_parser = parse_num::<u16>)]
    vid: Option<u16>,
    /// New Product ID, decimal or `0x`-prefixed hex
    #[arg(long, value_parser = parse_num::<u16>)]
    pid: Option<u16>,
    /// New software version, decimal or `0x`-prefixed hex
    #[arg(long, value_parser = parse_num::<u32>)]
    sw_version: Option<u32>,
    /// New displayable software version
    #[arg(long)]
    sw_version_str: Option<String>,
    #[command(flatten)]
    applicability: Applicability,
    /// The OTA image file to copy
    image: PathBuf,
    /// The OTA image file to write
    #[arg(long, short = 'o')]
    out: PathBuf,
}

/// The optional header fields, shared by `create` and `change-header`
#[derive(Args, Debug, Clone)]
pub struct Applicability {
    /// Lowest software version the image can be applied on top of
    #[arg(long, value_parser = parse_num::<u32>)]
    min_sw_version: Option<u32>,
    /// Highest software version the image can be applied on top of
    #[arg(long, value_parser = parse_num::<u32>)]
    max_sw_version: Option<u32>,
    /// Link to the release notes (`https`, 1 to 256 characters)
    #[arg(long)]
    release_notes_url: Option<String>,
}

/// Run an `ota-image` action
pub fn run(action: &Action) -> anyhow::Result<()> {
    match action {
        Action::Create(args) => create(args),
        Action::Show { image } => show(image),
        Action::Extract { image, out } => extract(image, out),
        Action::ChangeHeader(args) => change_header(args),
    }
}

fn create(args: &CreateArgs) -> anyhow::Result<()> {
    let crypto = crypto();
    let mut hasher = hasher(&crypto)?;
    let mut payload_size = 0;

    for path in &args.payload {
        payload_size += copy_payload(&mut open(path)?, None, None, &mut hasher)
            .with_context(|| format!("Cannot read {}", path.display()))?;
    }

    let digest = finish(hasher)?;

    let header = OtaImageHeader {
        vendor_id: args.vid,
        product_id: args.pid,
        software_version: args.sw_version,
        software_version_str: &args.sw_version_str,
        payload_size,
        min_applicable_software_version: args.applicability.min_sw_version,
        max_applicable_software_version: args.applicability.max_sw_version,
        release_notes_url: args.applicability.release_notes_url.as_deref(),
        image_digest_type: OTA_IMAGE_DIGEST_SHA256,
        image_digest: Octets(&digest),
    };

    let mut out = create_out(&args.out)?;

    write_header(&header, &mut out)?;

    for path in &args.payload {
        io::copy(&mut open(path)?, &mut out)
            .with_context(|| format!("Cannot copy {}", path.display()))?;
    }

    out.flush()?;

    print_header(&header);
    info!("OTA image written to {}", args.out.display());

    Ok(())
}

fn show(image: &Path) -> anyhow::Result<()> {
    let (header_bytes, mut file) = read_header(image)?;
    let (header, _) = decode_header(&header_bytes)?;

    print_header(&header);
    verify_payload(&header, &mut file, None, image)
}

fn extract(image: &Path, out: &Path) -> anyhow::Result<()> {
    let (header_bytes, mut file) = read_header(image)?;
    let (header, _) = decode_header(&header_bytes)?;

    let mut writer = create_out(out)?;
    let result = verify_payload(&header, &mut file, Some(&mut writer), image)
        .and_then(|()| writer.flush().map_err(Into::into));

    if result.is_err() {
        drop(writer);
        let _ = fs::remove_file(out);
    } else {
        info!("Payload written to {}", out.display());
    }

    result
}

fn change_header(args: &ChangeHeaderArgs) -> anyhow::Result<()> {
    let (header_bytes, mut file) = read_header(&args.image)?;
    let (old, _) = decode_header(&header_bytes)?;

    let applicability = &args.applicability;

    let header = OtaImageHeader {
        vendor_id: args.vid.unwrap_or(old.vendor_id),
        product_id: args.pid.unwrap_or(old.product_id),
        software_version: args.sw_version.unwrap_or(old.software_version),
        software_version_str: args
            .sw_version_str
            .as_deref()
            .unwrap_or(old.software_version_str),
        min_applicable_software_version: applicability
            .min_sw_version
            .or(old.min_applicable_software_version),
        max_applicable_software_version: applicability
            .max_sw_version
            .or(old.max_applicable_software_version),
        release_notes_url: applicability
            .release_notes_url
            .as_deref()
            .or(old.release_notes_url),
        ..old.clone()
    };

    let mut out = create_out(&args.out)?;

    write_header(&header, &mut out)?;

    let result = verify_payload(&old, &mut file, Some(&mut out), &args.image)
        .and_then(|()| out.flush().map_err(Into::into));

    if result.is_err() {
        drop(out);
        let _ = fs::remove_file(&args.out);
        return result;
    }

    print_header(&header);
    info!("OTA image written to {}", args.out.display());

    Ok(())
}

/// Reject header values that make the image apply to no device; warn about
/// dubious ones.
fn check_header(header: &OtaImageHeader) -> anyhow::Result<()> {
    if header
        .release_notes_url
        .is_some_and(|url| !url.starts_with("https://"))
    {
        warn!("The release notes URL should use `https`");
    }

    let version = header.software_version;

    if let Some(min) = header.min_applicable_software_version {
        if min >= version {
            bail!("The minimum applicable version ({min}) must be lower than the software version ({version}), or the image applies to no device");
        }
    }

    if let Some(max) = header.max_applicable_software_version {
        if header
            .min_applicable_software_version
            .is_some_and(|min| max < min)
        {
            bail!("The maximum applicable version ({max}) is lower than the minimum one");
        }

        if max >= version {
            warn!("The maximum applicable version ({max}) is not lower than the software version ({version}); devices on version {version} or later are never offered the image anyway");
        }
    }

    if header.vendor_id == 0 {
        warn!("Vendor ID 0: the image is offered to devices of any vendor");
    }

    if header.product_id == 0 {
        warn!("Product ID 0: the image is offered to devices of any product");
    }

    Ok(())
}

fn write_header(header: &OtaImageHeader, out: &mut impl Write) -> anyhow::Result<()> {
    check_header(header)?;

    let mut buf = [0; MAX_HEADER_LEN];
    let len = header.encode(&mut buf).map_err(|e| match e.code() {
        ErrorCode::ConstraintError => anyhow::anyhow!(
            "The software version string must be 1 to 64 characters long, and the release notes URL 1 to 256"
        ),
        _ => anyhow::anyhow!("Cannot encode the OTA image header: {:?}", e.code()),
    })?;

    out.write_all(&buf[..len])?;

    Ok(())
}

/// Read the prefix and the header of an image, leaving the file at the start
/// of the payload.
fn read_header(image: &Path) -> anyhow::Result<(Vec<u8>, BufReader<File>)> {
    let mut file = open(image)?;

    let mut bytes = Vec::with_capacity(MAX_HEADER_LEN);
    (&mut file)
        .take(MAX_HEADER_LEN as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("Cannot read {}", image.display()))?;

    let (_, payload_offset) = OtaImageHeader::decode(&bytes).map_err(|e| {
        anyhow::anyhow!(
            "{} is not an OTA image, or its header is malformed: {:?}",
            image.display(),
            e.code()
        )
    })?;

    bytes.truncate(payload_offset);
    file.seek(SeekFrom::Start(payload_offset as u64))?;

    Ok((bytes, file))
}

fn decode_header(bytes: &[u8]) -> anyhow::Result<(OtaImageHeader<'_>, usize)> {
    OtaImageHeader::decode(bytes)
        .map_err(|e| anyhow::anyhow!("Malformed OTA image header: {:?}", e.code()))
}

/// Read the payload that follows the header, optionally copying it to `out`,
/// and check it against the header's size and digest.
fn verify_payload(
    header: &OtaImageHeader,
    file: &mut impl Read,
    out: Option<&mut dyn Write>,
    image: &Path,
) -> anyhow::Result<()> {
    let crypto = crypto();
    let mut hasher = hasher(&crypto)?;
    let size = copy_payload(file, Some(header.payload_size), out, &mut hasher)
        .with_context(|| format!("Cannot read the payload of {}", image.display()))?;

    if size != header.payload_size {
        bail!(
            "The payload of {} is {size} bytes, but the header says {}",
            image.display(),
            header.payload_size
        );
    }

    if header.image_digest_type != OTA_IMAGE_DIGEST_SHA256 {
        warn!(
            "Digest not checked: digest type {} is not supported, only SHA-256 ({OTA_IMAGE_DIGEST_SHA256})",
            header.image_digest_type
        );

        return Ok(());
    }

    if finish(hasher)?.as_slice() != header.image_digest.0 {
        bail!(
            "The payload of {} does not match its digest",
            image.display()
        );
    }

    println!("Payload:       {size} bytes, SHA-256 digest OK");

    Ok(())
}

/// Copy `input` to `out` (if any) through `hasher`, returning the bytes read;
/// with `limit`, read at most one byte past it.
fn copy_payload(
    input: &mut impl Read,
    limit: Option<u64>,
    mut out: Option<&mut dyn Write>,
    hasher: &mut impl Digest<HASH_LEN>,
) -> anyhow::Result<u64> {
    let mut input = input.take(limit.map_or(u64::MAX, |limit| limit.saturating_add(1)));
    let mut buf = vec![0; CHUNK_LEN];
    let mut size = 0;

    loop {
        let len = input.read(&mut buf)?;
        if len == 0 {
            break;
        }

        hasher
            .update(&buf[..len])
            .map_err(|e| anyhow::anyhow!("Cannot hash the payload: {:?}", e.code()))?;

        if let Some(out) = out.as_mut() {
            out.write_all(&buf[..len])?;
        }

        size += len as u64;
    }

    Ok(size)
}

fn print_header(header: &OtaImageHeader) {
    println!("Vendor ID:     0x{:04X}", header.vendor_id);
    println!("Product ID:    0x{:04X}", header.product_id);
    println!(
        "SW version:    {} (0x{:X}) \"{}\"",
        header.software_version, header.software_version, header.software_version_str
    );

    if let Some(min) = header.min_applicable_software_version {
        println!("Min. applies:  {min} (0x{min:X})");
    }

    if let Some(max) = header.max_applicable_software_version {
        println!("Max. applies:  {max} (0x{max:X})");
    }

    if let Some(url) = header.release_notes_url {
        println!("Release notes: {url}");
    }

    let digest = header
        .image_digest
        .0
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    let digest_type = match header.image_digest_type {
        OTA_IMAGE_DIGEST_SHA256 => "SHA-256".to_string(),
        other => format!("type {other}"),
    };

    println!("Payload size:  {} bytes", header.payload_size);
    println!("Digest:        {digest_type} {digest}");
}

fn open(path: &Path) -> anyhow::Result<BufReader<File>> {
    Ok(BufReader::new(File::open(path).with_context(|| {
        format!("Cannot open {}", path.display())
    })?))
}

fn create_out(path: &Path) -> anyhow::Result<BufWriter<File>> {
    Ok(BufWriter::new(File::create(path).with_context(|| {
        format!("Cannot create {}", path.display())
    })?))
}

/// Parse a decimal or `0x`-prefixed hex number.
fn parse_num<T: TryFrom<u64>>(s: &str) -> Result<T, String> {
    let parsed = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        s.parse()
    };

    let value = parsed.map_err(|e| format!("Invalid number `{s}`: {e}"))?;

    T::try_from(value).map_err(|_| format!("Number `{s}` is out of range"))
}

/// `rs-matter`'s crypto backend, for the payload digest.
fn crypto() -> impl Crypto {
    // Hashing uses no key; the backend only needs one to be constructed.
    default_crypto(rand::rng(), DAC_PRIVKEY)
}

fn hasher<C: Crypto>(crypto: &C) -> anyhow::Result<C::Hash<'_>> {
    crypto
        .hash()
        .map_err(|e| anyhow::anyhow!("Cannot create a SHA-256 hasher: {:?}", e.code()))
}

fn finish(hasher: impl Digest<HASH_LEN>) -> anyhow::Result<[u8; HASH_LEN]> {
    let mut digest = CryptoSensitive::new();
    hasher
        .finish(&mut digest)
        .map_err(|e| anyhow::anyhow!("Cannot finish the SHA-256 digest: {:?}", e.code()))?;

    Ok(*digest.access())
}
