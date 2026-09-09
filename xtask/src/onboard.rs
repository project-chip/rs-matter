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

//! `xtask onboard` - derive a device's onboarding payloads from its commissioning
//! parameters: pairing code, QR code text, NFC NDEF message and, on request,
//! the QR code itself on the console or as a text / SVG file.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};

use clap::{Args, ValueEnum};

use log::info;

use rs_matter::pairing::qr::{
    no_optional_data, CommFlowType, NoOptionalData, Qr, QrPayload, QrTextType,
};
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::BasicCommData;

/// Quiet zone around the QR code, in modules.
const QR_BORDER: u8 = 4;

/// The ANSI reset the text renderers emit at the end of every line.
const ANSI_RESET: &str = "\x1b[0m";

/// Arguments of the `onboard` command
#[derive(Args, Debug, Clone)]
pub struct OnboardArgs {
    /// Setup passcode (1 to 99999998, minus the trivial values)
    #[arg(long, short = 'p')]
    passcode: u32,
    /// 12-bit discriminator (0 to 4095)
    #[arg(long, short = 'd')]
    discriminator: u16,
    /// Vendor ID, decimal or `0x`-prefixed hex
    #[arg(long, value_parser = parse_u16)]
    vid: u16,
    /// Product ID, decimal or `0x`-prefixed hex
    #[arg(long, value_parser = parse_u16)]
    pid: u16,
    /// Commissioning flow
    #[arg(long, default_value_t = Flow::Standard, value_enum)]
    flow: Flow,
    /// Discovery capabilities, comma-separated (e.g. `ip,ble`)
    #[arg(long, value_delimiter = ',', default_value = "ip", value_enum)]
    caps: Vec<Capability>,
    /// Serial number to embed in the QR payload as optional TLV data
    #[arg(long)]
    serial: Option<String>,
    /// Print the QR code on the console with the given renderer
    #[arg(long, value_name = "RENDERER", value_enum)]
    qr: Option<Renderer>,
    /// Draw the dark modules instead of the light ones (for dark-on-light
    /// viewers, e.g. a text file in an editor)
    #[arg(long)]
    qr_invert: bool,
    /// Write the QR code as text art to this file
    #[arg(long, value_name = "FILE")]
    qr_text: Option<PathBuf>,
    /// Renderer for `--qr-text`
    #[arg(long, default_value_t = Renderer::Unicode, value_enum)]
    qr_text_renderer: Renderer,
    /// Write the QR code as an SVG image to this file
    #[arg(long, value_name = "FILE")]
    qr_svg: Option<PathBuf>,
    /// Size of one QR module in the SVG, in pixels
    #[arg(long, default_value_t = 8)]
    qr_svg_scale: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum Flow {
    /// Standard commissioning flow
    Standard,
    /// User-intent commissioning flow
    UserIntent,
    /// Custom commissioning flow
    Custom,
}

impl From<Flow> for CommFlowType {
    fn from(flow: Flow) -> Self {
        match flow {
            Flow::Standard => CommFlowType::Standard,
            Flow::UserIntent => CommFlowType::UserIntent,
            Flow::Custom => CommFlowType::Custom,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum Capability {
    /// IP network (on-network commissioning)
    Ip,
    /// Bluetooth LE
    Ble,
    /// NFC Transport Layer
    Ntl,
    /// Wi-Fi Public Action Frames
    Paf,
    /// Soft Access Point (reserved as of Matter 1.6)
    SoftAp,
}

impl From<Capability> for DiscoveryCapabilities {
    fn from(cap: Capability) -> Self {
        match cap {
            Capability::Ip => DiscoveryCapabilities::IP,
            Capability::Ble => DiscoveryCapabilities::BLE,
            Capability::Ntl => DiscoveryCapabilities::NTL,
            Capability::Paf => DiscoveryCapabilities::PAF,
            Capability::SoftAp => DiscoveryCapabilities::SOFT_AP,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum Renderer {
    /// `#` and spaces; works everywhere
    Ascii,
    /// ANSI background colors
    Ansi,
    /// Unicode half-block characters
    Unicode,
}

impl From<Renderer> for QrTextType {
    fn from(renderer: Renderer) -> Self {
        match renderer {
            Renderer::Ascii => QrTextType::Ascii,
            Renderer::Ansi => QrTextType::Ansi,
            Renderer::Unicode => QrTextType::Unicode,
        }
    }
}

/// Run the `onboard` command
pub fn run(args: &OnboardArgs) -> anyhow::Result<()> {
    if args.discriminator > 0x0fff {
        bail!(
            "Discriminator {} does not fit in 12 bits",
            args.discriminator
        );
    }

    let caps = args.caps.iter().fold(0u8, |bits, cap| {
        bits | DiscoveryCapabilities::from(*cap).bits()
    });
    let caps = DiscoveryCapabilities::from_bits_truncate(caps);

    let comm_data = BasicCommData {
        password: args.passcode.to_le_bytes().into(),
        discriminator: args.discriminator,
    };

    let payload = QrPayload::new(
        caps,
        args.flow.into(),
        comm_data.clone(),
        args.vid,
        args.pid,
        args.serial.as_deref().unwrap_or(""),
        no_optional_data as NoOptionalData,
    );

    if !payload.is_valid() {
        bail!(
            "The parameters do not form a valid onboarding payload: \
             check the passcode (must be 1..=99999998 and not a trivial sequence), \
             the vendor ID (0 or up to 0xFFF4) and the product ID (non-zero unless the vendor ID is 0)"
        );
    }

    let mut buf = vec![0u8; 4096];

    let (qr_text, rest) = payload
        .as_str(&mut buf)
        .map_err(|e| anyhow::anyhow!("Cannot encode the QR code text: {e:?}"))?;
    let qr_text = qr_text.to_string();

    let (ndef, _) = payload
        .as_ndef(rest)
        .map_err(|e| anyhow::anyhow!("Cannot encode the NFC NDEF message: {e:?}"))?;
    let ndef_hex = ndef.iter().fold(String::new(), |mut hex, byte| {
        let _ = write!(hex, "{byte:02X}");
        hex
    });

    // Non-standard flows need the 21-digit code with VID/PID
    if matches!(args.flow, Flow::Standard) {
        println!("Pairing code: {}", comm_data.compute_pretty_pairing_code());
    } else {
        println!(
            "Pairing code: {}",
            comm_data.compute_pretty_pairing_code_long(args.vid, args.pid)
        );
    }
    println!("QR code:      {qr_text}");
    println!("NFC NDEF:     {ndef_hex}");

    if args.qr.is_none() && args.qr_text.is_none() && args.qr_svg.is_none() {
        return Ok(());
    }

    let mut tmp_buf = vec![0u8; 4096];
    let mut out_buf = vec![0u8; 4096];
    let qr = Qr::compute(&qr_text, &mut tmp_buf, &mut out_buf)
        .map_err(|e| anyhow::anyhow!("Cannot compute the QR code: {e:?}"))?;

    let mut render_buf = vec![0u8; 64 * 1024];

    if let Some(renderer) = args.qr {
        let (text, _) = qr
            .as_str(renderer.into(), QR_BORDER, args.qr_invert, &mut render_buf)
            .map_err(|e| anyhow::anyhow!("Cannot render the QR code: {e:?}"))?;

        println!();
        print!("{text}");
    }

    if let Some(path) = &args.qr_text {
        let (text, _) = qr
            .as_str(
                args.qr_text_renderer.into(),
                QR_BORDER,
                args.qr_invert,
                &mut render_buf,
            )
            .map_err(|e| anyhow::anyhow!("Cannot render the QR code: {e:?}"))?;

        // Only the ANSI rendering needs the per-line resets in a file
        let text = if matches!(args.qr_text_renderer, Renderer::Ansi) {
            text.to_string()
        } else {
            text.replace(ANSI_RESET, "")
        };

        write_file(path, text.as_bytes())?;
        info!("QR code written as text to {}", path.display());
    }

    if let Some(path) = &args.qr_svg {
        if args.qr_svg_scale == 0 {
            bail!("The SVG scale must be at least 1");
        }

        let svg = render_svg(&qr, QR_BORDER, args.qr_svg_scale);

        write_file(path, svg.as_bytes())?;
        info!("QR code written as SVG to {}", path.display());
    }

    Ok(())
}

/// Render the QR code as a minimal SVG: one `<path>` for the dark modules.
fn render_svg(qr: &Qr<'_>, border: u8, scale: u32) -> String {
    let size = qr.size();
    let total = size + 2 * border as u32;
    let px = total * scale;

    let mut path = String::new();

    for y in 0..size {
        for x in 0..size {
            if qr.get_module(x as i32, y as i32) {
                let _ = write!(path, "M{} {}h1v1h-1z", x + border as u32, y + border as u32);
            }
        }
    }

    format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" ",
            "width=\"{px}\" height=\"{px}\" viewBox=\"0 0 {total} {total}\" ",
            "shape-rendering=\"crispEdges\">\n",
            "  <rect width=\"100%\" height=\"100%\" fill=\"#ffffff\"/>\n",
            "  <path d=\"{path}\" fill=\"#000000\"/>\n",
            "</svg>\n"
        ),
        px = px,
        total = total,
        path = path,
    )
}

fn write_file(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    std::fs::write(path, data).with_context(|| format!("Cannot write {}", path.display()))
}

/// Parse a decimal or `0x`-prefixed hex `u16`
fn parse_u16(s: &str) -> Result<u16, String> {
    let parsed = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u16::from_str_radix(hex, 16)
    } else {
        s.parse()
    };

    parsed.map_err(|e| format!("Invalid number `{s}`: {e}"))
}
