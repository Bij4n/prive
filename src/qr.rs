//! QR codes drawn with Unicode half blocks, to scan an otpauth URI into a phone's
//! authenticator app straight from the terminal.

use anyhow::{Context, Result};
use qrcode::QrCode;
use qrcode::render::unicode::Dense1x2;

/// The QR code for `text`, two rows per character line, with a quiet zone around it so phones
/// pick it up on dark and light terminals alike.
pub fn render(text: &str) -> Result<String> {
    let code = QrCode::new(text.as_bytes()).context("making the QR code")?;
    Ok(code
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .quiet_zone(true)
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_a_square_of_half_blocks() {
        let qr = render("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP").unwrap();
        let lines: Vec<&str> = qr.lines().collect();
        assert!(lines.len() > 10);
        let width = lines[0].chars().count();
        assert!(lines.iter().all(|l| l.chars().count() == width));
        assert!(qr.chars().all(|c| " ▀▄█\n".contains(c)));
    }
}
