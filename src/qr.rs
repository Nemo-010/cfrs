//! QR rendering for share URLs.

use anyhow::Result;
use qrcode::{Color, QrCode};

const QUIET_ZONE: usize = 4;
const MAX_QR_SIZE: usize = 200;

/// Square 0/1 module matrix including the quiet zone.
pub fn matrix_for(payload: &str) -> Result<Vec<String>> {
    let code = QrCode::new(payload.as_bytes())?;
    let width = code.width();
    let size = width + QUIET_ZONE * 2;
    if size > MAX_QR_SIZE {
        anyhow::bail!("payload too large for a QR code");
    }
    let mut rows = Vec::with_capacity(size);
    for y in 0..size {
        let mut row = String::with_capacity(size);
        for x in 0..size {
            let dark = x >= QUIET_ZONE
                && y >= QUIET_ZONE
                && x < QUIET_ZONE + width
                && y < QUIET_ZONE + width
                && code[(x - QUIET_ZONE, y - QUIET_ZONE)] == Color::Dark;
            row.push(if dark { '1' } else { '0' });
        }
        rows.push(row);
    }
    Ok(rows)
}

/// Terminal rendering using half blocks so the code is compact and square.
pub fn render_terminal(payload: &str) -> Result<String> {
    let rows = matrix_for(payload)?;
    let mut out = String::new();
    let mut y = 0;
    while y < rows.len() {
        let top = rows[y].as_bytes();
        let bottom = if y + 1 < rows.len() {
            rows[y + 1].as_bytes()
        } else {
            &vec![b'0'; rows[y].len()]
        };
        for x in 0..rows[y].len() {
            let t = top[x] == b'1';
            let b = bottom[x] == b'1';
            out.push(match (t, b) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        out.push('\n');
        y += 2;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_is_square() {
        let rows = matrix_for("https://x.trycloudflare.com/s/abc").unwrap();
        let size = rows.len();
        assert!(size > 10);
        for row in &rows {
            assert_eq!(row.len(), size);
            assert!(row.chars().all(|c| c == '0' || c == '1'));
        }
        assert!(rows.iter().any(|r| r.contains('1')));
        assert!(rows[0].chars().all(|c| c == '0'));
    }

    #[test]
    fn terminal_render_has_blocks() {
        let text = render_terminal("https://example.trycloudflare.com/").unwrap();
        assert!(text.contains('█') || text.contains('▀') || text.contains('▄'));
    }
}
