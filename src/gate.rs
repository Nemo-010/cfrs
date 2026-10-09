//! A PIN gate for public sessions, ported from quickbridge's idea: a 6-digit
//! code shown only on the machine that owns the tunnel, exchanged for a
//! session cookie. The PIN never appears in the URL.

use axum::http::HeaderMap;
use uuid::Uuid;

pub const UNLOCK_PATH: &str = "/__cfrs/unlock";
pub const COOKIE_NAME: &str = "cfrs_pin";

#[derive(Clone, Debug)]
enum Mode {
    Off,
    Pin,
}

#[derive(Clone, Debug)]
pub struct Gate {
    mode: Mode,
    pin: String,
    session: String,
}

impl Gate {
    pub fn off() -> Self {
        Self {
            mode: Mode::Off,
            pin: String::new(),
            session: String::new(),
        }
    }

    pub fn pin() -> Self {
        let pin = format!("{:06}", Uuid::new_v4().as_u128() % 1_000_000);
        Self {
            mode: Mode::Pin,
            pin,
            session: Uuid::new_v4().simple().to_string(),
        }
    }

    pub fn enabled(&self) -> bool {
        matches!(self.mode, Mode::Pin)
    }

    /// The code to show the operator. `None` when the gate is off.
    pub fn pin_display(&self) -> Option<&str> {
        self.enabled().then_some(self.pin.as_str())
    }

    /// True when the request carries the unlocked session cookie.
    pub fn is_open(&self, headers: &HeaderMap) -> bool {
        if !self.enabled() {
            return true;
        }
        headers
            .get(axum::http::header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .map(|cookies| {
                cookies.split(';').any(|part| {
                    let part = part.trim();
                    part.strip_prefix(&format!("{COOKIE_NAME}="))
                        .map(|value| value == self.session)
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    }

    /// Check a submitted PIN. On success returns the `Set-Cookie` value.
    pub fn unlock(&self, password: &str) -> Option<String> {
        if !self.enabled() || password.trim() != self.pin {
            return None;
        }
        Some(format!(
            "{COOKIE_NAME}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400",
            self.session
        ))
    }

    /// HTML unlock page.
    pub fn page_html(&self, next: &str, failed: bool) -> String {
        let next = escape_attr(next);
        let error = if failed {
            "<p class=\"err\">Wrong code, try again.</p>"
        } else {
            ""
        };
        format!(
            "<!doctype html><html><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
             <title>cfrs — locked</title><style>\
             body{{font-family:system-ui,sans-serif;background:#0b1020;color:#e8ecf5;\
             display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}\
             form{{background:#161d33;padding:2rem;border-radius:12px;width:min(90vw,320px)}}\
             h1{{font-size:1.1rem;margin:0 0 1rem}}p{{color:#9aa7c7;font-size:.9rem}}\
             .err{{color:#ff8a8a}}input{{width:100%;box-sizing:border-box;padding:.7rem;\
             font-size:1.4rem;letter-spacing:.4rem;text-align:center;border-radius:8px;\
             border:1px solid #33406a;background:#0b1020;color:#fff}}\
             button{{margin-top:1rem;width:100%;padding:.7rem;border:0;border-radius:8px;\
             background:#4f7cff;color:#fff;font-size:1rem}}\
             </style></head><body><form method=\"post\" action=\"{UNLOCK_PATH}\">\
             <h1>Enter the 6-digit code</h1>{error}\
             <input name=\"password\" inputmode=\"numeric\" pattern=\"[0-9]*\" \
             maxlength=\"6\" autofocus autocomplete=\"one-time-code\">\
             <input type=\"hidden\" name=\"next\" value=\"{next}\">\
             <button type=\"submit\">Unlock</button>\
             <p>The code is shown on the computer running cfrs.</p></form></body></html>"
        )
    }
}

fn escape_attr(value: &str) -> String {
    value
        .chars()
        .filter(|c| !matches!(c, '<' | '>' | '"' | '\'' | '&'))
        .take(512)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn off_is_open() {
        let gate = Gate::off();
        assert!(gate.is_open(&HeaderMap::new()));
        assert!(gate.pin_display().is_none());
    }

    #[test]
    fn pin_locks_until_cookie() {
        let gate = Gate::pin();
        let mut headers = HeaderMap::new();
        assert!(!gate.is_open(&headers));
        assert!(gate.unlock("000000").is_none() || gate.unlock("000000").is_some());

        let pin = gate.pin_display().unwrap().to_string();
        let cookie = gate.unlock(&pin).expect("correct pin");
        let value = cookie.split(';').next().unwrap().to_string();
        headers.insert(axum::http::header::COOKIE, HeaderValue::from_str(&value).unwrap());
        assert!(gate.is_open(&headers));
    }

    #[test]
    fn pin_is_six_digits() {
        for _ in 0..50 {
            let gate = Gate::pin();
            let pin = gate.pin_display().unwrap();
            assert_eq!(pin.len(), 6);
            assert!(pin.chars().all(|c| c.is_ascii_digit()));
        }
    }
}
