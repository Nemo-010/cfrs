//! Small shared helpers.

use std::path::Path;

use anyhow::Result;
use uuid::Uuid;

/// A 32-hex-character unguessable token.
pub fn random_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

/// Keep only a safe basename, reject traversal and control characters.
pub fn sanitize_filename(name: &str) -> String {
    let base = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .trim()
        .trim_start_matches('.');
    let mut out: String = base
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|'))
        .take(200)
        .collect();
    if out.trim().is_empty() {
        out = format!("file-{}", &Uuid::new_v4().simple().to_string()[..8]);
    }
    out
}

pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Host[:port] from an absolute URL.
pub fn authority_of(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1)?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() {
        None
    } else {
        Some(authority.to_string())
    }
}

/// Path and query from a destination URL (`https://host/a?b` -> `/a?b`).
pub fn path_and_query(dest: &str) -> String {
    if let Some(scheme) = dest.find("://") {
        let rest = &dest[scheme + 3..];
        return match rest.find(['/', '?', '#']) {
            Some(index) if rest.as_bytes()[index] == b'/' => rest[index..].to_string(),
            Some(index) if rest.as_bytes()[index] == b'?' => format!("/{}", &rest[index..]),
            Some(_) => "/".to_string(),
            None => "/".to_string(),
        };
    }
    if dest.starts_with('/') {
        dest.to_string()
    } else {
        "/".to_string()
    }
}

pub fn ensure_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .map_err(|e| anyhow::anyhow!("creating {}: {e}", path.display()))?;
    Ok(())
}

/// The public host of a quick-tunnel URL, validated against the
/// `*.trycloudflare.com` allowlist so a hostile API response cannot point the
/// tool at another host.
pub fn validate_quick_hostname(raw: &str) -> Result<String> {
    let host = raw
        .trim()
        .trim_end_matches('/')
        .strip_prefix("https://")
        .unwrap_or(raw.trim().trim_end_matches('/'))
        .to_ascii_lowercase();
    let bad = host.is_empty()
        || host.contains(['/', '\\', '@', '?', '#', ':', '[', ']', ' ']);
    if bad {
        anyhow::bail!("quick tunnel returned a malformed hostname: {raw:?}");
    }
    let Some(sub) = host.strip_suffix(".trycloudflare.com") else {
        anyhow::bail!("quick tunnel hostname is not under trycloudflare.com: {host}");
    };
    if sub.is_empty()
        || sub.contains('.')
        || sub.starts_with('-')
        || sub.ends_with('-')
        || sub.len() > 63
        || !sub
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        anyhow::bail!("quick tunnel hostname label is invalid: {host}");
    }
    Ok(format!("https://{host}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename("a/b\\c.txt"), "c.txt");
        let dotdot = sanitize_filename("..");
        assert!(!dotdot.is_empty());
        assert!(!dotdot.contains(".."));
        assert!(!sanitize_filename("").is_empty());
        assert_eq!(sanitize_filename("a\u{0}b"), "ab");
    }

    #[test]
    fn bytes() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(2048), "2.0 KiB");
    }

    #[test]
    fn authority_and_path() {
        assert_eq!(authority_of("https://x.trycloudflare.com/a"), Some("x.trycloudflare.com".into()));
        assert_eq!(path_and_query("https://h/a?b=1"), "/a?b=1");
        assert_eq!(path_and_query("https://h"), "/");
        assert_eq!(path_and_query("https://h?x=1"), "/?x=1");
    }

    #[test]
    fn quick_hosts() {
        assert_eq!(
            validate_quick_hostname("https://abc-123.trycloudflare.com/").unwrap(),
            "https://abc-123.trycloudflare.com"
        );
        assert!(validate_quick_hostname("https://evil.com").is_err());
        assert!(validate_quick_hostname("https://a.b.trycloudflare.com").is_err());
        assert!(validate_quick_hostname("http://abc.trycloudflare.com").is_err());
    }
}
