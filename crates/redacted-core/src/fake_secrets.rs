//! Synthetic secrets generated at runtime.
//! Values match engine.yml but never sit in source, so push protection stays quiet.

use std::cell::Cell;
use std::time::{SystemTime, UNIX_EPOCH};

const ALNUM: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const UPPER_ALNUM: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const BASE64URL: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

// Each test thread gets its own PRNG state; `Cell` allows updating it through
// the shared reference `with` hands out.
thread_local! {
    static PRNG_STATE: Cell<u64> = Cell::new(
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(1, |d| d.as_nanos() as u64) | 1,
    );
}

/// Fixes this thread's sequence, so a benchmark run can be replayed from its seed.
pub fn reseed(seed: u64) {
    PRNG_STATE.with(|s| s.set(seed | 1));
}

// xorshift64*: enough randomness for fixtures, no crate needed.
fn next_random() -> u64 {
    PRNG_STATE.with(|s| {
        let mut x = s.get();
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        s.set(x);
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    })
}

fn random_from_charset(charset: &str, n: usize) -> String {
    let charset_bytes = charset.as_bytes();
    (0..n)
        .map(|_| charset_bytes[(next_random() % charset_bytes.len() as u64) as usize] as char)
        .collect()
}

pub fn alnum(n: usize) -> String {
    random_from_charset(ALNUM, n)
}

pub fn hex(n: usize) -> String {
    random_from_charset("0123456789abcdef", n)
}

pub fn digits(n: usize) -> String {
    random_from_charset("0123456789", n)
}

pub fn upper_alnum(n: usize) -> String {
    random_from_charset(UPPER_ALNUM, n)
}

pub fn base64url(n: usize) -> String {
    random_from_charset(BASE64URL, n)
}

pub fn last_four_chars(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    chars[chars.len().saturating_sub(4)..].iter().collect()
}

pub fn aws_access_key() -> String {
    format!("AKIA{}", upper_alnum(16))
}

pub fn aws_secret_key() -> String {
    format!("{}/{}", alnum(37), alnum(2))
}

pub fn github_token(prefix: &str) -> String {
    format!("{prefix}{}", alnum(40))
}

pub fn github_fine_grained() -> String {
    format!("github_pat_{}", alnum(26))
}

pub fn stripe_key(prefix: &str) -> String {
    format!("{prefix}{}", alnum(24))
}

pub fn twilio_sid(prefix: &str) -> String {
    format!("{prefix}{}", hex(32))
}

pub fn digitalocean_token() -> String {
    format!("dop_v1_{}", hex(64))
}

pub fn digitalocean_spaces_value() -> String {
    format!("{}{}", upper_alnum(4), alnum(16))
}

pub fn sentry_dsn() -> String {
    format!(
        "https://{}@o{}.ingest.sentry.io/{}",
        hex(32),
        digits(6),
        digits(7)
    )
}

pub fn slack_token(prefix: &str) -> String {
    format!("{prefix}-{}-{}", digits(12), digits(12))
}

pub fn sendgrid_key() -> String {
    format!("SG.{}.{}", alnum(22), alnum(43))
}

pub fn hubspot_pat(region: &str) -> String {
    format!(
        "pat-{region}-{}-{}-{}-{}-{}",
        hex(8),
        hex(4),
        hex(4),
        hex(4),
        hex(12)
    )
}

pub fn jwt() -> String {
    format!(
        "eyJ{}.eyJ{}.{}",
        base64url(33),
        base64url(25),
        base64url(43)
    )
}

pub fn database_url(scheme: &str, host: &str) -> String {
    format!("{scheme}://user:{}@{host}:5432/mydb", alnum(12))
}

/// The hyphen keeps it from reading as a code identifier under a `password:` key.
pub fn password() -> String {
    format!("{}-{}", alnum(12), digits(4))
}

pub fn private_key(kind: &str) -> String {
    format!(
        "-----BEGIN {kind}PRIVATE KEY-----\n{}\n-----END {kind}PRIVATE KEY-----",
        alnum(14)
    )
}

pub fn private_key_truncated(kind: &str) -> String {
    format!(
        "-----BEGIN {kind}PRIVATE KEY-----\n{}\n{}",
        alnum(64),
        alnum(64)
    )
}

pub fn slack_webhook() -> String {
    format!(
        "https://hooks.slack.com/services/T{}/B{}/{}",
        upper_alnum(8),
        upper_alnum(8),
        alnum(24)
    )
}

/// The `"private_key": "-----BEGIN...` field of a GCP service-account JSON,
/// with the `\n` escapes a dump carries and no END marker.
pub fn gcp_private_key_field() -> String {
    format!(
        r#""private_key": "-----BEGIN PRIVATE KEY-----\n{}\n"#,
        alnum(96)
    )
}

/// redacted.my.id belongs to the author, so a generated address reaches no one else.
pub fn email() -> String {
    format!("{}@redacted.my.id", alnum(10))
}

/// A North American number in the 555-01xx range kept for fiction.
pub fn phone() -> String {
    let area_code = format!("{}{}", random_from_charset("23456789", 1), digits(2));
    format!("+1 {area_code} 555 01{}", digits(2))
}

/// A Visa-shaped number with a valid Luhn check digit: random, so no account is behind it.
pub fn credit_card() -> String {
    let body = format!("4{}", digits(14));
    let sum: u32 = body
        .chars()
        .rev()
        .filter_map(|c| c.to_digit(10))
        .enumerate()
        .map(|(position, digit)| match (position % 2, digit * 2) {
            (1, _) => digit,
            (_, doubled) if doubled > 9 => doubled - 9,
            (_, doubled) => doubled,
        })
        .sum();
    format!("{body}{}", (10 - sum % 10) % 10)
}

/// A British-shaped IBAN with valid mod-97 check digits over a random account.
pub fn iban() -> String {
    let account = format!(
        "{}{}",
        random_from_charset("ABCDEFGHJKLMNPRSTUVWXYZ", 4),
        digits(14)
    );
    // Check digits are 98 minus the remainder of the account followed by GB00.
    let remainder = format!("{account}GB00")
        .bytes()
        .fold(0u32, |remainder, byte| {
            if byte.is_ascii_digit() {
                (remainder * 10 + u32::from(byte - b'0')) % 97
            } else {
                (remainder * 100 + u32::from(byte - b'A') + 10) % 97
            }
        });
    format!("GB{:02}{account}", 98 - remainder)
}

/// A dashed US SSN with an area, group and serial the SSA could issue.
pub fn us_ssn() -> String {
    let area = format!("{}{}", random_from_charset("12345", 1), digits(2));
    format!("{area}-1{}-1{}", digits(1), digits(3))
}

/// An Indonesian NIK: a Jakarta region code, a birth date and a serial.
pub fn nik() -> String {
    let day = format!("1{}", digits(1));
    let month = format!("0{}", random_from_charset("123456789", 1));
    format!("317405{day}{month}{}1{}", digits(2), digits(3))
}

/// An Indonesian NPWP in its dotted form.
pub fn npwp() -> String {
    format!(
        "{}.{}.{}.{}-{}.{}",
        digits(2),
        digits(3),
        digits(3),
        digits(1),
        digits(3),
        digits(3)
    )
}

pub fn npm_token() -> String {
    format!("npm_{}", alnum(36))
}
