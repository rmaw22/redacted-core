//! Validators for the PII rows whose regex only matches a shape: a run of digits
//! is a card, an IBAN or a NIK only when its check digits and fields add up, and
//! capitalised words after `Pak` are a name only when they are not a title.

/// Card numbers the payment networks publish for testing: no account behind them.
const TEST_CARDS: [&str; 15] = [
    "4111111111111111",
    "4242424242424242",
    "4012888888881881",
    "4000056655665556",
    "5555555555554444",
    "5105105105105100",
    "5200828282828210",
    "2223003122003222",
    "378282246310005",
    "371449635398431",
    "6011111111111117",
    "6011000990139424",
    "3530111333300000",
    "3566002020360505",
    "30569309025904",
];

/// IBAN length per country (ISO 13616 registry). A country outside it is not matched.
const IBAN_LENGTHS: [(&str, usize); 70] = [
    ("AD", 24),
    ("AE", 23),
    ("AL", 28),
    ("AT", 20),
    ("AZ", 28),
    ("BA", 20),
    ("BE", 16),
    ("BG", 22),
    ("BH", 22),
    ("BR", 29),
    ("CH", 21),
    ("CR", 22),
    ("CY", 28),
    ("CZ", 24),
    ("DE", 22),
    ("DK", 18),
    ("DO", 28),
    ("EE", 20),
    ("EG", 29),
    ("ES", 24),
    ("FI", 18),
    ("FO", 18),
    ("FR", 27),
    ("GB", 22),
    ("GE", 22),
    ("GI", 23),
    ("GL", 18),
    ("GR", 27),
    ("GT", 28),
    ("HR", 21),
    ("HU", 28),
    ("IE", 22),
    ("IL", 23),
    ("IQ", 23),
    ("IS", 26),
    ("IT", 27),
    ("JO", 30),
    ("KW", 30),
    ("KZ", 20),
    ("LB", 28),
    ("LI", 21),
    ("LT", 20),
    ("LU", 20),
    ("LV", 21),
    ("MC", 27),
    ("MD", 24),
    ("ME", 22),
    ("MK", 19),
    ("MR", 27),
    ("MT", 31),
    ("MU", 30),
    ("NL", 18),
    ("NO", 15),
    ("PK", 24),
    ("PL", 28),
    ("PS", 29),
    ("PT", 25),
    ("QA", 29),
    ("RO", 24),
    ("RS", 22),
    ("SA", 24),
    ("SE", 24),
    ("SI", 19),
    ("SK", 24),
    ("SM", 27),
    ("TN", 24),
    ("TR", 26),
    ("UA", 29),
    ("VG", 24),
    ("XK", 20),
];

/// Province codes that open a NIK (Kemendagri), the six Papua provinces included.
const NIK_PROVINCES: [u32; 38] = [
    11, 12, 13, 14, 15, 16, 17, 18, 19, 21, 31, 32, 33, 34, 35, 36, 51, 52, 53, 61, 62, 63, 64, 65,
    71, 72, 73, 74, 75, 76, 81, 82, 91, 92, 93, 94, 95, 96,
];

/// What follows Pak, Bu, Bapak or Ibu when no person is named: a title, a role,
/// or the second half of a set phrase (`Ibu Kota`, `Bapak Ibu sekalian`).
const TITLE_WORDS: [&str; 44] = [
    "angkat",
    "bapak",
    "bendahara",
    "bos",
    "boss",
    "bu",
    "bupati",
    "camat",
    "dekan",
    "direktur",
    "dirut",
    "dokter",
    "dosen",
    "gubernur",
    "guru",
    "haji",
    "hajjah",
    "hakim",
    "ibu",
    "jari",
    "kades",
    "kandung",
    "kepala",
    "ketua",
    "kos",
    "kota",
    "lurah",
    "manager",
    "manajer",
    "menteri",
    "mertua",
    "negara",
    "pak",
    "pertiwi",
    "polisi",
    "presiden",
    "rektor",
    "rt",
    "rumah",
    "rw",
    "satpam",
    "sekretaris",
    "tiri",
    "wali",
];

/// Capitalised words that follow a name without being part of it: weekdays,
/// months, and the words that open a company or team name.
const AFTER_NAME_WORDS: [&str; 30] = [
    "senin",
    "selasa",
    "rabu",
    "kamis",
    "jumat",
    "jum'at",
    "sabtu",
    "minggu",
    "ahad",
    "januari",
    "februari",
    "maret",
    "april",
    "mei",
    "juni",
    "juli",
    "agustus",
    "september",
    "oktober",
    "november",
    "desember",
    "pt",
    "cv",
    "ud",
    "bank",
    "tim",
    "divisi",
    "hr",
    "hrd",
    "it",
];

/// Words that count a thing after a number, so `Jalan Kaki 30 menit` is no address.
const UNIT_WORDS: [&str; 14] = [
    "km", "m", "meter", "jam", "menit", "detik", "hari", "minggu", "bulan", "tahun", "kali",
    "orang", "unit", "persen",
];

fn digits_of(text: &str) -> Vec<u32> {
    text.chars().filter_map(|c| c.to_digit(10)).collect()
}

/// The number the first `count` digits spell.
fn leading_number(digits: &[u32], count: usize) -> u32 {
    digits[..count]
        .iter()
        .fold(0, |sum, digit| sum * 10 + digit)
}

fn passes_luhn(digits: &[u32]) -> bool {
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(position, &digit)| match (position % 2, digit * 2) {
            (0, _) => digit,
            (_, doubled) if doubled > 9 => doubled - 9,
            (_, doubled) => doubled,
        })
        .sum();
    sum.is_multiple_of(10)
}

/// Whether the leading digits and the length belong to one card network.
fn has_card_network_shape(digits: &[u32]) -> bool {
    let len = digits.len();
    let (two, three, four) = (
        leading_number(digits, 2),
        leading_number(digits, 3),
        leading_number(digits, 4),
    );
    match digits[0] {
        // Visa
        4 => matches!(len, 13 | 16 | 19),
        // Mastercard, old and 2-series ranges
        5 => (51..=55).contains(&two) && len == 16,
        2 => (2221..=2720).contains(&four) && len == 16,
        3 => match two {
            // American Express
            34 | 37 => len == 15,
            // JCB
            35 => (3528..=3589).contains(&four) && (16..=19).contains(&len),
            // Diners Club
            30 | 36 | 38 | 39 => (14..=19).contains(&len),
            _ => false,
        },
        // Discover and UnionPay
        6 => {
            (four == 6011 || two == 65 || two == 62 || (644..=649).contains(&three))
                && (16..=19).contains(&len)
        }
        _ => false,
    }
}

/// One of the networks' published test numbers, with or without separators.
pub(super) fn is_test_card(matched: &str) -> bool {
    let compact: String = matched.chars().filter(char::is_ascii_digit).collect();
    TEST_CARDS.contains(&compact.as_str())
}

/// A payment card: a network's prefix and length, a Luhn check digit, and not a test number.
pub(super) fn is_card_number(matched: &str) -> bool {
    let digits = digits_of(matched);
    (13..=19).contains(&digits.len())
        && has_card_network_shape(&digits)
        && passes_luhn(&digits)
        && !is_test_card(matched)
}

/// An IBAN: a registry country at its exact length whose mod-97 check is 1.
pub(super) fn is_iban(matched: &str) -> bool {
    let compact: Vec<u8> = matched.bytes().filter(|byte| *byte != b' ').collect();
    let has_country_length = IBAN_LENGTHS
        .iter()
        .any(|(country, len)| compact.starts_with(country.as_bytes()) && compact.len() == *len);
    if !has_country_length {
        return false;
    }
    // The check moves the first four characters to the end and reads letters as 10..35.
    let remainder = compact[4..]
        .iter()
        .chain(&compact[..4])
        .fold(0u32, |remainder, &byte| match byte {
            b'0'..=b'9' => (remainder * 10 + u32::from(byte - b'0')) % 97,
            _ => (remainder * 100 + u32::from(byte - b'A') + 10) % 97,
        });
    remainder == 1
}

/// A US Social Security number the SSA could have issued: no 000, 666 or 9xx area,
/// no 00 group, no 0000 serial.
pub(super) fn is_us_ssn(matched: &str) -> bool {
    let digits = digits_of(matched);
    if digits.len() != 9 {
        return false;
    }
    let area = leading_number(&digits, 3);
    let group = leading_number(&digits[3..], 2);
    let serial = leading_number(&digits[5..], 4);
    area != 0 && area != 666 && area < 900 && group != 0 && serial != 0
}

/// An Indonesian NIK: province, regency and district codes, a birth date as DDMMYY
/// (women add 40 to the day), then a serial. A family card number (KK) has the same layout.
/// A Mastercard test number can read as a NIK from Bali, so those are left out here too.
pub(super) fn is_nik(matched: &str) -> bool {
    let digits = digits_of(matched);
    if digits.len() != 16 || is_test_card(matched) {
        return false;
    }
    let field = |start: usize| leading_number(&digits[start..], 2);
    let day = match field(6) {
        day @ 41..=71 => day - 40,
        day => day,
    };
    NIK_PROVINCES.contains(&field(0))
        && field(2) != 0
        && field(4) != 0
        && (1..=31).contains(&day)
        && (1..=12).contains(&field(8))
        && leading_number(&digits[12..], 4) != 0
}

/// An Indonesian bank account number has 10 to 16 digits, whatever the grouping.
pub(super) fn is_bank_account(matched: &str) -> bool {
    (10..=16).contains(&digits_of(matched).len())
}

/// An all-digit passport number counts only right after the label: `passport
/// expires 20301231` holds a date. A number with letters may sit a few words on.
pub(super) fn is_passport_out_of_reach(matched: &str) -> bool {
    let mut words = matched
        .split(|c: char| " \t:#=-".contains(c))
        .filter(|word| !word.is_empty());
    let is_bare_number = words
        .next_back()
        .is_some_and(|value| value.bytes().all(|byte| byte.is_ascii_digit()));
    let has_other_words = words.skip(1).any(|word| {
        let word = word.trim_end_matches('.').to_ascii_lowercase();
        !matches!(word.as_str(), "no" | "number" | "nomor")
    });
    is_bare_number && has_other_words
}

/// A street is an address once a house number, RT or RW pins it down.
pub(super) fn is_address(matched: &str) -> bool {
    matched.bytes().any(|byte| byte.is_ascii_digit())
}

/// Whether the text opens with a unit word: the number before it is a count.
pub(super) fn starts_with_unit(rest: &str) -> bool {
    let word: String = rest
        .trim_start_matches([' ', '\t'])
        .chars()
        .take_while(char::is_ascii_alphabetic)
        .collect();
    UNIT_WORDS.contains(&word.to_ascii_lowercase().as_str())
}

/// How many bytes of the words after a name label are the name: all of them up
/// to a weekday, month or company word, and none when they open with a title.
pub(super) fn name_len(words: &str) -> usize {
    let (mut len, mut offset) = (0, 0);
    for piece in words.split_inclusive([' ', '\t']) {
        let word = piece.trim_end_matches([' ', '\t']);
        let lower = word.to_ascii_lowercase();
        if len == 0 && TITLE_WORDS.contains(&lower.as_str()) {
            return 0;
        }
        if AFTER_NAME_WORDS.contains(&lower.as_str()) {
            break;
        }
        if !word.is_empty() {
            len = offset + word.len();
        }
        offset += piece.len();
    }
    len
}

#[cfg(test)]
mod tests;
