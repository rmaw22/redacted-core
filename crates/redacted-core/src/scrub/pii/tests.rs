//! Unit tests for the PII validators and the rows they back.

use super::*;
use crate::fake_secrets;
use crate::scrub::tests::{default_scrubber, pii_scrubber};

#[test]
fn a_card_needs_a_network_prefix_its_length_and_a_luhn_digit() {
    for card in [
        "4539 1488 0343 6467",
        "4539-1488-0343-6467",
        "4539148803436467",
        "5425233430109903",
        "2222420000001113",
        "3400 000000 00009",
        "6011000000000004",
    ] {
        assert!(is_card_number(card), "{card}");
    }
    for not_a_card in [
        // Luhn fails.
        "4539148803436468",
        // Luhn passes, but no network starts with 1 or 9.
        "1791860933376004",
        "9999999999999995",
        // A Mastercard prefix at a Visa-only length.
        "5425233430101",
    ] {
        assert!(!is_card_number(not_a_card), "{not_a_card}");
    }
}

#[test]
fn published_test_cards_are_left_alone() {
    let scrubber = pii_scrubber();
    for card in TEST_CARDS {
        assert!(!is_card_number(card), "{card}");
        assert_eq!(scrubber.scrub(card).text, card);
    }
    let spaced = "pay with 4242 4242 4242 4242 in test mode";
    assert_eq!(scrubber.scrub(spaced).text, spaced);
}

#[test]
fn an_iban_needs_a_registry_country_its_length_and_mod_97() {
    for iban in [
        "GB82WEST12345698765432",
        "GB82 WEST 1234 5698 7654 32",
        "DE89370400440532013000",
        "DE89 3704 0044 0532 0130 00",
        "NL91ABNA0417164300",
        "FR1420041010050500013M02606",
        "NO9386011117947",
    ] {
        assert!(is_iban(iban), "{iban}");
    }
    for not_an_iban in [
        // One digit off, so mod-97 fails.
        "GB82WEST12345698765433",
        // Right check digits for the body, wrong length for Germany.
        "DE8937040044053201300",
        // No such IBAN country.
        "ZZ82WEST12345698765432",
    ] {
        assert!(!is_iban(not_an_iban), "{not_an_iban}");
    }
}

#[test]
fn an_ssn_needs_an_area_group_and_serial_the_ssa_issues() {
    for ssn in ["536-90-4399", "001-01-0001", "899-99-9999"] {
        assert!(is_us_ssn(ssn), "{ssn}");
    }
    for not_an_ssn in [
        "000-12-3456",
        "666-12-3456",
        "900-12-3456",
        "123-00-4567",
        "123-45-0000",
    ] {
        assert!(!is_us_ssn(not_an_ssn), "{not_an_ssn}");
    }
}

#[test]
fn a_nik_needs_region_codes_a_birth_date_and_a_serial() {
    for nik in [
        "3174051203900004",
        // A woman's day of birth is stored plus 40.
        "3174055203900004",
        "9601011708850001",
    ] {
        assert!(is_nik(nik), "{nik}");
    }
    for not_a_nik in [
        // No province 10 or 99.
        "1074051203900004",
        "9974051203900004",
        // Day 00, day 32, day 72, month 13.
        "3174050003900004",
        "3174053203900004",
        "3174057203900004",
        "3174051213900004",
        // Regency 00, district 00, serial 0000.
        "3100051203900004",
        "3174001203900004",
        "3174051203900000",
    ] {
        assert!(!is_nik(not_a_nik), "{not_a_nik}");
    }
}

#[test]
fn identity_rows_redact_in_prose_and_keep_the_words_around_them() {
    let scrubber = pii_scrubber();
    for (input, expected) in [
        (
            "NIK saya 3174051203900004 ya",
            "NIK saya [REDACTED:nik ...0004] ya",
        ),
        (
            "NPWP: 01.234.567.8-901.000",
            "NPWP: [REDACTED:npwp ....000]",
        ),
        (
            "kartu 4539 1488 0343 6467 exp 12/27",
            "kartu [REDACTED:credit_card ...6467] exp 12/27",
        ),
        (
            "wire to GB82 WEST 1234 5698 7654 32 today",
            "wire to [REDACTED:iban ...4 32] today",
        ),
        ("SSN 536-90-4399.", "SSN [REDACTED:us_ssn]."),
    ] {
        assert_eq!(scrubber.scrub(input).text, expected, "{input}");
    }
}

#[test]
fn identity_rows_leave_look_alike_numbers_alone() {
    let scrubber = pii_scrubber();
    for input in [
        // A 16-digit id that fails the NIK and card checks.
        "trace 1791860933376006 done",
        // Glued to a word or part of a longer dashed id.
        "build-3174051203900004",
        "ref 536-90-4399-01",
        // An ISBN and a date are not an SSN.
        "978-3-16-148410-0",
        "2026-10-16",
        // A dotted version is not an NPWP.
        "v01.234.567",
        // IBAN-shaped, but the check digits are wrong.
        "GB00WEST12345698765432",
    ] {
        assert_eq!(scrubber.scrub(input).text, input, "{input}");
    }
}

#[test]
fn identity_rows_are_off_by_default_and_each_toggle_stands_alone() {
    let samples = [
        ("credit_card", fake_secrets::credit_card()),
        ("iban", fake_secrets::iban()),
        ("us_ssn", fake_secrets::us_ssn()),
        ("nik", fake_secrets::nik()),
        ("npwp", fake_secrets::npwp()),
    ];
    let line = samples.map(|(_, value)| value).join(" | ");
    assert_eq!(default_scrubber().scrub(&line).text, line);

    let only_nik = crate::config::Config {
        pii: crate::config::PiiConfig {
            nik: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let scrubber =
        crate::scrub::Scrubber::new(&only_nik, &crate::config::EngineConfig::default()).unwrap();
    let result = scrubber.scrub(&line);
    assert_eq!(result.count, 1);
    assert_eq!(result.counts_by_pattern.get("nik"), Some(&1));
}

#[test]
fn a_spaced_card_keeps_its_label_with_the_phone_row_on() {
    // `0566 5566 5556` on its own reads as an Indonesian local phone number.
    let result = pii_scrubber().scrub("4000 0566 5566 5564");
    assert_eq!(result.counts_by_pattern.get("credit_card"), Some(&1));
    assert_eq!(result.count, 1);
}
