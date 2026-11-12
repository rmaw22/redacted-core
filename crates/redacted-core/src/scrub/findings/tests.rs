//! Unit tests for findings: offsets into the original text, whatever the tiers rewrote before.

use super::*;
use crate::fake_secrets;
use crate::scrub::tests::{
    builtin_pattern_cases, clean_corpus, default_scrubber, pii_scrubber, scrubber_with_learned,
};

fn replacement(name: &str, start: usize, end: usize, written: usize) -> Replacement<'_> {
    Replacement {
        name,
        start,
        end,
        written,
        lead: 0,
    }
}

fn spans(log: MarkerLog) -> Vec<(String, usize, usize)> {
    log.into_findings()
        .into_iter()
        .map(|finding| (finding.name, finding.start, finding.end))
        .collect()
}

/// The original with its findings cut out, blanks dropped: a keyed marker swaps
/// the blanks after its separator for one space.
fn outside_findings(original: &str, findings: &[Finding]) -> String {
    let mut out = String::new();
    let mut copied_until = 0;
    for finding in findings {
        out.push_str(&original[copied_until..finding.start]);
        copied_until = finding.end;
    }
    out.push_str(&original[copied_until..]);
    out.split_whitespace().collect()
}

/// The scrubbed text with its markers cut out, blanks dropped.
fn outside_markers(scrubbed: &str) -> String {
    let mut parts = scrubbed.split("[REDACTED");
    let mut out = parts.next().unwrap_or_default().to_string();
    for part in parts {
        out.push_str(part.split_once(']').map_or(part, |(_, rest)| rest));
    }
    out.split_whitespace().collect()
}

#[test]
fn a_finding_points_at_the_secret_in_the_original_text() {
    let key = fake_secrets::aws_access_key();
    let text = format!("first line\nkey {key} here");
    let result = default_scrubber().scrub(&text);
    assert_eq!(result.findings.len(), 1);
    let finding = &result.findings[0];
    assert_eq!(finding.name, "aws_access_key");
    assert_eq!(&text[finding.start..finding.end], key);
}

#[test]
fn clean_text_has_no_findings() {
    assert!(default_scrubber().scrub("just prose").findings.is_empty());
}

#[test]
fn findings_from_different_tiers_come_back_in_text_order() {
    // The email row runs after both keys, on text their markers already shortened.
    let (stripe, aws, address) = (
        fake_secrets::stripe_key("sk_live_"),
        fake_secrets::aws_access_key(),
        fake_secrets::email(),
    );
    let text = format!("mail {address} then {stripe}\nand {aws} last");
    let result = pii_scrubber().scrub(&text);
    let found: Vec<(&str, &str)> = result
        .findings
        .iter()
        .map(|finding| (finding.name.as_str(), &text[finding.start..finding.end]))
        .collect();
    assert_eq!(
        found,
        [
            ("email", address.as_str()),
            ("stripe_live", stripe.as_str()),
            ("aws_access_key", aws.as_str()),
        ]
    );
    assert_eq!(result.findings.len(), result.count);
}

#[test]
fn a_keyed_finding_is_the_value_without_its_key_or_the_blanks_before_it() {
    let password = fake_secrets::password();
    for separator in ["=", ": ", ":   "] {
        let text = format!("x\nDB_PASSWORD{separator}{password}\n");
        let result = default_scrubber().scrub(&text);
        let finding = &result.findings[0];
        assert_eq!(finding.name, "password_assignment");
        assert_eq!(&text[finding.start..finding.end], password, "{separator:?}");
    }
}

#[test]
fn offsets_are_bytes_so_text_before_a_finding_may_hold_any_characters() {
    let key = fake_secrets::aws_access_key();
    let text = format!("kunci 🔑 é: {key} — selesai");
    let result = default_scrubber().scrub(&text);
    let finding = &result.findings[0];
    assert_eq!(&text[finding.start..finding.end], key);
}

#[test]
fn a_learned_secret_is_a_finding_under_its_learned_name() {
    let value = fake_secrets::alnum(24);
    let scrubber = scrubber_with_learned(vec![crate::scrub::learn("DB_PASS", &value).unwrap()]);
    let text = format!("{} and {value}.", fake_secrets::aws_access_key());
    let result = scrubber.scrub(&text);
    let last = result.findings.last().unwrap();
    assert_eq!(last.name, "db_pass");
    assert_eq!(&text[last.start..last.end], value);
    assert_eq!(result.findings.len(), 2);
}

#[test]
fn every_builtin_finding_cuts_the_secret_and_nothing_else_out_of_the_corpus() {
    let scrubber = pii_scrubber();
    for (name, data) in clean_corpus() {
        for case in builtin_pattern_cases() {
            let text = format!("{data}\nfound {} é\n{data}", case.input);
            let result = scrubber.scrub(&text);
            let pattern = case.name;
            assert_eq!(
                outside_findings(&text, &result.findings),
                outside_markers(&result.text),
                "{pattern} in {name}"
            );
            let is_ordered = result
                .findings
                .windows(2)
                .all(|pair| pair[0].end <= pair[1].start);
            assert!(is_ordered, "{pattern} in {name}");
        }
    }
}

#[test]
fn a_later_marker_moves_the_earlier_ones_after_it() {
    // "aaaa SECRET bbbb TOKEN": the second tier rewrites text before the first marker.
    let mut log = MarkerLog::default();
    log.record(&[replacement("late", 17, 22, 3)]);
    log.record(&[replacement("early", 5, 11, 20)]);
    assert_eq!(
        spans(log),
        [("early".to_string(), 5, 11), ("late".to_string(), 17, 22)]
    );
}

#[test]
fn a_match_after_a_marker_is_shifted_by_what_the_marker_hid() {
    // The marker stands for 30 original bytes in 10 written ones.
    let mut log = MarkerLog::default();
    log.record(&[replacement("first", 4, 34, 10)]);
    log.record(&[replacement("second", 20, 26, 8)]);
    assert_eq!(
        spans(log),
        [("first".to_string(), 4, 34), ("second".to_string(), 40, 46)]
    );
}

#[test]
fn a_match_that_swallows_or_cuts_into_a_marker_takes_its_original_bytes() {
    // Marker at 10..20 of the rewritten text stands for original 10..50.
    let swallowed = {
        let mut log = MarkerLog::default();
        log.record(&[replacement("inner", 10, 50, 10)]);
        log.record(&[replacement("outer", 5, 25, 9)]);
        spans(log)
    };
    assert_eq!(swallowed, [("outer".to_string(), 5, 55)]);

    let cut_at_the_end = {
        let mut log = MarkerLog::default();
        log.record(&[replacement("inner", 10, 50, 10)]);
        log.record(&[replacement("outer", 5, 15, 9)]);
        spans(log)
    };
    assert_eq!(cut_at_the_end, [("outer".to_string(), 5, 50)]);

    let cut_at_the_start = {
        let mut log = MarkerLog::default();
        log.record(&[replacement("inner", 10, 50, 10)]);
        log.record(&[replacement("outer", 15, 25, 9)]);
        spans(log)
    };
    assert_eq!(cut_at_the_start, [("outer".to_string(), 10, 55)]);
}
