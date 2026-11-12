//! Where each redaction sat in the text as it was passed to `scrub`.
//!
//! The tiers run one after another, each on the text the last one rewrote, so a
//! match is found at an offset in half-redacted text. `MarkerLog` keeps every
//! marker's place in that text next to the original bytes it stands for, and
//! translates each new match back through them.

use std::iter::Peekable;
use std::vec::IntoIter;

/// One redaction: the pattern that made it and the bytes it replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The pattern name, as in `counts_by_pattern`.
    pub name: String,
    /// Byte offsets into the original text. For a keyed pattern this is the
    /// value alone: the key and separator stay in the output.
    pub start: usize,
    pub end: usize,
}

/// One rewrite a tier made, at offsets in the text as that tier saw it.
pub(super) struct Replacement<'a> {
    pub(super) name: &'a str,
    pub(super) start: usize,
    pub(super) end: usize,
    /// Byte length of the text written in place of `start..end`.
    pub(super) written: usize,
    /// Leading bytes of `start..end` that are not part of the finding: the
    /// blanks between a separator and its value.
    pub(super) lead: usize,
}

/// A marker in the text being rewritten, and what it replaced in the original.
#[derive(Debug)]
struct Marker {
    at: usize,
    len: usize,
    finding: Finding,
}

impl Marker {
    /// How many more bytes the original holds here than the rewritten text.
    fn shrunk_by(&self) -> isize {
        (self.finding.end - self.finding.start) as isize - self.len as isize
    }
}

fn moved(offset: usize, by: isize) -> usize {
    (offset as isize + by) as usize
}

/// The original bytes one rewrite stands for. Every earlier marker it covers or
/// cuts into is consumed, and `to_original` moves past them.
fn original_span(
    earlier: &mut Peekable<IntoIter<Marker>>,
    replacement: &Replacement,
    to_original: &mut isize,
) -> (usize, usize) {
    let finding_start = replacement.start + replacement.lead;
    let mut start = moved(finding_start, *to_original);
    let mut end_inside_marker = None;
    while let Some(marker) = earlier.next_if(|m| m.at < replacement.end) {
        if marker.at < finding_start {
            start = marker.finding.start;
        }
        if marker.at + marker.len > replacement.end {
            end_inside_marker = Some(marker.finding.end);
        }
        *to_original += marker.shrunk_by();
    }
    let end = end_inside_marker.unwrap_or(moved(replacement.end, *to_original));
    (start, end)
}

/// Every marker written so far, in text order.
#[derive(Debug, Default)]
pub(super) struct MarkerLog {
    markers: Vec<Marker>,
}

impl MarkerLog {
    /// Adds one tier's rewrites, sorted and non-overlapping. A rewrite that
    /// covers or cuts into an earlier marker takes that marker's original bytes
    /// as its own, and the earlier finding is dropped.
    pub(super) fn record(&mut self, replacements: &[Replacement]) {
        let mut earlier = std::mem::take(&mut self.markers).into_iter().peekable();
        // Offset in the original minus offset in the text this tier saw.
        let mut to_original: isize = 0;
        // Offset in the text this tier wrote minus offset in the text it saw.
        let mut to_rewritten: isize = 0;

        for replacement in replacements {
            while let Some(marker) = earlier.next_if(|m| m.at + m.len <= replacement.start) {
                to_original += marker.shrunk_by();
                self.markers.push(Marker {
                    at: moved(marker.at, to_rewritten),
                    ..marker
                });
            }
            let (start, end) = original_span(&mut earlier, replacement, &mut to_original);
            self.markers.push(Marker {
                at: moved(replacement.start, to_rewritten),
                len: replacement.written,
                finding: Finding {
                    name: replacement.name.to_string(),
                    start,
                    end,
                },
            });
            to_rewritten +=
                replacement.written as isize - (replacement.end - replacement.start) as isize;
        }
        for marker in earlier {
            self.markers.push(Marker {
                at: moved(marker.at, to_rewritten),
                ..marker
            });
        }
    }

    /// The findings in the order they sit in the original text.
    pub(super) fn into_findings(self) -> Vec<Finding> {
        self.markers
            .into_iter()
            .map(|marker| marker.finding)
            .collect()
    }
}

#[cfg(test)]
mod tests;
