//! The slice of Python's `difflib` the policy loader depends on.
//!
//! When a policy file carries an unrecognized key, the loader suggests the key
//! the author probably meant. Getting a *different* suggestion out of the Rust
//! loader would mean the two implementations disagree about the same broken
//! file, so the similarity measure is ported rather than approximated: this is
//! `SequenceMatcher.ratio` and `get_close_matches`, not an edit distance that
//! happens to rank most cases the same way.
//!
//! Only the no-junk path is reproduced. `difflib`'s "autojunk" heuristic
//! activates at 200 elements, and these sequences are policy key names.

use std::collections::HashMap;

/// Python's `SequenceMatcher(None, a, b).ratio()`.
///
/// `2 * matched / (len(a) + len(b))`, where `matched` is the total size of the
/// recursive longest-matching-block decomposition (Ratcliff/Obershelp).
pub fn ratio(a: &str, b: &str) -> f64 {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let length = a.len() + b.len();
    if length == 0 {
        return 1.0;
    }

    // Index of b, in the same shape `difflib` builds: element -> positions.
    let mut positions: HashMap<char, Vec<usize>> = HashMap::new();
    for (index, c) in b.iter().enumerate() {
        positions.entry(*c).or_default().push(index);
    }

    let mut matched = 0usize;
    let mut queue = vec![(0, a.len(), 0, b.len())];
    while let Some((alo, ahi, blo, bhi)) = queue.pop() {
        let (i, j, k) = longest_match(&a, &positions, alo, ahi, blo, bhi);
        if k == 0 {
            continue;
        }
        matched += k;
        if alo < i && blo < j {
            queue.push((alo, i, blo, j));
        }
        if i + k < ahi && j + k < bhi {
            queue.push((i + k, ahi, j + k, bhi));
        }
    }

    2.0 * matched as f64 / length as f64
}

/// `difflib`'s `find_longest_match`, restricted to the no-junk case.
///
/// Returns `(i, j, size)`: the earliest longest block, preferring the lowest
/// `i` and then the lowest `j`, which is the tie-break Python makes and which
/// the recursion below inherits.
// The index is the loop's subject, not just a way to reach an element: `best_i`
// is computed from it. Rewriting this as an `enumerate().skip().take()` chain
// would obscure the correspondence with `difflib`'s own loop.
#[allow(clippy::needless_range_loop)]
fn longest_match(
    a: &[char],
    positions: &HashMap<char, Vec<usize>>,
    alo: usize,
    ahi: usize,
    blo: usize,
    bhi: usize,
) -> (usize, usize, usize) {
    let (mut best_i, mut best_j, mut best_size) = (alo, blo, 0usize);

    // Length of the run of matches ending at each position of `b`, carried one
    // row of `a` at a time.
    let mut run_ending_at: HashMap<usize, usize> = HashMap::new();
    for i in alo..ahi {
        let mut next: HashMap<usize, usize> = HashMap::new();
        if let Some(js) = positions.get(&a[i]) {
            for &j in js {
                if j < blo {
                    continue;
                }
                if j >= bhi {
                    break;
                }
                let k = j
                    .checked_sub(1)
                    .and_then(|prev| run_ending_at.get(&prev).copied())
                    .unwrap_or(0)
                    + 1;
                next.insert(j, k);
                if k > best_size {
                    best_i = i + 1 - k;
                    best_j = j + 1 - k;
                    best_size = k;
                }
            }
        }
        run_ending_at = next;
    }

    (best_i, best_j, best_size)
}

/// Python's `difflib.get_close_matches(word, possibilities, n=1, cutoff)`.
///
/// `possibilities` must already be in the order the caller wants ties resolved
/// against; the loader passes them sorted, as the Python loader does.
pub fn closest_match<'a>(word: &str, possibilities: &'a [String], cutoff: f64) -> Option<&'a str> {
    let mut best: Option<(f64, &'a str)> = None;
    for candidate in possibilities {
        // Python sets seq2 to the word and seq1 to the candidate; the argument
        // order is preserved because `ratio` is not guaranteed symmetric.
        let score = ratio(candidate, word);
        if score < cutoff {
            continue;
        }
        // `heapq.nlargest` compares the whole `(score, candidate)` tuple, so an
        // exact tie goes to the lexicographically greater name.
        let better = match best {
            None => true,
            Some((best_score, best_name)) => {
                score > best_score || (score == best_score && candidate.as_str() > best_name)
            }
        };
        if better {
            best = Some((score, candidate.as_str()));
        }
    }
    best.map(|(_, name)| name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Values taken from CPython's `difflib` on the exact strings the policy
    /// loader compares. `tests/test_differential.py` re-derives them from the
    /// live Python implementation, so a drift here is caught twice.
    #[test]
    fn ratio_matches_cpython() {
        let cases: &[(&str, &str, f64)] = &[
            ("", "", 1.0),
            ("abc", "abc", 1.0),
            ("resource", "resorce", 14.0 / 15.0),
            ("action", "actoin", 5.0 / 6.0),
            ("reason", "resaon", 5.0 / 6.0),
            ("where", "wher", 8.0 / 9.0),
            ("when", "whn", 6.0 / 7.0),
            ("name", "nmae", 0.75),
            // A single shared character out of fourteen, and the recursion
            // finds nothing either side of it.
            ("resource", "action", 1.0 / 7.0),
            ("abcd", "dcba", 0.25),
        ];
        for (a, b, expected) in cases {
            let got = ratio(a, b);
            assert!(
                (got - expected).abs() < 1e-12,
                "ratio({a:?}, {b:?}) = {got}, expected {expected}"
            );
        }
    }

    #[test]
    fn closest_match_honours_the_cutoff() {
        let allowed: Vec<String> = ["action", "name", "reason", "resource", "when", "where"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(closest_match("resorce", &allowed, 0.8), Some("resource"));
        assert_eq!(closest_match("actoin", &allowed, 0.8), Some("action"));
        assert_eq!(closest_match("wher", &allowed, 0.8), Some("where"));
        // Nothing close enough is better than a misleading suggestion.
        assert_eq!(closest_match("tests", &allowed, 0.8), None);
        assert_eq!(closest_match("resource", &allowed, 0.8), Some("resource"));
    }
}
