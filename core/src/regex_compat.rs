//! Translating a Python `re` pattern into one `fancy-regex` reads the same way.
//!
//! Every regex in a policy file was written against Python's `re`, so the Rust
//! engine has to answer the way `re` answers. Two anchors do not, and both are
//! security-relevant because they are how deny patterns pin the *end* of a value:
//!
//! - **`$`.** Python's `$` also matches immediately before a single trailing
//!   newline. Rust's does not. Left untranslated, a deny rule spelled
//!   `matches: ['passwd$']` would fire in Python for `"/etc/passwd\n"` and
//!   **not** fire in Rust — the Rust engine would allow a call the Python engine
//!   denies. That is a fail-open divergence, which is the one direction this port
//!   cannot tolerate, so `$` becomes `(?=\n?\z)`.
//! - **`\Z`.** Python's spelling of "end of string". `fancy-regex` accepts `\Z`
//!   but gives it Perl's meaning, which is Python's `$` — the same fail-open
//!   shape one step over. It becomes `\z`, the Rust spelling of Python's `\Z`.
//!
//! Backreference syntax is translated too (`(?P=name)` → `\k<name>`), since it
//! would otherwise be a load error on a pattern that is perfectly valid Python.
//!
//! ## What is deliberately not translated
//!
//! Under an inline `(?m)` flag, `$` means end-of-line in both engines, so it is
//! left alone. Python-only flags (`(?a)`, `(?u)`, `(?L)`) are not rewritten and
//! fail to compile — a loud load error rather than a silently different pattern,
//! which fails closed. Same for `(?#comment)` groups and `\N{NAME}` escapes.

/// Rewrite a Python `re` pattern as an equivalent `fancy-regex` pattern.
///
/// Character-class bodies and escaped characters are passed through untouched:
/// `[$]` and `\$` are a literal dollar sign in both engines and must stay one.
pub fn translate(pattern: &str) -> String {
    // Under `(?m)` the two engines already agree about `$`, and rewriting it
    // would change its meaning rather than preserve it.
    let multiline = has_multiline_flag(pattern);

    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();
    let mut in_class = false;

    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                out.push('\\');
                match chars.next() {
                    // Python's end-of-string anchor, spelled `\z` in Rust.
                    Some('Z') if !in_class => out.push('z'),
                    Some(next) => out.push(next),
                    // A trailing backslash is invalid in both engines; leave it
                    // for the compiler to reject.
                    None => {}
                }
            }
            '[' if !in_class => {
                in_class = true;
                out.push('[');
                // A `]` immediately after `[` or `[^` is a literal, so it must
                // not be read as closing the class.
                if chars.peek() == Some(&'^') {
                    out.push(chars.next().unwrap());
                }
                if chars.peek() == Some(&']') {
                    out.push(chars.next().unwrap());
                }
            }
            ']' if in_class => {
                in_class = false;
                out.push(']');
            }
            '$' if !in_class && !multiline => out.push_str("(?=\n?\\z)"),
            '(' if !in_class => {
                // `(?P=name)` is Python's named backreference; Rust spells it
                // `\k<name>`. `(?P<name>...)` is accepted by both.
                match strip_named_backreference(&mut chars) {
                    Some(name) => out.push_str(&format!("\\k<{name}>")),
                    None => out.push('('),
                }
            }
            c => out.push(c),
        }
    }

    out
}

/// Consume `?P=name)` if that is what comes next, returning the name.
fn strip_named_backreference(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
) -> Option<String> {
    let mut lookahead = chars.clone();
    if lookahead.next() != Some('?')
        || lookahead.next() != Some('P')
        || lookahead.next() != Some('=')
    {
        return None;
    }
    let mut name = String::new();
    loop {
        match lookahead.next() {
            Some(')') => break,
            Some(c) if c.is_alphanumeric() || c == '_' => name.push(c),
            _ => return None,
        }
    }
    if name.is_empty() {
        return None;
    }
    *chars = lookahead;
    Some(name)
}

/// True when the pattern turns on multi-line mode with an inline flag.
///
/// Scans for `(?flags)` and `(?flags:` groups outside character classes. It does
/// not track whether the group has been closed, so a pattern that enables `m` in
/// a subgroup suppresses the `$` rewrite everywhere — conservative in the safe
/// direction: `$` keeps Rust's stricter meaning, which cannot make a deny rule
/// match less than Python's would at the end of the subject.
fn has_multiline_flag(pattern: &str) -> bool {
    let mut chars = pattern.chars().peekable();
    let mut in_class = false;

    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                chars.next();
            }
            '[' if !in_class => in_class = true,
            ']' if in_class => in_class = false,
            '(' if !in_class => {
                if chars.peek() != Some(&'?') {
                    continue;
                }
                let mut lookahead = chars.clone();
                lookahead.next();
                let mut flags = String::new();
                loop {
                    match lookahead.next() {
                        // `(?-m)` turns the flag off, so only a leading `m`
                        // counts.
                        Some(')' | ':') => {
                            let enabled = flags.split('-').next().unwrap_or("");
                            if enabled.contains('m') {
                                return true;
                            }
                            break;
                        }
                        Some(c @ ('i' | 'm' | 's' | 'x' | 'u' | 'a' | 'L' | '-')) => flags.push(c),
                        _ => break,
                    }
                }
            }
            _ => {}
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every expectation here was read off Python's `re` and then off
    /// `fancy-regex`, because the whole point is that the two agree.
    fn searches(pattern: &str, subject: &str) -> bool {
        fancy_regex::Regex::new(&translate(pattern))
            .expect("translated pattern must compile")
            .is_match(subject)
            .unwrap_or(false)
    }

    #[test]
    fn dollar_matches_before_a_single_trailing_newline_as_python_does() {
        // The fail-open case: without translation the Rust engine would let
        // `"/etc/passwd\n"` through a rule that denies `"/etc/passwd"`.
        assert!(searches("passwd$", "/etc/passwd"));
        assert!(searches("passwd$", "/etc/passwd\n"));
        // One newline only, and nothing after it.
        assert!(!searches("passwd$", "/etc/passwd\n\n"));
        assert!(!searches("passwd$", "/etc/passwd\nx"));
        assert!(!searches("passwd$", "/etc/passwd_backup"));
    }

    #[test]
    fn python_end_of_string_is_stricter_than_dollar() {
        assert!(searches(r"passwd\Z", "/etc/passwd"));
        assert!(!searches(r"passwd\Z", "/etc/passwd\n"));
        assert!(searches(r"\Apasswd\Z", "passwd"));
    }

    #[test]
    fn a_literal_dollar_stays_literal() {
        assert!(searches(r"cost\$", "cost$"));
        assert!(searches("[$]", "a$b"));
        assert!(!searches("[$]", "ab"));
        // A `]` right after `[` is a literal member, not the terminator, so the
        // `$` after it is still inside the class.
        assert!(searches("[]$]", "$"));
        assert!(searches("[]$]", "]"));
        // Inside a class `\Z` is not an anchor either.
        assert_eq!(translate(r"[\Z]"), r"[\Z]");
    }

    #[test]
    fn multiline_patterns_are_left_alone() {
        assert_eq!(translate("(?m)^x$"), "(?m)^x$");
        assert_eq!(translate("(?im)x$"), "(?im)x$");
        assert_eq!(translate("(?m:x$)"), "(?m:x$)");
        // No `m`, so the rewrite still applies.
        assert_eq!(translate("(?i)x$"), "(?i)x(?=\n?\\z)");
    }

    #[test]
    fn named_groups_and_backreferences_translate() {
        assert_eq!(
            translate("(?P<seg>[a-z]+)/(?P=seg)"),
            "(?P<seg>[a-z]+)/\\k<seg>"
        );
        assert!(searches("(?P<seg>[a-z]+)/(?P=seg)", "etc/etc"));
        assert!(!searches("(?P<seg>[a-z]+)/(?P=seg)", "etc/var"));
        // Not a backreference; left as an ordinary group opener.
        assert_eq!(translate("(?:a)"), "(?:a)");
        assert_eq!(translate("(a)"), "(a)");
    }

    #[test]
    fn lookaround_still_compiles_because_that_is_why_fancy_regex_is_here() {
        assert!(searches(r"^(?!/tmp/).*\.key$", "/etc/tls.key"));
        assert!(!searches(r"^(?!/tmp/).*\.key$", "/tmp/tls.key"));
    }

    #[test]
    fn a_pattern_with_no_anchors_is_unchanged() {
        for pattern in [r"\.\.", "etc", r"^/proc/\d+", r"a{2,3}b", "(a|b)+"] {
            assert_eq!(translate(pattern), pattern);
        }
    }
}
