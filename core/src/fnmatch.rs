//! Python's `fnmatch.fnmatchcase`, used to match one resource-name segment.
//!
//! Resource patterns are split on `.` and each segment is matched with
//! `fnmatchcase`, so `fs.read_*` works and `fs.*` matches exactly one segment.
//! Case is always significant: the Python loader calls `fnmatchcase`, not
//! `fnmatch`, so matching does not depend on the host filesystem.
//!
//! `fnmatch` compiles its pattern to a regex; this matches directly. The
//! observable behaviour is the same for `*`, `?`, and `[...]`, including the
//! bracket quirks: an unterminated `[` is a literal `[`, a `]` in first position
//! is a member rather than the terminator, and `[!]` is therefore three literal
//! characters rather than a negated empty set.

#[derive(Debug, Clone, PartialEq)]
enum Token {
    /// `*` — any run of characters, including none and including newlines.
    Star,
    /// `?` — exactly one character, including a newline (`fnmatch` compiles with
    /// `(?s:...)`).
    Any,
    Class {
        negated: bool,
        items: Vec<ClassItem>,
    },
    Literal(char),
}

#[derive(Debug, Clone, PartialEq)]
enum ClassItem {
    Char(char),
    Range(char, char),
}

/// Python's `fnmatch.fnmatchcase(name, pattern)`.
pub fn fnmatchcase(name: &str, pattern: &str) -> bool {
    let tokens = tokenize(pattern);
    let name: Vec<char> = name.chars().collect();
    matches_tokens(&name, &tokens)
}

fn tokenize(pattern: &str) -> Vec<Token> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            '*' => {
                // `fnmatch.translate` collapses runs of `*` into one.
                if tokens.last() != Some(&Token::Star) {
                    tokens.push(Token::Star);
                }
                i += 1;
            }
            '?' => {
                tokens.push(Token::Any);
                i += 1;
            }
            '[' => {
                match class_end(&chars, i + 1) {
                    // No closing bracket: `translate` emits a literal `[`.
                    None => {
                        tokens.push(Token::Literal('['));
                        i += 1;
                    }
                    Some(end) => {
                        tokens.push(parse_class(&chars[i + 1..end]));
                        i = end + 1;
                    }
                }
            }
            c => {
                tokens.push(Token::Literal(c));
                i += 1;
            }
        }
    }

    tokens
}

/// Index of the `]` closing a class opened just before `start`, following
/// `fnmatch.translate`: a leading `!` is skipped, and a `]` in first position is
/// a member rather than the terminator.
fn class_end(chars: &[char], start: usize) -> Option<usize> {
    let mut j = start;
    if j < chars.len() && chars[j] == '!' {
        j += 1;
    }
    if j < chars.len() && chars[j] == ']' {
        j += 1;
    }
    while j < chars.len() && chars[j] != ']' {
        j += 1;
    }
    if j >= chars.len() {
        None
    } else {
        Some(j)
    }
}

fn parse_class(body: &[char]) -> Token {
    let (negated, body) = match body.split_first() {
        Some(('!', rest)) => (true, rest),
        _ => (false, body),
    };

    let mut items = Vec::new();
    let mut i = 0;
    while i < body.len() {
        // `-` is a range only between two members; leading and trailing hyphens
        // are literal.
        if i + 2 < body.len() && body[i + 1] == '-' {
            items.push(ClassItem::Range(body[i], body[i + 2]));
            i += 3;
        } else {
            items.push(ClassItem::Char(body[i]));
            i += 1;
        }
    }

    Token::Class { negated, items }
}

fn class_matches(negated: bool, items: &[ClassItem], c: char) -> bool {
    let found = items.iter().any(|item| match item {
        ClassItem::Char(member) => *member == c,
        // An inverted range (`[z-a]`) matches nothing, which is what the
        // comparison already gives.
        ClassItem::Range(low, high) => *low <= c && c <= *high,
    });
    found != negated
}

fn token_matches(token: &Token, c: char) -> bool {
    match token {
        Token::Any => true,
        Token::Literal(expected) => *expected == c,
        Token::Class { negated, items } => class_matches(*negated, items, c),
        Token::Star => unreachable!("stars are handled by the outer loop"),
    }
}

/// Greedy match with backtracking over the last `*`.
fn matches_tokens(name: &[char], tokens: &[Token]) -> bool {
    let (mut n, mut t) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;

    loop {
        if t < tokens.len() && tokens[t] == Token::Star {
            star = Some((t, n));
            t += 1;
            continue;
        }

        if n < name.len() && t < tokens.len() && token_matches(&tokens[t], name[n]) {
            n += 1;
            t += 1;
            continue;
        }

        if n == name.len() && t == tokens.len() {
            return true;
        }

        // Give the most recent `*` one more character and retry.
        match star {
            Some((star_t, star_n)) if star_n < name.len() => {
                t = star_t + 1;
                n = star_n + 1;
                star = Some((star_t, n));
            }
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stars_and_literals() {
        assert!(fnmatchcase("read_file", "read_*"));
        assert!(fnmatchcase("read_file", "*"));
        assert!(fnmatchcase("read_file", "*file"));
        assert!(fnmatchcase("read_file", "r*d_f*e"));
        assert!(fnmatchcase("", "*"));
        assert!(fnmatchcase("", ""));
        assert!(!fnmatchcase("read_file", "write_*"));
        assert!(!fnmatchcase("read_file", ""));
        assert!(fnmatchcase("read_file", "**"));
    }

    #[test]
    fn case_is_significant() {
        assert!(!fnmatchcase("READ_FILE", "read_*"));
        assert!(!fnmatchcase("read_file", "READ_*"));
    }

    #[test]
    fn single_character_wildcard() {
        assert!(fnmatchcase("abc", "a?c"));
        assert!(!fnmatchcase("ac", "a?c"));
        // `fnmatch` compiles with DOTALL, so `?` matches a newline too.
        assert!(fnmatchcase("a\nc", "a?c"));
    }

    #[test]
    fn character_classes() {
        assert!(fnmatchcase("abc", "[a-c][a-c][a-c]"));
        assert!(fnmatchcase("v2", "v[0-9]"));
        assert!(!fnmatchcase("vx", "v[0-9]"));
        assert!(fnmatchcase("vx", "v[!0-9]"));
        assert!(!fnmatchcase("v2", "v[!0-9]"));
        assert!(fnmatchcase("a-b", "a[-x]b"));
        // A trailing hyphen is a member, not a dangling range.
        assert!(fnmatchcase("a", "[a-]"));
        assert!(fnmatchcase("-", "[a-]"));
        // A `]` in first position is a member.
        assert!(fnmatchcase("]", "[]]"));
        assert!(fnmatchcase("x", "[!]]"));
        assert!(!fnmatchcase("]", "[!]]"));
    }

    #[test]
    fn an_unterminated_class_is_a_literal_bracket() {
        assert!(fnmatchcase("[abc", "[abc"));
        assert!(fnmatchcase("[]", "[]"));
        assert!(!fnmatchcase("a", "[abc"));
        // `[!]` looks like a negated empty set but the leading-`]` rule consumes
        // the terminator, so there is no closing bracket left to find.
        assert!(fnmatchcase("[!]", "[!]"));
        assert!(!fnmatchcase("q", "[!]"));
    }

    #[test]
    fn backtracking_terminates_on_pathological_patterns() {
        assert!(!fnmatchcase(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaab",
            "*a*a*a*a*a*a*a*a*a*c"
        ));
    }
}
