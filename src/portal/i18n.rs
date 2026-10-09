//! Portal strings in English and Korean, chosen by `Accept-Language`.
//!
//! Strings live in `templates/i18n/<lang>.toml` (compiled in). The files use
//! a small subset of TOML: `"key" = "value"` lines, `#` comments, and the
//! escapes `\"`, `\\`, `\n`, `\t`. A key missing from a language falls back to
//! English, then to the key itself, so a page never renders empty text.

use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    En,
    Ko,
}

impl Lang {
    pub fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Ko => "ko",
        }
    }
}

/// Pick the best supported language from an `Accept-Language` value.
/// English is the default and wins ties.
pub fn pick_lang(accept_language: Option<&str>) -> Lang {
    let Some(value) = accept_language else {
        return Lang::En;
    };
    // Weights in thousandths; the best of each language over its tags.
    let (mut en, mut ko) = (0u32, 0u32);
    for item in value.split(',').take(32) {
        let mut parts = item.split(';');
        let tag = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        let mut q = 1000u32;
        for p in parts {
            if let Some(v) = p.trim().strip_prefix("q=") {
                q = match v.trim().parse::<f32>() {
                    Ok(f) if (0.0..=1.0).contains(&f) => (f * 1000.0).round() as u32,
                    _ => 0,
                };
            }
        }
        let primary = tag.split('-').next().unwrap_or("");
        match primary {
            "en" => en = en.max(q),
            "ko" => ko = ko.max(q),
            _ => {}
        }
    }
    if ko > en { Lang::Ko } else { Lang::En }
}

/// Parse the TOML subset into a map. Errors name the 1-based line.
pub fn parse_strings(src: &str) -> Result<HashMap<String, String>, String> {
    let mut out = HashMap::new();
    for (i, raw) in src.lines().enumerate() {
        let n = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, rest) = quoted(line).ok_or_else(|| format!("line {n}: expected a quoted key"))?;
        let rest = rest
            .trim_start()
            .strip_prefix('=')
            .ok_or_else(|| format!("line {n}: expected '='"))?;
        let (value, tail) = quoted(rest.trim_start())
            .ok_or_else(|| format!("line {n}: expected a quoted value"))?;
        let tail = tail.trim();
        if !(tail.is_empty() || tail.starts_with('#')) {
            return Err(format!("line {n}: unexpected text after the value"));
        }
        if out.insert(key, value).is_some() {
            return Err(format!("line {n}: duplicate key"));
        }
    }
    Ok(out)
}

/// A double-quoted string at the start of `s`, and what follows it.
fn quoted(s: &str) -> Option<(String, &str)> {
    let mut chars = s.strip_prefix('"')?.char_indices();
    let body = &s[1..];
    let mut out = String::new();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Some((out, &body[i + 1..])),
            '\\' => match chars.next()?.1 {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                'n' => out.push('\n'),
                't' => out.push('\t'),
                _ => return None,
            },
            c => out.push(c),
        }
    }
    None
}

/// One language's strings.
pub struct Strings {
    own: HashMap<String, String>,
    fallback: Option<&'static HashMap<String, String>>,
}

impl Strings {
    /// The string for `key` (English, then the key itself, when missing).
    pub fn get<'a>(&'a self, key: &'a str) -> &'a str {
        self.own
            .get(key)
            .or_else(|| self.fallback.and_then(|f| f.get(key)))
            .map_or(key, String::as_str)
    }

    /// `get(key)` with `{name}` replaced by `value` (once, left to right; the
    /// value is never re-scanned).
    pub fn fmt(&self, key: &str, name: &str, value: &str) -> String {
        let template = self.get(key);
        let needle = format!("{{{name}}}");
        match template.split_once(&needle) {
            Some((head, tail)) => format!("{head}{value}{}", tail.replace(&needle, value)),
            None => template.to_string(),
        }
    }

    /// Whether the language itself defines `key`.
    pub fn has(&self, key: &str) -> bool {
        self.own.contains_key(key)
    }

    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.own.keys()
    }
}

const EN_SRC: &str = include_str!("../../templates/i18n/en.toml");
const KO_SRC: &str = include_str!("../../templates/i18n/ko.toml");

struct Loaded {
    en: Strings,
    ko: Strings,
}

fn load() -> &'static Loaded {
    static LOADED: OnceLock<Loaded> = OnceLock::new();
    static EN_MAP: OnceLock<HashMap<String, String>> = OnceLock::new();
    LOADED.get_or_init(|| {
        // The files are compiled in and covered by tests; a parse failure here
        // would be a build defect, so degrade to key-as-text instead of panicking.
        let en_map = EN_MAP.get_or_init(|| parse_strings(EN_SRC).unwrap_or_default());
        Loaded {
            en: Strings {
                own: en_map.clone(),
                fallback: None,
            },
            ko: Strings {
                own: parse_strings(KO_SRC).unwrap_or_default(),
                fallback: Some(en_map),
            },
        }
    })
}

/// The compiled-in strings for `lang`.
pub fn strings(lang: Lang) -> &'static Strings {
    let l = load();
    match lang {
        Lang::En => &l.en,
        Lang::Ko => &l.ko,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_language_selection() {
        assert_eq!(pick_lang(None), Lang::En);
        assert_eq!(pick_lang(Some("")), Lang::En);
        assert_eq!(pick_lang(Some("ko")), Lang::Ko);
        assert_eq!(pick_lang(Some("ko-KR,ko;q=0.9,en;q=0.8")), Lang::Ko);
        assert_eq!(pick_lang(Some("en-US,en;q=0.9,ko;q=0.8")), Lang::En);
        assert_eq!(pick_lang(Some("fr-FR, ko;q=0.5")), Lang::Ko);
        assert_eq!(pick_lang(Some("ko;q=0.4, en;q=0.6")), Lang::En);
        assert_eq!(pick_lang(Some("ko;q=0")), Lang::En);
        assert_eq!(pick_lang(Some("KO-kr")), Lang::Ko);
        assert_eq!(pick_lang(Some("*")), Lang::En);
        assert_eq!(pick_lang(Some("de, fr")), Lang::En);
        assert_eq!(pick_lang(Some(&"ko,".repeat(5000))), Lang::Ko);
        assert_eq!(pick_lang(Some("ko;q=abc")), Lang::En);
    }

    #[test]
    fn toml_subset_parses_and_reports_lines() {
        let m =
            parse_strings("# c\n\n\"a.b\" = \"x \\\"y\\\" \\\\ z\"\n\"c\" = \"한국어\" # tail\n")
                .unwrap();
        assert_eq!(m["a.b"], "x \"y\" \\ z");
        assert_eq!(m["c"], "한국어");
        let e = parse_strings("\"a\" = \"x\"\nnot a pair\n").unwrap_err();
        assert!(e.contains("line 2"), "{e}");
        assert!(parse_strings("\"a\" = \"x\"\n\"a\" = \"y\"\n").is_err());
        assert!(parse_strings("\"a\" = \"unterminated\n").is_err());
        assert!(parse_strings("\"a\" = \"bad \\q escape\"\n").is_err());
    }

    #[test]
    fn both_languages_define_the_same_keys() {
        let en: std::collections::BTreeSet<_> = strings(Lang::En).keys().cloned().collect();
        let ko: std::collections::BTreeSet<_> = strings(Lang::Ko).keys().cloned().collect();
        assert!(!en.is_empty());
        assert_eq!(en, ko, "en.toml and ko.toml must define the same keys");
    }

    #[test]
    fn placeholders_match_between_languages() {
        let placeholders = |s: &str| {
            let mut v: Vec<String> = Vec::new();
            let mut rest = s;
            while let Some(i) = rest.find('{') {
                if let Some(j) = rest[i..].find('}') {
                    v.push(rest[i..=i + j].to_string());
                    rest = &rest[i + j + 1..];
                } else {
                    break;
                }
            }
            v.sort();
            v
        };
        for k in strings(Lang::En).keys() {
            assert_eq!(
                placeholders(strings(Lang::En).get(k)),
                placeholders(strings(Lang::Ko).get(k)),
                "{k}"
            );
        }
    }

    #[test]
    fn every_key_a_template_uses_exists() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("templates");
        let mut used = std::collections::BTreeSet::new();
        for entry in std::fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            if p.extension().is_some_and(|e| e == "html") {
                let text = std::fs::read_to_string(&p).unwrap();
                for call in ["t.get(\"", "t.fmt(\""] {
                    let mut rest = text.as_str();
                    while let Some(i) = rest.find(call) {
                        rest = &rest[i + call.len()..];
                        let end = rest.find('"').unwrap();
                        used.insert(rest[..end].to_string());
                    }
                }
            }
        }
        assert!(used.len() > 10, "templates should use many keys: {used:?}");
        for k in &used {
            assert!(strings(Lang::En).has(k), "en.toml lacks {k}");
            assert!(strings(Lang::Ko).has(k), "ko.toml lacks {k}");
        }
    }

    #[test]
    fn lookup_formats_and_falls_back() {
        let en = strings(Lang::En);
        assert_eq!(
            en.fmt("login.button", "provider", "Google"),
            "Continue with Google"
        );
        assert!(
            strings(Lang::Ko)
                .fmt("continue.body", "host", "app.example.test")
                .contains("app.example.test")
        );
        assert_eq!(en.get("no.such.key"), "no.such.key");
        assert_eq!(strings(Lang::Ko).get("lang.code"), "ko");
        // A value containing a brace is not re-expanded.
        assert_eq!(
            en.fmt("login.button", "provider", "{provider}"),
            "Continue with {provider}"
        );
    }
}
