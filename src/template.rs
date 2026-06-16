//! `get --format`: an entry's fields put into a line of text, with KeePass's placeholder names,
//! so a template reads the same as a KeePass auto-type sequence.
//!
//! `{TITLE}`, `{USERNAME}`, `{PASSWORD}`, `{URL}`, `{NOTES}` (any case), `{S:Field name}` for a
//! custom field (exact name) and `{TOTP}` for the current one-time code. Anything else in
//! braces is left as written, so JSON and shell syntax pass through untouched. Field
//! references in the values are resolved.

use zeroize::Zeroizing;

use crate::entry::Entry;
use crate::error::Failure;

/// Fill in `template` from `entry`. A custom field or one-time code the entry doesn't have is
/// an error, never an empty string a script would carry on with.
pub fn render(template: &str, entry: &Entry, all: &[Entry]) -> anyhow::Result<Zeroizing<String>> {
    let mut out = Zeroizing::new(String::with_capacity(template.len()));
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            // An unclosed brace: the rest is text.
            out.push_str(&rest[open..]);
            return Ok(out);
        };
        let name = &after[..close];
        match value(name, entry, all)? {
            Some(v) => {
                out.push_str(&v);
                rest = &after[close + 1..];
            }
            None => {
                // Not a placeholder: keep the brace and carry on just after it, so a nested
                // `{"user":"{USERNAME}"}` still fills in the inner one.
                out.push('{');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    Ok(out)
}

fn value(name: &str, entry: &Entry, all: &[Entry]) -> anyhow::Result<Option<Zeroizing<String>>> {
    let resolved = |v: &str| Some(crate::refs::resolve(all, v));
    if let Some(field) = name.strip_prefix("S:").or_else(|| name.strip_prefix("s:")) {
        let Some(c) = entry.custom.iter().find(|c| c.name == field) else {
            return Err(Failure::NotFound(format!(
                "{}: field '{field}' (it has: {})",
                entry.path(),
                entry.field_names().join(", ")
            ))
            .into());
        };
        return Ok(resolved(&c.value));
    }
    Ok(match name.to_ascii_uppercase().as_str() {
        "TITLE" => resolved(&entry.title),
        "USERNAME" => resolved(&entry.username),
        "PASSWORD" => resolved(&entry.password),
        "URL" => resolved(&entry.url),
        "NOTES" => resolved(&entry.notes),
        "TOTP" => {
            let Some(t) = crate::otp::Totp::from_entry(entry) else {
                return Err(
                    Failure::NotFound(format!("{}: no one-time code", entry.path())).into(),
                );
            };
            Some(Zeroizing::new(t.now().0))
        }
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::CustomField;

    fn sample() -> Vec<Entry> {
        vec![
            Entry {
                uuid: "00000000000000000000000000000001".into(),
                title: "DB".into(),
                username: "app".into(),
                password: Zeroizing::new("s3cret".into()),
                url: "postgres://db.example.invalid:5432/app".into(),
                custom: vec![CustomField {
                    name: "API key".into(),
                    value: Zeroizing::new("k-123".into()),
                    protected: true,
                }],
                ..Entry::default()
            },
            Entry {
                uuid: "00000000000000000000000000000002".into(),
                title: "Replica".into(),
                username: "{REF:U@I:00000000000000000000000000000001}".into(),
                password: Zeroizing::new("{REF:P@I:00000000000000000000000000000001}".into()),
                ..Entry::default()
            },
        ]
    }

    fn fill(template: &str, n: usize) -> String {
        let all = sample();
        render(template, &all[n], &all).unwrap().to_string()
    }

    #[test]
    fn standard_fields_in_any_case() {
        assert_eq!(fill("{USERNAME}:{password}", 0), "app:s3cret");
        assert_eq!(
            fill("{Title} at {URL}", 0),
            "DB at postgres://db.example.invalid:5432/app"
        );
    }

    #[test]
    fn custom_fields_by_exact_name() {
        assert_eq!(fill("key={S:API key}", 0), "key=k-123");
        let all = sample();
        let err = render("{S:api key}", &all[0], &all).err().unwrap();
        assert!(matches!(
            err.downcast_ref::<Failure>(),
            Some(Failure::NotFound(_))
        ));
    }

    #[test]
    fn references_are_resolved() {
        assert_eq!(fill("{USERNAME}/{PASSWORD}", 1), "app/s3cret");
    }

    #[test]
    fn other_braces_pass_through() {
        assert_eq!(
            fill(r#"{"user":"{USERNAME}","pass":"{PASSWORD}"}"#, 0),
            r#"{"user":"app","pass":"s3cret"}"#
        );
        assert_eq!(fill("${HOME} {nope} {", 0), "${HOME} {nope} {");
        assert_eq!(fill("", 0), "");
    }

    #[test]
    fn a_missing_code_is_an_error() {
        let all = sample();
        assert!(render("{TOTP}", &all[0], &all).is_err());
    }
}
