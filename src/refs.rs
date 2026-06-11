//! KeePass field references: `{REF:P@I:46C9B1FF...}` in a field means "the password of the
//! entry with that UUID". KeePassXC, KeePass and KeePassDX resolve them when a value is used;
//! so does prive, for anything it prints, copies or hands to another program.
//!
//! Form: `{REF:<field>@<search>:<text>}`. Fields: `T` title, `U` username, `P` password,
//! `A` URL, `N` notes, `I` UUID. Searches: `I` by UUID, or `T`, `U`, `P`, `A`, `N` for an
//! entry whose field contains the text (KeePass's rule; the first in path order wins).

use zeroize::Zeroizing;

use crate::entry::Entry;

/// How deep references to references may go before prive stops, as KeePass does.
const MAX_DEPTH: usize = 10;

fn uuid_hex(uuid: &str) -> String {
    uuid.chars()
        .filter(char::is_ascii_hexdigit)
        .collect::<String>()
        .to_ascii_uppercase()
}

fn standard(e: &Entry, letter: char) -> Option<&str> {
    match letter.to_ascii_uppercase() {
        'T' => Some(&e.title),
        'U' => Some(&e.username),
        'P' => Some(&e.password),
        'A' => Some(&e.url),
        'N' => Some(&e.notes),
        _ => None,
    }
}

fn find<'a>(entries: &'a [Entry], search: char, text: &str) -> Option<&'a Entry> {
    let search = search.to_ascii_uppercase();
    if search == 'I' {
        let want = uuid_hex(text);
        return entries.iter().find(|e| uuid_hex(&e.uuid) == want);
    }
    let needle = text.to_lowercase();
    entries
        .iter()
        .find(|e| standard(e, search).is_some_and(|v| v.to_lowercase().contains(&needle)))
}

/// `value` with every reference replaced by what it points at. A reference that points at
/// nothing is left as written, as KeePass does, so the user sees what to fix.
pub fn resolve(entries: &[Entry], value: &str) -> Zeroizing<String> {
    resolve_depth(entries, value, 0)
}

fn resolve_depth(entries: &[Entry], value: &str, depth: usize) -> Zeroizing<String> {
    if depth >= MAX_DEPTH || !value.contains("{REF:") {
        return Zeroizing::new(value.to_string());
    }
    let mut out = Zeroizing::new(String::with_capacity(value.len()));
    let mut rest = value;
    while let Some(start) = rest.find("{REF:") {
        out.push_str(&rest[..start]);
        let after = &rest[start..];
        let Some(end) = after.find('}') else {
            out.push_str(after);
            return out;
        };
        let inner = &after[5..end]; // after "{REF:"
        let replaced = parse(inner).and_then(|(field, search, text)| {
            let target = find(entries, search, text)?;
            let raw = if field.eq_ignore_ascii_case(&'I') {
                uuid_hex(&target.uuid)
            } else {
                standard(target, field)?.to_string()
            };
            Some(resolve_depth(entries, &raw, depth + 1))
        });
        match replaced {
            Some(v) => out.push_str(&v),
            None => out.push_str(&after[..=end]),
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

/// `P@I:46C9...` into ('P', 'I', "46C9...").
fn parse(inner: &str) -> Option<(char, char, &str)> {
    let (spec, text) = inner.split_once(':')?;
    let (field, search) = spec.split_once('@')?;
    let field = single(field)?;
    let search = single(search)?;
    Some((field, search, text))
}

fn single(s: &str) -> Option<char> {
    let mut chars = s.chars();
    let c = chars.next()?;
    chars.next().is_none().then_some(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries() -> Vec<Entry> {
        vec![
            Entry {
                uuid: "00000000-0000-0000-0000-000000000010".into(),
                title: "Bank".into(),
                username: "me".into(),
                password: Zeroizing::new("bank-pw".into()),
                ..Entry::default()
            },
            Entry {
                uuid: "00000000-0000-0000-0000-000000000020".into(),
                title: "Shared".into(),
                password: Zeroizing::new("{REF:P@I:00000000000000000000000000000010}".into()),
                ..Entry::default()
            },
            Entry {
                uuid: "00000000-0000-0000-0000-000000000030".into(),
                title: "Loop".into(),
                password: Zeroizing::new("{REF:P@T:Loop}".into()),
                ..Entry::default()
            },
        ]
    }

    #[test]
    fn references_by_uuid_and_by_title() {
        let e = entries();
        assert_eq!(
            resolve(&e, "{REF:P@I:00000000000000000000000000000010}").as_str(),
            "bank-pw"
        );
        assert_eq!(
            resolve(&e, "user {REF:U@T:bank} pw {REF:P@T:Bank}!").as_str(),
            "user me pw bank-pw!"
        );
        // A reference to a reference.
        assert_eq!(resolve(&e, &e[1].password).as_str(), "bank-pw");
    }

    #[test]
    fn broken_and_looping_references_stay_visible() {
        let e = entries();
        assert_eq!(resolve(&e, "{REF:P@I:FFFF}").as_str(), "{REF:P@I:FFFF}");
        assert_eq!(resolve(&e, "{REF:X@I:1}").as_str(), "{REF:X@I:1}");
        assert_eq!(
            resolve(&e, "{REF:P@I:unclosed").as_str(),
            "{REF:P@I:unclosed"
        );
        // Self-reference: stops after MAX_DEPTH instead of looping forever.
        assert_eq!(resolve(&e, "{REF:P@T:Loop}").as_str(), "{REF:P@T:Loop}");
        assert_eq!(resolve(&e, "no refs").as_str(), "no refs");
    }
}
