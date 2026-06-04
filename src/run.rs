//! `prive run`: start a command with secrets in its environment, never on disk or screen.

use anyhow::{Result, bail};
use zeroize::Zeroizing;

use crate::entry::Entry;
use crate::error::Failure;
use crate::select;

/// `NAME=ENTRY` (the entry's password) or `NAME=ENTRY:FIELD`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvSpec {
    pub name: String,
    pub target: String,
}

/// Environment variable names: letters, digits and `_`, not starting with a digit.
pub fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub fn parse_spec(s: &str) -> Result<EnvSpec> {
    let Some((name, target)) = s.split_once('=') else {
        bail!("'{s}': expected NAME=ENTRY or NAME=ENTRY:FIELD");
    };
    if !valid_name(name) {
        bail!("'{name}' is not a valid environment variable name");
    }
    if target.is_empty() {
        bail!("'{s}': no entry named");
    }
    Ok(EnvSpec {
        name: name.to_string(),
        target: target.to_string(),
    })
}

/// The value a spec names. The whole target is tried as an entry name first, because titles
/// may contain `:`; only if that matches nothing is the part after the last `:` a field.
pub fn resolve(entries: &[Entry], spec: &EnvSpec) -> Result<Zeroizing<String>> {
    let not_found = match select::select(entries, &spec.target) {
        Ok(e) => return Ok(Zeroizing::new(e.password.to_string())),
        Err(f @ Failure::Ambiguous { .. }) => return Err(f.into()),
        Err(f) => f,
    };
    if let Some((entry, field)) = spec.target.rsplit_once(':')
        && let Ok(e) = select::select(entries, entry)
    {
        let value = e.field(field).ok_or_else(|| {
            Failure::NotFound(format!("{}: field '{field}' (for {})", e.path(), spec.name))
        })?;
        return Ok(Zeroizing::new(value.to_string()));
    }
    Err(not_found.into())
}

/// Names `--from` exports: upper case, digits and `_`, the way environment variables are
/// written (`AWS_ACCESS_KEY_ID`). Fields like `plan` or `otp` stay put.
pub fn exported_name(name: &str) -> bool {
    valid_name(name)
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        && !crate::otp::is_otp_field(name)
}

/// Every custom field of `entry` named like an environment variable, e.g. an entry holding
/// `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` as fields.
pub fn fields_as_env(entry: &Entry) -> Vec<(String, Zeroizing<String>)> {
    entry
        .custom
        .iter()
        .filter(|c| exported_name(&c.name))
        .map(|c| (c.name.clone(), Zeroizing::new(c.value.to_string())))
        .collect()
}

/// Replace this process with `program` (Unix) or run it and pass its exit code on (Windows),
/// with `vars` added to the environment. Returns only if starting it failed.
pub fn exec(program: &str, args: &[String], vars: &[(String, Zeroizing<String>)]) -> Result<i32> {
    use anyhow::Context;
    let mut cmd = std::process::Command::new(program);
    cmd.args(args);
    for (name, value) in vars {
        cmd.env(name, value.as_str());
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // exec only comes back on failure.
        let err = cmd.exec();
        Err(err).with_context(|| format!("running {program}"))
    }
    #[cfg(not(unix))]
    {
        let status = cmd.status().with_context(|| format!("running {program}"))?;
        Ok(status.code().unwrap_or(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries() -> Vec<Entry> {
        vec![
            Entry {
                uuid: "1".into(),
                group: "Work".into(),
                title: "GitHub".into(),
                username: "demo".into(),
                password: Zeroizing::new("gh-pw".into()),
                ..Entry::default()
            },
            Entry {
                uuid: "2".into(),
                title: "Odd: name".into(),
                password: Zeroizing::new("odd-pw".into()),
                ..Entry::default()
            },
        ]
    }

    #[test]
    fn specs() {
        assert_eq!(
            parse_spec("TOKEN=Work/GitHub:username").unwrap(),
            EnvSpec {
                name: "TOKEN".into(),
                target: "Work/GitHub:username".into()
            }
        );
        for bad in ["NOEQUALS", "1X=a", "A-B=x", "X="] {
            assert!(parse_spec(bad).is_err(), "{bad}");
        }
        assert!(valid_name("_A1") && !valid_name("") && !valid_name("é"));
    }

    #[test]
    fn values() {
        let e = entries();
        let get = |s: &str| resolve(&e, &parse_spec(s).unwrap()).map(|v| v.to_string());
        assert_eq!(get("P=Work/GitHub").unwrap(), "gh-pw");
        assert_eq!(get("U=Work/GitHub:username").unwrap(), "demo");
        // A title with a colon still works as a whole name.
        assert_eq!(get("O=Odd: name").unwrap(), "odd-pw");
        assert!(get("X=Work/GitHub:nope").is_err());
        assert!(get("X=Nobody").is_err());
    }

    #[test]
    fn exportable_fields() {
        let e = Entry {
            custom: vec![
                crate::entry::CustomField {
                    name: "AWS_ACCESS_KEY_ID".into(),
                    value: Zeroizing::new("AKIA".into()),
                    protected: false,
                },
                crate::entry::CustomField {
                    name: "API key".into(),
                    value: Zeroizing::new("no".into()),
                    protected: true,
                },
            ],
            ..Entry::default()
        };
        let vars = fields_as_env(&e);
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].0, "AWS_ACCESS_KEY_ID");
    }

    #[test]
    fn only_upper_case_names_are_exported() {
        assert!(exported_name("AWS_REGION"));
        assert!(exported_name("_X1"));
        assert!(!exported_name("plan"));
        assert!(!exported_name("Api_Key"));
        assert!(
            !exported_name("OTP"),
            "one-time code settings are never exported"
        );
        assert!(!exported_name("1ABC"));
    }
}
