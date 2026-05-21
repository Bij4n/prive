//! What commands print. Data goes to stdout; everything else (prompts, notices) to stderr.

use std::io::Write;

use anyhow::Result;
use serde::Serialize;

/// Pretty JSON on stdout, one trailing newline.
pub fn print_json<T: Serialize + ?Sized>(value: &T) -> Result<()> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, value)?;
    writeln!(out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn json_shape_of_a_summary() {
        let e = crate::entry::Entry {
            uuid: "u1".into(),
            title: "Bank".into(),
            ..Default::default()
        };
        let v = serde_json::to_value(e.summary()).unwrap();
        assert_eq!(v["path"], "Bank");
        assert_eq!(v["has_otp"], false);
        assert!(v.get("password").is_none());
    }
}
