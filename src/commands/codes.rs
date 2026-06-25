//! One-time codes: one entry's, every entry's, their setup as a QR code or URI.

use super::*;

/// Redraw the current code and a bar of the time it has left, once a quarter second, until
/// interrupted.
pub fn otp_watch(global: &Global, entry: &str) -> Result<()> {
    use std::io::Write;
    // Checked first, so a pipe never gets a password prompt for nothing.
    anyhow::ensure!(
        std::io::stdout().is_terminal(),
        "--watch needs a terminal; scripts use `prive otp` (with --min-validity if needed)"
    );
    let db = open(global)?;
    let e = select::select(&db.entries, entry)?;
    let totp = totp_of(e)?;
    output::notice(&format!("{} (Ctrl-C to stop)", e.path()));
    let mut out = std::io::stdout();
    loop {
        let (code, left) = totp.now();
        write!(out, "\r{}", output::watch_line(&code, left, totp.period))?;
        out.flush()?;
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

pub fn otp(
    global: &Global,
    entry: &str,
    min_validity: u64,
    next: bool,
    clip: bool,
    json: bool,
) -> Result<()> {
    let db = open(global)?;
    let e = select::select(&db.entries, entry)?;
    let totp = totp_of(e)?;
    let (mut code, mut left) = totp.now();
    anyhow::ensure!(
        min_validity < totp.period,
        "--min-validity must be shorter than the code's period ({} s)",
        totp.period
    );
    if next {
        let t = otp::unix_now() + left;
        code = totp.code_at(t);
        left += totp.period;
    } else if left < min_validity {
        if std::io::stderr().is_terminal() {
            output::notice(&format!("(waiting {left} s for a fresh code)"));
        }
        std::thread::sleep(std::time::Duration::from_secs(left));
        (code, left) = totp.now();
    }
    if json {
        return output::print_json(&serde_json::json!({
            "code": code,
            "seconds_left": left,
            "period": totp.period,
        }));
    }
    if clip {
        copy_and_tell(&code)?;
    } else {
        output::print(&format!("{code}\n"))?;
    }
    if std::io::stderr().is_terminal() {
        output::notice(&format!("(valid for {left} more seconds)"));
    }
    Ok(())
}

/// The entry's one-time code setup, as a QR code to scan or as an otpauth URI.
pub fn otp_setup(global: &Global, entry: &str, qr: bool) -> Result<()> {
    let db = open(global)?;
    let e = select::select(&db.entries, entry)?;
    let totp = totp_of(e)?;
    let issuer = if e.title.is_empty() {
        e.path()
    } else {
        e.title.clone()
    };
    let uri = Zeroizing::new(totp.to_uri(&issuer, &e.username));
    if qr {
        output::print(&crate::qr::render(&uri)?)?;
        output::notice(
            "Scan it with the authenticator app. Anyone who sees it can make your codes.",
        );
        Ok(())
    } else {
        output::print(&format!("{}\n", uri.as_str()))
    }
}

/// The current code of every entry that has one (or of those matching `query`).
pub fn codes(global: &Global, query: Option<&str>, json: bool, watch: bool) -> Result<()> {
    if watch {
        anyhow::ensure!(
            std::io::stdout().is_terminal(),
            "--watch needs a terminal; scripts use `prive codes --json`"
        );
    }
    let db = open(global)?;
    let pool: Vec<&Entry> = match query {
        Some(q) => select::search(&db.entries, q),
        None => db.entries.iter().collect(),
    };
    let codes: Vec<(String, otp::Totp)> = pool
        .iter()
        .filter_map(|e| otp::Totp::from_entry(e).map(|t| (e.path(), t)))
        .collect();
    if codes.is_empty() {
        return Err(Failure::Missing("no entries with one-time codes".into()).into());
    }
    if watch {
        return watch_codes(&codes);
    }
    let rows: Vec<(String, String, u64)> = codes
        .iter()
        .map(|(path, t)| {
            let (code, left) = t.now();
            (path.clone(), code, left)
        })
        .collect();
    if json {
        // The same fields as `otp --json`, with the entry's path.
        let list: Vec<_> = rows
            .iter()
            .zip(&codes)
            .map(|((p, c, l), (_, t))| {
                serde_json::json!({ "path": p, "code": c, "seconds_left": l, "period": t.period })
            })
            .collect();
        return output::print_json(&list);
    }
    let columns = rows
        .iter()
        .map(|(p, _, _)| output::width(p))
        .max()
        .unwrap_or(0);
    let text: String = rows
        .iter()
        .map(|(p, c, l)| format!("{}  {c:<10} {l:>2}s\n", output::pad(p, columns)))
        .collect();
    output::print_human(&text)
}

/// Draw every code with its time left, then redraw the same lines in place (the cursor goes
/// back up over them) four times a second until interrupted.
fn watch_codes(codes: &[(String, otp::Totp)]) -> Result<()> {
    use std::io::Write;
    let width = codes
        .iter()
        .map(|(p, _)| output::width(p))
        .max()
        .unwrap_or(0);
    output::notice("Ctrl-C to stop");
    let mut out = std::io::stdout();
    let mut first = true;
    loop {
        if !first {
            write!(out, "\x1b[{}A", codes.len())?;
        }
        first = false;
        for (path, t) in codes {
            let (code, left) = t.now();
            writeln!(
                out,
                "\r{}  {}",
                output::pad(&output::visible(path), width),
                output::watch_line(&format!("{code:<10}"), left, t.period)
            )?;
        }
        out.flush()?;
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}
