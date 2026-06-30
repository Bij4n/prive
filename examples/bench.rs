//! Time what prive's commands do, stage by stage, on a database of your choice:
//!
//! ```text
//! cargo run --release --example bench -- path/to/db.kdbx < password.txt
//! ```
//!
//! The password is the first line of stdin. Nothing is printed but timings and counts, never a
//! value. `docs/performance.md` was measured this way, on a 5,000-entry KeePassXC database.

use std::io::BufRead;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

fn time<T>(label: &str, f: impl FnOnce() -> T) -> T {
    let started = Instant::now();
    let out = f();
    let took = started.elapsed();
    println!("{label:<40} {:>9.1} ms", ms(took));
    out
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: bench DATABASE < password"))?;
    let path = std::path::PathBuf::from(path);
    let mut line = Zeroizing::new(String::new());
    std::io::stdin().lock().read_line(&mut line)?;
    let creds = prive::unlock::Credentials {
        password: Some(Zeroizing::new(
            line.trim_end_matches(['\r', '\n']).to_string(),
        )),
        keyfile: None,
    };

    let bytes = time("read the file", || prive::db::read_file(&path))?;
    let db = time("open (key derivation, decrypt, walk)", || {
        prive::db::Db::from_bytes(&path, &bytes, &creds)
    })?;
    println!(
        "{} entries, {} groups, {}",
        db.entries.len(),
        db.info.groups,
        db.info.kdf.describe()
    );
    time("ls (render every line)", || {
        let all: Vec<&prive::entry::Entry> = db.entries.iter().collect();
        prive::output::render_list(&all).len()
    });
    let paths: Vec<String> = db.entries.iter().map(|e| e.path()).collect();
    // One command looks up one entry; this does all of them to get a steady figure.
    let started = Instant::now();
    let found = paths
        .iter()
        .filter(|p| prive::select::select(&db.entries, p).is_ok())
        .count();
    println!(
        "{:<40} {:>9.3} ms",
        "select an entry by path (each)",
        ms(started.elapsed()) / found.max(1) as f64
    );
    time("search (a word that matches nothing)", || {
        prive::select::search(&db.entries, "nothing-matches-this").len()
    });
    time("codes (every one-time code)", || {
        db.entries
            .iter()
            .filter_map(prive::otp::Totp::from_entry)
            .map(|t| t.now().0.len())
            .sum::<usize>()
    });
    time("audit (strength of every password)", || {
        prive::audit::audit(
            &db.entries,
            &prive::audit::Options {
                max_age_days: 0,
                ..prive::audit::Options::default()
            },
        )
        .map(|r| r.findings.len())
    })?;
    time("diff against itself", || {
        prive::diff::compare(&db.entries, &db.entries).len()
    });
    time("export as csv", || {
        let all: Vec<&prive::entry::Entry> = db.entries.iter().collect();
        prive::export::csv(&all, &db.entries).map(|b| b.len())
    })?;
    Ok(())
}
