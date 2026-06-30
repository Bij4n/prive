//! Commands around other programs and files: run, gen, import, config, git's helper, completions.

use super::*;

pub fn run(global: &Global, specs: &[String], from: &[String], command: &[String]) -> Result<()> {
    let specs: Vec<crate::run::EnvSpec> = specs
        .iter()
        .map(|s| crate::run::parse_spec(s))
        .collect::<Result<_>>()?;
    let db = open(global)?;
    let mut vars = Vec::new();
    for name in from {
        let e = select::select(&db.entries, name)?;
        let fields = crate::run::fields_as_env(e, &db.entries);
        if fields.is_empty() {
            anyhow::bail!(
                "{}: no custom fields named like environment variables",
                e.path()
            );
        }
        vars.extend(fields);
    }
    // --env comes last, so it overrides a field of the same name.
    for s in &specs {
        vars.push((s.name.clone(), crate::run::resolve(&db.entries, s)?));
    }
    drop(db); // the child gets only what it asked for
    let (program, args) = command.split_first().expect("clap requires a command");
    let code = crate::run::exec(program, args, &vars)?;
    std::process::exit(code);
}

/// Read an export and print what would come across. Needs no database.
pub fn import_check(
    file: &std::path::Path,
    from: Option<crate::import::Format>,
    map: &[String],
    list: bool,
) -> Result<()> {
    use anyhow::Context;
    let text = Zeroizing::new(
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?,
    );
    let map = crate::import::generic::parse_map(map)?;
    // --map only makes sense for the generic CSV reader, so it implies --from csv.
    let format = match (from, map.is_empty()) {
        (Some(f), _) => f,
        (None, false) => crate::import::Format::Csv,
        (None, true) => crate::import::Format::detect(&text).with_context(|| {
            format!(
                "can't tell which app made {}; name it with --from (proton, apple, google, lastpass, csv)",
                file.display()
            )
        })?,
    };
    let (records, report) = format.parse(&text, &map)?;
    let mut out = format!("{} export: {}", format.label(), report.render(&records));
    if list {
        out.push_str(&crate::import::render_list(&records));
    }
    output::print_human(&out)
}

pub fn generate(args: &GenArgs) -> Result<()> {
    if args.count > 1 {
        let mut text = String::new();
        for _ in 0..args.count {
            text.push_str(&one_generated(args)?.value);
            text.push('\n');
        }
        return output::print(&text);
    }
    let g = one_generated(args)?;
    if args.json {
        return output::print_json(&g);
    }
    if args.clip {
        copy_and_tell(&g.value)?;
    } else {
        output::print(&format!("{}\n", g.value))?;
    }
    if std::io::stderr().is_terminal() {
        output::notice(&format!("({:.0} bits of entropy)", g.entropy_bits));
    }
    Ok(())
}

fn one_generated(args: &GenArgs) -> Result<generate::Generated> {
    Ok(if let Some(n) = args.words {
        match &args.word_list {
            Some(file) => {
                let text = std::fs::read_to_string(file)
                    .with_context(|| format!("reading the word list {}", file.display()))?;
                let list = generate::word_list(&text)
                    .with_context(|| format!("word list {}", file.display()))?;
                generate::passphrase_from(&list, n, &args.separator, args.capitalize)?
            }
            None => generate::passphrase(n, &args.separator, args.capitalize)?,
        }
    } else if let Some(n) = args.pin {
        generate::pin(n)?
    } else {
        generate::password(&generate::CharsetSpec {
            length: args.length,
            upper: !args.no_upper,
            digits: !args.no_digits,
            symbols: !args.no_symbols,
            avoid_ambiguous: args.avoid_ambiguous,
            symbol_set: args.symbols.clone(),
            exclude: args.exclude.clone().unwrap_or_default(),
        })?
    })
}

/// The settings in effect: where the config file is, which database and key file a command
/// would open (and why), the clipboard and agent timeouts, and where the agent's socket is.
pub fn show_config(global: &Global, json: bool) -> Result<()> {
    let path = config::Config::path();
    let cfg = config::Config::load()?;
    let target = cfg
        .target(global.db.as_deref(), global.keyfile.as_deref())
        .ok();
    let source = match (&global.db, &cfg.db) {
        (Some(d), _) if std::env::var_os("PRIVE_DB").is_some_and(|v| v == d.as_os_str()) => {
            "PRIVE_DB"
        }
        (Some(_), _) => "--db",
        (None, Some(_)) => "config file",
        (None, None) => "not set",
    };
    // `--db work` is reported as the file it stands for, and where the name came from.
    let db_from = match global.db.as_deref().filter(|d| cfg.named(d).is_some()) {
        Some(name) => format!("{source}, [databases.{}]", name.display()),
        None => source.to_string(),
    };
    let db = target
        .as_ref()
        .map(|t| t.db.clone())
        .or_else(|| global.db.clone());
    // The order unlock.rs tries them in, leaving out --password-stdin (it is per command).
    let password_from = if let Some(f) = std::env::var_os("PRIVE_PASSWORD_FILE") {
        format!("PRIVE_PASSWORD_FILE {}", std::path::Path::new(&f).display())
    } else if let Some(cmd) = target.as_ref().and_then(|t| t.password_command.as_ref()) {
        format!("password_command {}", cmd.join(" "))
    } else {
        "asked for when needed".to_string()
    };
    let keyfile = target.and_then(|t| t.keyfile);
    #[cfg(unix)]
    let agent_dir = Some(crate::agent::dir::agent_dir());
    #[cfg(not(unix))]
    let agent_dir: Option<std::path::PathBuf> = None;
    if json {
        return output::print_json(&serde_json::json!({
            "config_file": path,
            "config_file_exists": path.as_ref().is_some_and(|p| p.exists()),
            "database": db,
            "database_from": db_from,
            "keyfile": keyfile,
            "password_from": password_from,
            "clipboard_seconds": cfg.clipboard_seconds(),
            "agent_minutes": cfg.agent_idle().as_secs() / 60,
            "agent_dir": agent_dir,
            "databases": cfg.databases,
        }));
    }
    let show = |p: &Option<std::path::PathBuf>| {
        p.as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "-".into())
    };
    let exists = if path.as_ref().is_some_and(|p| p.exists()) {
        ""
    } else {
        " (doesn't exist)"
    };
    let mut text = format!(
        "config file:       {}{exists}\n\
         database:          {} ({db_from})\n\
         key file:          {}\n\
         password:          {password_from}\n\
         clipboard clears:  after {} s\n\
         agent locks:       after {} min unused\n\
         agent directory:   {}\n",
        show(&path),
        show(&db),
        show(&keyfile),
        cfg.clipboard_seconds(),
        cfg.agent_idle().as_secs() / 60,
        show(&agent_dir),
    );
    let columns = cfg
        .databases
        .keys()
        .map(|n| output::width(n))
        .max()
        .unwrap_or(0);
    for (i, (name, d)) in cfg.databases.iter().enumerate() {
        let label = if i == 0 { "named databases:" } else { "" };
        text.push_str(&format!(
            "{label:<18} {}  {}\n",
            output::pad(name, columns),
            d.path.display()
        ));
    }
    output::print_human(&text)
}

/// Answer git's credential request from stdin. Never an error that stops git: anything that
/// goes wrong (locked, nothing fits, several fit) is said on stderr, and git carries on with
/// its next helper or its own prompt.
pub fn git_credential(global: &Global, action: &str) -> Result<()> {
    use std::io::Read;
    let mut input = Zeroizing::new(String::new());
    std::io::stdin().read_to_string(&mut input)?;
    if action != "get" {
        return Ok(()); // store / erase: prive doesn't write the database
    }
    let req = crate::gitcred::parse_request(&input);
    if req.host.is_empty() {
        return Ok(());
    }
    let db = match open(global) {
        Ok(db) => db,
        Err(e) => {
            if matches!(e.downcast_ref::<Failure>(), Some(Failure::NoTerminal)) {
                eprintln!("prive: run `prive unlock` so git can use your passwords");
            } else {
                eprintln!("prive: {e:#}");
            }
            return Ok(());
        }
    };
    let found = crate::gitcred::matches(&db.entries, &req);
    match found.as_slice() {
        [one] => output::print(&crate::gitcred::answer(one, &db.entries)),
        [] => Ok(()),
        many => {
            eprintln!(
                "prive: {} entries fit {}; set the username in the remote URL to choose: {}",
                many.len(),
                req.host,
                many.iter().map(|e| e.path()).collect::<Vec<_>>().join(", ")
            );
            Ok(())
        }
    }
}

pub fn completions(shell: clap_complete::Shell) -> Result<()> {
    let mut cmd = <crate::cli::Cli as clap::CommandFactory>::command();
    let mut out = Vec::new();
    clap_complete::generate(shell, &mut cmd, "prive", &mut out);
    output::print(&String::from_utf8_lossy(&out))
}

/// Every entry with its secrets, to a new owner-only file or to a pipe. Refused on a terminal,
/// where it would put every password on screen and into the scrollback.
pub fn export(
    global: &Global,
    format: crate::export::Format,
    out: Option<&std::path::Path>,
) -> Result<()> {
    if out.is_none() && std::io::stdout().is_terminal() {
        anyhow::bail!(
            "export writes every password in plain text; give --out FILE, or pipe it somewhere"
        );
    }
    let db = open(global)?;
    let bytes = match format {
        crate::export::Format::Csv => crate::export::csv(&db.entries)?,
        crate::export::Format::Json => crate::export::json(&db.entries)?,
    };
    match out {
        Some(path) => {
            crate::fsutil::write_new_file(path, &bytes)?;
            output::notice(&format!(
                "Wrote {} entries, passwords in plain text, to {}. Delete it when you are done.",
                db.entries.len(),
                path.display()
            ));
            Ok(())
        }
        None => {
            use std::io::Write;
            let mut stdout = std::io::stdout().lock();
            match stdout.write_all(&bytes).and_then(|()| stdout.flush()) {
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
                other => Ok(other?),
            }
        }
    }
}
