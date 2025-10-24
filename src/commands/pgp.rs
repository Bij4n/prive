use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use colored::Colorize;
use pgp::types::PublicKeyTrait;

use crate::cli::PgpCommand;
use crate::pgp::generate::generate_keypair;
use crate::pgp::keyring::Keyring;

pub fn handle_pgp(cmd: &PgpCommand) -> Result<()> {
    match cmd {
        PgpCommand::Generate {
            name,
            email,
            algorithm,
            expire: _,
        } => cmd_generate(name.as_deref(), email.as_deref(), algorithm),
        PgpCommand::List { secret } => cmd_list(*secret),
        PgpCommand::Export {
            key_id,
            secret,
            output,
        } => cmd_export(key_id, *secret, output.as_deref()),
        PgpCommand::Import { file } => cmd_import(file),
        PgpCommand::Delete { key_id, force } => cmd_delete(key_id, *force),
        PgpCommand::Info { key_id } => cmd_info(key_id),
    }
}

fn cmd_generate(name: Option<&str>, email: Option<&str>, algorithm: &str) -> Result<()> {
    let name = if let Some(n) = name {
        n.to_string()
    } else {
        print!("Name: ");
        std::io::Write::flush(&mut std::io::stdout())?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        input.trim().to_string()
    };

    let email = if let Some(e) = email {
        e.to_string()
    } else {
        print!("Email: ");
        std::io::Write::flush(&mut std::io::stdout())?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        input.trim().to_string()
    };

    let passphrase = rpassword::prompt_password("Key passphrase (empty for none): ")?;

    println!("Generating {} keypair...", algorithm.dimmed());
    let key = generate_keypair(&name, &email, algorithm, &passphrase)
        .map_err(|e| anyhow::anyhow!(e))?;
