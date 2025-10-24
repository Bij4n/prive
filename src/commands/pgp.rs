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
