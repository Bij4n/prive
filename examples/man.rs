//! Write prive's man pages: `cargo run --example man -- <dir>` (default `man/`).
//! One page for `prive` and one per subcommand (`prive-gen.1`, ...).

use std::path::PathBuf;

use clap::CommandFactory;

fn main() -> std::io::Result<()> {
    let dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| "man".into());
    std::fs::create_dir_all(&dir)?;
    clap_mangen::generate_to(prive::cli::Cli::command(), &dir)?;
    println!("man pages written to {}", dir.display());
    Ok(())
}
