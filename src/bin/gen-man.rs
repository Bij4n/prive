//! Generate man pages for prive.
//!
//! Usage: cargo run --bin gen-man [-- <output-dir>]
//! Default output directory: man/

use std::path::PathBuf;

use clap::CommandFactory;
use clap_mangen::Man;

fn main() {
    let out_dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("man"));

    std::fs::create_dir_all(&out_dir)
        .unwrap_or_else(|e| panic!("Failed to create output dir '{}': {e}", out_dir.display()));

    let cmd = prive::cli::Cli::command();
    generate_man_pages(&cmd, &out_dir, None);

    println!("Man pages written to {}/", out_dir.display());
}

fn generate_man_pages(cmd: &clap::Command, out_dir: &std::path::Path, parent: Option<&str>) {
    let name = match parent {
        Some(p) => format!("{p}-{}", cmd.get_name()),
        None => cmd.get_name().to_string(),
    };

    let filename = format!("{name}.1");
    let path = out_dir.join(&filename);

    let man = Man::new(cmd.clone());
    let mut buf = Vec::new();
    man.render(&mut buf)
        .unwrap_or_else(|e| panic!("Failed to render man page for '{name}': {e}"));

    std::fs::write(&path, &buf)
        .unwrap_or_else(|e| panic!("Failed to write '{path}': {e}", path = path.display()));

    println!("  {}", path.display());

    // Recurse into subcommands
    for sub in cmd.get_subcommands() {
        if sub.get_name() != "help" {
            generate_man_pages(sub, out_dir, Some(&name));
        }
    }
}
