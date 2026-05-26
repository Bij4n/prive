//! Man pages render for the top command and every subcommand.

use clap::CommandFactory;

#[test]
fn every_command_gets_a_man_page() {
    let dir = tempfile::tempdir().unwrap();
    clap_mangen::generate_to(prive::cli::Cli::command(), dir.path()).unwrap();
    let mut pages: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    pages.sort();
    assert!(pages.contains(&"prive.1".to_string()));
    assert!(pages.contains(&"prive-gen.1".to_string()));
    let top = std::fs::read_to_string(dir.path().join("prive.1")).unwrap();
    assert!(top.contains("KeePass"));
}
