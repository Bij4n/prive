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
    // One page for every subcommand, whatever is added later.
    for sub in prive::cli::Cli::command().get_subcommands() {
        let page = format!("prive-{}.1", sub.get_name());
        assert!(pages.contains(&page), "{page} missing from {pages:?}");
    }
    // The internal helpers never get a page.
    assert!(!pages.iter().any(|p| p.contains("__")), "{pages:?}");
    let top = std::fs::read_to_string(dir.path().join("prive.1")).unwrap();
    assert!(top.contains("KeePass"));
}
