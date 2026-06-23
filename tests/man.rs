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
    for page in [
        "prive.1",
        "prive-gen.1",
        "prive-info.1",
        "prive-diff.1",
        "prive-doctor.1",
        "prive-git-credential.1",
    ] {
        assert!(pages.contains(&page.to_string()), "{page} in {pages:?}");
    }
    // The internal helpers never get a page.
    assert!(!pages.iter().any(|p| p.contains("__")), "{pages:?}");
    let top = std::fs::read_to_string(dir.path().join("prive.1")).unwrap();
    assert!(top.contains("KeePass"));
}
