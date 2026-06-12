//! The documentation links to itself a lot; a renamed page should fail here, not on GitHub.

use std::path::{Path, PathBuf};

fn markdown_files() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files: Vec<PathBuf> = [
        "README.md",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
    ]
    .iter()
    .map(|f| root.join(f))
    .filter(|p| p.exists())
    .collect();
    for e in std::fs::read_dir(root.join("docs")).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "md") {
            files.push(p);
        }
    }
    files
}

/// Targets of `[text](target)` links, skipping web links and in-page anchors.
fn local_links(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("](") {
        rest = &rest[i + 2..];
        let Some(end) = rest.find(')') else { break };
        let target = &rest[..end];
        rest = &rest[end..];
        if target.contains("://") || target.starts_with('#') || target.starts_with("mailto:") {
            continue;
        }
        let path = target.split('#').next().unwrap_or("");
        if !path.is_empty() && !path.contains(' ') {
            out.push(path.to_string());
        }
    }
    out
}

#[test]
fn every_local_link_points_at_a_file() {
    let mut broken = Vec::new();
    for file in markdown_files() {
        let text = std::fs::read_to_string(&file).unwrap();
        let dir = file.parent().unwrap();
        for link in local_links(&text) {
            if !dir.join(&link).exists() {
                broken.push(format!("{}: {link}", file.display()));
            }
        }
    }
    assert!(broken.is_empty(), "broken links:\n{}", broken.join("\n"));
}

#[test]
fn links_are_found() {
    let text = "see [a](docs/a.md), [b](https://x.org) and [c](c.md#part), [d](#here)";
    assert_eq!(local_links(text), ["docs/a.md", "c.md"]);
}
