//! Interactive fuzzy picker (fzf-style), drawn on stderr so stdout stays clean for scripts.

use anyhow::{Result, bail};
use nucleo_picker::{PickerOptions, Render};

use crate::entry::Entry;

struct Item {
    index: usize,
    label: String,
}

struct Labels;

impl Render<Item> for Labels {
    type Str<'a> = &'a str;

    fn render<'a>(&self, item: &'a Item) -> &'a str {
        &item.label
    }
}

/// What the picker shows for an entry: its path, and the username in brackets.
pub fn label(e: &Entry) -> String {
    if e.username.is_empty() {
        e.path()
    } else {
        format!("{}  ({})", e.path(), e.username)
    }
}

/// Let the user choose one entry. `None` if they cancel (Esc or Ctrl-C).
pub fn pick<'a>(entries: &'a [Entry], query: Option<&str>) -> Result<Option<&'a Entry>> {
    if entries.is_empty() {
        bail!("the database has no entries");
    }
    let mut opts = PickerOptions::default();
    if let Some(q) = query {
        opts = opts.query(q);
    }
    let mut picker = opts.picker(Labels);
    let injector = picker.injector();
    for (index, e) in entries.iter().enumerate() {
        injector.push(Item {
            index,
            label: label(e),
        });
    }
    match picker.pick() {
        Ok(Some(item)) => Ok(Some(&entries[item.index])),
        Ok(None) => Ok(None),
        Err(e) => bail!("the picker needs an interactive terminal: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_show_path_and_username() {
        let mut e = Entry {
            group: "Work".into(),
            title: "GitHub".into(),
            ..Entry::default()
        };
        assert_eq!(label(&e), "Work/GitHub");
        e.username = "demo".into();
        assert_eq!(label(&e), "Work/GitHub  (demo)");
    }

    #[test]
    fn an_empty_database_has_nothing_to_pick() {
        assert!(pick(&[], None).is_err());
    }
}
