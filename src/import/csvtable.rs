//! A CSV export read by column name, the way exporters label them, ignoring case, spaces and
//! a leading byte-order mark. Columns can come in any order; unknown ones are kept so the
//! caller can carry them over instead of losing them.

use std::collections::HashMap;

use anyhow::{Context, Result};
use zeroize::Zeroizing;

pub struct Table {
    headers: Vec<String>,
    index: HashMap<String, usize>,
    rows: Vec<Vec<Zeroizing<String>>>,
}

fn key(h: &str) -> String {
    h.trim_start_matches('\u{feff}')
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '_' && *c != '-')
        .collect::<String>()
        .to_lowercase()
}

impl Table {
    pub fn parse(text: &str) -> Result<Table> {
        let mut reader = csv::ReaderBuilder::new()
            .flexible(true)
            .from_reader(text.as_bytes());
        let headers: Vec<String> = reader
            .headers()
            .context("reading the CSV header")?
            .iter()
            .map(|h| h.trim_start_matches('\u{feff}').trim().to_string())
            .collect();
        let index = headers
            .iter()
            .enumerate()
            .map(|(i, h)| (key(h), i))
            .collect();
        let mut rows = Vec::new();
        for (n, rec) in reader.records().enumerate() {
            let rec = rec.with_context(|| format!("reading CSV row {}", n + 2))?;
            rows.push(rec.iter().map(|v| Zeroizing::new(v.to_string())).collect());
        }
        Ok(Table {
            headers,
            index,
            rows,
        })
    }

    /// The header names as written.
    pub fn headers(&self) -> &[String] {
        &self.headers
    }

    pub fn has(&self, name: &str) -> bool {
        self.index.contains_key(&key(name))
    }

    pub fn rows(&self) -> impl Iterator<Item = Row<'_>> {
        self.rows
            .iter()
            .map(move |cells| Row { table: self, cells })
    }
}

pub struct Row<'a> {
    table: &'a Table,
    cells: &'a [Zeroizing<String>],
}

impl Row<'_> {
    /// The value under the first of `names` that exists, trimmed; "" if none.
    pub fn get(&self, names: &[&str]) -> &str {
        names
            .iter()
            .find_map(|n| self.table.index.get(&key(n)))
            .and_then(|&i| self.cells.get(i))
            .map(|v| v.trim())
            .unwrap_or("")
    }

    /// Every column not among `known`, with a non-empty value: (header, value).
    pub fn others(&self, known: &[&str]) -> Vec<(String, Zeroizing<String>)> {
        let known: Vec<String> = known.iter().map(|k| key(k)).collect();
        self.table
            .headers
            .iter()
            .zip(self.cells.iter())
            .filter(|(h, v)| !known.contains(&key(h)) && !v.trim().is_empty())
            .map(|(h, v)| (h.clone(), Zeroizing::new(v.trim().to_string())))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns_by_name_in_any_order_and_case() {
        let t = Table::parse("\u{feff}URL,User Name,PASSWORD,extra col\nhttps://a,me,pw,keep me\n")
            .unwrap();
        let row = t.rows().next().unwrap();
        assert_eq!(row.get(&["username", "login"]), "me");
        assert_eq!(row.get(&["password"]), "pw");
        assert_eq!(row.get(&["url"]), "https://a");
        assert_eq!(row.get(&["missing"]), "");
        let others = row.others(&["url", "username", "password"]);
        assert_eq!(others.len(), 1);
        assert_eq!(others[0].0, "extra col");
        assert!(t.has("User_Name"));
    }

    #[test]
    fn quoted_commas_newlines_and_short_rows() {
        let t =
            Table::parse("name,notes,password\n\"a, b\",\"line 1\nline 2\",x\nshort\n").unwrap();
        let rows: Vec<_> = t.rows().collect();
        assert_eq!(rows[0].get(&["name"]), "a, b");
        assert_eq!(rows[0].get(&["notes"]), "line 1\nline 2");
        assert_eq!(rows[1].get(&["password"]), "");
    }
}
