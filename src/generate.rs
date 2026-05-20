//! Password, passphrase and PIN generation.
//!
//! Passphrases use the EFF large word list (7,776 words, 12.9 bits each), published by the
//! Electronic Frontier Foundation under CC BY 3.0 US: <https://www.eff.org/dice>.

use rand::Rng;
use rand::seq::IndexedRandom;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!#$%&()*+,-./:;<=>?@[]^_{|}~";

const EFF_LIST: &str = include_str!("../assets/eff_large_wordlist.txt");

fn words() -> Vec<&'static str> {
    EFF_LIST
        .lines()
        .filter_map(|l| l.split_once('\t').map(|(_, w)| w.trim()))
        .collect()
}

#[derive(Debug, Clone)]
pub struct CharsetSpec {
    pub length: usize,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
}

pub struct Generated {
    pub value: String,
    pub entropy_bits: f64,
}

/// Random characters. Every enabled class appears at least once.
pub fn password(spec: &CharsetSpec) -> anyhow::Result<Generated> {
    anyhow::ensure!(spec.length >= 4, "length must be at least 4");
    anyhow::ensure!(spec.length <= 1024, "length must be at most 1024");
    let mut classes: Vec<Vec<char>> = vec![LOWER.chars().collect()];
    if spec.upper {
        classes.push(UPPER.chars().collect());
    }
    if spec.digits {
        classes.push(DIGITS.chars().collect());
    }
    if spec.symbols {
        classes.push(SYMBOLS.chars().collect());
    }
    let all: Vec<char> = classes.iter().flatten().copied().collect();

    let mut rng = rand::rng();
    let value = loop {
        let candidate: String = (0..spec.length)
            .map(|_| all[rng.random_range(0..all.len())])
            .collect();
        if classes
            .iter()
            .all(|cls| candidate.chars().any(|c| cls.contains(&c)))
        {
            break candidate;
        }
    };
    Ok(Generated {
        value,
        entropy_bits: spec.length as f64 * (all.len() as f64).log2(),
    })
}

/// Words from the EFF list joined by `separator`.
pub fn passphrase(count: usize, separator: &str, capitalize: bool) -> anyhow::Result<Generated> {
    anyhow::ensure!((3..=64).contains(&count), "use between 3 and 64 words");
    let list = words();
    let mut rng = rand::rng();
    let chosen: Vec<String> = (0..count)
        .map(|_| {
            let w = *list.choose(&mut rng).expect("the word list is not empty");
            if capitalize {
                let mut c = w.chars();
                c.next()
                    .map(|first| first.to_uppercase().chain(c).collect())
                    .unwrap_or_default()
            } else {
                w.to_string()
            }
        })
        .collect();
    Ok(Generated {
        value: chosen.join(separator),
        entropy_bits: count as f64 * (list.len() as f64).log2(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(length: usize) -> CharsetSpec {
        CharsetSpec {
            length,
            upper: true,
            digits: true,
            symbols: true,
        }
    }

    #[test]
    fn every_class_appears_and_length_is_exact() {
        for _ in 0..200 {
            let g = password(&spec(8)).unwrap();
            assert_eq!(g.value.chars().count(), 8);
            assert!(g.value.chars().any(|c| c.is_ascii_lowercase()));
            assert!(g.value.chars().any(|c| c.is_ascii_uppercase()));
            assert!(g.value.chars().any(|c| c.is_ascii_digit()));
            assert!(g.value.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn entropy_is_length_times_log2_of_the_alphabet() {
        let lower = password(&CharsetSpec {
            length: 10,
            upper: false,
            digits: false,
            symbols: false,
        })
        .unwrap();
        assert!((lower.entropy_bits - 10.0 * 26f64.log2()).abs() < 1e-9);
    }

    #[test]
    fn length_bounds() {
        assert!(password(&spec(3)).is_err());
        assert!(password(&spec(1025)).is_err());
    }

    #[test]
    fn the_word_list_is_the_full_eff_list() {
        let w = words();
        assert_eq!(w.len(), 7776);
        assert_eq!(w[0], "abacus");
        assert_eq!(w[7775], "zoom");
        let unique: std::collections::HashSet<_> = w.iter().collect();
        assert_eq!(unique.len(), 7776);
    }

    #[test]
    fn passphrases() {
        let p = passphrase(6, "-", false).unwrap();
        assert_eq!(p.value.split('-').count(), 6);
        assert!((p.entropy_bits - 77.55).abs() < 0.01);
        let cap = passphrase(4, " ", true).unwrap();
        assert!(
            cap.value
                .split(' ')
                .all(|w| w.chars().next().unwrap().is_uppercase())
        );
        assert!(passphrase(2, "-", false).is_err());
    }
}
