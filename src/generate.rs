//! Password generation.

use rand::Rng;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!#$%&()*+,-./:;<=>?@[]^_{|}~";

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
}
