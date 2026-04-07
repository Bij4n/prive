/// Password strength scoring using multiple heuristics.

#[derive(Debug, Clone)]
pub struct StrengthReport {
    pub score: u32, // 0-100
    pub level: StrengthLevel,
    pub feedback: Vec<String>,
    pub crack_time_display: String,
    pub entropy_bits: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrengthLevel {
    VeryWeak,
    Weak,
    Fair,
    Strong,
    VeryStrong,
}

impl std::fmt::Display for StrengthLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StrengthLevel::VeryWeak => write!(f, "Very Weak"),
            StrengthLevel::Weak => write!(f, "Weak"),
            StrengthLevel::Fair => write!(f, "Fair"),
            StrengthLevel::Strong => write!(f, "Strong"),
            StrengthLevel::VeryStrong => write!(f, "Very Strong"),
        }
    }
}

pub fn analyze_strength(password: &str) -> StrengthReport {
    let mut score: u32 = 0;
    let mut feedback = Vec::new();
    let len = password.len();

    // Length scoring
    if len >= 16 {
        score += 30;
    } else if len >= 12 {
        score += 20;
    } else if len >= 8 {
        score += 10;
    } else {
        feedback.push(format!(
            "Too short ({len} chars). Use at least 12 characters."
        ));
    }

    // Character variety
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password.chars().any(|c| !c.is_ascii_alphanumeric());

    let variety = [has_lower, has_upper, has_digit, has_symbol]
        .iter()
        .filter(|&&v| v)
        .count();

    score += (variety as u32) * 10;

    if variety < 3 {
        feedback.push("Mix uppercase, lowercase, numbers, and symbols.".to_string());
    }

    // Uniqueness of characters
    let unique: std::collections::HashSet<char> = password.chars().collect();
    let uniqueness = unique.len() as f64 / len.max(1) as f64;
    if uniqueness > 0.8 {
        score += 15;
    } else if uniqueness > 0.5 {
        score += 8;
    } else {
        feedback.push("Too many repeated characters.".to_string());
    }

    // Sequential detection
    let sequential = count_sequential(password);
    if sequential > 3 {
        score = score.saturating_sub(10);
        feedback.push("Contains sequential characters (abc, 123).".to_string());
    }

    // Repeated patterns
    if has_repeated_pattern(password) {
        score = score.saturating_sub(10);
        feedback.push("Contains repeated patterns.".to_string());
    }

    // Common password check
    if is_common_password(&password.to_lowercase()) {
        score = score.saturating_sub(30);
        feedback.push("This is a commonly used password.".to_string());
    }

    // Entropy calculation
    let entropy = super::password_gen::password_entropy(password);
    if entropy > 60.0 {
        score += 15;
    } else if entropy > 40.0 {
        score += 8;
    }

    score = score.min(100);

    let level = match score {
        0..=20 => StrengthLevel::VeryWeak,
        21..=40 => StrengthLevel::Weak,
        41..=60 => StrengthLevel::Fair,
        61..=80 => StrengthLevel::Strong,
        _ => StrengthLevel::VeryStrong,
    };

    let crack_time = estimate_crack_time(entropy);

    if feedback.is_empty() {
        feedback.push("Strong password!".to_string());
    }

    StrengthReport {
        score,
        level,
        feedback,
        crack_time_display: crack_time,
        entropy_bits: entropy,
    }
}

fn count_sequential(password: &str) -> usize {
    let chars: Vec<char> = password.chars().collect();
    let mut count = 0;

    for i in 0..chars.len().saturating_sub(2) {
        let a = chars[i] as i32;
        let b = chars[i + 1] as i32;
        let c = chars[i + 2] as i32;

        if b - a == 1 && c - b == 1 {
            count += 1;
        }
        if a - b == 1 && b - c == 1 {
            count += 1;
        }
    }

    count
}

fn has_repeated_pattern(password: &str) -> bool {
    let len = password.len();
    if len < 4 {
        return false;
    }

    for pattern_len in 1..=len / 2 {
        let pattern = &password[..pattern_len];
        let repetitions = password.matches(pattern).count();
        if repetitions >= 3 && pattern_len * repetitions >= len / 2 {
            return true;
        }
    }

    false
}

fn is_common_password(password: &str) -> bool {
    const COMMON: &[&str] = &[
        "password",
        "123456",
        "12345678",
        "qwerty",
        "abc123",
        "monkey",
        "1234567",
        "letmein",
        "trustno1",
        "dragon",
        "baseball",
        "master",
        "michael",
        "shadow",
        "ashley",
        "football",
        "admin",
        "passw0rd",
        "welcome",
        "login",
        "princess",
        "starwars",
        "solo",
        "hello",
        "charlie",
        "donald",
        "sunshine",
        "password1",
        "qwerty123",
    ];
    COMMON.contains(&password)
}

fn estimate_crack_time(entropy_bits: f64) -> String {
    // Assume 10 billion guesses per second (modern GPU)
    let guesses_per_sec: f64 = 1e10;
    let total_guesses = 2f64.powf(entropy_bits);
    let seconds = total_guesses / guesses_per_sec;

    if seconds < 1.0 {
        "instant".to_string()
    } else if seconds < 60.0 {
        format!("{:.0} seconds", seconds)
    } else if seconds < 3600.0 {
        format!("{:.0} minutes", seconds / 60.0)
    } else if seconds < 86400.0 {
        format!("{:.0} hours", seconds / 3600.0)
    } else if seconds < 86400.0 * 365.0 {
        format!("{:.0} days", seconds / 86400.0)
    } else if seconds < 86400.0 * 365.0 * 1000.0 {
        format!("{:.0} years", seconds / (86400.0 * 365.0))
    } else if seconds < 86400.0 * 365.0 * 1e6 {
        format!("{:.0} thousand years", seconds / (86400.0 * 365.0 * 1000.0))
    } else if seconds < 86400.0 * 365.0 * 1e9 {
        format!("{:.0} million years", seconds / (86400.0 * 365.0 * 1e6))
    } else {
        "billions of years".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_very_weak_password() {
        let report = analyze_strength("a");
        assert!(report.score <= 30);
        assert!(matches!(
            report.level,
            StrengthLevel::VeryWeak | StrengthLevel::Weak
        ));
    }

    #[test]
    fn test_weak_password() {
        let report = analyze_strength("password");
        assert!(report.score <= 40);
    }

    #[test]
    fn test_strong_password() {
        let report = analyze_strength("Xk9#mP2$vL7@nQ4!");
        assert!(report.score >= 60);
    }

    #[test]
    fn test_very_strong_password() {
        let report = analyze_strength("j&3Kx!9mR@5pWv#2nQ8$fL6*");
        assert_eq!(report.level, StrengthLevel::VeryStrong);
    }

    #[test]
    fn test_common_password_penalty() {
        let report = analyze_strength("password");
        assert!(report.feedback.iter().any(|f| f.contains("commonly used")));
    }

    #[test]
    fn test_sequential_detection() {
        assert!(count_sequential("abcdef") > 0);
        assert!(count_sequential("123456") > 0);
        assert_eq!(count_sequential("xkm"), 0);
    }

    #[test]
    fn test_repeated_pattern() {
        assert!(has_repeated_pattern("abcabcabc"));
        assert!(!has_repeated_pattern("xK9mP2vL"));
    }

    #[test]
    fn test_crack_time_format() {
        assert_eq!(estimate_crack_time(0.0), "instant");
        assert!(estimate_crack_time(80.0).contains("years"));
    }

    #[test]
    fn test_strength_level_display() {
        assert_eq!(format!("{}", StrengthLevel::VeryStrong), "Very Strong");
        assert_eq!(format!("{}", StrengthLevel::Weak), "Weak");
    }

    #[test]
    fn test_entropy_contributes_to_score() {
        let weak = analyze_strength("aaa");
        let strong = analyze_strength("Xk9#mP2$vL7@nQ4!wR8%");
        assert!(strong.entropy_bits > weak.entropy_bits);
        assert!(strong.score > weak.score);
    }
}
