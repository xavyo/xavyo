//! Fuzzy Matching Service (F062).
//!
//! Provides string similarity algorithms for identity duplicate detection:
//! - Levenshtein distance (edit distance)
//! - Jaro-Winkler similarity (positional matching)
//! - Soundex phonetic matching (sound-alike names)
//! - Normalized combined scoring

use strsim::{jaro_winkler, levenshtein, normalized_levenshtein};

/// Result of a fuzzy match comparison between two strings.
#[derive(Debug, Clone)]
pub struct FuzzyMatchResult {
    /// Original value being compared.
    pub original: String,
    /// Candidate value being compared against.
    pub candidate: String,
    /// Levenshtein similarity score (0.0 to 1.0).
    pub levenshtein_score: f64,
    /// Jaro-Winkler similarity score (0.0 to 1.0).
    pub jaro_winkler_score: f64,
    /// Soundex match (true if phonetically similar).
    pub soundex_match: bool,
    /// Combined weighted score (0.0 to 1.0).
    pub combined_score: f64,
}

/// Configuration for fuzzy matching weights.
#[derive(Debug, Clone)]
pub struct FuzzyMatchConfig {
    /// Weight for Levenshtein score (default 0.4).
    pub levenshtein_weight: f64,
    /// Weight for Jaro-Winkler score (default 0.4).
    pub jaro_winkler_weight: f64,
    /// Weight for Soundex match (default 0.2).
    pub soundex_weight: f64,
    /// Minimum score to consider a match (default 0.7).
    pub threshold: f64,
}

impl Default for FuzzyMatchConfig {
    fn default() -> Self {
        Self {
            levenshtein_weight: 0.4,
            jaro_winkler_weight: 0.4,
            soundex_weight: 0.2,
            threshold: 0.7,
        }
    }
}

/// Service for fuzzy string matching using multiple algorithms.
#[derive(Debug, Clone)]
pub struct FuzzyMatchingService {
    config: FuzzyMatchConfig,
}

impl Default for FuzzyMatchingService {
    fn default() -> Self {
        Self::new()
    }
}

impl FuzzyMatchingService {
    /// Create a new fuzzy matching service with default configuration.
    pub fn new() -> Self {
        Self {
            config: FuzzyMatchConfig::default(),
        }
    }

    /// Create a new fuzzy matching service with custom configuration.
    pub fn with_config(config: FuzzyMatchConfig) -> Self {
        Self { config }
    }

    /// Compare two strings using all fuzzy matching algorithms.
    pub fn compare(&self, original: &str, candidate: &str) -> FuzzyMatchResult {
        let original_normalized = self.normalize(original);
        let candidate_normalized = self.normalize(candidate);

        // Special case: both empty strings are considered an exact match
        if original_normalized.is_empty() && candidate_normalized.is_empty() {
            return FuzzyMatchResult {
                original: original.to_string(),
                candidate: candidate.to_string(),
                levenshtein_score: 1.0,
                jaro_winkler_score: 1.0,
                soundex_match: true,
                combined_score: 1.0,
            };
        }

        let levenshtein_score = normalized_levenshtein(&original_normalized, &candidate_normalized);
        let jaro_winkler_score = jaro_winkler(&original_normalized, &candidate_normalized);
        let soundex_match = self.soundex_match(&original_normalized, &candidate_normalized);

        let soundex_score = if soundex_match { 1.0 } else { 0.0 };

        let combined_score = (levenshtein_score * self.config.levenshtein_weight)
            + (jaro_winkler_score * self.config.jaro_winkler_weight)
            + (soundex_score * self.config.soundex_weight);

        FuzzyMatchResult {
            original: original.to_string(),
            candidate: candidate.to_string(),
            levenshtein_score,
            jaro_winkler_score,
            soundex_match,
            combined_score,
        }
    }

    /// Check if two strings are a match based on threshold.
    pub fn is_match(&self, original: &str, candidate: &str) -> bool {
        let result = self.compare(original, candidate);
        result.combined_score >= self.config.threshold
    }

    /// Get the raw Levenshtein distance (edit distance).
    pub fn levenshtein_distance(&self, a: &str, b: &str) -> usize {
        levenshtein(&self.normalize(a), &self.normalize(b))
    }

    /// Get the normalized Levenshtein similarity (0.0 to 1.0).
    pub fn levenshtein_similarity(&self, a: &str, b: &str) -> f64 {
        normalized_levenshtein(&self.normalize(a), &self.normalize(b))
    }

    /// Get the Jaro-Winkler similarity (0.0 to 1.0).
    pub fn jaro_winkler_similarity(&self, a: &str, b: &str) -> f64 {
        jaro_winkler(&self.normalize(a), &self.normalize(b))
    }

    /// Check if two strings match phonetically using Soundex.
    pub fn soundex_match(&self, a: &str, b: &str) -> bool {
        let soundex_a = self.soundex(&self.normalize(a));
        let soundex_b = self.soundex(&self.normalize(b));
        soundex_a == soundex_b && !soundex_a.is_empty()
    }

    /// Calculate Soundex code for a string.
    ///
    /// Soundex is a phonetic algorithm that encodes names by sound.
    /// Format: First letter + 3 digits (e.g., "Robert" -> "R163")
    pub fn soundex(&self, s: &str) -> String {
        if s.is_empty() {
            return String::new();
        }

        let chars: Vec<char> = s.chars().collect();
        let first_letter = chars[0].to_ascii_uppercase();

        // Soundex digit mapping
        let get_code = |c: char| -> Option<char> {
            match c.to_ascii_lowercase() {
                'b' | 'f' | 'p' | 'v' => Some('1'),
                'c' | 'g' | 'j' | 'k' | 'q' | 's' | 'x' | 'z' => Some('2'),
                'd' | 't' => Some('3'),
                'l' => Some('4'),
                'm' | 'n' => Some('5'),
                'r' => Some('6'),
                _ => None, // Vowels and H, W, Y are ignored
            }
        };

        let mut result = String::with_capacity(4);
        result.push(first_letter);

        let mut prev_code: Option<char> = get_code(first_letter);

        for &c in &chars[1..] {
            if result.len() >= 4 {
                break;
            }

            let code = get_code(c);
            if let Some(char_code) = code {
                if code != prev_code {
                    result.push(char_code);
                }
            }
            prev_code = code;
        }

        // Pad with zeros if needed
        while result.len() < 4 {
            result.push('0');
        }

        result
    }

    /// Normalize a string for comparison (lowercase, trim, remove extra spaces).
    fn normalize(&self, s: &str) -> String {
        s.trim()
            .to_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Compare multiple fields and return an aggregate score.
    pub fn compare_fields(
        &self,
        fields: &[((&str, &str), f64)], // ((original, candidate), weight)
    ) -> f64 {
        let total_weight: f64 = fields.iter().map(|(_, w)| w).sum();
        if total_weight == 0.0 {
            return 0.0;
        }

        let weighted_sum: f64 = fields
            .iter()
            .map(|((orig, cand), weight)| {
                let result = self.compare(orig, cand);
                result.combined_score * weight
            })
            .sum();

        weighted_sum / total_weight
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let service = FuzzyMatchingService::new();
        let result = service.compare("John Smith", "John Smith");
        assert!((result.combined_score - 1.0).abs() < 0.001);
        assert!(result.soundex_match);
    }

    #[test]
    fn test_similar_names() {
        let service = FuzzyMatchingService::new();
        let result = service.compare("John Smith", "Jon Smith");
        assert!(result.combined_score > 0.8);
        assert!(result.jaro_winkler_score > 0.9);
    }

    #[test]
    fn test_different_names() {
        let service = FuzzyMatchingService::new();
        let result = service.compare("John Smith", "Jane Doe");
        assert!(result.combined_score < 0.5);
    }

    #[test]
    fn test_soundex_robert_rupert() {
        let service = FuzzyMatchingService::new();
        // Robert and Rupert should have similar Soundex codes
        let soundex_robert = service.soundex("Robert");
        let soundex_rupert = service.soundex("Rupert");
        assert_eq!(soundex_robert, "R163");
        assert_eq!(soundex_rupert, "R163");
        assert!(service.soundex_match("Robert", "Rupert"));
    }

    #[test]
    fn test_soundex_smith_smythe() {
        let service = FuzzyMatchingService::new();
        let soundex_smith = service.soundex("Smith");
        let soundex_smythe = service.soundex("Smythe");
        assert_eq!(soundex_smith, "S530");
        assert_eq!(soundex_smythe, "S530");
        assert!(service.soundex_match("Smith", "Smythe"));
    }

    #[test]
    fn test_levenshtein_distance() {
        let service = FuzzyMatchingService::new();
        assert_eq!(service.levenshtein_distance("kitten", "sitting"), 3);
        assert_eq!(service.levenshtein_distance("test", "test"), 0);
    }

    #[test]
    fn test_normalization() {
        let service = FuzzyMatchingService::new();
        let result = service.compare("  JOHN   SMITH  ", "john smith");
        assert!((result.combined_score - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_is_match_threshold() {
        let service = FuzzyMatchingService::new();
        assert!(service.is_match("John Smith", "John Smyth"));
        assert!(!service.is_match("John Smith", "Jane Doe"));
    }

    #[test]
    fn test_custom_config() {
        let config = FuzzyMatchConfig {
            levenshtein_weight: 0.5,
            jaro_winkler_weight: 0.5,
            soundex_weight: 0.0,
            threshold: 0.9,
        };
        let service = FuzzyMatchingService::with_config(config);
        let result = service.compare("John", "Jon");
        // Without soundex weight, score should be different
        assert!(result.combined_score > 0.7);
    }

    #[test]
    fn test_compare_fields() {
        let service = FuzzyMatchingService::new();
        let score = service.compare_fields(&[
            (("John", "John"), 1.0),   // Exact match
            (("Smith", "Smyth"), 1.0), // Close match
        ]);
        assert!(score > 0.9);
    }

    #[test]
    fn test_empty_strings() {
        let service = FuzzyMatchingService::new();
        let result = service.compare("", "");
        assert!((result.combined_score - 1.0).abs() < 0.001); // Empty strings match
    }

    #[test]
    fn test_soundex_empty() {
        let service = FuzzyMatchingService::new();
        assert_eq!(service.soundex(""), "");
    }
}
