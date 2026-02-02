//! Terminal output helpers for consistent CLI formatting

/// Check if color output is enabled
fn use_color() -> bool {
    std::env::var("NO_COLOR").is_err()
}

/// Print a success message (green checkmark)
pub fn print_success(message: &str) {
    if use_color() {
        println!("\x1b[32m✓\x1b[0m {}", message);
    } else {
        println!("OK: {}", message);
    }
}

/// Print a warning message (yellow)
pub fn print_warning(message: &str) {
    if use_color() {
        eprintln!("\x1b[33mWarning:\x1b[0m {}", message);
    } else {
        eprintln!("Warning: {}", message);
    }
}

/// Print an info message (blue)
pub fn print_info(message: &str) {
    if use_color() {
        println!("\x1b[34mℹ\x1b[0m {}", message);
    } else {
        println!("Info: {}", message);
    }
}

/// Print a header with decorative border
pub fn print_header(title: &str) {
    let border = "═".repeat(59);
    println!();
    println!("{}", border);
    println!("{:^59}", title);
    println!("{}", border);
    println!();
}

/// Print a key-value pair with consistent formatting
pub fn print_key_value(key: &str, value: &str) {
    if use_color() {
        println!("  \x1b[1m{}:\x1b[0m {}", key, value);
    } else {
        println!("  {}: {}", key, value);
    }
}

/// Print a list of next steps
pub fn print_next_steps(steps: &[String]) {
    println!("\nNext steps:");
    for (i, step) in steps.iter().enumerate() {
        println!("  {}. {}", i + 1, step);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_use_color_respects_no_color() {
        // Save current value
        let had_no_color = std::env::var("NO_COLOR").is_ok();

        // Test with NO_COLOR set
        std::env::set_var("NO_COLOR", "1");
        assert!(!use_color());

        // Test without NO_COLOR
        std::env::remove_var("NO_COLOR");
        assert!(use_color());

        // Restore
        if had_no_color {
            std::env::set_var("NO_COLOR", "1");
        }
    }
}
