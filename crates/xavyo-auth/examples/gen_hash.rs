//! Generate a password hash for testing.
//!
//! Usage: cargo run -p xavyo-auth --example gen_hash

use xavyo_auth::hash_password;

fn main() {
    let password = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "Test123!".to_string());
    match hash_password(&password) {
        Ok(hash) => println!("{}", hash),
        Err(e) => eprintln!("Error: {}", e),
    }
}
