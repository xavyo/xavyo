//! Apply embedded SQLx migrations (for CI and local test database setup).

use xavyo_db::{run_migrations, DbPool};

#[tokio::main]
async fn main() {
    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL environment variable is required");

    let pool = DbPool::connect(&database_url)
        .await
        .expect("failed to connect to database for migrations");

    run_migrations(&pool)
        .await
        .expect("database migrations failed");
}
