pub mod schema;

use crate::Result;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};

pub async fn init_pool(db_path: &str) -> Result<SqlitePool> {
    // Ensure DB file exists
    if !std::path::Path::new(db_path).exists() {
        std::fs::File::create(db_path)
            .map_err(|e| crate::Error::DatabaseError(e.to_string()))?;
    }

    let database_url = if db_path.starts_with("sqlite:") {
        db_path.to_string()
    } else {
        format!("sqlite:{}", db_path)
    };

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .map_err(|e| crate::Error::DatabaseError(e.to_string()))?;

    schema::init_db(&pool).await?;

    Ok(pool)
}
