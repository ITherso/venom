pub mod schema;

use crate::Result;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};

pub async fn init_pool(db_path: &str) -> Result<SqlitePool> {
    let database_url = format!("sqlite://{}", db_path);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .map_err(|e| crate::Error::DatabaseError(e.to_string()))?;

    schema::init_db(&pool).await?;

    Ok(pool)
}
