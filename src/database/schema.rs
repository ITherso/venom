pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    headers TEXT NOT NULL,
    body BLOB,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    response_id INTEGER
);

CREATE TABLE IF NOT EXISTS responses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    status_code INTEGER NOT NULL,
    headers TEXT NOT NULL,
    body BLOB,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    size INTEGER
);

CREATE TABLE IF NOT EXISTS intercepts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL,
    modified_body BLOB,
    modified_headers TEXT,
    action TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (request_id) REFERENCES requests(id)
);

CREATE INDEX IF NOT EXISTS idx_requests_url ON requests(url);
CREATE INDEX IF NOT EXISTS idx_requests_timestamp ON requests(timestamp);
CREATE INDEX IF NOT EXISTS idx_responses_timestamp ON responses(timestamp);
"#;

pub async fn init_db(pool: &sqlx::SqlitePool) -> crate::Result<()> {
    sqlx::raw_sql(SCHEMA)
        .execute(pool)
        .await
        .map_err(|e| crate::Error::DatabaseError(e.to_string()))?;

    Ok(())
}
