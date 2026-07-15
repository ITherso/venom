use crate::Result;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub id: Option<i64>,
    pub method: String,
    pub url: String,
    pub headers: String,
    pub body: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub id: Option<i64>,
    pub status_code: u16,
    pub headers: String,
    pub body: Option<Vec<u8>>,
    pub size: u32,
}

pub struct ProxyHistory {
    pool: SqlitePool,
}

impl ProxyHistory {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn save_request(&self, req: &HttpRequest) -> Result<i64> {
        let headers_json = &req.headers;
        let body = &req.body;

        let id = sqlx::query_scalar::<_, i64>(
            "INSERT INTO requests (method, url, headers, body) VALUES (?, ?, ?, ?) RETURNING id"
        )
        .bind(&req.method)
        .bind(&req.url)
        .bind(headers_json)
        .bind(body)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| crate::Error::DatabaseError(e.to_string()))?;

        Ok(id)
    }

    pub async fn save_response(&self, resp: &HttpResponse) -> Result<i64> {
        let headers_json = &resp.headers;
        let body = &resp.body;

        let id = sqlx::query_scalar::<_, i64>(
            "INSERT INTO responses (status_code, headers, body, size) VALUES (?, ?, ?, ?) RETURNING id"
        )
        .bind(resp.status_code as i32)
        .bind(headers_json)
        .bind(body)
        .bind(resp.size as i32)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| crate::Error::DatabaseError(e.to_string()))?;

        Ok(id)
    }

    pub async fn link_response(&self, req_id: i64, resp_id: i64) -> Result<()> {
        sqlx::query("UPDATE requests SET response_id = ? WHERE id = ?")
            .bind(resp_id)
            .bind(req_id)
            .execute(&self.pool)
            .await
            .map_err(|e| crate::Error::DatabaseError(e.to_string()))?;

        Ok(())
    }

    pub async fn get_requests(&self, limit: u32) -> Result<Vec<HttpRequest>> {
        let requests = sqlx::query_as::<_, (i64, String, String, String, Option<Vec<u8>>)>(
            "SELECT id, method, url, headers, body FROM requests ORDER BY timestamp DESC LIMIT ?"
        )
        .bind(limit as i32)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| crate::Error::DatabaseError(e.to_string()))?;

        Ok(requests
            .into_iter()
            .map(|(id, method, url, headers, body)| HttpRequest {
                id: Some(id),
                method,
                url,
                headers,
                body,
            })
            .collect())
    }
}
