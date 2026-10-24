//! A harmless local upstream for the README walkthrough.
use axum::{
    Json, Router, body::to_bytes, extract::Request, http::StatusCode, response::IntoResponse,
};
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let address = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:3000".into());
    let listener = tokio::net::TcpListener::bind(&address).await?;
    println!(
        "Demo upstream listening on http://{}",
        listener.local_addr()?
    );
    let app = Router::new().fallback(|request: Request| async move {
        let (parts, body) = request.into_parts();
        match to_bytes(body, 16 * 1024 * 1024).await {
            Ok(body) => (StatusCode::OK, Json(json!({"method": parts.method.as_str(), "target": parts.uri.to_string(), "body_bytes": body.len()}))).into_response(),
            Err(_) => StatusCode::BAD_REQUEST.into_response(),
        }
    });
    axum::serve(listener, app).await?;
    Ok(())
}
