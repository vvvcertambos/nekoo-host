use sqlx::SqlitePool;
use reqwest::Client;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub client: Client,
    pub rotation_strategy: std::sync::Arc<std::sync::atomic::AtomicU8>, // 0: Random, 1: Sequential
}

