mod db;
mod github;
mod routes;

use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use sqlx::sqlite::SqlitePoolOptions;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use trust_dns_resolver::{TokioAsyncResolver, config::{ResolverConfig, ResolverOpts}};

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = dotenvy::dotenv();

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "nekoo=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Database setup
    let db_url = "sqlite:nekoo.db";
    if !std::path::Path::new("nekoo.db").exists() {
         std::fs::File::create("nekoo.db")?;
    }

    // Create and Clean Temp Directory
    let temp_dir = "temp_uploads";
    if std::path::Path::new(temp_dir).exists() {
        tracing::info!("Cleaning temp directory...");
        for entry in std::fs::read_dir(temp_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let _ = std::fs::remove_file(path);
            }
        }
    } else {
        std::fs::create_dir(temp_dir)?;
    }

    let pool = SqlitePoolOptions::new()
        .max_connections(50)
        .min_connections(5)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .connect(db_url)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;

    // Build HTTP client with GitHub DNS optimization
    let mut client_builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .connect_timeout(std::time::Duration::from_secs(10));

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::google(), ResolverOpts::default());
    if let Ok(ips) = resolver.ipv4_lookup("api.github.com").await {
        if let Some(ip) = ips.iter().next() {
            tracing::info!("Resolved api.github.com to {} (Geo-Optimized)", ip);
            client_builder = client_builder
                .resolve("api.github.com", SocketAddr::new(std::net::IpAddr::V4(ip.0), 443))
                .pool_max_idle_per_host(10)
                .pool_idle_timeout(None)
                .tcp_keepalive(std::time::Duration::from_secs(60));
        }
    } else {
        tracing::warn!("Custom DNS failed, falling back to system DNS for GitHub");
    }

    let client = client_builder.build().expect("Failed to build HTTP client");
    
    let state = db::AppState {
        pool,
        client,
        rotation_strategy: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0)),
    };

    let app = Router::new()
        // Main pages
        .route("/", get(routes::index))
        .route("/help", get(routes::help_page))
        .route("/terms", get(routes::terms_page))
        // Upload endpoints
        .route("/upload", post(routes::upload))
        .route("/api/upload", post(routes::upload))
        .route("/api/upload-chunk", post(routes::upload_chunk))
        .route("/api/upload-finalize", post(routes::upload_finalize))
        // File access
        .route("/view/:slug", get(routes::view_code))
        .route("/:slug", get(routes::download))
        // Utility endpoints
        .route("/api/stats", get(routes::stats))
        .route("/health", get(routes::health))
        // Static assets
        .route("/logo.png", get(routes::logo))
        .route("/logo.webp", get(routes::logo_webp))
        .route("/robots.txt", get(routes::robots))
        .route("/.well-known/security.txt", get(routes::security))
        // Admin (protected by env key)
        .route("/admin", get(routes::admin_panel))
        .route("/api/admin/dashboard", post(routes::admin_dashboard))
        .route("/api/admin/tokens", post(routes::admin_tokens))
        .route("/api/admin/maintenance", post(routes::admin_maintenance))
        .route("/api/admin/import", post(routes::admin_import_tokens))
        .route("/api/admin/backup", post(routes::admin_backup_db))
        .route("/api/admin/toggle_rotation", post(routes::admin_toggle_rotation))
        .route("/api/admin/purge", post(routes::admin_purge))
        .route("/api/admin/logs", post(routes::admin_logs))
        .route("/api/admin/slurp", post(routes::admin_slurp))
        .route("/admin/delete/:id", post(routes::delete_file))
        .layer(tower::ServiceBuilder::new()
            .layer(axum::extract::DefaultBodyLimit::max(2 * 1024 * 1024 * 1024))
            .layer(tower::limit::ConcurrencyLimitLayer::new(100))
            .layer(tower_http::compression::CompressionLayer::new())
        )
        .fallback(routes::not_found)
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::info!("Server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
    
    Ok(())
}
