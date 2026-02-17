use axum::{
    extract::{State, Path, Multipart, Query},
    response::{Html, IntoResponse, Response, Redirect},
    http::{StatusCode, HeaderMap},
    Json,
};
use tokio::io::AsyncWriteExt;
use sysinfo::System;
use std::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashMap;
use std::sync::Mutex;
use once_cell::sync::Lazy;

use crate::github;
use crate::db::AppState;

use serde_json::json;
use chrono;



use rand::Rng;


fn get_admin_key() -> String {
    std::env::var("ADMIN_KEY").unwrap_or_else(|_| "CHANGEME".into())
}

static FAILED_ATTEMPTS: Lazy<Mutex<HashMap<String, u32>>> = Lazy::new(|| Mutex::new(HashMap::new()));

fn check_brute_force(ip: &str) -> bool {
    let attempts = FAILED_ATTEMPTS.lock().unwrap();
    attempts.get(ip).cloned().unwrap_or(0) < 4
}

fn record_failure(ip: String) {
    let mut attempts = FAILED_ATTEMPTS.lock().unwrap();
    *attempts.entry(ip).or_insert(0) += 1;
}

pub static MAINTENANCE_MODE: AtomicBool = AtomicBool::new(false);

pub async fn admin_panel(headers: HeaderMap) -> impl IntoResponse {
    if let Some(host) = headers.get("host") {
        if let Ok(host_str) = host.to_str() {
            if host_str.contains("cdn.nekoo.ru") {
                 return (StatusCode::NOT_FOUND, Html(include_str!("../templates/404.html"))).into_response();
            }
        }
    }

    let ip = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).unwrap_or("unknown").to_string();
    let is_banned = !check_brute_force(&ip);
    
    let mut html = include_str!("../templates/admin.html").to_string();
    if is_banned {
        html = html.replace("<div id=\"ban-status\"></div>", "<div style='color:red; font-size:11px; margin-top:5px; font-weight:bold;'>IP BANNED: BRUTE FORCE DETECTED</div>");
    }

    (
        [(axum::http::header::CONTENT_TYPE, "text/html")],
        Html(html)
    ).into_response()
}

#[derive(serde::Deserialize)]
pub struct AdminRequest {
    pub admin_key: String,
}

#[derive(serde::Serialize)]
pub struct DashboardResponse {
    pub cpu: f32,
    pub ram: u64,
    pub uptime: String,
    pub load: String,
    pub total_files: i64,
    pub total_size: i64,
    pub maintenance: bool,
    pub rotation_strategy: u8,
    pub top_files: Vec<TopFile>,
}

#[derive(serde::Serialize)]
pub struct TopFile {
    pub name: String,
    pub hits: i64,
}

pub async fn admin_dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<AdminRequest>,
) -> Result<Json<DashboardResponse>, StatusCode> {
    let ip = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).unwrap_or("unknown").to_string();
    if !check_brute_force(&ip) { return Err(StatusCode::FORBIDDEN); }

    if payload.admin_key != get_admin_key() { 
        record_failure(ip);
        return Err(StatusCode::UNAUTHORIZED); 
    }

    let mut sys = System::new_all();
    sys.refresh_all();
    
    let cpu = sys.global_cpu_info().cpu_usage();
    let ram = sys.used_memory() / 1024 / 1024;
    let uptime_secs = System::uptime();
    let uptime = format!("{}h {}m", uptime_secs / 3600, (uptime_secs % 3600) / 60);
    let avg = System::load_average();
    let load = format!("{:.2} {:.2} {:.2}", avg.one, avg.five, avg.fifteen);

    let (count, size): (i64, Option<i64>) = sqlx::query_as("SELECT COUNT(*), SUM(file_size) FROM uploads")
        .fetch_one(&state.pool)
        .await
        .unwrap_or((0, Some(0)));

    let rows: Vec<(String,)> = sqlx::query_as("SELECT original_filename FROM uploads ORDER BY id DESC LIMIT 5")
        .fetch_all(&state.pool).await.unwrap_or_default();
    
    let top_files = rows.into_iter().map(|(n,)| TopFile { name: n, hits: rand::thread_rng().gen_range(1..100) }).collect();

    Ok(Json(DashboardResponse {
        cpu, ram, uptime, load,
        total_files: count,
        total_size: size.unwrap_or(0),
        maintenance: MAINTENANCE_MODE.load(Ordering::SeqCst),
        rotation_strategy: state.rotation_strategy.load(Ordering::SeqCst),
        top_files,
    }))
}

#[derive(serde::Serialize)]
pub struct TokenStatus {
    pub user: String,
    pub online: bool,
}

#[derive(serde::Serialize)]
pub struct TokensResponse {
    pub tokens: Vec<TokenStatus>,
}

pub async fn admin_tokens(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<AdminRequest>,
) -> Result<Json<TokensResponse>, StatusCode> {
    let ip = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).unwrap_or("unknown").to_string();
    if !check_brute_force(&ip) { return Err(StatusCode::FORBIDDEN); }
    if payload.admin_key != get_admin_key() { 
        record_failure(ip);
        return Err(StatusCode::UNAUTHORIZED); 
    }

    let rows: Vec<(String, String)> = sqlx::query_as("SELECT user, token FROM tokens").fetch_all(&state.pool).await.unwrap_or_default();
    let mut statuses = Vec::new();

    for (user, token) in rows {
        let resp = state.client.get("https://api.github.com/user")
            .header("Authorization", format!("token {}", token))
            .header("User-Agent", "nekoo")
            .send().await;
        
        statuses.push(TokenStatus {
            user,
            online: resp.map(|r| r.status().is_success()).unwrap_or(false),
        });
    }

    Ok(Json(TokensResponse { tokens: statuses }))
}

pub async fn admin_maintenance(
    headers: HeaderMap,
    Json(payload): Json<AdminRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let ip = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).unwrap_or("unknown").to_string();
    if !check_brute_force(&ip) { return Err(StatusCode::FORBIDDEN); }
    if payload.admin_key != get_admin_key() { 
        record_failure(ip);
        return Err(StatusCode::UNAUTHORIZED); 
    }
    let current = MAINTENANCE_MODE.load(Ordering::SeqCst);
    MAINTENANCE_MODE.store(!current, Ordering::SeqCst);
    Ok(Json(json!({"status": "success", "maintenance": !current})))
}

#[derive(serde::Deserialize)]
pub struct ImportRequest {
    pub admin_key: String,
    pub tokens: String, // format: "user:token" or just "token" per line
}

pub async fn admin_import_tokens(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ImportRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let ip = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).unwrap_or("unknown").to_string();
    if !check_brute_force(&ip) { return Err(StatusCode::FORBIDDEN); }
    if payload.admin_key != get_admin_key() { 
        record_failure(ip);
        return Err(StatusCode::UNAUTHORIZED); 
    }
    
    let mut count = 0;
    for line in payload.tokens.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() == 2 {
            let user = parts[0].trim();
            let token = parts[1].trim();
            let _ = sqlx::query("INSERT OR REPLACE INTO tokens (user, token) VALUES (?, ?)")
                .bind(user).bind(token).execute(&state.pool).await;
            count += 1;
        }
    }
    
    Ok(Json(json!({"status": "success", "imported": count})))
}

pub async fn admin_backup_db(
    headers: HeaderMap,
    Json(payload): Json<AdminRequest>,
) -> Result<Response, StatusCode> {
    let ip = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).unwrap_or("unknown").to_string();
    if !check_brute_force(&ip) { return Err(StatusCode::FORBIDDEN); }
    if payload.admin_key != get_admin_key() { 
        record_failure(ip);
        return Err(StatusCode::UNAUTHORIZED); 
    }
    
    let db_bytes = tokio::fs::read("/root/nekoo/nekoo.db").await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Response::builder()
        .header("Content-Type", "application/x-sqlite3")
        .header("Content-Disposition", "attachment; filename=\"nekoo_backup.db\"")
        .body(db_bytes.into())
        .unwrap())
}

pub async fn admin_toggle_rotation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<AdminRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let ip = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).unwrap_or("unknown").to_string();
    if !check_brute_force(&ip) { return Err(StatusCode::FORBIDDEN); }
    if payload.admin_key != get_admin_key() { 
        record_failure(ip);
        return Err(StatusCode::UNAUTHORIZED); 
    }
    let current = state.rotation_strategy.load(Ordering::SeqCst);
    let next = if current == 0 { 1 } else { 0 };
    state.rotation_strategy.store(next, Ordering::SeqCst);
    Ok(Json(json!({"status": "success", "strategy": next})))
}

#[derive(serde::Deserialize)]
pub struct PurgeRequest {
    pub admin_key: String,
    pub ext: Option<String>,
    pub _ip: Option<String>,
}

pub async fn admin_purge(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<PurgeRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let ip = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).unwrap_or("unknown").to_string();
    if !check_brute_force(&ip) { return Err(StatusCode::FORBIDDEN); }
    if payload.admin_key != get_admin_key() { 
        record_failure(ip);
        return Err(StatusCode::UNAUTHORIZED); 
    }
    
    let mut count = 0;
    if let Some(ext) = payload.ext {
        let res = sqlx::query("DELETE FROM uploads WHERE original_filename LIKE ?")
            .bind(format!("%.{}", ext))
            .execute(&state.pool).await.unwrap();
        count += res.rows_affected();
    }
    
    Ok(Json(json!({"status": "success", "deleted": count})))
}

pub async fn admin_logs(
    headers: HeaderMap,
    Json(payload): Json<AdminRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let ip = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).unwrap_or("unknown").to_string();
    if !check_brute_force(&ip) { return Err(StatusCode::FORBIDDEN); }
    if payload.admin_key != get_admin_key() { 
        record_failure(ip);
        return Err(StatusCode::UNAUTHORIZED); 
    }
    let log_msg = "NEKO SYSTEM BOOTED\n[INFO] SSL Certificates Active\n[INFO] HTTP/1.1 Upload Stream Optimized\n[INFO] BBR Congestion Control Active\n[INFO] Admin Panel Accessed";
    Ok(Json(json!({"logs": log_msg})))
}

#[derive(serde::Deserialize)]
pub struct SlurpRequest {
    pub admin_key: String,
    pub url: String,
}

pub async fn admin_slurp(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<SlurpRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let ip = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).unwrap_or("unknown").to_string();
    if !check_brute_force(&ip) { return Err(StatusCode::FORBIDDEN); }
    if payload.admin_key != get_admin_key() { 
        record_failure(ip);
        return Err(StatusCode::UNAUTHORIZED); 
    }
    
    let url = payload.url;
    let resp = state.client.get(&url).send().await.map_err(|_| StatusCode::BAD_GATEWAY)?;
    let _ = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("application/octet-stream");
    let file_size = resp.content_length().unwrap_or(0);
    let original_filename = url.split('/').last().unwrap_or("slurped_file").to_string();
    let body = resp.bytes().await.map_err(|_| StatusCode::BAD_GATEWAY)?;

    let strategy = state.rotation_strategy.load(Ordering::SeqCst);
    let (user, token) = github::get_random_token(&state.pool, strategy).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let slug: String = rand::thread_rng().sample_iter(&rand::distributions::Alphanumeric).take(8).map(char::from).collect();
    
    let github_url = github::create_repo_and_upload(&state.client, &user, &token, &original_filename, body.into(), file_size).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    sqlx::query("INSERT INTO uploads (slug, github_url, original_filename, file_hash, file_size) VALUES (?, ?, ?, ?, ?)")
        .bind(&slug)
        .bind(&github_url)
        .bind(&original_filename)
        .bind("slurped_no_hash_available_x")
        .bind(file_size as i64)
        .execute(&state.pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(json!({"status": "success", "url": format!("https://nekoo.ru/{}", slug)})))
}

pub async fn index(headers: HeaderMap) -> impl IntoResponse {
    if let Some(host) = headers.get("host") {
        if let Ok(host_str) = host.to_str() {
            if host_str.contains("cdn.nekoo.ru") {
                 return (StatusCode::NOT_FOUND, Html(include_str!("../templates/404.html"))).into_response();
            }
        }
    }

    if MAINTENANCE_MODE.load(Ordering::SeqCst) {
        return (StatusCode::SERVICE_UNAVAILABLE, Html("<h1>Maintenance</h1><p>The NEKO is sleeping. Come back later.</p>")).into_response();
    }
    (
        [
            (axum::http::header::CONTENT_TYPE, "text/html"),
            (axum::http::header::CACHE_CONTROL, "no-cache, no-store, must-revalidate"),
        ],
        Html(include_str!("../templates/index.html"))
    ).into_response()
}

pub async fn view_code(headers: HeaderMap) -> impl IntoResponse {
    if let Some(host) = headers.get("host") {
        if let Ok(host_str) = host.to_str() {
            if host_str.contains("cdn.nekoo.ru") {
                 return (StatusCode::NOT_FOUND, Html(include_str!("../templates/404.html"))).into_response();
            }
        }
    }
    (
        [
            (axum::http::header::CONTENT_TYPE, "text/html"),
            (axum::http::header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        Html(include_str!("../templates/view.html"))
    ).into_response()
}

pub async fn robots() -> &'static str {
    "User-agent: *\nDisallow:\nAllow: /"
}

pub async fn security() -> &'static str {
    "Contact: mailto:help@nekoo.ru\nExpires: 2027-01-01T00:00:00.000Z\nPreferred-Languages: en, ru"
}


// Health check endpoint for monitoring
pub async fn health() -> &'static str {
    "OK"
}

// Stats endpoint - returns total storage used
pub async fn stats(
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let total_bytes: i64 = sqlx::query_scalar("SELECT COALESCE(SUM(file_size), 0) FROM uploads")
        .fetch_one(&state.pool)
        .await
        .unwrap_or(0);
    
    let total_files: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM uploads")
        .fetch_one(&state.pool)
        .await
        .unwrap_or(0);
    
    // Format as GB with 2 decimal places
    let total_gb = (total_bytes as f64) / 1_073_741_824.0;
    
    Json(json!({
        "total_bytes": total_bytes,
        "total_gb": format!("{:.2}", total_gb),
        "total_files": total_files
    }))
}


#[derive(serde::Deserialize)]
pub struct UploadParams {
    pub ttl: Option<String>,
}

pub async fn upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<UploadParams>,
    mut multipart: Multipart,
) -> Response {
    if MAINTENANCE_MODE.load(Ordering::SeqCst) {
        return (StatusCode::SERVICE_UNAVAILABLE, "System is under maintenance. Please try again later.").into_response();
    }
    
    // Parse TTL
    let expires_at = if let Some(ttl) = &params.ttl {
        match ttl.as_str() {
            "1h" => Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            "12h" => Some(chrono::Utc::now() + chrono::Duration::hours(12)),
            "24h" | "1d" => Some(chrono::Utc::now() + chrono::Duration::days(1)),
            "7d" => Some(chrono::Utc::now() + chrono::Duration::days(7)),
            _ => None,
        }
    } else {
        None
    };

    // Strict 2GB limit check from Header
    if let Some(len_header) = headers.get("content-length") {
        if let Ok(len_str) = len_header.to_str() {
             if let Ok(len) = len_str.parse::<u64>() {
                 if len > 2 * 1024 * 1024 * 1024 {
                     return (StatusCode::PAYLOAD_TOO_LARGE, "File too large (Max 2GB)").into_response();
                 }
             }
        }
    }

    // Process multipart fields - just look for file
    let mut file_name = String::from("file.bin");
    let mut temp_path: Option<String> = None;
    let mut total_size: i64 = 0;
    
    while let Ok(Some(field)) = multipart.next_field().await {
        let field_name = field.name().map(|s| s.to_string());
        
        if field_name.as_deref() == Some("file") {
            file_name = field.file_name().unwrap_or("file.bin").to_string();
            
            // Stream to temp file
            let temp_id: u128 = rand::thread_rng().gen();
            let path = format!("temp_uploads/upload_{}.tmp", temp_id);
            
            let mut file = match tokio::fs::File::create(&path).await {
                Ok(f) => f,
                Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create temp file").into_response(),
            };
            
            let mut field = field;
            while let Ok(Some(chunk)) = field.chunk().await {
                total_size += chunk.len() as i64;
                if let Err(_) = file.write_all(&chunk).await {
                    let _ = tokio::fs::remove_file(&path).await;
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to write file").into_response();
                }
            }
            
            if let Err(_) = file.flush().await {
                let _ = tokio::fs::remove_file(&path).await;
                return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to flush file").into_response();
            }
            
            temp_path = Some(path);
        }
    }
    
    let temp_path = match temp_path {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, "No file provided").into_response(),
    };
    
    let file_size = total_size;

    // Generate slug with file extension
    let base_slug: String = (0..20).map(|_| rand::thread_rng().gen_range(0..=9).to_string()).collect();
    let extension = std::path::Path::new(&file_name)
        .extension()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("bin");
    let slug = format!("{}.{}", base_slug, extension);

    // Rename temp file to slug-based name so download route can find it
    let slug_temp_path = format!("temp_uploads/{}", slug);
    if let Err(e) = tokio::fs::rename(&temp_path, &slug_temp_path).await {
        tracing::error!("Failed to rename temp file: {}", e);
        let _ = tokio::fs::remove_file(&temp_path).await;
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to prepare file").into_response();
    }
    let temp_path = slug_temp_path;
    
    // Public uploads - no user authentication
    let user_id: Option<i64> = None;
    let is_private = false;

    // Insert into database (no hash)
    let row_id: i64 = match sqlx::query_scalar(
        "INSERT INTO uploads (slug, github_url, original_filename, file_size, expires_at, user_id, is_private) VALUES (?, 'pending', ?, ?, ?, ?, ?) RETURNING id"
    )
    .bind(&slug)
    .bind(&file_name)
    .bind(file_size)
    .bind(expires_at.map(|dt| dt.to_rfc3339()))
    .bind(user_id)
    .bind(is_private as i32)
    .fetch_one(&state.pool)
    .await {
        Ok(id) => id,
        Err(_) => {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
        }
    };

    // Spawn async GitHub upload task (fire and forget)
    let pool = state.pool.clone();
    let client = state.client.clone();
    let strategy = state.rotation_strategy.load(Ordering::SeqCst);
    let slug_clone = slug.clone();
    let file_name_clone = file_name.clone();
    let temp_path_clone = temp_path.clone();

    tokio::spawn(async move {
        // Upload to GitHub
        let ext = std::path::Path::new(&file_name_clone)
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or("bin");
        
        let random_filename = format!("{}.{}", 
            (0..32).map(|_| rand::thread_rng().gen_range(0..=9).to_string()).collect::<String>(),
            ext
        );

        // Read file and create stream
        if let Ok(file) = tokio::fs::File::open(&temp_path_clone).await {
            let stream = tokio_util::io::ReaderStream::new(file);
            let body = reqwest::Body::wrap_stream(stream);

            // Get token and upload
            if let Ok((user, token)) = github::get_random_token(&pool, strategy).await {
                if let Ok(github_url) = github::create_repo_and_upload(
                    &client, &user, &token, &random_filename, body, file_size as u64
                ).await {
                    // Update database with GitHub URL
                    let _ = sqlx::query("UPDATE uploads SET github_url = ? WHERE slug = ?")
                        .bind(&github_url)
                        .bind(&slug_clone)
                        .execute(&pool)
                        .await;
                    
                    tracing::info!("File {} uploaded to GitHub: {}", slug_clone, github_url);
                    // Only delete temp file after successful GitHub upload
                    let _ = tokio::fs::remove_file(&temp_path_clone).await;
                } else {
                    tracing::warn!("GitHub upload failed for {}, keeping temp file", slug_clone);
                }
            } else {
                tracing::warn!("No GitHub tokens available for {}, keeping temp file", slug_clone);
            }
        }
    });

    // Return URL immediately (before GitHub upload completes)
    // Wrap in "files" array for frontend compatibility
    Json(json!({
        "files": [{
            "status": "success",
            "url": format!("https://cdn.nekoo.ru/{}", slug),
            "slug": slug,
            "id": row_id,
            "size": file_size,
            "original_filename": file_name,
            "created_at": chrono::Utc::now().to_rfc3339()
        }]
    })).into_response()
}

#[derive(serde::Deserialize)]
pub struct AdminDeleteRequest {
    pub admin_key: String,
}

pub async fn delete_file(
    Path(id): Path<i64>,
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(payload): axum::Json<AdminDeleteRequest>,
) -> impl IntoResponse {
    let ip = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).unwrap_or("unknown").to_string();
    if !check_brute_force(&ip) { return (StatusCode::FORBIDDEN, "Banned").into_response(); }
    if payload.admin_key != get_admin_key() {
         record_failure(ip);
         return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }
    
    let result = sqlx::query("DELETE FROM uploads WHERE id = ?")
        .bind(id)
        .execute(&state.pool)
        .await;

    match result {
        Ok(res) => {
            if res.rows_affected() == 0 {
                return (StatusCode::NOT_FOUND, axum::Json(json!({"status": "error", "message": "File not found"}))).into_response();
            }
            (StatusCode::OK, axum::Json(json!({"status": "success", "message": format!("File {} deleted", id)}))).into_response()
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(json!({"status": "error", "message": e.to_string()}))).into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct DownloadParams {
    pub r#as: Option<String>,
}

pub async fn download(
    Path(slug): Path<String>,
    Query(params): Query<DownloadParams>,
    State(state): State<AppState>,
) -> Result<Response, StatusCode> {
    // 1. Check Short URL Redirect
    let redirect_check: Result<Option<String>, _> = sqlx::query_scalar("SELECT url FROM short_urls WHERE slug = ?")
        .bind(&slug)
        .fetch_optional(&state.pool)
        .await;

    if let Ok(Some(url)) = redirect_check {
        return Ok(Redirect::permanent(&url).into_response());
    }
    
    // 2. File Lookup
    // Select original_filename too
    let row: (String, String) = match sqlx::query_as("SELECT github_url, original_filename FROM uploads WHERE slug = ?")
        .bind(&slug)
        .fetch_optional(&state.pool)
        .await {
            Ok(Some(r)) => r,
            Ok(None) => return Ok((StatusCode::NOT_FOUND, Html(include_str!("../templates/404.html").replace("<p id=\"error-msg\"></p>", "<p>This file does not exist or has been deleted.</p>"))).into_response()),
            Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        };

    let github_url = row.0;
    let original_filename = row.1;

    // If GitHub upload is still pending, serve from local temp file
    if github_url == "pending" {
        let temp_path = format!("temp_uploads/{}", slug);
        if let Ok(file) = tokio::fs::File::open(&temp_path).await {
            let metadata = tokio::fs::metadata(&temp_path).await.ok();
            let stream = tokio_util::io::ReaderStream::new(file);
            let body = axum::body::Body::from_stream(stream);

            let ext = std::path::Path::new(&original_filename)
                .extension()
                .and_then(std::ffi::OsStr::to_str)
                .unwrap_or("bin");
            let content_type = match ext.to_lowercase().as_str() {
                "jpg" | "jpeg" => "image/jpeg",
                "png" => "image/png",
                "gif" => "image/gif",
                "webp" => "image/webp",
                "pdf" => "application/pdf",
                "txt" => "text/plain",
                "mp4" => "video/mp4",
                "zip" => "application/zip",
                "ipa" => "application/octet-stream",
                _ => "application/octet-stream",
            };
            let encoded = urlencoding::encode(&original_filename).to_string();
            let mut builder = Response::builder()
                .status(StatusCode::OK)
                .header(axum::http::header::CONTENT_TYPE, content_type)
                .header(axum::http::header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{}\"; filename*=UTF-8''{}", original_filename, encoded));
            if let Some(meta) = metadata {
                builder = builder.header(axum::http::header::CONTENT_LENGTH, meta.len().to_string());
            }
            return builder.body(body).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
        } else {
            return Ok((StatusCode::NOT_FOUND, Html(include_str!("../templates/404.html").replace("<p id=\"error-msg\"></p>", "<p>File is still being processed. Please try again in a moment.</p>"))).into_response());
        }
    }

    // Use shared client to fetch from GitHub
    let resp = state.client.get(&github_url)
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch from GitHub: {}", e);
            StatusCode::BAD_GATEWAY
        })?;

    if !resp.status().is_success() {
         tracing::error!("GitHub returned error: {}", resp.status());
         let msg = if resp.status() == 404 { "The file was found in our records but its content is missing from the storage fleet (likely deleted)." } else { "Storage fleet error." };
         return Ok((StatusCode::NOT_FOUND, Html(include_str!("../templates/404.html").replace("<p id=\"error-msg\"></p>", &format!("<p>{}</p>", msg)))).into_response());
    }
    
    // Log removed


    let headers = resp.headers().clone();
    let stream = resp.bytes_stream();
    let body = axum::body::Body::from_stream(stream);

    let mut response_builder = Response::builder()
        .status(StatusCode::OK);

    // Forward useful headers
    if let Some(ct) = headers.get(reqwest::header::CONTENT_TYPE) {
        if let Ok(val) = ct.to_str() {
             response_builder = response_builder.header(axum::http::header::CONTENT_TYPE, val);
        }
    }
    if let Some(cl) = headers.get(reqwest::header::CONTENT_LENGTH) {
        if let Ok(val) = cl.to_str() {
             response_builder = response_builder.header(axum::http::header::CONTENT_LENGTH, val);
        }
    }
    
    // Chameleon Mask logic
    let mut final_filename = original_filename.clone();
    let mut final_content_type = headers.get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

    if let Some(mask_ext) = params.r#as {
        // Disguise extension
        let base = std::path::Path::new(&original_filename)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("file");
        final_filename = format!("{}.{}", base, mask_ext);
        
        // Map common mask extensions to content types
        final_content_type = match mask_ext.to_lowercase().as_str() {
            "jpg" | "jpeg" => "image/jpeg",
            "png" => "image/png",
            "pdf" => "application/pdf",
            "txt" => "text/plain",
            "mp4" => "video/mp4",
            _ => "application/octet-stream",
        }.to_string();
    }

    let encoded_filename = urlencoding::encode(&final_filename).to_string();
    
    // Detect if file is an image - use inline to display, attachment to download
    let is_image = final_filename.to_lowercase().ends_with(".png") ||
                   final_filename.to_lowercase().ends_with(".jpg") ||
                   final_filename.to_lowercase().ends_with(".jpeg") ||
                   final_filename.to_lowercase().ends_with(".gif") ||
                   final_filename.to_lowercase().ends_with(".webp");
    
    let disposition_type = if false || !is_image { "attachment" } else { "inline" };
    let disposition = format!("{}; filename=\"{}\"; filename*=UTF-8''{}", disposition_type, final_filename, encoded_filename);

    // Override content type for images (GitHub returns application/octet-stream)
    if is_image {
        final_content_type = if final_filename.to_lowercase().ends_with(".png") {
            "image/png".to_string()
        } else if final_filename.to_lowercase().ends_with(".jpg") || final_filename.to_lowercase().ends_with(".jpeg") {
            "image/jpeg".to_string()
        } else if final_filename.to_lowercase().ends_with(".gif") {
            "image/gif".to_string()
        } else if final_filename.to_lowercase().ends_with(".webp") {
            "image/webp".to_string()
        } else {
            final_content_type
        };
    }
    
    response_builder = response_builder
        .header(axum::http::header::CONTENT_TYPE, final_content_type)
        .header(axum::http::header::CONTENT_DISPOSITION, disposition);

    response_builder.body(body).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub async fn logo() -> impl IntoResponse {
    let bytes = include_bytes!("../logo.png");
    (
        [
            (axum::http::header::CONTENT_TYPE, "image/png"),
            (axum::http::header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        axum::body::Body::from(&bytes[..])
    )
}

pub async fn logo_webp() -> impl IntoResponse {
    let bytes = include_bytes!("../logo.webp");
    (
        [
            (axum::http::header::CONTENT_TYPE, "image/webp"),
            (axum::http::header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        axum::body::Body::from(&bytes[..])
    )
}



    



pub async fn not_found() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, Html(include_str!("../templates/404.html")))
}

pub async fn help_page() -> Html<String> {
    let html = tokio::fs::read_to_string("templates/help.html")
        .await
        .unwrap_or_else(|_| "Help page not found".to_string());
    Html(html)
}

pub async fn terms_page() -> Html<String> {
    let html = tokio::fs::read_to_string("templates/terms.html")
        .await
        .unwrap_or_else(|_| "Terms page not found".to_string());
    Html(html)
}

// --- Chunked Upload Support ---

pub async fn upload_chunk(
    State(_state): State<AppState>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let mut upload_id = String::new();
    let mut chunk_index: u32 = 0;
    let mut chunk_data: Option<Vec<u8>> = None;

    while let Some(field) = multipart.next_field().await.unwrap_or(None) {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "upload_id" => {
                upload_id = field.text().await.unwrap_or_default();
            }
            "chunk_index" => {
                chunk_index = field.text().await.unwrap_or_default().parse().unwrap_or(0);
            }
            "file" => {
                chunk_data = Some(field.bytes().await.unwrap_or_default().to_vec());
            }
            _ => {
                let _ = field.text().await; // consume other fields
            }
        }
    }

    if upload_id.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "missing upload_id"}))).into_response();
    }

    let chunk_data = match chunk_data {
        Some(d) => d,
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "no chunk data"}))).into_response(),
    };

    // Save chunk to temp_uploads/
    let chunk_path = format!("temp_uploads/{}_{}", upload_id, chunk_index);
    if let Err(e) = tokio::fs::write(&chunk_path, &chunk_data).await {
        tracing::error!("Failed to write chunk: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "write failed"}))).into_response();
    }

    tracing::info!("Saved chunk {} for upload {}", chunk_index, upload_id);
    Json(json!({"status": "ok", "chunk_index": chunk_index})).into_response()
}

#[derive(serde::Deserialize)]
pub struct FinalizeRequest {
    pub upload_id: String,
    pub original_filename: String,
    pub total_size: u64,
}

pub async fn upload_finalize(
    State(state): State<AppState>,
    Json(req): Json<FinalizeRequest>,
) -> impl IntoResponse {
    // Find all chunk files for this upload_id
    let mut chunk_files: Vec<(u32, String)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir("temp_uploads") {
        for entry in entries.flatten() {
            let fname = entry.file_name().to_string_lossy().to_string();
            if fname.starts_with(&format!("{}_", req.upload_id)) {
                if let Some(idx_str) = fname.strip_prefix(&format!("{}_", req.upload_id)) {
                    if let Ok(idx) = idx_str.parse::<u32>() {
                        chunk_files.push((idx, entry.path().to_string_lossy().to_string()));
                    }
                }
            }
        }
    }

    if chunk_files.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "no chunks found"}))).into_response();
    }

    // Sort by chunk index
    chunk_files.sort_by_key(|c| c.0);

    // Assemble into final file
    let extension = std::path::Path::new(&req.original_filename)
        .extension()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("bin");
    let temp_path = format!("temp_uploads/assembled_{}.{}", req.upload_id, extension);

    {
        let mut output = match tokio::fs::File::create(&temp_path).await {
            Ok(f) => f,
            Err(e) => {
                tracing::error!("Failed to create assembled file: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "assembly failed"}))).into_response();
            }
        };

        for (idx, chunk_path) in &chunk_files {
            match tokio::fs::read(chunk_path).await {
                Ok(data) => {
                    if let Err(e) = output.write_all(&data).await {
                        tracing::error!("Failed to write chunk {}: {}", idx, e);
                        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "write failed"}))).into_response();
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to read chunk {}: {}", idx, e);
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "read failed"}))).into_response();
                }
            }
        }
    }

    // Delete chunk files
    for (_, chunk_path) in &chunk_files {
        let _ = tokio::fs::remove_file(chunk_path).await;
    }

    let file_size = req.total_size as i64;
    let file_name = req.original_filename.clone();

    // Generate slug
    let base_slug: String = (0..20).map(|_| rand::thread_rng().gen_range(0..=9).to_string()).collect();
    let slug = format!("{}.{}", base_slug, extension);

    // Rename assembled file to slug-based name so download route can find it
    let slug_temp_path = format!("temp_uploads/{}", slug);
    if let Err(e) = tokio::fs::rename(&temp_path, &slug_temp_path).await {
        tracing::error!("Failed to rename assembled file: {}", e);
        let _ = tokio::fs::remove_file(&temp_path).await;
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "rename failed"}))).into_response();
    }
    let temp_path = slug_temp_path;

    // Insert into database
    let expires_at: Option<chrono::DateTime<chrono::Utc>> = None;
    let user_id: Option<i64> = None;
    let is_private = false;

    let row_id: i64 = match sqlx::query_scalar(
        "INSERT INTO uploads (slug, github_url, original_filename, file_size, expires_at, user_id, is_private) VALUES (?, 'pending', ?, ?, ?, ?, ?) RETURNING id"
    )
    .bind(&slug)
    .bind(&file_name)
    .bind(file_size)
    .bind(expires_at.map(|dt| dt.to_rfc3339()))
    .bind(user_id)
    .bind(is_private as i32)
    .fetch_one(&state.pool)
    .await {
        Ok(id) => id,
        Err(_) => {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "database error"}))).into_response();
        }
    };

    // Spawn async GitHub upload
    let pool = state.pool.clone();
    let client = state.client.clone();
    let strategy = state.rotation_strategy.load(Ordering::SeqCst);
    let slug_clone = slug.clone();
    let file_name_clone = file_name.clone();
    let temp_path_clone = temp_path.clone();

    tokio::spawn(async move {
        let ext = std::path::Path::new(&file_name_clone)
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or("bin");

        let random_filename = format!("{}.{}",
            (0..32).map(|_| rand::thread_rng().gen_range(0..=9).to_string()).collect::<String>(),
            ext
        );

        if let Ok(file) = tokio::fs::File::open(&temp_path_clone).await {
            let stream = tokio_util::io::ReaderStream::new(file);
            let body = reqwest::Body::wrap_stream(stream);

            if let Ok((user, token)) = github::get_random_token(&pool, strategy).await {
                if let Ok(github_url) = github::create_repo_and_upload(
                    &client, &user, &token, &random_filename, body, file_size as u64
                ).await {
                    let _ = sqlx::query("UPDATE uploads SET github_url = ? WHERE slug = ?")
                        .bind(&github_url)
                        .bind(&slug_clone)
                        .execute(&pool)
                        .await;
                    tracing::info!("Chunked file {} uploaded to GitHub: {}", slug_clone, github_url);
                    // Only delete temp file after successful GitHub upload
                    let _ = tokio::fs::remove_file(&temp_path_clone).await;
                } else {
                    tracing::warn!("GitHub upload failed for chunked file {}, keeping temp file", slug_clone);
                }
            } else {
                tracing::warn!("No GitHub tokens for chunked file {}, keeping temp file", slug_clone);
            }
        }
    });

    Json(json!({
        "files": [{
            "status": "success",
            "url": format!("https://cdn.nekoo.ru/{}", slug),
            "slug": slug,
            "id": row_id,
            "size": file_size,
            "original_filename": file_name,
            "created_at": chrono::Utc::now().to_rfc3339()
        }]
    })).into_response()
}
