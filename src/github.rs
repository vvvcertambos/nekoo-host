use sqlx::SqlitePool;
use reqwest::Client;
use rand::seq::SliceRandom;
use serde_json::json;

#[derive(sqlx::FromRow)]
struct Token {
    user: String,
    token: String,
}

pub async fn get_random_token(pool: &SqlitePool, strategy: u8) -> Result<(String, String), String> {
    let tokens = sqlx::query_as::<_, Token>("SELECT user, token FROM tokens ORDER BY id ASC")
        .fetch_all(pool)
        .await
        .map_err(|e| e.to_string())?;

    if tokens.is_empty() {
        return Err("No GitHub tokens available".to_string());
    }

    let chosen = if strategy == 1 {
        // Sequential (Using time/modulo as a simple persistent counter for all threads)
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let idx = (now as usize) % tokens.len();
        &tokens[idx]
    } else {
        // Random
        tokens.choose(&mut rand::thread_rng()).unwrap()
    };
    
    Ok((chosen.user.clone(), chosen.token.clone()))
}

pub async fn create_repo_and_upload(
    client: &Client,
    user: &str, 
    token: &str, 
    file_name: &str, 
    file_content: reqwest::Body,
    file_size: u64
) -> Result<String, String> {
    // client is passed in


    // ... repo/release creation ...
    
    use rand::Rng;
    let repo_name = format!("storage-{}", (0..40).map(|_| rand::thread_rng().gen_range(0..=9).to_string()).collect::<String>());

    // 1. Create Repo
    let create_url = "https://api.github.com/user/repos";
    let resp = client.post(create_url)
        .header("Authorization", format!("token {}", token))
        .header("User-Agent", "nekoo")
        .json(&json!({
            "name": repo_name,
            "private": false,
            "auto_init": true 
        }))
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        let txt = resp.text().await.unwrap_or_default();
        return Err(format!("Failed to create repo: {}", txt));
    }

    // Wait a bit for repo propagation
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // 2. Create Release
    let release_url = format!("https://api.github.com/repos/{}/{}/releases", user, repo_name);
    let resp = client.post(&release_url)
        .header("Authorization", format!("token {}", token))
        .header("User-Agent", "nekoo")
        .json(&json!({
            "tag_name": "v1",
            "name": "v1",
            "body": "Storage release"
        }))
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        return Err(format!("Failed to create release: {}", resp.text().await.unwrap_or_default()));
    }
    
    let release_data: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    let upload_url_template = release_data["upload_url"].as_str().ok_or("No upload_url in release")?;
    let upload_url = upload_url_template.replace("{?name,label}", "");

    // 3. Upload Asset (Streamed with Length)
    let upload_query_url = format!("{}?name={}", upload_url, file_name);
    let resp = client.post(&upload_query_url)
        .header("Authorization", format!("token {}", token))
        .header("User-Agent", "nekoo")
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", file_size)
        .timeout(std::time::Duration::from_secs(7200)) // 2 Hours
        .body(file_content)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        return Err(format!("Failed to upload asset: {}", resp.text().await.unwrap_or_default()));
    }
    
    let asset_data: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    let download_url = asset_data["browser_download_url"].as_str().ok_or("No browser_download_url")?;
    
    Ok(download_url.to_string())
}
