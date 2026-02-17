-- Create tokens table
CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT NOT NULL,
    token TEXT NOT NULL
);

-- Create uploads table
CREATE TABLE IF NOT EXISTS uploads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,
    github_url TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    file_hash TEXT,
    file_size INTEGER,
    expires_at INTEGER,
    user_id TEXT,
    is_private INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Create short_urls table
CREATE TABLE IF NOT EXISTS short_urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,
    url TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_uploads_slug ON uploads(slug);
CREATE INDEX IF NOT EXISTS idx_short_urls_slug ON short_urls(slug);
