# Nekoo - File Hosting on GitHub Actions

File hosting service running on GitHub Actions with 5-account rotation for 24/7 uptime.

**Domain:** [dropl.link](https://dropl.link)

## Architecture

- **Storage:** GitHub Releases (unlimited)
- **Backend:** Rust (Axum framework)
- **Database:** SQLite
- **Tunnel:** Cloudflare Tunnel
- **Rotation:** 5 accounts × 6 hours each

## Deployment Schedule

- Account 1: 00:00-06:00 UTC & 12:00-18:00 UTC
- Account 2: 06:00-12:00 UTC & 18:00-24:00 UTC

## Setup Instructions

### 1. Fork to All 5 Accounts

Fork this repo to:
- avi8427/nekoo-host
- avimf2005/nekoo-host
- DaryoshKhiyam/nekoo-host
- vvvcertambos/nekoo-host
- cowgirlsz/nekoo-host

### 2. Configure Secrets

Each repo needs these secrets:

| Secret | Value |
|--------|-------|
| `CLOUDFLARE_TUNNEL_TOKEN` | `eyJhIjoiNDE2YzhkZmQ0OGQ3MDE3YWE3ZDNkYzM4NDEyMzU2Y2EiLCJ0IjoiNWZjODNkMzEtNWUxMS00NzQ1LTkxZGEtMTEwZTZjMTFhZTM4IiwicyI6IjhSbHZzeVF1Mjc4c1ZXU2dadmFmOXp2K2dWa0hBZEw0UHl1WDhZeHJONjg9In0=` |
| `ADMIN_KEY` | `OMCs71ym8oU3mDcT41LBoTr27N9pfKO3F-9fTv2z0Xczmmc1DEbdA6a6KDG9A6daWWSekOb08ytB9lrwu4WBRw` |

### 3. Enable Workflows

- Go to Actions tab in each repo
- Enable workflows
- Manually trigger first run to test

## Features

- File upload to GitHub Releases
- URL shortener
- Gallery with search
- Code viewer with syntax highlighting
- Automatic file deduplication

## Tech Stack

- Rust + Axum
- SQLite
- GitHub API
- Cloudflare Tunnel
