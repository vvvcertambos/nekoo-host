#!/bin/bash
# Daily database backup script for Nekoo

DATE=$(date +%Y%m%d_%H%M%S)
DB_PATH="/root/nekoo/nekoo.db"
BACKUP_DIR="/root/nekoo/db_backups"
# Load environment variables
if [ -f /root/nekoo/.env ]; then
    export $(grep -v '^#' /root/nekoo/.env | xargs)
fi

GITHUB_TOKEN="$BACKUP_GITHUB_TOKEN"
REPO="KupQ/nekoo-backup"

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Create database backup
BACKUP_FILE="$BACKUP_DIR/nekoo_db_$DATE.db"
cp "$DB_PATH" "$BACKUP_FILE"

# Compress the backup
gzip "$BACKUP_FILE"
BACKUP_FILE="$BACKUP_FILE.gz"

# Keep only last 7 days of local backups
find "$BACKUP_DIR" -name "nekoo_db_*.db.gz" -mtime +7 -delete

# Create a GitHub release with the database backup
RELEASE_NAME="db-backup-$DATE"
RELEASE_TAG="backup-$DATE"

# Create release
RELEASE_RESPONSE=$(curl -s -X POST \
  -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.v3+json" \
  https://api.github.com/repos/$REPO/releases \
  -d "{
    \"tag_name\": \"$RELEASE_TAG\",
    \"name\": \"Database Backup - $DATE\",
    \"body\": \"Automated daily database backup\",
    \"draft\": false,
    \"prerelease\": false
  }")

# Extract upload URL and release ID
UPLOAD_URL=$(echo "$RELEASE_RESPONSE" | grep -o '"upload_url": "[^"]*' | cut -d'"' -f4 | sed 's/{?name,label}//')
RELEASE_ID=$(echo "$RELEASE_RESPONSE" | grep -o '"id": [0-9]*' | head -1 | cut -d' ' -f2)

if [ -n "$UPLOAD_URL" ]; then
    # Upload the database backup as a release asset
    curl -s -X POST \
      -H "Authorization: token $GITHUB_TOKEN" \
      -H "Content-Type: application/gzip" \
      --data-binary @"$BACKUP_FILE" \
      "${UPLOAD_URL}?name=nekoo_db_$DATE.db.gz"
    
    echo "Database backup uploaded to GitHub release: $RELEASE_TAG"
else
    echo "Failed to create GitHub release"
fi

# Clean up old GitHub releases (keep last 30)
RELEASES=$(curl -s -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/repos/$REPO/releases?per_page=100")

# Delete releases older than 30 days
echo "$RELEASES" | grep -o '"id": [0-9]*' | cut -d' ' -f2 | tail -n +31 | while read release_id; do
    curl -s -X DELETE \
      -H "Authorization: token $GITHUB_TOKEN" \
      "https://api.github.com/repos/$REPO/releases/$release_id"
done

echo "Backup completed: $BACKUP_FILE"
