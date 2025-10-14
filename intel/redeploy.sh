#!/bin/bash
# ===========================================================================
#  THE DAILY BRIEF — Redeploy from GitHub
# ===========================================================================
#  Usage: ./daily-brief-repo/redeploy.sh
#
#  Pulls latest code from GitHub and syncs to the deploy directories.
#  Run this on EC2 after pushing changes from any computer.
# ===========================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $1"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $1"; exit 1; }

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/home/ec2-user/daily-brief"
WEB_ROOT="/var/www/daily-brief"
UPDATED_BACKEND=false

echo ""
echo "==========================================================================="
echo "  THE DAILY BRIEF — Redeploy from GitHub"
echo "==========================================================================="
echo ""

# ===================================================================
# Step 1: Pull latest from GitHub
# ===================================================================

info "Pulling latest code from GitHub..."
GIT_ROOT="$(cd "$REPO_DIR" && git rev-parse --show-toplevel)"
cd "$GIT_ROOT" && git pull || fail "git pull failed — resolve conflicts or check credentials"
cd "$REPO_DIR"
ok "Code updated from GitHub"

# ===================================================================
# Step 2: Deploy web files (HTML, CSS, JS)
# ===================================================================

info "Syncing web files..."

declare -A WEB_FILES=(
    ["the-daily-brief.html"]="index.html"
    ["map.html"]="map.html"
    ["feed-dashboard.js"]="feed-dashboard.js"
    ["threat-map.js"]="threat-map.js"
    ["dashboard-enhancements.css"]="dashboard-enhancements.css"
    ["threat-map.css"]="threat-map.css"
)

WEB_COUNT=0
for src in "${!WEB_FILES[@]}"; do
    dest="${WEB_FILES[$src]}"
    if [ -f "$REPO_DIR/$src" ]; then
        cp "$REPO_DIR/$src" "$INSTALL_DIR/web/$dest"
        sudo cp "$INSTALL_DIR/web/$dest" "$WEB_ROOT/$dest"
        sudo chown nginx:nginx "$WEB_ROOT/$dest"
        WEB_COUNT=$((WEB_COUNT + 1))
    fi
done
ok "$WEB_COUNT web files synced"

# ===================================================================
# Step 3: Deploy backend files (aggregator + configs)
# ===================================================================

info "Syncing backend files..."

BACKEND_COUNT=0

if [ -f "$REPO_DIR/aggregate_feeds_enhanced.py" ]; then
    cp "$REPO_DIR/aggregate_feeds_enhanced.py" "$INSTALL_DIR/scripts/aggregate_feeds.py"
    BACKEND_COUNT=$((BACKEND_COUNT + 1))
    UPDATED_BACKEND=true
fi

for cfg in feeds.json platform_config.json countries.json; do
    if [ -f "$REPO_DIR/$cfg" ]; then
        cp "$REPO_DIR/$cfg" "$INSTALL_DIR/$cfg"
        BACKEND_COUNT=$((BACKEND_COUNT + 1))
        UPDATED_BACKEND=true
    fi
done

ok "$BACKEND_COUNT backend files synced"

# Note: api_keys.json is never overwritten from repo
if [ -f "$REPO_DIR/api_keys.json" ]; then
    warn "api_keys.json found in repo but NOT deployed (managed on EC2 only)"
fi

# ===================================================================
# Step 4: Re-run aggregator if backend changed
# ===================================================================

if [ "$UPDATED_BACKEND" = true ]; then
    info "Backend files changed — re-running feed aggregator..."
    source "$INSTALL_DIR/venv/bin/activate"

    python3 "$INSTALL_DIR/scripts/aggregate_feeds.py" \
        --project-dir "$INSTALL_DIR" \
        && ok "Aggregator completed" \
        || warn "Aggregator had errors (check output above)"

    deactivate

    if [ -f "$INSTALL_DIR/output/feed_data.json" ]; then
        sudo cp "$INSTALL_DIR/output/feed_data.json" "$WEB_ROOT/output/feed_data.json"
        sudo chown nginx:nginx "$WEB_ROOT/output/feed_data.json"
        ok "Feed data published to web root"
    fi
else
    info "No backend changes — skipping aggregator"
fi

# ===================================================================
# Summary
# ===================================================================

echo ""
echo "==========================================================================="
echo "  REDEPLOY COMPLETE"
echo "==========================================================================="
echo ""
echo "  Web files updated:     $WEB_COUNT"
echo "  Backend files updated: $BACKEND_COUNT"

if [ -f "$WEB_ROOT/output/feed_data.json" ]; then
    ARTICLE_COUNT=$(python3 -c "import json; d=json.load(open('$WEB_ROOT/output/feed_data.json')); print(d['metadata']['total_articles'])" 2>/dev/null || echo "?")
    echo "  Articles:              $ARTICLE_COUNT"
fi

echo ""
echo "  Redeploy complete."
echo ""
echo "==========================================================================="
