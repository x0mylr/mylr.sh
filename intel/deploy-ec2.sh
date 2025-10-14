#!/bin/bash
# ===========================================================================
#  THE DAILY BRIEF — EC2 Deployment Script (Amazon Linux 2023)
# ===========================================================================
#  Usage: ./deploy-ec2.sh <domain> <email>
#
#  Run this on an Amazon Linux 2023 EC2 instance after SCP'ing the project
#  files to ~/upload/. See EC2_SETUP.md for full instructions.
# ===========================================================================

set -euo pipefail

# --- Color output helpers ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $1"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $1"; exit 1; }

# ===================================================================
# Section 1: Argument parsing
# ===================================================================

if [ $# -lt 2 ]; then
    echo ""
    echo "Usage: $0 <domain> <email>"
    echo ""
    echo "  domain  Your domain or subdomain (e.g. intel.example.com)"
    echo "  email   Email for Let's Encrypt certificate notifications"
    echo ""
    echo "Example: $0 intel.mydomain.com admin@mydomain.com"
    echo ""
    exit 1
fi

DOMAIN="$1"
EMAIL="$2"
INSTALL_DIR="/home/ec2-user/daily-brief"
WEB_ROOT="/var/www/daily-brief"
UPLOAD_DIR="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo "==========================================================================="
echo "  THE DAILY BRIEF — EC2 Deployment"
echo "==========================================================================="
echo "  Domain:      $DOMAIN"
echo "  Email:       $EMAIL"
echo "  Install dir: $INSTALL_DIR"
echo "  Web root:    $WEB_ROOT"
echo "  Upload from: $UPLOAD_DIR"
echo "==========================================================================="
echo ""

# Validate we have the required source files
REQUIRED_FILES=("aggregate_feeds_enhanced.py" "feeds.json" "platform_config.json" "countries.json" "the-daily-brief.html" "feed-dashboard.js" "map.html" "threat-map.js" "dashboard-enhancements.css" "threat-map.css")
for f in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$UPLOAD_DIR/$f" ]; then
        fail "Required file not found: $UPLOAD_DIR/$f"
    fi
done
ok "All required source files found"

# ===================================================================
# Section 2: System packages (Amazon Linux 2023)
# ===================================================================

info "Installing system packages..."
sudo dnf update -y -q
sudo dnf install -y -q nginx python3 python3-pip python3-devel gcc cronie

# Enable and start services
sudo systemctl enable nginx
sudo systemctl enable crond
sudo systemctl start crond
ok "System packages installed"

# ===================================================================
# Section 3: Project directory structure
# ===================================================================

info "Creating directory structure..."
mkdir -p "$INSTALL_DIR"/{scripts,web/output,config,output,data,logs}
ok "Directory structure created"

# ===================================================================
# Section 4: File deployment
# ===================================================================

info "Deploying project files..."

# Aggregator script
cp "$UPLOAD_DIR/aggregate_feeds_enhanced.py" "$INSTALL_DIR/scripts/aggregate_feeds.py"

# Web files
cp "$UPLOAD_DIR/the-daily-brief.html"      "$INSTALL_DIR/web/index.html"
cp "$UPLOAD_DIR/map.html"                   "$INSTALL_DIR/web/map.html"
cp "$UPLOAD_DIR/feed-dashboard.js"          "$INSTALL_DIR/web/feed-dashboard.js"
cp "$UPLOAD_DIR/threat-map.js"              "$INSTALL_DIR/web/threat-map.js"
cp "$UPLOAD_DIR/dashboard-enhancements.css" "$INSTALL_DIR/web/dashboard-enhancements.css"
cp "$UPLOAD_DIR/threat-map.css"             "$INSTALL_DIR/web/threat-map.css"

# Config files (at project root — aggregator expects them here)
cp "$UPLOAD_DIR/feeds.json"            "$INSTALL_DIR/feeds.json"
cp "$UPLOAD_DIR/platform_config.json"  "$INSTALL_DIR/platform_config.json"
cp "$UPLOAD_DIR/countries.json"        "$INSTALL_DIR/countries.json"

# API keys — preserve existing if already configured
if [ -f "$INSTALL_DIR/api_keys.json" ]; then
    warn "api_keys.json already exists — preserving existing config"
else
    cp "$UPLOAD_DIR/api_keys.json" "$INSTALL_DIR/api_keys.json"
    info "Copied default api_keys.json (edit later to enable API feeds)"
fi

ok "Project files deployed"

# ===================================================================
# Section 5: Python virtual environment
# ===================================================================

info "Setting up Python virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"
pip install --upgrade pip -q
pip install feedparser requests geopy -q

# Optional enrichment packages (non-fatal if unavailable)
pip install OTXv2 vt-py 2>/dev/null || warn "Optional packages (OTXv2, vt-py) not installed — not required"

deactivate
ok "Python virtual environment ready"

# ===================================================================
# Section 6: Nginx configuration
# ===================================================================

info "Configuring Nginx..."

# Remove the default server block from nginx.conf if it exists
# Amazon Linux includes a default server {} block inside nginx.conf
if sudo grep -q "listen.*80 default_server" /etc/nginx/nginx.conf 2>/dev/null; then
    info "Removing default server block from nginx.conf..."
    sudo sed -i '/^    server {/,/^    }/d' /etc/nginx/nginx.conf
fi

# Write our site config
sudo tee /etc/nginx/conf.d/daily-brief.conf > /dev/null <<NGINXEOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    root ${WEB_ROOT};
    index index.html;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;

    location / {
        try_files \$uri \$uri/ =404;
    }

    # JSON data — no caching so dashboard always gets fresh data
    location /output/ {
        add_header Cache-Control "no-cache, must-revalidate";
        add_header Access-Control-Allow-Origin "*";
    }

    # Static assets — cache aggressively
    location ~* \.(css|js|png|jpg|ico|svg|woff2?)$ {
        expires 7d;
        add_header Cache-Control "public, immutable";
    }

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_types text/plain text/css application/json application/javascript text/xml;
    gzip_min_length 1000;

    access_log /var/log/nginx/daily-brief-access.log;
    error_log /var/log/nginx/daily-brief-error.log;
}
NGINXEOF

# Deploy web files to Nginx web root
sudo mkdir -p "$WEB_ROOT/output"
sudo cp -r "$INSTALL_DIR/web/"* "$WEB_ROOT/"
sudo chown -R nginx:nginx "$WEB_ROOT"

# Test and start Nginx
sudo nginx -t || fail "Nginx config test failed"
sudo systemctl restart nginx
ok "Nginx configured and running"

# ===================================================================
# Section 7: Let's Encrypt SSL
# ===================================================================

info "Installing Let's Encrypt SSL certificate..."
sudo dnf install -y -q certbot python3-certbot-nginx

# Check DNS resolution before attempting cert
if ! host "$DOMAIN" > /dev/null 2>&1; then
    warn "DNS for $DOMAIN does not resolve yet."
    warn "Make sure your A record points to this server's Elastic IP."
    warn "You can run certbot manually later:"
    warn "  sudo certbot --nginx -d $DOMAIN --non-interactive --agree-tos --email $EMAIL"
    echo ""
    SKIP_SSL=true
else
    sudo certbot --nginx -d "$DOMAIN" \
        --non-interactive \
        --agree-tos \
        --email "$EMAIL" \
        --redirect \
        && ok "SSL certificate installed and HTTP->HTTPS redirect enabled" \
        || { warn "Certbot failed — you can retry manually after DNS propagates:"; \
             warn "  sudo certbot --nginx -d $DOMAIN --non-interactive --agree-tos --email $EMAIL"; \
             SKIP_SSL=true; }
fi

# Certbot auto-renewal is handled by systemd timer on AL2023
if sudo systemctl list-timers | grep -q certbot 2>/dev/null; then
    ok "Certbot auto-renewal timer is active"
else
    # Fallback: add cron-based renewal
    (sudo crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet") | sudo crontab -
    ok "Added certbot renewal cron job"
fi

# ===================================================================
# Section 8: Update script + Cron
# ===================================================================

info "Creating update script and cron job..."

cat > "$INSTALL_DIR/scripts/update.sh" <<'UPDATEEOF'
#!/bin/bash
# The Daily Brief — Feed Update Script
# Runs every 30 minutes via cron

INSTALL_DIR="/home/ec2-user/daily-brief"
WEB_ROOT="/var/www/daily-brief"
LOG_FILE="$INSTALL_DIR/logs/cron.log"

cd "$INSTALL_DIR"
source "$INSTALL_DIR/venv/bin/activate"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting feed update..." >> "$LOG_FILE"

python3 "$INSTALL_DIR/scripts/aggregate_feeds.py" \
    --project-dir "$INSTALL_DIR" \
    >> "$LOG_FILE" 2>&1

# Copy generated data to web root
if [ -f "$INSTALL_DIR/output/feed_data.json" ]; then
    sudo cp "$INSTALL_DIR/output/feed_data.json" "$WEB_ROOT/output/feed_data.json"
    sudo chown nginx:nginx "$WEB_ROOT/output/feed_data.json"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Update complete — data published" >> "$LOG_FILE"
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Update failed — no output generated" >> "$LOG_FILE"
fi

deactivate
UPDATEEOF

chmod +x "$INSTALL_DIR/scripts/update.sh"

# Add cron job — every 30 minutes
(crontab -l 2>/dev/null | grep -v "update.sh"; echo "*/30 * * * * $INSTALL_DIR/scripts/update.sh") | crontab -
ok "Update script created, cron job set (every 30 min)"

# ===================================================================
# Section 9: File permissions
# ===================================================================

info "Setting file permissions..."
chmod 600 "$INSTALL_DIR/api_keys.json"
chmod +x "$INSTALL_DIR/scripts/"*.sh
ok "Permissions set (api_keys.json is 600)"

# ===================================================================
# Section 10: Initial aggregation run
# ===================================================================

info "Running initial feed aggregation..."
source "$INSTALL_DIR/venv/bin/activate"

python3 "$INSTALL_DIR/scripts/aggregate_feeds.py" \
    --project-dir "$INSTALL_DIR"

deactivate

# Publish to web root
if [ -f "$INSTALL_DIR/output/feed_data.json" ]; then
    sudo cp "$INSTALL_DIR/output/feed_data.json" "$WEB_ROOT/output/feed_data.json"
    sudo chown nginx:nginx "$WEB_ROOT/output/feed_data.json"
    ok "Feed data published to web root"
else
    warn "No feed_data.json generated — check logs at $INSTALL_DIR/logs/"
fi

# ===================================================================
# Section 11: Verification + Summary
# ===================================================================

echo ""
echo "==========================================================================="
echo "  DEPLOYMENT COMPLETE"
echo "==========================================================================="
echo ""

# Check article count
if [ -f "$WEB_ROOT/output/feed_data.json" ]; then
    ARTICLE_COUNT=$(python3 -c "import json; d=json.load(open('$WEB_ROOT/output/feed_data.json')); print(d['metadata']['total_articles'])" 2>/dev/null || echo "?")
    DEFCON=$(python3 -c "import json; d=json.load(open('$WEB_ROOT/output/feed_data.json')); print(d['metadata']['defcon_level'])" 2>/dev/null || echo "?")
    echo "  Articles:  $ARTICLE_COUNT"
    echo "  DEFCON:    $DEFCON"
else
    warn "Could not read feed data for verification"
fi

echo ""

if [ "${SKIP_SSL:-false}" = "true" ]; then
    echo "  Dashboard:  http://$DOMAIN"
    echo "  Threat Map: http://$DOMAIN/map.html"
    echo ""
    warn "SSL not yet configured — run certbot after DNS propagates:"
    echo "  sudo certbot --nginx -d $DOMAIN --non-interactive --agree-tos --email $EMAIL"
else
    echo "  Dashboard:  https://$DOMAIN"
    echo "  Threat Map: https://$DOMAIN/map.html"
fi

echo ""
echo "  Feeds update every 30 minutes via cron."
echo "  Logs: $INSTALL_DIR/logs/cron.log"
echo "  API keys: $INSTALL_DIR/api_keys.json (edit to enable enrichment feeds)"
echo ""
echo "  Manual update:  $INSTALL_DIR/scripts/update.sh"
echo "  Nginx logs:     /var/log/nginx/daily-brief-*.log"
echo "  SSL renewal:    sudo certbot renew --dry-run"
echo ""
echo "==========================================================================="
