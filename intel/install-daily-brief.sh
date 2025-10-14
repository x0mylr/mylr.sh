#!/bin/bash
###############################################################################
# The Daily Brief - Master Installation Script
# Complete threat intelligence platform deployment for WSL/Linux
###############################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BURNT_SIENNA='\033[38;5;166m'
NC='\033[0m'

# Configuration
PROJECT_NAME="The Daily Brief"
INSTALL_DIR="${HOME}/_x0mylr/intel/feeds"
WEB_ROOT="/var/www/daily-brief"
NGINX_AVAILABLE="/etc/nginx/sites-available/daily-brief"
NGINX_ENABLED="/etc/nginx/sites-enabled/daily-brief"

echo -e "${BURNT_SIENNA}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║        📰 THE DAILY BRIEF - INSTALLATION WIZARD          ║
║     Complete Threat Intelligence Platform Setup          ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

###############################################################################
# Step 1: Check Prerequisites
###############################################################################
echo -e "\n${BLUE}[1/10] Checking prerequisites...${NC}"

# Check if running as root (we'll need sudo later)
if [ "$EUID" -eq 0 ]; then 
   echo -e "${RED}Please run as regular user (not root). We'll ask for sudo when needed.${NC}"
   exit 1
fi

# Check for WSL or Linux
if ! grep -qi microsoft /proc/version 2>/dev/null && [ ! -f /etc/os-release ]; then
    echo -e "${RED}This script is designed for WSL or Linux environments${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Environment check passed${NC}"

###############################################################################
# Step 2: Install System Dependencies
###############################################################################
echo -e "\n${BLUE}[2/10] Installing system dependencies...${NC}"

sudo apt update

# Core dependencies
PACKAGES=(
    "nginx"
    "python3"
    "python3-pip"
    "python3-venv"
    "git"
    "curl"
    "jq"
    "certbot"
    "python3-certbot-nginx"
)

for package in "${PACKAGES[@]}"; do
    if ! dpkg -l | grep -q "^ii  $package "; then
        echo -e "${YELLOW}Installing $package...${NC}"
        sudo apt install -y "$package"
    else
        echo -e "${GREEN}✓ $package already installed${NC}"
    fi
done

###############################################################################
# Step 3: Create Project Structure
###############################################################################
echo -e "\n${BLUE}[3/10] Creating project structure...${NC}"

# Create main directories
mkdir -p "${INSTALL_DIR}"/{config,scripts,web,output,logs,data,backups}

# Create web subdirectories
mkdir -p "${INSTALL_DIR}/web"/{css,js,assets}

# Create data subdirectories
mkdir -p "${INSTALL_DIR}/data"/{geocode_cache,api_cache,attack_database}

echo -e "${GREEN}✓ Project structure created at ${INSTALL_DIR}${NC}"

###############################################################################
# Step 4: Setup Python Virtual Environment
###############################################################################
echo -e "\n${BLUE}[4/10] Setting up Python virtual environment...${NC}"

cd "${INSTALL_DIR}"

# Create virtual environment
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
else
    echo -e "${YELLOW}Virtual environment already exists${NC}"
fi

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install Python dependencies
echo -e "${YELLOW}Installing Python packages...${NC}"
pip install --break-system-packages \
    feedparser==6.0.11 \
    requests==2.31.0 \
    geopy==2.4.1 \
    python-dateutil==2.8.2 \
    pycountry==23.12.11 \
    beautifulsoup4==4.12.2 \
    lxml==4.9.3 \
    OTXv2==1.5.12 \
    vt-py==0.17.5

echo -e "${GREEN}✓ Python environment configured${NC}"

###############################################################################
# Step 5: Create Configuration Files
###############################################################################
echo -e "\n${BLUE}[5/10] Creating configuration files...${NC}"

# API Keys Configuration Template
cat > "${INSTALL_DIR}/config/api_keys.json" << 'EOF'
{
  "virustotal": {
    "api_key": "YOUR_VIRUSTOTAL_API_KEY",
    "enabled": false,
    "rate_limit_per_minute": 4
  },
  "alienvault_otx": {
    "api_key": "YOUR_OTX_API_KEY",
    "enabled": false,
    "rate_limit_per_minute": 10
  },
  "abuseipdb": {
    "api_key": "YOUR_ABUSEIPDB_API_KEY",
    "enabled": false,
    "rate_limit_per_day": 1000
  },
  "shodan": {
    "api_key": "YOUR_SHODAN_API_KEY",
    "enabled": false,
    "rate_limit_per_month": 100
  },
  "greynoise": {
    "api_key": "YOUR_GREYNOISE_API_KEY",
    "enabled": false,
    "rate_limit_per_minute": 50
  },
  "ipinfo": {
    "api_key": "YOUR_IPINFO_API_KEY",
    "enabled": false,
    "rate_limit_per_month": 50000
  }
}
EOF

# Platform Configuration
cat > "${INSTALL_DIR}/config/platform_config.json" << 'EOF'
{
  "platform": {
    "name": "The Daily Brief",
    "update_interval_minutes": 30,
    "timezone": "UTC"
  },
  "defcon": {
    "auto_calculate": true,
    "manual_override": null,
    "thresholds": {
      "critical": 4.0,
      "severe": 3.0,
      "elevated": 2.0,
      "guarded": 1.0
    }
  },
  "map": {
    "enabled": true,
    "default_zoom": 2,
    "center_lat": 20.0,
    "center_lon": 0.0,
    "clustering_enabled": true,
    "heatmap_enabled": true
  },
  "enrichment": {
    "enabled": true,
    "cache_duration_hours": 24,
    "max_retries": 3,
    "timeout_seconds": 10
  },
  "geocoding": {
    "cache_enabled": true,
    "provider": "nominatim",
    "user_agent": "TheDailyBrief/1.0"
  }
}
EOF

# Country Coordinates Database
cat > "${INSTALL_DIR}/data/geocode_cache/countries.json" << 'EOF'
{
  "United States": {"lat": 37.0902, "lon": -95.7129, "code": "US"},
  "China": {"lat": 35.8617, "lon": 104.1954, "code": "CN"},
  "Russia": {"lat": 61.5240, "lon": 105.3188, "code": "RU"},
  "United Kingdom": {"lat": 55.3781, "lon": -3.4360, "code": "GB"},
  "Germany": {"lat": 51.1657, "lon": 10.4515, "code": "DE"},
  "France": {"lat": 46.2276, "lon": 2.2137, "code": "FR"},
  "India": {"lat": 20.5937, "lon": 78.9629, "code": "IN"},
  "Brazil": {"lat": -14.2350, "lon": -51.9253, "code": "BR"},
  "Japan": {"lat": 36.2048, "lon": 138.2529, "code": "JP"},
  "Australia": {"lat": -25.2744, "lon": 133.7751, "code": "AU"},
  "Canada": {"lat": 56.1304, "lon": -106.3468, "code": "CA"},
  "South Korea": {"lat": 35.9078, "lon": 127.7669, "code": "KR"},
  "Iran": {"lat": 32.4279, "lon": 53.6880, "code": "IR"},
  "North Korea": {"lat": 40.3399, "lon": 127.5101, "code": "KP"},
  "Ukraine": {"lat": 48.3794, "lon": 31.1656, "code": "UA"},
  "Israel": {"lat": 31.0461, "lon": 34.8516, "code": "IL"},
  "Saudi Arabia": {"lat": 23.8859, "lon": 45.0792, "code": "SA"},
  "Turkey": {"lat": 38.9637, "lon": 35.2433, "code": "TR"},
  "Mexico": {"lat": 23.6345, "lon": -102.5528, "code": "MX"},
  "South Africa": {"lat": -30.5595, "lon": 22.9375, "code": "ZA"},
  "Italy": {"lat": 41.8719, "lon": 12.5674, "code": "IT"},
  "Spain": {"lat": 40.4637, "lon": -3.7492, "code": "ES"},
  "Poland": {"lat": 51.9194, "lon": 19.1451, "code": "PL"},
  "Netherlands": {"lat": 52.1326, "lon": 5.2913, "code": "NL"},
  "Sweden": {"lat": 60.1282, "lon": 18.6435, "code": "SE"},
  "Norway": {"lat": 60.4720, "lon": 8.4689, "code": "NO"},
  "Finland": {"lat": 61.9241, "lon": 25.7482, "code": "FI"},
  "Denmark": {"lat": 56.2639, "lon": 9.5018, "code": "DK"},
  "Belgium": {"lat": 50.5039, "lon": 4.4699, "code": "BE"},
  "Switzerland": {"lat": 46.8182, "lon": 8.2275, "code": "CH"},
  "Austria": {"lat": 47.5162, "lon": 14.5501, "code": "AT"},
  "Greece": {"lat": 39.0742, "lon": 21.8243, "code": "GR"},
  "Portugal": {"lat": 39.3999, "lon": -8.2245, "code": "PT"},
  "Czech Republic": {"lat": 49.8175, "lon": 15.4730, "code": "CZ"},
  "Romania": {"lat": 45.9432, "lon": 24.9668, "code": "RO"},
  "Hungary": {"lat": 47.1625, "lon": 19.5033, "code": "HU"},
  "Vietnam": {"lat": 14.0583, "lon": 108.2772, "code": "VN"},
  "Thailand": {"lat": 15.8700, "lon": 100.9925, "code": "TH"},
  "Indonesia": {"lat": -0.7893, "lon": 113.9213, "code": "ID"},
  "Philippines": {"lat": 12.8797, "lon": 121.7740, "code": "PH"},
  "Malaysia": {"lat": 4.2105, "lon": 101.9758, "code": "MY"},
  "Singapore": {"lat": 1.3521, "lon": 103.8198, "code": "SG"},
  "Pakistan": {"lat": 30.3753, "lon": 69.3451, "code": "PK"},
  "Bangladesh": {"lat": 23.6850, "lon": 90.3563, "code": "BD"},
  "Egypt": {"lat": 26.8206, "lon": 30.8025, "code": "EG"},
  "Nigeria": {"lat": 9.0820, "lon": 8.6753, "code": "NG"},
  "Kenya": {"lat": -0.0236, "lon": 37.9062, "code": "KE"},
  "Argentina": {"lat": -38.4161, "lon": -63.6167, "code": "AR"},
  "Chile": {"lat": -35.6751, "lon": -71.5430, "code": "CL"},
  "Colombia": {"lat": 4.5709, "lon": -74.2973, "code": "CO"},
  "Peru": {"lat": -9.1900, "lon": -75.0152, "code": "PE"},
  "Venezuela": {"lat": 6.4238, "lon": -66.5897, "code": "VE"}
}
EOF

echo -e "${GREEN}✓ Configuration files created${NC}"
echo -e "${YELLOW}⚠  Edit ${INSTALL_DIR}/config/api_keys.json with your API keys${NC}"

###############################################################################
# Step 6: Copy Core Application Files
###############################################################################
echo -e "\n${BLUE}[6/10] Setting up application files...${NC}"

# We'll create these files in subsequent steps
echo -e "${YELLOW}Application files will be created in next steps...${NC}"

###############################################################################
# Step 7: Configure Nginx
###############################################################################
echo -e "\n${BLUE}[7/10] Configuring Nginx web server...${NC}"

# Create web root
sudo mkdir -p "${WEB_ROOT}"
sudo chown -R $USER:$USER "${WEB_ROOT}"

# Nginx configuration
sudo tee "${NGINX_AVAILABLE}" > /dev/null << 'NGINXCONF'
server {
    listen 80;
    server_name localhost daily-brief.local;

    root /var/www/daily-brief;
    index index.html;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;

    # Main site
    location / {
        try_files $uri $uri/ =404;
    }

    # API endpoints (for future use)
    location /api/ {
        proxy_pass http://127.0.0.1:5000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 60s;
    }

    # JSON data files
    location /output/ {
        add_header Cache-Control "no-cache, must-revalidate";
        add_header Access-Control-Allow-Origin "*";
    }

    # Static assets caching
    location ~* \.(jpg|jpeg|png|gif|ico|css|js|svg|woff|woff2|ttf)$ {
        expires 7d;
        add_header Cache-Control "public, immutable";
    }

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml;
    gzip_min_length 1000;

    # Logging
    access_log /var/log/nginx/daily-brief-access.log;
    error_log /var/log/nginx/daily-brief-error.log;
}
NGINXCONF

# Enable site
sudo ln -sf "${NGINX_AVAILABLE}" "${NGINX_ENABLED}"

# Test nginx configuration
if sudo nginx -t; then
    echo -e "${GREEN}✓ Nginx configuration valid${NC}"
    sudo systemctl restart nginx
    sudo systemctl enable nginx
else
    echo -e "${RED}✗ Nginx configuration error${NC}"
    exit 1
fi

###############################################################################
# Step 8: Setup Cron Jobs
###############################################################################
echo -e "\n${BLUE}[8/10] Configuring automated updates...${NC}"

# Create update script
cat > "${INSTALL_DIR}/scripts/update.sh" << 'UPDATESCRIPT'
#!/bin/bash
# Automated feed update script

cd "$(dirname "$0")/.."
source venv/bin/activate

# Run feed aggregation with enrichment
python3 scripts/aggregate_feeds.py

# Sync to web root
rsync -av --delete web/ /var/www/daily-brief/
rsync -av output/ /var/www/daily-brief/output/

# Log completion
echo "[$(date)] Feed update completed" >> logs/cron.log
UPDATESCRIPT

chmod +x "${INSTALL_DIR}/scripts/update.sh"

# Add to crontab (run every 30 minutes)
CRON_JOB="*/30 * * * * ${INSTALL_DIR}/scripts/update.sh >> ${INSTALL_DIR}/logs/cron.log 2>&1"

# Check if cron job already exists
if ! crontab -l 2>/dev/null | grep -q "update.sh"; then
    (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
    echo -e "${GREEN}✓ Cron job added (runs every 30 minutes)${NC}"
else
    echo -e "${YELLOW}Cron job already exists${NC}"
fi

###############################################################################
# Step 9: Create Systemd Service (Optional)
###############################################################################
echo -e "\n${BLUE}[9/10] Creating systemd service...${NC}"

sudo tee /etc/systemd/system/daily-brief.service > /dev/null << SERVICEEOF
[Unit]
Description=The Daily Brief - Threat Intelligence Platform
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/scripts/update.sh
Restart=on-failure
RestartSec=300

[Install]
WantedBy=multi-user.target
SERVICEEOF

sudo systemctl daemon-reload
echo -e "${GREEN}✓ Systemd service created${NC}"
echo -e "${YELLOW}  To enable on boot: sudo systemctl enable daily-brief${NC}"

###############################################################################
# Step 10: Final Setup & Verification
###############################################################################
echo -e "\n${BLUE}[10/10] Final setup and verification...${NC}"

# Create initial run marker
touch "${INSTALL_DIR}/.installed"

# Set permissions
chmod +x "${INSTALL_DIR}/scripts"/*.sh 2>/dev/null || true

echo -e "\n${GREEN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║        ✅ INSTALLATION COMPLETE!                          ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

###############################################################################
# Installation Summary
###############################################################################
echo -e "\n${BURNT_SIENNA}📋 Installation Summary:${NC}"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}✓ Project Directory:${NC}     ${INSTALL_DIR}"
echo -e "${GREEN}✓ Web Root:${NC}              ${WEB_ROOT}"
echo -e "${GREEN}✓ Virtual Environment:${NC}   ${INSTALL_DIR}/venv"
echo -e "${GREEN}✓ Nginx Configuration:${NC}   ${NGINX_AVAILABLE}"
echo -e "${GREEN}✓ Update Frequency:${NC}      Every 30 minutes (cron)"
echo -e "${GREEN}✓ Systemd Service:${NC}       daily-brief.service"

echo -e "\n${BURNT_SIENNA}📝 Next Steps:${NC}"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "1. ${YELLOW}Configure API keys:${NC}"
echo -e "   nano ${INSTALL_DIR}/config/api_keys.json"
echo -e ""
echo -e "2. ${YELLOW}Run first feed update:${NC}"
echo -e "   cd ${INSTALL_DIR} && source venv/bin/activate"
echo -e "   python3 scripts/aggregate_feeds.py"
echo -e ""
echo -e "3. ${YELLOW}Access the dashboard:${NC}"
echo -e "   http://localhost/"
echo -e "   http://$(hostname -I | awk '{print $1}')/"
echo -e ""
echo -e "4. ${YELLOW}View logs:${NC}"
echo -e "   tail -f ${INSTALL_DIR}/logs/cron.log"
echo -e ""
echo -e "5. ${YELLOW}Manual update:${NC}"
echo -e "   ${INSTALL_DIR}/scripts/update.sh"

echo -e "\n${BURNT_SIENNA}🔧 Optional Configuration:${NC}"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "• Platform settings: ${INSTALL_DIR}/config/platform_config.json"
echo -e "• Feed configuration: ${INSTALL_DIR}/config/feeds.json"
echo -e "• Country coordinates: ${INSTALL_DIR}/data/geocode_cache/countries.json"

echo -e "\n${GREEN}Installation complete! The Daily Brief is ready to use.${NC}\n"

# Save installation info
cat > "${INSTALL_DIR}/.install_info" << INFOEOF
Installation Date: $(date)
Install Directory: ${INSTALL_DIR}
Web Root: ${WEB_ROOT}
User: $USER
Hostname: $(hostname)
INFOEOF

exit 0
