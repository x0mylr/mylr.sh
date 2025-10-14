#!/bin/bash
###############################################################################
# The Daily Brief - Master Quick Deploy Script
# One command to deploy the complete threat intelligence platform
#
# This script deploys from a FLAT project directory where all files live
# alongside this script. It creates the server structure under INSTALL_DIR.
###############################################################################

set -e

BURNT_SIENNA='\033[38;5;166m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${HOME}/daily-brief"
WEB_ROOT="/var/www/daily-brief"

echo -e "${BURNT_SIENNA}"
cat << 'EOF'
+--------------------------------------------------------------+
|                                                                |
|     THE DAILY BRIEF - MASTER DEPLOYMENT SCRIPT                 |
|        Complete Threat Intelligence Platform                   |
|                                                                |
|  This script will:                                             |
|  * Install system dependencies (nginx, python, etc.)           |
|  * Create project structure                                    |
|  * Deploy all application files                                |
|  * Setup DEFCON automation                                     |
|  * Deploy interactive threat map                               |
|  * Configure API enrichment                                    |
|  * Setup cron jobs for auto-updates                            |
|  * Start web server                                            |
|                                                                |
+--------------------------------------------------------------+
EOF
echo -e "${NC}\n"

echo -e "Source directory: ${BURNT_SIENNA}${SCRIPT_DIR}${NC}"
echo -e "Install directory: ${BURNT_SIENNA}${INSTALL_DIR}${NC}"
echo -e "Web root: ${BURNT_SIENNA}${WEB_ROOT}${NC}"
echo ""

read -p "Ready to deploy The Daily Brief? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deployment cancelled."
    exit 0
fi

###############################################################################
# Phase 1: Run Base Installation (if script exists)
###############################################################################
echo -e "\n${BLUE}[PHASE 1/5] Running base installation...${NC}"

if [ -f "${SCRIPT_DIR}/install-daily-brief.sh" ]; then
    bash "${SCRIPT_DIR}/install-daily-brief.sh"
else
    echo -e "${YELLOW}  install-daily-brief.sh not found. Attempting manual setup...${NC}"

    # Create directory structure
    mkdir -p "${INSTALL_DIR}"/{scripts,web/js,web/css,web/output,config,output,data/api_cache,data/geocode_cache,logs}

    # Install Python venv if needed
    if [ ! -d "${INSTALL_DIR}/venv" ]; then
        echo "  Creating Python virtual environment..."
        python3 -m venv "${INSTALL_DIR}/venv"
    fi

    # Install Python dependencies
    echo "  Installing Python dependencies..."
    source "${INSTALL_DIR}/venv/bin/activate"
    pip install --quiet feedparser requests geopy beautifulsoup4 2>/dev/null || true
    pip install --quiet OTXv2 vt-py 2>/dev/null || true
    deactivate
fi

echo -e "${GREEN}  Phase 1 complete${NC}"

###############################################################################
# Phase 2: Deploy Application Files
###############################################################################
echo -e "\n${BLUE}[PHASE 2/5] Deploying application files...${NC}"

# Ensure directories exist
mkdir -p "${INSTALL_DIR}"/{scripts,web/js,web/css,web/output,config,output}

# Copy Python aggregator
echo "  Installing enhanced feed aggregator..."
cp "${SCRIPT_DIR}/aggregate_feeds_enhanced.py" "${INSTALL_DIR}/scripts/aggregate_feeds.py"
chmod +x "${INSTALL_DIR}/scripts/aggregate_feeds.py"

# Copy dashboard HTML
echo "  Installing dashboard..."
cp "${SCRIPT_DIR}/the-daily-brief.html" "${INSTALL_DIR}/web/index.html"

# Copy map HTML
echo "  Installing threat map..."
cp "${SCRIPT_DIR}/map.html" "${INSTALL_DIR}/web/map.html"

# Copy JavaScript files
echo "  Installing JavaScript..."
cp "${SCRIPT_DIR}/feed-dashboard.js" "${INSTALL_DIR}/web/feed-dashboard.js"
cp "${SCRIPT_DIR}/threat-map.js" "${INSTALL_DIR}/web/threat-map.js"

# Copy CSS files
echo "  Installing stylesheets..."
cp "${SCRIPT_DIR}/threat-map.css" "${INSTALL_DIR}/web/threat-map.css"
cp "${SCRIPT_DIR}/dashboard-enhancements.css" "${INSTALL_DIR}/web/dashboard-enhancements.css"

# Copy configuration files
echo "  Installing configuration..."
cp "${SCRIPT_DIR}/feeds.json" "${INSTALL_DIR}/feeds.json"
cp "${SCRIPT_DIR}/platform_config.json" "${INSTALL_DIR}/platform_config.json"
cp "${SCRIPT_DIR}/countries.json" "${INSTALL_DIR}/countries.json"

# Copy API keys template (don't overwrite if exists)
if [ ! -f "${INSTALL_DIR}/api_keys.json" ]; then
    cp "${SCRIPT_DIR}/api_keys.json" "${INSTALL_DIR}/api_keys.json"
    echo "  Installed api_keys.json template"
else
    echo "  api_keys.json already exists, preserving existing keys"
fi

echo -e "${GREEN}  Phase 2 complete${NC}"

###############################################################################
# Phase 3: Verify Configuration
###############################################################################
echo -e "\n${BLUE}[PHASE 3/5] Verifying configuration...${NC}"

REQUIRED_FILES=(
    "feeds.json"
    "platform_config.json"
    "countries.json"
    "api_keys.json"
    "scripts/aggregate_feeds.py"
    "web/index.html"
    "web/map.html"
    "web/feed-dashboard.js"
    "web/threat-map.js"
    "web/threat-map.css"
    "web/dashboard-enhancements.css"
)

ALL_OK=true
for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "${INSTALL_DIR}/${file}" ]; then
        echo "    ${file}"
    else
        echo -e "${RED}    MISSING: ${file}${NC}"
        ALL_OK=false
    fi
done

if [ "$ALL_OK" = true ]; then
    echo -e "${GREEN}  All files verified${NC}"
else
    echo -e "${RED}  Some files are missing! Check source directory.${NC}"
fi

###############################################################################
# Phase 4: Test Installation
###############################################################################
echo -e "\n${BLUE}[PHASE 4/5] Testing installation...${NC}"

cd "${INSTALL_DIR}"
source venv/bin/activate

echo "  Testing Python imports..."
python3 << 'PYTEST'
try:
    import feedparser
    import requests
    print("    Core dependencies OK")

    try:
        from geopy.geocoders import Nominatim
        print("    Geopy available")
    except ImportError:
        print("    Geopy not available (optional)")

    try:
        from OTXv2 import OTXv2
        print("    AlienVault OTX available")
    except ImportError:
        print("    OTX not available (optional)")

    try:
        import vt
        print("    VirusTotal API available")
    except ImportError:
        print("    VirusTotal not available (optional)")

except Exception as e:
    print(f"    Error: {e}")
    exit(1)
PYTEST

# Test nginx if installed
if command -v nginx &> /dev/null; then
    echo "  Testing Nginx..."
    if sudo nginx -t 2>&1 | grep -q "successful"; then
        echo -e "${GREEN}    Nginx configuration valid${NC}"
    else
        echo -e "${YELLOW}    Nginx configuration needs attention${NC}"
    fi
fi

echo -e "${GREEN}  Phase 4 complete${NC}"

###############################################################################
# Phase 5: Initial Data Population
###############################################################################
echo -e "\n${BLUE}[PHASE 5/5] Running initial feed aggregation...${NC}"

cd "${INSTALL_DIR}"
source venv/bin/activate

echo "  Aggregating threat intelligence feeds..."
python3 scripts/aggregate_feeds.py --project-dir "${INSTALL_DIR}"

if [ -f "${INSTALL_DIR}/output/feed_data.json" ]; then
    echo -e "${GREEN}  Feed data generated successfully${NC}"

    # Sync to web directory
    cp "${INSTALL_DIR}/output/feed_data.json" "${INSTALL_DIR}/web/output/feed_data.json"

    # If nginx web root exists, sync there too
    if [ -d "${WEB_ROOT}" ]; then
        echo "  Syncing to web server root..."
        sudo rsync -av "${INSTALL_DIR}/web/" "${WEB_ROOT}/"
        sudo mkdir -p "${WEB_ROOT}/output"
        sudo cp "${INSTALL_DIR}/output/feed_data.json" "${WEB_ROOT}/output/feed_data.json"
        sudo chown -R www-data:www-data "${WEB_ROOT}/" 2>/dev/null || true
        echo -e "${GREEN}  Files synced to ${WEB_ROOT}${NC}"
    fi
else
    echo -e "${YELLOW}  Feed aggregation completed but no output file. Check logs.${NC}"
fi

deactivate

###############################################################################
# Create update script
###############################################################################
echo "  Creating update script..."
cat > "${INSTALL_DIR}/scripts/update.sh" << UPDATEEOF
#!/bin/bash
# The Daily Brief - Update Script
cd "${INSTALL_DIR}"
source venv/bin/activate
python3 scripts/aggregate_feeds.py --project-dir "${INSTALL_DIR}"

# Sync output to web directories
cp "${INSTALL_DIR}/output/feed_data.json" "${INSTALL_DIR}/web/output/feed_data.json"
if [ -d "${WEB_ROOT}" ]; then
    sudo cp "${INSTALL_DIR}/output/feed_data.json" "${WEB_ROOT}/output/feed_data.json" 2>/dev/null
fi
deactivate
UPDATEEOF
chmod +x "${INSTALL_DIR}/scripts/update.sh"

# Setup cron job (every 30 minutes)
CRON_ENTRY="*/30 * * * * ${INSTALL_DIR}/scripts/update.sh >> ${INSTALL_DIR}/logs/cron.log 2>&1"
(crontab -l 2>/dev/null | grep -v "daily-brief"; echo "$CRON_ENTRY") | crontab - 2>/dev/null || true
echo "  Cron job configured (every 30 minutes)"

###############################################################################
# Deployment Complete
###############################################################################
echo -e "\n${GREEN}"
cat << 'EOF'
+--------------------------------------------------------------+
|                                                                |
|              DEPLOYMENT SUCCESSFUL!                            |
|                                                                |
+--------------------------------------------------------------+
EOF
echo -e "${NC}\n"

echo -e "${BURNT_SIENNA}Platform Summary:${NC}"
echo -e "--------------------------------------------------------------"
echo -e "${GREEN}  Web Server:${NC}         Nginx (if configured)"
echo -e "${GREEN}  Dashboard:${NC}          http://localhost/"
echo -e "${GREEN}  Threat Map:${NC}         http://localhost/map.html"
echo -e "${GREEN}  Auto-Updates:${NC}       Every 30 minutes (cron)"
echo -e "${GREEN}  DEFCON System:${NC}      Automated calculation"
echo -e "${GREEN}  Geocoding:${NC}          60+ countries in database"
echo -e "${GREEN}  API Enrichment:${NC}     VirusTotal, OTX ready"

# Get DEFCON level from output
if [ -f "${INSTALL_DIR}/output/feed_data.json" ]; then
    DEFCON_LEVEL=$(python3 -c "import json; data=json.load(open('${INSTALL_DIR}/output/feed_data.json')); print(f'DEFCON {data[\"metadata\"][\"defcon_level\"]} - {data[\"metadata\"][\"defcon_details\"][\"name\"]}')" 2>/dev/null || echo "N/A")
    TOTAL_ARTICLES=$(python3 -c "import json; data=json.load(open('${INSTALL_DIR}/output/feed_data.json')); print(data['metadata']['total_articles'])" 2>/dev/null || echo "0")
    GEOLOCATED=$(python3 -c "import json; data=json.load(open('${INSTALL_DIR}/output/feed_data.json')); print(data['metadata']['geo_stats']['total_geolocated'])" 2>/dev/null || echo "0")

    echo ""
    echo -e "${BURNT_SIENNA}Current Status:${NC}"
    echo -e "--------------------------------------------------------------"
    echo -e "${GREEN}  Threat Level:${NC}       ${DEFCON_LEVEL}"
    echo -e "${GREEN}  Total Articles:${NC}     ${TOTAL_ARTICLES}"
    echo -e "${GREEN}  Geolocated:${NC}         ${GEOLOCATED} articles"
fi

echo ""
echo -e "${BURNT_SIENNA}Next Steps:${NC}"
echo -e "--------------------------------------------------------------"
echo -e "1. ${YELLOW}Configure API Keys:${NC}"
echo -e "   nano ${INSTALL_DIR}/api_keys.json"
echo -e ""
echo -e "2. ${YELLOW}Access Dashboard:${NC}"
echo -e "   http://localhost/"
echo -e "   http://localhost/map.html"
echo -e ""
echo -e "3. ${YELLOW}Manual Update:${NC}"
echo -e "   ${INSTALL_DIR}/scripts/update.sh"
echo -e ""
echo -e "4. ${YELLOW}View Logs:${NC}"
echo -e "   tail -f ${INSTALL_DIR}/logs/cron.log"

echo -e "\n${GREEN}The Daily Brief is now live!${NC}\n"

# Open browser (if in WSL with Windows browser available)
if command -v explorer.exe &> /dev/null; then
    echo "Opening dashboard in browser..."
    explorer.exe "http://localhost/" 2>/dev/null &
fi

exit 0
