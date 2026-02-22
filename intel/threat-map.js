/**
 * The Daily Brief - Interactive Threat Map
 * Secure implementation: No innerHTML for user/external data.
 * Features: Leaflet.js, marker clustering, heatmap, category filtering.
 */

'use strict';

class ThreatMap {
    constructor(containerId) {
        this.containerId = containerId;
        this.map = null;
        this.markers = null;
        this.heatmapLayer = null;
        this.feedData = null;
        this.activeView = 'markers';

        this.categoryColors = {
            'APT': '#9a4c30',
            'VULNERABILITY': '#ff4444',
            'MALWARE': '#ff9944',
            'BREACH': '#4fc3f7',
            'RESEARCH': '#5cb85c',
            'SUPPLY_CHAIN': '#8e44ad',
            'ADVISORY': '#34495e',
            'PHISHING': '#e67e22',
            'NETWORK': '#16a085',
            'GEOPOLITICAL': '#c0392b',
            'TTPS': '#2c3e50'
        };
    }

    async init(feedDataUrl) {
        const paths = feedDataUrl ? [feedDataUrl] : [];
        paths.push('output/feed_data.json', 'feed_data.json', '../output/feed_data.json');

        let loaded = false;
        for (const path of paths) {
            try {
                const response = await fetch(path);
                if (!response.ok) continue;

                const contentType = response.headers.get('content-type') || '';
                if (!contentType.includes('application/json') && !contentType.includes('text/')) {
                    continue;
                }

                const data = await response.json();
                if (!data || !Array.isArray(data.articles) || !data.metadata) continue;

                this.feedData = data;
                loaded = true;
                break;
            } catch {
                continue;
            }
        }

        if (!loaded) {
            this.loadSampleData();
        }

        // Hide loading overlay
        const loadingEl = document.getElementById('map-loading');
        if (loadingEl) loadingEl.style.display = 'none';

        this.initializeMap();
        this.addMapControls();
        this.displayMarkers();
        this.addLegend();
        this.handleUrlParams();

        // Wire up refresh button
        const refreshBtn = document.getElementById('btn-refresh');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                window.location.reload();
            });
        }
    }

    loadSampleData() {
        const now = new Date();
        this.feedData = {
            metadata: {
                generated_at: now.toISOString(),
                total_articles: 4,
                feeds_processed: 4,
                defcon_level: 3,
                defcon_details: { name: 'ELEVATED', color: '#ff9944', score: 2.5 },
                geo_stats: {
                    total_geolocated: 3,
                    countries: {
                        'Iran': { count: 1, latitude: 32.4279, longitude: 53.6880 },
                        'United States': { count: 1, latitude: 37.0902, longitude: -95.7129 },
                        'China': { count: 1, latitude: 35.8617, longitude: 104.1954 }
                    },
                    heatmap_data: [
                        { lat: 32.4279, lon: 53.6880, intensity: 1 },
                        { lat: 37.0902, lon: -95.7129, intensity: 1 },
                        { lat: 35.8617, lon: 104.1954, intensity: 1 }
                    ]
                }
            },
            articles: [
                {
                    id: 'sample-001',
                    title: 'Iranian Infy APT Resurfaces',
                    link: '#',
                    summary: 'Iranian APT group resurfaces with new malware.',
                    published: new Date(now - 2 * 3600000).toISOString(),
                    source: 'The Hacker News',
                    category: 'APT',
                    icon: '🎯',
                    priority: 1,
                    geo: { country: 'Iran', latitude: 32.4279, longitude: 53.6880 }
                },
                {
                    id: 'sample-002',
                    title: 'Critical Zero-Day in Ivanti',
                    link: '#',
                    summary: 'Critical vulnerability actively exploited.',
                    published: new Date(now - 4 * 3600000).toISOString(),
                    source: 'BleepingComputer',
                    category: 'VULNERABILITY',
                    icon: '🔓',
                    priority: 1,
                    geo: { country: 'United States', latitude: 37.0902, longitude: -95.7129 }
                },
                {
                    id: 'sample-004',
                    title: 'Volt Typhoon Expands Operations',
                    link: '#',
                    summary: 'Chinese APT targets European critical infrastructure.',
                    published: new Date(now - 12 * 3600000).toISOString(),
                    source: 'CyberScoop',
                    category: 'APT',
                    icon: '🎯',
                    priority: 1,
                    geo: { country: 'China', latitude: 35.8617, longitude: 104.1954 }
                }
            ]
        };
    }

    initializeMap() {
        this.map = L.map(this.containerId, {
            center: [20, 0],
            zoom: 2,
            minZoom: 2,
            maxZoom: 10,
            worldCopyJump: true
        });

        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>, &copy; <a href="https://carto.com/">CARTO</a>',
            subdomains: 'abcd',
            maxZoom: 19
        }).addTo(this.map);
    }

    displayMarkers() {
        if (this.markers) this.map.removeLayer(this.markers);
        if (this.heatmapLayer) this.map.removeLayer(this.heatmapLayer);

        this.markers = L.markerClusterGroup({
            chunkedLoading: true,
            spiderfyOnMaxZoom: true,
            showCoverageOnHover: false,
            zoomToBoundsOnClick: true,
            maxClusterRadius: 50,
            iconCreateFunction: (cluster) => {
                const count = cluster.getChildCount();
                let size = 'small';
                if (count > 10) size = 'large';
                else if (count > 5) size = 'medium';

                const div = document.createElement('div');
                const span = document.createElement('span');
                span.textContent = count;
                div.appendChild(span);

                return L.divIcon({
                    html: div.outerHTML,
                    className: `marker-cluster marker-cluster-${size}`,
                    iconSize: L.point(40, 40)
                });
            }
        });

        let markersAdded = 0;
        this.feedData.articles.forEach(article => {
            if (!article.geo) return;
            if (!article.geo.latitude || !article.geo.longitude) return;

            const marker = this.createMarker(article);
            if (marker) {
                this.markers.addLayer(marker);
                markersAdded++;
            }
        });

        this.map.addLayer(this.markers);
        this.activeView = 'markers';

        if (markersAdded > 0) {
            try {
                this.map.fitBounds(this.markers.getBounds(), { padding: [50, 50] });
            } catch {
                this.map.setView([20, 0], 2);
            }
        }
    }

    createMarker(article) {
        const lat = parseFloat(article.geo.latitude);
        const lon = parseFloat(article.geo.longitude);
        if (isNaN(lat) || isNaN(lon)) return null;

        const icon = this.createCustomIcon(article);
        const marker = L.marker([lat, lon], { icon });

        // Build popup using safe DOM construction
        const popup = this.createPopupElement(article);
        marker.bindPopup(popup, {
            maxWidth: 450,
            minWidth: 300,
            className: 'threat-popup'
        });

        const safeTitle = (article.title || 'Untitled').substring(0, 80);
        marker.bindTooltip(safeTitle, {
            direction: 'top',
            offset: [0, -20]
        });

        return marker;
    }

    createCustomIcon(article) {
        const color = this.categoryColors[article.category] || '#999';
        const size = article.priority === 1 ? 30 : article.priority === 2 ? 24 : 18;
        const pulseClass = article.priority === 1 ? 'pulse-marker' : '';

        // Build icon HTML via DOM for safety
        const wrapper = document.createElement('div');
        wrapper.className = `custom-marker ${pulseClass}`;
        wrapper.style.backgroundColor = color;
        wrapper.style.width = `${size}px`;
        wrapper.style.height = `${size}px`;

        const iconSpan = document.createElement('span');
        iconSpan.className = 'marker-icon';
        iconSpan.textContent = article.icon || '📰';
        wrapper.appendChild(iconSpan);

        return L.divIcon({
            html: wrapper.outerHTML,
            className: 'custom-marker-container',
            iconSize: [size, size],
            iconAnchor: [size / 2, size / 2],
            popupAnchor: [0, -size / 2]
        });
    }

    /**
     * Build popup content using DOM APIs instead of string concatenation.
     * Returns an HTMLElement that Leaflet can use directly.
     */
    createPopupElement(article) {
        const geo = article.geo || {};
        const location = geo.country || geo.location || 'Unknown';
        const summary = (article.summary || 'No summary available').substring(0, 200);
        const categoryColor = this.categoryColors[article.category] || '#999';
        const safeLink = this.sanitizeUrl(article.link);

        const container = document.createElement('div');
        container.className = 'threat-popup-content';

        // Header
        const header = document.createElement('div');
        header.className = 'popup-header';
        header.style.borderLeft = `4px solid ${categoryColor}`;

        const title = document.createElement('div');
        title.className = 'popup-title';
        title.textContent = article.title || 'Untitled';
        header.appendChild(title);

        const meta = document.createElement('div');
        meta.className = 'popup-meta';

        const catSpan = document.createElement('span');
        catSpan.className = 'popup-category';
        catSpan.textContent = article.category || 'Unknown';
        meta.appendChild(catSpan);

        const priSpan = document.createElement('span');
        priSpan.className = `popup-priority priority-${article.priority || 3}`;
        priSpan.textContent = `P${article.priority || 3}`;
        meta.appendChild(priSpan);

        header.appendChild(meta);
        container.appendChild(header);

        // Body
        const body = document.createElement('div');
        body.className = 'popup-body';

        // Location
        const locSection = this.createPopupSection('Location:', location);
        body.appendChild(locSection);

        // Source
        const srcSection = this.createPopupSection('Source:', article.source || 'Unknown');
        body.appendChild(srcSection);

        // Published
        const pubSection = this.createPopupSection('Published:', this.formatDate(article.published));
        body.appendChild(pubSection);

        // Threat intel (if available)
        if (article.threat_intel && Object.keys(article.threat_intel).length > 0) {
            const intelSection = document.createElement('div');
            intelSection.className = 'popup-section';

            const intelLabel = document.createElement('strong');
            intelLabel.textContent = 'Threat Intelligence:';
            intelSection.appendChild(intelLabel);

            Object.entries(article.threat_intel).forEach(([ioc, intel]) => {
                const iocItem = document.createElement('div');
                iocItem.className = 'ioc-item';

                const iocValue = document.createElement('span');
                iocValue.className = 'ioc-value';
                iocValue.textContent = ioc;
                iocItem.appendChild(iocValue);

                if (intel.sources) {
                    const sources = document.createElement('span');
                    sources.className = 'ioc-sources';
                    sources.textContent = intel.sources.join(', ');
                    iocItem.appendChild(sources);
                }

                if (intel.malicious || (intel.vt_malicious && intel.vt_malicious > 0)) {
                    const malicious = document.createElement('span');
                    malicious.className = 'ioc-malicious';
                    malicious.textContent = 'Malicious';
                    iocItem.appendChild(malicious);
                }

                intelSection.appendChild(iocItem);
            });

            body.appendChild(intelSection);
        }

        // Summary
        const summarySection = document.createElement('div');
        summarySection.className = 'popup-section';
        const summaryDiv = document.createElement('div');
        summaryDiv.className = 'popup-summary';
        summaryDiv.textContent = summary + '...';
        summarySection.appendChild(summaryDiv);
        body.appendChild(summarySection);

        container.appendChild(body);

        // Footer
        const footer = document.createElement('div');
        footer.className = 'popup-footer';

        const viewIntelBtn = document.createElement('button');
        viewIntelBtn.type = 'button';
        viewIntelBtn.className = 'popup-link';
        viewIntelBtn.textContent = 'View Intel Report →';
        viewIntelBtn.addEventListener('click', () => this.showArticleDetail(article));
        footer.appendChild(viewIntelBtn);

        if (safeLink !== '#') {
            const extLink = document.createElement('a');
            extLink.className = 'popup-link popup-link-secondary';
            extLink.href = safeLink;
            extLink.target = '_blank';
            extLink.rel = 'noopener noreferrer';
            extLink.textContent = 'Original Source ↗';
            footer.appendChild(extLink);
        }

        container.appendChild(footer);

        return container;
    }

    createPopupSection(label, value) {
        const section = document.createElement('div');
        section.className = 'popup-section';
        const strong = document.createElement('strong');
        strong.textContent = label + ' ';
        section.appendChild(strong);
        section.appendChild(document.createTextNode(value));
        return section;
    }

    displayHeatmap() {
        if (this.markers) this.map.removeLayer(this.markers);
        if (this.heatmapLayer) this.map.removeLayer(this.heatmapLayer);

        const geo = this.feedData.metadata.geo_stats;
        if (!geo || !geo.heatmap_data || geo.heatmap_data.length === 0) {
            return;
        }

        const heatData = geo.heatmap_data.map(point => [
            point.lat,
            point.lon,
            point.intensity || 1
        ]);

        if (typeof L.heatLayer === 'function') {
            this.heatmapLayer = L.heatLayer(heatData, {
                radius: 30,
                blur: 20,
                maxZoom: 10,
                max: 2,
                gradient: {
                    0.0: '#1a472a',
                    0.2: '#2ecc40',
                    0.4: '#ffdc00',
                    0.6: '#ff851b',
                    0.8: '#ff4136',
                    1.0: '#ff0000'
                }
            }).addTo(this.map);
            this.activeView = 'heatmap';
        }
    }

    addMapControls() {
        const self = this;

        const ViewControl = L.Control.extend({
            options: { position: 'topright' },
            onAdd() {
                const container = L.DomUtil.create('div', 'view-control leaflet-bar');

                const markersBtn = document.createElement('button');
                markersBtn.type = 'button';
                markersBtn.id = 'markers-view';
                markersBtn.className = 'view-btn active';
                markersBtn.title = 'Markers View';
                markersBtn.textContent = 'Markers';

                const heatmapBtn = document.createElement('button');
                heatmapBtn.type = 'button';
                heatmapBtn.id = 'heatmap-view';
                heatmapBtn.className = 'view-btn';
                heatmapBtn.title = 'Heatmap View';
                heatmapBtn.textContent = 'Heatmap';

                const resetBtn = document.createElement('button');
                resetBtn.type = 'button';
                resetBtn.id = 'reset-view';
                resetBtn.className = 'view-btn';
                resetBtn.title = 'Reset View';
                resetBtn.textContent = 'Reset';

                container.appendChild(markersBtn);
                container.appendChild(heatmapBtn);
                container.appendChild(resetBtn);

                markersBtn.addEventListener('click', () => {
                    self.displayMarkers();
                    self.setActiveButton('markers-view');
                });

                heatmapBtn.addEventListener('click', () => {
                    self.displayHeatmap();
                    self.setActiveButton('heatmap-view');
                });

                resetBtn.addEventListener('click', () => {
                    self.map.setView([20, 0], 2);
                });

                L.DomEvent.disableClickPropagation(container);
                return container;
            }
        });

        new ViewControl().addTo(this.map);
        this.addCategoryFilter();
    }

    addCategoryFilter() {
        const self = this;
        const categories = [...new Set(this.feedData.articles.filter(a => a.geo).map(a => a.category))];
        if (categories.length === 0) return;

        const FilterControl = L.Control.extend({
            options: { position: 'topleft' },
            onAdd() {
                const container = L.DomUtil.create('div', 'filter-control leaflet-bar');

                const header = document.createElement('div');
                header.className = 'filter-header';
                header.textContent = 'Filter by Category';
                container.appendChild(header);

                categories.forEach(category => {
                    const color = self.categoryColors[category] || '#999';

                    const label = document.createElement('label');
                    label.className = 'filter-item';

                    const checkbox = document.createElement('input');
                    checkbox.type = 'checkbox';
                    checkbox.className = 'category-filter';
                    checkbox.value = category;
                    checkbox.checked = true;

                    const icon = document.createElement('span');
                    icon.className = 'filter-icon';
                    icon.style.backgroundColor = color;

                    const text = document.createElement('span');
                    text.className = 'filter-label';
                    text.textContent = category;

                    label.appendChild(checkbox);
                    label.appendChild(icon);
                    label.appendChild(text);
                    container.appendChild(label);

                    checkbox.addEventListener('change', () => self.applyFilters());
                });

                L.DomEvent.disableClickPropagation(container);
                return container;
            }
        });

        new FilterControl().addTo(this.map);
    }

    applyFilters() {
        const selectedCategories = Array.from(document.querySelectorAll('.category-filter:checked'))
            .map(cb => cb.value);

        if (!this.markers) return;

        this.markers.clearLayers();

        this.feedData.articles.forEach(article => {
            if (!article.geo) return;
            if (!article.geo.latitude || !article.geo.longitude) return;
            if (!selectedCategories.includes(article.category)) return;

            const marker = this.createMarker(article);
            if (marker) this.markers.addLayer(marker);
        });
    }

    addLegend() {
        const self = this;

        const LegendControl = L.Control.extend({
            options: { position: 'bottomright' },
            onAdd() {
                const container = L.DomUtil.create('div', 'map-legend leaflet-bar');

                const totalArticles = self.feedData.metadata.total_articles || 0;
                const geolocated = self.feedData.metadata.geo_stats
                    ? self.feedData.metadata.geo_stats.total_geolocated : 0;
                const defconLevel = self.feedData.metadata.defcon_level || '--';
                const defconDetails = self.feedData.metadata.defcon_details || {};

                // Build legend with DOM
                const headerEl = document.createElement('div');
                headerEl.className = 'legend-header';
                headerEl.textContent = 'Threat Priority';
                container.appendChild(headerEl);

                [
                    { cls: 'priority-1', label: 'Critical (P1)' },
                    { cls: 'priority-2', label: 'High (P2)' },
                    { cls: 'priority-3', label: 'Medium (P3)' }
                ].forEach(item => {
                    const row = document.createElement('div');
                    row.className = 'legend-item';

                    const marker = document.createElement('span');
                    marker.className = `legend-marker ${item.cls}`;
                    row.appendChild(marker);

                    const text = document.createElement('span');
                    text.textContent = item.label;
                    row.appendChild(text);

                    container.appendChild(row);
                });

                const stats = document.createElement('div');
                stats.className = 'legend-stats';

                const totalLine = document.createElement('div');
                totalLine.textContent = `Total Threats: ${totalArticles}`;
                stats.appendChild(totalLine);

                const geoLine = document.createElement('div');
                geoLine.textContent = `Geolocated: ${geolocated}`;
                stats.appendChild(geoLine);

                const defconLine = document.createElement('div');
                defconLine.textContent = `DEFCON: ${defconLevel} - ${defconDetails.name || 'N/A'}`;
                defconLine.style.color = defconDetails.color || '#ff9944';
                stats.appendChild(defconLine);

                container.appendChild(stats);

                L.DomEvent.disableClickPropagation(container);
                return container;
            }
        });

        new LegendControl().addTo(this.map);
    }

    handleUrlParams() {
        const params = new URLSearchParams(window.location.search);
        const country = params.get('country');

        if (country && this.feedData.metadata.geo_stats && this.feedData.metadata.geo_stats.countries) {
            // Sanitize the country param
            const sanitized = country.replace(/[^a-zA-Z\s\-'().]/g, '');
            const countryData = this.feedData.metadata.geo_stats.countries[sanitized];
            if (countryData && countryData.latitude && countryData.longitude) {
                this.map.setView([countryData.latitude, countryData.longitude], 5);
            }

            // Show country context banner
            this.showCountryBanner(sanitized);
        }
    }

    showCountryBanner(countryName) {
        const mapContainer = document.getElementById('map-container');
        if (!mapContainer) return;

        const banner = document.createElement('div');
        banner.className = 'country-context-banner';
        banner.setAttribute('role', 'status');

        const label = document.createElement('span');
        label.className = 'banner-label';
        label.textContent = `Viewing threats: ${countryName}`;
        banner.appendChild(label);

        const btnGroup = document.createElement('div');
        btnGroup.className = 'banner-actions';

        const resetBtn = document.createElement('button');
        resetBtn.type = 'button';
        resetBtn.className = 'banner-btn';
        resetBtn.textContent = 'Show All Regions';
        resetBtn.addEventListener('click', () => {
            this.map.setView([20, 0], 2);
            banner.remove();
        });
        btnGroup.appendChild(resetBtn);

        const dashBtn = document.createElement('a');
        dashBtn.href = '/';
        dashBtn.className = 'banner-btn banner-btn-primary';
        dashBtn.textContent = 'Return to Dashboard';
        btnGroup.appendChild(dashBtn);

        banner.appendChild(btnGroup);
        mapContainer.insertBefore(banner, mapContainer.firstChild);
    }

    setActiveButton(buttonId) {
        document.querySelectorAll('.view-control .view-btn').forEach(btn => btn.classList.remove('active'));
        const btn = document.getElementById(buttonId);
        if (btn) btn.classList.add('active');
    }

    // ============================================
    // Intelligence Report Modal
    // ============================================

    showArticleDetail(article) {
        this.closeArticleDetail();

        const safeLink = this.sanitizeUrl(article.link);

        // Overlay (backdrop)
        const overlay = document.createElement('div');
        overlay.className = 'detail-overlay';
        overlay.id = 'article-detail-overlay';
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) this.closeArticleDetail();
        });

        const panel = document.createElement('div');
        panel.className = 'detail-panel';

        // Header bar
        const headerBar = document.createElement('div');
        headerBar.className = 'detail-header-bar';

        const headerLabel = document.createElement('span');
        headerLabel.className = 'detail-header-label';
        headerLabel.textContent = 'INTELLIGENCE REPORT';
        headerBar.appendChild(headerLabel);

        const closeBtn = document.createElement('button');
        closeBtn.type = 'button';
        closeBtn.className = 'detail-close-btn';
        closeBtn.textContent = 'CLOSE [ESC]';
        closeBtn.setAttribute('aria-label', 'Close detail view');
        closeBtn.addEventListener('click', () => this.closeArticleDetail());
        headerBar.appendChild(closeBtn);

        panel.appendChild(headerBar);

        // Scrollable content area
        const content = document.createElement('div');
        content.className = 'detail-content';

        // Title
        const cleanTitle = this.cleanArticleTitle(article.title, article.source);
        const titleEl = document.createElement('h2');
        titleEl.className = 'detail-title';
        titleEl.textContent = cleanTitle;
        content.appendChild(titleEl);

        // Tags row
        const tagsRow = document.createElement('div');
        tagsRow.className = 'detail-tags';

        const catTag = document.createElement('span');
        catTag.className = `tag tag-${this.getCategoryClass(article.category)}`;
        catTag.textContent = article.category || 'UNKNOWN';
        tagsRow.appendChild(catTag);

        const priLevel = Math.max(1, Math.min(5, parseInt(article.priority) || 3));
        const priTag = document.createElement('span');
        priTag.className = `tag tag-priority priority-${priLevel}`;
        priTag.textContent = priLevel === 1 ? 'CRITICAL' : priLevel === 2 ? 'HIGH' : 'MEDIUM';
        tagsRow.appendChild(priTag);

        const srcTag = document.createElement('span');
        srcTag.className = 'tag tag-source';
        srcTag.textContent = article.source || 'Unknown';
        tagsRow.appendChild(srcTag);

        if (article.scope) {
            const scopeTag = document.createElement('span');
            scopeTag.className = 'tag tag-source';
            scopeTag.textContent = article.scope.toUpperCase();
            tagsRow.appendChild(scopeTag);
        }
        content.appendChild(tagsRow);

        // Metadata grid
        const metaGrid = document.createElement('div');
        metaGrid.className = 'detail-meta-grid';

        const addMeta = (label, value) => {
            const item = document.createElement('div');
            item.className = 'detail-meta-item';
            const labelEl = document.createElement('span');
            labelEl.className = 'detail-meta-label';
            labelEl.textContent = label;
            const valueEl = document.createElement('span');
            valueEl.className = 'detail-meta-value';
            valueEl.textContent = value;
            item.appendChild(labelEl);
            item.appendChild(valueEl);
            metaGrid.appendChild(item);
        };

        addMeta('Published:', this.formatDate(article.published));
        addMeta('Source:', article.source || 'Unknown');
        addMeta('Feed:', article.feed_name || 'N/A');
        if (article.geo && article.geo.country) {
            addMeta('Location:', article.geo.country);
        }
        if (article.sector) {
            addMeta('Sector:', article.sector);
        }
        addMeta('Audience:', article.audience ? article.audience.charAt(0).toUpperCase() + article.audience.slice(1) : 'N/A');
        content.appendChild(metaGrid);

        // Summary section
        const summarySection = document.createElement('div');
        summarySection.className = 'detail-section';
        const summaryTitle = document.createElement('h3');
        summaryTitle.className = 'detail-section-title';
        summaryTitle.textContent = 'SUMMARY';
        summarySection.appendChild(summaryTitle);
        const summaryText = document.createElement('p');
        summaryText.className = 'detail-summary-text';
        summaryText.textContent = article.summary || 'No summary available.';
        summarySection.appendChild(summaryText);
        content.appendChild(summarySection);

        // ATT&CK Techniques
        if (article.attack_techniques && article.attack_techniques.length > 0) {
            const ttpNames = {
                'T1566': 'Spearphishing Attachment', 'T1059': 'Command & Scripting Interpreter',
                'T1078': 'Valid Accounts', 'T1190': 'Exploit Public-Facing Application',
                'T1071': 'Application Layer Protocol', 'T1486': 'Data Encrypted for Impact',
                'T1048': 'Exfiltration Over Alternative Protocol', 'T1021': 'Remote Services',
                'T1053': 'Scheduled Task/Job', 'T1027': 'Obfuscated Files or Information',
                'T1105': 'Ingress Tool Transfer'
            };

            const attackSection = document.createElement('div');
            attackSection.className = 'detail-section';
            const attackTitle = document.createElement('h3');
            attackTitle.className = 'detail-section-title';
            attackTitle.textContent = 'MITRE ATT&CK TECHNIQUES';
            attackSection.appendChild(attackTitle);

            const techList = document.createElement('div');
            techList.className = 'detail-technique-list';

            article.attack_techniques.forEach(tech => {
                if (!/^T\d{4}(?:\.\d{3})?$/.test(tech)) return;

                const techItem = document.createElement('div');
                techItem.className = 'detail-technique-item';

                const techId = document.createElement('span');
                techId.className = 'detail-technique-id';
                techId.textContent = tech;
                techItem.appendChild(techId);

                const techName = document.createElement('span');
                techName.className = 'detail-technique-name';
                techName.textContent = ttpNames[tech] || 'Unknown Technique';
                techItem.appendChild(techName);

                const techLink = document.createElement('a');
                techLink.className = 'detail-technique-link';
                techLink.href = `https://attack.mitre.org/techniques/${encodeURIComponent(tech)}/`;
                techLink.target = '_blank';
                techLink.rel = 'noopener noreferrer';
                techLink.textContent = 'View on MITRE →';
                techItem.appendChild(techLink);

                techList.appendChild(techItem);
            });

            attackSection.appendChild(techList);
            content.appendChild(attackSection);
        }

        // IOCs section
        if (article.iocs) {
            const iocTypes = [
                { key: 'cves', label: 'CVE' },
                { key: 'ips', label: 'IP' },
                { key: 'domains', label: 'Domain' },
                { key: 'hashes', label: 'Hash' }
            ];

            const hasIocs = iocTypes.some(t => article.iocs[t.key] && article.iocs[t.key].length > 0);
            if (hasIocs) {
                const iocSection = document.createElement('div');
                iocSection.className = 'detail-section';
                const iocTitle = document.createElement('h3');
                iocTitle.className = 'detail-section-title';
                iocTitle.textContent = 'INDICATORS OF COMPROMISE';
                iocSection.appendChild(iocTitle);

                const iocGrid = document.createElement('div');
                iocGrid.className = 'detail-ioc-grid';

                iocTypes.forEach(({ key, label }) => {
                    if (article.iocs[key]) {
                        article.iocs[key].forEach(val => {
                            const iocItem = document.createElement('div');
                            iocItem.className = 'detail-ioc-item';
                            const iocType = document.createElement('span');
                            iocType.className = 'detail-ioc-type';
                            iocType.textContent = label;
                            const iocValue = document.createElement('span');
                            iocValue.className = 'detail-ioc-value';
                            iocValue.textContent = val;
                            iocItem.appendChild(iocType);
                            iocItem.appendChild(iocValue);
                            iocGrid.appendChild(iocItem);
                        });
                    }
                });

                iocSection.appendChild(iocGrid);
                content.appendChild(iocSection);
            }
        }

        // External link footer
        if (safeLink !== '#') {
            const extSection = document.createElement('div');
            extSection.className = 'detail-section detail-ext-section';
            const extLink = document.createElement('a');
            extLink.className = 'detail-ext-link';
            extLink.href = safeLink;
            extLink.target = '_blank';
            extLink.rel = 'noopener noreferrer';
            extLink.textContent = 'View Original Source →';
            extSection.appendChild(extLink);
            content.appendChild(extSection);
        }

        panel.appendChild(content);
        overlay.appendChild(panel);
        document.body.appendChild(overlay);

        closeBtn.focus();

        // ESC to close
        this._detailEscHandler = (e) => {
            if (e.key === 'Escape') this.closeArticleDetail();
        };
        document.addEventListener('keydown', this._detailEscHandler);
    }

    closeArticleDetail() {
        const overlay = document.getElementById('article-detail-overlay');
        if (overlay) overlay.remove();
        if (this._detailEscHandler) {
            document.removeEventListener('keydown', this._detailEscHandler);
            this._detailEscHandler = null;
        }
    }

    getCategoryClass(category) {
        const classes = {
            'APT': 'incidents', 'VULNERABILITY': 'advisories', 'MALWARE': 'incidents',
            'BREACH': 'incidents', 'RESEARCH': 'research', 'ADVISORY': 'advisories',
            'PHISHING': 'incidents', 'SUPPLY_CHAIN': 'incidents', 'NETWORK': 'advisories'
        };
        return classes[category] || 'incidents';
    }

    cleanArticleTitle(title, source) {
        let cleanTitle = title || 'Untitled';
        if (source) {
            const suffixes = [` - ${source}`, ` – ${source}`, ` | ${source}`, ` (${source})`];
            for (const suffix of suffixes) {
                if (cleanTitle.endsWith(suffix)) {
                    cleanTitle = cleanTitle.slice(0, -suffix.length);
                    break;
                }
            }
        }
        return cleanTitle;
    }

    sanitizeUrl(href) {
        if (typeof href !== 'string' || href.length === 0) return '#';
        try {
            const parsed = new URL(href, window.location.origin);
            if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
                return parsed.href;
            }
        } catch {
            // invalid
        }
        return '#';
    }

    formatDate(dateStr) {
        if (!dateStr) return 'Unknown';
        const date = new Date(dateStr);
        if (isNaN(date.getTime())) return dateStr;

        const now = new Date();
        const diff = now - date;
        const hours = Math.floor(diff / (1000 * 60 * 60));

        if (hours < 1) return 'Just now';
        if (hours < 24) return `${hours}h ago`;
        const days = Math.floor(hours / 24);
        if (days < 7) return `${days}d ago`;

        return date.toLocaleDateString();
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    const mapContainer = document.getElementById('threat-map');
    if (mapContainer) {
        const threatMap = new ThreatMap('threat-map');
        threatMap.init();
    }
});
