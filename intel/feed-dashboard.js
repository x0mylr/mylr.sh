/**
 * The Daily Brief - Threat Intelligence Feed Dashboard
 * Secure, modular architecture with safe DOM operations.
 *
 * Security: All dynamic content rendered via textContent or safe DOM builders.
 *           No innerHTML with user/external data. Input validated and sanitized.
 */

'use strict';

/* ============================================
   UTILITY: Safe DOM helpers
   ============================================ */
const DOM = {
    /**
     * Create an element with attributes and children.
     * All text is set via textContent (never innerHTML).
     */
    create(tag, attrs = {}, children = []) {
        const el = document.createElement(tag);
        for (const [key, value] of Object.entries(attrs)) {
            if (key === 'textContent') {
                el.textContent = value;
            } else if (key === 'className') {
                el.className = value;
            } else if (key === 'dataset') {
                for (const [dk, dv] of Object.entries(value)) {
                    el.dataset[dk] = dv;
                }
            } else if (key === 'style' && typeof value === 'object') {
                for (const [sk, sv] of Object.entries(value)) {
                    el.style[sk] = sv;
                }
            } else if (key.startsWith('on') && typeof value === 'function') {
                el.addEventListener(key.slice(2).toLowerCase(), value);
            } else {
                el.setAttribute(key, value);
            }
        }
        for (const child of children) {
            if (typeof child === 'string') {
                el.appendChild(document.createTextNode(child));
            } else if (child instanceof Node) {
                el.appendChild(child);
            }
        }
        return el;
    },

    /** Clear all children from an element safely */
    clear(el) {
        while (el.firstChild) {
            el.removeChild(el.firstChild);
        }
    },

    /** Query with null-safety */
    qs(selector, parent = document) {
        return parent.querySelector(selector);
    },

    qsa(selector, parent = document) {
        return Array.from(parent.querySelectorAll(selector));
    }
};

/* ============================================
   UTILITY: Input sanitization
   ============================================ */
const Sanitize = {
    /** Strip anything that isn't alphanumeric, spaces, hyphens, or basic punctuation */
    searchQuery(input) {
        if (typeof input !== 'string') return '';
        return input.slice(0, 256).replace(/[^\w\s\-.,;:'"!?@#()/\\]/g, '');
    },

    /** Validate ATT&CK technique ID format */
    attackTechniqueId(id) {
        if (typeof id !== 'string') return null;
        const match = id.match(/^T\d{4}(?:\.\d{3})?$/);
        return match ? match[0] : null;
    },

    /** Validate country name (letters, spaces, hyphens only) */
    countryName(name) {
        if (typeof name !== 'string') return '';
        return name.slice(0, 100).replace(/[^a-zA-Z\s\-'().]/g, '');
    },

    /** Validate and return a safe URL, or '#' as fallback */
    url(href) {
        if (typeof href !== 'string' || href.length === 0) return '#';
        try {
            const parsed = new URL(href, window.location.origin);
            if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
                return parsed.href;
            }
        } catch {
            // invalid URL
        }
        return '#';
    },

    /** Ensure a value is a safe integer within bounds */
    integer(val, min = 0, max = Number.MAX_SAFE_INTEGER) {
        const num = parseInt(val, 10);
        if (isNaN(num)) return min;
        return Math.max(min, Math.min(max, num));
    },

    /** Escape text for CSV field */
    csvField(text) {
        if (text == null) return '""';
        const str = String(text).replace(/"/g, '""');
        return `"${str}"`;
    }
};

/* ============================================
   UTILITY: Announcement for screen readers
   ============================================ */
function announce(message) {
    const region = document.getElementById('live-announcements');
    if (region) {
        region.textContent = message;
    }
}

/* ============================================
   MAIN DASHBOARD CLASS
   ============================================ */
class FeedDashboard {
    constructor() {
        this.feedData = null;
        this.selectedArticles = new Set();
        this.currentView = 'list';
        this._searchDebounceTimer = null;

        // Active filters
        this.filters = {
            scope: new Set(['tactical', 'strategic']),
            audience: new Set(['technical', 'executive', 'analyst']),
            category: new Set(['all']),
            priority: 'all',
            timeRange: '24h',
            customFrom: null,
            customTo: null,
            searchQuery: ''
        };

        // Cache DOM references for metrics (avoid nth-child fragility)
        this._metricEls = {};
    }

    async init() {
        await this.loadFeedData();

        // Cache metric elements by data-metric attribute
        DOM.qsa('[data-metric]').forEach(el => {
            const key = el.dataset.metric;
            this._metricEls[key] = DOM.qs('.metric-value', el);
        });

        this.updateMetrics();
        this.updateDEFCON();
        this.updateFilterCounts();
        this.updateTrending();
        this.updateSectorStats();
        this.updateGeoStats();
        this.updateTTPsList();
        this.renderFeed();
        this.attachEventListeners();
        this.handleUrlArticleParam();

        announce('Dashboard loaded. Displaying threat intelligence feed.');
    }

    async loadFeedData() {
        const paths = [
            'output/feed_data.json',
            'feed_data.json',
            '../output/feed_data.json'
        ];

        for (const path of paths) {
            try {
                const response = await fetch(path);
                if (!response.ok) continue;

                const contentType = response.headers.get('content-type') || '';
                if (!contentType.includes('application/json') && !contentType.includes('text/')) {
                    continue;
                }

                const data = await response.json();

                // Validate basic structure
                if (!data || !Array.isArray(data.articles) || !data.metadata) {
                    continue;
                }

                this.feedData = data;
                return;
            } catch {
                continue;
            }
        }

        this.loadSampleData();
    }

    loadSampleData() {
        const now = new Date();
        this.feedData = {
            metadata: {
                generated_at: now.toISOString(),
                total_articles: 4,
                feeds_processed: 4,
                defcon_level: 3,
                defcon_details: {
                    name: 'ELEVATED',
                    color: '#ff9944',
                    description: 'Sample data - run aggregator for live intel',
                    score: 2.5
                },
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
                    title: 'Iranian Infy APT Resurfaces with New Malware Activity After Years of Silence',
                    link: '#',
                    summary: 'Iranian state-sponsored threat actor Infy has returned after years of dormancy, deploying sophisticated malware targeting government agencies. The campaign demonstrates evolved TTPs including enhanced evasion techniques and multi-stage payload delivery.',
                    published: new Date(now - 2 * 3600000).toISOString(),
                    source: 'The Hacker News',
                    category: 'APT',
                    feed_name: 'Advanced Persistent Threats',
                    icon: '🎯',
                    color: '#9a4c30',
                    priority: 1,
                    scope: 'strategic',
                    audience: 'analyst',
                    attack_techniques: ['T1566', 'T1059'],
                    geo: { country: 'Iran', latitude: 32.4279, longitude: 53.6880 }
                },
                {
                    id: 'sample-002',
                    title: 'Critical Zero-Day in Ivanti Connect Secure Actively Exploited in the Wild',
                    link: '#',
                    summary: 'CISA confirms active exploitation of CVE-2024-99999 affecting Ivanti Connect Secure VPN appliances. Remote attackers can achieve unauthenticated RCE, leading to full system compromise.',
                    published: new Date(now - 4 * 3600000).toISOString(),
                    source: 'BleepingComputer',
                    category: 'VULNERABILITY',
                    feed_name: 'Critical Vulnerabilities',
                    icon: '🔓',
                    color: '#d9534f',
                    priority: 1,
                    scope: 'tactical',
                    audience: 'technical',
                    attack_techniques: ['T1190'],
                    iocs: { cves: ['CVE-2024-99999'] },
                    geo: { country: 'United States', latitude: 37.0902, longitude: -95.7129 }
                },
                {
                    id: 'sample-003',
                    title: 'LockBit 4.0 Ransomware Variant Targets Healthcare Organizations',
                    link: '#',
                    summary: 'Security researchers identify evolved LockBit variant with enhanced encryption algorithms and data exfiltration capabilities specifically targeting healthcare sector.',
                    published: new Date(now - 6 * 3600000).toISOString(),
                    source: 'SOCRadar',
                    category: 'MALWARE',
                    feed_name: 'Ransomware & Malware',
                    icon: '💀',
                    color: '#f0ad4e',
                    priority: 2,
                    scope: 'tactical',
                    audience: 'technical',
                    attack_techniques: ['T1486', 'T1048'],
                    sector: 'Healthcare'
                },
                {
                    id: 'sample-004',
                    title: 'Volt Typhoon Infrastructure Expands to Target European Critical Infrastructure',
                    link: '#',
                    summary: 'Chinese APT group establishes new command and control infrastructure targeting European energy sector. Analysis reveals living-off-the-land techniques.',
                    published: new Date(now - 12 * 3600000).toISOString(),
                    source: 'CyberScoop',
                    category: 'APT',
                    feed_name: 'Advanced Persistent Threats',
                    icon: '🎯',
                    color: '#9a4c30',
                    priority: 1,
                    scope: 'strategic',
                    audience: 'executive',
                    attack_techniques: ['T1071', 'T1078', 'T1059'],
                    geo: { country: 'China', latitude: 35.8617, longitude: 104.1954 },
                    sector: 'Energy'
                }
            ]
        };
    }

    /* ============================================
       METRICS
    ============================================ */
    updateMetrics() {
        const articles = this.feedData.articles;

        this.animateCounter('total-events', this.feedData.metadata.total_articles);

        const critical = articles.filter(a => a.priority === 1).length;
        this.animateCounter('critical', critical);

        const apts = articles.filter(a => a.category === 'APT').length;
        this.animateCounter('active-apts', apts);
    }

    updateDEFCON() {
        const level = this.feedData.metadata.defcon_level;
        const details = this.feedData.metadata.defcon_details;
        const el = this._metricEls['threat-level'];

        if (el) {
            el.textContent = `DEFCON ${Sanitize.integer(level, 1, 5)}`;
            // Use CSS class instead of inline style for DEFCON color
            el.className = 'metric-value defcon-' + Sanitize.integer(level, 1, 5);
            el.title = `${details.name || ''}: ${details.description || ''}\nScore: ${details.score || 0}/5.0`;
        }
    }

    updateFilterCounts() {
        const articles = this.feedData.articles;

        this.setFilterCount('scope-tactical', articles.filter(a => a.scope === 'tactical').length);
        this.setFilterCount('scope-strategic', articles.filter(a => a.scope === 'strategic').length);

        this.setFilterCount('aud-technical', articles.filter(a => a.audience === 'technical').length);
        this.setFilterCount('aud-executive', articles.filter(a => a.audience === 'executive').length);
        this.setFilterCount('aud-analyst', articles.filter(a => a.audience === 'analyst').length);

        this.setFilterCount('cat-all', articles.length);
        const categories = ['apt', 'vulnerability', 'malware', 'breach', 'research', 'advisory', 'phishing', 'supply_chain', 'network'];
        categories.forEach(cat => {
            const count = articles.filter(a => a.category.toLowerCase() === cat).length;
            this.setFilterCount(`cat-${cat}`, count);
        });

        const catTotal = document.getElementById('category-total');
        if (catTotal) {
            const uniqueCategories = new Set(articles.map(a => a.category));
            catTotal.textContent = uniqueCategories.size;
        }

        this.setFilterCount('pri-critical', articles.filter(a => a.priority === 1).length);
        this.setFilterCount('pri-high', articles.filter(a => a.priority === 2).length);
        this.setFilterCount('pri-medium', articles.filter(a => a.priority === 3).length);
    }

    setFilterCount(key, value) {
        const el = DOM.qs(`[data-count="${CSS.escape(key)}"]`);
        if (el) el.textContent = value;
    }

    /* ============================================
       CONTEXT PANEL: Trending, Sectors, Geo, TTPs
    ============================================ */
    updateTrending() {
        const container = DOM.qs('.trending-attacks');
        if (!container) return;

        const techniques = {};
        this.feedData.articles.forEach(article => {
            if (article.attack_techniques) {
                article.attack_techniques.forEach(tech => {
                    const validated = Sanitize.attackTechniqueId(tech);
                    if (validated) {
                        techniques[validated] = (techniques[validated] || 0) + 1;
                    }
                });
            }
        });

        const top10 = Object.entries(techniques)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10);

        DOM.clear(container);

        if (top10.length === 0) {
            container.appendChild(
                DOM.create('div', { className: 'no-data', textContent: 'No ATT&CK techniques detected' })
            );
            return;
        }

        top10.forEach(([tech, count], index) => {
            const item = DOM.create('div', {
                className: 'trending-item',
                role: 'listitem',
                dataset: { technique: tech },
                title: `View ${tech} on MITRE ATT&CK`
            }, [
                DOM.create('span', { className: 'trending-rank', textContent: `${index + 1}.` }),
                DOM.create('span', { className: 'trending-name', textContent: tech }),
                DOM.create('span', { className: 'trending-count', textContent: String(count) })
            ]);

            item.addEventListener('click', () => {
                const validated = Sanitize.attackTechniqueId(tech);
                if (validated) {
                    window.open(
                        `https://attack.mitre.org/techniques/${encodeURIComponent(validated)}/`,
                        '_blank',
                        'noopener,noreferrer'
                    );
                }
            });

            item.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    item.click();
                }
            });

            item.setAttribute('tabindex', '0');
            container.appendChild(item);
        });
    }

    updateSectorStats() {
        const sectorList = DOM.qs('.sector-list');
        const sectorChart = document.getElementById('sector-chart');
        if (!sectorList) return;

        const sectors = {};
        this.feedData.articles.forEach(article => {
            const sector = article.sector || this.inferSector(article.category);
            sectors[sector] = (sectors[sector] || 0) + 1;
        });

        const sortedSectors = Object.entries(sectors)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 6);

        DOM.clear(sectorList);

        if (sortedSectors.length === 0) {
            sectorList.appendChild(
                DOM.create('div', { className: 'no-data', textContent: 'No sector data' })
            );
            return;
        }

        // Build chart bars safely
        if (sectorChart) {
            DOM.clear(sectorChart);
            const maxCount = sortedSectors[0][1];
            sortedSectors.forEach(([sector, count]) => {
                const pct = Math.max(15, (count / maxCount) * 100);
                const bar = DOM.create('div', {
                    className: 'chart-bar',
                    title: `${sector}: ${count}`,
                    style: { height: `${pct}%` }
                });
                sectorChart.appendChild(bar);
            });
        }

        // Build list
        sortedSectors.forEach(([sector, count]) => {
            const item = DOM.create('div', {
                className: 'sector-item',
                role: 'listitem'
            }, [
                DOM.create('span', { className: 'sector-bullet', textContent: '● ' }),
                document.createTextNode(`${sector}: `),
                DOM.create('strong', { textContent: `${count} events` })
            ]);
            sectorList.appendChild(item);
        });
    }

    inferSector(category) {
        const sectorMap = {
            'HEALTHCARE': 'Healthcare',
            'FINANCIAL': 'Finance',
            'ENERGY': 'Energy',
            'GOVERNMENT': 'Government',
            'APT': 'Government',
            'VULNERABILITY': 'Technology',
            'MALWARE': 'Various',
            'BREACH': 'Various',
            'SUPPLY_CHAIN': 'Infrastructure',
            'ADVISORY': 'Government',
            'PHISHING': 'Various',
            'NETWORK': 'Infrastructure',
            'RESEARCH': 'Research'
        };
        return sectorMap[category] || 'Other';
    }

    updateGeoStats() {
        const geoList = DOM.qs('.geo-list');
        if (!geoList) return;

        const geo = this.feedData.metadata.geo_stats;
        if (!geo || !geo.countries || Object.keys(geo.countries).length === 0) {
            DOM.clear(geoList);
            geoList.appendChild(
                DOM.create('div', { className: 'no-data', textContent: 'No geographic data available' })
            );
            return;
        }

        const sortedCountries = Object.entries(geo.countries)
            .sort((a, b) => b[1].count - a[1].count)
            .slice(0, 8);

        DOM.clear(geoList);

        sortedCountries.forEach(([country, data]) => {
            const safeName = Sanitize.countryName(country);
            const item = DOM.create('div', {
                className: 'geo-item',
                role: 'listitem',
                dataset: { country: safeName },
                title: `View ${safeName} on threat map`
            }, [
                document.createTextNode(`${safeName}: `),
                DOM.create('strong', { textContent: `${data.count} articles` })
            ]);

            item.addEventListener('click', () => {
                window.open(`map.html?country=${encodeURIComponent(safeName)}`, '_blank', 'noopener');
            });

            item.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    item.click();
                }
            });

            item.setAttribute('tabindex', '0');
            geoList.appendChild(item);
        });
    }

    updateTTPsList() {
        const ttpsList = DOM.qs('.ttps-list');
        if (!ttpsList) return;

        const ttps = {};
        const ttpNames = {
            'T1566': 'Spearphishing Attachment',
            'T1566.001': 'Spearphishing Attachment',
            'T1059': 'Command & Scripting Interpreter',
            'T1078': 'Valid Accounts',
            'T1190': 'Exploit Public-Facing Application',
            'T1071': 'Application Layer Protocol',
            'T1486': 'Data Encrypted for Impact',
            'T1048': 'Exfiltration Over Alternative Protocol',
            'T1021': 'Remote Services',
            'T1053': 'Scheduled Task/Job',
            'T1027': 'Obfuscated Files or Information',
            'T1105': 'Ingress Tool Transfer'
        };

        this.feedData.articles.forEach(article => {
            if (article.attack_techniques) {
                article.attack_techniques.forEach(tech => {
                    const validated = Sanitize.attackTechniqueId(tech);
                    if (validated) {
                        const name = ttpNames[validated] || validated;
                        ttps[name] = (ttps[name] || 0) + 1;
                    }
                });
            }
        });

        const sorted = Object.entries(ttps)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 8);

        DOM.clear(ttpsList);

        if (sorted.length === 0) {
            ttpsList.appendChild(
                DOM.create('div', { className: 'no-data', textContent: 'No TTP data available' })
            );
            return;
        }

        sorted.forEach(([name, count]) => {
            ttpsList.appendChild(
                DOM.create('div', { role: 'listitem', textContent: `● ${name} (${count})` })
            );
        });
    }

    /* ============================================
       FEED RENDERING (Safe DOM construction)
    ============================================ */
    renderFeed() {
        const container = DOM.qs('.intel-feed');
        if (!container) return;

        const filtered = this.filterArticles();

        container.setAttribute('aria-busy', 'true');
        DOM.clear(container);

        if (filtered.length === 0) {
            container.appendChild(
                DOM.create('div', { className: 'feed-status', textContent: 'No articles match current filters' })
            );
            container.setAttribute('aria-busy', 'false');
            this.updateSelectionInfo();
            announce('No articles match current filters.');
            return;
        }

        filtered.forEach(article => {
            container.appendChild(this.createArticleCard(article));
        });

        container.setAttribute('aria-busy', 'false');
        this.updateSelectionInfo();
        announce(`Showing ${filtered.length} threat intelligence articles.`);
    }

    renderGraphView() {
        const container = DOM.qs('.intel-feed');
        if (!container) return;
        DOM.clear(container);

        const articles = this.filterArticles();
        if (articles.length === 0) {
            container.appendChild(DOM.create('div', { className: 'feed-status', textContent: 'No articles to graph' }));
            return;
        }

        // Build graph data: nodes = articles + shared concepts, edges = relationships
        const nodes = [];
        const edges = [];
        const conceptMap = {};

        articles.forEach((article, i) => {
            nodes.push({
                id: article.id,
                label: this.truncate(this.cleanArticleTitle(article.title, article.source), 40),
                type: 'article',
                category: article.category,
                priority: article.priority,
                article: article
            });

            // ATT&CK technique nodes
            if (article.attack_techniques) {
                article.attack_techniques.forEach(tech => {
                    const validated = Sanitize.attackTechniqueId(tech);
                    if (!validated) return;
                    if (!conceptMap[validated]) {
                        conceptMap[validated] = { id: `tech-${validated}`, label: validated, type: 'technique', connections: [] };
                    }
                    conceptMap[validated].connections.push(article.id);
                });
            }

            // Category nodes
            const catKey = `cat-${article.category}`;
            if (!conceptMap[catKey]) {
                conceptMap[catKey] = { id: catKey, label: article.category, type: 'category', connections: [] };
            }
            conceptMap[catKey].connections.push(article.id);

            // Geo nodes
            if (article.geo && article.geo.country) {
                const geoKey = `geo-${article.geo.country}`;
                if (!conceptMap[geoKey]) {
                    conceptMap[geoKey] = { id: geoKey, label: Sanitize.countryName(article.geo.country), type: 'geo', connections: [] };
                }
                conceptMap[geoKey].connections.push(article.id);
            }
        });

        // Only include concept nodes that connect 2+ articles
        Object.values(conceptMap).forEach(concept => {
            if (concept.connections.length >= 2) {
                nodes.push(concept);
                concept.connections.forEach(articleId => {
                    edges.push({ source: concept.id, target: articleId });
                });
            }
        });

        // Create canvas
        const wrapper = DOM.create('div', { className: 'graph-view-wrapper' });
        const legend = DOM.create('div', { className: 'graph-legend' }, [
            DOM.create('span', { className: 'graph-legend-item graph-legend-article', textContent: 'Articles' }),
            DOM.create('span', { className: 'graph-legend-item graph-legend-technique', textContent: 'ATT&CK Techniques' }),
            DOM.create('span', { className: 'graph-legend-item graph-legend-category', textContent: 'Categories' }),
            DOM.create('span', { className: 'graph-legend-item graph-legend-geo', textContent: 'Countries' })
        ]);
        wrapper.appendChild(legend);

        const canvas = DOM.create('canvas', {
            className: 'graph-canvas',
            'aria-label': 'Threat intelligence relationship graph'
        });
        wrapper.appendChild(canvas);
        container.appendChild(wrapper);

        // Size canvas
        const rect = wrapper.getBoundingClientRect();
        const width = rect.width || 800;
        const height = Math.max(500, window.innerHeight - 300);
        canvas.width = width;
        canvas.height = height;

        // Simple force-directed layout
        this._runGraphSimulation(canvas, nodes, edges, width, height);
        announce(`Graph view: ${articles.length} articles with ${edges.length} relationships.`);
    }

    _runGraphSimulation(canvas, nodes, edges, width, height) {
        const ctx = canvas.getContext('2d');
        const nodeColors = {
            article: '#9a4c30',
            technique: '#2c3e50',
            category: '#4fc3f7',
            geo: '#44ff88'
        };
        const nodeRadius = {
            article: 12,
            technique: 8,
            category: 10,
            geo: 8
        };

        // Initialize positions
        nodes.forEach((node, i) => {
            const angle = (2 * Math.PI * i) / nodes.length;
            const r = Math.min(width, height) * 0.35;
            node.x = width / 2 + r * Math.cos(angle) + (Math.random() - 0.5) * 40;
            node.y = height / 2 + r * Math.sin(angle) + (Math.random() - 0.5) * 40;
            node.vx = 0;
            node.vy = 0;
        });

        // Build node lookup
        const nodeMap = {};
        nodes.forEach(n => { nodeMap[n.id] = n; });

        let iteration = 0;
        const maxIterations = 150;
        const self = this;

        function simulate() {
            // Repulsion between all nodes
            for (let i = 0; i < nodes.length; i++) {
                for (let j = i + 1; j < nodes.length; j++) {
                    let dx = nodes[j].x - nodes[i].x;
                    let dy = nodes[j].y - nodes[i].y;
                    let dist = Math.sqrt(dx * dx + dy * dy) || 1;
                    let force = 800 / (dist * dist);
                    let fx = (dx / dist) * force;
                    let fy = (dy / dist) * force;
                    nodes[i].vx -= fx;
                    nodes[i].vy -= fy;
                    nodes[j].vx += fx;
                    nodes[j].vy += fy;
                }
            }

            // Attraction along edges
            edges.forEach(edge => {
                const source = nodeMap[edge.source];
                const target = nodeMap[edge.target];
                if (!source || !target) return;
                let dx = target.x - source.x;
                let dy = target.y - source.y;
                let dist = Math.sqrt(dx * dx + dy * dy) || 1;
                let force = (dist - 120) * 0.02;
                let fx = (dx / dist) * force;
                let fy = (dy / dist) * force;
                source.vx += fx;
                source.vy += fy;
                target.vx -= fx;
                target.vy -= fy;
            });

            // Center gravity
            nodes.forEach(node => {
                node.vx += (width / 2 - node.x) * 0.002;
                node.vy += (height / 2 - node.y) * 0.002;
            });

            // Apply velocity with damping
            const damping = 0.85;
            nodes.forEach(node => {
                node.vx *= damping;
                node.vy *= damping;
                node.x += node.vx;
                node.y += node.vy;
                // Keep in bounds
                const r = nodeRadius[node.type] || 10;
                node.x = Math.max(r, Math.min(width - r, node.x));
                node.y = Math.max(r, Math.min(height - r, node.y));
            });

            // Draw
            ctx.clearRect(0, 0, width, height);

            // Background
            ctx.fillStyle = '#0d0d0d';
            ctx.fillRect(0, 0, width, height);

            // Edges
            ctx.strokeStyle = 'rgba(154, 76, 48, 0.3)';
            ctx.lineWidth = 1;
            edges.forEach(edge => {
                const source = nodeMap[edge.source];
                const target = nodeMap[edge.target];
                if (!source || !target) return;
                ctx.beginPath();
                ctx.moveTo(source.x, source.y);
                ctx.lineTo(target.x, target.y);
                ctx.stroke();
            });

            // Nodes
            nodes.forEach(node => {
                const r = nodeRadius[node.type] || 10;
                const color = nodeColors[node.type] || '#999';

                ctx.beginPath();
                ctx.arc(node.x, node.y, r, 0, 2 * Math.PI);
                ctx.fillStyle = color;
                ctx.fill();
                ctx.strokeStyle = 'rgba(255,255,255,0.2)';
                ctx.lineWidth = 1;
                ctx.stroke();

                // Labels
                ctx.fillStyle = '#b0b0b0';
                ctx.font = node.type === 'article' ? '10px Courier New' : '9px Courier New';
                ctx.textAlign = 'center';
                ctx.fillText(node.label, node.x, node.y + r + 12);
            });

            iteration++;
            if (iteration < maxIterations) {
                requestAnimationFrame(simulate);
            }
        }

        simulate();

        // Click handling for article nodes
        canvas.addEventListener('click', (e) => {
            const rect = canvas.getBoundingClientRect();
            const mx = e.clientX - rect.left;
            const my = e.clientY - rect.top;

            for (const node of nodes) {
                const r = nodeRadius[node.type] || 10;
                const dx = mx - node.x;
                const dy = my - node.y;
                if (dx * dx + dy * dy <= (r + 4) * (r + 4)) {
                    if (node.type === 'article' && node.article) {
                        self.showArticleDetail(node.article);
                    } else if (node.type === 'technique') {
                        const techId = node.label;
                        const validated = Sanitize.attackTechniqueId(techId);
                        if (validated) {
                            window.open(
                                `https://attack.mitre.org/techniques/${encodeURIComponent(validated)}/`,
                                '_blank',
                                'noopener,noreferrer'
                            );
                        }
                    }
                    break;
                }
            }
        });
    }

    filterArticles() {
        if (!this.feedData || !this.feedData.articles) return [];

        return this.feedData.articles.filter(article => {
            if (!this.filters.scope.has(article.scope)) return false;
            if (!this.filters.audience.has(article.audience)) return false;

            if (!this.filters.category.has('all') && !this.filters.category.has(article.category)) {
                return false;
            }

            if (this.filters.priority !== 'all' && article.priority !== parseInt(this.filters.priority, 10)) {
                return false;
            }

            if (!this.matchesTimeRange(article.published)) return false;

            if (this.filters.searchQuery) {
                const query = this.filters.searchQuery.toLowerCase();
                const searchable = `${article.title} ${article.summary || ''} ${article.category} ${article.source || ''}`.toLowerCase();
                if (!searchable.includes(query)) return false;
            }

            return true;
        });
    }

    matchesTimeRange(publishedDate) {
        if (!publishedDate) return true;
        const now = new Date();
        const published = new Date(publishedDate);
        if (isNaN(published.getTime())) return true;

        const hours = (now - published) / (1000 * 60 * 60);

        switch (this.filters.timeRange) {
            case '24h': return hours <= 24;
            case '7d': return hours <= 168;
            case '30d': return hours <= 720;
            case 'custom': {
                const from = this.filters.customFrom;
                const to = this.filters.customTo;
                if (from && published < from) return false;
                if (to && published > to) return false;
                return true;
            }
            default: return true;
        }
    }

    /**
     * Build an intel card using safe DOM construction.
     * No innerHTML - all content is textContent or attribute-based.
     */
    createArticleCard(article) {
        const isSelected = this.selectedArticles.has(article.id);
        const cleanTitle = this.cleanArticleTitle(article.title, article.source);
        const safeLink = Sanitize.url(article.link);

        // Card wrapper
        const card = DOM.create('article', {
            className: 'intel-card',
            role: 'article',
            dataset: { articleId: article.id }
        });

        // Checkbox
        const checkbox = DOM.create('input', {
            type: 'checkbox',
            className: 'card-checkbox',
            dataset: { id: article.id },
            'aria-label': `Select: ${cleanTitle}`
        });
        if (isSelected) checkbox.checked = true;

        checkbox.addEventListener('change', (e) => {
            if (e.target.checked) {
                this.selectedArticles.add(article.id);
            } else {
                this.selectedArticles.delete(article.id);
            }
            this.updateSelectionInfo();
        });

        // Tags
        const tagsContainer = DOM.create('div', { className: 'card-tags' });
        tagsContainer.appendChild(DOM.create('span', {
            className: `tag tag-${this.getCategoryClass(article.category)}`,
            textContent: article.category
        }));
        tagsContainer.appendChild(DOM.create('span', {
            className: 'tag tag-source',
            textContent: article.source || 'Unknown'
        }));
        tagsContainer.appendChild(DOM.create('span', {
            className: `tag tag-priority priority-${Sanitize.integer(article.priority, 1, 5)}`,
            textContent: `P${article.priority}`
        }));

        // ATT&CK technique tags
        if (article.attack_techniques && article.attack_techniques.length > 0) {
            article.attack_techniques.slice(0, 3).forEach(tech => {
                const validated = Sanitize.attackTechniqueId(tech);
                if (validated) {
                    const techTag = DOM.create('span', {
                        className: 'tag tag-attack',
                        textContent: validated,
                        dataset: { technique: validated },
                        title: `View ${validated} on MITRE ATT&CK`
                    });
                    techTag.addEventListener('click', (e) => {
                        e.stopPropagation();
                        window.open(
                            `https://attack.mitre.org/techniques/${encodeURIComponent(validated)}/`,
                            '_blank',
                            'noopener,noreferrer'
                        );
                    });
                    tagsContainer.appendChild(techTag);
                }
            });
        }

        // Summary
        const summary = DOM.create('p', {
            className: 'card-summary',
            textContent: article.summary ? this.truncate(article.summary, 200) : 'No summary available'
        });

        // Meta items
        const metaContainer = DOM.create('div', { className: 'card-meta' });
        metaContainer.appendChild(DOM.create('span', {
            className: 'meta-item',
            textContent: this.formatDate(article.published)
        }));
        metaContainer.appendChild(DOM.create('span', {
            className: 'meta-item',
            textContent: article.category
        }));
        if (article.geo && (article.geo.country || article.geo.location)) {
            metaContainer.appendChild(DOM.create('span', {
                className: 'meta-item',
                textContent: Sanitize.countryName(article.geo.country || article.geo.location || '')
            }));
        }

        // View Intel button (opens internal detail view)
        const viewLink = DOM.create('button', {
            type: 'button',
            className: 'card-action',
            textContent: 'VIEW INTEL →',
            onClick: (e) => {
                e.stopPropagation();
                this.showArticleDetail(article);
            }
        });

        // Footer
        const footer = DOM.create('div', { className: 'card-footer' }, [metaContainer, viewLink]);

        // Card content wrapper
        const content = DOM.create('div', { className: 'card-content' }, [
            DOM.create('h3', { className: 'card-title', textContent: cleanTitle }),
            tagsContainer,
            summary,
            footer
        ]);

        // Header
        const header = DOM.create('div', { className: 'card-header' }, [checkbox, content]);
        card.appendChild(header);

        return card;
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

    getCategoryClass(category) {
        const classes = {
            'APT': 'incidents',
            'VULNERABILITY': 'advisories',
            'MALWARE': 'incidents',
            'BREACH': 'incidents',
            'RESEARCH': 'research',
            'ADVISORY': 'advisories',
            'PHISHING': 'incidents',
            'SUPPLY_CHAIN': 'incidents',
            'NETWORK': 'advisories'
        };
        return classes[category] || 'incidents';
    }

    /* ============================================
       EVENT LISTENERS
    ============================================ */
    attachEventListeners() {
        // Search with debounce + command support
        const searchInput = document.getElementById('search-input');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                clearTimeout(this._searchDebounceTimer);
                this._searchDebounceTimer = setTimeout(() => {
                    const raw = e.target.value;
                    this.filters.searchQuery = Sanitize.searchQuery(raw);
                    this.renderFeed();
                    this._updateSearchHints(raw);
                }, 300);
            });

            searchInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    const raw = searchInput.value.trim();
                    if (raw) this._executeSearchCommand(raw);
                }
            });

            // Build search hints container
            this._buildSearchHints();
        }

        // Scope filters
        DOM.qsa('#scope-tactical, #scope-strategic').forEach(cb => {
            cb.addEventListener('change', () => this.handleScopeFilter());
        });

        // Audience filters
        DOM.qsa('[id^="aud-"]').forEach(cb => {
            cb.addEventListener('change', () => this.handleAudienceFilter());
        });

        // Category filters
        DOM.qsa('[id^="cat-"]').forEach(cb => {
            cb.addEventListener('change', (e) => this.handleCategoryFilter(e.target));
        });

        // Priority filters
        DOM.qsa('[name="priority"]').forEach(radio => {
            radio.addEventListener('change', (e) => {
                const value = e.target.id.replace('pri-', '');
                this.filters.priority = value === 'all' ? 'all' :
                                       value === 'critical' ? 1 :
                                       value === 'high' ? 2 : 3;
                this.renderFeed();
            });
        });

        // Time range filters
        const customRangeInputs = DOM.qs('#custom-range-inputs');
        DOM.qsa('[name="timerange"]').forEach(radio => {
            radio.addEventListener('change', (e) => {
                this.filters.timeRange = e.target.id.replace('time-', '');
                if (customRangeInputs) {
                    customRangeInputs.style.display = this.filters.timeRange === 'custom' ? 'block' : 'none';
                }
                this.renderFeed();
            });
        });

        // Custom date range inputs
        const customFrom = DOM.qs('#custom-from');
        const customTo = DOM.qs('#custom-to');
        if (customFrom) {
            customFrom.addEventListener('change', (e) => {
                this.filters.customFrom = e.target.value ? new Date(e.target.value + 'T00:00:00') : null;
                if (this.filters.timeRange === 'custom') this.renderFeed();
            });
        }
        if (customTo) {
            customTo.addEventListener('change', (e) => {
                this.filters.customTo = e.target.value ? new Date(e.target.value + 'T23:59:59') : null;
                if (this.filters.timeRange === 'custom') this.renderFeed();
            });
        }

        // Bulk actions - matched by data-action attribute (not text content)
        this.attachBulkActions();

        // View toggles
        this.attachViewToggles();

        // Header buttons
        this.attachHeaderButtons();
    }

    /* ============================================
       ENHANCED SEARCH
    ============================================ */
    _buildSearchHints() {
        const searchBar = DOM.qs('.search-bar');
        if (!searchBar) return;

        const hints = DOM.create('div', { className: 'search-hints', id: 'search-hints' });
        hints.style.display = 'none';
        searchBar.parentNode.insertBefore(hints, searchBar.nextSibling);
    }

    _updateSearchHints(raw) {
        const hints = document.getElementById('search-hints');
        if (!hints) return;

        if (!raw || raw.length < 2) {
            hints.style.display = 'none';
            return;
        }

        DOM.clear(hints);

        // Show external search options based on query
        const lowerRaw = raw.toLowerCase().trim();
        const resources = this._getSearchResources(lowerRaw);

        if (resources.length > 0) {
            const extLabel = DOM.create('div', { className: 'search-hint-label', textContent: 'EXTERNAL RESOURCES — press Enter to search' });
            hints.appendChild(extLabel);

            resources.forEach(r => {
                const item = DOM.create('div', { className: 'search-hint-item' }, [
                    DOM.create('span', { className: 'search-hint-source', textContent: r.source }),
                    DOM.create('span', { className: 'search-hint-desc', textContent: r.description })
                ]);
                item.addEventListener('click', () => {
                    window.open(r.url, '_blank', 'noopener,noreferrer');
                });
                hints.appendChild(item);
            });
        }

        // Show query prefix help
        const prefixes = [
            { prefix: 'cve:', desc: 'Search CVE databases (e.g. cve:CVE-2024-1234)' },
            { prefix: 'ip:', desc: 'Lookup IP reputation (e.g. ip:1.2.3.4)' },
            { prefix: 'domain:', desc: 'Check domain reputation (e.g. domain:evil.com)' },
            { prefix: 'hash:', desc: 'Search file hash (e.g. hash:abc123...)' },
            { prefix: 'mitre:', desc: 'Lookup ATT&CK technique (e.g. mitre:T1566)' },
            { prefix: 'apt:', desc: 'Search threat actor (e.g. apt:Volt Typhoon)' }
        ];

        const matchingPrefixes = prefixes.filter(p => !lowerRaw.includes(':') && p.prefix.startsWith(lowerRaw.charAt(0)));
        if (matchingPrefixes.length > 0 && !lowerRaw.includes(':')) {
            const prefixLabel = DOM.create('div', { className: 'search-hint-label', textContent: 'SEARCH COMMANDS' });
            hints.appendChild(prefixLabel);
            matchingPrefixes.forEach(p => {
                hints.appendChild(DOM.create('div', { className: 'search-hint-item search-hint-cmd' }, [
                    DOM.create('code', { textContent: p.prefix }),
                    DOM.create('span', { className: 'search-hint-desc', textContent: p.desc })
                ]));
            });
        }

        hints.style.display = (hints.childNodes.length > 0) ? 'block' : 'none';
    }

    _getSearchResources(query) {
        const resources = [];
        const q = encodeURIComponent(query);

        // Detect query type and provide targeted resources
        if (/^cve[:\s-]/i.test(query)) {
            const cveId = query.replace(/^cve[:\s-]*/i, '').trim();
            const cveQ = encodeURIComponent(cveId);
            resources.push(
                { source: 'NVD', description: `Search NIST NVD for ${cveId}`, url: `https://nvd.nist.gov/vuln/search/results?query=${cveQ}` },
                { source: 'MITRE CVE', description: `Lookup ${cveId} on CVE.org`, url: `https://www.cve.org/CVERecord?id=${cveQ}` },
                { source: 'ExploitDB', description: `Search Exploit Database`, url: `https://www.exploit-db.com/search?cve=${cveQ}` }
            );
        } else if (/^ip[:\s]/i.test(query)) {
            const ip = query.replace(/^ip[:\s]*/i, '').trim();
            const ipQ = encodeURIComponent(ip);
            resources.push(
                { source: 'AbuseIPDB', description: `Check IP reputation`, url: `https://www.abuseipdb.com/check/${ipQ}` },
                { source: 'Shodan', description: `Search Shodan for ${ip}`, url: `https://www.shodan.io/host/${ipQ}` },
                { source: 'VirusTotal', description: `Analyze on VirusTotal`, url: `https://www.virustotal.com/gui/ip-address/${ipQ}` }
            );
        } else if (/^domain[:\s]/i.test(query)) {
            const domain = query.replace(/^domain[:\s]*/i, '').trim();
            const dQ = encodeURIComponent(domain);
            resources.push(
                { source: 'VirusTotal', description: `Domain analysis`, url: `https://www.virustotal.com/gui/domain/${dQ}` },
                { source: 'URLScan', description: `Scan domain`, url: `https://urlscan.io/search/#domain:${dQ}` },
                { source: 'Shodan', description: `Domain search`, url: `https://www.shodan.io/search?query=hostname:${dQ}` }
            );
        } else if (/^hash[:\s]/i.test(query)) {
            const hash = query.replace(/^hash[:\s]*/i, '').trim();
            const hQ = encodeURIComponent(hash);
            resources.push(
                { source: 'VirusTotal', description: `File hash analysis`, url: `https://www.virustotal.com/gui/search/${hQ}` },
                { source: 'MalwareBazaar', description: `Search malware samples`, url: `https://bazaar.abuse.ch/browse/tag/${hQ}/` }
            );
        } else if (/^mitre[:\s]/i.test(query)) {
            const tech = query.replace(/^mitre[:\s]*/i, '').trim();
            const validated = Sanitize.attackTechniqueId(tech);
            if (validated) {
                resources.push(
                    { source: 'MITRE ATT&CK', description: `View technique ${validated}`, url: `https://attack.mitre.org/techniques/${encodeURIComponent(validated)}/` }
                );
            } else {
                resources.push(
                    { source: 'MITRE ATT&CK', description: `Search ATT&CK`, url: `https://attack.mitre.org/techniques/enterprise/` }
                );
            }
        } else if (/^apt[:\s]/i.test(query)) {
            const actor = query.replace(/^apt[:\s]*/i, '').trim();
            const aQ = encodeURIComponent(actor);
            resources.push(
                { source: 'MITRE ATT&CK', description: `Search threat groups`, url: `https://attack.mitre.org/groups/` },
                { source: 'Malpedia', description: `Search threat actor`, url: `https://malpedia.caad.fkie.fraunhofer.de/search?q=${aQ}` }
            );
        } else {
            // General search
            resources.push(
                { source: 'MITRE ATT&CK', description: `Search ATT&CK knowledge base`, url: `https://attack.mitre.org/techniques/enterprise/` },
                { source: 'NIST NVD', description: `Search vulnerability database`, url: `https://nvd.nist.gov/vuln/search/results?query=${q}` },
                { source: 'VirusTotal', description: `Search VirusTotal`, url: `https://www.virustotal.com/gui/search/${q}` },
                { source: 'Shodan', description: `Internet-facing asset search`, url: `https://www.shodan.io/search?query=${q}` }
            );
        }

        return resources;
    }

    _executeSearchCommand(raw) {
        const resources = this._getSearchResources(raw.toLowerCase().trim());
        if (resources.length > 0) {
            // Open the first (most relevant) resource
            window.open(resources[0].url, '_blank', 'noopener,noreferrer');
            announce(`Opening ${resources[0].source} for: ${raw}`);
        }

        // Hide hints
        const hints = document.getElementById('search-hints');
        if (hints) hints.style.display = 'none';
    }

    handleScopeFilter() {
        this.filters.scope.clear();
        if (document.getElementById('scope-tactical')?.checked) {
            this.filters.scope.add('tactical');
        }
        if (document.getElementById('scope-strategic')?.checked) {
            this.filters.scope.add('strategic');
        }
        this.renderFeed();
    }

    handleAudienceFilter() {
        this.filters.audience.clear();
        if (document.getElementById('aud-technical')?.checked) {
            this.filters.audience.add('technical');
        }
        if (document.getElementById('aud-executive')?.checked) {
            this.filters.audience.add('executive');
        }
        if (document.getElementById('aud-analyst')?.checked) {
            this.filters.audience.add('analyst');
        }
        this.renderFeed();
    }

    handleCategoryFilter(changedCheckbox) {
        this.filters.category.clear();
        const allCheckbox = document.getElementById('cat-all');

        if (changedCheckbox && changedCheckbox.id === 'cat-all') {
            // User clicked "All" - check it and uncheck everything else
            if (allCheckbox) allCheckbox.checked = true;
            this.filters.category.add('all');
            DOM.qsa('[id^="cat-"]:not(#cat-all)').forEach(cb => { cb.checked = false; });
        } else {
            // User clicked a specific category - uncheck "All"
            if (allCheckbox) allCheckbox.checked = false;

            DOM.qsa('[id^="cat-"]:checked').forEach(cb => {
                if (cb.id !== 'cat-all') {
                    const category = cb.id.replace('cat-', '').toUpperCase();
                    this.filters.category.add(category);
                }
            });

            // If nothing selected, revert to "All"
            if (this.filters.category.size === 0) {
                this.filters.category.add('all');
                if (allCheckbox) allCheckbox.checked = true;
            }
        }
        this.renderFeed();
    }

    attachBulkActions() {
        // Use data-action attributes instead of text content matching
        DOM.qsa('.export-btn[data-action]').forEach(btn => {
            const action = btn.dataset.action;
            btn.addEventListener('click', () => {
                switch (action) {
                    case 'select-all':
                        this.selectedArticles.clear();
                        this.filterArticles().forEach(a => this.selectedArticles.add(a.id));
                        this.renderFeed();
                        break;
                    case 'clear':
                        this.selectedArticles.clear();
                        this.renderFeed();
                        break;
                    case 'export-csv':
                        this.exportCSV();
                        break;
                    case 'export-markdown':
                        this.exportMarkdown();
                        break;
                    case 'export-pdf':
                        this.exportPDF();
                        break;
                    case 'export-stix':
                        this.exportSTIX();
                        break;
                }
            });
        });
    }

    attachViewToggles() {
        const viewBtns = DOM.qsa('.view-toggle .view-btn');
        viewBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const view = btn.dataset.view;

                // Update active/aria-pressed state
                viewBtns.forEach(b => {
                    b.classList.remove('active');
                    b.setAttribute('aria-pressed', 'false');
                });
                btn.classList.add('active');
                btn.setAttribute('aria-pressed', 'true');

                this.currentView = view;
                switch (view) {
                    case 'list':
                        this.renderFeed();
                        break;
                    case 'map':
                        window.location.href = 'map.html';
                        break;
                    case 'graph':
                        this.renderGraphView();
                        break;
                }
            });
        });
    }

    attachHeaderButtons() {
        const analyticsBtn = document.getElementById('btn-analytics');
        if (analyticsBtn) {
            analyticsBtn.addEventListener('click', () => this.showAnalytics());
        }

        const addIntelBtn = document.getElementById('btn-add-intel');
        if (addIntelBtn) {
            addIntelBtn.addEventListener('click', () => this.showAddIntelForm());
        }
    }

    /* ============================================
       ANALYTICS DASHBOARD OVERLAY
    ============================================ */
    showAnalytics() {
        this.closeArticleDetail(); // Reuse same close mechanism

        const overlay = DOM.create('div', { className: 'detail-overlay', id: 'article-detail-overlay' });
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) this.closeArticleDetail();
        });

        const panel = DOM.create('div', { className: 'detail-panel analytics-panel' });

        const headerBar = DOM.create('div', { className: 'detail-header-bar' }, [
            DOM.create('span', { className: 'detail-header-label', textContent: 'ANALYTICS DASHBOARD' }),
            DOM.create('button', {
                type: 'button',
                className: 'detail-close-btn',
                textContent: 'CLOSE [ESC]',
                'aria-label': 'Close analytics',
                onClick: () => this.closeArticleDetail()
            })
        ]);
        panel.appendChild(headerBar);

        const content = DOM.create('div', { className: 'detail-content' });
        const articles = this.feedData.articles;

        // Summary stats row
        const statsRow = DOM.create('div', { className: 'analytics-stats-row' });
        const critCount = articles.filter(a => a.priority === 1).length;
        const highCount = articles.filter(a => a.priority === 2).length;
        const medCount = articles.filter(a => a.priority === 3).length;
        const uniqueSources = new Set(articles.map(a => a.source)).size;
        const uniqueCountries = this.feedData.metadata.geo_stats ? Object.keys(this.feedData.metadata.geo_stats.countries || {}).length : 0;

        const addStat = (label, value, color) => {
            statsRow.appendChild(DOM.create('div', { className: 'analytics-stat' }, [
                DOM.create('div', { className: 'analytics-stat-value', textContent: String(value), style: { color } }),
                DOM.create('div', { className: 'analytics-stat-label', textContent: label })
            ]));
        };
        addStat('Total Events', articles.length, '#e0e0e0');
        addStat('Critical', critCount, '#ff4444');
        addStat('High', highCount, '#ff9944');
        addStat('Medium', medCount, '#44aaff');
        addStat('Sources', uniqueSources, '#4fc3f7');
        addStat('Countries', uniqueCountries, '#44ff88');
        content.appendChild(statsRow);

        // Charts row
        const chartsRow = DOM.create('div', { className: 'analytics-charts-row' });

        // Category distribution
        const catSection = DOM.create('div', { className: 'analytics-chart-section' });
        catSection.appendChild(DOM.create('h3', { className: 'detail-section-title', textContent: 'CATEGORY DISTRIBUTION' }));
        const catCanvas = DOM.create('canvas', { className: 'analytics-chart-canvas', width: '350', height: '200' });
        catSection.appendChild(catCanvas);
        chartsRow.appendChild(catSection);

        // Source breakdown
        const srcSection = DOM.create('div', { className: 'analytics-chart-section' });
        srcSection.appendChild(DOM.create('h3', { className: 'detail-section-title', textContent: 'SOURCE BREAKDOWN' }));
        const srcCanvas = DOM.create('canvas', { className: 'analytics-chart-canvas', width: '350', height: '200' });
        srcSection.appendChild(srcCanvas);
        chartsRow.appendChild(srcSection);

        content.appendChild(chartsRow);

        // Priority breakdown bar list
        const priSection = DOM.create('div', { className: 'detail-section' });
        priSection.appendChild(DOM.create('h3', { className: 'detail-section-title', textContent: 'PRIORITY BREAKDOWN' }));
        const priList = DOM.create('div', { className: 'analytics-bar-list' });

        const priData = [
            { label: 'Critical (P1)', count: critCount, color: '#ff4444' },
            { label: 'High (P2)', count: highCount, color: '#ff9944' },
            { label: 'Medium (P3)', count: medCount, color: '#44aaff' }
        ];
        const maxPri = Math.max(...priData.map(p => p.count), 1);
        priData.forEach(p => {
            const pct = (p.count / maxPri) * 100;
            priList.appendChild(DOM.create('div', { className: 'analytics-bar-item' }, [
                DOM.create('span', { className: 'analytics-bar-label', textContent: p.label }),
                DOM.create('div', { className: 'analytics-bar-track' }, [
                    DOM.create('div', { className: 'analytics-bar-fill', style: { width: `${pct}%`, background: p.color } })
                ]),
                DOM.create('span', { className: 'analytics-bar-value', textContent: String(p.count) })
            ]));
        });
        priSection.appendChild(priList);
        content.appendChild(priSection);

        // Top ATT&CK techniques
        const techSection = DOM.create('div', { className: 'detail-section' });
        techSection.appendChild(DOM.create('h3', { className: 'detail-section-title', textContent: 'TOP ATT&CK TECHNIQUES' }));
        const techs = {};
        articles.forEach(a => {
            if (a.attack_techniques) {
                a.attack_techniques.forEach(t => {
                    const v = Sanitize.attackTechniqueId(t);
                    if (v) techs[v] = (techs[v] || 0) + 1;
                });
            }
        });
        const topTechs = Object.entries(techs).sort((a, b) => b[1] - a[1]).slice(0, 8);
        const maxTech = topTechs.length > 0 ? topTechs[0][1] : 1;
        const techList = DOM.create('div', { className: 'analytics-bar-list' });
        topTechs.forEach(([tech, count]) => {
            const pct = (count / maxTech) * 100;
            techList.appendChild(DOM.create('div', { className: 'analytics-bar-item' }, [
                DOM.create('span', { className: 'analytics-bar-label', textContent: tech, style: { color: '#00ff41' } }),
                DOM.create('div', { className: 'analytics-bar-track' }, [
                    DOM.create('div', { className: 'analytics-bar-fill', style: { width: `${pct}%`, background: '#2c3e50' } })
                ]),
                DOM.create('span', { className: 'analytics-bar-value', textContent: String(count) })
            ]));
        });
        techSection.appendChild(techList);
        content.appendChild(techSection);

        panel.appendChild(content);
        overlay.appendChild(panel);
        document.body.appendChild(overlay);

        // Draw charts after DOM append
        this._drawBarChart(catCanvas, this._getCategoryData(articles));
        this._drawBarChart(srcCanvas, this._getSourceData(articles));

        const closeBtn = DOM.qs('.detail-close-btn', panel);
        if (closeBtn) closeBtn.focus();

        this._detailEscHandler = (e) => {
            if (e.key === 'Escape') this.closeArticleDetail();
        };
        document.addEventListener('keydown', this._detailEscHandler);
        announce('Analytics dashboard opened.');
    }

    _getCategoryData(articles) {
        const cats = {};
        articles.forEach(a => { cats[a.category] = (cats[a.category] || 0) + 1; });
        return Object.entries(cats).sort((a, b) => b[1] - a[1]);
    }

    _getSourceData(articles) {
        const sources = {};
        articles.forEach(a => {
            const src = a.source || 'Unknown';
            sources[src] = (sources[src] || 0) + 1;
        });
        return Object.entries(sources).sort((a, b) => b[1] - a[1]).slice(0, 8);
    }

    _drawBarChart(canvas, data) {
        if (!canvas || data.length === 0) return;
        const ctx = canvas.getContext('2d');
        const w = canvas.width;
        const h = canvas.height;
        const padding = { top: 10, right: 10, bottom: 40, left: 10 };
        const chartW = w - padding.left - padding.right;
        const chartH = h - padding.top - padding.bottom;
        const barWidth = Math.min(40, chartW / data.length - 8);
        const maxVal = Math.max(...data.map(d => d[1]), 1);

        ctx.fillStyle = '#0d0d0d';
        ctx.fillRect(0, 0, w, h);

        const colors = ['#9a4c30', '#ff4444', '#ff9944', '#4fc3f7', '#44ff88', '#8e44ad', '#e67e22', '#16a085'];
        data.forEach(([label, value], i) => {
            const barH = (value / maxVal) * chartH;
            const x = padding.left + (chartW / data.length) * i + (chartW / data.length - barWidth) / 2;
            const y = padding.top + chartH - barH;

            ctx.fillStyle = colors[i % colors.length];
            ctx.fillRect(x, y, barWidth, barH);

            // Value label
            ctx.fillStyle = '#e0e0e0';
            ctx.font = '10px Courier New';
            ctx.textAlign = 'center';
            ctx.fillText(String(value), x + barWidth / 2, y - 4);

            // X-axis label
            ctx.fillStyle = '#666';
            ctx.font = '9px Courier New';
            ctx.save();
            ctx.translate(x + barWidth / 2, h - 4);
            ctx.rotate(-0.5);
            ctx.fillText(label.substring(0, 10), 0, 0);
            ctx.restore();
        });
    }

    /* ============================================
       ADD INTEL FORM
    ============================================ */
    showAddIntelForm() {
        this.closeArticleDetail();

        const overlay = DOM.create('div', { className: 'detail-overlay', id: 'article-detail-overlay' });
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) this.closeArticleDetail();
        });

        const panel = DOM.create('div', { className: 'detail-panel' });

        const headerBar = DOM.create('div', { className: 'detail-header-bar' }, [
            DOM.create('span', { className: 'detail-header-label', textContent: 'SUBMIT INTELLIGENCE REPORT' }),
            DOM.create('button', {
                type: 'button',
                className: 'detail-close-btn',
                textContent: 'CLOSE [ESC]',
                'aria-label': 'Close form',
                onClick: () => this.closeArticleDetail()
            })
        ]);
        panel.appendChild(headerBar);

        const content = DOM.create('div', { className: 'detail-content' });

        const form = DOM.create('form', {
            className: 'add-intel-form',
            onSubmit: (e) => {
                e.preventDefault();
                this._handleIntelSubmit(form);
            }
        });

        const addField = (labelText, inputId, type, placeholder, required) => {
            const group = DOM.create('div', { className: 'form-group' });
            group.appendChild(DOM.create('label', {
                className: 'form-label',
                for: inputId,
                textContent: labelText
            }));
            if (type === 'textarea') {
                group.appendChild(DOM.create('textarea', {
                    className: 'form-input form-textarea',
                    id: inputId,
                    name: inputId,
                    placeholder: placeholder,
                    required: required ? 'required' : undefined,
                    rows: '4'
                }));
            } else if (type === 'select') {
                const select = DOM.create('select', {
                    className: 'form-input',
                    id: inputId,
                    name: inputId
                });
                placeholder.forEach(opt => {
                    select.appendChild(DOM.create('option', { value: opt.value, textContent: opt.label }));
                });
                group.appendChild(select);
            } else {
                group.appendChild(DOM.create('input', {
                    className: 'form-input',
                    type: type,
                    id: inputId,
                    name: inputId,
                    placeholder: placeholder,
                    required: required ? 'required' : undefined,
                    maxlength: type === 'url' ? '2048' : '512'
                }));
            }
            return group;
        };

        form.appendChild(addField('Title *', 'intel-title', 'text', 'Intelligence report title...', true));
        form.appendChild(addField('Source URL', 'intel-url', 'url', 'https://...', false));
        form.appendChild(addField('Source Name *', 'intel-source', 'text', 'e.g. CISA, The Hacker News...', true));
        form.appendChild(addField('Category *', 'intel-category', 'select', [
            { value: 'APT', label: 'APT' },
            { value: 'VULNERABILITY', label: 'Vulnerability' },
            { value: 'MALWARE', label: 'Malware' },
            { value: 'BREACH', label: 'Breach' },
            { value: 'RESEARCH', label: 'Research' },
            { value: 'ADVISORY', label: 'Advisory' },
            { value: 'PHISHING', label: 'Phishing' },
            { value: 'SUPPLY_CHAIN', label: 'Supply Chain' },
            { value: 'NETWORK', label: 'Network' }
        ], true));
        form.appendChild(addField('Priority *', 'intel-priority', 'select', [
            { value: '1', label: 'P1 - Critical' },
            { value: '2', label: 'P2 - High' },
            { value: '3', label: 'P3 - Medium' }
        ], true));
        form.appendChild(addField('Summary *', 'intel-summary', 'textarea', 'Describe the threat intelligence...', true));
        form.appendChild(addField('ATT&CK Techniques', 'intel-techniques', 'text', 'e.g. T1566, T1059, T1078', false));
        form.appendChild(addField('IOCs (CVEs, IPs, Domains)', 'intel-iocs', 'textarea', 'One per line...', false));
        form.appendChild(addField('Country / Region', 'intel-country', 'text', 'e.g. United States, China...', false));

        const submitBtn = DOM.create('button', {
            type: 'submit',
            className: 'detail-ext-link',
            textContent: 'SUBMIT INTELLIGENCE',
            style: { border: 'none', cursor: 'pointer', fontFamily: 'inherit', display: 'block', width: '100%', textAlign: 'center', marginTop: '20px' }
        });
        form.appendChild(submitBtn);

        content.appendChild(form);
        panel.appendChild(content);
        overlay.appendChild(panel);
        document.body.appendChild(overlay);

        const closeBtn = DOM.qs('.detail-close-btn', panel);
        if (closeBtn) closeBtn.focus();

        this._detailEscHandler = (e) => {
            if (e.key === 'Escape') this.closeArticleDetail();
        };
        document.addEventListener('keydown', this._detailEscHandler);
        announce('Intel submission form opened.');
    }

    _handleIntelSubmit(form) {
        const data = new FormData(form);
        const title = Sanitize.searchQuery(data.get('intel-title') || '');
        const url = Sanitize.url(data.get('intel-url') || '');
        const source = Sanitize.searchQuery(data.get('intel-source') || '');
        const category = (data.get('intel-category') || 'APT').toUpperCase();
        const priority = Sanitize.integer(data.get('intel-priority'), 1, 3);
        const summary = Sanitize.searchQuery(data.get('intel-summary') || '');
        const techniques = (data.get('intel-techniques') || '').split(',').map(t => t.trim()).filter(t => Sanitize.attackTechniqueId(t));
        const country = Sanitize.countryName(data.get('intel-country') || '');

        if (!title || !source || !summary) {
            announce('Please fill in all required fields.');
            return;
        }

        const newArticle = {
            id: `manual-${this.generateUUID()}`,
            title: title,
            link: url,
            summary: summary,
            published: new Date().toISOString(),
            source: source,
            category: category,
            feed_name: 'Manual Submission',
            icon: '📝',
            color: '#9a4c30',
            priority: priority,
            scope: 'tactical',
            audience: 'analyst',
            attack_techniques: techniques
        };

        if (country) {
            newArticle.geo = { country: country };
        }

        // Parse IOCs
        const iocText = data.get('intel-iocs') || '';
        if (iocText.trim()) {
            const lines = iocText.split('\n').map(l => l.trim()).filter(Boolean);
            const iocs = { cves: [], ips: [], domains: [], hashes: [] };
            lines.forEach(line => {
                if (/^CVE-\d{4}-\d+$/i.test(line)) iocs.cves.push(line.toUpperCase());
                else if (/^\d{1,3}(\.\d{1,3}){3}$/.test(line)) iocs.ips.push(line);
                else if (/^[a-f0-9]{32,64}$/i.test(line)) iocs.hashes.push(line);
                else if (/^[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}$/.test(line)) iocs.domains.push(line);
            });
            if (iocs.cves.length || iocs.ips.length || iocs.domains.length || iocs.hashes.length) {
                newArticle.iocs = iocs;
            }
        }

        // Add to feed data
        this.feedData.articles.unshift(newArticle);
        this.feedData.metadata.total_articles = this.feedData.articles.length;

        // Close form, refresh display
        this.closeArticleDetail();
        this.updateMetrics();
        this.updateFilterCounts();
        this.updateTrending();
        this.updateSectorStats();
        this.updateTTPsList();
        this.renderFeed();

        announce(`Intelligence report "${title}" added successfully.`);
    }

    updateSelectionInfo() {
        const info = DOM.qs('.selection-info');
        if (info) {
            const total = this.filterArticles().length;
            DOM.clear(info);
            info.appendChild(DOM.create('strong', { textContent: `${this.selectedArticles.size} selected` }));
            info.appendChild(document.createTextNode(` of ${total} events`));
        }
    }

    /* ============================================
       ARTICLE DETAIL VIEW
    ============================================ */
    showArticleDetail(article) {
        // Remove existing overlay if any
        this.closeArticleDetail();

        const safeLink = Sanitize.url(article.link);
        const overlay = DOM.create('div', { className: 'detail-overlay', id: 'article-detail-overlay' });

        // Close on backdrop click
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) this.closeArticleDetail();
        });

        const panel = DOM.create('div', { className: 'detail-panel' });

        // Header bar
        const headerBar = DOM.create('div', { className: 'detail-header-bar' }, [
            DOM.create('span', { className: 'detail-header-label', textContent: 'INTELLIGENCE REPORT' }),
            DOM.create('button', {
                type: 'button',
                className: 'detail-close-btn',
                textContent: 'CLOSE [ESC]',
                'aria-label': 'Close detail view',
                onClick: () => this.closeArticleDetail()
            })
        ]);
        panel.appendChild(headerBar);

        // Scrollable content area
        const content = DOM.create('div', { className: 'detail-content' });

        // Title
        const cleanTitle = this.cleanArticleTitle(article.title, article.source);
        content.appendChild(DOM.create('h2', { className: 'detail-title', textContent: cleanTitle }));

        // Tags row
        const tagsRow = DOM.create('div', { className: 'detail-tags' });
        tagsRow.appendChild(DOM.create('span', {
            className: `tag tag-${this.getCategoryClass(article.category)}`,
            textContent: article.category
        }));
        tagsRow.appendChild(DOM.create('span', {
            className: `tag tag-priority priority-${Sanitize.integer(article.priority, 1, 5)}`,
            textContent: article.priority === 1 ? 'CRITICAL' : article.priority === 2 ? 'HIGH' : 'MEDIUM'
        }));
        tagsRow.appendChild(DOM.create('span', { className: 'tag tag-source', textContent: article.source || 'Unknown' }));
        if (article.scope) {
            tagsRow.appendChild(DOM.create('span', { className: 'tag tag-source', textContent: article.scope.toUpperCase() }));
        }
        content.appendChild(tagsRow);

        // Metadata grid
        const metaGrid = DOM.create('div', { className: 'detail-meta-grid' });
        const addMeta = (label, value) => {
            metaGrid.appendChild(DOM.create('div', { className: 'detail-meta-item' }, [
                DOM.create('span', { className: 'detail-meta-label', textContent: label }),
                DOM.create('span', { className: 'detail-meta-value', textContent: value })
            ]));
        };
        addMeta('Published:', this.formatDate(article.published));
        addMeta('Source:', article.source || 'Unknown');
        addMeta('Feed:', article.feed_name || 'N/A');
        if (article.geo && article.geo.country) {
            addMeta('Location:', Sanitize.countryName(article.geo.country));
        }
        if (article.sector) {
            addMeta('Sector:', article.sector);
        }
        addMeta('Audience:', article.audience ? article.audience.charAt(0).toUpperCase() + article.audience.slice(1) : 'N/A');
        content.appendChild(metaGrid);

        // Full summary
        const summarySection = DOM.create('div', { className: 'detail-section' });
        summarySection.appendChild(DOM.create('h3', { className: 'detail-section-title', textContent: 'SUMMARY' }));
        summarySection.appendChild(DOM.create('p', {
            className: 'detail-summary-text',
            textContent: article.summary || 'No summary available.'
        }));
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

            const attackSection = DOM.create('div', { className: 'detail-section' });
            attackSection.appendChild(DOM.create('h3', { className: 'detail-section-title', textContent: 'MITRE ATT&CK TECHNIQUES' }));

            const techList = DOM.create('div', { className: 'detail-technique-list' });
            article.attack_techniques.forEach(tech => {
                const validated = Sanitize.attackTechniqueId(tech);
                if (!validated) return;

                const techItem = DOM.create('div', { className: 'detail-technique-item' }, [
                    DOM.create('span', { className: 'detail-technique-id', textContent: validated }),
                    DOM.create('span', { className: 'detail-technique-name', textContent: ttpNames[validated] || 'Unknown Technique' }),
                    DOM.create('a', {
                        className: 'detail-technique-link',
                        href: `https://attack.mitre.org/techniques/${encodeURIComponent(validated)}/`,
                        target: '_blank',
                        rel: 'noopener noreferrer',
                        textContent: 'View on MITRE →'
                    })
                ]);
                techList.appendChild(techItem);
            });
            attackSection.appendChild(techList);
            content.appendChild(attackSection);
        }

        // IOCs section
        if (article.iocs) {
            const iocSection = DOM.create('div', { className: 'detail-section' });
            iocSection.appendChild(DOM.create('h3', { className: 'detail-section-title', textContent: 'INDICATORS OF COMPROMISE' }));

            const iocGrid = DOM.create('div', { className: 'detail-ioc-grid' });
            if (article.iocs.cves && article.iocs.cves.length > 0) {
                article.iocs.cves.forEach(cve => {
                    iocGrid.appendChild(DOM.create('div', { className: 'detail-ioc-item' }, [
                        DOM.create('span', { className: 'detail-ioc-type', textContent: 'CVE' }),
                        DOM.create('span', { className: 'detail-ioc-value', textContent: cve })
                    ]));
                });
            }
            if (article.iocs.ips && article.iocs.ips.length > 0) {
                article.iocs.ips.forEach(ip => {
                    iocGrid.appendChild(DOM.create('div', { className: 'detail-ioc-item' }, [
                        DOM.create('span', { className: 'detail-ioc-type', textContent: 'IP' }),
                        DOM.create('span', { className: 'detail-ioc-value', textContent: ip })
                    ]));
                });
            }
            if (article.iocs.domains && article.iocs.domains.length > 0) {
                article.iocs.domains.forEach(domain => {
                    iocGrid.appendChild(DOM.create('div', { className: 'detail-ioc-item' }, [
                        DOM.create('span', { className: 'detail-ioc-type', textContent: 'Domain' }),
                        DOM.create('span', { className: 'detail-ioc-value', textContent: domain })
                    ]));
                });
            }
            if (article.iocs.hashes && article.iocs.hashes.length > 0) {
                article.iocs.hashes.forEach(hash => {
                    iocGrid.appendChild(DOM.create('div', { className: 'detail-ioc-item' }, [
                        DOM.create('span', { className: 'detail-ioc-type', textContent: 'Hash' }),
                        DOM.create('span', { className: 'detail-ioc-value', textContent: hash })
                    ]));
                });
            }
            iocSection.appendChild(iocGrid);
            content.appendChild(iocSection);
        }

        // Threat Intel enrichment (if available)
        if (article.threat_intel && Object.keys(article.threat_intel).length > 0) {
            const enrichSection = DOM.create('div', { className: 'detail-section' });
            enrichSection.appendChild(DOM.create('h3', { className: 'detail-section-title', textContent: 'THREAT INTELLIGENCE ENRICHMENT' }));

            Object.entries(article.threat_intel).forEach(([ioc, intel]) => {
                const enrichItem = DOM.create('div', { className: 'detail-enrich-item' });
                enrichItem.appendChild(DOM.create('span', { className: 'detail-ioc-value', textContent: ioc }));

                if (intel.sources) {
                    enrichItem.appendChild(DOM.create('span', {
                        className: 'detail-enrich-sources',
                        textContent: `Sources: ${intel.sources.join(', ')}`
                    }));
                }
                if (intel.malicious || (intel.vt_malicious && intel.vt_malicious > 0)) {
                    enrichItem.appendChild(DOM.create('span', {
                        className: 'detail-enrich-malicious',
                        textContent: `Malicious (VT: ${intel.vt_malicious || 'N/A'} detections)`
                    }));
                }
                enrichSection.appendChild(enrichItem);
            });
            content.appendChild(enrichSection);
        }

        // Related articles
        const related = this.findRelatedArticles(article);
        if (related.length > 0) {
            const relatedSection = DOM.create('div', { className: 'detail-section' });
            relatedSection.appendChild(DOM.create('h3', { className: 'detail-section-title', textContent: 'RELATED INTELLIGENCE' }));

            related.forEach(rel => {
                const relItem = DOM.create('div', {
                    className: 'detail-related-item',
                    onClick: () => this.showArticleDetail(rel)
                });
                relItem.appendChild(DOM.create('span', {
                    className: `tag tag-${this.getCategoryClass(rel.category)}`,
                    textContent: rel.category,
                    style: { fontSize: '0.7em' }
                }));
                relItem.appendChild(DOM.create('span', {
                    className: 'detail-related-title',
                    textContent: this.cleanArticleTitle(rel.title, rel.source)
                }));
                relItem.appendChild(DOM.create('span', {
                    className: 'detail-related-meta',
                    textContent: this.formatDate(rel.published)
                }));
                relatedSection.appendChild(relItem);
            });
            content.appendChild(relatedSection);
        }

        // External link footer
        if (safeLink !== '#') {
            const extSection = DOM.create('div', { className: 'detail-section detail-ext-section' });
            extSection.appendChild(DOM.create('a', {
                className: 'detail-ext-link',
                href: safeLink,
                target: '_blank',
                rel: 'noopener noreferrer',
                textContent: 'View Original Source →'
            }));
            content.appendChild(extSection);
        }

        panel.appendChild(content);
        overlay.appendChild(panel);
        document.body.appendChild(overlay);

        // Focus trap: focus the close button
        const closeBtn = DOM.qs('.detail-close-btn', panel);
        if (closeBtn) closeBtn.focus();

        // ESC to close
        this._detailEscHandler = (e) => {
            if (e.key === 'Escape') this.closeArticleDetail();
        };
        document.addEventListener('keydown', this._detailEscHandler);

        announce(`Viewing intelligence report: ${cleanTitle}`);
    }

    closeArticleDetail() {
        const overlay = document.getElementById('article-detail-overlay');
        if (overlay) overlay.remove();
        if (this._detailEscHandler) {
            document.removeEventListener('keydown', this._detailEscHandler);
            this._detailEscHandler = null;
        }
    }

    findRelatedArticles(article) {
        if (!this.feedData || !this.feedData.articles) return [];
        return this.feedData.articles.filter(a => {
            if (a.id === article.id) return false;
            // Same category
            if (a.category === article.category) return true;
            // Shared ATT&CK techniques
            if (article.attack_techniques && a.attack_techniques) {
                const shared = article.attack_techniques.filter(t => a.attack_techniques.includes(t));
                if (shared.length > 0) return true;
            }
            // Same geo
            if (article.geo && a.geo && article.geo.country && a.geo.country === article.geo.country) return true;
            return false;
        }).slice(0, 5);
    }

    handleUrlArticleParam() {
        const params = new URLSearchParams(window.location.search);
        const articleId = params.get('article');
        if (articleId && this.feedData) {
            const article = this.feedData.articles.find(a => a.id === articleId);
            if (article) {
                this.showArticleDetail(article);
            }
        }
    }

    /* ============================================
       EXPORT FUNCTIONS
    ============================================ */
    exportCSV() {
        const articles = this.getSelectedArticles();
        if (articles.length === 0) {
            announce('No articles selected for export.');
            return;
        }

        const headers = ['Title', 'Category', 'Priority', 'Source', 'Published', 'Link'];
        const rows = articles.map(a => [
            Sanitize.csvField(a.title),
            Sanitize.csvField(a.category),
            Sanitize.csvField(`P${a.priority}`),
            Sanitize.csvField(a.source || 'Unknown'),
            Sanitize.csvField(a.published),
            Sanitize.csvField(a.link)
        ]);

        const csv = [headers.map(h => Sanitize.csvField(h)), ...rows].map(row => row.join(',')).join('\n');
        this.downloadFile('daily-brief-export.csv', csv, 'text/csv;charset=utf-8');
        announce(`Exported ${articles.length} articles as CSV.`);
    }

    exportMarkdown() {
        const articles = this.getSelectedArticles();
        if (articles.length === 0) {
            announce('No articles selected for export.');
            return;
        }

        let md = `# The Daily Brief - Export\n\n`;
        md += `Generated: ${new Date().toISOString()}\n`;
        md += `Total Articles: ${articles.length}\n\n---\n\n`;

        articles.forEach(article => {
            md += `## ${article.title}\n\n`;
            md += `**Category:** ${article.category} | **Priority:** P${article.priority}\n\n`;
            md += `**Source:** ${article.source || 'Unknown'}\n\n`;
            md += `**Published:** ${article.published}\n\n`;
            if (article.summary) md += `${article.summary}\n\n`;
            md += `[Read Full Article](${Sanitize.url(article.link)})\n\n---\n\n`;
        });

        this.downloadFile('daily-brief-export.md', md, 'text/markdown;charset=utf-8');
        announce(`Exported ${articles.length} articles as Markdown.`);
    }

    exportPDF() {
        const articles = this.getSelectedArticles();
        if (articles.length === 0) {
            announce('No articles selected for export.');
            return;
        }

        // Build print document safely using DOM APIs
        const printWindow = window.open('', '_blank');
        if (!printWindow) {
            announce('Popup blocked. Please allow popups for PDF export.');
            return;
        }

        const doc = printWindow.document;
        doc.open();
        doc.close();

        // Set title
        doc.title = 'Daily Brief Export';

        // Build styles
        const style = doc.createElement('style');
        style.textContent = `
            body { font-family: monospace; max-width: 800px; margin: 0 auto; padding: 20px; }
            .article { margin-bottom: 20px; border-bottom: 1px solid #ccc; padding-bottom: 15px; }
            .article h3 { margin: 0 0 5px; }
            .article-meta { color: #666; margin: 0 0 5px; }
            .article-summary { margin: 0; }
        `;
        doc.head.appendChild(style);

        // Build header
        const h1 = doc.createElement('h1');
        h1.textContent = 'The Daily Brief - Threat Intelligence Export';
        doc.body.appendChild(h1);

        const meta = doc.createElement('p');
        meta.textContent = `Generated: ${new Date().toISOString()} | Articles: ${articles.length}`;
        doc.body.appendChild(meta);

        doc.body.appendChild(doc.createElement('hr'));

        // Build articles safely
        articles.forEach(a => {
            const div = doc.createElement('div');
            div.className = 'article';

            const title = doc.createElement('h3');
            title.textContent = a.title;
            div.appendChild(title);

            const info = doc.createElement('p');
            info.className = 'article-meta';
            info.textContent = `${a.category} | P${a.priority} | ${a.source || 'Unknown'} | ${a.published}`;
            div.appendChild(info);

            if (a.summary) {
                const summary = doc.createElement('p');
                summary.className = 'article-summary';
                summary.textContent = a.summary;
                div.appendChild(summary);
            }

            doc.body.appendChild(div);
        });

        printWindow.print();
        announce(`PDF export generated for ${articles.length} articles.`);
    }

    exportSTIX() {
        const articles = this.getSelectedArticles();
        if (articles.length === 0) {
            announce('No articles selected for export.');
            return;
        }

        const bundle = {
            type: 'bundle',
            id: `bundle--${this.generateUUID()}`,
            objects: articles.map(a => ({
                type: 'indicator',
                spec_version: '2.1',
                id: `indicator--${this.generateUUID()}`,
                created: a.published,
                modified: a.published,
                name: a.title,
                description: a.summary || a.title,
                pattern: `[url:value = '${Sanitize.url(a.link)}']`,
                pattern_type: 'stix',
                valid_from: a.published,
                labels: [a.category.toLowerCase()]
            }))
        };

        this.downloadFile('daily-brief-export.json', JSON.stringify(bundle, null, 2), 'application/json');
        announce(`Exported ${articles.length} articles as STIX bundle.`);
    }

    getSelectedArticles() {
        if (this.selectedArticles.size === 0) {
            return this.filterArticles();
        }
        return this.feedData.articles.filter(a => this.selectedArticles.has(a.id));
    }

    downloadFile(filename, content, mimeType) {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    /* ============================================
       UTILITIES
    ============================================ */
    animateCounter(metricKey, target) {
        const element = this._metricEls[metricKey];
        if (!element || isNaN(target)) {
            if (element) element.textContent = target;
            return;
        }

        let current = 0;
        const duration = 800;
        const increment = target / (duration / 16);

        const timer = setInterval(() => {
            current += increment;
            if (current >= target) {
                element.textContent = target;
                clearInterval(timer);
            } else {
                element.textContent = Math.floor(current);
            }
        }, 16);
    }

    truncate(text, length) {
        if (!text) return '';
        return text.length > length ? text.substring(0, length) + '...' : text;
    }

    formatDate(dateStr) {
        if (!dateStr) return 'Unknown';
        const date = new Date(dateStr);
        if (isNaN(date.getTime())) return dateStr;

        const now = new Date();
        const diff = now - date;
        const hours = Math.floor(diff / (1000 * 60 * 60));

        if (hours < 0) return 'Just now';
        if (hours < 1) return 'Just now';
        if (hours < 24) return `${hours}h ago`;
        const days = Math.floor(hours / 24);
        if (days < 7) return `${days}d ago`;

        return date.toLocaleDateString();
    }

    generateUUID() {
        // Use crypto API when available for better randomness
        if (typeof crypto !== 'undefined' && crypto.randomUUID) {
            return crypto.randomUUID();
        }
        // Fallback to crypto.getRandomValues
        if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
            const bytes = new Uint8Array(16);
            crypto.getRandomValues(bytes);
            bytes[6] = (bytes[6] & 0x0f) | 0x40;
            bytes[8] = (bytes[8] & 0x3f) | 0x80;
            const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
            return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
        }
        // Last resort fallback
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
            const r = Math.random() * 16 | 0;
            const v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    const dashboard = new FeedDashboard();
    dashboard.init();
});
