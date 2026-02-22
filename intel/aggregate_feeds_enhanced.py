#!/usr/bin/env python3
"""
The Daily Brief - Enhanced Feed Aggregator
Features: DEFCON calculation, geocoding, API enrichment, threat mapping

Usage:
    python aggregate_feeds_enhanced.py                  # Run from project dir
    python aggregate_feeds_enhanced.py --project-dir /path/to/thedailybrief
"""

import json
import hashlib
import feedparser
import requests
import re
import sys
import time
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
from functools import lru_cache

# API integration imports (optional)
try:
    from OTXv2 import OTXv2
    OTX_AVAILABLE = True
except ImportError:
    OTX_AVAILABLE = False

try:
    import vt
    VT_AVAILABLE = True
except ImportError:
    VT_AVAILABLE = False

# Geocoding imports (optional)
try:
    from geopy.geocoders import Nominatim
    from geopy.exc import GeocoderTimedOut, GeocoderServiceError
    GEOPY_AVAILABLE = True
except ImportError:
    GEOPY_AVAILABLE = False


class ThreatEnrichment:
    """Handle API-based threat intelligence enrichment"""

    def __init__(self, api_config_path: Path, cache_dir: Path):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.api_config = {}
        self.otx_client = None
        self.vt_client = None

        # Load API configuration if file exists
        if api_config_path.exists():
            try:
                with open(api_config_path, encoding='utf-8') as f:
                    self.api_config = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                print(f"  Warning: Could not load API config: {e}")

        # Initialize API clients
        if OTX_AVAILABLE and self.api_config.get('alienvault_otx', {}).get('enabled'):
            api_key = self.api_config['alienvault_otx'].get('api_key', '')
            if api_key and api_key != 'YOUR_OTX_API_KEY':
                try:
                    self.otx_client = OTXv2(api_key)
                    print("  OTX client initialized")
                except Exception as e:
                    print(f"  Warning: OTX init failed: {e}")

        if VT_AVAILABLE and self.api_config.get('virustotal', {}).get('enabled'):
            api_key = self.api_config['virustotal'].get('api_key', '')
            if api_key and api_key != 'YOUR_VIRUSTOTAL_API_KEY':
                try:
                    self.vt_client = vt.Client(api_key)
                    print("  VirusTotal client initialized")
                except Exception as e:
                    print(f"  Warning: VT init failed: {e}")

    def enrich_article(self, article: Dict) -> Dict:
        """Enrich article with threat intelligence data"""
        iocs = self.extract_iocs(article)

        if not iocs or not any(iocs.values()):
            return article

        article['iocs'] = iocs
        article['threat_intel'] = {}

        for ip in iocs.get('ips', [])[:5]:
            intel = self.enrich_ip(ip)
            if intel:
                article['threat_intel'][ip] = intel

        for domain in iocs.get('domains', [])[:5]:
            intel = self.enrich_domain(domain)
            if intel:
                article['threat_intel'][domain] = intel

        for hash_val in iocs.get('hashes', [])[:3]:
            intel = self.enrich_hash(hash_val)
            if intel:
                article['threat_intel'][hash_val] = intel

        return article

    def extract_iocs(self, article: Dict) -> Dict:
        """Extract Indicators of Compromise from article text"""
        text = f"{article.get('title', '')} {article.get('summary', '')}"

        iocs = {
            'ips': [],
            'domains': [],
            'hashes': [],
            'cves': [],
            'urls': []
        }

        # IP addresses (IPv4)
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        iocs['ips'] = list(set(re.findall(ip_pattern, text)))
        iocs['ips'] = [ip for ip in iocs['ips'] if self.is_valid_ip(ip)]

        # Domain names (exclude common benign domains)
        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        benign_domains = {
            'news.google.com', 'google.com', 'www.google.com', 'youtube.com',
            'twitter.com', 'x.com', 'facebook.com', 'linkedin.com', 'github.com',
            'reddit.com', 'wikipedia.org', 'microsoft.com', 'apple.com',
            'amazon.com', 'cloudflare.com', 'bleepingcomputer.com',
            'www.bleepingcomputer.com', 'thehackernews.com', 'securityweek.com',
            'www.securityweek.com', 'darkreading.com', 'www.darkreading.com',
            'infosecurity-magazine.com', 'cyberscoop.com', 'therecord.media',
            'krebsonsecurity.com', 'socradar.io', 'cisa.gov', 'www.cisa.gov',
            'nist.gov', 'mitre.org', 'attack.mitre.org', 'nvd.nist.gov',
            'sentinelone.com', 'www.sentinelone.com',
            'unit42.paloaltonetworks.com', 'paloaltonetworks.com',
            'isc.sans.edu', 'sans.edu', 'sans.org',
            'ncsc.gov.uk', 'www.ncsc.gov.uk',
            'cert.europa.eu', 'cyber.gov.au', 'www.cyber.gov.au',
            'msrc.microsoft.com', 'googleprojectzero.blogspot.com',
            'abuse.ch', 'urlhaus-api.abuse.ch', 'threatfox-api.abuse.ch',
            'threatfox.abuse.ch', 'mb-api.abuse.ch', 'bazaar.abuse.ch',
            'urlhaus.abuse.ch', 'feedburner.com', 'feeds.feedburner.com',
            'talosintelligence.com', 'blog.talosintelligence.com',
            'therecord.media', 'cyberscoop.com'
        }
        raw_domains = set(re.findall(domain_pattern, text.lower()))
        iocs['domains'] = [d for d in raw_domains if d not in benign_domains and '.' in d]

        # File hashes (MD5, SHA1, SHA256)
        hash_patterns = [
            r'\b[a-fA-F0-9]{32}\b',
            r'\b[a-fA-F0-9]{40}\b',
            r'\b[a-fA-F0-9]{64}\b',
        ]
        for pattern in hash_patterns:
            iocs['hashes'].extend(re.findall(pattern, text))
        iocs['hashes'] = list(set(iocs['hashes']))

        # CVE identifiers
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        iocs['cves'] = list(set(re.findall(cve_pattern, text, re.IGNORECASE)))

        # Extract ATT&CK techniques
        attack_pattern = r'T\d{4}(?:\.\d{3})?'
        article['attack_techniques'] = list(set(re.findall(attack_pattern, text)))

        return iocs

    def is_valid_ip(self, ip: str) -> bool:
        """Basic IP validation"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False

    def enrich_ip(self, ip: str) -> Optional[Dict]:
        """Enrich IP address with threat intelligence"""
        cache_file = self.cache_dir / f"ip_{ip}.json"
        if cache_file.exists():
            age = time.time() - cache_file.stat().st_mtime
            if age < 86400:
                with open(cache_file, encoding='utf-8') as f:
                    return json.load(f)

        intel = {'ip': ip, 'sources': []}

        if self.otx_client:
            try:
                otx_data = self.otx_client.get_indicator_details_full(OTXv2.IndicatorTypes.IPv4, ip)
                if otx_data:
                    intel['sources'].append('OTX')
                    intel['otx_pulses'] = len(otx_data.get('general', {}).get('pulse_info', {}).get('pulses', []))
                    intel['malicious'] = otx_data.get('general', {}).get('pulse_info', {}).get('count', 0) > 0
            except Exception as e:
                print(f"  OTX error for {ip}: {e}")

        if self.vt_client:
            try:
                ip_obj = self.vt_client.get_object(f"/ip_addresses/{ip}")
                intel['sources'].append('VirusTotal')
                intel['vt_malicious'] = ip_obj.last_analysis_stats.get('malicious', 0)
                intel['vt_suspicious'] = ip_obj.last_analysis_stats.get('suspicious', 0)
                intel['country'] = getattr(ip_obj, 'country', None)
                intel['asn'] = getattr(ip_obj, 'asn', None)
            except Exception as e:
                print(f"  VirusTotal error for {ip}: {e}")

        if intel['sources']:
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(intel, f)
            return intel

        return None

    def enrich_domain(self, domain: str) -> Optional[Dict]:
        """Enrich domain with threat intelligence"""
        cache_file = self.cache_dir / f"domain_{domain}.json"
        if cache_file.exists():
            age = time.time() - cache_file.stat().st_mtime
            if age < 86400:
                with open(cache_file, encoding='utf-8') as f:
                    return json.load(f)

        intel = {'domain': domain, 'sources': []}

        if self.otx_client:
            try:
                otx_data = self.otx_client.get_indicator_details_full(OTXv2.IndicatorTypes.DOMAIN, domain)
                if otx_data:
                    intel['sources'].append('OTX')
                    intel['otx_pulses'] = len(otx_data.get('general', {}).get('pulse_info', {}).get('pulses', []))
            except Exception as e:
                print(f"  OTX error for {domain}: {e}")

        if self.vt_client:
            try:
                domain_obj = self.vt_client.get_object(f"/domains/{domain}")
                intel['sources'].append('VirusTotal')
                intel['vt_malicious'] = domain_obj.last_analysis_stats.get('malicious', 0)
                intel['reputation'] = getattr(domain_obj, 'reputation', None)
            except Exception as e:
                print(f"  VirusTotal error for {domain}: {e}")

        if intel['sources']:
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(intel, f)
            return intel

        return None

    def enrich_hash(self, hash_val: str) -> Optional[Dict]:
        """Enrich file hash with threat intelligence"""
        cache_file = self.cache_dir / f"hash_{hash_val}.json"
        if cache_file.exists():
            age = time.time() - cache_file.stat().st_mtime
            if age < 86400:
                with open(cache_file, encoding='utf-8') as f:
                    return json.load(f)

        intel = {'hash': hash_val, 'sources': []}

        if self.vt_client:
            try:
                file_obj = self.vt_client.get_object(f"/files/{hash_val}")
                intel['sources'].append('VirusTotal')
                intel['vt_malicious'] = file_obj.last_analysis_stats.get('malicious', 0)
                intel['vt_total'] = sum(file_obj.last_analysis_stats.values())
                intel['file_type'] = getattr(file_obj, 'type_description', None)
                intel['names'] = file_obj.names[:5] if hasattr(file_obj, 'names') else []
            except Exception as e:
                print(f"  VirusTotal error for {hash_val}: {e}")

        if intel['sources']:
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(intel, f)
            return intel

        return None


class GeocodingService:
    """Handle geographic location extraction and caching"""

    def __init__(self, cache_dir: Path, countries_db_path: Path):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.countries = {}

        # Load country coordinates database
        if countries_db_path.exists():
            try:
                with open(countries_db_path, encoding='utf-8') as f:
                    self.countries = json.load(f)
                print(f"  Loaded {len(self.countries)} countries for geocoding")
            except (json.JSONDecodeError, IOError) as e:
                print(f"  Warning: Could not load countries DB: {e}")
        else:
            print(f"  Warning: countries.json not found at {countries_db_path}")
            print("  Geocoding will use fallback method only")

        # Initialize geocoder
        self.geocoder = None
        if GEOPY_AVAILABLE:
            self.geocoder = Nominatim(user_agent="TheDailyBrief/1.0", timeout=10)

    @lru_cache(maxsize=1000)
    def geocode_article(self, title: str, summary: str, country_hint: str = None) -> Optional[Dict]:
        """Extract and geocode location from article"""
        text = f"{title} {summary or ''}"

        # Try to find country mentions
        location = self.extract_country(text)

        if location:
            coords = self.countries.get(location)
            if coords:
                return {
                    'country': location,
                    'latitude': coords['lat'],
                    'longitude': coords['lon'],
                    'country_code': coords.get('code', ''),
                    'source': 'database'
                }

        # Fallback to geocoder if available (only for high-confidence matches)
        if self.geocoder and not location:
            location = self.extract_location_generic(text)
            if location and len(location) > 3:
                try:
                    geo_data = self.geocoder.geocode(location, exactly_one=True, language='en')
                    if geo_data:
                        # Only accept results that look like real country/city names
                        addr = geo_data.address or ''
                        # Check if the geocoded address contains recognizable place types
                        if any(c in addr for c in self.countries.keys()):
                            country_in_addr = next((c for c in self.countries.keys() if c in addr), location)
                            return {
                                'country': country_in_addr,
                                'latitude': geo_data.latitude,
                                'longitude': geo_data.longitude,
                                'source': 'geocoder'
                            }
                except (GeocoderTimedOut, GeocoderServiceError):
                    pass
                except Exception:
                    pass

        return None

    def extract_country(self, text: str) -> Optional[str]:
        """Extract country name from text using word boundary matching"""
        if not self.countries:
            return None

        # Sort by length (longer names first to avoid partial matches)
        sorted_countries = sorted(self.countries.keys(), key=len, reverse=True)

        for country in sorted_countries:
            # Skip very short names (3 chars or fewer) for substring matching
            if len(country) <= 3:
                continue
            # Use word-boundary regex to avoid partial matches
            pattern = r'\b' + re.escape(country) + r'\b'
            if re.search(pattern, text, re.IGNORECASE):
                return country

        # Try country codes (only 2-letter codes, require exact word boundary)
        for country, data in self.countries.items():
            code = data.get('code', '')
            if code and len(code) == 2:
                # Require the code to be surrounded by spaces/punctuation
                pattern = r'(?<![A-Za-z])' + re.escape(code) + r'(?![A-Za-z])'
                if re.search(pattern, text):
                    return country

        return None

    def extract_location_generic(self, text: str) -> Optional[str]:
        """Extract location mentions (city, region) with false-positive filtering"""
        # Common false-positive words that look like locations but aren't
        false_positives = {
            'actors', 'tracker', 'threat', 'attack', 'campaign', 'malware',
            'breach', 'hack', 'cyber', 'security', 'intelligence', 'analysis',
            'research', 'report', 'group', 'team', 'update', 'alert', 'warning',
            'advisory', 'critical', 'vulnerability', 'exploit', 'phishing',
            'ransomware', 'incident', 'response', 'defense', 'network',
            'infrastructure', 'supply', 'chain', 'data', 'information',
            'january', 'february', 'march', 'april', 'may', 'june',
            'july', 'august', 'september', 'october', 'november', 'december',
            'monday', 'tuesday', 'wednesday', 'thursday', 'friday',
            'saturday', 'sunday', 'new', 'the', 'and', 'for'
        }

        patterns = [
            r'(?:based in|from|targeting|in) ([A-Z][a-z]{3,}(?: [A-Z][a-z]+)*)',
            r'([A-Z][a-z]{3,}(?: [A-Z][a-z]+)*)-based',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                candidate = match[0] if isinstance(match, tuple) else match
                if candidate.lower() not in false_positives and len(candidate) > 3:
                    return candidate

        return None


def scrape_defcon_level():
    """Scrape current DEFCON estimate from defconlevel.com (OSINT)"""
    DEFCON_MAP = {
        5: {'name': 'NORMAL', 'color': '#44ff88', 'description': 'Normal peacetime readiness'},
        4: {'name': 'ABOVE NORMAL', 'color': '#4488ff', 'description': 'Increased intelligence watch and security'},
        3: {'name': 'ELEVATED', 'color': '#ffcc00', 'description': 'Increase in force readiness above normal'},
        2: {'name': 'HIGH', 'color': '#ff9944', 'description': 'Armed forces ready to deploy in 6 hours'},
        1: {'name': 'MAXIMUM', 'color': '#ff0000', 'description': 'Maximum readiness, nuclear war imminent'}
    }
    try:
        resp = requests.get(
            'https://www.defconlevel.com/current-level.php',
            headers={'User-Agent': 'The Daily Brief/1.0 (OSINT Aggregator)'},
            timeout=15
        )
        resp.raise_for_status()
        html = resp.text

        # Try image src pattern: /images/defcon-3.png
        match = re.search(r'/images/defcon-(\d)\.png', html)
        if not match:
            # Fallback: text pattern "DEFCON 3"
            match = re.search(r'DEFCON\s+(\d)', html, re.IGNORECASE)
        if not match:
            return None

        level = int(match.group(1))
        if level < 1 or level > 5:
            return None

        details = DEFCON_MAP[level].copy()
        details['source'] = 'defconlevel.com (OSINT Estimate)'
        details['scraped_at'] = datetime.now().isoformat()

        return {'level': level, 'details': details}
    except Exception as e:
        print(f"  [WARN] Could not scrape DEFCON level: {e}")
        return None


class DEFCONCalculator:
    """Fallback: Calculate threat level based on intelligence feed data"""

    DEFCON_LEVELS = {
        1: {'name': 'MAXIMUM', 'color': '#ff0000', 'description': 'Maximum readiness, nuclear war imminent'},
        2: {'name': 'HIGH', 'color': '#ff9944', 'description': 'Armed forces ready to deploy in 6 hours'},
        3: {'name': 'ELEVATED', 'color': '#ffcc00', 'description': 'Increase in force readiness above normal'},
        4: {'name': 'ABOVE NORMAL', 'color': '#4488ff', 'description': 'Increased intelligence watch and security'},
        5: {'name': 'NORMAL', 'color': '#44ff88', 'description': 'Normal peacetime readiness'}
    }

    def __init__(self, config: Dict):
        self.config = config
        self.thresholds = config.get('thresholds', {
            'critical': 4.0, 'severe': 3.0, 'elevated': 2.0, 'guarded': 1.0
        })

    def calculate(self, articles: List[Dict]) -> Tuple[int, Dict]:
        score = 0.0
        breakdown = {
            'critical_count': 0, 'exploit_count': 0,
            'apt_count': 0, 'malware_count': 0,
            'total_articles': len(articles)
        }

        # Factor 1: Critical Article Count (40% weight - 2.0 max)
        critical_articles = [a for a in articles if a.get('priority') == 1]
        breakdown['critical_count'] = len(critical_articles)
        if len(critical_articles) >= 20: score += 2.0
        elif len(critical_articles) >= 10: score += 1.5
        elif len(critical_articles) >= 5: score += 1.0
        else: score += 0.5

        # Factor 2: Zero-Day/Active Exploitation (30% weight - 1.5 max)
        exploit_keywords = ['zero-day', 'zero day', 'actively exploited', 'in the wild', 'kev', '0day']
        exploit_articles = [
            a for a in articles
            if any(kw in (a.get('title', '') + ' ' + (a.get('summary') or '')).lower()
                   for kw in exploit_keywords)
        ]
        breakdown['exploit_count'] = len(exploit_articles)
        if len(exploit_articles) >= 5: score += 1.5
        elif len(exploit_articles) >= 3: score += 1.0
        elif len(exploit_articles) >= 1: score += 0.5

        # Factor 3: APT Activity (15% weight - 0.75 max)
        apt_articles = [a for a in articles if a.get('category') == 'APT']
        breakdown['apt_count'] = len(apt_articles)
        if len(apt_articles) >= 15: score += 0.75
        elif len(apt_articles) >= 10: score += 0.5
        elif len(apt_articles) >= 5: score += 0.25

        # Factor 4: Ransomware/Malware (15% weight - 0.75 max)
        malware_articles = [a for a in articles if a.get('category') == 'MALWARE']
        breakdown['malware_count'] = len(malware_articles)
        if len(malware_articles) >= 15: score += 0.75
        elif len(malware_articles) >= 10: score += 0.5
        elif len(malware_articles) >= 5: score += 0.25

        # Convert score to DEFCON level (lower number = more severe)
        if score >= self.thresholds['critical']: level = 1
        elif score >= self.thresholds['severe']: level = 2
        elif score >= self.thresholds['elevated']: level = 3
        elif score >= self.thresholds['guarded']: level = 4
        else: level = 5

        details = self.DEFCON_LEVELS[level].copy()
        details['score'] = round(score, 2)
        details['breakdown'] = breakdown
        details['calculated_at'] = datetime.now().isoformat()

        return level, details


class FeedAggregator:
    def __init__(self, project_dir: Path):
        """
        Initialize aggregator. All config files are expected in project_dir.
        Output is written to project_dir/output/
        """
        self.project_dir = project_dir
        self.output_dir = project_dir / 'output'
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Load configurations from flat project directory
        config_path = project_dir / 'feeds.json'
        platform_config_path = project_dir / 'platform_config.json'
        api_config_path = project_dir / 'api_keys.json'
        countries_db_path = project_dir / 'countries.json'

        if not config_path.exists():
            print(f"ERROR: feeds.json not found at {config_path}")
            sys.exit(1)

        with open(config_path, encoding='utf-8') as f:
            self.config = json.load(f)

        self.platform_config = {}
        if platform_config_path.exists():
            with open(platform_config_path, encoding='utf-8') as f:
                self.platform_config = json.load(f)

        # Initialize services
        cache_dir = project_dir / 'data' / 'api_cache'
        geocode_cache = project_dir / 'data' / 'geocode_cache'

        self.enrichment = ThreatEnrichment(api_config_path, cache_dir)
        self.geocoding = GeocodingService(geocode_cache, countries_db_path)
        self.defcon_calc = DEFCONCalculator(self.platform_config.get('defcon', {}))

        # Load API config for auth key resolution (JSON API feeds)
        self.api_config = {}
        if api_config_path.exists():
            try:
                with open(api_config_path, encoding='utf-8') as f:
                    self.api_config = json.load(f)
            except (json.JSONDecodeError, IOError):
                pass

        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'The Daily Brief/1.0'})

    def resolve_auth_key(self, feed_config: Dict) -> Optional[str]:
        """Resolve API key from api_keys.json reference"""
        ref = feed_config.get('auth_key_ref')
        if not ref:
            return None
        config = self.api_config.get(ref, {})
        if not config.get('enabled', False):
            return None
        key = config.get('api_key', '')
        if not key or key.startswith('YOUR_'):
            return None
        return key

    def fetch_rss_feed(self, feed_config: Dict) -> List[Dict]:
        """Fetch and parse RSS/Atom feed, return list of articles"""
        try:
            print(f"  Fetching RSS: {feed_config['name']}")
            timeout = feed_config.get('timeout', 15)
            response = self.session.get(feed_config['url'], timeout=timeout)
            response.raise_for_status()
            feed = feedparser.parse(response.content)
            if feed.bozo:
                print(f"    Warning: Parse error for {feed_config['name']}")

            max_items = feed_config.get('max_items',
                self.config.get('display_settings', {}).get('items_per_feed', 10))
            entries = feed.entries[:max_items]
            return [self.parse_rss_entry(entry, feed_config) for entry in entries]
        except Exception as e:
            print(f"    Error fetching {feed_config['name']}: {str(e)}")
            return []

    def fetch_json_static(self, feed_config: Dict) -> List[Dict]:
        """Fetch a static JSON feed (e.g., CISA KEV)"""
        try:
            print(f"  Fetching JSON: {feed_config['name']}")
            headers = {}
            auth_key = self.resolve_auth_key(feed_config)
            if auth_key:
                headers['Auth-Key'] = auth_key

            response = self.session.get(feed_config['url'], timeout=30, headers=headers)
            response.raise_for_status()
            data = response.json()

            # Navigate to the entries array using response_path
            entries = self._resolve_json_path(data, feed_config.get('response_path', ''))
            if not isinstance(entries, list):
                print(f"    Warning: response_path did not resolve to a list")
                return []

            # Sort by date field (descending) and take max_items most recent
            date_field = feed_config.get('field_mapping', {}).get('published', '')
            if date_field:
                entries = sorted(entries, key=lambda e: e.get(date_field, ''), reverse=True)

            max_items = feed_config.get('max_items',
                self.config.get('display_settings', {}).get('items_per_feed', 10))
            entries = entries[:max_items]

            return [self.parse_json_entry(entry, feed_config) for entry in entries]
        except requests.exceptions.RequestException as e:
            print(f"    HTTP error fetching {feed_config['name']}: {str(e)}")
            return []
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            print(f"    Parse error for {feed_config['name']}: {str(e)}")
            return []

    def fetch_json_api(self, feed_config: Dict) -> List[Dict]:
        """Fetch from a JSON API endpoint (GET or POST)"""
        try:
            print(f"  Fetching API: {feed_config['name']}")
            headers = {}
            auth_key = self.resolve_auth_key(feed_config)
            if auth_key:
                headers['Auth-Key'] = auth_key

            method = feed_config.get('method', 'GET').upper()
            if method == 'POST':
                post_body = feed_config.get('post_body', {})
                headers['Content-Type'] = 'application/json'
                response = self.session.post(
                    feed_config['url'], json=post_body,
                    timeout=30, headers=headers
                )
            else:
                response = self.session.get(
                    feed_config['url'], timeout=30, headers=headers
                )
            response.raise_for_status()
            data = response.json()

            entries = self._resolve_json_path(data, feed_config.get('response_path', ''))
            if not isinstance(entries, list):
                print(f"    Warning: response_path did not resolve to a list")
                return []

            max_items = feed_config.get('max_items',
                self.config.get('display_settings', {}).get('items_per_feed', 10))
            entries = entries[:max_items]

            return [self.parse_json_entry(entry, feed_config) for entry in entries]
        except requests.exceptions.RequestException as e:
            print(f"    HTTP error fetching {feed_config['name']}: {str(e)}")
            return []
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            print(f"    Parse error for {feed_config['name']}: {str(e)}")
            return []

    def _resolve_json_path(self, data, path: str):
        """Navigate nested JSON using dot-separated path (e.g., 'data.results')"""
        if not path:
            return data
        for key in path.split('.'):
            if isinstance(data, dict):
                data = data.get(key)
            elif isinstance(data, list) and key.isdigit():
                data = data[int(key)]
            else:
                return None
        return data

    def _interpolate_template(self, template: str, entry: Dict) -> str:
        """Replace {field} placeholders with values from entry dict"""
        if not template:
            return ''

        def replacer(match):
            key = match.group(1)
            value = entry.get(key, '')
            if isinstance(value, list):
                return ', '.join(str(v) for v in value)
            return str(value) if value is not None else ''

        return re.sub(r'\{(\w+)\}', replacer, template)

    def _parse_date_flexible(self, date_str: str) -> Optional[datetime]:
        """Parse date strings in various formats"""
        if not date_str:
            return None
        formats = [
            '%Y-%m-%d %H:%M:%S UTC',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%d',
        ]
        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue
        # Last resort: try fromisoformat
        try:
            return datetime.fromisoformat(date_str.replace('Z', '').replace('+00:00', ''))
        except (ValueError, AttributeError):
            return None

    def parse_json_entry(self, entry: Dict, feed_config: Dict) -> Dict:
        """Parse a JSON API entry using field_mapping from feed config"""
        mapping = feed_config.get('field_mapping', {})

        # Build fields using template interpolation
        title = self._interpolate_template(mapping.get('title', 'Untitled'), entry)
        link = self._interpolate_template(mapping.get('link', ''), entry)
        summary = self._interpolate_template(mapping.get('summary', ''), entry)
        source = mapping.get('source', feed_config['name'])

        # Parse published date
        date_field = mapping.get('published', '')
        published = self._parse_date_flexible(entry.get(date_field, ''))

        # Generate article ID from id_field or hash of title+link
        id_field = mapping.get('id_field', '')
        if id_field and entry.get(id_field):
            unique_str = f"{feed_config['id']}:{entry[id_field]}"
        else:
            unique_str = f"{link}{title}"
        article_id = hashlib.md5(unique_str.encode()).hexdigest()

        article = {
            'id': article_id,
            'title': self.strip_html(title),
            'link': link,
            'summary': self.strip_html(summary),
            'published': published.isoformat() if published else datetime.now().isoformat(),
            'source': source,
            'category': feed_config['category'],
            'feed_name': feed_config['name'],
            'feed_id': feed_config['id'],
            'icon': feed_config['icon'],
            'color': feed_config['color'],
            'priority': feed_config['priority'],
            'audience': feed_config.get('audience', 'analyst'),
            'scope': feed_config.get('scope', 'tactical'),
            'attack_techniques': []
        }

        # Geocoding (same as RSS path)
        if self.platform_config.get('map', {}).get('enabled', True):
            geo_data = self.geocoding.geocode_article(
                article['title'], article.get('summary', '')
            )
            if geo_data:
                article['geo'] = geo_data

        # IOC/enrichment (same as RSS path)
        if self.platform_config.get('enrichment', {}).get('enabled', True):
            article = self.enrichment.enrich_article(article)

        # For structured feeds, also extract IOCs directly from the raw entry
        self._extract_structured_iocs(entry, article, feed_config)

        return article

    def _extract_structured_iocs(self, entry: Dict, article: Dict, feed_config: Dict) -> None:
        """Extract IOCs directly from structured data in JSON API entries"""
        feed_id = feed_config['id']

        if 'iocs' not in article:
            article['iocs'] = {'ips': [], 'domains': [], 'hashes': [], 'cves': [], 'urls': []}

        iocs = article['iocs']

        if feed_id == 'cisa-kev':
            cve = entry.get('cveID', '')
            if cve and cve not in iocs['cves']:
                iocs['cves'].append(cve)

        elif feed_id == 'abusech-urlhaus':
            url = entry.get('url', '')
            if url and url not in iocs['urls']:
                iocs['urls'].append(url)
            host = entry.get('host', '')
            if host:
                if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
                    if host not in iocs['ips']:
                        iocs['ips'].append(host)
                elif '.' in host:
                    if host not in iocs['domains']:
                        iocs['domains'].append(host)

        elif feed_id == 'abusech-threatfox':
            ioc_value = entry.get('ioc', '')
            ioc_type = entry.get('ioc_type', '')
            if ioc_type == 'ip:port':
                ip = ioc_value.split(':')[0] if ':' in ioc_value else ioc_value
                if ip not in iocs['ips']:
                    iocs['ips'].append(ip)
            elif ioc_type == 'domain':
                if ioc_value not in iocs['domains']:
                    iocs['domains'].append(ioc_value)
            elif ioc_type == 'url':
                if ioc_value not in iocs['urls']:
                    iocs['urls'].append(ioc_value)
            # Extract hashes from malware_samples
            for sample in entry.get('malware_samples', []):
                sha256 = sample.get('sha256_hash', '')
                if sha256 and sha256 not in iocs['hashes']:
                    iocs['hashes'].append(sha256)

        elif feed_id == 'abusech-malwarebazaar':
            for hash_type in ['sha256_hash', 'sha1_hash', 'md5_hash']:
                h = entry.get(hash_type, '')
                if h and h not in iocs['hashes']:
                    iocs['hashes'].append(h)

    def generate_article_id(self, entry: Dict) -> str:
        unique_str = f"{entry.get('link', '')}{entry.get('title', '')}"
        return hashlib.md5(unique_str.encode()).hexdigest()

    @staticmethod
    def strip_html(text: str) -> str:
        """Remove HTML tags and decode entities from text"""
        if not text:
            return ''
        # Remove HTML tags
        clean = re.sub(r'<[^>]+>', ' ', text)
        # Decode common HTML entities
        clean = clean.replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>')
        clean = clean.replace('&quot;', '"').replace('&nbsp;', ' ').replace('&#39;', "'")
        # Collapse whitespace
        clean = re.sub(r'\s+', ' ', clean).strip()
        return clean

    def parse_rss_entry(self, entry: Dict, feed_config: Dict) -> Dict:
        """Parse RSS/Atom feed entry with enrichment"""
        published = entry.get('published_parsed') or entry.get('updated_parsed')
        pub_date = datetime(*published[:6]) if published else datetime.now()

        # Extract source name from Google News source field or title suffix
        source_name = feed_config['name']
        if hasattr(entry, 'source') and isinstance(entry.get('source'), dict):
            source_name = entry['source'].get('title', feed_config['name'])
        elif entry.get('source'):
            source_name = str(entry['source'])

        # Clean title: remove trailing "- Source" suffix that Google News adds
        raw_title = entry.get('title', 'No title')
        clean_title = raw_title
        if ' - ' in raw_title:
            parts = raw_title.rsplit(' - ', 1)
            if len(parts) == 2:
                clean_title = parts[0].strip()
                # Use the suffix as source name if more specific
                if parts[1].strip() and source_name == feed_config['name']:
                    source_name = parts[1].strip()

        # Clean summary: strip HTML from Google News RSS
        raw_summary = entry.get('summary', '')
        clean_summary = self.strip_html(raw_summary)

        article = {
            'id': self.generate_article_id(entry),
            'title': clean_title,
            'link': entry.get('link', ''),
            'summary': clean_summary,
            'published': pub_date.isoformat(),
            'source': source_name,
            'category': feed_config['category'],
            'feed_name': feed_config['name'],
            'feed_id': feed_config['id'],
            'icon': feed_config['icon'],
            'color': feed_config['color'],
            'priority': feed_config['priority'],
            'audience': feed_config.get('audience', 'analyst'),
            'scope': feed_config.get('scope', 'tactical'),
            'attack_techniques': []
        }

        # Geocoding
        if self.platform_config.get('map', {}).get('enabled', True):
            geo_data = self.geocoding.geocode_article(
                article['title'],
                article.get('summary', '')
            )
            if geo_data:
                article['geo'] = geo_data

        # API Enrichment
        if self.platform_config.get('enrichment', {}).get('enabled', True):
            article = self.enrichment.enrich_article(article)

        return article

    def aggregate_all_feeds(self) -> Dict:
        all_articles = []
        feed_stats = {}
        enabled_feeds = [f for f in self.config['feeds'] if f.get('enabled', True)]

        print(f"\n  Aggregating {len(enabled_feeds)} feeds...")
        print("  " + "=" * 58)

        for feed_config in enabled_feeds:
            feed_type = feed_config.get('type', 'rss')

            # Format dispatcher: route to appropriate fetch method by type
            if feed_type == 'rss':
                articles = self.fetch_rss_feed(feed_config)
            elif feed_type == 'json_static':
                articles = self.fetch_json_static(feed_config)
            elif feed_type == 'json_api':
                # Check if auth is required and available
                if feed_config.get('auth_key_ref'):
                    auth_key = self.resolve_auth_key(feed_config)
                    if not auth_key:
                        print(f"    Skipping {feed_config['name']}: API key not configured")
                        feed_stats[feed_config['id']] = {
                            'status': 'skipped', 'count': 0,
                            'reason': 'api_key_not_configured'
                        }
                        continue
                articles = self.fetch_json_api(feed_config)
            else:
                print(f"    Unknown feed type '{feed_type}' for {feed_config['name']}")
                feed_stats[feed_config['id']] = {'status': 'error', 'count': 0}
                continue

            if not articles:
                if feed_config['id'] not in feed_stats:
                    feed_stats[feed_config['id']] = {'status': 'error', 'count': 0}
            else:
                all_articles.extend(articles)
                feed_stats[feed_config['id']] = {
                    'status': 'success', 'count': len(articles)
                }
                print(f"    {len(articles)} articles from {feed_config['name']}")

            time.sleep(0.5)

        print("  " + "=" * 58)

        # Filters
        max_age = self.config.get('display_settings', {}).get('max_age_hours', 168)
        if max_age:
            original = len(all_articles)
            all_articles = self.filter_by_age(all_articles, max_age)
            removed = original - len(all_articles)
            if removed > 0:
                print(f"  Removed {removed} articles older than {max_age}h")

        if self.config.get('display_settings', {}).get('deduplicate', True):
            original = len(all_articles)
            all_articles = self.deduplicate(all_articles)
            removed = original - len(all_articles)
            if removed > 0:
                print(f"  Removed {removed} duplicate articles")

        all_articles.sort(key=lambda x: (x['priority'], x['published']), reverse=False)

        # Try scraping DEFCON from defconlevel.com first, fall back to internal calc
        scraped = scrape_defcon_level()
        if scraped:
            defcon_level = scraped['level']
            defcon_details = scraped['details']
            print(f"\n  DEFCON {defcon_level} - {defcon_details['name']} (source: defconlevel.com)")
        else:
            defcon_level, defcon_details = self.defcon_calc.calculate(all_articles)
            defcon_details['source'] = 'Internal Calculation'
            print(f"\n  DEFCON {defcon_level} - {defcon_details['name']} (internal)")
        print(f"  {defcon_details['description']}")

        geo_stats = self.calculate_geo_stats(all_articles)

        return {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_articles': len(all_articles),
                'feeds_processed': len(enabled_feeds),
                'feed_stats': feed_stats,
                'defcon_level': defcon_level,
                'defcon_details': defcon_details,
                'geo_stats': geo_stats
            },
            'articles': all_articles
        }

    def filter_by_age(self, articles: List[Dict], max_hours: int) -> List[Dict]:
        cutoff = datetime.now() - timedelta(hours=max_hours)
        filtered = []
        for a in articles:
            try:
                pub = datetime.fromisoformat(a['published'])
                if pub >= cutoff:
                    filtered.append(a)
            except (ValueError, KeyError):
                filtered.append(a)
        return filtered

    def deduplicate(self, articles: List[Dict]) -> List[Dict]:
        seen = set()
        unique = []
        for article in articles:
            if article['id'] not in seen:
                seen.add(article['id'])
                unique.append(article)
        return unique

    def calculate_geo_stats(self, articles: List[Dict]) -> Dict:
        stats = {'total_geolocated': 0, 'countries': {}, 'heatmap_data': []}

        for article in articles:
            if 'geo' in article and article['geo']:
                geo = article['geo']
                lat = geo.get('latitude')
                lon = geo.get('longitude')
                if lat is None or lon is None:
                    continue

                stats['total_geolocated'] += 1
                country = geo.get('country', geo.get('location', 'Unknown'))
                if country not in stats['countries']:
                    stats['countries'][country] = {
                        'count': 0, 'latitude': lat, 'longitude': lon
                    }
                stats['countries'][country]['count'] += 1
                stats['heatmap_data'].append({
                    'lat': lat, 'lon': lon,
                    'intensity': article.get('priority', 3)
                })

        return stats

    def save_output(self, data: Dict):
        output_file = self.output_dir / 'feed_data.json'
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        print(f"\n  Saved {data['metadata']['total_articles']} articles to {output_file}")
        self.save_summary(data)
        return output_file

    def save_summary(self, data: Dict):
        summary_path = self.output_dir / 'summary.txt'
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write("THE DAILY BRIEF - THREAT INTELLIGENCE SUMMARY\n")
            f.write("=" * 70 + "\n\n")
            f.write(f"Generated: {data['metadata']['generated_at']}\n")
            f.write(f"Total Articles: {data['metadata']['total_articles']}\n")
            f.write(f"Feeds Processed: {data['metadata']['feeds_processed']}\n\n")

            defcon = data['metadata']['defcon_details']
            f.write(f"THREAT LEVEL: DEFCON {data['metadata']['defcon_level']} - {defcon['name']}\n")
            f.write(f"Description: {defcon['description']}\n")
            f.write(f"Score: {defcon['score']}/5.0\n\n")

            geo = data['metadata']['geo_stats']
            f.write(f"Geographic Coverage: {geo['total_geolocated']} articles geolocated\n")
            if geo['countries']:
                f.write("Top Countries:\n")
                sorted_countries = sorted(geo['countries'].items(), key=lambda x: x[1]['count'], reverse=True)
                for country, info in sorted_countries[:10]:
                    f.write(f"  - {country}: {info['count']} articles\n")
            f.write("\n")

            by_category = defaultdict(list)
            for article in data['articles']:
                by_category[article['category']].append(article)

            for category, articles in sorted(by_category.items()):
                f.write(f"\n{category} ({len(articles)} articles)\n")
                f.write("-" * 70 + "\n")
                for article in articles[:5]:
                    f.write(f"  - {article['title']}\n")
                    f.write(f"    {article['source']} | {article['published']}\n")
                    if 'geo' in article:
                        loc = article['geo'].get('country', article['geo'].get('location', 'Unknown'))
                        f.write(f"    Location: {loc}\n")
                    f.write("\n")

        print(f"  Summary saved to {summary_path}")


def main():
    parser = argparse.ArgumentParser(description='The Daily Brief - Threat Intelligence Aggregator')
    parser.add_argument('--project-dir', type=str, default=None,
                        help='Path to project directory (default: directory containing this script)')
    args = parser.parse_args()

    if args.project_dir:
        project_dir = Path(args.project_dir).resolve()
    else:
        project_dir = Path(__file__).parent.resolve()

    print("\n" + "=" * 70)
    print("  THE DAILY BRIEF - THREAT INTELLIGENCE AGGREGATOR")
    print("=" * 70)
    print(f"  Project directory: {project_dir}")

    if not (project_dir / 'feeds.json').exists():
        print(f"\n  ERROR: feeds.json not found in {project_dir}")
        print("  Make sure you're running from the project directory or use --project-dir")
        sys.exit(1)

    aggregator = FeedAggregator(project_dir)
    data = aggregator.aggregate_all_feeds()
    aggregator.save_output(data)

    print(f"\n  Feed aggregation complete!")
    print(f"  Output: {project_dir / 'output' / 'feed_data.json'}")
    print("=" * 70 + "\n")


if __name__ == '__main__':
    main()
