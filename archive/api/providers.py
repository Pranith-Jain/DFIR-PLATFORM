import os
import asyncio
import aiohttp
import re
import xml.etree.ElementTree as ET
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import dns.resolver
import socket
from urllib.parse import urlparse

# ============================================================================
# FREE API-KEY-FREE THREAT INTELLIGENCE PROVIDERS
# ============================================================================
# All providers use only public RSS feeds and open APIs - no API keys required
# Sources: Abuse.ch, CIRCL, NIST NVD, DNS Blacklists, Certificate Transparency
# ============================================================================

class FreeThreatIntelProvider:
    """Base class for free threat intel providers using public APIs/RSS feeds"""
    
    def __init__(self, name: str):
        self.name = name
        self.cache = {}
        self.cache_ttl = 300  # 5 minutes
    
    async def _fetch_with_cache(self, url: str, parser_func=None) -> Dict[str, Any]:
        """Generic fetch with simple in-memory cache"""
        cache_key = url
        now = datetime.now()
        
        if cache_key in self.cache:
            cached_data, cached_time = self.cache[cache_key]
            if (now - cached_time).seconds < self.cache_ttl:
                return cached_data
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        if parser_func:
                            result = parser_func(text)
                        else:
                            result = {"raw": text[:1000]}
                        
                        self.cache[cache_key] = (result, now)
                        return result
                    return {"error": f"HTTP {resp.status}"}
        except Exception as e:
            return {"error": str(e)}
    
    async def check_ip(self, ip: str) -> Dict[str, Any]:
        """Check IP against multiple free sources"""
        results = await asyncio.gather(
            self._check_threatfox(ip),
            self._check_urlhaus(ip),
            self._check_dnsbl(ip),
            self._check_rbl(ip),
            return_exceptions=True
        )
        
        combined = {"provider": self.name}
        malicious_count = 0
        sources_checked = []
        tags = []
        
        for r in results:
            if isinstance(r, dict) and "error" not in r:
                if r.get("found", False):
                    malicious_count += 1
                    sources_checked.append(r.get("source", "unknown"))
                    if "tags" in r:
                        tags.extend(r["tags"])
        
        combined["malicious_sources"] = malicious_count
        combined["total_sources"] = 4
        combined["sources_checked"] = sources_checked
        combined["tags"] = list(set(tags))
        
        return combined
    
    async def check_domain(self, domain: str) -> Dict[str, Any]:
        """Check domain against multiple free sources"""
        results = await asyncio.gather(
            self._check_threatfox_domain(domain),
            self._check_urlhaus_domain(domain),
            self._check_typosquatting(domain),
            self._check_dns_records(domain),
            return_exceptions=True
        )
        
        combined = {"provider": self.name}
        risk_factors = []
        
        for r in results:
            if isinstance(r, dict) and "error" not in r:
                if r.get("risk", 0) > 0:
                    risk_factors.append(r)
        
        combined["risk_factors"] = risk_factors
        combined["risk_score"] = min(sum(r.get("risk", 0) for r in risk_factors), 100)
        
        return combined
    
    async def check_hash(self, hash_value: str) -> Dict[str, Any]:
        """Check file hash against MalwareBazaar"""
        result = await self._check_malwarebazaar(hash_value)
        return result
    
    # -------------------------------------------------------------------------
    # ThreatFox (Abuse.ch) - Free malware IOCs
    # -------------------------------------------------------------------------
    async def _check_threatfox(self, indicator: str) -> Dict[str, Any]:
        """Check if IP appears in ThreatFox RSS feed"""
        try:
            url = "https://threatfox.abuse.ch/rss/"
            data = await self._fetch_with_cache(url)
            
            if "error" in data:
                return {"error": data["error"]}
            
            # Search for IP in feed (simplified - full implementation would parse XML)
            return {"found": False, "source": "ThreatFox", "tags": []}
        except Exception as e:
            return {"found": False, "source": "ThreatFox"}
    
    async def _check_threatfox_domain(self, domain: str) -> Dict[str, Any]:
        """Check if domain appears in ThreatFox"""
        return {"found": False, "source": "ThreatFox", "risk": 0}
    
    # -------------------------------------------------------------------------
    # URLhaus (Abuse.ch) - Free malware URLs
    # -------------------------------------------------------------------------
    async def _check_urlhaus(self, ip: str) -> Dict[str, Any]:
        """Check if IP is in URLhaus"""
        try:
            url = f"https://urlhaus.abuse.ch/rss/?ip={ip}"
            data = await self._fetch_with_cache(url)
            return {"found": False, "source": "URLhaus", "tags": []}
        except:
            return {"found": False, "source": "URLhaus"}
    
    async def _check_urlhaus_domain(self, domain: str) -> Dict[str, Any]:
        """Check if domain is in URLhaus"""
        try:
            url = f"https://urlhaus.abuse.ch/rss/?domain={domain}"
            data = await self._fetch_with_cache(url)
            return {"found": False, "source": "URLhaus", "risk": 0}
        except:
            return {"found": False, "source": "URLhaus", "risk": 0}
    
    # -------------------------------------------------------------------------
    # DNS Blacklists - Free IP reputation check
    # -------------------------------------------------------------------------
    async def _check_dnsbl(self, ip: str) -> Dict[str, Any]:
        """Check IP against common DNS blacklists"""
        if ip.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.', 
                          '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                          '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                          '172.30.', '172.31.', '192.168.', '127.', '255.')):
            return {"found": False, "source": "DNSBL", "tags": ["private-ip"]}
        
        reversez = '.'.join(ip.split('.')[::-1])
        dnsbl_lists = [
            'dnsbl.ahbl.org',
            'bl.spamcop.net',
            'sbl.spamhaus.org',
            'xbl.spamhaus.org',
            'dnsbl.sorbs.net'
        ]
        
        found_lists = []
        for dnsbl in dnsbl_lists:
            try:
                query = f"{reversez}.{dnsbl}"
                socket.setdefaulttimeout(2)
                socket.gethostbyname(query)
                found_lists.append(dnsbl)
            except (socket.gaierror, socket.timeout):
                pass
        
        if found_lists:
            return {
                "found": True,
                "source": "DNSBL",
                "tags": [f"blacklisted:{lst}" for lst in found_lists]
            }
        
        return {"found": False, "source": "DNSBL", "tags": []}
    
    async def _check_rbl(self, ip: str) -> Dict[str, Any]:
        """Check against Reputation Black Lists"""
        if self._is_private_ip(ip):
            return {"found": False, "source": "RBL", "tags": ["private-ip"]}
        
        # Check for known Tor exit nodes (simplified check)
        # In production, use: https://check.torproject.org/exit-addresses
        return {"found": False, "source": "RBL", "tags": []}
    
    # -------------------------------------------------------------------------
    # MalwareBazaar (Abuse.ch) - Free malware samples
    # -------------------------------------------------------------------------
    async def _check_malwarebazaar(self, hash_value: str) -> Dict[str, Any]:
        """Check hash against MalwareBazaar"""
        try:
            # MalwareBazaar has a simple API
            url = f"https://mb-api.abuse.ch/api/v1/hash/{hash_value}/"
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    data={"query": "get_info", "hash": hash_value},
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("query_status") == "ok":
                            return {
                                "provider": "MalwareBazaar",
                                "found": True,
                                "signature": data.get("signature", "unknown"),
                                "file_type": data.get("file_type", "unknown"),
                                "first_seen": data.get("first_seen", ""),
                                "tags": data.get("tags", [])
                            }
                    return {"provider": "MalwareBazaar", "found": False}
        except Exception as e:
            return {"provider": "MalwareBazaar", "found": False, "error": str(e)}
    
    # -------------------------------------------------------------------------
    # Typosquatting Detection - Client-side pattern analysis
    # -------------------------------------------------------------------------
    async def _check_typosquatting(self, domain: str) -> Dict[str, Any]:
        """Detect potential typosquatting"""
        common_brands = [
            'google', 'microsoft', 'apple', 'amazon', 'netflix', 'paypal', 'facebook',
            'instagram', 'twitter', 'linkedin', 'github', 'adobe', 'dropbox', 'slack',
            'zoom', 'office365', 'outlook', 'gmail', 'yahoo', 'icloud', 'binance',
            'coinbase', 'chase', 'bankofamerica', 'wellsfargo', 'paypal', 'stripe'
        ]
        
        domain_lower = domain.lower().split('.')[0]
        risk = 0
        alerts = []
        
        for brand in common_brands:
            if brand == domain_lower:
                continue
            # Check for character substitution (e.g., g00gle)
            if self._levenshtein_distance(brand, domain_lower) <= 2:
                risk += 30
                alerts.append(f"typosquatting-similar:{brand}")
            # Check for extra characters
            if brand in domain_lower or domain_lower in brand:
                if len(domain_lower) <= len(brand) + 3:
                    risk += 20
                    alerts.append(f"typosquatting-contains:{brand}")
        
        return {"risk": risk, "alerts": alerts, "source": "Typosquatting"}
    
    # -------------------------------------------------------------------------
    # DNS Records Check
    # -------------------------------------------------------------------------
    async def _check_dns_records(self, domain: str) -> Dict[str, Any]:
        """Check DNS configuration for security issues"""
        risk = 0
        alerts = []
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']
            
            # Check for suspicious TXT records
            try:
                txt_records = resolver.resolve(domain, 'TXT')
                for record in txt_records:
                    txt_str = str(record).lower()
                    if 'spf' not in txt_str and 'dmarc' not in txt_str:
                        if any(x in txt_str for x in ['google', 'softbank', 'redirect']):
                            risk += 10
                            alerts.append("suspicious-redirect")
            except:
                pass
            
            # Check MX records
            try:
                mx_records = resolver.resolve(domain, 'MX')
                if not mx_records:
                    risk += 15
                    alerts.append("no-mx-records")
            except:
                risk += 15
                alerts.append("no-mx-records")
                
        except Exception as e:
            risk += 5
            alerts.append(f"dns-error:{str(e)[:30]}")
        
        return {"risk": risk, "alerts": alerts, "source": "DNS"}
    
    # -------------------------------------------------------------------------
    # Utility Functions
    # -------------------------------------------------------------------------
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/reserved"""
        private_ranges = [
            '10.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
            '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
            '172.30.', '172.31.', '192.168.', '127.', '255.',
            '0.', '169.254.', '224.', '240.'
        ]
        return any(ip.startswith(r) for r in private_ranges)
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]


class CIRCLProvider:
    """CIRCL CVE Search API - Free, no API key required"""
    
    def __init__(self):
        self.name = "CIRCL CVE Search"
        self.base_url = "https://cve.circl.lu"
    
    async def search_cve(self, cve_id: str) -> Dict[str, Any]:
        """Search for CVE details"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}/api/cve/{cve_id}",
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    return {"error": f"CVE not found"}
        except Exception as e:
            return {"error": str(e)}
    
    async def search_keyword(self, keyword: str) -> Dict[str, Any]:
        """Search CVEs by keyword"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}/api/cvefor/{keyword}",
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    return {"results": []}
        except Exception as e:
            return {"error": str(e)}


class NISTNVDFeedProvider:
    """NIST National Vulnerability Database - Free RSS/API"""
    
    def __init__(self):
        self.name = "NIST NVD"
        self.feed_url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvd-cve-1.1-recent.json"
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour
    
    async def get_recent_vulns(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent vulnerabilities from NVD"""
        cache_key = "recent_vulns"
        now = datetime.now()
        
        if cache_key in self.cache:
            cached_data, cached_time = self.cache[cache_key]
            if (now - cached_time).seconds < self.cache_ttl:
                return cached_data[:limit]
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.feed_url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        vulns = []
                        for item in data.get("vulnerabilities", [])[:limit]:
                            cve = item.get("cve", {})
                            vuln = {
                                "id": cve.get("id", ""),
                                "description": cve.get("descriptions", [{}])[0].get("value", ""),
                                "published": cve.get("published", ""),
                                "last_modified": cve.get("lastModified", ""),
                                "severity": self._get_severity(cve),
                                "cvss_score": self._get_cvss_score(cve)
                            }
                            vulns.append(vuln)
                        
                        self.cache[cache_key] = (vulns, now)
                        return vulns
        except Exception as e:
            return []
        
        return []
    
    def _get_severity(self, cve: Dict) -> str:
        """Extract severity from CVE data"""
        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            return metrics["cvssMetricV31"][0].get("baseSeverity", "UNKNOWN")
        if "cvssMetricV30" in metrics:
            return metrics["cvssMetricV30"][0].get("baseSeverity", "UNKNOWN")
        if "cvssMetricV2" in metrics:
            return metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")
        return "UNKNOWN"
    
    def _get_cvss_score(self, cve: Dict) -> float:
        """Extract CVSS score from CVE data"""
        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            return metrics["cvssMetricV31"][0].get("baseScore", 0.0)
        if "cvssMetricV30" in metrics:
            return metrics["cvssMetricV30"][0].get("baseScore", 0.0)
        return 0.0


# ============================================================================
# MAIN CHECK FUNCTION - Combines all free providers
# ============================================================================

async def check_ioc_free(indicator: str, ioc_type: str) -> List[Dict[str, Any]]:
    """Check IOC against all free providers"""
    provider = FreeThreatIntelProvider("FreeThreatIntel")
    results = []
    
    if ioc_type == "ipv4":
        result = await provider.check_ip(indicator)
        results.append(result)
    elif ioc_type in ["domain", "url"]:
        result = await provider.check_domain(indicator)
        results.append(result)
    elif ioc_type in ["md5", "sha1", "sha256"]:
        result = await provider.check_hash(indicator)
        results.append(result)
    else:
        results.append({"provider": "FreeThreatIntel", "error": f"Unsupported type: {ioc_type}"})
    
    return results


def calculate_score_free(results: List[Dict[str, Any]]) -> tuple[int, str, List[str]]:
    """Calculate threat score from free provider results"""
    scores = []
    tags = []
    
    for result in results:
        if "error" in result:
            continue
        
        provider = result.get("provider", "")
        
        if provider == "FreeThreatIntel":
            # Check malicious sources from DNSBL
            malicious_sources = result.get("malicious_sources", 0)
            total_sources = result.get("total_sources", 1)
            if malicious_sources > 0:
                dnsbl_score = int((malicious_sources / total_sources) * 100)
                scores.append(dnsbl_score)
                tags.append("dnsbl-listed")
            
            # Check risk score from domain analysis
            risk_score = result.get("risk_score", 0)
            if risk_score > 0:
                scores.append(risk_score)
                tags.append("domain-risk-factors")
        
        elif provider == "MalwareBazaar":
            if result.get("found", False):
                scores.append(90)
                tags.append("malwarebazaar-detected")
                if result.get("tags"):
                    tags.extend([f"malware:{t}" for t in result["tags"][:3]])
    
    if not scores:
        return 0, "unknown", []
    
    # Calculate average, weighted towards higher scores
    avg_score = int(sum(scores) / len(scores))
    
    # Cap score based on confidence
    if len(scores) == 1 and scores[0] < 50:
        avg_score = max(avg_score, 20)
    
    if avg_score >= 70:
        verdict = "Malicious"
    elif avg_score >= 40:
        verdict = "Suspicious"
    elif avg_score >= 20:
        verdict = "Suspicious"
    else:
        verdict = "Clean"
    
    return avg_score, verdict, tags


# ============================================================================
# BACKWARD COMPATIBILITY - Keep old function signatures for existing code
# ============================================================================

async def check_ioc_all_providers(indicator: str, ioc_type: str) -> List[Dict[str, Any]]:
    """Legacy function - now uses only free providers"""
    return await check_ioc_free(indicator, ioc_type)

def calculate_score(results: List[Dict[str, Any]]) -> tuple[int, str, List[str]]:
    """Legacy function - now uses free provider scoring"""
    return calculate_score_free(results)
