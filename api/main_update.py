# This script updates main.py to fix the providers status endpoint

import re

# Read the current main.py
with open('/home/engine/project/DFIR-PLATFORM/api/main.py', 'r') as f:
    content = f.read()

# Replace the providers status endpoint
old_provider_status = '''@app.get("/api/providers/status")
def providers_status():
    return {
        "providers": [
            {"name": "VirusTotal", "status": "configured" if os.getenv("VIRUSTOTAL_API_KEY") else "missing-api-key"},
            {"name": "AbuseIPDB", "status": "configured" if os.getenv("ABUSEIPDB_API_KEY") else "missing-api-key"},
            {"name": "Shodan", "status": "configured" if os.getenv("SHODAN_API_KEY") else "missing-api-key"},
            {"name": "GreyNoise", "status": "configured" if os.getenv("GREYNOISE_API_KEY") else "missing-api-key"},
            {"name": "OTX", "status": "configured" if os.getenv("OTX_API_KEY") else "missing-api-key"},
            {"name": "URLScan", "status": "configured" if os.getenv("URLSCAN_API_KEY") else "missing-api-key"}
        ]
    }'''

new_provider_status = '''@app.get("/api/providers/status")
def providers_status():
    """Free API-key-free providers status"""
    return {
        "mode": "api-key-free",
        "providers": [
            {"name": "DNS Blacklists", "status": "active", "type": "free"},
            {"name": "Abuse.ch (ThreatFox/URLhaus)", "status": "active", "type": "free"},
            {"name": "MalwareBazaar", "status": "active", "type": "free"},
            {"name": "NIST NVD", "status": "active", "type": "free"},
            {"name": "CIRCL CVE Search", "status": "active", "type": "free"},
            {"name": "CISA Feeds", "status": "active", "type": "free"}
        ],
        "note": "All providers are free and require no API keys"
    }'''

content = content.replace(old_provider_status, new_provider_status)

# Update the intel feed endpoint to use more sources
old_intel_feed = '''@app.get("/api/v1/intel/feed")
async def get_intel_feed():
    feeds = [
        {"name": "DFIR Lab", "url": "https://dfir-lab.ch/feed.xml"},
        {"name": "DFIR Radar", "url": "https://falhumaid.github.io/DFIR_Radar_RSS/rss.xml"}
    ]
    results = []
    async with httpx.AsyncClient(timeout=30.0) as client:
        for feed in feeds:
            try:
                response = await client.get(feed["url"])
                root = ElementTree.fromstring(response.text)
                items = []
                for item in root.findall(".//item")[:10]:
                    title = item.find("title"); link = item.find("link"); pubDate = item.find("pubDate"); desc = item.find("description")
                    items.append({
                        "title": title.text if title is not None else "",
                        "link": link.text if link is not None else "",
                        "pubDate": pubDate.text if pubDate is not None else "",
                        "desc": desc.text[:200] + "..." if desc is not None and len(desc.text or "") > 200 else desc.text if desc is not None else ""
                    })
                results.append({"name": feed["name"], "items": items})
            except Exception as e:
                results.append({"name": feed["name"], "items": [], "error": str(e)})
    return {"feeds": results}'''

new_intel_feed = '''@app.get("/api/v1/intel/feed")
async def get_intel_feed():
    """Get threat intelligence feeds from free sources"""
    feeds = [
        # Threat Intel
        {"name": "ThreatFox (Abuse.ch)", "url": "https://threatfox.abuse.ch/rss/", "category": "malware"},
        {"name": "URLhaus (Abuse.ch)", "url": "https://urlhaus.abuse.ch/rss/", "category": "malware"},
        {"name": "MalwareBazaar", "url": "https://mb-api.abuse.ch/rss/", "category": "malware"},
        {"name": "SANS ISC", "url": "https://isc.sans.edu/rssfeed.xml", "category": "threat-intel"},
        {"name": "PacketStorm", "url": "https://rss.packetstormsecurity.com/", "category": "exploits"},
        {"name": "DFIR Lab", "url": "https://dfir-lab.ch/feed.xml", "category": "research"},
        {"name": "CISA Current", "url": "https://www.cisa.gov/uscert/current-activity.xml", "category": "advisory"},
        {"name": "CISA Alerts", "url": "https://www.cisa.gov/uscert/ncas/alerts.xml", "category": "advisory"},
        # Vulnerabilities
        {"name": "NIST NVD", "url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml", "category": "vulnerability"},
        {"name": "Exploit-DB", "url": "https://www.exploit-db.com/rss.xml", "category": "exploits"},
    ]
    results = []
    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
        for feed in feeds:
            try:
                response = await client.get(feed["url"], headers={"User-Agent": "DFIR-PLATFORM/1.0"})
                if response.status_code == 200:
                    root = ElementTree.fromstring(response.text)
                    items = []
                    for item in root.findall(".//item")[:8]:
                        title = item.find("title"); link = item.find("link"); pubDate = item.find("pubDate"); desc = item.find("description")
                        items.append({
                            "title": title.text if title is not None else "",
                            "link": link.text if link is not None else "",
                            "pubDate": pubDate.text if pubDate is not None else "",
                            "description": desc.text[:300] + "..." if desc is not None and len(desc.text or "") > 300 else desc.text if desc is not None else ""
                        })
                    results.append({"name": feed["name"], "category": feed["category"], "items": items})
                else:
                    results.append({"name": feed["name"], "category": feed["category"], "items": [], "error": f"HTTP {response.status_code}"})
            except Exception as e:
                results.append({"name": feed["name"], "category": feed["category"], "items": [], "error": str(e)[:50]})
    return {"feeds": results, "last_updated": datetime.utcnow().isoformat() + "Z"}'''

content = content.replace(old_intel_feed, new_intel_feed)

# Update research feeds endpoint
old_research_feed = '''@app.get("/api/v1/research/feeds")
async def get_research_feeds():
    feeds = [
        {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
        {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml"},
        {"name": "SecurityWeek", "url": "https://www.securityweek.com/feed/"},
        {"name": "CISA Alerts", "url": "https://www.cisa.gov/uscert/ncas/alerts.xml"},
        {"name": "DFIR Lab", "url": "https://dfir-lab.ch/feed.xml"},
        {"name": "DFIR Radar", "url": "https://falhumaid.github.io/DFIR_Radar_RSS/rss.xml"}
    ]
    results = []
    async with httpx.AsyncClient(timeout=10.0) as client:
        for feed in feeds:
            try:
                response = await client.get(feed["url"])
                root = ElementTree.fromstring(response.text)
                items = []
                for item in root.findall(".//item")[:5]:
                    title = item.find("title"); link = item.find("link"); pubDate = item.find("pubDate"); desc = item.find("description")
                    items.append({
                        "title": title.text if title is not None else "",
                        "link": link.text if link is not None else "",
                        "pubDate": pubDate.text if pubDate is not None else "",
                        "desc": desc.text[:200] + "..." if desc is not None and len(desc.text or "") > 200 else desc.text if desc is not None else ""
                    })
                results.append({"name": feed["name"], "items": items})
            except Exception: results.append({"name": feed["name"], "items": [], "error": "Failed to fetch"})
    return {"feeds": results}'''

new_research_feed = '''@app.get("/api/v1/research/feeds")
async def get_research_feeds():
    """Get security research and news from free RSS feeds"""
    feeds = [
        {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "category": "news"},
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "category": "news"},
        {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/", "category": "journalism"},
        {"name": "Dark Reading", "url": "https://www.darkreading.com/rss/all.xml", "category": "news"},
        {"name": "SecurityWeek", "url": "https://www.securityweek.com/feed/", "category": "news"},
        {"name": "Schneier on Security", "url": "https://www.schneier.com/blog/atom.xml", "category": "research"},
        {"name": "Ars Technica Security", "url": "https://feeds.arstechnica.com/arstechnica/security/", "category": "news"},
        {"name": "Help Net Security", "url": "https://www.helpnetsecurity.com/feed/", "category": "news"},
        {"name": "The Daily Swig", "url": "https://portswigger.net/daily-swig/rss", "category": "news"},
        {"name": "CISO Series", "url": "https://cisoseries.com/feed/", "category": "commentary"},
    ]
    results = []
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        for feed in feeds:
            try:
                response = await client.get(feed["url"], headers={"User-Agent": "DFIR-PLATFORM/1.0"})
                if response.status_code == 200:
                    root = ElementTree.fromstring(response.text)
                    items = []
                    for item in root.findall(".//item")[:5]:
                        title = item.find("title"); link = item.find("link"); pubDate = item.find("pubDate"); desc = item.find("description")
                        items.append({
                            "title": title.text if title is not None else "",
                            "link": link.text if link is not None else "",
                            "pubDate": pubDate.text if pubDate is not None else "",
                            "description": desc.text[:300] + "..." if desc is not None and len(desc.text or "") > 300 else desc.text if desc is not None else ""
                        })
                    results.append({"name": feed["name"], "category": feed["category"], "items": items})
                else:
                    results.append({"name": feed["name"], "category": feed["category"], "items": [], "error": f"HTTP {response.status_code}"})
            except Exception as e:
                results.append({"name": feed["name"], "category": feed["category"], "items": [], "error": str(e)[:50]})
    return {"feeds": results, "last_updated": datetime.utcnow().isoformat() + "Z"}'''

content = content.replace(old_research_feed, new_research_feed)

# Write the updated content
with open('/home/engine/project/DFIR-PLATFORM/api/main.py', 'w') as f:
    f.write(content)

print("main.py updated successfully")
