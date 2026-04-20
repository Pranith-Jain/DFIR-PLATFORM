from fastapi import FastAPI, UploadFile, File as FastAPIFile, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Any
import re
import asyncio
import os
import httpx
from xml.etree import ElementTree
from urllib.parse import urlparse
from sqlalchemy.orm import Session
from datetime import timedelta, datetime

from providers import check_ioc_all_providers, calculate_score
from domain import DomainChecker, ExposureScanner, FileAnalyzer
from wiki_data import wiki_articles, wiki_content
from actors_data import threat_actors
import models
import database
import auth
from auth import get_current_user, create_access_token, get_password_hash, verify_password, ACCESS_TOKEN_EXPIRE_MINUTES

# Initialize database
database.init_db()

app = FastAPI(title="DFIR Platform API", version="1.0.0")

domain_checker = DomainChecker()
exposure_scanner = ExposureScanner()
file_analyzer = FileAnalyzer()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Pydantic Models ---

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id: int
    is_active: bool
    credits: int

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class PhishingRequest(BaseModel):
    email_raw: str

class IOCRequest(BaseModel):
    indicator: str

class IOCResponse(BaseModel):
    success: bool
    indicator: str
    type: str
    score: int
    verdict: str
    sources: List[dict]
    tags: List[str]
    defanged: str
    credits_used: int

class PhishingResponse(BaseModel):
    success: bool
    verdict: str
    confidence: int
    auth_results: dict
    extracted_iocs: List[dict]
    tags: List[str]
    credits_used: int

class HistoryResponse(BaseModel):
    id: int
    query_type: str
    indicator: str
    timestamp: datetime
    
    class Config:
        from_attributes = True

# --- Utility Functions ---

def defang(ioc: str) -> str:
    result = ioc
    if re.match(r'\d+\.\d+\.\d+\.\d+', ioc):
        result = ioc.replace('.', '[.]')
    return result

def detect_ioc_type(indicator: str) -> str:
    indicator = indicator.strip()
    
    if re.match(r'\d+\.\d+\.\d+\.\d+$', indicator):
        return "ipv4"
    if re.match(r'[0-9a-fA-F]{32}$', indicator):
        return "md5"
    if re.match(r'[0-9a-fA-F]{40}$', indicator):
        return "sha1"
    if re.match(r'[0-9a-fA-F]{64}$', indicator):
        return "sha256"
    if indicator.startswith(('http://', 'https://', 'ftp://')):
        return "url"
    if '@' in indicator and '.' in indicator:
        return "email"
    if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]', indicator):
        return "domain"
    return "unknown"

def check_typosquatting(domain: str) -> List[str]:
    common_brands = [
        'google', 'microsoft', 'apple', 'amazon', 'netflix', 'paypal', 'facebook', 
        'instagram', 'twitter', 'linkedin', 'github', 'adobe', 'dropbox', 'slack', 
        'zoom', 'webex', 'office365', 'outlook', 'protonmail', 'gmail', 'yahoo', 
        'aol', 'icloud', 'binance', 'coinbase', 'kraken', 'metamask', 'ledger', 'trezor',
        'chase', 'bankofamerica', 'wellsfargo', 'citi', 'hsbc', 'barclays', 'standardchartered',
        'visa', 'mastercard', 'americanexpress', 'discover', 'stripe', 'paypal'
    ]
    
    domain_parts = domain.lower().split('.')
    if not domain_parts:
        return []
    
    alerts = []
    for part in domain_parts:
        for brand in common_brands:
            if part == brand: continue
            if brand in part:
                alerts.append(f"possible-typosquatting:{brand}")
                continue
            if len(part) >= 3 and len(brand) >= 3:
                if len(part) == len(brand):
                    diffs = sum(1 for a, b in zip(part, brand) if a != b)
                    if diffs <= 2: alerts.append(f"possible-typosquatting:{brand}")
                elif abs(len(part) - len(brand)) == 1:
                    if brand in part or part in brand: alerts.append(f"possible-typosquatting:{brand}")
    return list(set(alerts))

def save_history(db: Session, user_id: int, q_type: str, indicator: str, results: Any):
    history_entry = models.SearchHistory(
        user_id=user_id,
        query_type=q_type,
        indicator=indicator,
        results=results
    )
    db.add(history_entry)
    # Deduct credit
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user and user.credits > 0:
        user.credits -= 1
    db.commit()

# --- Auth Endpoints ---

@app.post("/api/v1/auth/register", response_model=UserResponse)
def register(user: UserCreate, db: Session = Depends(database.get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_pwd = get_password_hash(user.password)
    new_user = models.User(email=user.email, hashed_password=hashed_pwd)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/api/v1/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/v1/auth/me", response_model=UserResponse)
async def read_users_me(current_user: models.User = Depends(get_current_user)):
    return current_user

@app.get("/api/v1/history", response_model=List[HistoryResponse])
async def get_history(db: Session = Depends(database.get_db), current_user: models.User = Depends(get_current_user)):
    return db.query(models.SearchHistory).filter(models.SearchHistory.user_id == current_user.id).order_by(models.SearchHistory.timestamp.desc()).all()

# --- Core Tool Endpoints ---

@app.get("/")
def root():
    return {"status": "ok", "service": "DFIR Platform API", "version": "1.0.0"}

@app.post("/api/v1/ioc/check", response_model=IOCResponse)
async def check_ioc(request: IOCRequest, db: Session = Depends(database.get_db), current_user: Optional[models.User] = Depends(auth.get_current_user)):
    indicator = request.indicator.strip()
    ioc_type = detect_ioc_type(indicator)
    defanged_ioc = defang(indicator)
    
    sources = await check_ioc_all_providers(indicator, ioc_type)
    score, verdict, tags = calculate_score(sources)
    
    result = {
        "success": True,
        "indicator": indicator,
        "type": ioc_type,
        "score": score,
        "verdict": verdict,
        "sources": sources,
        "tags": tags,
        "defanged": defanged_ioc,
        "credits_used": 1
    }
    
    if current_user:
        save_history(db, current_user.id, "ioc", indicator, result)
        
    return result

@app.post("/api/v1/phishing/analyze", response_model=PhishingResponse)
def analyze_phishing(request: PhishingRequest, db: Session = Depends(database.get_db), current_user: Optional[models.User] = Depends(auth.get_current_user)):
    email_content = request.email_raw
    
    auth_results = {
        "spf": analyze_spf(email_content),
        "dkim": analyze_dkim(email_content),
        "dmarc": analyze_dmarc(email_content)
    }
    
    tags = []
    verdict = "clean"
    confidence = 95
    
    urgency_keywords = ['urgent', 'immediately', 'suspend', 'locked', 'verify', 'unauthorized', 'action required', 'expires in']
    if any(kw in email_content.lower() for kw in urgency_keywords):
        tags.append("urgency-language")
        verdict = "suspicious"
        confidence = min(confidence - 30, 60)
    
    financial_keywords = ['invoice', 'payment', 'wire transfer', 'bank', 'account update', 'balance', 'transaction']
    if any(kw in email_content.lower() for kw in financial_keywords):
        tags.append("financial-context")
        if verdict == "suspicious":
            verdict = "malicious"
            confidence = min(confidence - 20, 70)
        else:
            verdict = "suspicious"
            confidence = min(confidence, 75)

    extracted_iocs = []
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, email_content)
    for url in urls[:5]:
        extracted_iocs.append({"type": "url", "value": url})
        try:
            domain = urlparse(url).netloc
            typo_alerts = check_typosquatting(domain)
            if typo_alerts:
                tags.extend(typo_alerts)
                verdict = "malicious"
        except: pass
    
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, email_content)
    for ip in ips[:5]:
        if not ip.startswith('0.') and not ip.startswith('255.'):
            extracted_iocs.append({"type": "ipv4", "value": ip})
    
    domain_pattern = r'[a-zA-Z0-9][-a-zA-Z0-9]*\.(?:com|org|net|io|co|ru|cn|xyz|info|biz|tk|ml|ga|cf|gq|pw|cc|ws|top|site|online|club|fun|tech|pro)'
    domains = re.findall(domain_pattern, email_content.lower())
    for domain in set(domains[:5]):
        extracted_iocs.append({"type": "domain", "value": domain})
        typo_alerts = check_typosquatting(domain)
        if typo_alerts:
            tags.extend(typo_alerts)
            verdict = "malicious"
    
    hash_patterns = [r'\b[0-9a-fA-F]{32}\b', r'\b[0-9a-fA-F]{40}\b', r'\b[0-9a-fA-F]{64}\b']
    for pattern in hash_patterns:
        hashes = re.findall(pattern, email_content)
        for h in hashes[:3]:
            length = len(h)
            h_type = "md5" if length == 32 else "sha1" if length == 40 else "sha256"
            extracted_iocs.append({"type": h_type, "value": h})
    
    suspicious_attachments = ['.exe', '.scr', '.bat', '.vbs', '.js', '.jar', '.zip', '.rar', '.iso', '.img']
    for ext in suspicious_attachments:
        if ext in email_content.lower(): tags.append(f"suspicious-attachment:{ext}")
    
    if check_link_display_mismatch(email_content):
        tags.append("link-display-mismatch")
        verdict = "malicious"
        confidence = max(confidence - 25, 75)
    
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.xyz', '.top', '.click']
    for ioc in extracted_iocs:
        if ioc.get('type') == 'domain' and any(ioc.get('value', '').endswith(tld) for tld in suspicious_tlds):
            tags.append("suspicious-tld")
            verdict = "malicious"
            break
    
    if auth_results['spf'] == 'fail' or auth_results['dmarc'] == 'fail':
        tags.append("authentication-failed")
        verdict = "malicious"
        confidence = min(confidence + 10, 100)

    result = {
        "success": True,
        "verdict": verdict,
        "confidence": confidence,
        "auth_results": auth_results,
        "extracted_iocs": extracted_iocs,
        "tags": list(set(tags)),
        "credits_used": 1
    }
    
    if current_user:
        save_history(db, current_user.id, "phishing", "Email Analysis", result)
        
    return result

def analyze_spf(email_content: str) -> str:
    if 'spf=pass' in email_content.lower(): return "pass"
    if 'spf=fail' in email_content.lower() or 'spf=softfail' in email_content.lower(): return "fail"
    if 'spf=neutral' in email_content.lower(): return "neutral"
    return "unknown"

def analyze_dkim(email_content: str) -> str:
    if 'dkim=pass' in email_content.lower(): return "pass"
    if 'dkim=fail' in email_content.lower(): return "fail"
    return "unknown"

def analyze_dmarc(email_content: str) -> str:
    if 'dmarc=pass' in email_content.lower(): return "pass"
    if 'dmarc=fail' in email_content.lower(): return "fail"
    return "unknown"

def check_link_display_mismatch(email_content: str) -> bool:
    link_pattern = r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>'
    matches = re.findall(link_pattern, email_content, re.IGNORECASE)
    for href, text in matches:
        text_clean = text.replace('[.]', '.').replace('[dot]', '.').strip()
        if not text_clean: continue
        if ('.' in text_clean or 'http' in text_clean.lower()) and text_clean not in href: return True
    return False

@app.get("/health")
def health():
    return {"status": "healthy"}

@app.get("/api/providers/status")
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
    }

class DomainRequest(BaseModel):
    domain: str

class ExposureRequest(BaseModel):
    domain: str

class FileRequest(BaseModel):
    hash_value: str

@app.post("/api/v1/domain/check")
async def check_domain(request: DomainRequest, db: Session = Depends(database.get_db), current_user: Optional[models.User] = Depends(auth.get_current_user)):
    result = await domain_checker.check_domain(request.domain)
    if current_user:
        save_history(db, current_user.id, "domain", request.domain, result)
    return result

@app.post("/api/v1/exposure/scan")
async def scan_exposure(request: ExposureRequest, db: Session = Depends(database.get_db), current_user: Optional[models.User] = Depends(auth.get_current_user)):
    result = await exposure_scanner.scan(request.domain)
    if current_user:
        save_history(db, current_user.id, "exposure", request.domain, result)
    return result

@app.post("/api/v1/file/analyze")
async def analyze_file(request: FileRequest, db: Session = Depends(database.get_db), current_user: Optional[models.User] = Depends(auth.get_current_user)):
    result = await file_analyzer.analyze_hash(request.hash_value)
    if current_user:
        save_history(db, current_user.id, "file", request.hash_value, result)
    return result

@app.get("/api/v1/wiki")
def get_wiki_categories():
    return {"categories": [
        {"id": "email_security", "name": "Email Security", "count": len(wiki_articles["email_security"]), "articles": wiki_articles["email_security"]},
        {"id": "threat_intelligence", "name": "Threat Intelligence", "count": len(wiki_articles["threat_intelligence"]), "articles": wiki_articles["threat_intelligence"]},
        {"id": "forensics", "name": "Forensics", "count": len(wiki_articles["forensics"]), "articles": wiki_articles["forensics"]},
        {"id": "detection_engineering", "name": "Detection Engineering", "count": len(wiki_articles["detection_engineering"]), "articles": wiki_articles["detection_engineering"]},
        {"id": "attack_types", "name": "Attack Types", "count": len(wiki_articles["attack_types"]), "articles": wiki_articles["attack_types"]}
    ]}

@app.get("/api/v1/wiki/article/{slug}")
def get_wiki_article(slug: str):
    if slug in wiki_content: return wiki_content[slug]
    for category in wiki_articles.values():
        for article in category:
            if article["slug"] == slug: return {"title": article["title"], "description": article["description"], "slug": slug}
    return {"error": "Article not found"}

@app.get("/api/v1/intel/feed")
async def get_intel_feed():
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get("https://dfir-lab.ch/feed.xml")
            return {"xml": response.text}
    except Exception as e: return {"error": str(e)}

@app.get("/api/v1/research/feeds")
async def get_research_feeds():
    feeds = [
        {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
        {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml"},
        {"name": "SecurityWeek", "url": "https://www.securityweek.com/feed/"},
        {"name": "CISA Alerts", "url": "https://www.cisa.gov/uscert/ncas/alerts.xml"},
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
    return {"feeds": results}

@app.get("/api/v1/actors")
def get_actors():
    return {"actors": threat_actors}

@app.post("/api/v1/file/upload")
async def upload_file(file: UploadFile = FastAPIFile(...), db: Session = Depends(database.get_db), current_user: Optional[models.User] = Depends(auth.get_current_user)):
    contents = await file.read()
    result = await file_analyzer.analyze_file_upload(contents, file.filename)
    if current_user:
        save_history(db, current_user.id, "file_upload", file.filename, result)
    return result
