import re
import io
import zipfile
import numpy as np
import dns.resolver
import requests
import whois
import socket
from datetime import datetime
from urllib.parse import urlparse
from flask import Flask, request, render_template
from joblib import load
from sklearn.base import BaseEstimator, TransformerMixin

# ---- Dynamic override lists ----

def fetch_top_sites(limit=2000) -> set[str]:
    """
    Fetch the Top 1 Million list from Cisco Umbrella’s mirror and return the
    top `limit` domains.
    Source: https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip
    """
    url = 'https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip'
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    z = zipfile.ZipFile(io.BytesIO(resp.content))
    with z.open('top-1m.csv') as f:
        domains = set()
        for idx, line in enumerate(f):
            if idx >= limit:
                break
            parts = line.decode('utf-8').strip().split(',')
            if len(parts) == 2:
                domains.add(parts[1].lower())
        return domains

def fetch_phishing_domains() -> set[str]:
    """
    Fetch the OpenPhish feed of known phishing URLs.
    Source: https://openphish.com/feed.txt
    """
    url = 'https://openphish.com/feed.txt'
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    domains = set()
    for link in resp.text.splitlines():
        try:
            dom = urlparse(link.strip()).netloc.lower()
            if dom:
                domains.add(dom)
        except:
            continue
    return domains

# Build override sets at startup
try:
    SAFE_DOMAINS = fetch_top_sites(limit=2000)
    print(f"Loaded {len(SAFE_DOMAINS)} safe domains")
except Exception as e:
    print("⚠️ Failed to fetch SAFE_DOMAINS:", e)
    SAFE_DOMAINS = set()

try:
    HIGH_RISK_DOMAINS = fetch_phishing_domains()
    print(f"Loaded {len(HIGH_RISK_DOMAINS)} high-risk domains")
except Exception as e:
    print("⚠️ Failed to fetch HIGH_RISK_DOMAINS:", e)
    HIGH_RISK_DOMAINS = set()

# ---- Unpickle helpers ----
class TextStats(BaseEstimator, TransformerMixin):
    """Extract URL count, exclamations, ALL-CAPS words, and length from text."""
    def fit(self, X, y=None): return self
    def transform(self, X):
        stats = []
        for doc in X:
            urls   = len(re.findall(r'https?://', doc))
            excl   = doc.count('!')
            caps   = len(re.findall(r'\b[A-Z]{2,}\b', doc))
            length = len(doc)
            stats.append([urls, excl, caps, length])
        return np.array(stats)

def to_dense(X):
    if hasattr(X, 'toarray'):
        return X.toarray()
    return X

# ---- Email synopsis helper ----
def email_synopsis(text: str) -> str:
    """
    Return a short human-readable bullet list of why this email might be flagged.
    """
    reasons = []
    if re.search(r'\b(urgent|immediately|verify|credentials?|password|bank)\b', text, flags=re.I):
        reasons.append("Contains urgent/verification keywords")
    url_count = len(re.findall(r'https?://', text))
    if url_count:
        reasons.append(f"Includes {url_count} link{'s' if url_count>1 else ''}")
    caps = re.findall(r'\b[A-Z]{2,}\b', text)
    if len(caps) >= 3:
        reasons.append("Excessive ALL-CAPS words")
    excl = text.count('!')
    if excl >= 3:
        reasons.append(f"{excl} exclamation point{'s' if excl>1 else ''}")
    if not reasons:
        return "No obvious red flags found."
    return "• " + "\n• ".join(reasons)

# ---- App setup ----
app   = Flask(__name__)
model = load('scam_detector_robust.joblib')

# ---- Risk thresholds ----
def categorize_risk(p: float) -> str:
    if p > 0.85:   return 'High Risk'
    if p > 0.60:   return 'Medium Risk'
    return 'Low Risk'

def categorize_site_risk(p: float) -> str:
    if p >= 0.75:  return 'High Risk'
    if p >= 0.50:  return 'Medium Risk'
    return 'Low Risk'

# ---- Helpers ----
def adjust_probability(text: str, base: float) -> float:
    boost = 0.0
    if re.search(r'https?://', text): boost += 0.2
    if re.search(r'\b(urgent|suspended|verify|credentials?)\b', text, flags=re.I):
        boost += 0.2
    return min(1.0, base + boost)

def check_ip_risk(ip: str) -> tuple[str,str,float]:
    rev = '.'.join(reversed(ip.split('.'))) + '.zen.spamhaus.org'
    try:
        dns.resolver.resolve(rev, 'A')
        return 'High Risk','Listed',    1.0
    except dns.resolver.NXDOMAIN:
        return 'Low Risk', 'Not Listed', 0.0
    except:
        return 'Medium Risk','Lookup Error',0.5

def domain_age_days(domain: str) -> int|None:
    try:
        w  = whois.whois(domain)
        cd = w.creation_date
        if isinstance(cd, list): cd = cd[0]
        return (datetime.now() - cd).days
    except:
        return None

def check_site_risk(url: str) -> float:
    # Normalize + extract bare domain
    if not url.startswith(('http://','https://')):
        url = 'https://' + url
    dom = urlparse(url).netloc.lower().split(':')[0]

    # 1) Override: always-safe?
    if dom in SAFE_DOMAINS:
        return 0.0
    # 2) Override: always-high-risk?
    if dom in HIGH_RISK_DOMAINS:
        return 1.0
    # 3) Very young domains → High Risk
    age = domain_age_days(dom)
    if age is not None and age < 180:
        return 1.0
    # 4) IP‐listed hosts → High/Medium
    try:
        ip_label, _, ip_prob = check_ip_risk(socket.gethostbyname(dom))
        if ip_label == 'High Risk': return 1.0
        if ip_label == 'Medium Risk': return 0.5
    except:
        pass
    # 5) Fallback to ML model + keyword boost
    try:
        resp = requests.get(url, timeout=5, headers={'User-Agent':'Mozilla/5.0'})
        text = resp.text
    except requests.exceptions.SSLError:
        return 1.0
    except:
        text = url
    base  = model.predict_proba([text])[0][1]
    boost = 0.0
    if re.search(r'(login|signin|secure|password)', url, flags=re.I):
        boost += 0.1
    return min(1.0, base + boost)

# ---- Routes ----
@app.route('/', methods=['GET','POST'])
def index():
    # Email
    sender_email = email_text = probability = risk = synopsis = None
    verified = False
    link_results = []

    # IP
    ip_address = ip_risk = ip_list_status = ip_score = None

    # Website
    site_url = site_probability = site_risk = None

    check_type = None

    if request.method == 'POST':
        check_type = request.form.get('check_type')

        if check_type == 'email':
            sender_email = request.form.get('sender_email','').strip()
            email_text   = request.form.get('email_text','').strip()
            if email_text:
                # 1) Base email risk
                base        = model.predict_proba([email_text])[0][1]
                adj         = adjust_probability(email_text, base)
                probability = f"{adj*100:.2f}%"
                risk        = categorize_risk(adj)
                # 2) Synopsis if medium/high
                synopsis    = email_synopsis(email_text) if risk in ('Medium Risk','High Risk') else None
                # 3) Extract and evaluate any links
                urls = re.findall(r'https?://[^\s"\']+', email_text)
                for link in set(urls):
                    try:
                        p = check_site_risk(link)
                        link_results.append({
                            'url': link,
                            'risk': categorize_site_risk(p),
                            'prob': f"{p*100:.2f}%"
                        })
                    except:
                        continue

            # verify sender domain MX
            m = re.search(r'@([\w\.-]+)$', sender_email)
            if m:
                try:
                    dns.resolver.resolve(m.group(1), 'MX')
                    verified = True
                except:
                    verified = False

        elif check_type == 'ip':
            ip_address = request.form.get('ip_address','').strip()
            if ip_address:
                ip_risk, ip_list_status, ip_prob = check_ip_risk(ip_address)
                ip_score = f"{ip_prob*100:.2f}%"

        elif check_type == 'site':
            site_url = request.form.get('site_url','').strip()
            if site_url:
                p               = check_site_risk(site_url)
                site_probability = f"{p*100:.2f}%"
                site_risk        = categorize_site_risk(p)

    return render_template('index.html',
        check_type=check_type,
        sender_email=sender_email,
        email_text=email_text,
        probability=probability,
        risk=risk,
        synopsis=synopsis,
        link_results=link_results,
        verified=verified,
        ip_address=ip_address,
        ip_risk=ip_risk,
        ip_list_status=ip_list_status,
        ip_score=ip_score,
        site_url=site_url,
        site_probability=site_probability,
        site_risk=site_risk
    )

if __name__ == '__main__':
    app.run(debug=True)
