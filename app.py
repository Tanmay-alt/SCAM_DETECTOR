import re
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

# ---- Unpickle helpers ----
class TextStats(BaseEstimator, TransformerMixin):
    """Extract URL count, exclamations, ALL-CAPS words, and length from text."""
    def fit(self, X, y=None):
        return self
    def transform(self, X):
        stats = []
        for doc in X:
            urls = len(re.findall(r'https?://', doc))
            excl = doc.count('!')
            caps = len(re.findall(r'\b[A-Z]{2,}\b', doc))
            length = len(doc)
            stats.append([urls, excl, caps, length])
        return np.array(stats)

def to_dense(X):
    """Convert sparse matrix to dense, if needed."""
    if hasattr(X, 'toarray'):
        return X.toarray()
    return X

# ---- App setup ----
app = Flask(__name__)
model = load('scam_detector_robust.joblib')

# ---- Common logic ----
def categorize_risk(p: float) -> str:
    if p > 0.85: return 'High Risk'
    if p > 0.6:  return 'Medium Risk'
    return 'Low Risk'

def adjust_probability(text: str, base: float) -> float:
    boost = 0.0
    if re.search(r'https?://', text): boost += 0.2
    if re.search(r'\b(urgent|suspended|verify|credentials?)\b', text, flags=re.I): boost += 0.2
    return min(1.0, base + boost)

def check_ip_risk(ip: str):
    rev = '.'.join(reversed(ip.split('.'))) + '.zen.spamhaus.org'
    try:
        dns.resolver.resolve(rev, 'A')
        return 'High Risk','Listed'
    except dns.resolver.NXDOMAIN:
        return 'Low Risk','Not Listed'
    except:
        return 'Medium Risk','Lookup Error'

def domain_age_days(domain: str) -> int|None:
    try:
        w = whois.whois(domain)
        cd = w.creation_date
        if isinstance(cd, list): cd = cd[0]
        return (datetime.now() - cd).days
    except:
        return None

def check_site_risk(url: str) -> float:
    if not url.startswith(('http://','https://')):
        url = 'https://' + url
    # SSL error => high risk
    try:
        resp = requests.get(url, timeout=5, headers={'User-Agent':'Mozilla/5.0'})
        text = resp.text
    except requests.exceptions.SSLError:
        return 1.0
    except:
        text = url
    base = model.predict_proba([text])[0][1]
    boost = 0.0
    if re.search(r'(login|signin|secure|password)', url, flags=re.I): boost += 0.1
    # young domain boost
    dom = urlparse(url).netloc.split(':')[0]
    age = domain_age_days(dom)
    if age is not None and age < 180: boost += 0.2
    # IP reputation boost
    try:
        ip = socket.gethostbyname(dom)
        ipr, _ = check_ip_risk(ip)
        if ipr == 'High Risk': boost += 0.3
        elif ipr == 'Medium Risk': boost += 0.1
    except:
        pass
    return min(1.0, base + boost)

# ---- Routes ----
@app.route('/', methods=['GET','POST'])
def index():
    sender_email = email_text = probability = risk = None
    verified = False
    ip_address = ip_risk = ip_score = None
    site_url = site_probability = site_risk = None
    check_type = None

    if request.method == 'POST':
        check_type = request.form.get('check_type')

        if check_type == 'email':
            sender_email = request.form.get('sender_email','').strip()
            email_text   = request.form.get('email_text','').strip()
            if email_text:
                base = model.predict_proba([email_text])[0][1]
                adj = adjust_probability(email_text, base)
                probability = f"{adj*100:.2f}%"
                risk = categorize_risk(adj)
            m = re.search(r'@([\w\.-]+)$', sender_email)
            if m:
                try: dns.resolver.resolve(m.group(1),'MX'); verified = True
                except: verified = False

        elif check_type == 'ip':
            ip_address = request.form.get('ip_address','').strip()
            if ip_address:
                ip_risk, ip_score = check_ip_risk(ip_address)

        elif check_type == 'site':
            site_url = request.form.get('site_url','').strip()
            if site_url:
                p = check_site_risk(site_url)
                site_probability = f"{p*100:.2f}%"
                site_risk = categorize_risk(p)

    return render_template('index.html',
        check_type=check_type,
        sender_email=sender_email,
        email_text=email_text,
        probability=probability,
        risk=risk,
        verified=verified,
        ip_address=ip_address,
        ip_risk=ip_risk,
        ip_score=ip_score,
        site_url=site_url,
        site_probability=site_probability,
        site_risk=site_risk
    )

if __name__=='__main__':
    app.run(debug=True)
