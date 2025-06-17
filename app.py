import re
import io
import zipfile
import numpy as np
import dns.resolver
import requests
import whois
import socket
import os
import csv
from datetime import datetime, timezone
from urllib.parse import urlparse
from flask import Flask, request, render_template, redirect, url_for, flash, Response
from flask_caching import Cache
from joblib import load
from sklearn.base import BaseEstimator, TransformerMixin
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash

# ---- App & Extension Setup ----
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a-very-secret-key-that-should-be-changed'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config.from_mapping({
    "CACHE_TYPE": "simple",
    "CACHE_DEFAULT_TIMEOUT": 3600
})

db = SQLAlchemy(app)
cache = Cache(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Redirect to /login if user tries to access a protected page

# ---- Database Models ----
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    history = db.relationship('History', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    check_type = db.Column(db.String(50), nullable=False)
    input_data = db.Column(db.String(500), nullable=False)
    risk = db.Column(db.String(50))
    probability = db.Column(db.String(20))
    details = db.Column(db.JSON)
    timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---- Dynamic override lists ----
@cache.memoize(timeout=86400)
def fetch_top_sites(limit=2000) -> set[str]:
    # ... (rest of the function is unchanged)
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

@cache.memoize(timeout=86400)
def fetch_phishing_domains() -> set[str]:
    # ... (rest of the function is unchanged)
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

# ---- Unpickle helpers ----
class TextStats(BaseEstimator, TransformerMixin):
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

def to_dense(X): return X.toarray() if hasattr(X, 'toarray') else X

# ---- Analysis Helpers (unchanged from before) ----
def email_synopsis(text: str) -> str:
    reasons = []
    if re.search(r'\b(urgent|immediately|verify|credentials?|password|bank)\b', text, flags=re.I): reasons.append("Contains urgent/verification keywords")
    url_count = len(re.findall(r'https?://', text));
    if url_count: reasons.append(f"Includes {url_count} link{'s' if url_count>1 else ''}")
    if len(re.findall(r'\b[A-Z]{2,}\b', text)) >= 3: reasons.append("Excessive ALL-CAPS words")
    excl = text.count('!');
    if excl >= 3: reasons.append(f"{excl} exclamation point{'s' if excl>1 else ''}")
    return "• " + "\n• ".join(reasons) if reasons else "No obvious red flags found."

def categorize_risk(p: float) -> str:
    if p > 0.85: return 'High Risk'
    if p > 0.60: return 'Medium Risk'
    return 'Low Risk'

def categorize_site_risk(p: float) -> str:
    if p >= 0.75: return 'High Risk'
    if p >= 0.50: return 'Medium Risk'
    return 'Low Risk'

@cache.memoize(timeout=86400)
def get_ip_geolocation(ip: str) -> dict:
    try:
        resp = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        resp.raise_for_status()
        data = resp.json()
        if data.get('status') == 'success':
            return {'country': data.get('country', 'N/A'), 'city': data.get('city', 'N/A'), 'isp': data.get('isp', 'N/A')}
    except requests.exceptions.RequestException as e:
        print(f"Geolocation lookup failed for {ip}: {e}")
    return {}

def adjust_probability(text: str, base: float) -> float:
    boost = 0.0
    if re.search(r'https?://', text): boost += 0.2
    if re.search(r'\b(urgent|suspended|verify|credentials?)\b', text, flags=re.I): boost += 0.2
    return min(1.0, base + boost)

@cache.memoize(timeout=3600)
def check_ip_risk(ip: str) -> tuple[str,str,float]:
    rev = '.'.join(reversed(ip.split('.'))) + '.zen.spamhaus.org'
    try:
        dns.resolver.resolve(rev, 'A')
        return 'High Risk','Listed', 1.0
    except dns.resolver.NXDOMAIN:
        return 'Low Risk', 'Not Listed', 0.0
    except:
        return 'Medium Risk','Lookup Error',0.5

@cache.memoize(timeout=86400)
def domain_age_days(domain: str) -> int|None:
    try:
        w = whois.whois(domain)
        cd = w.creation_date
        if isinstance(cd, list): cd = cd[0]
        return (datetime.now() - cd).days
    except:
        return None

@cache.memoize(timeout=3600)
def check_site_risk(url: str) -> dict:
    result = {'prob': 0.0, 'final_url': url, 'age': None}
    if not url.startswith(('http://','https://')): url = 'https://' + url
    try: dom = urlparse(url).netloc.lower().split(':')[0]
    except ValueError: result['prob'] = 0.5; return result
    if dom in SAFE_DOMAINS: return result
    if dom in HIGH_RISK_DOMAINS: result['prob'] = 1.0; return result
    age = domain_age_days(dom); result['age'] = age
    if age is not None and age < 180: result['prob'] = 1.0; return result
    final_url, text = url, url
    try:
        resp = requests.get(url, timeout=5, headers={'User-Agent':'Mozilla/5.0'}, allow_redirects=True)
        resp.raise_for_status(); final_url = resp.url; text = resp.text
        final_dom = urlparse(final_url).netloc.lower().split(':')[0]
        if final_dom != dom: result['age'] = domain_age_days(final_dom)
    except requests.exceptions.SSLError: result['prob'] = 1.0; return result
    except requests.RequestException: pass
    result['final_url'] = final_url
    try:
        ip_label, _, ip_prob = check_ip_risk(socket.gethostbyname(dom))
        if ip_label == 'High Risk': result['prob'] = 1.0; return result
        if ip_label == 'Medium Risk': result['prob'] = max(result['prob'], 0.5)
    except: pass
    base_prob = model.predict_proba([text])[0][1]; boost = 0.0
    if re.search(r'(login|signin|secure|password)', url, flags=re.I): boost += 0.1
    result['prob'] = min(1.0, base_prob + boost)
    return result

# ---- Load ML Model & Static Sets ----
model = load('scam_detector_robust.joblib')
SAFE_DOMAINS = fetch_top_sites()
HIGH_RISK_DOMAINS = fetch_phishing_domains()
print(f"Loaded {len(SAFE_DOMAINS)} safe and {len(HIGH_RISK_DOMAINS)} high-risk domains.")

# ---- Main Application Routes ----
@app.route('/', methods=['GET','POST'])
@login_required
def index():
    context = {'check_type': None}
    if request.method == 'POST':
        check_type = request.form.get('check_type')
        context['check_type'] = check_type
        history_entry = History(user_id=current_user.id, check_type=check_type, details={})

        if check_type == 'email':
            sender = request.form.get('sender_email','').strip()
            text = request.form.get('email_text','').strip()
            context.update({'sender_email': sender, 'email_text': text})
            history_entry.input_data = sender
            
            if text:
                base = model.predict_proba([text])[0][1]; adj = adjust_probability(text, base)
                risk = categorize_risk(adj); prob = f"{adj*100:.2f}%"
                context.update({'risk': risk, 'probability': prob})
                history_entry.risk = risk; history_entry.probability = prob
                if risk in ('Medium Risk','High Risk'): context['synopsis'] = email_synopsis(text)
                
                urls = re.findall(r'https?://[^\s"<>\']+', text)
                context['link_results'] = [check_site_risk(link) for link in set(urls)]

            m = re.search(r'@([\w\.-]+)$', sender)
            if m:
                domain = m.group(1)
                try:
                    dns.resolver.resolve(domain, 'MX'); context['verified'] = True
                    ip = socket.gethostbyname(domain)
                    context['sender_geo_info'] = get_ip_geolocation(ip)
                except Exception: context['verified'] = False

        elif check_type == 'ip':
            ip_addr = request.form.get('ip_address','').strip()
            context['ip_address'] = ip_addr
            history_entry.input_data = ip_addr
            if ip_addr:
                risk, status, prob = check_ip_risk(ip_addr)
                context.update({'ip_risk': risk, 'ip_list_status': status, 'ip_score': f"{prob*100:.2f}%"})
                context['ip_geo_info'] = get_ip_geolocation(ip_addr)
                history_entry.risk = risk; history_entry.probability = f"{prob*100:.2f}%"
                history_entry.details = {'status': status}

        elif check_type == 'site':
            url = request.form.get('site_url','').strip()
            context['site_url'] = url
            history_entry.input_data = url
            if url:
                results = check_site_risk(url)
                p = results['prob']; risk = categorize_site_risk(p)
                context.update({'site_risk': risk, 'site_probability': f"{p*100:.2f}%", 'domain_age': results['age'], 'final_url': results['final_url']})
                history_entry.risk = risk; history_entry.probability = f"{p*100:.2f}%"
                history_entry.details = {'age': results['age'], 'final_url': results['final_url']}
                try:
                    domain = urlparse(results['final_url']).netloc
                    ip = socket.gethostbyname(domain)
                    context['site_geo_info'] = get_ip_geolocation(ip)
                except Exception: pass
        
        db.session.add(history_entry)
        db.session.commit()

    context['history_records'] = History.query.filter_by(user_id=current_user.id).order_by(History.timestamp.desc()).all()
    return render_template('index.html', **context)

# ---- Authentication Routes ----
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user, remember=True)
            return redirect(url_for('index'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        if User.query.filter_by(username=request.form['username']).first():
            flash('Username already exists', 'warning')
            return redirect(url_for('register'))
        new_user = User(username=request.form['username'])
        new_user.set_password(request.form['password'])
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/export/csv')
@login_required
def export_csv():
    """Exports the user's history to a CSV file."""
    records = History.query.filter_by(user_id=current_user.id).order_by(History.timestamp.desc()).all()
    
    # Use StringIO to create the CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)

    # Write the header row
    writer.writerow(['Date (UTC)', 'Type', 'Input', 'Risk', 'Score'])

    # Write data rows
    for record in records:
        writer.writerow([
            record.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            record.check_type,
            record.input_data,
            record.risk,
            record.probability
        ])

    # Seek to the beginning of the stream
    output.seek(0)

    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=analysis_history.csv"}
    )


if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Create database tables if they don't exist
    app.run(debug=True)