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
import json
import base64
from datetime import datetime, timezone
from urllib.parse import urlparse
from flask import Flask, request, render_template, redirect, url_for, flash, Response
from flask_caching import Cache
from joblib import load
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func
from ml_helpers import TextStats, to_dense
import google.generativeai as genai
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# ---- App & Extension Setup ----
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)

# Load configuration directly from environment variables
app.config['SECRET_KEY'] = 'a-super-secret-key-for-local-dev' # Hardcoded for local non-docker setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# A small patch for compatibility between Render's Postgres URL and SQLAlchemy
if app.config.get('SQLALCHEMY_DATABASE_URI', '').startswith("postgres://"):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace("postgres://", "postgresql://", 1)

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
cache = Cache(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# ---- Database Models ----
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    history = db.relationship('History', backref='author', lazy=True)
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

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

# ===================================================================
# ---- ALL HELPER FUNCTIONS ARE DEFINED HERE (BEFORE THEY ARE CALLED) ----
# ===================================================================

@cache.memoize(timeout=86400)
def fetch_top_sites(limit=2000) -> set[str]:
    url = 'https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip'
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    z = zipfile.ZipFile(io.BytesIO(resp.content))
    with z.open('top-1m.csv') as f:
        domains = set()
        for idx, line in enumerate(f):
            if idx >= limit: break
            parts = line.decode('utf-8').strip().split(',')
            if len(parts) == 2: domains.add(parts[1].lower())
        return domains

@cache.memoize(timeout=86400)
def fetch_phishing_domains() -> set[str]:
    url = 'https://openphish.com/feed.txt'
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    domains = set()
    for link in resp.text.splitlines():
        try:
            dom = urlparse(link.strip()).netloc.lower()
            if dom: domains.add(dom)
        except: continue
    return domains

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

@cache.memoize(timeout=3600)
def check_virustotal(resource_type: str, resource: str) -> dict:
    """Checks a resource (URL or IP) against the VirusTotal API."""
    api_key = os.environ.get('VIRUSTOTAL_API_KEY')
    if not api_key: return {}
    if resource_type == 'urls': resource = base64.urlsafe_b64encode(resource.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/{resource_type}/{resource}"
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(api_url, headers=headers, timeout=10)
        if resp.status_code == 404: return {'status': 'not_found'}
        resp.raise_for_status()
        data = resp.json().get('data', {})
        stats = data.get('attributes', {}).get('last_analysis_stats', {})
        vt_link = data.get('links', {}).get('self', '').replace('/api/v3/urls/', '/gui/url/')
        return {'status': 'found', 'malicious': stats.get('malicious', 0), 'suspicious': stats.get('suspicious', 0), 'harmless': stats.get('harmless', 0), 'undetected': stats.get('undetected', 0), 'link': vt_link}
    except requests.RequestException as e:
        print(f"VirusTotal API error: {e}")
        return {}

def generate_phishing_email(company: str, scenario: str) -> dict:
    """Uses Gemini to generate a phishing email subject and body."""
    api_key = os.environ.get('GEMINI_API_KEY')
    if not api_key:
        return {'error': 'GEMINI_API_KEY not configured.'}
    
    try:
        genai.configure(api_key=api_key)
        # UPDATED this line to use a current model name
        model = genai.GenerativeModel('gemini-1.5-flash-latest')
        
        prompt = f"""
        Create a realistic-looking but fake phishing email.
        The email should impersonate the company: "{company}".
        The scenario is: "{scenario}".
        The email must have a clear sense of urgency or curiosity to trick a user into clicking a link.
        Do NOT include any real links, instead use placeholder links like "https://{company.lower().replace(" ", "")}-support.xyz/login".
        
        Format the output as a valid JSON object with two keys: "subject" and "body".
        The body should be formatted as simple HTML. Do not wrap the JSON in markdown backticks.
        
        Example output format:
        {{
            "subject": "Example Subject",
            "body": "<p>Example HTML body.</p>"
        }}
        """
        
        response = model.generate_content(prompt)
        return json.loads(response.text)

    except Exception as e:
        print(f"Gemini API Error: {e}")
        return {'error': f'Failed to generate email content: {e}'}

# app.py (Updated send_email function)

def send_email(recipient: str, subject: str, body: str, from_name: str) -> bool:
    """Sends an email using the SendGrid API with a custom From Name."""
    api_key = os.environ.get('SENDGRID_API_KEY')
    from_email_address = os.environ.get('MAIL_FROM_EMAIL')
    if not api_key or not from_email_address:
        print("SendGrid API key or From Email not configured.")
        return False

    # The from_email parameter can be a tuple: (email_address, name)
    message = Mail(
        from_email=(from_email_address, from_name),
        to_emails=recipient,
        subject=subject,
        html_content=body)
    try:
        sg = SendGridAPIClient(api_key)
        response = sg.send(message)
        return response.status_code == 202
    except Exception as e:
        print(f"SendGrid Error: {e}")
        return False

# ===================================================================
# ---- Load ML Model & Static Sets (AFTER functions are defined) ----
# ===================================================================
model = load('scam_detector_robust.joblib')
SAFE_DOMAINS = fetch_top_sites()
HIGH_RISK_DOMAINS = fetch_phishing_domains()
print(f"Loaded {len(SAFE_DOMAINS)} safe and {len(HIGH_RISK_DOMAINS)} high-risk domains.")


# ===================================================================
# ---- Main Application Routes ----
# ===================================================================

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
                context['ip_vt_results'] = check_virustotal('ip-addresses', ip_addr)
                history_entry.details = {'status': status, 'vt_results': context['ip_vt_results']}

        elif check_type == 'site':
            url = request.form.get('site_url','').strip()
            context['site_url'] = url
            history_entry.input_data = url
            if url:
                results = check_site_risk(url)
                p = results['prob']; risk = categorize_site_risk(p)
                context.update({'site_risk': risk, 'site_probability': f"{p*100:.2f}%", 'domain_age': results['age'], 'final_url': results['final_url']})
                history_entry.risk = risk; history_entry.probability = f"{p*100:.2f}%"
                context['site_vt_results'] = check_virustotal('urls', results['final_url'])
                history_entry.details = {'age': results['age'], 'final_url': results['final_url'], 'vt_results': context['site_vt_results']}
                try:
                    domain = urlparse(results['final_url']).netloc
                    ip = socket.gethostbyname(domain)
                    context['site_geo_info'] = get_ip_geolocation(ip)
                except Exception: pass
        
        db.session.add(history_entry)
        db.session.commit()

    context['history_records'] = History.query.filter_by(user_id=current_user.id).order_by(History.timestamp.desc()).all()
    return render_template('index.html', **context)

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
    records = History.query.filter_by(user_id=current_user.id).order_by(History.timestamp.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Date (UTC)', 'Type', 'Input', 'Risk', 'Score'])
    for record in records:
        writer.writerow([record.timestamp.strftime('%Y-%m-%d %H:%M:%S'), record.check_type, record.input_data, record.risk, record.probability])
    output.seek(0)
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=analysis_history.csv"})

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = current_user.id
    total_scans = db.session.query(func.count(History.id)).filter_by(user_id=user_id).scalar()
    risk_breakdown_query = db.session.query(History.risk, func.count(History.risk)).filter_by(user_id=user_id).group_by(History.risk).all()
    top_high_risk = db.session.query(History.input_data, func.count(History.input_data).label('count')).filter_by(user_id=user_id, risk='High Risk').group_by(History.input_data).order_by(func.count(History.input_data).desc()).limit(5).all()
    risk_breakdown = {risk: count for risk, count in risk_breakdown_query}
    stats = {'total_scans': total_scans, 'high_risk_count': risk_breakdown.get('High Risk', 0), 'medium_risk_count': risk_breakdown.get('Medium Risk', 0), 'low_risk_count': risk_breakdown.get('Low Risk', 0), 'top_high_risk': top_high_risk, 'chart_data': {'labels': list(risk_breakdown.keys()), 'values': list(risk_breakdown.values())}}
    return render_template('dashboard.html', stats=stats)

# app.py (Updated /simulator route)

@app.route('/simulator', methods=['GET', 'POST'])
@login_required
def simulator():
    if request.method == 'POST':
        recipient = request.form.get('recipient_email')
        company = request.form.get('company')
        scenario = request.form.get('scenario')

        # 1. Generate the email content with AI
        email_content = generate_phishing_email(company, scenario)

        if email_content.get('error'):
            flash(f"AI Error: {email_content['error']}", 'danger')
            return redirect(url_for('simulator'))
        
        # 2. Send the generated email with the custom From Name
        subject = email_content.get('subject', f'Important Notification from {company}')
        body = email_content.get('body', '<p>Please review your account.</p>')
        from_name = f"The {company} Security Team" # Create the fake sender name
        
        if send_email(recipient, subject, body, from_name):
            flash(f'Phishing simulation email has been sent to {recipient}!', 'success')
        else:
            flash('Failed to send the email. Please check server logs.', 'danger')

        return redirect(url_for('simulator'))

    return render_template('phishing_simulator.html')