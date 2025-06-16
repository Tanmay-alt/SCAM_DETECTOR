# app.py
import re
import dns.resolver
from flask import Flask, request, render_template
from joblib import load

app = Flask(__name__)
model = load('scam_detector.joblib')

def categorize_risk(prob):
    if prob > 0.85:
        return 'High Risk'
    elif prob > 0.6:
        return 'Medium Risk'
    else:
        return 'Low Risk'

def adjust_probability(text, base_prob):
    boost = 0.0
    if re.search(r'https?://', text):
        boost += 0.2
    if re.search(r'\b(urgent|suspended|verify|credentials?)\b', text, flags=re.IGNORECASE):
        boost += 0.2
    return min(1.0, base_prob + boost)

def check_ip_risk(ip):
    rev = '.'.join(reversed(ip.split('.'))) + '.zen.spamhaus.org'
    try:
        dns.resolver.resolve(rev, 'A')
        return 'High Risk', 'Listed'
    except dns.resolver.NXDOMAIN:
        return 'Low Risk', 'Not Listed'
    except Exception:
        return 'Medium Risk', 'Lookup Error'

@app.route('/', methods=['GET','POST'])
def index():
    sender_email = email_text = probability = risk = verified = None
    ip_address = ip_risk = ip_score = None

    if request.method == 'POST':
        sender_email = request.form.get('sender_email','').strip()
        email_text   = request.form.get('email_text','').strip()

        if email_text:
            base = model.predict_proba([email_text])[0][1]
            adj  = adjust_probability(email_text, base)
            probability = f"{adj*100:.2f}%"
            risk        = categorize_risk(adj)

        # MX verify
        verified = False
        m = re.search(r'@([\w\.-]+)$', sender_email)
        if m:
            domain = m.group(1)
            try:
                dns.resolver.resolve(domain, 'MX')
                verified = True
            except:
                verified = False

        # IP check
        ip_address = request.form.get('ip_address','').strip()
        if ip_address:
            ip_risk, ip_score = check_ip_risk(ip_address)

        return render_template('index.html',
            sender_email=sender_email,
            email_text=email_text,
            probability=probability,
            risk=risk,
            verified=verified,
            ip_address=ip_address,
            ip_risk=ip_risk,
            ip_score=ip_score
        )

    return render_template('index.html')

if __name__=='__main__':
    app.run(debug=True)
