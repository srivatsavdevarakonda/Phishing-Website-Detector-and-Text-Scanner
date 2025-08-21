from flask import Flask, request, jsonify, render_template
import requests
import socket
import whois
import re
from urllib.parse import urlparse
from datetime import datetime
import json
import os

app = Flask(__name__)

# --- LOCAL THREAT INTELLIGENCE DATABASE ---
LOCAL_THREAT_DB = set()

def load_local_threat_db():
    """Loads a local phishing URL database from a JSON file."""
    global LOCAL_THREAT_DB
    db_file = 'local_phishtank_db.json'
    
    if not os.path.exists(db_file):
        print("INFO: Local threat database not found. Creating a sample database.")
        sample_db = [
            "http://paypal.com.security-check.info/login",
            "http://micros0ft.com/update-account",
            "http://chase-bank-verify.xyz/secure"
        ]
        with open(db_file, 'w') as f:
            json.dump(sample_db, f)

    try:
        with open(db_file, 'r') as f:
            urls = json.load(f)
            LOCAL_THREAT_DB = set(urls)
        print(f"SUCCESS: Loaded {len(LOCAL_THREAT_DB)} threats from local database.")
    except (IOError, json.JSONDecodeError) as e:
        print(f"ERROR: Could not load local threat database: {e}")

# --- CORE ANALYSIS ENGINE ---

def expand_shortened_url(url):
    """Follows redirects to find the final destination of a shortened URL."""
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        return response.url
    except requests.RequestException:
        return url

def get_domain_age_days(hostname):
    """Gets the age of a domain in days."""
    try:
        domain_info = whois.whois(hostname)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            return (datetime.now() - creation_date).days
    except Exception:
        return None

def analyze_url(url):
    """Performs a comprehensive analysis of a single URL and returns a score and report."""
    report = []
    score = 0

    final_url = expand_shortened_url(url)
    if final_url != url:
        report.append(f"Redirect Detected: URL redirects to `{final_url}`. Analyzing final destination.")
        score += 10

    if final_url in LOCAL_THREAT_DB:
        report.append("CRITICAL: URL found in the local phishing threat database.")
        score += 90

    try:
        parsed_url = urlparse(final_url)
        hostname = parsed_url.hostname
        if not hostname:
            return 0, ["Invalid URL: Could not parse a valid hostname."]
    except Exception:
        return 0, ["Invalid URL: Could not be parsed."]

    domain_age = get_domain_age_days(hostname)
    if domain_age is not None:
        if domain_age < 90:
            report.append(f"High Risk: Domain is very new ({domain_age} days old).")
            score += 30
        elif domain_age < 365:
            report.append(f"Suspicious: Domain is less than a year old ({domain_age} days).")
            score += 15
        else:
            report.append(f"OK: Domain is well-established ({domain_age} days old).")
            score -= 10

    if parsed_url.scheme != 'https':
        report.append("High Risk: Site does not use HTTPS.")
        score += 20
    else:
        report.append("OK: Site uses HTTPS.")

    suspicious_keywords = ['login', 'verify', 'account', 'update', 'secure', 'signin', 'banking', 'confirm', 'password']
    if any(kw in final_url.lower() for kw in suspicious_keywords):
        report.append("Suspicious: URL contains keywords often used in phishing.")
        score += 15
    
    if hostname.count('.') > 3:
        report.append("Suspicious: URL has an excessive number of subdomains.")
        score += 10

    brands = ["microsoft", "google", "apple", "paypal", "amazon", "facebook", "netflix", "chase"]
    for brand in brands:
        if brand in hostname and not hostname.endswith(f".{brand}.com"):
            report.append(f"High Risk: Potential brand impersonation of '{brand}' in the domain.")
            score += 40
            break

    final_score = max(0, min(100, score))
    return final_score, report

def analyze_text(text):
    """Analyzes a block of text for phishing indicators."""
    report = []
    score = 0
    
    keyword_sets = {
        "Urgency/Threat": ['urgent', 'action required', 'suspended', 'limited time', 'verify immediately'],
        "Financial/Prize": ['winner', 'claim', 'prize', 'free gift', 'invoice', 'payment'],
    }
    for category, keywords in keyword_sets.items():
        found = [kw for kw in keywords if kw in text.lower()]
        if found:
            report.append(f"{category} Keywords: Found suspicious words: `{', '.join(found)}`.")
            score += 20

    sender_pattern = re.search(r'from:\s*".*?"\s*<(.+?)>', text.lower())
    if sender_pattern:
        sender_email = sender_pattern.group(1)
        brands = ["paypal", "microsoft", "bank", "apple", "google"]
        for brand in brands:
            if brand in text.lower()[:text.lower().find(sender_email)] and brand not in sender_email:
                report.append("High Risk: Potential sender spoofing detected.")
                score += 35
                break

    links = list(set(re.findall(r'https?://[^\s/$.?#].[^\s]*', text)))
    if links:
        report.append(f"Links Found: Analyzing {len(links)} unique URL(s)...")
        highest_link_score = 0
        for link in links:
            link_score, _ = analyze_url(link)
            if link_score > highest_link_score:
                highest_link_score = link_score
        
        if highest_link_score > 0:
            report.append(f"High Risk Link Detected: At least one link was flagged as high risk (score: {highest_link_score}).")
            score += highest_link_score
    else:
        report.append("No Links Found: No URLs were detected in the text.")

    final_score = max(0, min(100, score))
    return final_score, report

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    analysis_type = data.get('type')
    
    if analysis_type == 'url':
        input_data = data.get('url_input')
        if not input_data:
            return jsonify({'error': 'URL input is empty'}), 400
        score, report = analyze_url(input_data)
        
    elif analysis_type == 'text':
        input_data = data.get('text_input')
        if not input_data:
            return jsonify({'error': 'Text input is empty'}), 400
        score, report = analyze_text(input_data)
        
    else:
        return jsonify({'error': 'Invalid analysis type'}), 400

    return jsonify({'score': score, 'report': report})


if __name__ == '__main__':
    load_local_threat_db()
    app.run(debug=True)