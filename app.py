import streamlit as st
import requests
import socket
import whois
import re
from urllib.parse import urlparse, urljoin
from datetime import datetime
import time
import ssl
from OpenSSL import crypto
import json
import os

# --- CONFIGURATION & SETUP ---
# Use a session state to cache the local threat database to avoid reloading from disk on every interaction.
if 'local_threat_db' not in st.session_state:
    st.session_state.local_threat_db = set()

# --- LOCAL THREAT INTELLIGENCE DATABASE ---
def load_local_threat_db():
    """
    Loads a local phishing URL database from a JSON file.
    This approach avoids real-time API calls and their rate-limiting issues.
    """
    if st.session_state.local_threat_db: # Don't reload if already loaded
        return

    db_file = 'local_phishtank_db.json'
    
    # For demonstration, we create a sample DB if it doesn't exist.
    # INSTRUCTIONS FOR YOUR PROJECT:
    # 1. Download the full database from http://data.phishtank.com/data/online-valid.json
    # 2. Save it in the same directory as your script with the name 'local_phishtank_db.json'
    # 3. The script will then use your comprehensive local file instead of this small sample.
    if not os.path.exists(db_file):
        st.info("Local threat database not found. Creating a sample database for demonstration.")
        sample_db = [
            {"url": "http://paypal.com.security-check.info/login"},
            {"url": "http://micros0ft.com/update-account"},
            {"url": "http://chase-bank-verify.xyz/secure"}
        ]
        # We only need the URLs for our set
        url_list = [item['url'] for item in sample_db]
        with open(db_file, 'w') as f:
            json.dump(url_list, f)
    
    try:
        with open(db_file, 'r') as f:
            urls = json.load(f)
            # If the file is from PhishTank, it's a list of dicts. If it's our simplified one, it's a list of strings.
            if urls and isinstance(urls[0], dict):
                 st.session_state.local_threat_db = {item['url'] for item in urls}
            else:
                 st.session_state.local_threat_db = set(urls)
        st.success(f"Loaded {len(st.session_state.local_threat_db)} threats from local database.")
    except (IOError, json.JSONDecodeError) as e:
        st.error(f"Error loading local threat database: {e}")
        st.session_state.local_threat_db = set()

# --- CORE ANALYSIS ENGINE ---

def expand_shortened_url(url):
    """Follows redirects to find the final destination of a shortened URL."""
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        with requests.Session() as session:
            response = session.get(url, headers=headers, timeout=10, allow_redirects=True)
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
        report.append(f"⚠️ **Redirect Detected:** URL redirects to `{final_url}`. Analyzing final destination.")
        score += 10

    if final_url in st.session_state.local_threat_db:
        report.append("🚨 **CRITICAL:** URL found in the local phishing threat database.")
        score += 90

    try:
        parsed_url = urlparse(final_url)
        hostname = parsed_url.hostname
        if not hostname:
            return 0, ["❌ **Invalid URL:** Could not parse a valid hostname."]
    except Exception:
        return 0, ["❌ **Invalid URL:** Could not be parsed."]

    domain_age = get_domain_age_days(hostname)
    if domain_age is not None:
        if domain_age < 90:
            report.append(f"🚨 **High Risk:** Domain is very new ({domain_age} days old).")
            score += 30
        elif domain_age < 365:
            report.append(f"⚠️ **Suspicious:** Domain is less than a year old ({domain_age} days).")
            score += 15
        else:
            report.append(f"✅ **OK:** Domain is well-established ({domain_age} days old).")
            score -= 10

    if parsed_url.scheme != 'https':
        report.append("🚨 **High Risk:** Site does not use HTTPS.")
        score += 20
    else:
        report.append("✅ **OK:** Site uses HTTPS.")

    suspicious_keywords = ['login', 'verify', 'account', 'update', 'secure', 'signin', 'banking', 'confirm', 'password']
    if any(kw in final_url.lower() for kw in suspicious_keywords):
        report.append("⚠️ **Suspicious:** URL contains keywords often used in phishing.")
        score += 15
    
    if hostname.count('.') > 3:
        report.append("⚠️ **Suspicious:** URL has an excessive number of subdomains.")
        score += 10

    brands = ["microsoft", "google", "apple", "paypal", "amazon", "facebook", "netflix", "chase"]
    for brand in brands:
        if brand in hostname and not hostname.endswith(f".{brand}.com"):
            report.append(f"🚨 **High Risk:** Potential brand impersonation of '{brand}' in the domain.")
            score += 40
            break

    final_score = max(0, min(100, score))
    return final_score, report

def analyze_text(text):
    """Analyzes a block of text for phishing indicators based on content and structure."""
    report = []
    score = 0
    
    keyword_sets = {
        "Urgency/Threat": ['urgent', 'action required', 'suspended', 'limited time', 'verify immediately'],
        "Financial/Prize": ['winner', 'claim', 'prize', 'free gift', 'invoice', 'payment'],
    }
    for category, keywords in keyword_sets.items():
        found = [kw for kw in keywords if kw in text.lower()]
        if found:
            report.append(f"⚠️ **{category} Keywords:** Found suspicious words: `{', '.join(found)}`.")
            score += 20

    sender_pattern = re.search(r'from:\s*".*?"\s*<(.+?)>', text.lower())
    if sender_pattern:
        sender_email = sender_pattern.group(1)
        brands = ["paypal", "microsoft", "bank", "apple", "google"]
        for brand in brands:
            if brand in text.lower()[:text.lower().find(sender_email)] and brand not in sender_email:
                report.append(f"🚨 **High Risk:** Potential sender spoofing detected.")
                score += 35
                break

    words = text.split()
    if len(words) > 10:
        num_caps = sum(1 for word in words if word.isupper() and len(word) > 2)
        if (num_caps / len(words)) > 0.1:
            report.append("⚠️ **Suspicious Structure:** Message contains excessive capitalization.")
            score += 10

    links = list(set(re.findall(r'https?://[^\s/$.?#].[^\s]*', text)))
    if links:
        report.append(f"✅ **Links Found:** Analyzing {len(links)} unique URL(s)...")
        highest_link_score = 0
        for link in links:
            link_score, _ = analyze_url(link)
            if link_score > highest_link_score:
                highest_link_score = link_score
        
        if highest_link_score > 0:
            report.append(f"🚨 **High Risk Link Detected:** At least one link was flagged as high risk (score: {highest_link_score}).")
            score += highest_link_score
    else:
        report.append("✅ **No Links Found:** No URLs were detected in the text.")

    final_score = max(0, min(100, score))
    return final_score, report

# --- STREAMLIT UI ---
st.set_page_config(layout="wide", page_title="Phishing Detector Pro")
st.title("🛡️ Phishing Detector Pro")
st.markdown("A robust, file-based tool to detect phishing risks in URLs and text messages.")

load_local_threat_db()

tab1, tab2, tab3 = st.tabs(["URL Analysis", "Text/Message Analysis", "Methodology"])

with tab1:
    st.header("Analyze a Single Website URL")
    url_input = st.text_input("Enter a full URL to analyze:", "http://paypal.com.security-check.info/login")
    
    if st.button("Analyze URL"):
        if not url_input:
            st.warning("Please enter a URL.")
        else:
            with st.spinner(f"Performing deep analysis on `{url_input}`..."):
                score, report = analyze_url(url_input)
            
            st.subheader("Analysis Report")
            if score > 75: level, color = "High Risk / Likely Phishing", "red"
            elif score > 40: level, color = "Suspicious", "orange"
            else: level, color = "Likely Safe", "green"
                
            st.markdown(f"### Overall Risk Score: <span style='color:{color};'>{score}/100 ({level})</span>", unsafe_allow_html=True)
            with st.expander("Show Detailed Breakdown", expanded=True):
                for item in report:
                    st.markdown(f"- {item}")

with tab2:
    st.header("Analyze a Suspicious Text or Email")
    text_input = st.text_area("Paste the full text of the suspicious message below:", height=250, 
    placeholder="""Example: From: "PayPal Support" <support-team@pp-alerts.xyz>...""")
    
    if st.button("Analyze Text"):
        if not text_input:
            st.warning("Please enter some text to analyze.")
        else:
            with st.spinner("Analyzing text content and embedded links..."):
                score, report = analyze_text(text_input)

            st.subheader("Text Analysis Report")
            if score > 75: level, color = "High Risk / Likely Phishing", "red"
            elif score > 40: level, color = "Suspicious", "orange"
            else: level, color = "Likely Safe", "green"
            
            st.markdown(f"### Overall Risk Score: <span style='color:{color};'>{score}/100 ({level})</span>", unsafe_allow_html=True)
            with st.expander("Show Detailed Breakdown", expanded=True):
                for item in report:
                    st.markdown(f"- {item}")

with tab3:
    st.header("Analysis Methodology")
    st.markdown("""
    This tool uses a multi-layered heuristic analysis approach to determine the risk score of a given URL or text message. It does **not** rely on a single factor but combines several indicators to make a more accurate assessment.

    ### Key Analysis Techniques:

    1.  **File-Based Threat Intelligence:**
        - The application uses a local JSON file (`local_phishtank_db.json`) as a threat database.
        - This provides a rapid, offline check for known phishing URLs without hitting API rate limits.
        - A URL found in this database is immediately flagged as critical risk.

    2.  **Domain Age Analysis (WHOIS Lookup):**
        - Phishing websites are often hosted on newly registered domains.
        - The tool performs a `whois` lookup to find the domain's creation date.
        - Domains created less than 90 days ago are considered high-risk.

    3.  **URL Structural Analysis:**
        - **Keywords:** Scans for common phishing keywords (e.g., `login`, `secure`, `verify`) in the URL.
        - **Subdomains:** Checks for an excessive number of subdomains (e.g., `login.microsoft.com.security.net`), a common tactic to confuse users.
        - **HTTPS:** Verifies that the site uses a secure HTTPS connection. While many phishing sites now use HTTPS, its absence is a major red flag.

    4.  **Brand Impersonation & Typosquatting:**
        - The tool checks if the domain name contains well-known brand names (like `google`, `paypal`) in a suspicious manner (e.g., `paypal-security.com` instead of `paypal.com`).
        - This helps catch one of the most common phishing techniques.

    5.  **Text Content Analysis (for messages):**
        - **Urgency & Threat Keywords:** Scans for words designed to create panic and urgency.
        - **Sender Spoofing:** Looks for mismatches between the sender's display name and their actual email address.
        - **Embedded Link Analysis:** Automatically extracts all URLs from the text and performs the full URL analysis on each one. The highest risk score from any link is factored into the overall text score.
    """)
