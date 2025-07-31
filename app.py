import streamlit as st
import requests
import socket
import whois
import re
from urllib.parse import urlparse
from datetime import datetime
import concurrent.futures
import time
import ssl
from OpenSSL import crypto

# --- INTELLIGENT ANALYSIS ENGINE ---

def levenshtein_distance(s1, s2):
    """Calculates the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

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

def check_typosquatting(hostname):
    """
    Performs an intelligent typosquatting check using Levenshtein distance.
    """
    legitimate_domains = [
        "microsoft.com", "google.com", "apple.com", "paypal.com",
        "amazon.com", "facebook.com", "instagram.com", "netflix.com",
        "bankofamerica.com", "chase.com", "wellsfargo.com"
    ]
    
    # Remove TLD like .com, .org for a cleaner comparison
    hostname_base = '.'.join(hostname.split('.')[:-1])
    
    for legit_domain in legitimate_domains:
        legit_base = '.'.join(legit_domain.split('.')[:-1])
        distance = levenshtein_distance(hostname_base, legit_base)
        
        # If the domains are not identical, but the distance is very small, it's a red flag.
        if 0 < distance <= 2:
            return f"Warning: '{hostname}' is suspiciously similar to '{legit_domain}' (edit distance: {distance})."
            
    return "No lookalike or typosquatting detected for popular brands."


def get_ssl_certificate_info(hostname):
    """Fetches and parses the real SSL certificate for a given hostname."""
    try:
        cert_pem = ssl.get_server_certificate((hostname, 443))
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
        issuer_components = dict(cert.get_issuer().get_components())
        valid_from_str = cert.get_notBefore().decode('ascii')
        valid_to_str = cert.get_notAfter().decode('ascii')
        return {
            "issuer": issuer_components.get(b'O', b'N/A').decode(),
            "valid_from": datetime.strptime(valid_from_str, '%Y%m%d%H%M%SZ'),
            "valid_to": datetime.strptime(valid_to_str, '%Y%m%d%H%M%SZ'),
            "error": None
        }
    except Exception as e:
        return {"error": f"SSL cert fetch failed: {e}"}

def get_technical_details(url):
    """Gathers various technical details about the URL using real-time checks."""
    details = {"url": url}
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if not hostname: return {"error": "Could not parse hostname from URL."}
        details['hostname'] = hostname
        details['uses_https'] = parsed_url.scheme == 'https'
        try:
            domain_info = whois.whois(hostname)
            details['domain_creation_date'] = domain_info.creation_date
        except Exception:
            details['domain_creation_date'] = None
        if details['uses_https']:
            details['ssl_info'] = get_ssl_certificate_info(hostname)
        else:
            details['ssl_info'] = {"error": "Site does not use HTTPS."}
        return details
    except Exception as e:
        return {"error": str(e)}

def calculate_risk_score(details):
    """Calculates a weighted risk score including the intelligent typosquatting check."""
    score, factors = 0, []
    hostname = details.get('hostname', '')
    typo_result = check_typosquatting(hostname)
    if "Warning" in typo_result:
        score += 40
        factors.append("High-risk typosquatting pattern detected (+40)")

    creation_date = details.get('domain_creation_date')
    if creation_date:
        if isinstance(creation_date, list): creation_date = creation_date[0]
        age_days = (datetime.now() - creation_date).days
        if age_days < 180:
            score += 25; factors.append(f"Domain is very new ({age_days} days old) (+25)")
        elif age_days > 730:
            score -= 15; factors.append("Domain is well-established (>2 years old) (-15)")

    ssl_info = details.get('ssl_info', {})
    if not ssl_info.get("error"):
        ssl_age_days = (datetime.now() - ssl_info['valid_from']).days
        if ssl_age_days < 90:
            score += 15; factors.append(f"SSL certificate is new ({ssl_age_days} days old) (+15)")
    else:
        score += 10; factors.append("Site does not use HTTPS or SSL cert is invalid (+10)")

    if '@' in details['url']:
        score += 20; factors.append("URL contains '@' symbol (+20)")

    final_score = max(0, min(100, score))
    return final_score, factors, typo_result

# --- UI-SPECIFIC FUNCTIONS ---
PORT_SERVICE_MAP = { 80: "HTTP", 443: "HTTPS", 21: "FTP", 22: "SSH" }
def port_scan(target, port_range):
    open_ports, closed_ports, error_msg = [], [], None
    try:
        target_ip = socket.gethostbyname(target)
        def scan_port(port):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((target_ip, port)) == 0: open_ports.append(port)
                else: closed_ports.append(port)
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(scan_port, range(port_range[0], port_range[1] + 1))
    except socket.gaierror:
        error_msg = f"Error: Could not resolve domain '{target}'."
    return sorted(open_ports), sorted(closed_ports), error_msg
def discover_paths(url): return [f"{url}/", f"{url}/assets/"]

# --- Streamlit App UI ---
st.set_page_config(layout="centered", page_title="Phishing Detector")
st.title("🛡️ Phishing Website Detector, Port & Text Scanner")
st.markdown("Analyze a website, suspicious text, or message for phishing risk!")

tab1, tab2, tab3 = st.tabs(["Website/Domain Analysis", "Text/Message Analysis", "Phishing Self-Test"])

with tab1:
    st.header("Website Analysis")
    url_to_analyze = st.text_input("Enter URL to analyze:", "https://micr0s0ft.com")
    perform_scan = st.checkbox("Perform Port Scan (for open ports)", value=False)
    if perform_scan:
        col1, col2 = st.columns(2)
        port_start, port_end = col1.number_input("Start Port", 1, 65535, 1), col2.number_input("End Port", 1, 65535, 1024)

    if st.button("Analyze Website"):
        with st.spinner(f"Performing deep analysis of {url_to_analyze}..."):
            tech_details = get_technical_details(url_to_analyze)
            risk_score, risk_factors, typo_result = calculate_risk_score(tech_details)
            paths = discover_paths(url_to_analyze.strip('/'))

            open_ports, closed_ports, port_error = (None, None, None)
            if perform_scan:
                open_ports, closed_ports, port_error = port_scan(tech_details.get('hostname'), (port_start, port_end))

            st.subheader("Analysis Results")
            col1, col2 = st.columns(2)
            col1.metric("Risk Score", f"{risk_score}/100")

            with col2:
                st.write("**Prediction**")
                if risk_score > 60: color, text = "#dc3545", "High Risk / Phishing"
                elif risk_score > 30: color, text = "#ffc107", "Potentially Suspicious"
                else: color, text = "#28a745", "Potentially Safe"
                st.markdown(f"""<div style="display: flex; align-items: center; gap: 8px;"><div style="width: 15px; height: 15px; background-color: {color}; border-radius: 50%;"></div><span style="color: {color}; font-weight: bold;">{text}</span></div>""", unsafe_allow_html=True)

            with st.expander("Show Risk Factors", expanded=True):
                if not risk_factors: st.markdown("- No significant risk factors detected.")
                for factor in risk_factors:
                    if "(-" in factor: st.markdown(f"<p style='color:green;'>✓ {factor}</p>", unsafe_allow_html=True)
                    else: st.markdown(f"<p style='color:orange;'>⚠️ {factor}</p>", unsafe_allow_html=True)

            st.markdown("---")
            st.subheader("SSL/TLS Certificate Transparency")
            ssl_info = tech_details.get('ssl_info', {})
            if ssl_info.get("error"): st.error(ssl_info["error"])
            else:
                st.info(f"**Issuer:** {ssl_info.get('issuer', 'N/A')}")
                st.write(f"**Valid from:** {ssl_info.get('valid_from')} | **To:** {ssl_info.get('valid_to')}")
                age_days = (datetime.now() - ssl_info['valid_from']).days
                st.write(f"**Certificate age:** {age_days} days")
                if age_days < 90: st.warning("⚠️ Certificate is very new (issued in the last 90 days).")
            
            st.subheader("Typosquatting & Lookalike Domain Check")
            if "Warning" in typo_result: st.warning(typo_result)
            else: st.success(typo_result)
            
            # Other sections of the UI
            if perform_scan:
                st.subheader(f"Port Scan Results ({port_start}–{port_end})")
                if port_error: st.error(port_error)
                if open_ports:
                    st.markdown("**Open Ports:**")
                    for port in open_ports: st.markdown(f"&nbsp;&nbsp;• Port {port}: <span style='color:green;font-weight:bold;'>OPEN</span> ({PORT_SERVICE_MAP.get(port, '')})", unsafe_allow_html=True)

# --- TAB 2: TEXT/MESSAGE ANALYSIS ---
with tab2:
    st.header("Text & Message Analysis")
    text_to_analyze = st.text_area("Paste any suspicious email, SMS, or message below:", height=200, key="text_analyzer_input")
    if st.button("Analyze Text"):
        if not text_to_analyze:
            st.warning("Please paste some text to analyze.")
        else:
            with st.spinner("Analyzing text..."):
                score, issues = 0, []
                links = re.findall(r'https?://[^\s/$.?#].[^\s]*', text_to_analyze)
                if links:
                    score += 25; issues.append(f"Suspicious links found: `{', '.join(links)}`")
                else:
                    issues.append("No suspicious links detected.")
                
                keywords = ['urgent', 'verify', 'account', 'suspended', 'password', 'winner', 'claim']
                found_keywords = [kw for kw in keywords if kw in text_to_analyze.lower()]
                if found_keywords:
                    score += 30; issues.append(f"Phishing keywords detected: `{', '.join(found_keywords)}`")
                else:
                    issues.append("No common phishing keywords detected.")
                
                st.subheader("Text Analysis Results")
                col1, col2 = st.columns(2)
                col1.metric("Risk Score", f"{score}/100")
                if score > 50: col2.error("Prediction: High Risk")
                elif score > 20: col2.warning("Prediction: Medium Risk")
                else: col2.success("Prediction: Low Risk")
                
                st.subheader("Detected Issues")
                for issue in issues: st.markdown(f"- {issue}")

# --- TAB 3: PHISHING SELF-TEST ---
with tab3:
    st.header("🎓 Phishing Awareness Self-Test")
    st.markdown("Test your ability to spot phishing attempts!")
    with st.form("quiz_form"):
        st.markdown("**1. You receive an email from 'support@micros0ft.com'. What's the biggest red flag?**")
        q1 = st.radio("Answer 1", ["The urgent tone", "The sender's email address", "The link inside"], key="q1")
        st.markdown("**2. A website uses HTTPS. Does this always mean it's safe?**")
        q2 = st.radio("Answer 2", ["Yes, HTTPS means the site is always safe.", "No, phishing sites can also use HTTPS to appear legitimate."], key="q2")
        st.markdown("**3. An SMS says you've won a prize and asks you to click a link to 'claim.it/now'. You should:**")
        q3 = st.radio("Answer 3", ["Click the link to see the prize.", "Ignore and delete the message.", "Reply 'STOP' to unsubscribe."], key="q3")
        
        if st.form_submit_button("Submit Quiz"):
            score = 0
            if "sender's email address" in q1: score += 1
            if "No, phishing sites can" in q2: score += 1
            if "Ignore and delete" in q3: score += 1
            st.subheader(f"Your Score: {score}/3")
            if score == 3:
                st.success("Excellent! You have a sharp eye for phishing attempts."); st.balloons()
            else:
                st.warning("Good job, but be sure to review the correct answers to stay safe!")