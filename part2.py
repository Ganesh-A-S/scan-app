import os
import json
import requests
import re
import streamlit as st
import plotly.express as px
import pandas as pd
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import smtplib

# Constants
SCAN_MODES = {
    "Intense Scan": "-T4 -A -v",
    "Quick Scan": "-T4 -F",
    "Ping Scan": "-sn",
    "Regular Scan": "",
    "Intense Scan, all TCP ports": "-p 1-65535 -T4 -A -v",
    "Intense Scan, no ping": "-T4 -A -v -Pn",
    "Slow Comprehensive Scan": "-sS -sU -T4 -A -v"
}
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# Utility Functions
def scan_network(target_ip_range, scan_mode):
    """Perform an Nmap scan on the target IP range."""
    scan_command = SCAN_MODES.get(scan_mode, "")
    result = os.popen(f"nmap {scan_command} {target_ip_range}").read()
    return result

def is_valid_email(email):
    """Validate email format."""
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email)

def send_email_with_attachment(sender_email, sender_password, recipient_email, subject, body, attachment_paths):
    """Send an email with attachments."""
    try:
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        # Attach files
        for attachment_path in attachment_paths:
            if os.path.exists(attachment_path):
                with open(attachment_path, 'rb') as attachment:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename={os.path.basename(attachment_path)}')
                msg.attach(part)

        # Connect to SMTP server
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def fetch_vulnerabilities_and_exploits_from_shodan(ip_address, api_key):
    """Fetch vulnerabilities and corresponding exploits from Shodan for a given IP."""
    
    # Fetch data from Shodan
    url = f'https://api.shodan.io/shodan/host/{ip_address}?key={api_key}'
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        vulnerabilities = []
        
        # Extract vulnerabilities from Shodan response
        for service in data.get("data", []):
            for vuln in service.get("vulns", []):
                cvss_score = service.get('vulns', {}).get(vuln, {}).get('cvss', 'N/A')
                description = service.get('vulns', {}).get(vuln, {}).get('summary', 'No description available')
                
                # Now search for exploits related to this CVE in Shodan
                exploit_url = f"https://www.shodan.io/search?query=cve:{vuln}"
                exploit_details = f"Exploit URL: {exploit_url}"  # Exploit URL linking to Shodan
                
                # Append the vulnerability and its corresponding exploit link
                vulnerabilities.append({
                    "ip_address": ip_address,
                    "port": service.get('port', 'N/A'),
                    "cve_id": vuln,
                    "description": description,
                    "severity": cvss_score,
                    "exploit_link": exploit_details
                })
        return vulnerabilities
    else:
        st.error(f"Error fetching vulnerabilities for {ip_address}: {response.status_code}")
        return []

def plot_severity_distribution(vulnerabilities):
    """Plot severity distribution using Plotly."""
    severity_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'N/A')
        if severity == 'N/A':
            continue
        severity_score = float(severity)
        if severity_score >= 9:
            severity_count['Critical'] += 1
        elif 7 <= severity_score < 9:
            severity_count['High'] += 1
        elif 4 <= severity_score < 7:
            severity_count['Medium'] += 1
        else:
            severity_count['Low'] += 1
    severity_df = pd.DataFrame(list(severity_count.items()), columns=['Severity', 'Count'])
    fig = px.bar(severity_df, x='Severity', y='Count', title='Vulnerability Severity Distribution')
    return fig

# Streamlit Interface
# Streamlit Interface
st.title("Network Vulnerability Monitoring Dashboard")
st.markdown("""This tool helps you scan a network for vulnerabilities, fetch details from Shodan, and send detailed reports via email.""")

# Tabs for different functionalities
tab1, tab2, tab3 = st.tabs(["Scan Network", "Vulnerability Analysis", "CVE Details"])

# Tab 1: Network Scan
with tab1:
    st.header("Network Scan")
    target_ip_range = st.text_input("Enter the target IP range (e.g., 192.168.1.0/24):", "192.168.1.0/24")
    scan_mode = st.selectbox("Select Scan Mode:", list(SCAN_MODES.keys()))

    if st.button("Start Scan"):
        with st.spinner("Scanning network..."):
            scan_results = scan_network(target_ip_range, scan_mode)
            st.text_area("Scan Results", scan_results, height=300)

# Initialize session state for vulnerabilities_df
if "vulnerabilities_df" not in st.session_state:
    st.session_state.vulnerabilities_df = None

# Tab 2: Fetch Vulnerabilities and Send Email Automatically
with tab2:
    st.header("Vulnerability Analysis")
    api_key = st.text_input("Enter your Shodan API Key:", type="password", key="api_key_input")

    sender_email = st.text_input("Enter your Email Address:", key="sender_email_input")
    sender_password = st.text_input("Enter your Email Password:", type="password", key="sender_password_input")
    recipient_email = st.text_input("Enter Recipient's Email Address:", key="recipient_email_input")

    if st.button("Fetch Vulnerabilities"):
        if not api_key:
            st.error("Please enter a valid API key.")
        else:
            vulnerabilities = fetch_vulnerabilities_and_exploits_from_shodan(target_ip_range, api_key)
            if vulnerabilities:
                st.session_state.vulnerabilities_df = pd.DataFrame(vulnerabilities)
                st.dataframe(st.session_state.vulnerabilities_df)

                # Generate severity chart
                severity_fig = plot_severity_distribution(vulnerabilities)
                st.plotly_chart(severity_fig)

                # Send an email with vulnerabilities detected
                if sender_email and sender_password and recipient_email:
                    if is_valid_email(sender_email) and is_valid_email(recipient_email):
                        csv_path = "vulnerabilities_report.csv"
                        st.session_state.vulnerabilities_df.to_csv(csv_path, index=False)
                        subject = "Vulnerability Scan Report"
                        body = "Please find the attached vulnerability report and severity chart."

                        if send_email_with_attachment(sender_email, sender_password, recipient_email, subject, body, [csv_path]):
                            st.success("Email sent successfully!")
                            os.remove(csv_path)
                        else:
                            st.error("Failed to send email. Check your credentials.")
                    else:
                        st.error("Invalid email address(es). Please enter valid email addresses.")
            else:
                st.error("No vulnerabilities found for the specified IP range.")

# Tab 3: CVE Details
with tab3:
    st.header("CVE Details")
    
    if st.session_state.vulnerabilities_df is not None:
        # Dropdown for selecting a CVE
        cve_list = st.session_state.vulnerabilities_df['cve_id'].unique()
        selected_cve = st.selectbox("Select a CVE to view details:", options=cve_list)

        # Show details for the selected CVE
        if selected_cve:
            cve_details = st.session_state.vulnerabilities_df[st.session_state.vulnerabilities_df['cve_id'] == selected_cve].iloc[0]
            
            st.subheader(f"Details for {selected_cve}")
            st.write(f"**Description:** {cve_details['description']}")
            st.write(f"**Severity:** {cve_details['severity']}")
            st.write(f"**Port Affected:** {cve_details['port']}")
            st.write(f"**Exploit Link:** [View Exploit on Shodan]({cve_details['exploit_link']})")
    else:
        st.info("No vulnerabilities data available. Please fetch vulnerabilities in the 'Vulnerability Analysis' tab first.")
