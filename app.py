from flask import Flask, request, jsonify, render_template
import pandas as pd
from urllib.parse import urlparse
import requests
import base64
import re
import dns.resolver
import dns.name
import socket
import validators
from datetime import datetime
import time
import os

app = Flask(__name__)

# VirusTotal API key
API_KEY = "467a353c0f7e25b80e7d5243f02865c254b95731b703d4d7f342aa1f212366a9" #VirusTotal Premium API for student


# List of valid TLDs (279 TLDs) - 32 Generic TLD, and 247 Country Code TLDs (ccTLDs)
VALID_TLDS = [
    "com", "org", "net", "int", "edu", "gov", "mil", "co", "io", "biz", "info", "xyz",
    "top", "club", "online", "site", "shop", "vip", "tech", "store", "me", "art", "pro",
    "my", "id", "jp", "academy", "ads", "bio", "blog", "dev", "education", "eco", "google",
    "us", "uk", "ca", "de", "fr", "au", "ru", "nl", "br", "it", "se", "es", "in", "cn", "mx",
    "ch", "kr", "pl", "tv", "ly", "ai", "ac", "ad", "ae", "af", "ag", "al", "am",
    "ao", "bs", "cd", "cf", "cm", "cr", "cu", "cz", "at", "kp", "ky", "kz", "lb", "lc", "li",
    "lr", "ls", "lu", "mc", "md", "mg", "mh", "mn", "mp", "aq", "ar", "as", "aw",
    "ax", "az", "ba", "bb", "bd", "be", "bf", "bg", "bh", "bi", "bj", "bm", "bn", "bo", "bq",
    "br", "bs", "bt", "bw", "by", "bz", "cc", "cg", "ci", "ck", "cl", "cm", "cn", "co", "cr",
    "cu", "cv", "cw", "cx", "cy", "cz", "de", "dj", "dk", "dm", "do", "dz", "ec", "ee", "eg",
    "eh", "er", "es", "et", "eu", "fi", "fj", "fk", "fm", "fo", "fr",
    "ga", "gb", "gd", "ge", "gf", "gg", "gh", "gi", "gl", "gm", "gn", "gp", "gq", "gr", "gs",
    "gt", "gu", "gw", "gy", "hk", "hm", "hn", "hr", "ht", "hu", "id", "ie", "il", "im", "in",
    "io", "iq", "ir", "is", "it", "je", "jm", "jo", "ke", "kg", "kh", "ki", "km", "kn",
    "kp", "kr", "kw", "ky", "kz", "la", "lb", "lc", "li", "lk", "lr", "ls", "lt", "lu", "lv",
    "ly", "ma", "mc", "md", "me", "mf", "mg", "mh", "mk", "ml", "mm", "mn", "mo", "mp", "mq",
    "mr", "ms", "mt", "mu", "mv", "mw", "mx", "my", "mz", "na", "nc", "ne", "nf", "ng", "ni",
    "nl", "no", "np", "nr", "nu", "nz", "om", "pa", "pe", "pf", "pg", "ph", "pk", "pl", "pm",
    "pn", "pr", "ps", "pt", "pw", "py", "qa", "re", "ro", "rs", "ru", "rw", "sa", "sb", "sc",
    "sd", "se", "sg", "sh", "si", "sj", "sk", "sl", "sm", "sn", "so", "sr", "ss", "st", "sv",
    "sx", "sy", "sz", "tc", "td", "tf", "tg", "th", "tj", "tk", "tl", "tm", "tn", "to", "tr",
    "tt", "tv", "tw", "tz", "ua", "ug", "uk", "us", "uy", "uz", "va", "vc", "ve", "vg", "vi",
    "vn", "vu", "wf", "ws", "ye", "yt", "za", "zm", "zw"
]

# Function to get the final redirection URL and last analysis stats from VirusTotal
def get_virustotal_data(original_url):
    base64_encoded = base64.urlsafe_b64encode(original_url.encode()).decode().rstrip('=')
    url = f"https://www.virustotal.com/api/v3/urls/{base64_encoded}"
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }
    response = requests.get(url, headers=headers)
    data = response.json()

    if 'data' in data and 'attributes' in data['data']:
        last_final_url = data['data']['attributes'].get('last_final_url')
        redirection_chain = data['data']['attributes'].get('redirection_chain', [])

        # Use the final URL to get the last_analysis_stats
        if last_final_url:
            base64_encoded_final = base64.urlsafe_b64encode(last_final_url.encode()).decode().rstrip('=')
            url_final = f"https://www.virustotal.com/api/v3/urls/{base64_encoded_final}"
            response_final = requests.get(url_final, headers=headers)
            data_final = response_final.json()
            if 'data' in data_final and 'attributes' in data_final['data']:
                last_analysis_stats = data_final['data']['attributes'].get('last_analysis_stats')
            else:
                last_analysis_stats = None
        else:
            last_analysis_stats = None

        return last_final_url, last_analysis_stats, redirection_chain
    else:
        return None, None, None

# Function to get the domain report from VirusTotal
def get_domain_report(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        # Extract popularity ranks and timestamp
        popularity_ranks = data['data']['attributes'].get('popularity_ranks', {})
        return data, popularity_ranks
    else:
        return None, {}


# Function to check if it is valid domain name (no IP address) - validators
def is_valid_domain(domain):
    return "YES" if validators.domain(domain) else "NO"

# Function to check if the URL contains suspicious HTTP
def is_suspicious_http(url):
    if 'http://' in url:
        return "YES, MALICIOUS"
    elif 'https://' in url:
        return "NO"
    else:
        return "NO"

# Function to check if a domain has valid DNS records of types 'A', 'AAAA', 'MX', 'CNAME', or 'TXT', returning "YES" if at least one valid record is found, otherwise "NO" USING dnspython
def valid_DNS_Record(domain):
    if not domain:  # Check if the domain is empty
        return "NO"

    record_types = ['A', 'AAAA', 'MX', 'CNAME', 'TXT']
    for record_type in record_types:
        try:
            dns.resolver.resolve(domain, record_type)
            return "YES"
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, socket.gaierror, dns.resolver.LifetimeTimeout, dns.name.EmptyLabel):
            continue
    return "NO"

# Function to extract TTL and determine if it's greater than 100
def extract_ttl_and_check(record):
    ttl = record.get('ttl', None)
    if ttl is not None:
        ttl_check = "YES" if ttl > 100 else "NO"
    else:
        ttl_check = "N/A"
    return ttl, ttl_check

# Function to parse datetime with different formats
def parse_datetime(date_string):
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(date_string, fmt)
        except ValueError:
            continue
    raise ValueError(f"Time data {date_string} does not match any known formats.")

# Function to convert timestamp to a readable format
def convert_timestamp_to_readable(timestamp):
    try:
        # Assuming the timestamp is in UNIX format
        dt_object = datetime.fromtimestamp(timestamp)
        readable_format = dt_object.strftime('%Y-%m-%d %H:%M:%S')
        return readable_format
    except Exception as e:
        return "Invalid timestamp"

# Function to extract and validate TLD
def extract_and_validate_tld(domain_report):
    if domain_report and 'data' in domain_report and 'attributes' in domain_report['data']:
        domain_info = domain_report['data']['attributes']
        tld = domain_info.get('tld')

        # Split the domain by dots to check for combinations of TLDs
        tld_parts = tld.split('.')

        # Check if any combination of TLDs separated by dots is in the VALID_TLDS list
        for i in range(1, len(tld_parts) + 1):
            combined_tld = '.'.join(tld_parts[-i:])
            if combined_tld in VALID_TLDS:
                return f"Valid TLD {combined_tld}", 0  # Return the valid combined TLD and weight 0

        # If no valid combination of TLDs is found, check if the last part of the TLD is in VALID_TLDS
        if tld not in VALID_TLDS:
            return f"Invalid TLD {tld}", 50  # Invalid TLD
        else:
            return f"Valid TLD {tld}", 0  # Valid TLD

    return "No TLD", 100  # Default if no TLD information is found

# Function to standardize TYPE values from .csv file
def standardize_type(value):
    malicious_terms = ["malicious", "malware", "phishing", "scam", "defacement", "harmful", "dangerous", "scam"]
    benign_terms = ["benign", "harmless", "safe", "legitimate"]

    if any(term in value.lower() for term in malicious_terms):
        return "Malicious"
    elif any(term in value.lower() for term in benign_terms):
        return "Benign"
    else:
        return value  # If it doesn't match any known terms, return the original value

# Function to extract features from the URL
def extract_url_features(url):
    start_time = time.time()  # Start time for measuring elapsed time
    # Initial weight is 0
    weight = 0.0
    # total_feature_weight = 647.0
    total_feature_weight = 0

    final_url, analysis_stats, redirection_chain = get_virustotal_data(url)
    if final_url is None:
        final_url = url  # Fallback to the original URL if final redirection URL is not found


    # Original URL processing
    original_url_without_prefix = url.replace("http://", "").replace("https://", "").replace("www.", "").rstrip("/")

    # Final URL processing
    final_url_without_prefix = final_url.replace("http://", "").replace("https://", "").replace("www.", "").rstrip("/")


    parsed_url = urlparse(final_url)

    # Basic URL features
    url_length = len(final_url)
    if 40 <= url_length < 60:
        weight += 5
    elif 60 <= url_length < 80:
        weight += 10
    elif 80 <= url_length < 100:
        weight += 15
    elif 100 <= url_length < 150:
        weight += 20
    elif 150 <= url_length < 180:
        weight += 30
    elif url_length >= 180:
        weight += 40
    total_feature_weight += 40

    # num_dots = final_url.count('.')

    # num_hyphens = final_url.count('-')

    # num_digits = sum(c.isdigit() for c in final_url)

    # # Host-based features
    domain = parsed_url.netloc

    # domain_length = len(domain)

    valid_domain = is_valid_domain(domain)  # Check if domain contains an IP address
    contains_suspicious_http = is_suspicious_http(url)  # Check if URL contains suspicious HTTP
    DNS_Record = valid_DNS_Record(domain)  # Check if the domain is valid by DNS lookup

    # Get domain report from VirusTotal
    domain_report, popularity_ranks = get_domain_report(domain)
    last_dns_records = None
    last_https_certificate_validity = None

    # Initialize TTL records as an empty list
    ttl_records = []
    if domain_report and 'data' in domain_report and 'attributes' in domain_report['data']:
        last_dns_records = domain_report['data']['attributes'].get('last_dns_records')
        last_https_certificate = domain_report['data']['attributes'].get('last_https_certificate')

        if last_https_certificate and 'validity' in last_https_certificate:
            last_https_certificate_validity = last_https_certificate['validity']

    # Extract TTL and check if it's greater than 60 if last_dns_records is not None
    if last_dns_records:
        ttl_records = [extract_ttl_and_check(record) for record in last_dns_records]

    # Extract and validate TLD
    tld, tld_weight = extract_and_validate_tld(domain_report)
    weight += tld_weight
    total_feature_weight += 100

    # Lowercase and Split the URL for the path token
    path_tokens = re.split(r'[/.?]', final_url.lower())

    # Initialize the weight increment based on the number of detected sensitive tokens (47)
    sensitive_token_weight = path_tokens.count('secure') + path_tokens.count('zip') + path_tokens.count('order') + \
    path_tokens.count('account') + path_tokens.count('rar') + path_tokens.count('dbsys.php') + \
    path_tokens.count('webscr') + path_tokens.count('jpg') + path_tokens.count('dbsys') + \
    path_tokens.count('ebayisapi') + path_tokens.count('js') + path_tokens.count('config.bin') + \
    path_tokens.count('banking') + path_tokens.count('gif') + path_tokens.count('config') + \
    path_tokens.count('confirm') + path_tokens.count('bin') + path_tokens.count('download') + \
    path_tokens.count('blog') + path_tokens.count('jar') + path_tokens.count('mail') + \
    path_tokens.count('signin') + path_tokens.count('swf') + path_tokens.count('payment') + \
    path_tokens.count('signon') + path_tokens.count('cgi') + path_tokens.count('files') + \
    path_tokens.count('logon') + path_tokens.count('php') + path_tokens.count('css') + \
    path_tokens.count('login') + path_tokens.count('viewer.php') + path_tokens.count('shopping') + \
    path_tokens.count('asp') + path_tokens.count('viewer') + path_tokens.count('update') + \
    path_tokens.count('link') + path_tokens.count('abuse') + path_tokens.count('link=') + \
    path_tokens.count('suspend') + path_tokens.count('getImage.asp') + path_tokens.count('admin') + \
    path_tokens.count('exe') + path_tokens.count('plugins') + path_tokens.count('personal') + \
    path_tokens.count('verification') + path_tokens.count('paypal')

    # Initialize malicious and harmless counts
    malicious_count = 0
    harmless_count = 0

    # Update malicious and harmless counts from analysis_stats
    if analysis_stats:
        malicious_count = analysis_stats.get('malicious', 0)
        harmless_count = analysis_stats.get('harmless', 0)


    # Calculate TTL weight - row 3 detect as malicious, pdhl dia benign
    if ttl_records:
        has_response = any(ttl is not None for ttl, _ in ttl_records)  # Check if VirusTotal returned any TTL

        if has_response:
            # Check if at least one TTL is smaller than or equal to 100
            if any(ttl <= 100 for ttl, _ in ttl_records):
                weight += 0
                total_feature_weight += 100

            # Check if at least one TTL is greater than 100
            if any(ttl > 100 for ttl, _ in ttl_records):
                weight += 100
                total_feature_weight += 100

        else:
            # If VirusTotal didn't get any response or feedback
            total_feature_weight += 0
    else:
        # If ttl_records is empty (no TTL data available)
        total_feature_weight += 0


    # Update weight based on malicious analysis stats
    if analysis_stats and 'malicious' in analysis_stats and analysis_stats['malicious'] >= 2:
        weight += 100  # 100% weight if 'malicious' count is greater than or equal to 2
    if analysis_stats: #If VT returns analysis_stats, else total_feature_weight wont be added
        total_feature_weight += 100
    if not analysis_stats:
        weight += 40
        total_feature_weight +=40

    # Estimate the weight of maliciousness based on the features
    if contains_suspicious_http == "YES, MALICIOUS":
        weight += 100
    if contains_suspicious_http:
        total_feature_weight += 100

    if valid_domain == "NO":
        weight += 100
    if valid_domain:
        total_feature_weight += 100

    if DNS_Record == "NO":
        weight += 10
    if DNS_Record:
        total_feature_weight += 10

    if sensitive_token_weight > 0:
        weight += sensitive_token_weight
    if sensitive_token_weight or sensitive_token_weight == 0:
        total_feature_weight += 47

    # Check if the URL is shortened
    if 'bitly' in original_url_without_prefix or 'bitly' in final_url_without_prefix or len(original_url_without_prefix) < len(final_url_without_prefix):
        weight += 10  # Add weight if URL is shortened
        shortened_url_message = "YES, IT IS SHORTENED URL"
        total_feature_weight += 10
    else:
        shortened_url_message = "NO"
        total_feature_weight += 10

    # Check the HTTPS certificate validity
    if last_https_certificate_validity:
        try:
            start_date = parse_datetime(last_https_certificate_validity['not_before'])
            end_date = parse_datetime(last_https_certificate_validity['not_after'])
            if start_date <= datetime.now() <= end_date:
                certificate_status = "CERTIFICATE IS VALID"
                total_feature_weight += 100
            else:
                certificate_status = "CERTIFICATE IS NOT VALID"
                weight += 100
                total_feature_weight += 100
        except ValueError: # When neither date format matches, it raises a value error.
            certificate_status = "Date Format Error"
            weight += 100
            total_feature_weight += 100
    else:
        certificate_status = "NO CERTIFICATE"
        weight += 100
        total_feature_weight += 100

    # Check for popularity ranks and timestamps
    all_popularity_ranks = {}
    for source, details in popularity_ranks.items():
        rank = details.get("rank", "N/A")
        timestamp = details.get("timestamp", "N/A")

        # Convert timestamp to a readable format
        readable_timestamp = convert_timestamp_to_readable(timestamp) if timestamp != "N/A" else "N/A"

        all_popularity_ranks[source] = {"rank": rank, "timestamp": readable_timestamp}


    # If all popularity ranks are empty
    if not all_popularity_ranks:
        weight += 80
        total_feature_weight += 80
    #If Virustotal return popularity rank
    if all_popularity_ranks:
        total_feature_weight += 80

    # Assign Maliciousness Labels
    def assign_maliciousness_label(percentage_of_malicious):
        if percentage_of_malicious < 32:
            return "Benign"
        else:
            return "Malicious"

    percentage_of_malicious = (weight/total_feature_weight)*100
    percentage_of_malicious_formatted = "{:.2f}".format(percentage_of_malicious)

    maliciousness_label = assign_maliciousness_label(percentage_of_malicious)

    end_time = time.time()  # End time for measuring elapsed time
    elapsed_time = end_time - start_time  # Calculate elapsed time

    result = {}

    result["Original URL"] = url
    result["Final URL (VirusTotal)"] = final_url
    result["Original URL without Prefix"] = original_url_without_prefix
    result["Final URL without Prefix"] = final_url_without_prefix
    result["redirection_chain (VirusTotal)"] = redirection_chain
    result["Is Shortened URL"] = shortened_url_message
    result["URL Length"] = url_length
    result["Domain"] = domain
    result["Valid Domain (Validators)"] = valid_domain
    result["Contains Suspicious HTTP"] = contains_suspicious_http
    result["Valid DNS Record (dnspython)"] = DNS_Record
    result["Number of Sensitive Token"] = sensitive_token_weight
    result["Malicious Count (VirusTotal)"] = malicious_count
    result["Benign Count (VirusTotal)"] = harmless_count
    result["DNS Records (VirusTotal)"] = last_dns_records
    result["TTL Records (VirusTotal)"] = ttl_records
    result["Last HTTPS Certificate Validity (VirusTotal)"] = last_https_certificate_validity
    result["Last HTTPS Certificate Validity Status (VirusTotal)"] = certificate_status
    result["TLD"] = tld
    result["TLD Weight"] = tld_weight
    result["Popularity Ranks (VirusTotal)"] = all_popularity_ranks
    result["Elapsed Time"] = elapsed_time
    result["Total Weight"] = weight
    result["Total Feature Weight"] = total_feature_weight
    result["Percentage of Maliciousness"] = percentage_of_malicious_formatted
    result["Maliciousness Label"] = maliciousness_label

    return result
    # return elapsed_time, {
    #     'Maliciousness Label': maliciousness_label,
    #     'Percentage of Maliciousness': percentage_of_malicious,
    #     'Total Weight': weight,
    #     'Total Feature Weight': total_feature_weight,
    #     'Original URL': url,
    #     'VirusTotal - Final URL': final_url,
    #     'Original URL without Prefix': original_url_without_prefix,
    #     'Final URL without Prefix': final_url_without_prefix,
    #     'Is Shortened URL': shortened_url_message,
    #     'URL Length': url_length,
    #     'Domain': domain,
    #     'Validators - Valid Domain': valid_domain,
    #     'Contains Suspicious HTTP': contains_suspicious_http,
    #     'dnspython - Valid DNS Record': DNS_Record,
    #     'Number of Sensitive Token': sensitive_token_weight,
    #     'VirusTotal - Malicious Count': malicious_count,
    #     'VirusTotal - Harmless Count': harmless_count,
    #     'VirusTotal - DNS Records': last_dns_records,
    #     'TTL Records - VirusTotal': ttl_records,
    #     'Last HTTPS Certificate Validity - VirusTotal': last_https_certificate_validity,
    #     'Last HTTPS Certificate Validity Status - VirusTotal': certificate_status,
    #     'TLD': tld,
    #     'TLD Weight': tld_weight,
    #     'redirection_chain': redirection_chain,
    #     'Popularity Ranks': all_popularity_ranks,
    #     'Elapsed Time': elapsed_time,
    # }


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/detect', methods=['POST'])
def detect():
    data = request.get_json()
    url = data.get('url')
    if url:
        result = extract_url_features(url)
        return jsonify(result)
    else:
        return jsonify({"error": "No URL provided"}), 400

if __name__ == '__main__':
    app.run(debug=True)
