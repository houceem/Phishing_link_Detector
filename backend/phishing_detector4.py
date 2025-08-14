import requests
from urllib.parse import urlparse
import socket
import ssl
import re
import tldextract
import whois
import validators
from datetime import datetime
import pandas as pd

SHORT_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly"}
SUSPICIOUS_KEYWORDS = [
    "login", "secure", "update", "verify", "confirm", "account", "bank", "signin", "password", "webscr"
]

def normalize_url(url):
    if not re.match(r"^https?://", url):
        return "http://" + url
    return url

def is_ip_in_url(url):
    parsed = urlparse(url)
    host = parsed.netloc.split(':')[0]
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    return re.match(ip_pattern, host) is not None

def is_shortened(url):
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    return host in SHORT_DOMAINS

def contains_suspicious_keyword(url):
    low = url.lower()
    return [k for k in SUSPICIOUS_KEYWORDS if k in low]

def count_redirects(response):
    return len(response.history) if response else 0

def get_final_response(url, timeout=7):
    try:
        r = requests.get(url, allow_redirects=True, timeout=timeout, headers={"User-Agent":"Mozilla/5.0"})
        return r
    except Exception:
        return None

def get_ssl_expiry(domain, timeout=5):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                notAfter = cert.get('notAfter')
                if notAfter:
                    exp = datetime.strptime(notAfter, "%b %d %H:%M:%S %Y %Z")
                    return exp
    except Exception:
        return None

def dns_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception:
        return None

def whois_info(domain):
    try:
        w = whois.whois(domain)
        return w
    except Exception:
        return None

def extract_features_for_model(url):
    parsed_url = urlparse(url)
    suffix = tldextract.extract(url).suffix
    path = parsed_url.path
    
    def safe_div(num, denom):
        return num / denom if denom > 0 else 0
    
    features = {
        'length_url': len(url),
        'length_hostname': len(parsed_url.netloc),
        'ip': int(is_ip_in_url(url)),
        'nb_dots': url.count('.'),
        'nb_hyphens': url.count('-'),
        'nb_at': url.count('@'),
        'nb_qm': url.count('?'),
        'nb_and': url.count('&'),
        'nb_or': url.count('|'),
        'nb_eq': url.count('='),
        'nb_underscore': url.count('_'),
        'nb_tilde': url.count('~'),
        'nb_percent': url.count('%'),
        'nb_slash': url.count('/'),
        'nb_star': url.count('*'),
        'nb_colon': url.count(':'),
        'nb_comma': url.count(','),
        'nb_semicolumn': url.count(';'),
        'nb_dollar': url.count('$'),
        'nb_space': url.count(' '),
        'nb_www': url.lower().count('www'),
        'nb_com': url.lower().count('.com'),
        'nb_dslash': url.count('//'),
        'http_in_path': int("http" in path),
        'https_token': int("https" in parsed_url.netloc),
        'ratio_digits_url': safe_div(sum(c.isdigit() for c in url), len(url)),
        'ratio_digits_host': safe_div(sum(c.isdigit() for c in parsed_url.netloc), len(parsed_url.netloc)),
        'punycode': int("xn--" in url),
        'port': parsed_url.port if parsed_url.port else 0,
        'tld_in_path': int(suffix in path),
        'tld_in_subdomain': 0,  # يمكنك تطويرها لاحقاً
        'abnormal_subdomain': 0,
        'nb_subdomains': parsed_url.netloc.count('.'),
        'prefix_suffix': 0,
        'random_domain': 0,
        'shortening_service': int(is_shortened(url)),
        'path_extension': 0,
        'nb_redirection': 0,
        'nb_external_redirection': 0
    }
    return pd.DataFrame([features])

def analyze_url(raw_url):
    url = normalize_url(raw_url)
    report = {
        "input_url": raw_url,
        "normalized_url": url,
        "valid_url": validators.url(url),
        "contains_ip": is_ip_in_url(url),
        "is_shortened": is_shortened(url),
        "suspicious_keywords": contains_suspicious_keyword(url),
        "redirect_count": 0,
        "final_url": None,
        "status_code": None,
        "domain": urlparse(url).netloc.split(':')[0],
        "ip": None,
        "ssl_expiry": None,
        "whois": None,
        "ml_prediction": None,
        "notes": []
    }

    resp = get_final_response(url)
    if resp:
        report["status_code"] = resp.status_code
        report["final_url"] = resp.url
        report["redirect_count"] = count_redirects(resp)
        final_domain = urlparse(resp.url).netloc.split(':')[0]
        if final_domain != report["domain"]:
            report["notes"].append(f"Redirects to different domain: {final_domain}")
    else:
        report["notes"].append("No response or request failed.")

    ip = dns_lookup(report["domain"])
    report["ip"] = ip

    ssl_expiry = get_ssl_expiry(report["domain"])
    if ssl_expiry:
        report["ssl_expiry"] = ssl_expiry.isoformat()
    else:
        report["notes"].append("No SSL info found or port 443 closed.")

    w = whois_info(report["domain"])
    if w:
        try:
            created = w.creation_date
            report["whois"] = {
                "registrar": getattr(w, "registrar", None),
                "creation_date": str(created) if created else None,
                "expiration_date": str(getattr(w, "expiration_date", None))
            }
        except Exception:
            report["whois"] = {"raw": str(w)}
    else:
        report["notes"].append("WHOIS lookup failed or blocked.")

    return report

