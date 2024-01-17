import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from tld import get_tld
from googlesearch import search

def is_phishing(url):
    # Check for suspicious patterns in the URL
    patterns = [
        r'https?://(?:www\.)?([^\s]+)\.([a-z]{2,})',
        r'@',
        r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    ]

    for pattern in patterns:
        if re.search(pattern, url):
            return True

    # Check for IP address in the domain
    domain = urlparse(url).netloc
    if re.match(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', domain):
        return True

    # Check for subdomains count
    subdomains_count = len(domain.split('.'))
    if subdomains_count > 3:
        return True

    # Check if the domain is a known phishing domain using an external API
    if is_known_phishing_domain(domain):
        return True

    # Check if the webpage contains suspicious keywords using an external API
    if is_suspicious_keywords(url):
        return True

    # Check if the page is listed in Google Safe Browsing database
    if is_safe_browsing(url):
        return True

    return False

def is_known_phishing_domain(domain):
    # Use an external API to check if the domain is known for phishing
    # Replace 'API_KEY' with an actual API key
    api_key = 'API_KEY'
    api_url = f'https://api.phishtank.com/check.php?format=json&url={domain}&app_key={api_key}'

    try:
        response = requests.get(api_url)
        data = response.json()
        return data.get('valid', False)
    except Exception as e:
        print(f"Error checking phishing domain: {e}")
        return False

def is_suspicious_keywords(url):
    # Use an external API to check if the webpage contains suspicious keywords
    # Replace 'API_KEY' with an actual API key
    api_key = 'API_KEY'
    api_url = f'https://example.com/check_keywords?url={url}&api_key={api_key}'

    try:
        response = requests.get(api_url)
        data = response.json()
        return data.get('suspicious', False)
    except Exception as e:
        print(f"Error checking suspicious keywords: {e}")
        return False

def is_safe_browsing(url):
    # Use Google Safe Browsing API to check if the page is listed
    # Replace 'API_KEY' with an actual API key
    api_key = 'API_KEY'
    api_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}'

    payload = {
        "client": {
            "clientId": "your-client-id",
            "clientVersion": "1.5.2"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(api_url, json=payload)
        data = response.json()
        return bool(data.get('matches', []))
    except Exception as e:
        print(f"Error checking Safe Browsing: {e}")
        return False

def main():
    # Replace this URL with the one you want to check
    url_to_check = "https://example-phishing-site.com"
    
    if is_phishing(url_to_check):
        print(f"The URL {url_to_check} is suspicious and may be a phishing attempt.")
    else:
        print(f"The URL {url_to_check} appears to be safe.")

if __name__ == "__main__":
    main()

