import requests
from requests.exceptions import RequestException
from .config import USER_AGENT

HEADERS = {"User-Agent": USER_AGENT}

def fetch_url(url, timeout=10):
    try:
        h = requests.head(url, headers=HEADERS, timeout=5, allow_redirects=True)
        if h.status_code >= 400:
            r = requests.get(url, headers=HEADERS, timeout=timeout)
        else:
            r = requests.get(url, headers=HEADERS, timeout=timeout)
        return r.status_code, r.headers.get("content-type", ""), r.text
    except RequestException:
        return None, None, None