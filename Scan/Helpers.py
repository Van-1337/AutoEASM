from urllib.parse import urlparse
import os
import shutil
import re
from dataclasses import dataclass
from datetime import datetime
import random
import requests


def delete_http_duplicates(urls):
    def normalize_netloc(netloc):
        if netloc.startswith("www."):
            return netloc[4:]
        return netloc


    def deduplicate_urls(urls):
        domain_dict = {}

        for url in urls:
            parsed = urlparse(url)
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()
            normalized_netloc = normalize_netloc(netloc)

            if normalized_netloc in domain_dict:
                existing_scheme = domain_dict[normalized_netloc]['scheme']
                if scheme == 'https' and existing_scheme == 'http':
                    domain_dict[normalized_netloc] = {'scheme': scheme, 'url': url}
            else:
                domain_dict[normalized_netloc] = {'scheme': scheme, 'url': url}

        deduplicated_urls = [info['url'] for info in domain_dict.values()]
        return deduplicated_urls

    return deduplicate_urls(urls)


def delete_postleaks_junk(run_dir):
    for entry in os.listdir(run_dir):
        full_path = os.path.join(run_dir, entry)
        if os.path.isdir(full_path) and entry.startswith("postleaks_"):
            shutil.rmtree(full_path)


def create_run_directory(first_domain):
    safe_domain = re.sub(r'[^A-Za-z0-9._-]', '_', first_domain)[:50] or "scan"
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    run_dir = "Logs/" + f"{timestamp}_{safe_domain}"
    os.makedirs(run_dir, exist_ok=True)
    return run_dir


def remove_ansi_escape_codes(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


def remove_non_links(urls):
    return [url for url in urls if url.startswith(('http://', 'https://'))]


def get_host_from_url(url, remove_port=False, keep_protocol=False):
    # urlparse needs a scheme to populate netloc, so prepend '//' when it is missing.
    parsed = urlparse(url if '://' in url else '//' + url)
    host = parsed.netloc
    if remove_port:
        host = host.split(':', 1)[0]
    if keep_protocol and parsed.scheme:
        return f"{parsed.scheme}://{host}"
    return host


def get_host_from_url_list(urls, remove_ports=False):
    result = []
    for url in urls:
        result.append(get_host_from_url(url, remove_ports))
    return result


def get_random_string(length):
    return ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=length))


def is_site_available(url):
    try:
        user_agent_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0"}
        requests.get(url, verify=False, headers=user_agent_headers, timeout=5, allow_redirects=False)
        return True
    except requests.RequestException:
        return False

@dataclass(frozen=True)
class LeakixVulnerability:
    event_source: str
    host: str
    time: str
    severity: str
    url: str


def extract_leakix_vulnerability(entry: dict) -> LeakixVulnerability:
    event_source = entry.get('event_source', '').strip()
    host = entry.get('host', '').strip()
    time = entry.get('time', '').strip()
    leak = entry.get('leak', {})
    severity = leak.get('severity', '').strip()
    http = entry.get('http', {})
    url = entry.get('protocol', '').strip() + "://" + host + http.get('url', '').strip()

    return LeakixVulnerability(
        event_source=event_source,
        host=host,
        time=time,
        severity=severity,
        url=url
    )


def is_date_actual(date_string):  # "2024-12-03T01:49:40.4933153Z"
    input_date = datetime.fromisoformat(date_string.rstrip("Z").split(".")[0])
    current_date = datetime.now()

    input_date = input_date.date()
    current_date = current_date.date()
    delta = abs(current_date - input_date)

    if delta.days <= 31:
        return True
    else:
        return False


def is_WAF_signatures_in_response(response):
    keywords = ('cloudflare', 'akamai', 'incap_ses')
    headers_contains_keyword = any(any(keyword in value.lower() for keyword in keywords)
                                   for value in response.headers.values())
    body_contains_keyword = 'Cloudflare' in response.text
    return headers_contains_keyword or body_contains_keyword


def is_site_real_by_response(response):
    body_contains_keyword = 'href="http://adm.tools/support/">' in response.text or\
                            '<p>This site is currently under construction.</p' in response.text or\
                            '">This site is currently suspended<' in response.text
    return not body_contains_keyword


def replace_last_colon(s: str) -> str:  # For 403 bypass results reporing
    idx = s.rfind(':')
    if idx == -1:
        return s
    return s[:idx] + ' -' + s[idx+1:]
