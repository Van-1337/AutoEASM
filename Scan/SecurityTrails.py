from Global import Flags, Threads
import Global
import time
import threading
import concurrent.futures
import requests
from Scan.Helpers import (
    get_host_from_url, get_host_from_url_list, get_random_string,
    is_WAF_signatures_in_response, is_site_real_by_response, is_http_to_https_redirect,
)

SECURITYTRAILS_API_BASE = "https://api.securitytrails.com/v1"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0"
BAD_INACTIVE_STATUSES = (400, 402, 403, 421, 429)  # Same "not a real hit" codes the existing inactive-hosts check ignores
_quota_exhausted = threading.Event()  # Set when the API stops accepting queries; other threads skip remaining work


class SecurityTrailsQuotaExhausted(Exception):
    """Raised when the API stops returning data (used-up monthly quota or sustained rate limit), so the whole check stops gracefully."""


def securitytrails_key_works():
    # /v1/ping only validates the key and does NOT count against the monthly query quota,
    # so it is safe to call at startup just to decide whether to enable the check.
    try:
        response = requests.get(f"{SECURITYTRAILS_API_BASE}/ping",
                                headers={"APIKEY": Global.SecurityTrailsAPIKey, "Accept": "application/json"},
                                timeout=15)
    except requests.RequestException:
        return False
    return response.status_code == 200


def _st_get(url):
    # Returns the parsed JSON for a successful call, None for a per-domain error we can skip,
    # and raises SecurityTrailsQuotaExhausted when the account can no longer query the API.
    if _quota_exhausted.is_set():
        raise SecurityTrailsQuotaExhausted()
    headers = {"APIKEY": Global.SecurityTrailsAPIKey, "Accept": "application/json"}
    for attempt in range(2):
        try:
            response = requests.get(url, headers=headers, timeout=20)
        except requests.RequestException:
            return None
        if response.status_code == 200:
            try:
                return response.json()
            except ValueError:
                return None
        if response.status_code == 429:
            # 429 covers both the short-term rate limit and a used-up monthly quota. Retry once for
            # the transient case; if it persists, treat the quota as gone and stop the whole check.
            if attempt == 0:
                time.sleep(5)
                continue
            _quota_exhausted.set()
            raise SecurityTrailsQuotaExhausted()
        if response.status_code in (401, 403):  # Key revoked or plan no longer allows this endpoint
            _quota_exhausted.set()
            raise SecurityTrailsQuotaExhausted()
        return None  # 404 (no history for this domain), 5xx, etc. - just skip this domain
    _quota_exhausted.set()
    raise SecurityTrailsQuotaExhausted()


def get_historical_ips(domain):
    # One query per domain. The history timeline already includes the current record, so there is no
    # need for a separate current-DNS call (keeps quota usage to a single query per domain).
    data = _st_get(f"{SECURITYTRAILS_API_BASE}/history/{domain}/dns/a")
    ips = []
    if data:
        for record in data.get("records", []):
            for value in record.get("values", []):
                ip = value.get("ip")
                if ip and ip not in ips:
                    ips.append(ip)
    return ips


def _request_with_host(target, host_header):
    try:
        return requests.get(target, verify=False, timeout=10, allow_redirects=False,
                            headers={"User-Agent": USER_AGENT, "Host": host_header})
    except requests.RequestException:
        return None


def _redirect_stays_on_target(response, ip):
    # Location must keep the client on this IP. Redirects back to the Host-header domain (typical
    # CDN HTTP→HTTPS upgrade) are not exploitable: following them leaves this IP.
    location = response.headers.get("Location") or response.headers.get("location") or ""
    return not location or ip in location


def _looks_like_original(original, response):
    # Task 1: the origin IP should answer like the real (WAF-fronted) site - same status and content
    # type, and a body of roughly the same size (a WAF may inject a little, so allow some slack).
    if response.status_code != original.status_code:
        return False
    if response.headers.get("Content-Type") != original.headers.get("Content-Type"):
        return False
    original_length, response_length = len(original.content), len(response.content)
    longest = max(original_length, response_length)
    if longest == 0:
        return True
    return abs(original_length - response_length) <= 0.3 * longest


def _differs_from_default(baseline, response):
    # Task 2: a hit only counts if the correct Host header changed the answer. If a random Host header
    # yields the same header set and body size, the server answers everything identically (default
    # vhost / catch-all), so it is not real evidence of access to this specific host.
    if baseline is None:
        return True
    return set(baseline.headers.keys()) != set(response.headers.keys()) or len(baseline.content) != len(response.content)


def _send_to_burp(target, host_header, proxies):
    try:
        requests.get(target, verify=False, timeout=15, allow_redirects=False, proxies=proxies,
                    headers={"User-Agent": USER_AGENT, "Host": host_header})
    except requests.RequestException:
        print(f"[e] Error sending request to {target} with {host_header} host header to Burp Suite!")


def _probe_origin_behind_waf(ip, domain, original, proxies):
    # Look for the real server behind the WAF: it must answer like the original site and must NOT
    # itself sit behind a WAF (otherwise we just found another CDN edge, not the origin).
    for scheme in ("https", "http"):
        target = f"{scheme}://{ip}"
        response = _request_with_host(target, domain)
        if response is None:
            continue
        if is_WAF_signatures_in_response(response) or not is_site_real_by_response(response):
            continue
        if is_http_to_https_redirect(response, target) or not _redirect_stays_on_target(response, ip):
            continue
        if _looks_like_original(original, response):
            if proxies:
                _send_to_burp(target, domain, proxies)
            return (domain, target)
    return None


def _probe_inactive_host(ip, domain, proxies):
    # Look for an internal/decommissioned app still reachable on an old IP once we send its own Host.
    for scheme in ("https", "http"):
        target = f"{scheme}://{ip}"
        response = _request_with_host(target, domain)
        if response is None:
            continue
        if response.status_code in BAD_INACTIVE_STATUSES or response.status_code // 100 == 5:
            continue
        if not is_site_real_by_response(response):
            continue
        if is_http_to_https_redirect(response, target) or not _redirect_stays_on_target(response, ip):
            continue
        baseline = _request_with_host(target, f"{get_random_string(10)}.com")
        if _differs_from_default(baseline, response):
            if proxies:
                _send_to_burp(target, domain, proxies)
            return (domain, target)
    return None


def _fetch_original(waf_url):
    try:
        return requests.get(waf_url, verify=False, timeout=15, allow_redirects=False,
                            headers={"User-Agent": USER_AGENT})
    except requests.RequestException:
        return None


def _check_waf_host(waf_url, proxies):
    if _quota_exhausted.is_set():
        return
    domain = get_host_from_url(waf_url, remove_port=True)
    if not any(character.isalpha() for character in domain):  # Skip bare IPs (e.g. in -i mode) - no DNS history
        return
    original = _fetch_original(waf_url)
    if original is None:
        return
    if '-v' in Flags:
        print(f"[v] SecurityTrails: checking historical IPs of WAF host {domain}")
    try:
        ips = get_historical_ips(domain)
    except SecurityTrailsQuotaExhausted:
        return
    for ip in ips:
        if _quota_exhausted.is_set():
            return
        finding = _probe_origin_behind_waf(ip, domain, original, proxies)
        if finding:
            Global.WAFBypassHosts.append(finding)


def _check_inactive_host(domain, proxies):
    if _quota_exhausted.is_set() or not any(character.isalpha() for character in domain):
        return
    if '-v' in Flags:
        print(f"[v] SecurityTrails: checking historical IPs of inactive host {domain}")
    try:
        ips = get_historical_ips(domain)
    except SecurityTrailsQuotaExhausted:
        return
    for ip in ips:
        if _quota_exhausted.is_set():
            return
        finding = _probe_inactive_host(ip, domain, proxies)
        if finding:
            Global.InactiveHostsAccess.append(finding)


def launch_securitytrails_scan():
    if not (Global.AssetsWithWAF or Global.RawSubdomains):
        return
    requests.packages.urllib3.disable_warnings()
    _quota_exhausted.clear()

    proxies = None
    if '-bb' in Flags:
        proxy_url = 'http://' + Global.BurpProxy
        proxies = {'http': proxy_url, 'https': proxy_url}

    live_hosts = get_host_from_url_list(Global.HTTPAssets + list(Global.AssetsWithWAF), remove_ports=True)
    inactive_hosts = []
    for raw in Global.RawSubdomains:
        domain = get_host_from_url(raw, remove_port=True)
        if domain and domain not in live_hosts and domain not in inactive_hosts:
            inactive_hosts.append(domain)

    waf_found_before = len(Global.WAFBypassHosts)
    inactive_found_before = len(Global.InactiveHostsAccess)
    print("[*] Searching for old subdomain IPs via SecurityTrails...")
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=Threads[Global.LoadLevel]['WAFbypassThreads']) as executor:
            futures = []
            for waf_url in list(Global.AssetsWithWAF):
                futures.append(executor.submit(_check_waf_host, waf_url, proxies))
                time.sleep(0.15)
            for domain in inactive_hosts:
                futures.append(executor.submit(_check_inactive_host, domain, proxies))
                time.sleep(0.15)
            concurrent.futures.wait(futures)
        if _quota_exhausted.is_set():
            print("[!] SecurityTrails query quota is exhausted - stopping SecurityTrails checks (results gathered so far are kept)")
    except KeyboardInterrupt:
        print("[!] Check aborted! Press Ctrl+C within the next 5 seconds if you want to exit completely.")
        time.sleep(5)

    new_waf = len(Global.WAFBypassHosts) - waf_found_before
    new_inactive = len(Global.InactiveHostsAccess) - inactive_found_before
    print(f"[+] SecurityTrails: found {new_waf} possible origin(s) behind WAF and {new_inactive} accessible inactive host(s)")
