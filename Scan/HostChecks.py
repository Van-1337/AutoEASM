from Global import Flags, Threads, CrawledURLs, URLsWithWAF, FuzzedDirectories, RawSubdomains
import Global
import time
import requests
import concurrent.futures
from Scan.Helpers import (
    get_host_from_url, get_host_from_url_list, get_random_string,
    is_site_available, is_WAF_signatures_in_response, is_site_real_by_response,
)


def launch_waf_bypass():
    def check_asset_with_WAF(domain_with_waf):
        try:
            orig_response = requests.get(domain_with_waf, verify=False, headers=user_agent_header, timeout=15,
                                         allow_redirects=False)
            for url_without_waf in Global.HTTPAssets:
                try:
                    headers = {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
                        "Host": get_host_from_url(domain_with_waf)}
                    last_response = requests.get(url_without_waf, verify=False, headers=headers, timeout=15,
                                                 allow_redirects=False)
                    if orig_response.status_code == last_response.status_code and \
                            orig_response.headers.get("Content-Type") == last_response.headers.get("Content-Type"):
                        if set(last_response.headers.keys()) != headers_sets[url_without_waf] and \
                                not is_WAF_signatures_in_response(last_response) and\
                                ("Location" not in last_response.headers or url_without_waf in last_response.headers["Location"])\
                                and ("location" not in last_response.headers or url_without_waf in last_response.headers["location"])\
                                and is_site_real_by_response(last_response):
                            Global.WAFBypassHosts.append((get_host_from_url(domain_with_waf), url_without_waf))
                            if send_to_burp:
                                try:
                                    requests.get(url_without_waf, verify=False, headers=headers, timeout=15,
                                                 proxies=proxies, allow_redirects=False)
                                except requests.RequestException:
                                    print(f"[e] Error sending request to {url_without_waf} with"
                                          f" {get_host_from_url(domain_with_waf)} host header to Burp Suite!")
                except requests.RequestException:
                    pass
        except requests.RequestException:
            pass

    if Global.HTTPAssets and Global.AssetsWithWAF:
        try:
            print("[*] Trying to bypass the WAF by finding the host on the same server without a firewall...")
            requests.packages.urllib3.disable_warnings()
            user_agent_header = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0"}
            wrong_host_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
                                   "Host": "qwertg.su"}
            send_to_burp = False
            if '-bb' in Flags:
                proxy_url = 'http://' + Global.BurpProxy
                proxies = {'http': proxy_url, 'https': proxy_url}
                send_to_burp = True

            headers_sets = {}
            for host_without_waf in Global.HTTPAssets:
                try:
                    response = requests.get(host_without_waf, verify=False, headers=wrong_host_headers, timeout=10, allow_redirects=False)
                    headers_sets[host_without_waf] = set(response.headers.keys())
                except requests.RequestException:
                    headers_sets[host_without_waf] = set()

            with concurrent.futures.ThreadPoolExecutor(max_workers=Threads[Global.LoadLevel]['WAFbypassThreads']) as executor:
                futures = []
                for url_with_waf in Global.AssetsWithWAF:
                    futures.append(executor.submit(check_asset_with_WAF, url_with_waf))
                    time.sleep(0.15)
                concurrent.futures.wait(futures)
        except KeyboardInterrupt:
            print("[!] Check aborted! Press Ctrl+C within the next 5 seconds if you want to exit completely.")
            time.sleep(5)
        print(f"[+] {len(Global.WAFBypassHosts)} successful WAF bypass attempts were done")


def launch_hidden_hosts_scan():
    def check_inactive_host(inactive_domain):
        def check_host_in_list(working_domains_list):
            found = False
            for working_url in working_domains_list:
                try:
                    headers = {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
                        "Host": inactive_domain}
                    last_response = requests.get(working_url, verify=False, headers=headers, timeout=15,
                                                 allow_redirects=False)
                    if set(last_response.headers.keys()) != headers_sets[working_url] and len(last_response.text) != responses_length[working_url]\
                            and last_response.status_code != 421 and last_response.status_code != 400 and last_response.status_code != 403 and \
                            last_response.status_code != 429 and last_response.status_code != 402 and last_response.status_code//100 != 5\
                            and ("Location" not in last_response.headers or get_host_from_url(working_url) in last_response.headers["Location"])\
                            and ("location" not in last_response.headers or get_host_from_url(working_url) in last_response.headers["location"])\
                            and is_site_real_by_response(last_response):
                        Global.InactiveHostsAccess.append((inactive_domain, working_url))
                        found = True
                        if send_to_burp:
                            try:
                                requests.get(working_url, verify=False, headers=headers, timeout=15,
                                             proxies=proxies, allow_redirects=False)
                            except requests.RequestException:
                                print(f"[e] Error sending request to {working_url} with"
                                      f" {inactive_domain} host header to Burp Suite!")
                except requests.RequestException:
                    pass
            return found

        if not is_site_available("https://" + inactive_domain):
            if not check_host_in_list(Global.HTTPAssets):
                check_host_in_list(assets_with_waf_list)

    if Global.HTTPAssets or Global.AssetsWithWAF:
        assets_with_waf_list = list(Global.AssetsWithWAF)
        try:
            print("[*] Trying to get access to old subdomains using host header manipulation...")
            requests.packages.urllib3.disable_warnings()
            send_to_burp = False
            if '-bb' in Flags:
                proxy_url = 'http://' + Global.BurpProxy
                proxies = {'http': proxy_url, 'https': proxy_url}
                send_to_burp = True

            headers_sets = {}
            responses_length = {}
            wrong_host_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0"}
            for host in Global.HTTPAssets + assets_with_waf_list:
                try:
                    wrong_host_headers["Host"] = f"{get_random_string(10)}.com"
                    response = requests.get(host, verify=False, headers=wrong_host_headers, timeout=15, allow_redirects=False)
                    headers_sets[host] = set(response.headers.keys())
                    body_length = len(response.text)
                    if body_length:
                        responses_length[host] = body_length
                    else:
                        responses_length[host] = 13371337
                except requests.RequestException:
                    headers_sets[host] = set()
                    responses_length[host] = 13371338

            with concurrent.futures.ThreadPoolExecutor(max_workers=Threads[Global.LoadLevel]['WAFbypassThreads']) as executor:
                futures = []
                inactive_hosts = [x for x in RawSubdomains if x not in get_host_from_url_list(Global.HTTPAssets + assets_with_waf_list, remove_ports=True)]
                for inactive_host in inactive_hosts:
                    futures.append(executor.submit(check_inactive_host, inactive_host))
                    time.sleep(0.1)
                concurrent.futures.wait(futures)
        except KeyboardInterrupt:
            print("[!] Check aborted! Press Ctrl+C within the next 5 seconds if you want to exit completely.")
            time.sleep(5)
        print(f"[+] Access to {len(Global.InactiveHostsAccess)} hosts were found")


def send_urls_to_burp():
    proxy_url = 'http://' + Global.BurpProxy
    proxies = {'http': proxy_url, 'https': proxy_url}
    requests.packages.urllib3.disable_warnings()
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0"}
    print("[*] Sending requests to Burp in parallel...")

    if '-ba' in Flags or '-bw' in Flags:
        for url in CrawledURLs:
            try:
                requests.get(url, proxies=proxies, verify=False, headers=headers, timeout=10)
            except requests.RequestException:
                print(f"[e] Error sending request to {url}")
    if '-ba' in Flags:
        for url in URLsWithWAF:
            try:
                requests.get(url, proxies=proxies, verify=False, headers=headers, timeout=10)
            except requests.RequestException:
                print(f"[e] Error sending request to {url}")
    if '-bf' in Flags:
        for code in FuzzedDirectories:
            for url in FuzzedDirectories[code]:
                try:
                    requests.get(url, proxies=proxies, verify=False, headers=headers, timeout=10)
                except requests.RequestException:
                    print(f"[e] Error sending request to {url}")
    print("[*] All requests were sent to Burp proxy!")
