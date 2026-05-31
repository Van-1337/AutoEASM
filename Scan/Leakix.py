from Global import LeakixFindings
import Global
import time
import json
import requests
from typing import List
from Scan.Helpers import get_host_from_url_list, extract_leakix_vulnerability, is_date_actual


def check_leakix():
    def check_url_with_leakix(domain: str, api_key: str) -> List[dict]:
        url = f'https://leakix.net/search?scope=leak&page=0&q="{domain}"'
        headers = {
            "accept": "application/json",
            "api-key": api_key
        }
        try:
            response = requests.get(url, headers=headers, timeout=20)
            response.raise_for_status()
        except requests.RequestException as e:
            raise ValueError(f"[e] Error when sending request: {e}")

        if 'application/json' not in response.headers.get('Content-Type', ''):
            raise ValueError("[e] Server response is not JSON")

        try:
            data = response.json()
        except json.JSONDecodeError:
            raise ValueError("[e] Failed to decode response as JSON")

        if not data:
            raise ValueError("[e] Empty JSON response received")
        if not isinstance(data, list):
            raise ValueError("[e] A list of JSON objects was expected")
        return data

    def get_domains_info(domains):
        for domain in get_host_from_url_list(domains, remove_ports=True):
            checked = False
            unsuccessful_attempts = 0
            while not checked:
                try:
                    data = check_url_with_leakix(domain, Global.LeakixAPIKey)
                    for info in data:
                        vuln = extract_leakix_vulnerability(info)
                        if is_date_actual(vuln.time):
                            LeakixFindings.append(vuln)
                    checked = True
                except ValueError as e:
                    if "429" in str(e):
                        unsuccessful_attempts += 1
                        if unsuccessful_attempts > 10:
                            print("[e] Leakix is not working!")
                            return
                        time.sleep(5)
                    else:
                        checked = True
                time.sleep(1)

    if Global.HTTPAssets or Global.AssetsWithWAF:
        print("[*] Checking domains on Leakix in parallel...")
        if Global.HTTPAssets:
            get_domains_info(Global.HTTPAssets)
        if Global.AssetsWithWAF:
            get_domains_info(list(Global.AssetsWithWAF.keys()))
        Global.LeakixFindings = list(dict.fromkeys(Global.LeakixFindings))
        print(f"[+] {len(Global.LeakixFindings)} issues were found on Leakix")
