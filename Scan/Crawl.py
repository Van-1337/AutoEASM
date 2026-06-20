from Global import (
    Flags, Threads, Details, CrawledURLs, URLsWithWAF, JSlinks,
    Katana_command, CDNCheck_command, Uro_command,
)
import Global
import os
import re
import json
import requests
from Scan.CommandRun import command_exec
from Scan.Helpers import (
    remove_non_links, get_host_from_url, get_host_from_url_list, is_site_available,
)


def launch_katana():
    def launch(are_hosts_with_WAF=False):
        if are_hosts_with_WAF:
            working_domains = list(Global.AssetsWithWAF)
        else:
            working_domains = Global.HTTPAssets
        if working_domains:
            input_data = '\n'.join(working_domains) + '\n'
            command = Katana_command.substitute(
                KatanaAdditionalFlags=Details[Global.DetailsLevel]['KatanaAdditionalFlags'],
                KatanaParallels=str(Threads[Global.LoadLevel]['KatanaParallels']),
                KatanaRate=Threads[Global.LoadLevel]['KatanaRate'])
            if "-ds" in Flags:
                command += " -fs fqdn"
            jsonl_file = None
            if "-daff" not in Flags:
                if are_hosts_with_WAF:
                    jsonl_file = Global.RunDir + "/Katana_WAF.jsonl"
                else:
                    jsonl_file = Global.RunDir + "/Katana.jsonl"
                command += f" -aff -j -o {jsonl_file}"
            if are_hosts_with_WAF:
                print("[*] Crawling URLs on hosts with WAF...")
                if "-dh" not in Flags:
                    command += " -headless --no-sandbox"
            else:
                print("[*] Crawling URLs on hosts without WAF...")

            if '-v' in Flags:
                print("[v] Executing command: " + command)
            result = command_exec(command, "Katana.txt", input_data)

            if result != "-":
                requests.packages.urllib3.disable_warnings()

                if jsonl_file and os.path.exists(jsonl_file):
                    try:
                        with open(jsonl_file, 'r', encoding='utf-8') as f:
                            jsonl_urls = []
                            for line in f:
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    entry = json.loads(line)
                                    if 'request' in entry and 'endpoint' in entry['request']:
                                        request = entry['request']
                                        method = request.get('method', '').upper()
                                        endpoint = request['endpoint']
                                        if method == 'GET' and endpoint.startswith(('http://', 'https://')):
                                            jsonl_urls.append(endpoint)
                                except json.JSONDecodeError:
                                    continue
                        Global.CrawledURLs.extend(jsonl_urls)
                    except OSError as e:
                        if '-v' in Flags:
                            print(f"[v] Error parsing JSONL file: {e}")
                        Global.CrawledURLs.extend(remove_non_links(result))
                else:
                    Global.CrawledURLs.extend(remove_non_links(result))

                if "-ds" not in Flags:
                    host_urls = []
                    for link in Global.CrawledURLs:
                        host_url = get_host_from_url(link, False, True)
                        if host_url and host_url not in host_urls:
                            host_urls.append(host_url)
                    for host_url in host_urls:
                        if host_url not in Global.RawSubdomains:
                            Global.RawSubdomains.append(host_url)
                        if host_url not in Global.HTTPAssets and is_site_available(host_url):
                            Global.HTTPAssets.append(host_url)
                    Global.RawSubdomains = [x for x in Global.RawSubdomains if x not in Global.ExcludedHosts]
                    Global.HTTPAssets = [x for x in Global.HTTPAssets if x not in Global.ExcludedHosts]
                    print(f"[+] {(len(Global.CrawledURLs))} links were found")
            else:
                print("[e] Error when running Katana utility")

    launch(are_hosts_with_WAF=False)
    launch(are_hosts_with_WAF=True)


def launch_uro():
    if CrawledURLs:
        input_data = '\n'.join(CrawledURLs) + '\n'
        command = Uro_command
        print("[*] Removing duplicate links...")
        if '-v' in Flags:
            print("[v] Executing command: " + command)
        result = command_exec(command, "URO.txt", input_data)

        if result != '-':
            Global.CrawledURLs = result
            for link in CrawledURLs:
                if '.js' in link:
                    JSlinks.append(link)
        else:
            print("[e] Error when running Uro utility")


def delete_assets_with_waf(start_from=0):
    if start_from == len(Global.HTTPAssets):
        return
    assets_list_file = Global.RunDir + "/HTTP_assets_list.txt"
    with open(assets_list_file, "w", encoding="utf-8") as file:
        for site in Global.HTTPAssets[start_from:]:
            file.write(site.replace("https://", "").replace("http://", "") + "\n")

    command = CDNCheck_command.substitute(AssetsListFile=assets_list_file)
    if start_from == 0:
        print("[*] Checking WAFs on found services...")
    else:
        print("[*] Checking WAFs on newly found services...")

    if '-v' in Flags:
        print("[v] Executing command: " + command)
    result = command_exec(command, "CDNcheck.txt")

    if result != '-':
        print("[*] Remove all sites with firewalls from the list...")
        for item in result:
            parts = item.split()
            if len(parts) >= 3:
                host_with_waf = parts[0]
                waf = ' '.join(parts[2:]).strip("[]")

                for index, url in enumerate(Global.HTTPAssets):
                    current_host = url.replace("https://", "").replace("http://", "")
                    if current_host == host_with_waf:
                        Global.AssetsWithWAF[url] = waf
                        del Global.HTTPAssets[index]
                        break
            else:
                print(f"[e] String '{item}' has the wrong format and will be skipped.")
    else:
        print("[e] Error when running CDNCheck utility")
        print("[e] Warning: all web application will be considered as without firewall!!")


def delete_urls_with_waf():
    if '-v' in Flags:
        print("[v] Divide the links into those with and without WAF...")

    hosts_with_waf = get_host_from_url_list(Global.AssetsWithWAF)
    for index, url in enumerate(CrawledURLs):
        current_host = get_host_from_url(url)
        if current_host in hosts_with_waf:
            URLsWithWAF.append(url)
            del CrawledURLs[index]


def check_social_networks():
    def social_media_account_exists(account_link):
        sm_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                   "Sec-Fetch-Site": "none"}

        if "youtube.com" in account_link:
            # From EU IPs YouTube 302-redirects every channel URL to its cookie-consent
            # page (HTTP 200), hiding the real 404 for non-existent channels. SOCS=CAI
            # skips that page so the status code stays meaningful.
            sm_headers["Cookie"] = "SOCS=CAI"
        elif account_link.startswith("tg://"):
            account_link = "https://t.me/" + account_link.split('=')[1]

        try:
            link_response = requests.get(account_link, headers=sm_headers, timeout=10)
        except requests.RequestException:
            print(f"[e] Error during social media checking when sending request to {account_link}")
            return True
        if "tiktok.com" in account_link:
            if '"userInfo":{' in link_response.text:
                return True
            return False
        if "youtube.com/" in account_link:
            if link_response.status_code == 404:
                return False
            return True
        if "//t.me" in account_link or "//telegram" in account_link:
            if '<meta name="twitter:description" content="\n">' in link_response.text:
                return False
            return True
        if "facebook.com" in account_link or "fb.com/" in account_link:
            if '<title>Facebook</title>' in link_response.text:
                return False
            return True
        if "instagram.com" in account_link or "instagr.am" in account_link:
            if '<title>Instagram</title>' in link_response.text:
                return False
            return True
        print(f"[e] Error when checking social media account existence (link: {account_link})")
        return True

    requests.packages.urllib3.disable_warnings()
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0"}
    # Each network keeps its patterns next to the relevance probe. should_exist_on_test
    # is the expected result of social_media_account_exists for test_url: a fake account
    # should report False, a real account True. If reality differs the detection is
    # unreliable, so that network's patterns are skipped for this run.
    networks = [
        {
            "name": "Telegram",
            "patterns": [
                r'https?://(?:t(?:elegram)?\.me|telegram\.org)/[A-Za-z0-9_]{5,32}/?',
                r'tg?://resolve\?domain=[A-Za-z0-9_]+/?',
            ],
            "test_url": "https://t.me/gjenwoepnfwvj",
            "should_exist_on_test": False,
        },
        {
            "name": "Tiktok",
            "patterns": [r'https?://(?:www\.)tiktok\.com/@[A-Za-z0-9_.-]+/?'],
            "test_url": "https://www.tiktok.com/@tiktok",
            "should_exist_on_test": True,
        },
        {
            "name": "Youtube",
            "patterns": [
                r'https?://(?:[A-Za-z]+\.)?youtube\.com/channel/[A-Za-z0-9-_]+/?',
                r'https?://(?:[A-Za-z]+\.)?youtube\.com/user/[A-Za-z0-9]+/?',
                r'https?://(?:[A-Za-z]+\.)?youtube\.com/@[A-Za-z0-9\-_]+/?',
                r'https?://(?:[A-Za-z]+\.)?youtube\.com/(?!(?:user|channel|embed|watch|playlist)/)[A-Za-z0-9-_]+/?',
            ],
            "test_url": "https://www.youtube.com/@gjenwoepnfwvj",
            "should_exist_on_test": False,
        },
        {
            "name": "Facebook",
            "patterns": [
                r'https?://(?:www\.)?(?:facebook|fb)\.com/(?![A-Za-z]+\.php|marketplace|gaming|watch|me|messages|help|search|groups|tr|people|share)[A-Za-z0-9_\-\.]+/?',
                r'https?://(?:www\.)?facebook\.com/profile\.php\?id=\d+/?',
            ],
            "test_url": "https://www.facebook.com/iufqnoiqfenoiep",
            "should_exist_on_test": False,
        },
        {
            "name": "Instagram",
            "patterns": [r'https?://(?:www\.)?(?:instagram\.com|instagr\.am)/(?!p/)[A-Za-z0-9_.]{1,30}/?'],
            "test_url": "https://www.instagram.com/gwprhgwirpgmwr",
            "should_exist_on_test": False,
        },
    ]

    print("[*] Checking social networks takeover in parallel...")
    patterns = []
    for network in networks:
        if social_media_account_exists(network["test_url"]) == network["should_exist_on_test"]:
            patterns.extend(network["patterns"])
        else:
            print(f"[e] {network['name']} account check is not relevant! Please contact developer for update.")

    existing_media = set()
    for url in Global.CrawledURLs + Global.URLsWithWAF:
        if '.js' not in url:
            try:
                response = requests.get(url, verify=False, headers=headers, timeout=10)
                response.raise_for_status()
                found_links = set()
                for pattern in patterns:
                    matches = re.findall(pattern, response.text)
                    found_links.update(matches)
                for media_link in found_links:
                    if media_link not in existing_media:
                        if social_media_account_exists(media_link):
                            existing_media.add(media_link)
                        else:
                            Global.NotExistingSocialMediaLinks.append((url, media_link))
            except requests.RequestException:
                pass
    print(f"[+] {len(Global.NotExistingSocialMediaLinks)} unregistered social media links were found")
