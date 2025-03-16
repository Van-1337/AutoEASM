from Global import *
import Global
from Scan.Helpers import *
import subprocess
import sys
import os
import threading
import time
import requests
from typing import List
import json
import glob
import concurrent.futures


def scanning():
    print("[N] Note: you can stop a current check with Ctrl+C")
    try:
        if check_installed_tools() != 0:
            print("[e] Not all required utilities are installed. Terminating.")
            sys.exit(1)
        if ensure_logs_directory():
            clear_logs()
        if '-ds' in Flags or '-i' in Flags:
            launch_subfinder_dnsx_naabu(scan_subdomains=False)
        else:
            launch_subfinder_dnsx_naabu(scan_subdomains=True)
            launch_subfinder_dnsx_naabu(scan_subdomains=False, console_output=False)  # Fixing strange Naabu bug where a root domain
            # is not in the results when there are a lot of subdomains with it. When the bug is fixed, just remove this line
        if '-dp' not in Flags and '-i' not in Flags:
            postleaks_thread = threading.Thread(target=launch_postleaks, name="PostleaksThread", daemon=True)
            postleaks_thread.start()
            time.sleep(1)  # To avoid problems with console output
        launch_httpx()
        if '-dc' not in Flags:
            launch_katana()
            launch_uro()
        else:
            Global.CrawledURLs = Global.HTTPAssets
        delete_assets_with_waf()  # And add them to AssetsWithWAF
        delete_urls_with_waf()  # And add them to URLsWithWAF
        if '-dw' not in Flags:
            launch_waf_bypass()
        if '-di' not in Flags:
            launch_hidden_hosts_scan()
        if '-dl' not in Flags:
            leakix_thread = threading.Thread(target=check_leakix, name="LeakixThread", daemon=True)
            leakix_thread.start()
            time.sleep(1)  # To avoid problems with console output
        if '-ba' in Flags or '-bw' in Flags or '-bf' in Flags:
            burp_sending_thread = threading.Thread(target=send_urls_to_burp, name="BurpSendingThread", daemon=True)
            burp_sending_thread.start()
            time.sleep(1)  # To avoid problems with console output
        if '-dm' not in Flags:
            social_networks_thread = threading.Thread(target=check_social_networks, name="CheckSocialNetworksThread", daemon=True)
            social_networks_thread.start()
            time.sleep(1)  # To avoid problems with console output
        if '-dt' not in Flags and Global.RawSubdomains:
            check_subdomains_takeover()
        if '-dn' not in Flags:
            launch_nuclei()
        if '-df' not in Flags:
            launch_feroxbuster()
        if '-db' not in Flags:
            launch_byp4xx()

        if 'postleaks_thread' in locals() and postleaks_thread.is_alive():
            print("[*] Waiting until postleaks finishes working...")
            global is_postleaks_waiting
            is_postleaks_waiting = True
            postleaks_thread.join()
        if 'burp_sending_thread' in locals() and burp_sending_thread.is_alive():
            print("[*] Waiting until all requests sending to Burp...")
            try:
                while burp_sending_thread.is_alive():
                    burp_sending_thread.join(timeout=1)
            except KeyboardInterrupt:
                print("[*] Finishing sending requests to Burp...")
        if 'leakix_thread' in locals() and leakix_thread.is_alive():
            print("[*] Waiting until leakix information collection finishes...")
            try:
                while leakix_thread.is_alive():
                    leakix_thread.join(timeout=1)
            except KeyboardInterrupt:
                print("[*] Finishing leakix check...")
        if 'social_networks_thread' in locals() and social_networks_thread.is_alive():
            print("[*] Waiting until social media takeover checks finishes...")
            try:
                while social_networks_thread.is_alive():
                    social_networks_thread.join(timeout=1)
            except KeyboardInterrupt:
                print("[*] Finishing social networks check...")
    except KeyboardInterrupt:
        print("[!] Ctrl+C detected, exiting...")
        sys.exit(1)


def command_exec(command, filename, input_data=None, filter_ansi=False):
    command = f'({command}) > Logs/{filename}'
    interrupted = False
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, input=input_data)
    except KeyboardInterrupt:
        print("[!] Command aborted! Press Ctrl+C within the next 5 seconds if you want to exit completely.")
        time.sleep(5)
        interrupted = True
    if interrupted or result.returncode == 0:
        if not interrupted and result.stdout and '-v' in Flags:
            print(f"[v] Got additional info in console when executing {command}\n{result.stdout}")

        if filter_ansi:
            output_file = open('Logs/' + filename, "r+")
            clean_command_output = remove_ansi_escape_codes(output_file.read())
            output_file.seek(0)
            output_file.write(clean_command_output)
            output_file.truncate()
            output_file.close()
            return clean_command_output.splitlines()
        else:
            output_file = open('Logs/' + filename, "r")
            command_output = output_file.read()
            output_file.close()
            return command_output.splitlines()
    else:
        print(f"[e] Error when running this command: {command}")
        print("[e] Error: " + result.stderr)
        return "-"


def clear_logs():
    directory = 'Logs'
    pattern = os.path.join(directory, '*.txt')
    txt_files = glob.glob(pattern)
    for file_path in txt_files:
        try:
            os.remove(file_path)
        except Exception as e:
            print(f'[e] {file_path} Can\'t be deleted. The reason is: {e}')


def check_installed_tools():
    errors_count = 0
    for utility in utilities_flags:
        if utilities_flags[utility] not in Flags:
            result = subprocess.run(f"{utility} -h", shell=True, capture_output=True)
            if result.returncode != 0:
                errors_count += 1
                if utilities_flags[utility] == "No flag":
                    print(f"[!] {utility} was not found, please install it and add to the path!")
                else:
                    print(f"[!] {utility} was not found, please install it and add to the path or use {utilities_flags[utility]} flag!")
    if not ("-dn" in Flags and "-dt" in Flags):
        nuclei_result = subprocess.run(f"nuclei -h", shell=True, capture_output=True)
        if nuclei_result.returncode != 0:
            print(f"[!] Nuclei was not found, please install it and add to the path or use both -dn and -dt flags!")
            errors_count += 1
    return errors_count


def launch_httpx():
    def delete_443_80_ports_from_assets():  # without this, hosts like "https://comfy.ua:80" sometimes appears
        for i in range(len(Global.HTTPAssets)):
            Global.HTTPAssets[i] = Global.HTTPAssets[i].replace(":80", "").replace(":443", "")
        Global.HTTPAssets = list(dict.fromkeys(Global.HTTPAssets))

    input_data = '\n'.join(Global.Services) + '\n'
    command = HTTPX_command.substitute(HTTPXthreads=Threads[Global.LoadLevel]['HTTPXthreads'],
                                       HTTPXrate=Threads[Global.LoadLevel]['HTTPXrate'])
    print("[*] Searching for HTTP services...")

    if '-v' in Flags:
        print("[v] Executing command: " + command)
    result = command_exec(command, "HTTPX.txt", input_data)
    # result = subprocess.run(command, input=input_data, shell=True, capture_output=True, text=True)

    if result != "-":
        # HTTPAssets.extend(delete_http_duplicates(result.stdout.splitlines()))
        HTTPAssets.extend(delete_http_duplicates(result))
        delete_443_80_ports_from_assets()
        #if '-ba' in Flags or '-bw' in Flags or '-bf' in Flags:
        #    for index, host in enumerate(Global.HTTPAssets):
        #        if host.startswith('http://localhost.'):  # Deleting hosts like localhost.vulnweb.com
        #            del Global.HTTPAssets[index]
        print(f"[+] {len(HTTPAssets)} active web services will be scanned")
    else:
        print("[e] Error when running HTTPX utility.")
        sys.exit(1)


def launch_subfinder_dnsx_naabu(scan_subdomains, console_output=True):
    input_data = '\n'.join(Global.Domains) + '\n'

    if '-i' in Flags:
        command = Naabu_command.substitute(NaabuThreads=Threads[Global.LoadLevel]['NaabuThreads'], NaabuRate=Threads[Global.LoadLevel]['NaabuRate'],
                                           NaabuPorts=Details[Global.DetailsLevel]['NaabuPorts'], NaabuFlags=Details[Global.DetailsLevel]['NaabuFlags'])
        if console_output:
            print("[*] Getting open network services on specified IP addresses...")
    else:
        if scan_subdomains:  # If not skipping subdomains enumeration
            if console_output:
                print("[*] Searching subdomains...")
            if '-v' in Flags:
                print("[v] Executing command: " + Subfinder_command)
            result = subprocess.run(Subfinder_command, shell=True, capture_output=True, text=True, input=input_data)

            if result.returncode == 0:
                Global.RawSubdomains.extend(result.stdout.splitlines())
                input_data = '\n'.join(Global.RawSubdomains) + '\n' + '\n'.join(Global.Domains) + '\n'
            else:
                print("[e] Error when running Subfinder utility:")
                print("[e] Command: " + Subfinder_command)
                print("[e] Error: " + result.stderr)
                sys.exit(1)

        command = DNSX_Naabu_command.substitute(dnsxThreads=Threads[Global.LoadLevel]['DNSX'], NaabuThreads=Threads[Global.LoadLevel]['NaabuThreads'],
                                                NaabuRate=Threads[Global.LoadLevel]['NaabuRate'], NaabuPorts=Details[Global.DetailsLevel]['NaabuPorts'],
                                                NaabuFlags=Details[Global.DetailsLevel]['NaabuFlags'])
        if console_output:
            print("[*] Getting open network services...")

    if '-v' in Flags:
        print("[v] Executing command: " + command)
    result = subprocess.run(command, shell=True, capture_output=True, text=True, input=input_data)

    if result.returncode == 0:
        Global.Services.extend(result.stdout.splitlines())
        Global.Services = list(dict.fromkeys(Global.Services))  # Filter duplicates
        if '-ba' in Flags or '-bw' in Flags or '-bf' in Flags:
            for index, service in enumerate(Global.Services):
                if service.startswith('localhost.'):  # Deleting hosts like localhost.vulnweb.com
                    del Global.Services[index]
    else:
        print("[e] Error when running Subfinder, DNSX or Naabu utilities:")
        print("[e] Command: " + command)
        print("[e] Error: " + result.stderr)
        sys.exit(1)


def launch_katana():
    if Global.HTTPAssets:
        input_data = '\n'.join(Global.HTTPAssets) + '\n'
        command = Katana_command.substitute(KatanaAdditionalFlagsD=Details[Global.DetailsLevel]['KatanaAdditionalFlagsD'],
                                            KatanaAdditionalFlagsT=Threads[Global.LoadLevel]['KatanaAdditionalFlagsT'])
        if "-ds" in Flags:
            command += " -fs fqdn"
        if "-aff" in Flags:
            command += " -aff"
        print("[*] Crawling URLs...")

        if '-v' in Flags:
            print("[v] Executing command: " + command)
        result = command_exec(command, "Katana.txt", input_data)

        if result != "-":
            requests.packages.urllib3.disable_warnings()
            Global.CrawledURLs.extend(remove_non_links(result))
            if "-ds" not in Flags:
                for link in Global.CrawledURLs:
                    slashes_amount = link.count('/')
                    if slashes_amount == 2 and (link + '/') not in Global.HTTPAssets and link not in Global.HTTPAssets:
                        if is_site_available(link):
                            Global.HTTPAssets.append(link)
                        if slashes_amount == 2 and (link + '/') not in Global.RawSubdomains and link not in Global.RawSubdomains:
                            Global.RawSubdomains.append(link)
                    elif slashes_amount == 3 and link[-1] == '/' and link not in Global.HTTPAssets and link[:-1] not in Global.HTTPAssets:
                        Global.HTTPAssets.append(link[:-1])
                        if slashes_amount == 3 and link[-1] == '/' and link not in Global.RawSubdomains and link[:-1] not in Global.RawSubdomains:
                            if is_site_available(link):
                                Global.RawSubdomains.append(link[:-1])
                print(f"[+] {(len(Global.CrawledURLs))} links were found")
        else:
            print("[e] Error when running Katana utility")


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


def delete_assets_with_waf():
    with open("Scan/HTTP_assets_list.txt", "w", encoding="utf-8") as file:
        for site in HTTPAssets:
            file.write(site.replace("https://", "").replace("http://", "") + "\n")

    command = CDNCheck_command
    print("[*] Checking WAFs on found services...")

    if '-v' in Flags:
        print("[v] Executing command: " + command)
    result = command_exec(command, "CDNcheck.txt")

    if result != '-':
        print("[*] Remove all sites with firewalls from the list...")
        for item in result:
            parts = item.split()
            if len(parts) >= 3:
                host = parts[0]
                waf = ' '.join(parts[2:]).strip("[]")

                for index, url in enumerate(HTTPAssets):  # Deleting host with WAF from the list
                    current_host = url.replace("https://", "").replace("http://", "")
                    if current_host == host:
                        AssetsWithWAF[url] = waf
                        del HTTPAssets[index]
                        break
            else:
                print(f"[e] String '{item}' has the wrong format and will be skipped.")
    else:
        print("[e] Error when running CDNCheck utility")
        print("[e] Warning: all web application will be considered as without firewall!!")

    if os.path.exists("Scan/HTTP_assets_list.txt"):
        os.remove("Scan/HTTP_assets_list.txt")


def delete_urls_with_waf():
    if '-v' in Flags:
        print("[v] Divide the links into those with and without WAF...")

    hosts_with_waf = get_host_from_url_list(AssetsWithWAF)
    for index, url in enumerate(CrawledURLs):  # Deleting links with WAF from the list
        current_host = get_host_from_url(url)
        if current_host in hosts_with_waf:
            URLsWithWAF.append(url)
            del CrawledURLs[index]


def launch_waf_bypass():
    def check_asset_with_WAF(domain_with_waf):
        try:
            orig_response = requests.get(domain_with_waf, verify=False, headers=user_agent_header, timeout=10,
                                         allow_redirects=False)
            for url_without_waf in HTTPAssets:
                try:
                    headers = {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
                        "Host": get_host_from_url(domain_with_waf)}
                    last_response = requests.get(url_without_waf, verify=False, headers=headers, timeout=10,
                                                 allow_redirects=False)
                    if orig_response.status_code == last_response.status_code and \
                            orig_response.headers.get("Content-Type") == last_response.headers.get("Content-Type"):
                        if set(last_response.headers.keys()) != headers_sets[url_without_waf] and \
                                not is_cloudflare_in_response(last_response) and\
                                ("Location" not in last_response.headers or url_without_waf in last_response.headers["Location"])\
                                and ("location" not in last_response.headers or url_without_waf in last_response.headers["location"]):
                            Global.WAFBypassHosts.append((get_host_from_url(domain_with_waf), url_without_waf))
                            if send_to_burp:
                                try:
                                    requests.get(url_without_waf, verify=False, headers=headers, timeout=10,
                                                 proxies=proxies, allow_redirects=False)
                                except requests.RequestException:
                                    print(f"[e] Error sending request to {url_without_waf} with"
                                          f" {get_host_from_url(domain_with_waf)} host header to Burp Suite!")
                except requests.RequestException:
                    pass
        except requests.RequestException:
            pass

    if HTTPAssets and AssetsWithWAF:
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

            headers_sets = {}  # {"example.com": set("Date", "Content-Type", "Content-Length")}
            for host_without_waf in HTTPAssets:
                try:
                    response = requests.get(host_without_waf, verify=False, headers=wrong_host_headers, timeout=10, allow_redirects=False)
                    headers_sets[host_without_waf] = set(response.headers.keys())
                except requests.RequestException:
                    headers_sets[host_without_waf] = set()

            with concurrent.futures.ThreadPoolExecutor(max_workers=Threads[Global.LoadLevel]['WAFbypassThreads']) as executor:
                futures = []
                for url_with_waf in AssetsWithWAF:
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
                    last_response = requests.get(working_url, verify=False, headers=headers, timeout=10,
                                                 allow_redirects=False)
                    if set(last_response.headers.keys()) != headers_sets[working_url] and len(last_response.text) != responses_length[working_url]\
                            and last_response.status_code != 421 and last_response.status_code != 400 and last_response.status_code != 403 and \
                            last_response.status_code != 429 and last_response.status_code != 402 and last_response.status_code//100 != 5\
                            and ("Location" not in last_response.headers or get_host_from_url(working_url) in last_response.headers["Location"])\
                            and ("location" not in last_response.headers or get_host_from_url(working_url) in last_response.headers["location"]):
                        Global.InactiveHostsAccess.append((inactive_domain, working_url))
                        found = True
                        if send_to_burp:
                            try:
                                requests.get(working_url, verify=False, headers=headers, timeout=10,
                                             proxies=proxies, allow_redirects=False)
                            except requests.RequestException:
                                print(f"[e] Error sending request to {working_url} with"
                                      f" {inactive_domain} host header to Burp Suite!")
                except requests.RequestException:
                    pass
            return found

        if not is_site_available("https://" + inactive_domain):  # Check if the host is really inactive. If inactive - then start checking
            if not check_host_in_list(HTTPAssets):
                check_host_in_list(AssetsWithWAFlist)

    if HTTPAssets or AssetsWithWAF:
        AssetsWithWAFlist = list(AssetsWithWAF)
        try:
            print("[*] Trying to get access to old subdomains using host header manipulation...")
            requests.packages.urllib3.disable_warnings()
            send_to_burp = False
            if '-bb' in Flags:
                proxy_url = 'http://' + Global.BurpProxy
                proxies = {'http': proxy_url, 'https': proxy_url}
                send_to_burp = True

            headers_sets = {}  # {"example.com": set("Date", "Content-Type", "Content-Length")}
            responses_length = {}  # {"example.com": 50505} - means response body length
            wrong_host_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0"}
            for host in HTTPAssets+AssetsWithWAFlist:
                try:
                    wrong_host_headers["Host"] = f"{get_random_string(10)}.com"
                    response = requests.get(host, verify=False, headers=wrong_host_headers, timeout=10, allow_redirects=False)
                    headers_sets[host] = set(response.headers.keys())
                    body_length = len(response.text)
                    if body_length:
                        responses_length[host] = body_length
                    else:
                        responses_length[host] = 13371337  # If the response body length is 0, then the length comparison
                                                           # should be ignored to avoid a large number of false-negatives
                except requests.RequestException:
                    headers_sets[host] = set()
                    responses_length[host] = 13371338

            with concurrent.futures.ThreadPoolExecutor(max_workers=Threads[Global.LoadLevel]['WAFbypassThreads']) as executor:
                futures = []
                inactive_hosts = [x for x in RawSubdomains if x not in get_host_from_url_list(HTTPAssets + AssetsWithWAFlist, remove_ports=True)]
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


def check_social_networks():
    def is_social_media_exist(social_media_link):
        sm_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                   "Sec-Fetch-Site": "none"}

        if "//youtube.com" in social_media_link:
            if social_media_link[-1] == '/':
                social_media_link = social_media_link[:-1] + "?cbrd=1"  # To skip cookies accept for EU users
            elif '?' in social_media_link:
                social_media_link += "&cbrd=1"
            else:
                social_media_link += "?cbrd=1"
        elif social_media_link.startswith("tg://"):
            social_media_link = "https://t.me/" + social_media_link.split('=')[1]

        try:
            link_response = requests.get(social_media_link, headers=sm_headers, timeout=10)
        except requests.RequestException:
            print(f"[e] Error during social network checking when sending request to {social_media_link}")
            return True
        if "tiktok.com" in social_media_link:
            if '"userInfo":{' in link_response.text:
                return True
            else:
                return False
        elif "youtube.com/" in social_media_link:
            if link_response.status_code == 404:
                return False
            else:
                return True
        elif "//t.me" in social_media_link or "//telegram" in social_media_link:
            if '<meta name="twitter:description" content="\n">' in link_response.text:
                return False
            else:
                return True
        elif "facebook.com" in social_media_link or "fb.com/" in social_media_link:
            if '<title>Facebook</title>' in link_response.text:
                return False
            else:
                return True
        elif "instagram.com" in social_media_link or "instagr.am" in social_media_link:
            if '<title>Instagram</title>' in link_response.text:
                return False
            else:
                return True
        print(f"[e] Error when checking social network existing (link: {social_media_link})")
        return True

    requests.packages.urllib3.disable_warnings()
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0"}
    patterns = [
        r'https?://(?:t(?:elegram)?\.me|telegram\.org)/[A-Za-z0-9_]{5,32}/?',
        r'https?://(?:www\.)tiktok\.com/@[A-Za-z0-9_.-]+/?',
        r'https?://(?:[A-Za-z]+\.)?youtube\.com/channel/[A-Za-z0-9-_]+/?',
        r'https?://(?:[A-Za-z]+\.)?youtube\.com/user/[A-Za-z0-9]+/?',
        r'https?://(?:[A-Za-z]+\.)?youtube\.com/@[A-Za-z0-9\-_]+/?',
        r'https?://(?:[A-Za-z]+\.)?youtube\.com/(?!(?:user|channel|embed|watch|playlist)/)[A-Za-z0-9-_]+/?',
        r'https?://(?:www\.)?(?:instagram\.com|instagr\.am)/(?!p/)[A-Za-z0-9_.]{1,30}/?',
        r'https?://(?:www\.)?(?:facebook|fb)\.com/(?![A-Za-z]+\.php|marketplace|gaming|watch|me|messages|help|search|groups|tr|people)[A-Za-z0-9_\-\.]+/?',
        r'https?://(?:www\.)?facebook\.com/profile\.php\?id=\d+/?',
        r'tg?://resolve\?domain=[A-Za-z0-9_]+/?'
    ]

    def checking_relevance():
        if is_social_media_exist("https://t.me/gjenwoepnfwvj"):
            patterns.remove(r'https?://(?:t(?:elegram)?\.me|telegram\.org)/[A-Za-z0-9_]{5,32}/?')
            patterns.remove(r'tg?://resolve\?domain=[A-Za-z0-9_]+/?')
            print("[e] Telegram account check is not relevant! Please contact developer for update.")
        if not is_social_media_exist("https://www.tiktok.com/@tiktok"):
            patterns.remove(r'https?://(?:www\.)tiktok\.com/@[A-Za-z0-9_.-]+/?')
            print("[e] Tiktok account check is not relevant! Please contact developer for update.")
        if is_social_media_exist("https://www.youtube.com/@gjenwoepnfwvj"):
            patterns.remove(r'https?://(?:[A-Za-z]+\.)?youtube\.com/channel/[A-Za-z0-9-_]+/?')
            patterns.remove(r'https?://(?:[A-Za-z]+\.)?youtube\.com/user/[A-Za-z0-9]+/?')
            patterns.remove(r'https?://(?:[A-Za-z]+\.)?youtube\.com/(?!(?:user|channel|embed|watch|playlist)/)[A-Za-z0-9-_]+/?')
            patterns.remove(r'https?://(?:[A-Za-z]+\.)?youtube\.com/@[A-Za-z0-9\-_]+/?')
            print("[e] Youtube account check is not relevant! Please contact developer for update.")
        if is_social_media_exist("https://www.facebook.com/iufqnoiqfenoiep"):
            patterns.remove(
                r'https?://(?:www\.)?(?:facebook|fb)\.com/(?![A-Za-z]+\.php|marketplace|gaming|watch|me|messages|help|search|groups|tr|people)[A-Za-z0-9_\-\.]+/?')
            patterns.remove(r'https?://(?:www\.)?facebook\.com/profile\.php\?id=\d+/?')
            print("[e] Facebook account check is not relevant! Please contact developer for update.")
        if is_social_media_exist("https://www.instagram.com/gwprhgwirpgmwr"):
            patterns.remove(r'https?://(?:www\.)?(?:instagram\.com|instagr\.am)/(?!p/)[A-Za-z0-9_.]{1,30}/?')
            print("[e] Instagram account check is not relevant! Please contact developer for update.")

    print("[*] Checking social networks takeover in parallel...")
    checking_relevance()

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
                        if is_social_media_exist(media_link):
                            existing_media.add(media_link)
                        else:
                            Global.NotExistingSocialLinks.append((url, media_link))
            except requests.RequestException:
                pass
                #print(f"[e] Error during social networks checking when sending request to {url}")
    print(f"[+] {len(Global.NotExistingSocialLinks)} not-registered links were found")


def launch_nuclei():
    def config_check():
        input_data = '\n'.join(HTTPAssets) + '\n'
        input_data += '\n'.join(AssetsWithWAF) + '\n'
        command = Nuclei_config_command.substitute(NucleiConfigCritical=Details[Global.DetailsLevel]['NucleiConfigCritical'],
                                                   NucleiRate=Threads[Global.LoadLevel]['NucleiRate'],
                                                   NucleiParallels=Threads[Global.LoadLevel]['NucleiParallels'])
        print("[*] Scanning with config Nuclei templates...")

        if '-v' in Flags:
            print("[v] Executing command: " + command)
        result = command_exec(command, "NucleiConfig.txt", input_data)

        if result != '-':
            print(f"[+] {len(result)} config issues were found")
            for item in result:
                parts = item.split()
                if len(parts) > 3:
                    severity = parts[2].strip("[]")
                    try:
                        NucleiConfigFindings[severity].append(item)
                    except KeyError:
                        NucleiConfigFindings["unknown"].append(item)
                else:
                    print(f"[e] String '{item}' has the wrong format and will be skipped.")
        else:
            print("[e] Error when running Nuclei utility on the config stage")

    def default_start():
        input_data = '\n'.join(HTTPAssets) + '\n'
        if not Details[Global.DetailsLevel]['WAFfiltering']:
            input_data += '\n'.join(AssetsWithWAF) + '\n'
        command = Nuclei_default_command.substitute(NucleiCritical=Details[Global.DetailsLevel]['NucleiCritical'],
                                                    NucleiRate=Threads[Global.LoadLevel]['NucleiRate'],
                                                    NucleiParallels=Threads[Global.LoadLevel]['NucleiParallels'])
        print("[*] Scanning with main Nuclei templates...")

        if '-v' in Flags:
            print("[v] Executing command: " + command)
        result = command_exec(command, "NucleiDefault.txt", input_data)

        if result != '-':
            print(f"[+] {len(result)} issues were found using main templates")
            for item in result:
                parts = item.split()
                if len(parts) > 3:
                    severity = parts[2].strip("[]")
                    try:
                        NucleiFindings[severity].append(item)
                    except KeyError:
                        NucleiFindings["unknown"].append(item)
                else:
                    print(f"[e] String '{item}' has the wrong format and will be skipped.")
        else:
            print("[e] Error when running Nuclei utility using default templates")

    def tokens_check():
        if JSlinks:
            input_data = '\n'.join(JSlinks) + '\n'
        else:
            input_data = '\n'.join(CrawledURLs) + '\n'
            input_data += '\n'.join(URLsWithWAF) + '\n'
        command = Nuclei_tokens_command.substitute(NucleiTokensCritical=Details[Global.DetailsLevel]['NucleiTokensCritical'])
        print("[*] Scanning with leaked tokens Nuclei templates...")

        if '-v' in Flags:
            print("[v] Executing command: " + command)
        result = command_exec(command, "NucleiTokens.txt", input_data)

        if result != '-':
            print(f"[+] {len(result)} tokens issues were found")
            for item in result:
                parts = item.split()
                if len(parts) > 3:
                    severity = parts[2].strip("[]")
                    try:
                        NucleiTokensFindings[severity].append(item)
                    except KeyError:
                        NucleiTokensFindings["unknown"].append(item)
                else:
                    print(f"[e] String '{item}' has the wrong format and will be skipped.")
        else:
            print("[e] Error when running Nuclei utility using tokens templates")

    def dast_start():
        input_data = '\n'.join(CrawledURLs) + '\n'
        if not Details[Global.DetailsLevel]['WAFfiltering']:
            input_data += '\n'.join(URLsWithWAF) + '\n'
        command = Nuclei_DAST_command.substitute(NucleiDASTCritical=Details[Global.DetailsLevel]['NucleiCritical'],
                                                 NucleiRate=Threads[Global.LoadLevel]['NucleiRate'],
                                                 NucleiParallels=Threads[Global.LoadLevel]['NucleiParallels'])
        print("[*] Scanning with Nuclei DAST templates...")

        if '-v' in Flags:
            print("[v] Executing command: " + command)
        result = command_exec(command, "NucleiDAST.txt", input_data)

        if result != '-':
            print(f"[+] {len(result)} dast issues were found")
            for item in result:
                parts = item.split()
                if len(parts) > 3:
                    severity = parts[2].strip("[]")
                    try:
                        NucleiDASTFindings[severity].append(item)
                    except KeyError:
                        NucleiDASTFindings["unknown"].append(item)
                else:
                    print(f"[e] String '{item}' has the wrong format and will be skipped.")
        else:
            print("[e] Error when running Nuclei utility using DAST checks")

    if CrawledURLs or URLsWithWAF:
        tokens_check()
    if HTTPAssets or AssetsWithWAF:
        config_check()
    if HTTPAssets or (AssetsWithWAF and not Details[Global.DetailsLevel]['WAFfiltering']):
        default_start()
    if '-dd' not in Flags and (CrawledURLs or (URLsWithWAF and not Details[Global.DetailsLevel]['WAFfiltering'])):
        dast_start()


def check_subdomains_takeover():
    input_data = '\n'.join(Global.RawSubdomains) + '\n'
    command = Nuclei_subdomains_takeover_command.substitute(NucleiRate=Threads[Global.LoadLevel]['NucleiRate'],
                                                            NucleiParallels=Threads[Global.LoadLevel]['NucleiParallels'])
    print("[*] Checking subdomains takeover possibilities...")

    if '-v' in Flags:
        print("[v] Executing command: " + command)
    result = command_exec(command, "NucleiSubdomainsTakeover.txt", input_data)

    if result != '-':
        print(f"[+] {len(result)} subdomains takeover possibilities were found")
        for item in result:
            parts = item.split()
            if len(parts) > 3:
                severity = parts[2].strip("[]")
                try:
                    NucleiTakeoverFindings[severity].append(item)
                except KeyError:
                    NucleiTakeoverFindings["unknown"].append(item)
            else:
                print(f"[e] String '{item}' has the wrong format and will be skipped.")
    else:
        print("[e] Error when running Nuclei utility on the subdomains takeover stage")


def launch_feroxbuster():
    wrong_directory_keyword = "NotExisting"  # Should not appear in the wordlist initially
    wrong_directory = wrong_directory_keyword + get_random_string(6)  # If the response code to this directory is 200, the remaining responses become invalid
    def clear_state_files():
        pattern = os.path.join('./', '*.state')
        state_files = glob.glob(pattern)
        state_files.append('resume.cfg')
        for file_path in state_files:
            try:
                os.remove(file_path)
            except Exception as e:
                if file_path != "resume.cfg":
                    print(f'[e] {file_path} Can\'t be deleted. The reason is: {e}')

    def check_wrong_directory_in_file():
        if not os.path.exists("Scan/fuzz.txt"):
            print("[!] Scan/fuzz.txt was not found! Skipping directory scanning with Feroxbuster.")
            return False

        with open("Scan/fuzz.txt", "r", encoding="utf-8") as file:
            lines = file.readlines()

        if lines:
            first_line = lines[0].strip()
        else:
            print("[!] File Scan/fuzz.txt is empty or unable to read! Skipping directory scanning with Feroxbuster.")
            return False

        if wrong_directory_keyword not in first_line:
            new_content = wrong_directory + "\n" + "".join(lines)
            with open("Scan/fuzz.txt", "w", encoding="utf-8") as file:
                file.write(new_content)
        return True

    def get_command_prefix():
        command = "feroxbuster -h"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            return ""
        else:
            return "Scan\\"

    def launch_fuzz(dictionary, urls, command_prefix, parallels, threads, timelimit):
        input_data = '\n'.join(urls) + '\n'
        command = command_prefix + Feroxbuster_command.substitute(FuzzingDictPath=dictionary, FeroxbusterParallels=parallels,
                                                                  FeroxbusterThreads=threads, FeroxbusterTimeLimit=timelimit,
                                                                  FeroxbusterAdditionalFlags=Details[Global.DetailsLevel]["FeroxbusterAdditionalFlags"])

        if '-v' in Flags:
            print("[v] Executing command: " + command)
        result = command_exec(command, "Feroxbuster.txt", input_data)

        if result != '-':
            incorrectly_fuzzed_hosts = []
            for raw_string in result:
                try:
                    parts = raw_string.split()  # 200  GET  7l  11w  153c  http://vulnweb.com/dump.sql
                    if len(parts) > 5 and parts[5].startswith("http") and not (parts[5].count('/') == 3 and parts[5][-1] == '/'):
                        correct_domain = False
                        host = get_host_from_url(parts[5])
                        for root_domain in Domains:
                            if root_domain in host:
                                correct_domain = True
                                break

                        if wrong_directory in parts[5] and (parts[0] == "200" or parts[0] == "403" or parts[0] == "401" or
                                                            parts[0] == "405" or parts[0][0] == "3"):
                            incorrectly_fuzzed_hosts.append(host)
                            if "-v" in Flags:
                                print(f"[v] {host} returns {parts[0]} status code to all requests and has been excluded from results")
                        if host not in incorrectly_fuzzed_hosts:
                            if correct_domain:
                                if parts[0] == "200":
                                    FuzzedDirectories["200"].append(parts[5])
                                elif parts[0] == "403":
                                    FuzzedDirectories["403"].append(parts[5])
                                elif parts[0] == "401":
                                    FuzzedDirectories["401"].append(parts[5])
                                elif parts[0] == "405":
                                    FuzzedDirectories["405"].append(parts[5])
                                elif parts[0][0] == "3":
                                    FuzzedDirectories["3xx"].append(' '.join(parts[5:]))  # "http://site.com/logout => http://site.com/"
                except KeyboardInterrupt:
                    print("[!] Feroxbuster scan already finished, processing the results. Please wait...")
            results_amount = len(FuzzedDirectories["200"]) + len(FuzzedDirectories["403"]) + len(FuzzedDirectories["401"])\
                             + len(FuzzedDirectories["405"]) + len(FuzzedDirectories["3xx"])
            print(f'[+] {results_amount} directories were found')
        else:
            print("[e] Error when running Feroxbuster utility")

    if not check_wrong_directory_in_file():
        return False
    prefix = get_command_prefix()
    if HTTPAssets:
        print("[*] Fuzzing suspicious directories (may take some time)...")
        launch_fuzz("Scan/fuzz.txt", HTTPAssets, prefix, Threads[Global.LoadLevel]['FeroxbusterParallels'],
                    Threads[Global.LoadLevel]['FeroxbusterThreads'], Threads[Global.LoadLevel]['FeroxbusterTimeLimit'])
    if not Details[Global.DetailsLevel]['WAFfiltering'] and AssetsWithWAF:
        print("[*] Fuzzing suspicious directories on sites with WAF (may take a long time)...")
        launch_fuzz("Scan/fuzz.txt", HTTPAssets, prefix, Threads[Global.LoadLevel]['FeroxbusterParallels']*2, 1, '45m')
    clear_state_files()


def launch_byp4xx():
    if FuzzedDirectories["403"] or FuzzedDirectories["401"]:
        with open("Scan/403pages.txt", "w", encoding="utf-8") as file:
            for url in FuzzedDirectories["403"]:
                file.write(url + "\n")
            for url in FuzzedDirectories["401"]:
                file.write(url + "\n")

        command = Byp4xx_command.substitute(byp4xx_threads=Threads[LoadLevel]['byp4xx_threads'],
                                            Byp4xx_flags=Details[DetailsLevel]['Byp4xx_flags'])
        print("[*] Trying to bypass 403 and 401 errors...")

        if '-v' in Flags:
            print("[*] Executing command: " + command)
        result = command_exec(command, "Byp4xx.txt", filter_ansi=True)

        if result != '-' and len(result) > 8:
            current_host_stings = []
            useful_strings = result[8:]
            useful_strings.append("==END OF OUTPUT==")

            for index, string in enumerate(useful_strings):
                if string.startswith("====="):
                    if len(current_host_stings) > 1:
                        Global.Byp4xxResult += f"<b>{current_host_stings[0]}</b><br>\n"
                        for host_string in current_host_stings[1:]:
                            Global.Byp4xxResult += host_string + "<br>\n"
                        Global.Byp4xxResult += "<br><br>\n"
                    current_host_stings = [string]
                elif string == "==END OF OUTPUT==":
                    if len(current_host_stings) > 1:
                        Global.Byp4xxResult += f"<b>{current_host_stings[0]}</b><br>\n"
                        for host_string in current_host_stings[1:]:
                            Global.Byp4xxResult += host_string + "<br>\n"
                        Global.Byp4xxResult += "<br><br>\n"
                elif string.startswith("=="):
                    if not useful_strings[index+1].startswith("=="):
                        current_host_stings.append(string)
                else:
                    current_host_stings.append(string)
        else:
            print("[e] Error when running byp4xx utility")
        if '-v' in Flags:
            print("[v] 403 bypass attempts finishes!")
        if os.path.exists("Scan/403pages.txt"):
            os.remove("Scan/403pages.txt")
        if '-v' in Flags:
            print("[v] unnecessary files were removed")


is_postleaks_waiting = False


def launch_postleaks():
    def get_keyword(url):
        parts = url.rsplit('.', 1)
        while len(parts) == 2 and len(parts[-1]) < 4:  # remove top level domains
            url = parts[0]
            parts = url.rsplit('.', 1)
        return url


    print("[*] Start searching suspicious Postman collections in parallel...")
    for domain in Domains:  # not using one command for all files because utility is unstable and sometimes gives errors
        keyword = get_keyword(domain)
        command = Postleaks_command.substitute(domain=keyword, PostleaksAditionalFlags=Details[Global.DetailsLevel]["PostleaksAditionalFlags"])

        if '-v' in Flags:
            print("[v] Executing command: " + command)

        executed = False

        while not executed:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            if result.returncode == 3221225786 or result.returncode == 130:
                if is_postleaks_waiting:
                    print("[*] Finishing postleaks execution...")
                    delete_postleaks_junk()
                    return
            else:
                executed = True

        if result.returncode == 0:
            count = 0
            for raw_string in remove_ansi_escape_codes(result.stdout).splitlines():
                if raw_string.startswith("[+") or raw_string.startswith(" -") or raw_string.startswith(" >"):
                    if count == 0:
                        Global.PostleaksResult += f'<h3>{keyword} results</h3>\n' \
                                                  f'<a href=\"https://www.postman.com/search?q={keyword}&scope=all&type=all\">Postman collection search link</a><br>\n'
                    count += 1
                    if raw_string.startswith(" >"):
                        Global.PostleaksResult += f"<b>{raw_string}</b> <br>\n"
                    else:
                        if raw_string.startswith("[+"):
                            Global.PostleaksResult += "<br>\n"
                        Global.PostleaksResult += raw_string + " <br>\n"
                elif raw_string.startswith("[-"):
                    print("[e]", raw_string)
            if count != 0:
                Global.PostleaksResult += "\n<br><br><br>\n"
        else:
            print("[e] Error when running postleaks utility")
    delete_postleaks_junk()


def check_leakix():
    def check_url_with_leakix(domain: str, api_key: str) -> List[dict]:
        url = f'https://leakix.net/search?scope=leak&page=0&q="{domain}"'
        headers = {
            "accept": "application/json",
            "api-key": api_key
        }
        try:
            response = requests.get(url, headers=headers, timeout=20)
            response.raise_for_status()  # Проверяет статус код и поднимает ошибку для 4xx/5xx
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
                    if "429" in str(e):  # 429 Client Error: Too Many Requests for url
                        unsuccessful_attempts += 1
                        if unsuccessful_attempts > 10:
                            print("[e] Leakix is not working!")
                            return
                        time.sleep(5)
                    else:
                        checked = True
                time.sleep(1)  # request no more than once per second is leakix requirement

    if HTTPAssets or AssetsWithWAF:
        print("[*] Checking domains on Leakix in parallel...")
        if HTTPAssets:
            get_domains_info(HTTPAssets)
        if AssetsWithWAF:
            get_domains_info(list(AssetsWithWAF.keys()))
        Global.LeakixFindings = list(dict.fromkeys(Global.LeakixFindings))  # Filter duplicates
        print(f"[+] {len(Global.LeakixFindings)} issues were found on Leakix")
