from Global import Flags, Domains
import Global
import sys
import threading
import time

from Scan.CommandRun import check_installed_tools
from Scan.Helpers import create_run_directory
from Scan.Discovery import launch_subfinder_dnsx_naabu, launch_httpx
from Scan.Crawl import launch_katana, launch_uro, delete_assets_with_waf, delete_urls_with_waf, check_social_networks
from Scan.HostChecks import launch_waf_bypass, launch_hidden_hosts_scan, send_urls_to_burp
from Scan.Postleaks import launch_postleaks, set_postleaks_waiting
from Scan.Leakix import check_leakix
from Scan.NucleiScan import launch_nuclei, check_subdomains_takeover
from Scan.Fuzzing import launch_feroxbuster, launch_byp4xx


def scanning():
    try:
        if check_installed_tools() != 0:
            print("[e] Not all required utilities are installed. Terminating.")
            sys.exit(1)
        print("[N] Note: you can stop a current check with Ctrl+C")
        Global.RunDir = create_run_directory(Domains[0])
        print(f"[*] Logs and temporary files for this run will be stored in: {Global.RunDir}")
        if '-ds' in Flags or '-i' in Flags:
            launch_subfinder_dnsx_naabu(scan_subdomains=False)
        else:
            launch_subfinder_dnsx_naabu(scan_subdomains=True)
            launch_subfinder_dnsx_naabu(scan_subdomains=False, console_output=False)
        if '-dp' not in Flags and '-i' not in Flags:
            postleaks_thread = threading.Thread(target=launch_postleaks, name="PostleaksThread", daemon=True)
            postleaks_thread.start()
            time.sleep(1)
        launch_httpx()
        delete_assets_with_waf()
        if '-dc' not in Flags:
            amount_of_processed_domains = len(Global.HTTPAssets)
            launch_katana()
            launch_uro()
            delete_assets_with_waf(amount_of_processed_domains)
        else:
            Global.CrawledURLs = Global.HTTPAssets
        delete_urls_with_waf()
        if '-dw' not in Flags:
            launch_waf_bypass()
        if '-di' not in Flags:
            launch_hidden_hosts_scan()
        if '-dl' not in Flags:
            leakix_thread = threading.Thread(target=check_leakix, name="LeakixThread", daemon=True)
            leakix_thread.start()
            time.sleep(1)
        if '-ba' in Flags or '-bw' in Flags or '-bf' in Flags:
            burp_sending_thread = threading.Thread(target=send_urls_to_burp, name="BurpSendingThread", daemon=True)
            burp_sending_thread.start()
            time.sleep(1)
        if '-dm' not in Flags:
            social_networks_thread = threading.Thread(target=check_social_networks, name="CheckSocialNetworksThread", daemon=True)
            social_networks_thread.start()
            time.sleep(1)
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
            set_postleaks_waiting(True)
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
