from Global import (
    Flags, Domains, Threads, Details,
    Subfinder_command, Naabu_command, DNSX_Naabu_command, DNSX_bruteforce_command, HTTPX_command,
)
import Global
import subprocess
import sys
import re
import os
import socket
import threading
import time
from Scan.CommandRun import command_exec
from Scan.Helpers import delete_http_duplicates, get_random_string

WILDCARD_PROBE_TIMEOUT = 7  # Seconds to wait for the DNS answer for the non-existent subdomain


def check_dns_wildcards():
    # A domain with a DNS wildcard resolves ANY subdomain, so subdomain enumeration would mark
    # thousands of non-existent hosts as alive. Such domains are dropped from the scan.
    wildcard_domains = []

    def probe_domain(domain):
        probe = get_random_string(10).lower() + '.' + domain
        if '-v' in Flags:
            print(f"[v] Resolving {probe} to check {domain} for a DNS wildcard")
        try:
            socket.getaddrinfo(probe, None)
        except OSError:
            return  # Does not resolve - the expected result for a domain without a wildcard
        wildcard_domains.append(domain)

    print("[*] Checking if subdomain enumeration is possible...")
    threads = [threading.Thread(target=probe_domain, args=(domain,), daemon=True) for domain in Global.Domains]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + WILDCARD_PROBE_TIMEOUT
    for thread in threads:
        thread.join(max(deadline - time.monotonic(), 0))  # Threads still resolving after the timeout are abandoned, their domain counts as fine

    if not wildcard_domains:
        return
    for domain in wildcard_domains:
        print(f"[e] {domain} resolves any non-existent subdomain, so subdomain enumeration would return only false results!")
    if len(wildcard_domains) == len(Global.Domains):
        print("[e] None of the specified root domains can be scanned for subdomains. Terminating.")
        sys.exit(1)
    for domain in wildcard_domains:
        Global.Domains.remove(domain)  # In place - other modules keep a reference to this list
    print(f"[!] Excluded from the scan: {', '.join(wildcard_domains)}. Continuing with: {', '.join(Global.Domains)}")
    Global.GeneralInfoNotes.append("Excluded from the scan because any non-existent subdomain resolves, "
                                   f"so subdomain enumeration is impossible: {', '.join(wildcard_domains)}")


def launch_httpx():
    def delete_443_80_ports_from_assets():
        for i in range(len(Global.HTTPAssets)):
            Global.HTTPAssets[i] = re.sub(r':(?:80|443)$', '', Global.HTTPAssets[i])
        Global.HTTPAssets = list(dict.fromkeys(Global.HTTPAssets))

    input_data = '\n'.join(Global.Services) + '\n'
    command = HTTPX_command.substitute(HTTPXthreads=Threads[Global.LoadLevel]['HTTPXthreads'],
                                       HTTPXrate=Threads[Global.LoadLevel]['HTTPXrate'])
    print("[*] Searching for HTTP services...")
    if '-v' in Flags:
        print("[v] Executing command: " + command)
    result = command_exec(command, "HTTPX.txt", input_data)

    if result != "-":
        Global.HTTPAssets.extend(delete_http_duplicates(result))
        delete_443_80_ports_from_assets()
        print(f"[+] {len(Global.HTTPAssets)} active web services will be scanned")
    else:
        print("[e] Error when running HTTPX utility.")
        sys.exit(1)


def bruteforce_subdomains(console_output=True):
    dict_path = Global.CustomSubdomainsDict if Global.CustomSubdomainsDict else Details[Global.DetailsLevel]['SubdomainsDict']
    if not os.path.exists(dict_path):
        print(f"[!] Subdomains wordlist {dict_path} was not found! Skipping subdomains bruteforce.")
        return

    domains_file = Global.RunDir + "/bruteforce_domains.txt"
    with open(domains_file, "w", encoding="utf-8") as file:
        file.write('\n'.join(Global.Domains) + '\n')

    command = DNSX_bruteforce_command.substitute(dnsxThreads=Threads[Global.LoadLevel]['DNSX'], SubdomainsDict=dict_path, DomainsFile=domains_file)
    if console_output:
        print("[*] Bruteforcing subdomains...")
    if '-v' in Flags:
        print("[v] Executing command: " + command)
    result = command_exec(command, "DNSX_bruteforce.txt")  # Via command_exec so this step (unlike subfinder/DNSX) can be skipped with Ctrl+C

    if result != "-":
        Global.RawSubdomains.extend([x for x in result if x])
        Global.RawSubdomains = list(dict.fromkeys(Global.RawSubdomains))
        Global.RawSubdomains = [x for x in Global.RawSubdomains if x not in Global.ExcludedHosts]
    else:
        print("[e] Error when running DNSX utility for subdomains bruteforce.")
        sys.exit(1)


def launch_subfinder_dnsx_naabu(scan_subdomains, console_output=True):
    input_data = '\n'.join(Global.Domains) + '\n'

    if '-i' in Flags:
        command = Naabu_command.substitute(
            NaabuThreads=Threads[Global.LoadLevel]['NaabuThreads'],
            NaabuRate=Threads[Global.LoadLevel]['NaabuRate'],
            NaabuPorts=Details[Global.DetailsLevel]['NaabuPorts'],
            NaabuFlags=Details[Global.DetailsLevel]['NaabuFlags'])
        if console_output:
            print("[*] Getting open network services on specified IP addresses...")
    else:
        if scan_subdomains:
            if console_output:
                print("[*] Searching subdomains...")
            if '-v' in Flags:
                print("[v] Executing command: " + Subfinder_command)
            result = subprocess.run(Subfinder_command, shell=True, capture_output=True, text=True, input=input_data)

            if result.returncode == 0:
                Global.RawSubdomains.extend(result.stdout.splitlines())
                Global.RawSubdomains = [x for x in Global.RawSubdomains if x not in Global.ExcludedHosts]
                bruteforce_subdomains(console_output)
                input_data = '\n'.join(Global.RawSubdomains) + '\n' + '\n'.join(Global.Domains) + '\n'
            else:
                print("[e] Error when running Subfinder utility:")
                print("[e] Command: " + Subfinder_command)
                print("[e] Error: " + result.stderr)
                sys.exit(1)
        else:
            Global.RawSubdomains.extend(Global.Domains)
            Global.RawSubdomains = [x for x in Global.RawSubdomains if x not in Global.ExcludedHosts]

        command = DNSX_Naabu_command.substitute(
            dnsxThreads=Threads[Global.LoadLevel]['DNSX'],
            NaabuThreads=Threads[Global.LoadLevel]['NaabuThreads'],
            NaabuRate=Threads[Global.LoadLevel]['NaabuRate'],
            NaabuPorts=Details[Global.DetailsLevel]['NaabuPorts'],
            NaabuFlags=Details[Global.DetailsLevel]['NaabuFlags'])
        if console_output:
            print("[*] Getting open network services...")

    if '-v' in Flags:
        print("[v] Executing command: " + command)
    result = subprocess.run(command, shell=True, capture_output=True, text=True, input=input_data)

    if result.returncode == 0:
        Global.Services.extend(result.stdout.splitlines())
        Global.Services = list(dict.fromkeys(Global.Services))
        if '-ba' in Flags or '-bw' in Flags or '-bf' in Flags:
            Global.Services = [s for s in Global.Services if not s.startswith('localhost.')]
    else:
        print("[e] Error when running Subfinder, DNSX or Naabu utilities:")
        print("[e] Command: " + command)
        print("[e] Error: " + result.stderr)
        sys.exit(1)
