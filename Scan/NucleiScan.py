from Global import (
    Flags, Threads, Details, CrawledURLs, URLsWithWAF, JSlinks,
    NucleiFindings, NucleiConfigFindings, NucleiTokensFindings, NucleiDASTFindings,
    NucleiTakeoverFindings,
    Nuclei_default_command, Nuclei_config_command, Nuclei_tokens_command,
    Nuclei_DAST_command, Nuclei_subdomains_takeover_command,
)
import Global
import os
import json
from Scan.CommandRun import command_exec
from Scan.Helpers import get_host_from_url, get_host_from_url_list


def process_nuclei_results(result, findings_dict: dict, success_label: str, error_message: str) -> None:
    if result == '-':
        print(error_message)
        return
    print(f"[+] {len(result)} {success_label}")
    for item in result:
        parts = item.split()
        if len(parts) > 3:
            severity = parts[2].strip("[]")
            try:
                findings_dict[severity].append(item)
            except KeyError:
                pass
        else:
            print(f"[e] String '{item}' has the wrong format and will be skipped.")


def launch_nuclei():
    if Global.TemplatesPath:
        templates_flag = " -t " + Global.TemplatesPath
    else:
        templates_flag = ""

    def config_check():
        input_data = '\n'.join(Global.HTTPAssets) + '\n'
        input_data += '\n'.join(Global.AssetsWithWAF) + '\n'
        command = Nuclei_config_command.substitute(
            NucleiConfigCritical=Details[Global.DetailsLevel]['NucleiConfigCritical'],
            NucleiRate=Threads[Global.LoadLevel]['NucleiRate'],
            NucleiParallels=Threads[Global.LoadLevel]['NucleiParallels']) + templates_flag
        print("[*] Scanning with config Nuclei templates...")
        if '-v' in Flags:
            print("[v] Executing command: " + command)
        result = command_exec(command, "NucleiConfig.txt", input_data)
        process_nuclei_results(result, NucleiConfigFindings, "config issues were found",
                               "[e] Error when running Nuclei utility on the config stage")

    def default_start():
        input_data = '\n'.join(Global.HTTPAssets) + '\n'
        if not Details[Global.DetailsLevel]['WAFfiltering']:
            input_data += '\n'.join(Global.AssetsWithWAF) + '\n'
        command = Nuclei_default_command.substitute(
            NucleiCritical=Details[Global.DetailsLevel]['NucleiCritical'],
            NucleiRate=Threads[Global.LoadLevel]['NucleiRate'],
            NucleiParallels=Threads[Global.LoadLevel]['NucleiParallels']) + templates_flag
        print("[*] Scanning with main Nuclei templates...")
        if '-v' in Flags:
            print("[v] Executing command: " + command)
        result = command_exec(command, "NucleiDefault.txt", input_data)
        process_nuclei_results(result, NucleiFindings, "issues were found using main templates",
                               "[e] Error when running Nuclei utility using default templates")

    def tokens_check():
        if JSlinks:
            input_data = '\n'.join(JSlinks) + '\n'
        else:
            input_data = '\n'.join(CrawledURLs) + '\n'
            input_data += '\n'.join(URLsWithWAF) + '\n'
        command = Nuclei_tokens_command.substitute(
            NucleiTokensCritical=Details[Global.DetailsLevel]['NucleiTokensCritical']) + templates_flag
        print("[*] Scanning with leaked tokens Nuclei templates...")
        if '-v' in Flags:
            print("[v] Executing command: " + command)
        result = command_exec(command, "NucleiTokens.txt", input_data)
        process_nuclei_results(result, NucleiTokensFindings, "tokens issues were found",
                               "[e] Error when running Nuclei utility using tokens templates")

    def dast_start():
        input_data = ""
        for url in CrawledURLs:
            if '.js' not in url:
                input_data += url + '\n'
        if not Details[Global.DetailsLevel]['WAFfiltering']:
            input_data += '\n'.join(URLsWithWAF) + '\n'
        command = Nuclei_DAST_command.substitute(
            NucleiDASTCritical=Details[Global.DetailsLevel]['NucleiCritical'],
            NucleiRate=Threads[Global.LoadLevel]['NucleiRate'],
            NucleiParallels=Threads[Global.LoadLevel]['NucleiParallels']) + templates_flag

        jsonl_files = []
        if "-daff" not in Flags:
            if os.path.exists(Global.RunDir + "/Katana.jsonl"):
                jsonl_files.append(Global.RunDir + "/Katana.jsonl")
            if os.path.exists(Global.RunDir + "/Katana_WAF.jsonl"):
                jsonl_files.append(Global.RunDir + "/Katana_WAF.jsonl")

        if jsonl_files:
            hosts_with_waf = set(get_host_from_url_list(list(Global.AssetsWithWAF.keys()), remove_ports=True))
            filtered_jsonl_file = Global.RunDir + "/Katana_DAST.jsonl"
            filtered_entries = []
            for jsonl_file in jsonl_files:
                try:
                    with open(jsonl_file, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                entry = json.loads(line)
                                if 'request' in entry and 'endpoint' in entry['request']:
                                    endpoint = entry['request']['endpoint']
                                    if endpoint.startswith(('http://', 'https://')):
                                        endpoint_host = get_host_from_url(endpoint, remove_port=True)
                                        if Details[Global.DetailsLevel]['WAFfiltering']:
                                            if endpoint_host not in hosts_with_waf:
                                                filtered_entries.append(line)
                                        else:
                                            filtered_entries.append(line)
                            except json.JSONDecodeError:
                                continue
                except OSError as e:
                    if '-v' in Flags:
                        print(f"[v] Error reading JSONL file {jsonl_file}: {e}")

            if filtered_entries:
                try:
                    with open(filtered_jsonl_file, 'w', encoding='utf-8') as f:
                        for entry in filtered_entries:
                            f.write(entry + '\n')
                    command += f" -l {filtered_jsonl_file} -im jsonl -etags fuzzing-req-header,fuzzing-req-cookie"
                except OSError as e:
                    if '-v' in Flags:
                        print(f"[v] Error writing filtered JSONL file: {e}")

        print("[*] Scanning with Nuclei DAST templates...")
        if '-v' in Flags:
            print("[v] Executing command: " + command)
        result = command_exec(command, "NucleiDAST.txt", input_data)
        process_nuclei_results(result, NucleiDASTFindings, "dast issues were found",
                               "[e] Error when running Nuclei utility using DAST checks")

    if CrawledURLs or URLsWithWAF:
        tokens_check()
    if Global.HTTPAssets or Global.AssetsWithWAF:
        config_check()
    if Global.HTTPAssets or (Global.AssetsWithWAF and not Details[Global.DetailsLevel]['WAFfiltering']):
        default_start()
    if '-dd' not in Flags and (CrawledURLs or (URLsWithWAF and not Details[Global.DetailsLevel]['WAFfiltering'])):
        dast_start()


def check_subdomains_takeover():
    input_data = '\n'.join(Global.RawSubdomains) + '\n'
    command = Nuclei_subdomains_takeover_command.substitute(
        NucleiRate=Threads[Global.LoadLevel]['NucleiRate'],
        NucleiParallels=Threads[Global.LoadLevel]['NucleiParallels'])
    print("[*] Checking subdomains takeover possibilities...")
    if '-v' in Flags:
        print("[v] Executing command: " + command)
    result = command_exec(command, "NucleiSubdomainsTakeover.txt", input_data)
    process_nuclei_results(result, NucleiTakeoverFindings, "subdomains takeover possibilities were found",
                           "[e] Error when running Nuclei utility on the subdomains takeover stage")
