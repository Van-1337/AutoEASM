from Global import (
    Flags, Domains, Threads, Details, LoadLevel, DetailsLevel,
    FuzzedDirectories, Feroxbuster_command, Byp4xx_command,
)
import Global
import os
import glob
import subprocess
from Scan.CommandRun import command_exec
from Scan.Helpers import get_host_from_url, get_random_string


def launch_feroxbuster():
    wrong_directory_keyword = "NotExisting"
    wrong_directory = wrong_directory_keyword + get_random_string(6)

    def clear_state_files():
        pattern = os.path.join('./', '*.state')
        state_files = glob.glob(pattern)
        state_files.append('resume.cfg')
        for file_path in state_files:
            try:
                os.remove(file_path)
            except OSError as e:
                if file_path != "resume.cfg":
                    print(f'[e] {file_path} Can\'t be deleted. The reason is: {e}')

    def check_wrong_directory_in_file():
        nonlocal wrong_directory
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
        else:
            wrong_directory = first_line
        return True

    def get_command_prefix():
        command = "feroxbuster -h"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            return ""
        return "Scan\\"

    def launch_fuzz(dictionary, urls, command_prefix, parallels, threads, timelimit, rate):
        input_data = '\n'.join(urls) + '\n'
        command = command_prefix + Feroxbuster_command.substitute(
            FuzzingDictPath=dictionary,
            FeroxbusterParallels=parallels,
            FeroxbusterThreads=threads,
            FeroxbusterTimeLimit=timelimit,
            FeroxbusterRate=rate,
            FeroxbusterAdditionalFlags=Details[Global.DetailsLevel]["FeroxbusterAdditionalFlags"])

        if '-v' in Flags:
            print("[v] Executing command: " + command)
        result = command_exec(command, "Feroxbuster.txt", input_data)

        if result != '-':
            incorrectly_fuzzed_hosts = []
            for raw_string in result:
                try:
                    parts = raw_string.split()
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
                        elif host not in incorrectly_fuzzed_hosts:
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
                                    FuzzedDirectories["3xx"].append(' '.join(parts[5:]))
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
    if Global.HTTPAssets:
        print("[*] Fuzzing suspicious directories (may take some time)...")
        launch_fuzz("Scan/fuzz.txt", Global.HTTPAssets, prefix, Threads[Global.LoadLevel]['FeroxbusterParallels'],
                    Threads[Global.LoadLevel]['FeroxbusterThreads'], Threads[Global.LoadLevel]['FeroxbusterTimeLimit'],
                    Threads[Global.LoadLevel]['FeroxbusterRate'])
    if not Details[Global.DetailsLevel]['WAFfiltering'] and Global.AssetsWithWAF:
        print("[*] Fuzzing suspicious directories on sites with WAF (may take a long time)...")
        launch_fuzz("Scan/fuzz.txt", Global.HTTPAssets, prefix, Threads[Global.LoadLevel]['FeroxbusterParallels']*2, 1, '45m',
                    Threads[Global.LoadLevel]['FeroxbusterRate'])
    clear_state_files()


def launch_byp4xx():
    if FuzzedDirectories["403"] or FuzzedDirectories["401"]:
        pages_403_file = Global.RunDir + "/403pages.txt"
        if Details[Global.DetailsLevel]['CheckAll403links']:
            with open(pages_403_file, "w", encoding="utf-8") as file:
                for url in FuzzedDirectories["403"]:
                    file.write(url + "\n")
                for url in FuzzedDirectories["401"]:
                    file.write(url + "\n")
        else:
            with open(pages_403_file, "w", encoding="utf-8") as file:
                written_hosts = []
                for url in FuzzedDirectories["403"]:
                    if get_host_from_url(url) not in written_hosts:
                        written_hosts.append(get_host_from_url(url))
                        file.write(url + "\n")
                written_hosts = []
                for url in FuzzedDirectories["401"]:
                    if get_host_from_url(url) not in written_hosts:
                        written_hosts.append(get_host_from_url(url))
                        file.write(url + "\n")

        command = Byp4xx_command.substitute(
            byp4xx_threads=Threads[LoadLevel]['byp4xx_threads'],
            Byp4xx_flags=Details[DetailsLevel]['Byp4xx_flags'],
            Pages403File=pages_403_file)
        print("[*] Trying to bypass 403 and 401 errors...")

        if '-v' in Flags:
            print("[*] Executing command: " + command)
        result = command_exec(command, "Byp4xx.txt", filter_ansi=True)

        if result != '-' and len(result) > 8:
            current_host_strings = []
            useful_strings = result[8:]
            useful_strings.append("==END OF OUTPUT==")

            for index, string in enumerate(useful_strings):
                if string.startswith("====="):
                    if len(current_host_strings) > 1:
                        Global.Byp4xxResult += f"<b>{current_host_strings[0]}</b><br>\n"
                        for host_string in current_host_strings[1:]:
                            Global.Byp4xxResult += host_string + "<br>\n"
                        Global.Byp4xxResult += "<br><br>\n"
                    current_host_strings = [string]
                elif string == "==END OF OUTPUT==":
                    if len(current_host_strings) > 1:
                        Global.Byp4xxResult += f"<b>{current_host_strings[0]}</b><br>\n"
                        for host_string in current_host_strings[1:]:
                            Global.Byp4xxResult += host_string + "<br>\n"
                        Global.Byp4xxResult += "<br><br>\n"
                elif string.startswith("=="):
                    if not useful_strings[index+1].startswith("=="):
                        current_host_strings.append(string)
                else:
                    current_host_strings.append(string)
        else:
            print("[e] Error when running byp4xx utility")
        if '-v' in Flags:
            print("[v] 403 bypass attempts finishes!")
