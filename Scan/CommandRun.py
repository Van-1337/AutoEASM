from Global import Flags
import Global
from Scan.Helpers import remove_ansi_escape_codes
import subprocess
import time


def command_exec(command, filename, input_data=None, filter_ansi=False):
    command = f'({command}) > {Global.RunDir}/{filename}'
    interrupted = False
    result = None
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, input=input_data)
    except KeyboardInterrupt:
        print("[!] Command aborted! Press Ctrl+C within the next 5 seconds if you want to exit completely.")
        time.sleep(5)
        interrupted = True
    if interrupted or (result and result.returncode == 0):
        if not interrupted and result.stdout and '-v' in Flags:
            print(f"[v] Got additional info in console when executing {command}\n{result.stdout}")

        log_path = Global.RunDir + '/' + filename
        if filter_ansi:
            with open(log_path, "r+", encoding='utf-8', errors='replace') as output_file:
                clean_command_output = remove_ansi_escape_codes(output_file.read())
                output_file.seek(0)
                output_file.write(clean_command_output)
                output_file.truncate()
            return clean_command_output.splitlines()
        with open(log_path, "r", encoding='utf-8', errors='replace') as output_file:
            return output_file.read().splitlines()
    if result:
        print(f"[e] Error when running this command: {command}")
        print("[e] Error: " + result.stderr)
    return "-"


def check_installed_tools():
    from Global import utilities_flags, Flags

    print("[*] Checking if all required tools are installed...")
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
    if "-dc" not in Flags and "-dh" not in Flags:
        result = subprocess.run(f"katana -headless --no-sandbox -u example.com -ct 3s", shell=True, capture_output=True)
        if result.returncode != 0:
            errors_count += 1
            print("[!] To crawl hosts protected by a WAF in headless mode, Katana needs to download the “leakless” script.\n"
                  "If this script is blocked by Windows Defender, you can either disable headless mode using the -dh flag "
                  "or add an exclusion in Windows Defender (Windows Security → Protection History → Threat quarantined → Actions → Restore).")
    if not ("-dn" in Flags and "-dt" in Flags):
        nuclei_result = subprocess.run(f"nuclei -h", shell=True, capture_output=True)
        if nuclei_result.returncode != 0:
            print(f"[!] Nuclei was not found, please install it and add to the path or use both -dn and -dt flags!")
            errors_count += 1
    return errors_count
