from Global import Flags, Domains, Details, Postleaks_command
import Global
import subprocess
from Scan.Helpers import remove_ansi_escape_codes, delete_postleaks_junk

is_postleaks_waiting = False


def set_postleaks_waiting(value: bool = True) -> None:
    global is_postleaks_waiting
    is_postleaks_waiting = value


def launch_postleaks():
    def get_keyword(url):
        parts = url.rsplit('.', 1)
        while len(parts) == 2 and len(parts[-1]) < 4:
            url = parts[0]
            parts = url.rsplit('.', 1)
        return url

    print("[*] Start searching suspicious Postman collections in parallel...")
    searched_keywords = set()
    for index, domain in enumerate(Domains):
        if '-' not in domain:
            keyword = get_keyword(domain)
            if keyword in searched_keywords:
                continue
            searched_keywords.add(keyword)
            command = Postleaks_command.substitute(
                domain=keyword,
                PostleaksAditionalFlags=Details[Global.DetailsLevel]["PostleaksAditionalFlags"],
                PostleaksOutput=f"{Global.RunDir}/postleaks_{index}")

            if '-v' in Flags:
                print("[v] Executing command: " + command)

            executed = False
            while not executed:
                result = subprocess.run(command, shell=True, capture_output=True, text=True)
                if result.returncode == 3221225786 or result.returncode == 130:
                    if is_postleaks_waiting:
                        print("[*] Finishing postleaks execution...")
                        delete_postleaks_junk(Global.RunDir)
                        return
                else:
                    executed = True

            if result.returncode == 0:
                keyword_findings = []
                for raw_string in remove_ansi_escape_codes(result.stdout).splitlines():
                    if raw_string.startswith("[+") or raw_string.startswith(" -") or raw_string.startswith(" >"):
                        keyword_findings.append(raw_string)
                    elif raw_string.startswith("[-"):
                        print("[e]", raw_string)
                if keyword_findings:
                    Global.PostleaksResult[keyword] = keyword_findings
            else:
                print("[e] Error when running postleaks utility")
    delete_postleaks_junk(Global.RunDir)
