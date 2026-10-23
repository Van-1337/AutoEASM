from Global import Flags, HelpText, Domains
import Global
from ReportCreation import CreateReport
import sys
import os
import Scan.Control
from Scan.Helpers import get_host_from_url


if __name__ == '__main__':
    sys.stdout.reconfigure(line_buffering=True)  # Python switches stdout to block buffering when it is redirected to a file, so progress lines would appear only at the end
    report_file = "Report"
    report_name_specified = False
    argument_was_used = False
    for i in range(1, len(sys.argv)):
        if argument_was_used:
            argument_was_used = False
            continue
        token = sys.argv[i]
        if token.startswith("--") and token not in ("--docker", "--help"):
            token = "-" + token[2:]
        if token == "-i":
            print("Flag -i was removed. Use -ip.")
            sys.exit(1)
        sys.argv[i] = Global.FlagAliases.get(token, token)
        if sys.argv[i] == '-h' or sys.argv[i] == '--help':
            print(HelpText)
            sys.exit(0)
        elif sys.argv[i] == '-d':
            if i + 1 < len(sys.argv) and sys.argv[i + 1][0] != '-':
                Domains.append(get_host_from_url(sys.argv[i + 1], remove_port=True))
                argument_was_used = True
            else:
                print("Please specify domain to scan after -domain. Example: -domain example.com")
                sys.exit(1)
        elif sys.argv[i] == '-f':
            if i + 1 < len(sys.argv) and sys.argv[i + 1][0] != '-':
                filename = sys.argv[i + 1]
                if "--docker" in Flags:
                    filename = "/src/" + filename
                if os.path.exists(filename):
                    with open(filename, "r", encoding="utf-8") as file:
                        Domains.extend([line.strip() for line in file.readlines()])
                    if len(Domains) == 0:
                        print("Domains file is empty!")
                        sys.exit(1)
                    for j in range(0, len(Domains)):
                        Domains[j] = get_host_from_url(Domains[j].strip(), remove_port=True)
                else:
                    print(f"{filename} file is not exist. Please recheck the file name")
                    sys.exit(1)
                argument_was_used = True
            else:
                print("Please specify the domain list after -file. Example: -file domains.txt")
                sys.exit(1)
        elif sys.argv[i] == '-o':
            if i + 1 < len(sys.argv) and sys.argv[i + 1][0] != '-':
                report_file = sys.argv[i + 1]
                report_name_specified = True
                argument_was_used = True
            else:
                print("Please specify the report name after -report. Example: -report Report3")
                sys.exit(1)
        elif sys.argv[i] == '-ll':
            if i + 1 < len(sys.argv) and sys.argv[i + 1][0] != '-':
                try:
                    Global.LoadLevel = int(sys.argv[i + 1])
                    if Global.LoadLevel not in Global.Threads:
                        raise ValueError("Wrong number")
                except (ValueError, KeyError):
                    print("Load (-load) should be a number from 1 to 3 (1 - minimum, 3 - maximum, default: 2). Exiting!")
                    sys.exit(1)
                argument_was_used = True
            else:
                print("Please specify a number after -load. Example: -load 3")
                sys.exit(1)
        elif sys.argv[i] == '-ld':
            if i + 1 < len(sys.argv) and sys.argv[i + 1][0] != '-':
                try:
                    Global.DetailsLevel = int(sys.argv[i + 1])
                    if Global.DetailsLevel not in Global.Details:
                        raise ValueError("Wrong number")
                except (ValueError, KeyError):
                    print("Depth (-deep) should be a number from 1 to 4 (1 - fastest, 4 - most findings, default: 2). Exiting!")
                    sys.exit(1)
                argument_was_used = True
            else:
                print("Please specify a number after -deep. Example: -deep 3")
                sys.exit(1)
        elif sys.argv[i] == '-rl':
            if i + 1 < len(sys.argv) and sys.argv[i + 1][0] != '-':
                try:
                    rate_limit = int(sys.argv[i + 1])
                    if rate_limit < 1:
                        raise ValueError("Wrong number")
                    for level in range(0, len(Global.Threads)):
                        Global.Threads[level + 1]['NaabuRate'] = Global.Threads[level + 1]['NaabuThreads'] * rate_limit
                        Global.Threads[level + 1]['HTTPXrate'] = Global.Threads[level + 1]['HTTPXthreads'] * rate_limit
                        Global.Threads[level + 1]['NucleiRate'] = Global.Threads[level + 1]['NucleiParallels'] * rate_limit
                        Global.Threads[level + 1]['KatanaRate'] = f"-rl {Global.Threads[level + 1]['KatanaParallels'] * rate_limit}"
                        Global.Threads[level + 1]['FeroxbusterRate'] = f"--rate-limit {rate_limit}"
                        Global.Threads[level + 1]['byp4xx_threads'] = max(round(rate_limit/3), 1)
                        Global.Threads[level + 1]['WAFbypassThreads'] = min(Global.Threads[level + 1]['WAFbypassThreads'], rate_limit)
                except (ValueError, KeyError):
                    print("Rate (-rate) should be a positive number. Exiting!")
                    sys.exit(1)
                argument_was_used = True
            else:
                print("Please specify a number after -rate. Example: -rate 50")
                sys.exit(1)
        elif sys.argv[i] == '-p':
            if i + 1 < len(sys.argv) and sys.argv[i + 1][0] != '-':
                Global.BurpProxy = sys.argv[i + 1].replace("http://", "").replace("https://", "")
                if Global.BurpProxy.count('.') != 3 or ":" not in Global.BurpProxy:
                    print("Burp proxy (-proxy) should look like 127.0.0.1:8080. Exiting!")
                    sys.exit(1)
                argument_was_used = True
            else:
                print("Please specify the proxy after -proxy. Example: -proxy 127.0.0.1:8080")
                sys.exit(1)
        elif sys.argv[i] == '-tem':
            if i + 1 < len(sys.argv) and sys.argv[i + 1][0] != '-':
                Global.TemplatesPath = sys.argv[i + 1]
                argument_was_used = True
            else:
                print("Please specify the Nuclei templates directory after -templates. Example: -templates /src/Nuclei-templates")
                sys.exit(1)
        elif sys.argv[i] == '-sw':
            if i + 1 < len(sys.argv) and sys.argv[i + 1][0] != '-':
                Global.CustomSubdomainsDict = sys.argv[i + 1]
                if "--docker" in Flags:
                    Global.CustomSubdomainsDict = "/src/" + Global.CustomSubdomainsDict
                if not os.path.exists(Global.CustomSubdomainsDict):
                    print(f"{Global.CustomSubdomainsDict} file is not exist. Please recheck the file name")
                    sys.exit(1)
                argument_was_used = True
            else:
                print("Please specify the subdomain wordlist after -wordlist. Example: -wordlist Scan/resources/subdomains-top1million-5000.txt")
                sys.exit(1)
        elif sys.argv[i] == '-ua':
            if i + 1 < len(sys.argv) and sys.argv[i + 1][0] != '-':
                Global.UserAgent = sys.argv[i + 1]
                argument_was_used = True
            else:
                print("Please specify the User-Agent after -user-agent. Example: -user-agent \"Mozilla/5.0\"")
                sys.exit(1)
        elif sys.argv[i] == '-ex':
            if i + 1 < len(sys.argv) and sys.argv[i + 1][0] != '-':
                Global.ExcludedHosts.append(get_host_from_url(sys.argv[i + 1], remove_port=True))
                Global.ExcludedHosts.append('https://' + get_host_from_url(sys.argv[i + 1], remove_port=True))
                Global.ExcludedHosts.append('http://' + get_host_from_url(sys.argv[i + 1], remove_port=True))
                argument_was_used = True
            else:
                print("Please specify a host after -exclude. Example: -exclude test.example.com")
                sys.exit(1)
        elif sys.argv[i] == '-sa':
            Flags.append('-sa')
            for level in range(0, len(Global.Details)):
                Global.Details[level+1]['NaabuPorts'] = "full"
        elif sys.argv[i] == '-waf':
            Flags.append('-waf')
            for level in range(0, len(Global.Details)):
                Global.Details[level+1]['WAFfiltering'] = False
        elif sys.argv[i] == "-do" or sys.argv[i] == "-v" or sys.argv[i] == "-md" or sys.argv[i] == "-ds" or sys.argv[i] == "-df"\
                or sys.argv[i] == "-dn" or sys.argv[i] == "-dp" or sys.argv[i] == "-dd" or sys.argv[i] == "-dl"\
                or sys.argv[i] == "-dc" or sys.argv[i] == "-db" or sys.argv[i] == "-dm" or sys.argv[i] == "-dt"\
                or sys.argv[i] == "-dw" or sys.argv[i] == "-di" or sys.argv[i] == "-daff" or sys.argv[i] == "-dh"\
                or sys.argv[i] == "--docker" or sys.argv[i] == "-i" or sys.argv[i] == "-q" or sys.argv[i] == "-asa" or sys.argv[i] == "-ba" or sys.argv[i] == "-bw"\
                or sys.argv[i] == "-bf" or sys.argv[i] == "-bb" or sys.argv[i] == "-dst" or sys.argv[i] == "-dcf":
            Flags.append(sys.argv[i])
        else:
            print(f"Unknown flag: {sys.argv[i]}. Use -h to get help menu")

    if not Domains:
        print("No domains to scan. Specify -domain or -file. Use -help to see all flags")
        sys.exit(0)
    if Global.LeakixAPIKey == "CHANGEME" and '-dl' not in Flags:
        Flags.append('-dl')
        if "--docker" in Flags:
            print("[!] LeakIX key not specified in the docker parameters, this check will be skipped! Use -e LeakIX_API_key=\"CHANGEME\"")
        else:
            print("[!] LeakIX key not specified in the Global.py file! LeakIX check will be skipped.")
    if '-dst' not in Flags:
        if not Global.SecurityTrailsAPIKey:
            Flags.append('-dst')  # No SecurityTrails_API_key in the environment => silently skip, no error (as requested)
        else:
            from Scan.SecurityTrails import securitytrails_key_works
            if securitytrails_key_works():
                print("[+] Found SecurityTrails API key, historical IP checks (origin behind WAF + inactive hosts access) are enabled")
            else:
                Flags.append('-dst')
                print("[!] SecurityTrails API key found but it is invalid or the account is blocked - this check will be skipped.")
    if '-q' in Flags:
        from Scan.Qualys import resolve_qualys_credentials, credentials_configured, QualysError
        creds_ok = False
        try:
            resolve_qualys_credentials()  # pulls SSM values in now so the whole run uses them
            creds_ok = credentials_configured()
        except QualysError as e:
            print(f"[!] Qualys: {e}")
        if not creds_ok:
            Flags.remove('-q')
            print("[!] Qualys credentials not configured - Qualys WAS sync (-q) will be skipped. Set "
                  "QUALYS_USERNAME/QUALYS_PASSWORD, the SSM params, or hardcode them in Global.py (see README).")
    if '-asa' in Flags:
        try:
            import boto3
            boto3.client("securityagent", region_name=Global.SecurityAgentRegion)
        except Exception as e:
            Flags.remove('-asa')
            print(f"[!] AWS Security Agent sync (-asa) will be skipped: boto3 with the securityagent client is required "
                  f"(pip install -U boto3). Details: {e}")

    Scan.Control.scanning()
    CreateReport(report_file, auto_increment=not report_name_specified)
