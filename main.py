from Global import Flags, HelpText, Domains
import Global
from ReportCreation import CreateReport
import sys
import os
import Scan.Control
from Scan.Helpers import get_host_from_url


if __name__ == '__main__':
    report_file = "Report"
    argument_was_used = False
    for i in range(1, len(sys.argv)):
        if argument_was_used:
            argument_was_used = False
            continue
        elif sys.argv[i] == '-h' or sys.argv[i] == '--help':
            print(HelpText)
            sys.exit(0)
        elif sys.argv[i] == '-d':
            if i + 1 < len(sys.argv) and sys.argv[i + 1][0] != '-':
                Domains.append(get_host_from_url(sys.argv[i + 1]))
                argument_was_used = True
            else:
                print("Please specify domain to scan after -d argument. Example: -d example.com")
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
                        Domains[j] = get_host_from_url(Domains[j].strip())
                else:
                    print(f"{filename} file is not exist. Please recheck the file name")
                    sys.exit(1)
                argument_was_used = True
            else:
                print("Please specify domain to scan after -f argument. Example: -f example.com")
                sys.exit(1)
        elif sys.argv[i] == '-o':
            if i + 1 < len(sys.argv) and sys.argv[i + 1][0] != '-':
                report_file = sys.argv[i + 1]
                argument_was_used = True
            else:
                print("Please specify HTML report name right after -o argument. Example: -o Report3")
                sys.exit(1)
        elif sys.argv[i] == '-ll':
            if i + 1 < len(sys.argv) and sys.argv[i + 1][0] != '-':
                try:
                    Global.LoadLevel = int(sys.argv[i + 1])
                    if Global.LoadLevel not in Global.Threads:
                        raise Exception("Wrong number")
                except:
                    print("Internet load level (-ll flag) should be a number between 1 and 3 (1 - minimum load, 3 - maximum, default: 2). Exiting!")
                    sys.exit(1)
                argument_was_used = True
            else:
                print("Please specify number after -ll argument. Example: -ll 3")
                sys.exit(1)
        elif sys.argv[i] == '-ld':
            if i + 1 < len(sys.argv) and sys.argv[i + 1][0] != '-':
                try:
                    Global.DetailsLevel = int(sys.argv[i + 1])
                    if Global.DetailsLevel not in Global.Details:
                        raise Exception("Wrong number")
                except:
                    print("Level of detail (-ld flag) should be a number between 1 and 4 (1 - max speed, 4 - max findings, default: 2). Exiting!")
                    sys.exit(1)
                argument_was_used = True
            else:
                print("Please specify number after -ld argument. Example: -ld 3")
                sys.exit(1)
        elif sys.argv[i] == '-p':
            if i + 1 < len(sys.argv) and sys.argv[i + 1][0] != '-':
                Global.BurpProxy = sys.argv[i + 1].replace("http://", "").replace("https://", "")
                if Global.BurpProxy.count('.') != 3 or ":" not in Global.BurpProxy:
                    print("Burp proxy (-p flag) should be in format like 127.0.0.1:8080. Exiting!")
                    sys.exit(1)
                argument_was_used = True
            else:
                print("Please specify proxy after -p argument. Example: -p 127.0.0.1:8080")
                sys.exit(1)
        elif sys.argv[i] == '-sa':
            Flags.append('-sa')
            for level in range(0, len(Global.Details)):
                Global.Details[level+1]['NaabuPorts'] = "full"
        elif sys.argv[i] == "-do" or sys.argv[i] == "-v" or sys.argv[i] == "-ds" or sys.argv[i] == "-df"\
                or sys.argv[i] == "-dn" or sys.argv[i] == "-dp" or sys.argv[i] == "-dd" or sys.argv[i] == "-dl"\
                or sys.argv[i] == "-dc" or sys.argv[i] == "-db" or sys.argv[i] == "-dm" or sys.argv[i] == "-dt"\
                or sys.argv[i] == "-dw"\
                or sys.argv[i] == "--docker" or sys.argv[i] == "-i" or sys.argv[i] == "-ba" or sys.argv[i] == "-bw"\
                or sys.argv[i] == "-bf" or sys.argv[i] == "-bb":
            Flags.append(sys.argv[i])
        else:
            print(f"Unknown flag: {sys.argv[i]}. Use -h to get help menu")

    if not Domains:
        print("No domains to scan! Please specify the -f or -d flag. Use -h to get help menu")
        sys.exit(0)
    if Global.LeakixAPIKey == "CHANGEME" and '-dl' not in Flags:
        Flags.append('-dl')
        if "--docker" in Flags:
            print("[!] LeakIX key not specified in the docker parameters, this check will be skipped! Use -e LeakIX_API_key=\"CHANGEME\"")
        else:
            print("[!] LeakIX key not specified in the Global.py file! LeakIX check will be skipped.")

    Scan.Control.scanning()
    CreateReport(report_file)
