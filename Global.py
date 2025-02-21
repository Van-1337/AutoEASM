from sys import argv
from string import Template
import os

HelpText = f"""Usage: {argv[0]} -f <file> -d example.com -o <file> -ll <number> -ld <number> -p <proxy> [-h] [-v] [-sa] [-i] [-do] [-ds] [-df] [-dn] [-dd] [-dc] [-db] [-dm] [-dp] [-dl] [-ba] [-bw] [-bf]

REQUIRED FLAGS:
-f - file with domains to scan
---OR---
-d - domain to scan

OPTIONAL FLAGS:
-h - show this help menu
-o <file> - name of the final output HTML file with the report. Caution, the file will always be overwritten if it already exists! Default name: Report
-v - verbose output
-ll <number> - internet load level, affects the number of threads in utilities. Number: 1-3, 1 - minimum load, 3 - maximum, Default: 2
-ld <number> - level of detail, slightly increases the number of findings and greatly increases execution time and junk info. Number: 1-4, 1 - max speed, 4 - max findings, Default: 2
-sa - scan ALL ports instead of 100 or 1000
-i - IP scan (skipping DNSX check, subdomain enumeration and Postman checking)

DISABLING FEATURES:
-do - don't open a report file after its creation
-ds - disable subdomains enumeration
-df - disable directory fuzzing
-dn - disable Nuclei scan
-dd - disable DAST scan
-dc - disable links crawling (and tokens check in JS)
-db - disable 403 bypass attempts
-dm - disable social media takeover checking
-dp - disable public Postman collections checking
-dl - disable Leakix checking

SENDING TO PROXY:
-ba - send all collected endpoints to Burp proxy including with WAF
-bw - send only collected endpoints without WAF to Burp proxy
-bf - send fuzzed directories to Burp proxy
-p <proxy> - burp proxy (default: 127.0.0.1:8080)"""

LoadLevel = 2
Threads = {1: {'DNSX': 20, 'NaabuThreads': 10, 'NaabuRate': 70, 'HTTPXthreads': 15, 'HTTPXrate': 70,
               'NucleiRate': 40, 'NucleiParallels': 10, 'FeroxbusterParallels': 10, 'FeroxbusterThreads': 5,
               'FeroxbusterTimeLimit': '30m', 'KatanaAdditionalFlagsT': '-p 7 -rl 70', 'byp4xx_threads': 10,
               'TimeoutModifier': 4},
           2: {'DNSX': 170, 'NaabuThreads': 100, 'NaabuRate': 220, 'HTTPXthreads': 80, 'HTTPXrate': 200,
               'NucleiRate': 135, 'NucleiParallels': 25, 'FeroxbusterParallels': 20, 'FeroxbusterThreads': 10,
               'FeroxbusterTimeLimit': '25m', 'KatanaAdditionalFlagsT': '-p 20', 'byp4xx_threads': 25,
               'TimeoutModifier': 1},
           3: {'DNSX': 500, 'NaabuThreads': 200, 'NaabuRate': 500, 'HTTPXthreads': 200, 'HTTPXrate': 500,
               'NucleiRate': 350, 'NucleiParallels': 40, 'FeroxbusterParallels': 25, 'FeroxbusterThreads': 20,
               'FeroxbusterTimeLimit': '20m', 'KatanaAdditionalFlagsT': '-p 25', 'byp4xx_threads': 40,
               'TimeoutModifier': 0.4}}  # Get threads amount by LoadLevel and tool
DetailsLevel = 2
Details = {1: {'NaabuPorts': 100, 'NaabuFlags': '', 'WAFfiltering': True, 'NucleiCritical': "high,critical",  # NucleiCritical is also currently using for DAST
               'NucleiConfigCritical': 'medium,high,critical', 'NucleiTokensCritical': 'low,medium,high,critical',
               'FeroxbusterAdditionalFlags': '-X "<html"', 'PostleaksAditionalFlags': '--strict',
               'KatanaAdditionalFlagsD': '-iqp -kf all -d 2 -ct 120', 'Byp4xx_flags': '-xV -xX -xS -xD',
               'TimeoutModifier': 0.7},
           2: {'NaabuPorts': 100, 'NaabuFlags': '', 'WAFfiltering': True, 'NucleiCritical': "medium,high,critical",
               'NucleiConfigCritical': 'low,medium,high,critical', 'NucleiTokensCritical': 'info,low,medium,high,critical',
               'FeroxbusterAdditionalFlags': "", 'PostleaksAditionalFlags': '--strict',
               'KatanaAdditionalFlagsD': '-iqp -kf all -d 3 -ct 180', 'Byp4xx_flags': '-xV -xX -xS -xD',
               'TimeoutModifier': 1},
           3: {'NaabuPorts': 1000, 'NaabuFlags': '-sa', 'WAFfiltering': True, 'NucleiCritical': "low,medium,high,critical",
               'NucleiConfigCritical': 'info,low,medium,high,critical,unknown', 'NucleiTokensCritical': 'info,low,medium,high,critical,unknown',
               'FeroxbusterAdditionalFlags': "", 'PostleaksAditionalFlags': '',
               'KatanaAdditionalFlagsD': '-iqp -kf all -d 4 -ct 600', 'Byp4xx_flags': '',
               'TimeoutModifier': 2.5},
           4: {'NaabuPorts': 1000, 'NaabuFlags': '-sa', 'WAFfiltering': False, 'NucleiCritical': "info,low,medium,high,critical,unknown",
               'NucleiConfigCritical': 'info,low,medium,high,critical,unknown', 'NucleiTokensCritical': 'info,low,medium,high,critical,unknown',
               'FeroxbusterAdditionalFlags': "", 'PostleaksAditionalFlags': '',
               'KatanaAdditionalFlagsD': '-kf all -d 5 -ct 2100', 'Byp4xx_flags': '',
               'TimeoutModifier': 10}}  # Get certain arguments by DetailsLevel and tool

Subfinder_DNSX_Naabu_command = Template("(subfinder -silent -all -dL Scan/root_domains.txt $includeRoots) | dnsx -silent -t $dnsxThreads -retry 5 -a | naabu $NaabuFlags -tp $NaabuPorts -ec -c $NaabuThreads -rate $NaabuRate -silent")
DNSX_Naabu_command = Template("dnsx -l Scan/root_domains.txt -silent -t $dnsxThreads -retry 5 -a | naabu $NaabuFlags -tp $NaabuPorts -ec -c $NaabuThreads -rate $NaabuRate -silent")
Naabu_command = Template("naabu -list Scan/root_domains.txt -tp $NaabuPorts -ec -c $NaabuThreads -rate $NaabuRate -silent $NaabuFlags")
HTTPX_command = Template("httpx -t $HTTPXthreads -rl $HTTPXrate -silent -retries 3")
CDNCheck_command = "cdncheck -i Scan/HTTP_assets_list.txt -silent -nc -resp -waf"
Nuclei_default_command = Template("nuclei -ss host-spray -eid waf-detect,tech-detect,dns-waf-detect -etags backup,config,exposure,panel,debug,network,js -s $NucleiCritical -rl $NucleiRate -c $NucleiParallels -silent -nc")
Nuclei_config_command = Template("nuclei -ss host-spray -eid waf-detect,tech-detect,dns-waf-detect -itags config,exposure,panel,debug,network,js -s $NucleiConfigCritical -rl $NucleiRate -c $NucleiParallels -silent -nc")
Nuclei_tokens_command = Template("nuclei -ss host-spray -tags token,tokens,takeover -s $NucleiTokensCritical -silent -nc")
Nuclei_DAST_command = Template("nuclei -ss host-spray -dast -etags backup -s $NucleiDASTCritical -rl $NucleiRate -c $NucleiParallels -silent -nc")
Feroxbuster_command = Template("feroxbuster --insecure -X \"requested URL was rejected\" -X \"<Message>Access Denied</Message>\" --auto-tune --no-recursion --quiet -w $FuzzingDictPath --stdin --redirects "
                               "--parallel $FeroxbusterParallels -t $FeroxbusterThreads --dont-extract-links -C 404 500 --time-limit $FeroxbusterTimeLimit $FeroxbusterAdditionalFlags")
Postleaks_command = Template("postleaks -k $domain $PostleaksAditionalFlags")
Katana_command = Template("katana -ef css,json,png,jpg,jpeg,woff2 -silent -nc -s breadth-first $KatanaAdditionalFlagsD $KatanaAdditionalFlagsT")
Uro_command = "uro"
Byp4xx_command = Template("go run Scan/byp4xx.go -xM -xUA $Byp4xx_flags -t $byp4xx_threads Scan/403pages.txt")
BurpProxy = "127.0.0.1:8080"

utilities_flags = {"nuclei": "-dn", "subfinder": "-ds", "dnsx": "-ds", "naabu": "No flag",
                   "httpx": "No flag", "cdncheck": "No flag", "katana": "-dc", "uro": "-dc"}  # "Utility": "Flag_to_disable". Required to check if the utility is installed


# ---Variables used by other utilities---
Flags = []
Domains = []  # Means root domains
Services = []  # All network services
HTTPAssets = []  # Subdomains and domains without WAF, also contains root domains services
AssetsWithWAF = {}  # {"https://site.com": "cloudflare"}
CrawledURLs = []  # Without WAF
URLsWithWAF = []
JSlinks = []

# ---Final results---
NucleiFindings = {"critical": [], "high": [], "medium": [], "low": [], "unknown": []}  # {"high": ["finding text", "finding text 2"]}
NucleiConfigFindings = {"critical": [], "high": [], "medium": [], "low": [], "info": [], "unknown": []}  # {"high": ["finding text", "finding text 2"]}
NucleiTokensFindings = {"critical": [], "high": [], "medium": [], "low": [], "info": [], "unknown": []}
NucleiDASTFindings = {"critical": [], "high": [], "medium": [], "low": [], "info": [], "unknown": []}
FuzzedDirectories = {"200": [], "3xx": [], "401": [], "403": [], "405": []}  # {"200": ["http://example.com/backup", http://example.com/admin]}
PostleaksResult = ""  # Text in HTML format
NotExistingSocialLinks = []  # [("http://example.com", "https://facebook.com/example"),  ("http://example.com/page", "https://t.me/example")]
LeakixFindings = []
Byp4xxResult = ""  # Text in HTML format

LeakixAPIKey = os.environ.get("LeakIX_API_key", "CHANGEME")  # Change CHANGEME to your API key
