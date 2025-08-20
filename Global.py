from sys import argv
from string import Template
import os

HelpText = f"""Usage: {argv[0]} -f <file> -d example.com -o <file> -ll <number> -ld <number> -ex test.example.com -rl <number> -p <proxy> -tem <path> [-h] [-v] [-sa] [-i] [-do] [-ds] [-df] [-dn] [-dt] [-dd] [-dc] [-db] [-dw] [-di] [-dm] [-dp] [-dl] [-ba] [-bw] [-bf] [-bb]

REQUIRED FLAGS:
-f - file with domains to scan
---OR---
-d - domain to scan. This parameter can be repeated

OPTIONAL FLAGS:
-h - show this help menu
-o <file> - name of the final output HTML file with the report. Caution, the file will always be overwritten if it already exists! Default name: Report
-v - verbose output
-ll <number> - internet load level, affects the number of threads in utilities. Number: 1-3, 1 - minimum load, 3 - maximum, Default: 2
-ld <number> - level of detail, slightly increases the number of findings and greatly increases execution time and junk info. Number: 1-4, 1 - max speed, 4 - max findings, Default: 2
-ex <subdomain> - subdomain to exclude from scanning. This parameter can be repeated
-sa - scan ALL ports instead of 100 or 1000
-rl <integer number> - rate limit for tools (max requests per second on one host)
-aff - add Automatic form filling in katana
-tem - specify directory with Nuclei templates
-i - IP scan (skipping DNSX check, subdomain enumeration and Postman checking)

DISABLING FEATURES:
-do - don't open a report file after its creation
-ds - disable subdomains enumeration
-df - disable directory fuzzing
-dn - disable Nuclei scan (except subdomains takeover)
-dt - disable subdomains takeover checking
-dd - disable DAST scan
-dc - disable links crawling (and tokens check in JS)
-db - disable 403 bypass attempts
-dw - disable WAF bypass attempts
-di - disable access search for inactive hosts
-dm - disable social media takeover checking
-dp - disable public Postman collections checking
-dl - disable Leakix checking

SENDING TO PROXY:
-ba - send all collected endpoints to Burp proxy including with WAF
-bw - send only collected endpoints without WAF to Burp proxy
-bf - send fuzzed directories to Burp proxy
-bb - send all successful WAF bypass attempts and old subdomains access to proxy
-p <proxy> - burp proxy (default: 127.0.0.1:8080)"""

utilities_flags = {"subfinder": "-ds", "dnsx": "-ds", "naabu": "No flag", "httpx": "No flag",
                   "cdncheck": "No flag", "katana": "-dc", "uro": "-dc"}  # "Utility": "Flag_to_disable". Required to check if the utility is installed

LoadLevel = 2
Threads = {1: {'DNSX': 20, 'NaabuThreads': 10, 'NaabuRate': 70, 'HTTPXthreads': 15, 'HTTPXrate': 70,
               'NucleiRate': 40, 'NucleiParallels': 10, 'FeroxbusterParallels': 10, 'FeroxbusterThreads': 5,
               'FeroxbusterTimeLimit': '30m', 'FeroxbusterRate': "--rate-limit 10", 'KatanaParallels': 7, 'KatanaRate': '-rl 70',
               'byp4xx_threads': 10, 'WAFbypassThreads': 12},
           2: {'DNSX': 120, 'NaabuThreads': 75, 'NaabuRate': 170, 'HTTPXthreads': 80, 'HTTPXrate': 180,
               'NucleiRate': 110, 'NucleiParallels': 25, 'FeroxbusterParallels': 20, 'FeroxbusterThreads': 10,
               'FeroxbusterTimeLimit': '25m', 'FeroxbusterRate': "--auto-tune", 'KatanaParallels': 20, 'KatanaRate': '',
                'byp4xx_threads': 25, 'WAFbypassThreads': 50},
           3: {'DNSX': 250, 'NaabuThreads': 150, 'NaabuRate': 400, 'HTTPXthreads': 200, 'HTTPXrate': 400,
               'NucleiRate': 250, 'NucleiParallels': 40, 'FeroxbusterParallels': 25, 'FeroxbusterThreads': 20,
               'FeroxbusterTimeLimit': '20m', 'FeroxbusterRate': "--auto-tune", 'KatanaParallels': 25, 'KatanaRate': '',
               'byp4xx_threads': 40, 'WAFbypassThreads': 110}}  # Get threads amount by LoadLevel and tool
DetailsLevel = 2
Details = {1: {'NaabuPorts': 100, 'NaabuFlags': '', 'WAFfiltering': True, 'NucleiCritical': "high,critical",  # NucleiCritical is also currently using for DAST
               'NucleiConfigCritical': 'medium,high,critical', 'NucleiTokensCritical': 'low,medium,high,critical',
               'FeroxbusterAdditionalFlags': '-X "<html"', 'PostleaksAditionalFlags': '--strict',
               'KatanaAdditionalFlags': '-iqp -kf all -d 2 -ct 120', 'Byp4xx_flags': '-xV -xX -xS -xD', 'CheckAll403links': False,
               'TimeoutModifier': 0.7},
           2: {'NaabuPorts': 100, 'NaabuFlags': '', 'WAFfiltering': True, 'NucleiCritical': "medium,high,critical",
               'NucleiConfigCritical': 'low,medium,high,critical', 'NucleiTokensCritical': 'info,low,medium,high,critical',
               'FeroxbusterAdditionalFlags': "", 'PostleaksAditionalFlags': '--strict',
               'KatanaAdditionalFlags': '-iqp -kf all -d 3 -ct 180', 'Byp4xx_flags': '-xV -xX -xS -xD', 'CheckAll403links': False,
               'TimeoutModifier': 1},
           3: {'NaabuPorts': 1000, 'NaabuFlags': '-sa', 'WAFfiltering': True, 'NucleiCritical': "low,medium,high,critical",
               'NucleiConfigCritical': 'info,low,medium,high,critical,unknown', 'NucleiTokensCritical': 'info,low,medium,high,critical,unknown',
               'FeroxbusterAdditionalFlags': "", 'PostleaksAditionalFlags': '',
               'KatanaAdditionalFlags': '-iqp -kf all -d 4 -ct 600', 'Byp4xx_flags': '', 'CheckAll403links': True,
               'TimeoutModifier': 2.5},
           4: {'NaabuPorts': 1000, 'NaabuFlags': '-sa', 'WAFfiltering': False, 'NucleiCritical': "info,low,medium,high,critical,unknown",
               'NucleiConfigCritical': 'info,low,medium,high,critical,unknown', 'NucleiTokensCritical': 'info,low,medium,high,critical,unknown',
               'FeroxbusterAdditionalFlags': "", 'PostleaksAditionalFlags': '',
               'KatanaAdditionalFlags': '-kf all -d 5 -ct 2100', 'Byp4xx_flags': '', 'CheckAll403links': True,
               'TimeoutModifier': 10}}  # Get certain arguments by DetailsLevel and tool

Subfinder_command = "subfinder -silent -all"
DNSX_Naabu_command = Template("dnsx -silent -t $dnsxThreads -retry 5 -a | naabu -s s $NaabuFlags -tp $NaabuPorts -ec -c $NaabuThreads -rate $NaabuRate -silent")
Naabu_command = Template("naabu -s s -tp $NaabuPorts -ec -c $NaabuThreads -rate $NaabuRate -silent $NaabuFlags")
HTTPX_command = Template("httpx -t $HTTPXthreads -rl $HTTPXrate -silent -retries 5")
CDNCheck_command = "cdncheck -i Scan/HTTP_assets_list.txt -silent -nc -resp -waf"
Nuclei_default_command = Template("nuclei -ss host-spray -eid waf-detect,tech-detect,dns-waf-detect -etags backup,cache,logs,listing,config,exposure,panel,debug,network,js -s $NucleiCritical -rl $NucleiRate -c $NucleiParallels -silent -nc -duc")
Nuclei_config_command = Template("nuclei -ss host-spray -eid waf-detect,tech-detect,dns-waf-detect -tags config,exposure,panel,debug,network,js -s $NucleiConfigCritical -rl $NucleiRate -c $NucleiParallels -silent -nc")
Nuclei_tokens_command = Template("nuclei -ss host-spray -tags token,tokens,takeover -s $NucleiTokensCritical -silent -nc -duc")
Nuclei_DAST_command = Template("nuclei -ss host-spray -dast -etags backup,cache,logs,listing -s $NucleiDASTCritical -rl $NucleiRate -c $NucleiParallels -silent -nc -duc -fuzz-param-frequency 1000")
Nuclei_subdomains_takeover_command = Template("nuclei -ss host-spray -profile subdomain-takeovers -rl $NucleiRate -c $NucleiParallels -silent -nc")
Feroxbuster_command = Template("feroxbuster --insecure -X \"requested URL was rejected\" -X \"blocked by AWS WAF\" -X \"sage>Access Denied<\/Mess\" -X \"firewall on this server is blocking your\" $FeroxbusterRate --no-recursion --quiet "
                               "-w $FuzzingDictPath --stdin --redirects --parallel $FeroxbusterParallels -t $FeroxbusterThreads --dont-extract-links -C 404 500 --time-limit $FeroxbusterTimeLimit $FeroxbusterAdditionalFlags")
Postleaks_command = Template("postleaks -k $domain $PostleaksAditionalFlags")
Katana_command = Template("katana -ef css,json,png,jpg,jpeg,woff2 -silent -nc -s breadth-first $KatanaAdditionalFlags -p $KatanaParallels $KatanaRate")
Uro_command = "uro"
Byp4xx_command = Template("go run Scan/byp4xx.go -xM -xUA $Byp4xx_flags -t $byp4xx_threads Scan/403pages.txt")


# ---Variables used by other utilities---
Flags = []
RawSubdomains = []  # Unchecked subdomains
Domains = []  # Means root domains
Services = []  # All network services
HTTPAssets = []  # Subdomains and domains without WAF, also contains root domains services
AssetsWithWAF = {}  # {"https://site.com": "cloudflare"}
CrawledURLs = []  # Without WAF
URLsWithWAF = []
JSlinks = []
TemplatesPath = ""
ExcludedHosts = []
BurpProxy = "127.0.0.1:8080"  # By default

# ---Final results---
NucleiFindings = {"critical": [], "high": [], "medium": [], "low": [], "unknown": []}  # {"high": ["finding text", "finding text 2"]}
NucleiConfigFindings = {"critical": [], "high": [], "medium": [], "low": [], "info": [], "unknown": []}  # {"high": ["finding text", "finding text 2"]}
NucleiTokensFindings = {"critical": [], "high": [], "medium": [], "low": [], "info": [], "unknown": []}
NucleiDASTFindings = {"critical": [], "high": [], "medium": [], "low": [], "info": [], "unknown": []}
NucleiTakeoverFindings = {"critical": [], "high": [], "medium": [], "low": [], "info": [], "unknown": []}
FuzzedDirectories = {"200": [], "3xx": [], "401": [], "403": [], "405": []}  # {"200": ["http://example.com/backup", http://example.com/admin]}
WAFBypassHosts = []  # [("siteinhostheader.com", "https://destinationhost.com"), ("host1.com", "http://host2.com")]
InactiveHostsAccess = []  # [("siteinhostheader.com", "https://destinationhost.com"), ("host1.com", "http://host2.com")]
PostleaksResult = ""  # Text in HTML format
NotExistingSocialLinks = []  # [("http://example.com", "https://facebook.com/example"),  ("http://example.com/page", "https://t.me/example")]
LeakixFindings = []
Byp4xxResult = ""  # Text in HTML format

LeakixAPIKey = os.environ.get("LeakIX_API_key", "CHANGEME")  # Change CHANGEME to your API key
