from sys import argv
from string import Template
import os

# Readable names accepted on the command line. The scan itself still looks at the
# short flag (the value). Old short names keep working.
FlagAliases = {
    "-domain": "-d", "-file": "-f", "-report": "-o",
    "-load": "-ll", "-deep": "-ld", "-rate": "-rl", "-exclude": "-ex",
    "-all-ports": "-sa", "-scan-waf": "-waf", "-templates": "-tem", "-wordlist": "-sw", "-user-agent": "-ua",
    "-ip": "-i", "-verbose": "-v", "-markdown": "-md", "-no-open": "-do",
    "-no-subdomains": "-ds", "-no-vulns": "-dn", "-no-takeover": "-dt", "-no-params": "-dd",
    "-no-crawl": "-dc", "-no-dirs": "-df", "-no-bypass": "-db", "-no-waf": "-dw",
    "-no-inactive": "-di", "-no-social": "-dm", "-no-postman": "-dp", "-no-leakix": "-dl",
    "-no-history": "-dst", "-no-deps": "-dcf", "-no-browser": "-dh", "-no-forms": "-daff",
    "-qualys": "-q", "-burp": "-bw", "-burp-all": "-ba", "-burp-dirs": "-bf", "-burp-hits": "-bb",
    "-proxy": "-p", "-help": "-h",
}

HelpText = f"""Usage: {argv[0]} -file <file> -domain example.com -report <file> -load <number> -deep <number> -exclude test.example.com -rate <number> -proxy <proxy> -templates <path> -wordlist <file> -user-agent <string> [-help] [-verbose] [-markdown] [-all-ports] [-scan-waf] [-no-forms] [-no-browser] [-ip] [-qualys] [-no-open] [-no-subdomains] [-no-dirs] [-no-vulns] [-no-takeover] [-no-params] [-no-crawl] [-no-bypass] [-no-waf] [-no-inactive] [-no-social] [-no-postman] [-no-leakix] [-no-history] [-no-deps] [-burp-all] [-burp] [-burp-dirs] [-burp-hits]

Each flag has a short form and a long form. Both are accepted, for example -ld and -deep.

REQUIRED FLAGS:
-file - file with domains to scan
---OR---
-domain - domain to scan. This parameter can be repeated

OPTIONAL FLAGS:
-help - show this help menu
-report <file> - name of the final report file. Caution, the file will be overwritten if it already exists!
-markdown - additionally generate the report in Markdown (.md) format (the HTML report is always generated)
-verbose - verbose output
-load <number> - internet load level, affects the number of threads in utilities. Number: 1-3, 1 - minimum load, 3 - maximum, Default: 2
-deep <number> - how deep to look: more findings, much more time. Number: 1-4, 1 - fastest, 4 - most findings, Default: 2
-exclude <host> - host to exclude from scanning. Exact name, this parameter can be repeated
-all-ports - scan ALL ports instead of 100 or 1000
-scan-waf - scan hosts behind WAFs with Nuclei and Feroxbuster too (short: -waf)
-rate <number> - max requests per second on one host
-templates <path> - directory with Nuclei templates
-wordlist <file> - wordlist for subdomain bruteforce
-user-agent <string> - User-Agent for HTTP requests and for Nuclei, Katana, Feroxbuster and byp4xx
-ip - scan only the given addresses (skip DNS, subdomain enumeration and Postman checking)

DISABLING FEATURES:
-no-open - don't open a report file after its creation
-no-subdomains - disable subdomain enumeration
-no-dirs - disable directory fuzzing
-no-vulns - disable Nuclei vulnerability scan (except subdomain takeover)
-no-takeover - disable subdomain takeover checking
-no-params - disable parameter checks on collected links
-no-crawl - disable link crawling (and the token check in JS)
-no-bypass - disable 403/401 bypass attempts
-no-waf - disable the search for the server behind a WAF
-no-inactive - disable access search for inactive hosts
-no-social - disable social media takeover checking
-no-postman - disable public Postman collection checking
-no-leakix - disable LeakIX checking
-no-history - disable SecurityTrails historical IP checks
-no-deps - disable dependency check (exposed manifests, dependency confusion, CVE scan)
-no-forms - disable automatic form filling in Katana
-no-browser - disable the headless browser in Katana

QUALYS WAS INTEGRATION:
-qualys - sync discovered live web services into Qualys WAS: for every domain/subdomain not already
     present as a web app, create it, copy the parent domain's scan schedule, and launch an
     immediate scan with the Fast_Scan option profile (off by default; needs Qualys credentials,
     see README). A summary email is sent for the launched scans. Hosts listed in qualys_exclude.txt
     (auto-detected, one host/pattern per line) or in QUALYS_IGNORE_HOSTS are skipped

SENDING TO PROXY:
-burp-all - send all collected endpoints to Burp proxy, including those behind a WAF
-burp - send only collected endpoints that are not behind a WAF
-burp-dirs - send discovered directories to Burp proxy
-burp-hits - send successful WAF bypasses and old-host access to Burp proxy
-proxy <address> - Burp proxy (default: 127.0.0.1:8080)"""

utilities_flags = {"subfinder": "-ds", "dnsx": "-ds", "naabu": "No flag", "httpx": "No flag",
                   "cdncheck": "No flag", "katana": "-dc", "uro": "-dc",
                   "confused": "-dcf", "osv-scanner": "-dcf"}  # "Utility": "Flag_to_disable". Required to check if the utility is installed

LoadLevel = 2
Threads = {1: {'DNSX': 20, 'NaabuThreads': 10, 'NaabuRate': 70, 'HTTPXthreads': 15, 'HTTPXrate': 70,
               'NucleiRate': 40, 'NucleiParallels': 10, 'FeroxbusterParallels': 10, 'FeroxbusterThreads': 5,
               'FeroxbusterTimeLimit': '30m', 'FeroxbusterRate': "--rate-limit 10", 'KatanaParallels': 7, 'KatanaRate': '-rl 70',
               'byp4xx_threads': 10, 'WAFbypassThreads': 12},
           2: {'DNSX': 120, 'NaabuThreads': 75, 'NaabuRate': 170, 'HTTPXthreads': 80, 'HTTPXrate': 180,
               'NucleiRate': 110, 'NucleiParallels': 25, 'FeroxbusterParallels': 20, 'FeroxbusterThreads': 10,
               'FeroxbusterTimeLimit': '25m', 'FeroxbusterRate': "--auto-tune", 'KatanaParallels': 20, 'KatanaRate': '-rl 90',
                'byp4xx_threads': 25, 'WAFbypassThreads': 50},
           3: {'DNSX': 250, 'NaabuThreads': 150, 'NaabuRate': 400, 'HTTPXthreads': 200, 'HTTPXrate': 400,
               'NucleiRate': 250, 'NucleiParallels': 40, 'FeroxbusterParallels': 25, 'FeroxbusterThreads': 20,
               'FeroxbusterTimeLimit': '20m', 'FeroxbusterRate': "--auto-tune", 'KatanaParallels': 25, 'KatanaRate': '',
               'byp4xx_threads': 40, 'WAFbypassThreads': 110}}  # Get threads amount by LoadLevel and tool
DetailsLevel = 2
Details = {1: {'NaabuPorts': 100, 'NaabuFlags': '', 'WAFfiltering': True, 'NucleiCritical': "high,critical",  # NucleiCritical is also currently using for DAST
               'NucleiConfigCritical': 'medium,high,critical', 'NucleiTokensCritical': 'low,medium,high,critical',
               'FeroxbusterAdditionalFlags': '-X "<html"', 'PostleaksAditionalFlags': '--strict',
               'KatanaAdditionalFlags': '-iqp -kf all -d 2 -ct 120 -jc', 'Byp4xx_flags': '-xV -xX -xS -xD', 'CheckAll403links': False,
               'TimeoutModifier': 0.7, 'SubdomainsDict': 'Scan/resources/subdomains-top1million-5000.txt'},
           2: {'NaabuPorts': 100, 'NaabuFlags': '', 'WAFfiltering': True, 'NucleiCritical': "medium,high,critical",
               'NucleiConfigCritical': 'low,medium,high,critical', 'NucleiTokensCritical': 'info,low,medium,high,critical',
               'FeroxbusterAdditionalFlags': "", 'PostleaksAditionalFlags': '--strict',
               'KatanaAdditionalFlags': '-iqp -kf all -d 3 -ct 180 -jc -jsl', 'Byp4xx_flags': '-xV -xX -xS -xD', 'CheckAll403links': False,
               'TimeoutModifier': 1, 'SubdomainsDict': 'Scan/resources/subdomains-top1million-5000.txt'},
           3: {'NaabuPorts': 1000, 'NaabuFlags': '-sa', 'WAFfiltering': True, 'NucleiCritical': "low,medium,high,critical",
               'NucleiConfigCritical': 'info,low,medium,high,critical,unknown', 'NucleiTokensCritical': 'info,low,medium,high,critical,unknown',
               'FeroxbusterAdditionalFlags': "", 'PostleaksAditionalFlags': '',
               'KatanaAdditionalFlags': '-iqp -kf all -d 4 -ct 600 -jc -jsl', 'Byp4xx_flags': '', 'CheckAll403links': True,
               'TimeoutModifier': 2.5, 'SubdomainsDict': 'Scan/resources/subdomains-top1million-20000.txt'},
           4: {'NaabuPorts': 1000, 'NaabuFlags': '-sa', 'WAFfiltering': False, 'NucleiCritical': "info,low,medium,high,critical,unknown",
               'NucleiConfigCritical': 'info,low,medium,high,critical,unknown', 'NucleiTokensCritical': 'info,low,medium,high,critical,unknown',
               'FeroxbusterAdditionalFlags': "", 'PostleaksAditionalFlags': '',
               'KatanaAdditionalFlags': '-kf all -d 5 -ct 2100 -jc -jsl', 'Byp4xx_flags': '', 'CheckAll403links': True,
               'TimeoutModifier': 10, 'SubdomainsDict': 'Scan/resources/subdomains-top1million-20000.txt'}}  # Get certain arguments by DetailsLevel and tool

Subfinder_command = "subfinder -silent -all"
DNSX_bruteforce_command = Template("dnsx -silent -t $dnsxThreads -a -w $SubdomainsDict -d $DomainsFile")
DNSX_Naabu_command = Template("dnsx -silent -t $dnsxThreads -retry 5 -a | naabu -s s $NaabuFlags -tp $NaabuPorts -ec -c $NaabuThreads -rate $NaabuRate -silent")
Naabu_command = Template("naabu -s s -tp $NaabuPorts -ec -c $NaabuThreads -rate $NaabuRate -silent $NaabuFlags")
HTTPX_command = Template("httpx -t $HTTPXthreads -rl $HTTPXrate -silent -retries 5")
CDNCheck_command = Template("cdncheck -i $AssetsListFile -silent -nc -resp -waf")
Nuclei_default_command = Template("nuclei -ss host-spray -eid waf-detect,tech-detect,dns-waf-detect -etags backup,cache,logs,listing,config,exposure,panel,debug,network,js -s $NucleiCritical -rl $NucleiRate -c $NucleiParallels -silent -nc -duc -H \"User-Agent: $UserAgent\"")
Nuclei_config_command = Template("nuclei -ss host-spray -eid waf-detect,tech-detect,dns-waf-detect -tags config,exposure,panel,debug,network,js -s $NucleiConfigCritical -rl $NucleiRate -c $NucleiParallels -silent -nc -H \"User-Agent: $UserAgent\"")
Nuclei_tokens_command = Template("nuclei -ss host-spray -tags token,tokens,takeover -s $NucleiTokensCritical -silent -nc -duc -H \"User-Agent: $UserAgent\"")
Nuclei_DAST_command = Template("nuclei -ss host-spray -dast -etags backup,cache,logs,listing -s $NucleiDASTCritical -rl $NucleiRate -c $NucleiParallels -silent -nc -duc -fuzz-param-frequency 1000 -H \"User-Agent: $UserAgent\"")
Nuclei_subdomains_takeover_command = Template("nuclei -ss host-spray -profile subdomain-takeovers -rl $NucleiRate -c $NucleiParallels -silent -nc -H \"User-Agent: $UserAgent\"")
Feroxbuster_command = Template("feroxbuster --insecure --user-agent \"$UserAgent\" -X \"requested URL was rejected\" -X \"blocked by AWS WAF\" -X \"sage>Access Denied<\\/Mess\" -X \"firewall on this server is blocking your\" $FeroxbusterRate --no-recursion --quiet "
                               "-w $FuzzingDictPath --stdin --redirects --parallel $FeroxbusterParallels -t $FeroxbusterThreads --dont-extract-links -C 404 500 --time-limit $FeroxbusterTimeLimit $FeroxbusterAdditionalFlags")
Postleaks_command = Template("postleaks -k $domain $PostleaksAditionalFlags --output $PostleaksOutput")
Katana_command = Template("katana -ef css,png,jpg,jpeg,woff2 -silent -nc -s breadth-first $KatanaAdditionalFlags -p $KatanaParallels $KatanaRate -H \"User-Agent: $UserAgent\"")
Uro_command = "uro"
Byp4xx_command = Template("go run Scan/byp4xx.go -xM -xUA $Byp4xx_flags -H \"User-Agent: $UserAgent\" -t $byp4xx_threads $Pages403File")

UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0"  # User-Agent used in our own HTTP requests


# ---Variables used by other utilities---
Flags = []  # Flags without additional arguments, like ['-do', '-v', '-dl']
RawSubdomains = []  # Unchecked subdomains
Domains = []  # Means root domains
WildcardDomains = []  # Root domains resolving any non-existent subdomain: enumeration is skipped for them, only the root domain itself is scanned
Services = []  # All network services
HTTPAssets = []  # Subdomains and domains without WAF, also contains root domains services
AssetsWithWAF = {}  # {"https://site.com": "cloudflare"}
CrawledURLs = []  # Without WAF
URLsWithWAF = []
JSlinks = []
TemplatesPath = ""
CustomSubdomainsDict = ""  # Custom wordlist for subdomains bruteforce (set by -sw flag). Empty means use the DetailsLevel default
ExcludedHosts = []
BurpProxy = "127.0.0.1:8080"  # By default
RunDir = "Logs"  # Set at the start of each scan to Logs/<first_domain>_<timestamp>. All logs and temporary files of the run are stored here

# ---Final results---
GeneralInfoNotes = []  # Extra lines printed at the end of the "General information" report section: excluded domains, non-fatal errors, enabled modules, etc.
NucleiFindings = {"critical": [], "high": [], "medium": [], "low": [], "unknown": []}  # {"high": ["finding text", "finding text 2"]}
NucleiConfigFindings = {"critical": [], "high": [], "medium": [], "low": [], "info": [], "unknown": []}  # {"high": ["finding text", "finding text 2"]}
NucleiTokensFindings = {"critical": [], "high": [], "medium": [], "low": [], "info": [], "unknown": []}
NucleiDASTFindings = {"critical": [], "high": [], "medium": [], "low": [], "info": [], "unknown": []}
NucleiTakeoverFindings = {"critical": [], "high": [], "medium": [], "low": [], "info": [], "unknown": []}
FuzzedDirectories = {"200": [], "3xx": [], "401": [], "403": [], "405": []}  # {"200": ["http://example.com/backup", http://example.com/admin]}
WAFBypassHosts = []  # [("siteinhostheader.com", "https://destinationhost.com", 200), ("host1.com", "http://host2.com", 301)]
InactiveHostsAccess = []  # [("siteinhostheader.com", "https://destinationhost.com", 200), ("host1.com", "http://host2.com", 200)]
PostleaksResult = {}  # {"keyword": ["[+] (ID...) GET: ...", " - Headers: ...", " > Potential secret found: ..."]} - raw postleaks output lines per keyword
NotExistingSocialMediaLinks = []  # [("http://example.com", "https://facebook.com/example"),  ("http://example.com/page", "https://t.me/example")]
LeakixFindings = []
Byp4xxResult = []  # [[host_title_line, result_line, result_line], ...] - raw byp4xx output grouped per host
DepExposedFiles = []  # URLs of leaked dependency manifests/lockfiles
DepConfusionFindings = []  # [{"url", "package", "scoped"}]
DepCveFindings = []  # [{"url", "package", "version", "vuln_id", "severity", "summary"}]

LeakixAPIKey = os.environ.get("LeakIX_API_key", "CHANGEME")  # Change CHANGEME to your API key
SecurityTrailsAPIKey = os.environ.get("SecurityTrails_API_key", "")  # Historical-DNS checks (origin behind WAF + access to inactive hosts). Empty => the check is silently disabled

# ---Qualys WAS integration (enabled with the -q flag)---
QualysAPIURL = os.environ.get("QUALYS_API_URL", "https://qualysapi.qualys.com")  # Must match your Qualys platform (POD), e.g. https://qualysapi.qualys.eu or https://qualysapi.qg2.apps.qualys.com

# Credentials (username + password). Resolved once at startup; first source that yields a value wins:
#   1. AWS SSM Parameter Store (used when the *_SSM_PARAM vars below are set) - preferred
#   2. environment variables QUALYS_USERNAME / QUALYS_PASSWORD
#   3. the hardcoded fallbacks below - just replace CHANGEME for a quick local test
QualysUsername = os.environ.get("QUALYS_USERNAME", "CHANGEME")  # Hardcode here for local testing
QualysPassword = os.environ.get("QUALYS_PASSWORD", "CHANGEME")  # Hardcode here for local testing
QualysSSMUserParam = os.environ.get("QUALYS_SSM_USER_PARAM", "")          # e.g. /autoeasm/qualys/username (SecureString)
QualysSSMPasswordParam = os.environ.get("QUALYS_SSM_PASSWORD_PARAM", "")  # e.g. /autoeasm/qualys/password (SecureString)
QualysSSMRegion = os.environ.get("QUALYS_SSM_REGION", "") or os.environ.get("AWS_REGION", "")  # boto3 region for the SSM calls

QualysScanProfileName = os.environ.get("QUALYS_SCAN_PROFILE", "Fast_Scan")     # Option profile for the immediate script-launched scans
QualysDefaultProfile = os.environ.get("QUALYS_DEFAULT_PROFILE", "default_vulnerability_scan")  # Option profile assigned to created web apps and their schedules
QualysEnsureTags = os.environ.get("QUALYS_ENSURE_TAGS", "prod,webapp")  # Tag names applied to a newly bootstrapped ROOT domain app, which has no parent to inherit tags from. Subdomains always inherit the root app's tags instead. Tags must already exist in Qualys - the API cannot create them
QualysIgnoreHosts = os.environ.get("QUALYS_IGNORE_HOSTS", "")  # Comma-separated hosts/patterns (fnmatch, e.g. "dev.example.com,*.staging.example.com") to skip in the Qualys WAS sync. Merged with the auto-detected qualys_exclude.txt file (one pattern per line)
# Default schedule applied to a freshly created root domain when there is no parent schedule to copy:
QualysDefaultSchedule = {"frequency": "WEEKLY", "weekDays": "SUNDAY", "startHour": 3, "timeZone": "UTC"}
QualysScheduleRecipients = os.environ.get("QUALYS_SCHEDULE_RECIPIENTS", "")  # Additional recipient(s) for the schedule's pre-scan notification (comma-separated)
QualysScheduleSendMail = os.environ.get("QUALYS_SCHEDULE_SENDMAIL", "false").lower() == "true"  # Schedule "send mail at scan completion" - off by default (Qualys otherwise emails all admins with view access)
QualysNotificationMessage = os.environ.get("QUALYS_NOTIFICATION_MESSAGE", "A Qualys scan is scheduled to start soon.")  # Custom pre-scan notification message on created schedules
QualysProgressiveScanning = os.environ.get("QUALYS_PROGRESSIVE_SCANNING", "ENABLED")  # Progressive scanning on created schedules: DEFAULT | ENABLED | DISABLED
# Distribution groups live only in the newer WAS REST 1.0 API on the portal host (not the QPS 3.0
# XML API). After a schedule is created via QPS, the group is attached via that API.
QualysWebUIURL = os.environ.get("QUALYS_WEBUI_URL", "") or QualysAPIURL.replace("qualysapi", "qualysguard")  # portal host, e.g. https://qualysguard.qualys.eu
QualysDistributionUuids = os.environ.get("QUALYS_DISTRIBUTION_UUIDS", "")  # Override distribution group UUID(s), comma-separated. Empty => copy from the parent domain's schedule
# Qualys scan-completion email for the immediate (script-launched) Fast_Scan. Qualys emails ALL
# users with view access to the web app (not selectable to "owner only"), so this defaults off to
# avoid spamming admins; set QUALYS_SCAN_SENDMAIL=true to let Qualys send it.
QualysScanSendMail = os.environ.get("QUALYS_SCAN_SENDMAIL", "false").lower() == "true"
QualysWASResults = []  # List of QualysWebAppResult records, shown in the report

# Email notification for the launched immediate scans
QualysNotifyEmail = os.environ.get("QUALYS_NOTIFY_EMAIL", "")
SMTPHost = os.environ.get("SMTP_HOST", "")          # Empty => notification is logged but not sent
SMTPPort = int(os.environ.get("SMTP_PORT", "587"))
SMTPUser = os.environ.get("SMTP_USER", "")
SMTPPassword = os.environ.get("SMTP_PASSWORD", "")
SMTPFrom = os.environ.get("SMTP_FROM", "") or SMTPUser
SMTPUseTLS = os.environ.get("SMTP_TLS", "true").lower() == "true"
