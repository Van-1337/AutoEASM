## Description

**AutoEASM** (External Attack Surface Management) **tool** allows a quick scan of all domains and subdomains of any company with the help of different utilities and gets a list of important issues for verification. This automation allows the automatic testing of domains regularly with limited resources of the security team.
Download and open **"Report Example.html"** file to see what you get when you run a scan with this utility.

## Used utilities

| **Name**  | **Link**                                                                                                                                                                                                                                                                                                                                                                    | **Description**                                                                                                                                                                                                                                                      |
| --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| subfinder | [subfinder: Fast passive subdomain enumeration tool.](https://github.com/projectdiscovery/subfinder)                                                                                                                                                                                                                                                                        | **Subfinder** is a subdomain discovery tool that returns valid subdomains for websites, using passive online sources. It has a simple, modular architecture and is optimized for speed.                                                                              |
| dnsx      | [dnsx: dnsx is a fast and multi-purpose DNS toolkit allow to run multiple DNS queries of your choice with a list of user-supplied resolvers.](https://github.com/projectdiscovery/dnsx)                                                                                                                                                                                     | **Dnsx** is a fast and multi-purpose DNS toolkit designed for running various probes. It supports multiple DNS queries, user supplied resolvers and DNS wildcard filtering.                                                                                          |
| naabu     | [naabu: A fast port scanner written in go with a focus on reliability and simplicity. Designed to be used in combination with other tools for attack surface discovery in bug bounties and pentests](https://github.com/projectdiscovery/naabu)                                                                                                                             | **Naabu** is a port scanning tool written in Go that allows you to enumerate valid ports for hosts in a fast and reliable manner. It is a really simple tool that does fast SYN/CONNECT/UDP scans on the host/list of hosts and lists all ports that return a reply. |
| httpx     | [httpx: httpx is a fast and multi-purpose HTTP toolkit that allows running multiple probes using the retryablehttp library.](https://github.com/projectdiscovery/httpx)                                                                                                                                                                                                     | **HTTPX** is a fast and multi-purpose HTTP toolkit that allows running multiple probes using the retryablehttp library. It is designed to maintain result reliability with an increased number of threads.                                                           |
| nuclei    | [nuclei: Nuclei is a fast, customizable vulnerability scanner powered by the global security community and built on a simple YAML-based DSL, enabling collaboration to tackle trending vulnerabilities on the internet. It helps you find vulnerabilities in your applications, APIs, networks, DNS, and cloud configurations.](https://github.com/projectdiscovery/nuclei) | **Nuclei** is a fast and customisable vulnerability scanner based on simple YAML based DSL.                                                                                                                                                                          |
| katana    | [katana: A next-generation crawling and spidering framework.](https://github.com/projectdiscovery/katana)                                                                                                                                                                                                                                                                   | **Katana** is a next-generation crawling and spidering framework.                                                                                                                                                                                                    |
| confused  | [confused (knavesec fork)](https://github.com/knavesec/confused)                                                                                                                                                                                                                                                                                                            | **Confused** checks dependency manifests against public registries and reports package names that are not registered (possible dependency confusion). Fork is used instead of the unmaintained original (Pipfile, composer `installed.json`, bugfixes).				 |
| osv-scanner | [osv-scanner: Vulnerability scanner that uses data from OSV.](https://github.com/google/osv-scanner)                                                                                                                                                                                                                                                                      | **OSV-Scanner** checks lockfiles, manifests and JS/CDN URLs (library name + version in the path or filename) against the OSV database. 																																 |
| feroxbuster | [feroxbuster: A fast, simple, recursive content discovery tool written in Rust.](https://github.com/epi052/feroxbuster)                                                                                                                                                                                                                                                   | **Feroxbuster** is an open-source web fuzzing tool. Has convenient functions for automatic adjustment of scanning speed and filters.                                                                                                                                 |
| uro       | [uro: declutters url lists for crawling/pentesting](https://github.com/s0md3v/uro)                                                                                                                                                                                                                                                                                          | **Uro** is designed to simplify handling URL lists for security testing, which can be cumbersome due to uninteresting or duplicate content.                                                                                                                          |
| byp4xx    | [byp4xx: 40X/HTTP bypasser in Go. Features: Verb tampering, headers, #bugbountytips, User-Agents, extensions, default credentials...](https://github.com/lobuhi/byp4xx)                                                                                                                                                                                                     | **byp4xx** is a 40X bypasser in Go. Methods from #bugbountytips, headers, verb tampering, user agents and more.                                                                                                                                                      |
| LeakiX    | [LeakiX](https://leakix.net/ "https://leakix.net/")                                                                                                                                                                                                                                                                                                                         | **LeakiX** is a cybersecurity company that specializes in providing businesses with comprehensive visibility into their internet-facing assets. It provides tools and analysis to detect vulnerabilities in systems and networks.                                    |
| Postleaks | [postleaks: Search for sensitive data in Postman public library.](https://github.com/cosad3s/postleaks)                                                                                                                                                                                                                                                                     | **Postleaks** script is aimed at searching for confidential information in the Postman public library.                                                                                                                                                               |


&nbsp;


![Flowchart](https://github.com/Van-1337/AutoEASM/raw/master/Flowchart.jpg)
&nbsp;

## Installation

1. Install Python and Go on your PC (it can be both Windows or Linux). Clone the repository:
`git clone https://github.com/Van-1337/AutoEASM`

2. For **Linux** the following commands are required:
```
sudo apt install -y feroxbuster
cd AutoEASM/ ; chmod +x Scan/byp4xx.go
apt-get install libpcap-dev -y
```
For **Windows** no additional commands are required.

3. Install dependencies using the following commands:
```
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/knavesec/confused@latest
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest
python -m pip install --user pipx    or     python3 -m pip install --user pipx
pip install requests
pip install postleaks
pipx install uro
```

4. \[*Optional, but preferable*\] Change the Leakix API key at the end of the Global.py file **OR** specify it in the `LeakIX_API_key` environment variable. A free key for 3000 requests per month can be obtained [here](https://leakix.net/settings/api).

5. \[*Optional, but preferable*\] Add your API keys to subfinder using [this instruction](https://docs.projectdiscovery.io/tools/subfinder/install#post-install-configuration) (for Windows, file with API keys is `C:\Users\*user*\AppData\Roaming\subfinder\provider-config.yaml`). We suggest adding at least Securitytrails free key, but you can also add other available keys.

## Docker using

1. Go to the docker directory: `cd Docker`
2. *\[Optional\]* Specify available API keys to provider-config.yaml file. We advice specify at least securitytrails key. For example:
```
securitytrails:
  - AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```
3. Build the docker container (use sudo on linux):
`docker build --no-cache -t easm-automate .`
4. Run the docker using the command below. If there will be a question about access to host files - allow this (it is required to copy the report to the host). If the container does not start after that - execute the command again.

**Windows:**  
`docker run --rm -it -v %cd%\Report:/app/output -v %cd%\provider-config.yaml:/root/.config/subfinder/provider-config.yaml -e LeakIX_API_key="CHANGEME" easm-automate -d domain.com`

**Linux:**  
`sudo docker run --rm -it -v "$(pwd)/Report":/app/output -v "$(pwd)/provider-config.yaml":/root/.config/subfinder/provider-config.yaml -e LeakIX_API_key="CHANGEME" easm-automate -d domain.com`

**Windows file scan:**  
`docker run --rm -it -v %cd%\Report:/app/output -v %cd%\provider-config.yaml:/root/.config/subfinder/provider-config.yaml -v %cd%:/src -e LeakIX_API_key="CHANGEME" easm-automate -f domains.txt`

**Linux file scan:**  
`sudo docker run --rm -it -v "$(pwd)/Report":/app/output -v "$(pwd)/provider-config.yaml":/root/.config/subfinder/provider-config.yaml -v "$(pwd):/src" -e LeakIX_API_key="CHANGEME" easm-automate -f domains.txt`

Parameter `-e LeakIX_API_key="CHANGEME"` can be deleted if you don't have a leakIX key.

## Usage

On the utility input, you need to get a list of root domains. It will find subdomains on them itself and scan for key vulnerabilities.

To get help menu:
`python main.py -h`

To scan one domain:
`python main.py -d vulnweb.com`

To scan the domain list:
`python main.py -f root_domains.txt`

Also, the useful flags include:
```
-ll <number> - internet load level, affects the number of threads in utilities. Number: 1-3, 1 - minimum load, 3 - maximum, Default: 2
-ld <number> - level of detail, slightly increases the number of findings and greatly increases execution time and junk info. Number: 1-4, 1 - max speed, 4 - max findings, Default: 2
```

For example, `-ll 1` can be used if the hosts can go down from the load, or `-ld 1` can be used if there is not a lot of time to check for findings.

## Qualys WAS integration (`-q`)

The optional `-q` flag pushes every **live web service** found by the scan (root domains and subdomains that HTTPX confirmed as reachable websites, with or without a WAF) into **Qualys Web Application Scanning (WAS)**. For each asset that does **not** already exist as a Qualys web app it will:

1. **Create the web app** — inheriting the parent domain's tags and default option profile.
2. **Create an active scan schedule** — `default_vulnerability_scan` option profile, progressive scanning enabled, and the recurrence + distribution group + pre-scan notification **copied from the parent domain's schedule**.
3. **Launch an immediate scan** with the `Fast_Scan` option profile.
4. Send a **summary email** of the launched scans (if SMTP is configured) and add a **Qualys WAS** section to the HTML/Markdown report.

Assets already present in Qualys are skipped. The feature is **off by default** — a normal run never touches Qualys.

```
python main.py -d example.com -q
```

### Configuration

Credentials are resolved once at startup in this order: **AWS SSM Parameter Store → environment variables → hardcoded values in `Global.py`**. For a quick local test, replace the `CHANGEME` values in the Qualys block at the end of `Global.py`. Everything can also be set via environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `QUALYS_API_URL` | `https://qualysapi.qualys.com` | QPS API host — set to your platform/POD (e.g. `https://qualysapi.qualys.eu`) |
| `QUALYS_USERNAME` / `QUALYS_PASSWORD` | `CHANGEME` | Qualys credentials (Basic auth) |
| `QUALYS_SSM_USER_PARAM` / `QUALYS_SSM_PASSWORD_PARAM` | *(empty)* | AWS SSM Parameter Store names for the credentials (SecureString). Requires `boto3` |
| `QUALYS_SSM_REGION` | `AWS_REGION` | AWS region for the SSM calls |
| `QUALYS_SCAN_PROFILE` | `Fast_Scan` | Option profile for the immediate, script-launched scan |
| `QUALYS_DEFAULT_PROFILE` | `default_vulnerability_scan` | Option profile assigned to created web apps and their schedules |
| `QUALYS_PROGRESSIVE_SCANNING` | `ENABLED` | Progressive scanning on created schedules (`DEFAULT`/`ENABLED`/`DISABLED`) |
| `QUALYS_WEBUI_URL` | derived from `QUALYS_API_URL` | Portal host for the WAS REST 1.0 API, e.g. `https://qualysguard.qualys.eu` |
| `QUALYS_DISTRIBUTION_UUIDS` | *(empty)* | Override distribution-group UUID(s). Empty = copy from the parent domain's schedule |
| `QUALYS_SCHEDULE_SENDMAIL` | `false` | Schedule "send mail at scan completion" (off avoids emailing all admins with view access) |
| `QUALYS_SCAN_SENDMAIL` | `false` | The immediate scan's completion email |
| `QUALYS_SCHEDULE_RECIPIENTS` | *(edit for your org)* | Additional recipient(s) for the schedule's pre-scan notification |
| `QUALYS_NOTIFICATION_MESSAGE` | *(edit for your org)* | Custom pre-scan notification message |
| `QUALYS_ENSURE_TAGS` | `prod,webapp` | Tags applied to a newly bootstrapped **root domain** app, which has no parent to inherit from. Subdomains always inherit the root's tags instead. Tags must already exist in Qualys |
| `QUALYS_IGNORE_HOSTS` | *(empty)* | Comma-separated hosts/patterns to skip (merged with `qualys_exclude.txt`) |
| `QUALYS_IGNORE_FILE` | *(empty)* | Path override for the exclude file |
| `QUALYS_NOTIFY_EMAIL` | *(edit for your org)* | Recipient of AutoEASM's own launched-scans summary email |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` / `SMTP_FROM` / `SMTP_TLS` | *(empty / 587 / on)* | SMTP server for the summary email (if unset, the summary is only printed) |

> **Distribution groups** exist only in the newer WAS REST 1.0 API on the portal host (`QUALYS_WEBUI_URL`). AutoEASM creates the schedule via the QPS 3.0 API, then attaches the group through that API with the same Basic-auth credentials. If the portal rejects Basic auth, the schedule is still created (without the group).

### Excluding hosts

Create a **`qualys_exclude.txt`** file next to `main.py` — copy the included **`qualys_exclude.txt.example`** — with one host or `fnmatch` wildcard per line. Matching domains/subdomains are never created, scheduled, or scanned in Qualys. It is **auto-detected**, no flag needed; blank lines and `#` comments are ignored, matching is case-insensitive. (`qualys_exclude.txt` itself is git-ignored so your internal hostnames stay local.)

```
dev.example.com
*.staging.example.com
test-*
```

### Testing without a full scan

`qualys_sync_test.py` runs only the Qualys sync against hosts you supply, skipping the discovery pipeline. Use `--dry-run` first (read-only — resolves and prints intended actions, mutates nothing):

```
python qualys_sync_test.py -d example.com --assets https://example.com,https://api.example.com --dry-run -v
```

`-d` sets the parent/root domains (for parent resolution and copy-from-parent); `--assets` / `--assets-file` is the list of live web services to sync. `--ignore` / `--ignore-file` add exclusions, and `--newapi-get <schedule_id>` dumps a schedule from the portal API for troubleshooting.

## SecurityTrails historical IP checks

If a **PAID** SecurityTrails API key is available in the `SecurityTrails_API_key` environment variable, AutoEASM uses historical DNS (A record) data to look for the real IPs behind the current infrastructure. It runs automatically only if the key is present. If all correct, you will see the `[+] Found SecurityTrails API key...` message in console on the first line.

Two checks are performed (one SecurityTrails query per host), and results are added to the existing **Host header manipulation** report tab:

- **Origin behind WAF** — for every subdomain that has a WAF, each historical IP is probed with a `Host: <subdomain>` header. If an IP answers like the real site and is **not** itself behind a WAF, it is reported under **WAF bypass** as a likely origin server hidden behind the firewall.
- **Access to inactive hosts** — for every subdomain that no longer responds, each historical IP is probed with a `Host: <subdomain>` header. If a server answers (using the same response checks as the regular inactive-hosts scan), it is reported under **Access to inactive hosts** as external access to an internal/decommissioned web application.

## Useful notes

- You can press Ctrl+C to skip the current stage of scanning (all results obtained so far will be saved). Quickly press Ctrl+C again to finish the program completely. The first stage cannot be skipped.
- Based on the logic of checking host header manipulation vulnerabilities, it would be better to send all domains of the same business to one scan (one business - one scan).
- If you think that the report does not contain the results of some utilities, review the outputs of the utilities in the Logs folder. In this folder, you can also view the real-time output of the utilities. These subdirectories are never deleted automatically, so remove old ones manually if they take up too much space.
- You can use multiple -d arguments to scan multiple domains (-d site1.com -d site2.com -d site3.com).
- `-bb` flag with enabled Burp Suite is very useful for quick investigating host header manipulation findings.
