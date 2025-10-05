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
| feroxbuster | [feroxbuster: A fast, simple, recursive content discovery tool written in Rust.](https://github.com/epi052/feroxbuster)                                                                                                                                                                                                                                                   | **Feroxbuster** is an open-source web fuzzing tool. Has convenient functions for automatic adjustment of scanning speed and filters.                                                                                                                                 |
| uro       | [uro: declutters url lists for crawling/pentesting](https://github.com/s0md3v/uro)                                                                                                                                                                                                                                                                                          | **Uro** is designed to simplify handling URL lists for security testing, which can be cumbersome due to uninteresting or duplicate content.                                                                                                                          |
| byp4xx    | [byp4xx: 40X/HTTP bypasser in Go. Features: Verb tampering, headers, #bugbountytips, User-Agents, extensions, default credentials...](https://github.com/lobuhi/byp4xx)                                                                                                                                                                                                     | **byp4xx** is a 40X bypasser in Go. Methods from #bugbountytips, headers, verb tampering, user agents and more.                                                                                                                                                      |
| LeakiX    | [LeakiX](https://leakix.net/ "https://leakix.net/")                                                                                                                                                                                                                                                                                                                         | **LeakiX** is a cybersecurity company that specializes in providing businesses with comprehensive visibility into their internet-facing assets. It provides tools and analysis to detect vulnerabilities in systems and networks.                                    |
| Postleaks | [postleaks: Search for sensitive data in Postman public library.](https://github.com/cosad3s/postleaks)                                                                                                                                                                                                                                                                     | **Postleaks** script is aimed at searching for confidential information in the Postman public library.                                                                                                                                                               |


&nbsp;


![Flowchart](https://github.com/user-attachments/assets/9970b075-78d9-4a50-949c-82f63d7d5fb1)
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

## Useful notes

- Please remember that if you do not save or rename an old report - it will be overwritten.
- You can press Ctrl+C to skip the current stage of scanning (all results obtained so far will be saved). Quickly press Ctrl+C again to finish the program completely. The first stage cannot be skipped.
- Based on the logic of checking host header manipulation vulnerabilities, it would be better to send all domains of the same business to one scan (one business - one scan).
- If you think that the report does not contain the results of some utilities, review the outputs of the utilities in the Logs folder. Note that only the results of the last scan are stored there. Also in this folder, you can view the real-time output of the utilities.
- You can use multiple -d arguments to scan multiple domains (-d site1.com -d site2.com -d site3.com).
- `-bb` flag with enabled Burp Suite is very useful for investigating host header manipulation findings.
- Do not run the utility several times at the same time from the same directory!
