## Description

**EASM** (External Attack Surface Management) **automated tool** allows a quick scan of all domains and subdomains of any company with the help of different utilities and gets a list of important issues for verification. This automation allows the automatic testing of domains regularly with limited resources of the security team.

## Used utilities

| **Name**  | **Link**                                                                                                                                                                                                                                                                                                                                                                    | **Description**                                                                                                                                                                                                                                                      |
| --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| subfinder | [subfinder: Fast passive subdomain enumeration tool.](https://github.com/projectdiscovery/subfinder)                                                                                                                                                                                                                                                                        | **Subfinder** is a subdomain discovery tool that returns valid subdomains for websites, using passive online sources. It has a simple, modular architecture and is optimized for speed.                                                                              |
| dnsx      | [dnsx: dnsx is a fast and multi-purpose DNS toolkit allow to run multiple DNS queries of your choice with a list of user-supplied resolvers.](https://github.com/projectdiscovery/dnsx)                                                                                                                                                                                     | **Dnsx** is a fast and multi-purpose DNS toolkit designed for running various probes. It supports multiple DNS queries, user supplied resolvers and DNS wildcard filtering.                                                                                          |
| naabu     | [naabu: A fast port scanner written in go with a focus on reliability and simplicity. Designed to be used in combination with other tools for attack surface discovery in bug bounties and pentests](https://github.com/projectdiscovery/naabu)                                                                                                                             | **Naabu** is a port scanning tool written in Go that allows you to enumerate valid ports for hosts in a fast and reliable manner. It is a really simple tool that does fast SYN/CONNECT/UDP scans on the host/list of hosts and lists all ports that return a reply. |
| httpx     | [httpx: httpx is a fast and multi-purpose HTTP toolkit that allows running multiple probes using the retryablehttp library.](https://github.com/projectdiscovery/httpx)                                                                                                                                                                                                     | **HTTPX** is a fast and multi-purpose HTTP toolkit that allows running multiple probes using the retryablehttp library. It is designed to maintain result reliability with an increased number of threads.                                                           |
| nuclei    | [nuclei: Nuclei is a fast, customizable vulnerability scanner powered by the global security community and built on a simple YAML-based DSL, enabling collaboration to tackle trending vulnerabilities on the internet. It helps you find vulnerabilities in your applications, APIs, networks, DNS, and cloud configurations.](https://github.com/projectdiscovery/nuclei) | **Nuclei** is a fast and customisable vulnerability scanner based on simple YAML based DSL.                                                                                                                                                                          |
| katana    | [katana: A next-generation crawling and spidering framework.](https://github.com/projectdiscovery/katana)                                                                                                                                                                                                                                                                   | **Katana** is a next-generation crawling and spidering framework.                                                                                                                                                                                                    |
| ffuf      | [ffuf: Fast web fuzzer written in Go](https://github.com/ffuf/ffuf)                                                                                                                                                                                                                                                                                                         | **Ffuf** is an open-source web fuzzing tool.                                                                                                                                                                                                                         |
| uro       | [uro: declutters url lists for crawling/pentesting](https://github.com/s0md3v/uro)                                                                                                                                                                                                                                                                                          | **Uro** is designed to simplify handling URL lists for security testing, which can be cumbersome due to uninteresting or duplicate content.                                                                                                                          |
| LeakiX    | [LeakiX](https://leakix.net/ "https://leakix.net/")                                                                                                                                                                                                                                                                                                                         | **LeakiX** is a cybersecurity company that specializes in providing businesses with comprehensive visibility into their internet-facing assets. It provides tools and analysis to detect vulnerabilities in systems and networks.                                    |
| Postleaks | [postleaks: Search for sensitive data in Postman public library.](https://github.com/cosad3s/postleaks)                                                                                                                                                                                                                                                                     | **Postleaks** script is aimed at searching for confidential information in the Postman public library.                                                                                                                                                               |


&nbsp;


![Flowchart](https://github.com/user-attachments/assets/8de9bd13-b6bf-4dd1-8272-5b9462182f62)
&nbsp;

## Installation

1. Install Python and Go on your PC (it can be both Windows or Linux).

2. Install dependencies using the following commands:
```
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
pip install requests
pip install postleaks
pip install uro
```

3. For **Linux** also the following commands are required:
```
sudo apt install -y feroxbuster
cd EASM-automate/ ; chmod +x Scan/byp4xx.go
```
For **Windows** no additional commands are required.

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

## Notes

- Please remember that if you do not save or rename an old report - it will be overwritten.
- You can press Ctrl+C to skip the current stage of scanning (all results obtained so far will be saved). Quickly press Ctrl+C again to finish the program completely. The first stage cannot be skipped.
- If you think that the report does not contain the results of some utilities, review the outputs of the utilities in the Logs folder. Note that only the results of the last scan are stored there. Also in this folder, you can view the real-time output of the utilities.
- You can use multiple -d arguments to scan multiple domains (-d site1.com -d site2.com -d site3.com).
- Do not run the utility several times at the same time from the same directory!
