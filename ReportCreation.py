from Global import Domains, HTTPAssets, Flags, AssetsWithWAF, NucleiFindings, NotExistingSocialLinks,\
    NucleiConfigFindings, FuzzedDirectories, NucleiTokensFindings, NucleiDASTFindings, NucleiTakeoverFindings, LeakixFindings
import Global
from datetime import datetime
from Scan.LeakixInfo import Leakix_info
import webbrowser
import os
from html import escape
from Scan.Helpers import replace_last_colon


def CreateReport(report_name="Report"):
    print("[*] Report creation...")
    prepath = "/app/output/" if "--docker" in Flags else ""
    ReportFile = open(prepath+report_name+".html", "w", encoding="utf-8")
    ReportFile.write(get_report_start())
    ReportFile.write(get_report_content())
    ReportFile.write(get_report_end())
    ReportFile.close()
    print(f"[+] Report has been generated! File name is {report_name+'.html'}")
    if "--docker" not in Flags:
        print("[N] Note: if you think that some findings may be missing in the report, check Logs directory")
    if "-do" not in Flags and "--docker" not in Flags:
        file_path = os.path.abspath(report_name+".html")
        webbrowser.open(f"file://{file_path}")


def get_report_start():
    return """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>AutoEASM Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: Arial, sans-serif;
            display: flex;
            min-height: 100vh;
        }
        .sidebar {
            position: fixed;
            top: 0;
            left: 0;
            width: 215px;
            height: 100%;
            background-color: #f4f4f4;
            border-right: 1px solid #ccc;
            overflow-x: hidden;
            padding-top: 20px;
        }
        .sidebar button {
            display: block;
            width: 100%;
            padding: 15px;
            border: none;
            background: none;
            text-align: left;
            cursor: pointer;
            outline: none;
            transition: background 0.3s;
            font-size: 16px;
        }
        .sidebar button:hover {
            background-color: #ddd;
        }
        .sidebar button.active {
            background-color: #ccc;
        }
        .content {
            margin-left: 215px;
            padding: 20px;
            flex: 1;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        .tab-content p {
            margin-bottom: 10px;
            line-height: 1.6;
        }
    </style>
</head>
<body>

    <div class="sidebar">
        <button class="tablink active" onclick="openTab(event, 'Overview')">General information</button>
        <button class="tablink" onclick="openTab(event, 'FoundNetworkAssets')">Found network services</button>
        <button class="tablink" onclick="openTab(event, 'FoundHTTPAssets')">Found websites</button>
        <button class="tablink" onclick="openTab(event, 'SecurityFindings')">Security findings</button>
        <button class="tablink" onclick="openTab(event, 'Fuzzed')">Interesting directories</button>
        <button class="tablink" onclick="openTab(event, 'Bypass403')">403 bypass</button>
        <button class="tablink" onclick="openTab(event, 'HostManipulation')">Host header manipulation</button>
        <button class="tablink" onclick="openTab(event, 'SocialMedia')">Social media takeover</button>
        <button class="tablink" onclick="openTab(event, 'Postleaks')">Postman leaks</button>
        <button class="tablink" onclick="openTab(event, 'Leakix')">Leakix results</button>
    </div>

    <div class="content">\n"""


def get_report_end():
    return """\n    </div>

    <script>
        function openTab(evt, tabName) {
            // Скрыть все содержимое вкладок
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tab-content");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].classList.remove("active");
            }
            // Убрать активный класс со всех кнопок
            tablinks = document.getElementsByClassName("tablink");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].classList.remove("active");
            }
            // Показать текущую вкладку и добавить активный класс к кнопке
            document.getElementById(tabName).classList.add("active");
            evt.currentTarget.classList.add("active");
        }
    </script>

</body>
</html>"""


def get_report_content():
    def overview():
        html_overview = """\n<div id="Overview" class="tab-content active">\n<h2>General information</h2><br>\n<p>"""
        html_overview += f"<b>Scanned domains:</b> {', '.join(Domains)}<br>\n"
        html_overview += f"<b>Generated on:</b> {datetime.now().strftime('%a, %d %b %Y, %H:%M:%S')}<br>\n"
        html_overview += f"<b>Level of detail:</b> {Global.DetailsLevel}<br>\n"
        html_overview += f"<b>Load level:</b> {Global.LoadLevel}<br>\n"
        if Global.ExcludedHosts:
            html_overview += f"<b>Excluded subdomains:</b> {'; '.join(Global.ExcludedHosts[::3])}<br>\n"
        if Flags:
            html_overview += f"<b>Flags:</b> {' '.join(Flags)}"
        html_overview += "</p>\n</div>\n"
        return html_overview

    def found_services():
        network_assets = """\n\n<div id="FoundNetworkAssets" class="tab-content">\n<h2>Found network services</h2>\n<p>\n"""
        for service in Global.Services:
            network_assets += f"<br> <a href=\"{service}\">{service}</a>\n"  # <a href="http://site.com">http://site.com</a>
        network_assets += "</p>\n</div>"
        return network_assets


    def found_assets():
        html_assets = """\n\n<div id="FoundHTTPAssets" class="tab-content">\n<h2>Found websites</h2>\n<br>\n"""

        if Global.AssetsWithWAF and Global.HTTPAssets:
            html_assets += "<h3>Without firewall</h3>"
        html_assets += "<p>\n"
        for link in Global.HTTPAssets:
            html_assets += f"<a href=\"{link}\">{link}</a> <br>\n"  # <a href="http://site.com">http://site.com</a>
        html_assets += "</p>"

        if Global.AssetsWithWAF:
            html_assets += "<h3>With firewall</h3>"
            html_assets += "<p>\n"
            for link in Global.AssetsWithWAF:
                html_assets += f"<a href=\"{link}\">{link}</a> - {Global.AssetsWithWAF[link]} <br>\n"  # <a href="http://site.com">http://site.com</a>
            html_assets += "</p>"

        html_assets += "\n</div>"

        return html_assets

    def nuclei_findings():
        findings_text = """\n\n<div id="SecurityFindings" class="tab-content">\n<h1>Nuclei Security Findings</h1><br>\n
        <h2>Main findings</h2><br>\n"""
        count = 0
        for severity in NucleiFindings:
            if NucleiFindings[severity]:
                findings_text += f"<h3>Issues with {severity} severity</h3><br>\n<p>\n"
                for finding in NucleiFindings[severity]:
                    findings_text += f"{escape(finding)} <br>\n"
                    count += 1
                findings_text += "</p>\n"
        if count == 0:
            findings_text += "No findings this time :( <br>\n"

        findings_text += "<br><br><h2>Config findings</h2><br>\n"
        count = 0
        for severity in NucleiConfigFindings:
            if NucleiConfigFindings[severity]:
                findings_text += f"<h3>Issues with {severity} severity</h3><br>\n<p>\n"
                for finding in NucleiConfigFindings[severity]:
                    findings_text += f"{escape(finding)} <br>\n"
                    count += 1
                findings_text += "</p>\n"
        if count == 0:
            findings_text += "No findings this time :( <br>\n"

        findings_text += "<br><br><h2>DAST scanning findings</h2><br>\n"
        count = 0
        for severity in NucleiDASTFindings:
            if NucleiDASTFindings[severity]:
                findings_text += f"<h3>Issues with {severity} severity</h3><br>\n<p>\n"
                for finding in NucleiDASTFindings[severity]:
                    findings_text += f"{escape(finding)} <br>\n"
                    count += 1
                findings_text += "</p>\n"
        if count == 0:
            findings_text += "No findings this time :( <br>\n"

        findings_text += "<br><br><h2>Leaked tokens findings</h2><br>\n"
        count = 0
        for severity in NucleiTokensFindings:
            if NucleiTokensFindings[severity]:
                findings_text += f"<h3>Issues with {severity} severity</h3><br>\n<p>\n"
                for finding in NucleiTokensFindings[severity]:
                    findings_text += f"{escape(finding)} <br>\n"
                    count += 1
                findings_text += "</p>\n"
        if count == 0:
            findings_text += "No findings this time :( <br>\n"

        findings_text += "<br><br><h2>Subdomain takeover findings</h2><br>\n"
        count = 0
        for severity in NucleiTakeoverFindings:
            if NucleiTakeoverFindings[severity]:
                findings_text += f"<h3>Issues with {severity} severity</h3><br>\n<p>\n"
                for finding in NucleiTakeoverFindings[severity]:
                    findings_text += f"{escape(finding)} <br>\n"
                    count += 1
                findings_text += "</p>\n"
        if count == 0:
            findings_text += "No findings this time :( <br>\n"

        findings_text += "</div>"
        return findings_text

    def fuzzing_results():
        fuzzing_text = """\n\n<div id="Fuzzed" class="tab-content">\n<h2>Fuzzed files and directories</h2><br>\n"""
        count = 0
        for HTTP_code in FuzzedDirectories:
            if FuzzedDirectories[HTTP_code]:
                fuzzing_text += f"<br><h3>Endpoints with {HTTP_code} code</h3><br>\n<p>\n"
                for endpoint in FuzzedDirectories[HTTP_code]:
                    fuzzing_text += f"<a href=\"{endpoint}\">{endpoint}</a><br>\n"
                    count += 1
                fuzzing_text += "</p>\n"
        if count == 0:
            fuzzing_text += "No fuzzing results this time :("
        fuzzing_text += "</div>"
        return fuzzing_text

    def bypass403_results():
        bypass_text = """\n\n<div id="Bypass403" class="tab-content">\n<h2>403 and 401 codes bypass results</h2><br>\n"""
        if Global.Byp4xxResult:
            bypass_text += "<i>Please note that 403 bypass tools often gives false positives.</i><br>\n"
            if not Global.Details[Global.DetailsLevel]['CheckAll403links']:
                bypass_text += "<b>Only 1 link was analyzed for each host. If a successful bypass was found, manually "\
                               "check other 403/401 links on this domain.</b><br><br>\n"
            else:
                bypass_text += "<br>\n"
            bypass_text += replace_last_colon(Global.Byp4xxResult)
        else:
            bypass_text += "No bypasses this time."
        bypass_text += "</div>"
        return bypass_text

    def host_manipulation():  # Get WAF bypass and inactive hosts access
        def get_host_result(hosts_pair):
            scan_commands = f"nuclei -u {hosts_pair[1]} -header Host:{hosts_pair[0]} -s {Global.Details[Global.DetailsLevel]['NucleiConfigCritical']} " \
                            f"-rl {Global.Threads[Global.LoadLevel]['NucleiRate']} -c {Global.Threads[Global.LoadLevel]['NucleiParallels']}\n" \
                            f"katana -u {hosts_pair[1]} -headers Host:{hosts_pair[0]} -ef css,json,png,jpg,jpeg,woff2 -silent -nc -s breadth-first -fs fqdn" \
                            f" {Global.Details[Global.DetailsLevel]['KatanaAdditionalFlags']} -p {Global.Threads[Global.LoadLevel]['KatanaParallels']}" \
                            f" | nuclei -header Host:{hosts_pair[0]} -dast -etags backup -s {Global.Details[Global.DetailsLevel]['NucleiCritical']} -rl " \
                            f"{Global.Threads[Global.LoadLevel]['NucleiRate']} -c {Global.Threads[Global.LoadLevel]['NucleiParallels']}\n" \
                            f"feroxbuster -H Host:{hosts_pair[0]} -u {hosts_pair[1]} -w Scan/fuzz.txt --insecure --auto-tune --no-recursion --redirects " \
                            f"-t {(Global.Threads[Global.LoadLevel]['FeroxbusterThreads']*Global.Threads[Global.LoadLevel]['FeroxbusterParallels'])//2} " \
                            f"--dont-extract-links -C 404 500 --time-limit {Global.Threads[Global.LoadLevel]['FeroxbusterTimeLimit']}\n"
            return f"<details><summary>Try using host header <b>{hosts_pair[0]}</b> on {hosts_pair[1]}</summary>" \
                   f"<br><pre>{scan_commands}</pre></details><br><br>\n"

        host_manipulation_text = """\n\n<div id="HostManipulation" class="tab-content">\n<h1>Host header manipulation</h1><br>\n"""
        host_manipulation_text += "<br><h2>WAF bypass</h2><br>\n"
        if Global.WAFBypassHosts:
            for hosts_pair in Global.WAFBypassHosts:
                host_manipulation_text += get_host_result(hosts_pair)
        else:
            if Global.AssetsWithWAF:
                host_manipulation_text += "No successful WAF bypass attempts this time."
            else:
                host_manipulation_text += "No hosts with WAF found."
        host_manipulation_text += "<br><br><h2>Access to inactive hosts</h2><br>\n"
        if Global.InactiveHostsAccess:
            for hosts_pair in Global.InactiveHostsAccess:
                host_manipulation_text += get_host_result(hosts_pair)
        else:
            host_manipulation_text += "No successful inactive hosts access attempts this time."
        host_manipulation_text += "</div>"
        return host_manipulation_text

    def social_media_bypass():
        social_media_text = """\n\n<div id="SocialMedia" class="tab-content">\n<h2>Inactive social media links</h2><br>\n"""
        if Global.NotExistingSocialLinks:
            for finding in NotExistingSocialLinks:
                social_media_text += f'Inactive <a href=\"{finding[1]}\">{finding[1]}</a> link on the <a href=\"{finding[0]}\">{finding[0]}</a> page.<br><br>\n'
        else:
            social_media_text += "No social media links takeover possibilities this time."
        social_media_text += "</div>"
        return social_media_text

    def postleaks_results():
        postleaks_text = """\n\n<div id="Postleaks" class="tab-content">\n<h2>Postman leaks</h2><br>\n"""
        if Global.PostleaksResult:
            postleaks_text += Global.PostleaksResult
        else:
            postleaks_text += "No Postman leaks this time."
        postleaks_text += "</div>"
        return postleaks_text

    def leakix_results():
        leakix_text = """\n\n<div id="Leakix" class="tab-content">\n<h2>Leakix results</h2><br>\n"""
        if LeakixFindings:
            for finding in LeakixFindings:
                if finding.event_source in Leakix_info:
                    leakix_text += f"<details><summary><b>{Leakix_info[finding.event_source][1]}</b> on <a href=\"{finding.url}\">{finding.url}</a>"
                    if finding.severity:
                        leakix_text += f" <i>(<b>{finding.severity}</b> severity)</i>"
                    elif Leakix_info[finding.event_source][0]:
                        leakix_text += f" (<b>{Leakix_info[finding.event_source][0]}</b> severity)"
                    leakix_text += f".  <a href=\"https://leakix.net/domain/{finding.host}\">More info here</a></summary>"
                    leakix_text += f"<br><pre>{escape(Leakix_info[finding.event_source][2])}</pre>"
                    leakix_text += "</details><br><br>\n"
                else:
                    leakix_text += f"<b>{finding.event_source}:</b> on <a href=\"{finding.url}\">{finding.url}</a>"
                    if finding.severity:
                        leakix_text += f" <i>(<b>{finding.severity}</b> severity)</i>"
                    leakix_text += f". <a href=\"https://leakix.net/domain/{finding.host}\">More info here</a>"
                    leakix_text += "<br><br><br>\n"
        else:
            leakix_text += "No Leakix results this time."
        leakix_text += "</div>"
        return leakix_text

    return overview() + found_services() + found_assets() + nuclei_findings() + fuzzing_results() + bypass403_results()\
        + host_manipulation() + social_media_bypass() + postleaks_results() + leakix_results()
