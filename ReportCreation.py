from Global import Domains, HTTPAssets, Flags, AssetsWithWAF, NucleiFindings, NotExistingSocialMediaLinks,\
    NucleiConfigFindings, FuzzedDirectories, NucleiTokensFindings, NucleiDASTFindings, NucleiTakeoverFindings, LeakixFindings
import Global
from datetime import datetime
from Scan.LeakixInfo import Leakix_info
import webbrowser
import os
from html import escape
from Scan.Helpers import replace_last_colon


def get_unique_report_name(prepath, base_name):
    if not os.path.exists(prepath + base_name + ".html"):
        return base_name
    counter = 2
    while os.path.exists(f"{prepath}{base_name}-{counter}.html"):
        counter += 1
    return f"{base_name}-{counter}"


def get_host_scan_commands(hosts_pair):  # Suggested manual scan commands for a (host_header, target) pair
    return f"nuclei -u {hosts_pair[1]} -header Host:{hosts_pair[0]} -s {Global.Details[Global.DetailsLevel]['NucleiConfigCritical']} " \
           f"-rl {Global.Threads[Global.LoadLevel]['NucleiRate']} -c {Global.Threads[Global.LoadLevel]['NucleiParallels']}\n" \
           f"katana -u {hosts_pair[1]} -headers Host:{hosts_pair[0]} -ef css,png,jpg,jpeg,woff2 -silent -nc -s breadth-first -fs fqdn" \
           f" {Global.Details[Global.DetailsLevel]['KatanaAdditionalFlags']} -p {Global.Threads[Global.LoadLevel]['KatanaParallels']}" \
           f" | nuclei -header Host:{hosts_pair[0]} -dast -etags backup -s {Global.Details[Global.DetailsLevel]['NucleiCritical']} -rl " \
           f"{Global.Threads[Global.LoadLevel]['NucleiRate']} -c {Global.Threads[Global.LoadLevel]['NucleiParallels']}\n" \
           f"feroxbuster -H Host:{hosts_pair[0]} -u {hosts_pair[1]} -w Scan/resources/fuzz.txt --insecure --auto-tune --no-recursion --redirects " \
           f"-t {(Global.Threads[Global.LoadLevel]['FeroxbusterThreads']*Global.Threads[Global.LoadLevel]['FeroxbusterParallels'])//2} " \
           f"--dont-extract-links -C 404 500 --time-limit {Global.Threads[Global.LoadLevel]['FeroxbusterTimeLimit']}\n"


def CreateReport(report_name="Report", auto_increment=False):
    print("[*] Report creation...")
    prepath = "/app/output/" if "--docker" in Flags else ""
    if auto_increment:
        report_name = get_unique_report_name(prepath, report_name)
    with open(prepath + report_name + ".html", "w", encoding="utf-8") as report_file:
        report_file.write(get_report_start())
        report_file.write(get_report_content())
        report_file.write(get_report_end())
    print(f"[+] Report has been generated! File name is {report_name+'.html'}")
    if "-md" in Flags:
        with open(prepath + report_name + ".md", "w", encoding="utf-8") as md_file:
            md_file.write(get_md_report_content())
        print(f"[+] Markdown report has been generated! File name is {report_name+'.md'}")
    if "--docker" not in Flags:
        print(f"[N] Note: if you think that some findings may be missing in the report, check the {Global.RunDir} directory")
    if "-do" not in Flags and "--docker" not in Flags:
        file_path = os.path.abspath(report_name+".html")
        webbrowser.open(f"file://{file_path}")


def get_report_start():
    report_start = """<!DOCTYPE html>
<html lang="en">
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
        table.dep-cves {
            border-collapse: collapse;
            width: 100%;
            margin: 8px 0 16px 0;
        }
        table.dep-cves th, table.dep-cves td {
            border: 1px solid #ccc;
            padding: 8px;
            text-align: left;
            vertical-align: top;
            font-size: 14px;
        }
        table.dep-cves th {
            background-color: #f4f4f4;
        }
        table.dep-cves th.sortable {
            cursor: pointer;
            user-select: none;
            white-space: nowrap;
        }
        table.dep-cves th.sortable:hover {
            background-color: #e8e8e8;
        }
        table.dep-cves th.sorted::after {
            content: " ▲";
            font-size: 11px;
        }
        table.dep-cves th.sorted.desc::after {
            content: " ▼";
        }
        table.dep-cves td.url {
            word-break: break-all;
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
        <button class="tablink" onclick="openTab(event, 'DependencyCheck')">Dependency check</button>
        <button class="tablink" onclick="openTab(event, 'SocialMedia')">Social media takeover</button>
        <button class="tablink" onclick="openTab(event, 'Postleaks')">Postman leaks</button>
        <button class="tablink" onclick="openTab(event, 'Leakix')">Leakix results</button>
"""
    if '-q' in Flags:
        report_start += """        <button class="tablink" onclick="openTab(event, 'QualysWAS')">Qualys WAS</button>\n"""
    report_start += """    </div>

    <div class="content">\n"""
    return report_start


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
        function sortDepCves(th, col, mode) {
            var table = th.closest("table");
            var headers = table.getElementsByTagName("th");
            var rows = Array.prototype.slice.call(table.getElementsByTagName("tr"), 1);
            var rank = {critical: 0, high: 1, medium: 2, low: 3, unknown: 4};
            var dir = th.getAttribute("data-dir") === "asc" ? -1 : 1;
            for (var i = 0; i < headers.length; i++) {
                headers[i].removeAttribute("data-dir");
                headers[i].classList.remove("sorted", "desc");
            }
            th.setAttribute("data-dir", dir === 1 ? "asc" : "desc");
            th.classList.add("sorted");
            if (dir === -1) {
                th.classList.add("desc");
            }
            rows.sort(function(a, b) {
                var av = a.cells[col].innerText.trim().toLowerCase();
                var bv = b.cells[col].innerText.trim().toLowerCase();
                var cmp;
                if (mode === "severity") {
                    cmp = (rank[av] != null ? rank[av] : 9) - (rank[bv] != null ? rank[bv] : 9);
                } else {
                    cmp = av.localeCompare(bv);
                }
                return cmp * dir;
            });
            for (var j = 0; j < rows.length; j++) {
                table.appendChild(rows[j]);
            }
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
            html_overview += f"<b>Flags:</b> {' '.join(Flags)}<br>\n"
        for note in Global.GeneralInfoNotes:
            html_overview += f"<br>{escape(note)}\n"
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

    def dependency_check():
        text = """\n\n<div id="DependencyCheck" class="tab-content">\n<h1>Dependency check</h1><br>\n"""
        unclaimed = [f for f in Global.DepConfusionFindings if not f["scoped"]]
        scoped = [f for f in Global.DepConfusionFindings if f["scoped"]]
        text += "<h2>Unclaimed packages</h2><br>\n"
        if unclaimed:
            text += "<p>\n"
            for finding in unclaimed:
                text += f'{escape(finding["package"])} — <a href="{escape(finding["url"])}">{escape(finding["url"])}</a><br>\n'
            text += "</p>\n"
        else:
            text += "No unclaimed package names this time.<br>\n"

        text += "<br><h2>Scoped packages</h2><br>\n"
        if scoped:
            text += "<i>These names were not found on the public registry. Whether the npm scope itself is already claimed cannot be determined automatically and requires manual verification.</i><br><br>\n"
            text += "<p>\n"
            for finding in scoped:
                text += f'{escape(finding["package"])} — <a href="{escape(finding["url"])}">{escape(finding["url"])}</a><br>\n'
            text += "</p>\n"
        else:
            text += "No scoped package names this time.<br>\n"

        text += "<br><h2>Known vulnerabilities</h2><br>\n"
        if Global.DepCveFindings:
            text += "<i>Click the Severity, Package or File column header to sort the table by that field. " \
                    "Click the same header again to reverse the order.</i><br><br>\n"
            text += "<table class=\"dep-cves\">\n<tr>" \
                    "<th class=\"sortable sorted\" data-dir=\"asc\" onclick=\"sortDepCves(this, 0, 'severity')\">Severity</th>" \
                    "<th class=\"sortable\" onclick=\"sortDepCves(this, 1)\">Package</th>" \
                    "<th>Version</th><th>ID</th><th>Summary</th>" \
                    "<th class=\"sortable\" onclick=\"sortDepCves(this, 5)\">File</th></tr>\n"
            for severity in ("critical", "high", "medium", "low", "unknown"):
                for finding in [f for f in Global.DepCveFindings if f["severity"] == severity]:
                    text += (
                        f'<tr><td>{escape(finding["severity"])}</td>'
                        f'<td>{escape(finding["package"])}</td>'
                        f'<td>{escape(finding["version"])}</td>'
                        f'<td>{escape(finding["vuln_id"])}</td>'
                        f'<td>{escape(finding["summary"])}</td>'
                        f'<td class="url"><a href="{escape(finding["url"])}">{escape(finding["url"])}</a></td></tr>\n'
                    )
            text += "</table>\n"
        else:
            text += "No known vulnerabilities this time.<br>\n"

        text += "<br><h2>Exposed dependency files</h2><br>\n"
        if Global.DepExposedFiles:
            text += "<p>\n"
            for url in Global.DepExposedFiles:
                text += f'<a href="{escape(url)}">{escape(url)}</a><br>\n'
            text += "</p>\n"
        else:
            text += "No dependency files were found.<br>\n"
        text += "</div>"
        return text

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
            byp4xx_html = ""
            for host_strings in Global.Byp4xxResult:
                byp4xx_html += f"<b>{host_strings[0]}</b><br>\n"
                for host_string in host_strings[1:]:
                    byp4xx_html += host_string + "<br>\n"
                byp4xx_html += "<br><br>\n"
            bypass_text += replace_last_colon(byp4xx_html)
        else:
            bypass_text += "No bypasses this time."
        bypass_text += "</div>"
        return bypass_text

    def host_manipulation():  # Get WAF bypass and inactive hosts access
        def get_host_result(hosts_pair):
            return f"<details><summary>Try using host header <b>{hosts_pair[0]}</b> on {hosts_pair[1]} " \
                   f"(<b>{hosts_pair[2]}</b> status code)</summary>" \
                   f"<br><pre>{get_host_scan_commands(hosts_pair)}</pre></details><br><br>\n"

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
        if Global.NotExistingSocialMediaLinks:
            for finding in NotExistingSocialMediaLinks:
                social_media_text += f'Inactive <a href=\"{finding[1]}\">{finding[1]}</a> link on the <a href=\"{finding[0]}\">{finding[0]}</a> page.<br><br>\n'
        else:
            social_media_text += "No social media links takeover possibilities this time."
        social_media_text += "</div>"
        return social_media_text

    def postleaks_results():
        postleaks_text = """\n\n<div id="Postleaks" class="tab-content">\n<h2>Postman leaks</h2><br>\n"""
        if Global.PostleaksResult:
            for keyword, lines in Global.PostleaksResult.items():
                postleaks_text += f'<h3>{keyword} results</h3>\n' \
                                  f'<a href=\"https://www.postman.com/search?q={keyword}&scope=all&type=all\">Postman collection search link</a><br>\n'
                for line in lines:
                    if line.startswith(" >"):
                        postleaks_text += f"<b>{escape(line)}</b> <br>\n"
                    else:
                        if line.startswith("[+"):
                            postleaks_text += "<br>\n"
                        postleaks_text += escape(line) + " <br>\n"
                postleaks_text += "\n<br><br><br>\n"
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

    def qualys_results():
        qualys_text = """\n\n<div id="QualysWAS" class="tab-content">\n<h2>Qualys WAS sync</h2><br>\n"""
        if Global.QualysWASResults:
            for r in Global.QualysWASResults:
                line = f"<b>{escape(r.action)}</b>: {escape(r.host)}"
                if r.parent and r.parent != r.host:
                    line += f" (parent: {escape(r.parent)})"
                details = []
                if r.webapp_id:
                    details.append(f"web app id: {escape(r.webapp_id)}")
                if r.scan_id:
                    details.append(f"scan id: {escape(r.scan_id)}")
                if details:
                    line += " - " + ", ".join(details)
                if r.message:
                    line += f" - {escape(r.message)}"
                qualys_text += line + "<br>\n"
        else:
            qualys_text += "No Qualys WAS sync results this time - the sync was interrupted (Ctrl+C) or crashed "\
                           "before it processed anything. Check the console output for details."
        qualys_text += "</div>"
        return qualys_text

    report_content = overview() + found_services() + found_assets() + nuclei_findings() + fuzzing_results()\
        + bypass403_results() + host_manipulation() + dependency_check() + social_media_bypass() + postleaks_results() + leakix_results()
    if '-q' in Flags:
        report_content += qualys_results()
    return report_content


def get_md_report_content():  # Markdown counterpart of get_report_content(). Raw tool output goes into code fences to avoid Markdown mangling
    def overview():
        md = "# AutoEASM Report\n\n## General information\n\n"
        md += f"- **Scanned domains:** {', '.join(Domains)}\n"
        md += f"- **Generated on:** {datetime.now().strftime('%a, %d %b %Y, %H:%M:%S')}\n"
        md += f"- **Level of detail:** {Global.DetailsLevel}\n"
        md += f"- **Load level:** {Global.LoadLevel}\n"
        if Global.ExcludedHosts:
            md += f"- **Excluded subdomains:** {'; '.join(Global.ExcludedHosts[::3])}\n"
        if Flags:
            md += f"- **Flags:** {' '.join(Flags)}\n"
        for note in Global.GeneralInfoNotes:
            md += f"\n{note}\n"
        return md + "\n"

    def found_services():
        md = "## Found network services\n\n"
        if Global.Services:
            for service in Global.Services:
                md += f"- {service}\n"
        else:
            md += "No network services found.\n"
        return md + "\n"

    def found_assets():
        md = "## Found websites\n\n"
        if not Global.HTTPAssets and not Global.AssetsWithWAF:
            return md + "No websites found.\n\n"
        if Global.AssetsWithWAF and Global.HTTPAssets:
            md += "### Without firewall\n\n"
        for link in Global.HTTPAssets:
            md += f"- {link}\n"
        if Global.AssetsWithWAF:
            md += "\n### With firewall\n\n"
            for link in Global.AssetsWithWAF:
                md += f"- {link} - {Global.AssetsWithWAF[link]}\n"
        return md + "\n"

    def nuclei_findings():
        def render_group(title, findings):
            text = f"### {title}\n\n"
            count = 0
            for severity in findings:
                if findings[severity]:
                    text += f"#### Issues with {severity} severity\n\n```\n"
                    for finding in findings[severity]:
                        text += finding + "\n"
                        count += 1
                    text += "```\n\n"
            if count == 0:
                text += "No findings this time :(\n\n"
            return text

        md = "## Nuclei Security Findings\n\n"
        md += render_group("Main findings", NucleiFindings)
        md += render_group("Config findings", NucleiConfigFindings)
        md += render_group("DAST scanning findings", NucleiDASTFindings)
        md += render_group("Leaked tokens findings", NucleiTokensFindings)
        md += render_group("Subdomain takeover findings", NucleiTakeoverFindings)
        return md

    def dependency_check():
        md = "## Dependency check\n\n### Unclaimed packages\n\n"
        unclaimed = [f for f in Global.DepConfusionFindings if not f["scoped"]]
        scoped = [f for f in Global.DepConfusionFindings if f["scoped"]]
        if unclaimed:
            for finding in unclaimed:
                md += f"- `{finding['package']}` — {finding['url']}\n"
            md += "\n"
        else:
            md += "No unclaimed package names this time.\n\n"
        md += "### Scoped packages\n\n"
        if scoped:
            md += "_These names were not found on the public registry. Whether the npm scope itself is already claimed cannot be determined automatically and requires manual verification._\n\n"
            for finding in scoped:
                md += f"- `{finding['package']}` — {finding['url']}\n"
            md += "\n"
        else:
            md += "No scoped package names this time.\n\n"
        md += "### Known vulnerabilities\n\n"
        if Global.DepCveFindings:
            md += "| Severity | Package | Version | ID | Summary | File |\n"
            md += "| --- | --- | --- | --- | --- | --- |\n"
            for severity in ("critical", "high", "medium", "low", "unknown"):
                for finding in [f for f in Global.DepCveFindings if f["severity"] == severity]:
                    summary = (finding["summary"] or "").replace("|", "\\|").replace("\n", " ")
                    md += (f"| {finding['severity']} | `{finding['package']}` | {finding['version']} "
                           f"| {finding['vuln_id']} | {summary} | {finding['url']} |\n")
            md += "\n"
        else:
            md += "No known vulnerabilities this time.\n\n"
        md += "### Exposed dependency files\n\n"
        if Global.DepExposedFiles:
            for url in Global.DepExposedFiles:
                md += f"- {url}\n"
            md += "\n"
        else:
            md += "No dependency files were found.\n\n"
        return md

    def fuzzing_results():
        md = "## Fuzzed files and directories\n\n"
        count = 0
        for HTTP_code in FuzzedDirectories:
            if FuzzedDirectories[HTTP_code]:
                md += f"### Endpoints with {HTTP_code} code\n\n"
                for endpoint in FuzzedDirectories[HTTP_code]:
                    md += f"- {endpoint}\n"
                    count += 1
                md += "\n"
        if count == 0:
            md += "No fuzzing results this time :(\n\n"
        return md

    def bypass403_results():
        md = "## 403 and 401 codes bypass results\n\n"
        if Global.Byp4xxResult:
            md += "_Please note that 403 bypass tools often give false positives._\n\n"
            if not Global.Details[Global.DetailsLevel]['CheckAll403links']:
                md += "**Only 1 link was analyzed for each host. If a successful bypass was found, " \
                      "manually check other 403/401 links on this domain.**\n\n"
            for host_strings in Global.Byp4xxResult:
                md += "```\n"
                for host_string in host_strings:
                    md += host_string + "\n"
                md += "```\n\n"
        else:
            md += "No bypasses this time.\n\n"
        return md

    def host_manipulation():
        def get_host_result(hosts_pair):
            return f"**Try using host header `{hosts_pair[0]}` on {hosts_pair[1]} ({hosts_pair[2]} status code)**\n\n" \
                   f"```\n{get_host_scan_commands(hosts_pair)}```\n\n"

        md = "## Host header manipulation\n\n### WAF bypass\n\n"
        if Global.WAFBypassHosts:
            for hosts_pair in Global.WAFBypassHosts:
                md += get_host_result(hosts_pair)
        elif Global.AssetsWithWAF:
            md += "No successful WAF bypass attempts this time.\n\n"
        else:
            md += "No hosts with WAF found.\n\n"
        md += "### Access to inactive hosts\n\n"
        if Global.InactiveHostsAccess:
            for hosts_pair in Global.InactiveHostsAccess:
                md += get_host_result(hosts_pair)
        else:
            md += "No successful inactive hosts access attempts this time.\n\n"
        return md

    def social_media_bypass():
        md = "## Inactive social media links\n\n"
        if Global.NotExistingSocialMediaLinks:
            for finding in NotExistingSocialMediaLinks:
                md += f"- Inactive {finding[1]} link on the {finding[0]} page.\n"
        else:
            md += "No social media links takeover possibilities this time.\n"
        return md + "\n"

    def postleaks_results():
        md = "## Postman leaks\n\n"
        if Global.PostleaksResult:
            for keyword, lines in Global.PostleaksResult.items():
                md += f"### {keyword} results\n\n"
                md += f"[Postman collection search link](https://www.postman.com/search?q={keyword}&scope=all&type=all)\n\n"
                md += "```\n"
                for line in lines:
                    md += line + "\n"
                md += "```\n\n"
        else:
            md += "No Postman leaks this time.\n"
        return md + "\n"

    def leakix_results():
        md = "## Leakix results\n\n"
        if LeakixFindings:
            for finding in LeakixFindings:
                if finding.event_source in Leakix_info:
                    md += f"### {Leakix_info[finding.event_source][1]}\n\n"
                    md += f"- URL: {finding.url}\n"
                    if finding.severity:
                        md += f"- Severity: {finding.severity}\n"
                    elif Leakix_info[finding.event_source][0]:
                        md += f"- Severity: {Leakix_info[finding.event_source][0]}\n"
                    md += f"- [More info here](https://leakix.net/domain/{finding.host})\n\n"
                    md += "```\n" + Leakix_info[finding.event_source][2].rstrip("\n") + "\n```\n\n"
                else:
                    md += f"### {finding.event_source}\n\n"
                    md += f"- URL: {finding.url}\n"
                    if finding.severity:
                        md += f"- Severity: {finding.severity}\n"
                    md += f"- [More info here](https://leakix.net/domain/{finding.host})\n\n"
        else:
            md += "No Leakix results this time.\n"
        return md + "\n"

    def qualys_results():
        md = "## Qualys WAS sync\n\n"
        if Global.QualysWASResults:
            for r in Global.QualysWASResults:
                line = f"- **{r.action}**: {r.host}"
                if r.parent and r.parent != r.host:
                    line += f" (parent: {r.parent})"
                details = []
                if r.webapp_id:
                    details.append(f"web app id: {r.webapp_id}")
                if r.scan_id:
                    details.append(f"scan id: {r.scan_id}")
                if details:
                    line += " - " + ", ".join(details)
                if r.message:
                    line += f" - {r.message}"
                md += line + "\n"
        else:
            md += "No Qualys WAS sync results this time - the sync was interrupted (Ctrl+C) or crashed "\
                  "before it processed anything. Check the console output for details.\n"
        return md + "\n"

    md_report = overview() + found_services() + found_assets() + nuclei_findings() + fuzzing_results()\
        + bypass403_results() + host_manipulation() + dependency_check() + social_media_bypass() + postleaks_results() + leakix_results()
    if '-q' in Flags:
        md_report += qualys_results()
    return md_report
