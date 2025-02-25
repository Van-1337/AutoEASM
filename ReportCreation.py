from Global import Domains, HTTPAssets, Flags, AssetsWithWAF, NucleiFindings, NotExistingSocialLinks,\
    NucleiConfigFindings, FuzzedDirectories, NucleiTokensFindings, NucleiDASTFindings, NucleiTakeoverFindings, LeakixFindings
import Global
from datetime import datetime
from Scan.LeakixInfo import Leakix_info
import webbrowser
import os

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
    <title>EASM Report</title>
    <style>
        /* Обнуляем отступы и устанавливаем box-sizing */
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
        /* Стили для фиксированной боковой панели */
        .sidebar {
            position: fixed; /* Фиксированное позиционирование */
            top: 0;
            left: 0;
            width: 200px;
            height: 100%; /* Полная высота окна */
            background-color: #f4f4f4;
            border-right: 1px solid #ccc;
            overflow-x: hidden; /* Отключение горизонтальной прокрутки */
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
        /* Стили для содержимого вкладок */
        .content {
            margin-left: 200px; /* Отступ для боковой панели */
            padding: 20px;
            flex: 1;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        /* Для демонстрации прокрутки */
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

        if AssetsWithWAF and HTTPAssets:
            html_assets += "<h3>Without firewall</h3>"
        html_assets += "<p>\n"
        for link in HTTPAssets:
            html_assets += f"<a href=\"{link}\">{link}</a> <br>\n"  # <a href="http://site.com">http://site.com</a>
        html_assets += "</p>"

        if AssetsWithWAF:
            html_assets += "<h3>With firewall</h3>"
            html_assets += "<p>\n"
            for link in AssetsWithWAF:
                html_assets += f"<a href=\"{link}\">{link}</a> - {AssetsWithWAF[link]} <br>\n"  # <a href="http://site.com">http://site.com</a>
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
                    findings_text += f"{finding} <br>\n"
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
                    findings_text += f"{finding} <br>\n"
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
                    findings_text += f"{finding} <br>\n"
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
                    findings_text += f"{finding} <br>\n"
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
                    findings_text += f"{finding} <br>\n"
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
                    fuzzing_text += f"{endpoint} <br>\n"
                    count += 1
                fuzzing_text += "</p>\n"
        if count == 0:
            fuzzing_text += "No fuzzing results this time :("
        fuzzing_text += "</div>"
        return fuzzing_text

    def bypass403_results():
        bypass_text = """\n\n<div id="Bypass403" class="tab-content">\n<h2>403 and 401 bypass results</h2><br>\n"""
        if Global.Byp4xxResult:
            bypass_text += "<i>Please note that 403 bypass tools often gives false positives</i><br><br>\n"
            bypass_text += Global.Byp4xxResult
        else:
            bypass_text += "No bypasses this time."
        bypass_text += "</div>"
        return bypass_text

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
                    leakix_text += f"<br><pre>{Leakix_info[finding.event_source][2]}</pre>"
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
        + social_media_bypass() + postleaks_results() + leakix_results()
