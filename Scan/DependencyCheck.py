from Global import Flags, Threads
import Global
from Scan.CommandRun import command_exec
from urllib.parse import urlparse, urljoin
import json
import os
import re
import subprocess
import requests

TEMPLATE_PATH = "Scan/resources/exposed-dependency-configs.yaml"
MAX_BODY_BYTES = 1048576

MANIFEST_SUFFIXES = (
    "/package-lock.json",
    "/npm-shrinkwrap.json",
    "/pnpm-lock.yaml",
    "/package.json",
    "/yarn.lock",
    "/composer.lock",
    "/composer.json",
    "/.composer/composer.json",
    "/vendor/composer/installed.json",
    "/requirements.txt",
    "/pyproject.toml",
    "/poetry.lock",
    "/Pipfile.lock",
    "/Pipfile",
    "/pom.xml",
    "/Gemfile.lock",
    "/Gemfile",
    "/go.mod",
    "/go.sum",
)

CONFUSED_LANG = {
    "package.json": "npm",
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "requirements.txt": "pip",
    "Pipfile": "pipenv",
    "composer.json": "composer",
    "installed.json": "composer-installed",
    "pom.xml": "mvn",
    "Gemfile.lock": "rubygems",
}

# Files osv-scanner -L can parse without conversion
OSV_NATIVE = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "composer.lock", "requirements.txt", "poetry.lock", "Pipfile.lock",
    "pom.xml", "Gemfile.lock", "go.mod",
}

# Filename/path stem -> npm name. Patterns follow common CDNs and Retire.js URI/filename extractors.
_JS_FILENAME_LIBS = {
    "jquery": "jquery",
    "jquery-migrate": "jquery-migrate",
    "jquery-ui": "jquery-ui",
    "jquery.ui": "jquery-ui",
    "jquery.mobile": "jquery-mobile",
    "jquery.validate": "jquery-validation",
    "jquery.validation": "jquery-validation",
    "lodash": "lodash",
    "underscore": "underscore",
    "bootstrap.bundle": "bootstrap",
    "bootstrap": "bootstrap",
    "angularjs": "angular",
    "angular": "angular",
    "vue": "vue",
    "react-dom": "react-dom",
    "react": "react",
    "moment": "moment",
    "handlebars": "handlebars",
    "mustache": "mustache",
    "backbone": "backbone",
    "axios": "axios",
    "d3": "d3",
    "popper.js": "popper.js",
    "popper": "popper.js",
    "knockout": "knockout",
    "ember": "ember",
    "leaflet": "leaflet",
    "swiper": "swiper",
    "select2": "select2",
    "three": "three",
    "core-js": "core-js",
    "tinymce": "tinymce",
    "ckeditor": "ckeditor",
    "jquery.datatables": "datatables.net",
    "datatables": "datatables.net",
    "chart.js": "chart.js",
    "chart": "chart.js",
    "highcharts": "highcharts",
    "alpinejs": "alpinejs",
    "alpine": "alpinejs",
    "echarts": "echarts",
    "video.js": "video.js",
    "quill": "quill",
    "marked": "marked",
    "highlight.js": "highlight.js",
    "highlight": "highlight.js",
    "svelte": "svelte",
    "mathjax": "mathjax",
}
_CDN_NAME_ALIASES = {
    "lodash.js": "lodash",
    "twitter-bootstrap": "bootstrap",
    "angular.js": "angular",
    "angularjs": "angular",
    "vue.js": "vue",
    "react.js": "react",
    "moment.js": "moment",
    "ember.js": "ember",
    "backbone.js": "backbone",
    "jqueryui": "jquery-ui",
    "three.js": "three",
    "chart.js": "chart.js",
}
_js_names_alt = "|".join(re.escape(n) for n in sorted(_JS_FILENAME_LIBS, key=len, reverse=True))
_js_ver = r"(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?)"
_js_filename_re = re.compile(
    rf"(?i)(?:^|/)({_js_names_alt})[-_.](\d+)[._-](\d+)[._-](\d+)(?:[-+][0-9A-Za-z.]+)?"
    r"(?:\.(?:min|slim|bundle|development|production|with-locales))*\.(?:js|css)(?:$|[?#])"
)
_js_verdir_re = re.compile(
    rf"(?i)/{_js_ver}/(?:js/)?({_js_names_alt})(?:\.(?:min|slim|bundle|with-locales))*\.(?:js|css)(?:$|[?#])"
)
_js_cdn_res = (
    (re.compile(r"(?:cdn|fastly|gcore|testingcf)\.jsdelivr\.net/npm/((?:@[^/]+/)?[^/@]+)@" + _js_ver, re.I), False),
    (re.compile(r"esm\.run/((?:@[^/]+/)?[^/@]+)@" + _js_ver, re.I), False),
    (re.compile(r"unpkg\.com/((?:@[^/]+/)?[^/@]+)@" + _js_ver, re.I), False),
    (re.compile(r"esm\.sh/((?:@[^/]+/)?[^/@]+)@" + _js_ver, re.I), False),
    (re.compile(r"skypack\.dev/((?:@[^/]+/)?[^/@]+)@" + _js_ver, re.I), False),
    (re.compile(r"jspm\.io/npm:((?:@[^/]+/)?[^/@]+)@" + _js_ver, re.I), False),
    (re.compile(r"(?:cdnjs\.cloudflare\.com|cdn\.bootcdn\.net|cdn\.bootcss\.com)/ajax/libs/([^/]+)/" + _js_ver, re.I), True),
    (re.compile(r"ajax\.googleapis\.com/ajax/libs/([^/]+)/" + _js_ver, re.I), True),
    (re.compile(r"(?:cdn\.staticfile\.org|lib\.baomitu\.com|cdn\.baomitu\.com|libs\.baidu\.com|apps\.bdimg\.com/libs)/([^/]+)/" + _js_ver, re.I), True),
)
_bootstrapcdn_re = re.compile(r"bootstrapcdn\.com/bootstrap/" + _js_ver, re.I)
_aspnet_bootstrap_re = re.compile(r"aspnetcdn\.com/ajax/bootstrap/" + _js_ver, re.I)
_aspnet_jqueryui_re = re.compile(r"aspnetcdn\.com/ajax/jqueryui/" + _js_ver, re.I)

_downloaded = []  # [{"url", "dir", "filename"}]


def collect_dependency_files():
    hosts = list(Global.HTTPAssets) + list(Global.AssetsWithWAF)
    if not hosts:
        return

    print("[*] Searching for exposed dependency files...")
    requests.packages.urllib3.disable_warnings()
    saved_urls = set()
    os.makedirs(Global.RunDir + "/dep_files", exist_ok=True)

    jsonl_lines = _run_nuclei(hosts)
    pending_download = []
    for url, body in _urls_from_nuclei(jsonl_lines):
        if body:
            _save_manifest(url, body, saved_urls)
        if _normalize_url(url) not in saved_urls:
            pending_download.append(url)

    for url in pending_download + list(Global.CrawledURLs) + list(Global.URLsWithWAF):
        if _normalize_url(url) in saved_urls:
            continue
        if not filename_from_url(url):
            continue
        body = _download_url(url)
        if body:
            _save_manifest(url, body, saved_urls)

    print(f"[+] {len(_downloaded)} dependency files were saved")


def analyze_dependency_files():
    allowed = set(Global.Details[Global.DetailsLevel]["NucleiCritical"].split(","))
    if _downloaded:
        print("[*] Checking downloaded dependency files...")
        for item in _downloaded:
            Global.DepExposedFiles.append(item["url"])
            _run_confused(item)
            _run_osv(item, allowed)
    scanned_js = _scan_js_cdn_cves(allowed)
    if _downloaded or scanned_js:
        print(f"[+] Dependency check: {len(Global.DepConfusionFindings)} unclaimed packages, "
              f"{len(Global.DepCveFindings)} CVEs")


def filename_from_url(url):
    path = urlparse(url.split("#")[0].split("?")[0]).path.replace("\\", "/")
    if not path.startswith("/"):
        path = "/" + path
    path = path.rstrip("/") or "/"
    for suffix in sorted(MANIFEST_SUFFIXES, key=len, reverse=True):
        if path == suffix or path.endswith(suffix):
            return suffix.rsplit("/", 1)[-1]
    return ""


def _normalize_url(url):
    return url.split("#")[0].split("?")[0].rstrip("/")


def _run_nuclei(hosts):
    input_data = "\n".join(hosts) + "\n"
    command = (
        f'nuclei -t {TEMPLATE_PATH} -ss host-spray -jsonl -ot -silent -nc -duc '
        f'-rl {Threads[Global.LoadLevel]["NucleiRate"]} -c {Threads[Global.LoadLevel]["NucleiParallels"]} '
        f'-H "User-Agent: {Global.UserAgent}"'
    )
    if "-v" in Flags:
        print("[v] Executing command: " + command)
    result = command_exec(command, "NucleiDeps.jsonl", input_data)
    if result == "-":
        print("[e] Error when running Nuclei utility for dependency files")
        return []
    return result


def _urls_from_nuclei(lines):
    found = []
    for line in lines:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = entry.get("matched-at") or entry.get("matched") or entry.get("url") or ""
        if not url or not filename_from_url(url):
            continue
        body = _http_body(entry.get("response"))
        found.append((url, body))
    return found


def _http_body(raw):
    if not raw:
        return ""
    if isinstance(raw, dict):
        return raw.get("body") or ""
    if "\r\n\r\n" in raw:
        return raw.split("\r\n\r\n", 1)[1]
    if "\n\n" in raw:
        return raw.split("\n\n", 1)[1]
    return raw


def _is_html(body):
    head = body.lstrip()[:300].lower()
    return head.startswith("<!doctype html") or head.startswith("<html") or "<html" in head


def _save_manifest(url, body, saved_urls):
    filename = filename_from_url(url)
    if not filename or not body or _is_html(body):
        return
    body_bytes = body.encode("utf-8", errors="replace")
    if len(body_bytes) > MAX_BODY_BYTES:
        return
    key = _normalize_url(url)
    if key in saved_urls:
        return
    index = len(_downloaded)
    dest_dir = os.path.join(Global.RunDir, "dep_files", str(index))
    os.makedirs(dest_dir, exist_ok=True)
    dest_path = os.path.join(dest_dir, filename)
    with open(dest_path, "w", encoding="utf-8", errors="replace", newline="\n") as file:
        file.write(body)
    saved_urls.add(key)
    _downloaded.append({"url": url, "dir": dest_dir, "filename": filename})


def _download_url(url):
    try:
        response = requests.get(url, headers={"User-Agent": Global.UserAgent}, timeout=15, verify=False)
        if response.status_code != 200:
            return ""
        return response.text
    except requests.RequestException:
        if "-v" in Flags:
            print(f"[v] Failed to download {url}")
        return ""


def _read_text(path):
    with open(path, encoding="utf-8", errors="replace") as file:
        return file.read()


def _write_json(path, data):
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)


def _pinned_version(version):
    version = (version or "").strip().strip("\"'")
    if version.startswith("=="):
        version = version[2:].strip()
    if not version or version[0] in "^~*<>=!":
        return ""
    if version.lower() in ("latest", "next", "*") or version.startswith(("file:", "git+", "http://", "https://", "workspace:", "link:", "npm:", "dev-")):
        return ""
    if re.search(r"[xX*]", version):
        return ""
    if version.startswith("v") and len(version) > 1 and version[1].isdigit():
        version = version[1:]
    if not re.match(r"^\d+(\.\d+)*([+-][0-9A-Za-z.-]+)?$", version):
        return ""
    return version


def _npm_name_from_descriptor(desc):
    desc = desc.strip().strip("\"'").split("(")[0]
    if not desc or desc.startswith("__") or desc in ("true", "false"):
        return ""
    if desc.startswith("@"):
        slash = desc.find("/")
        if slash < 0:
            return ""
        at2 = desc.find("@", slash)
        return desc[:at2] if at2 > 0 else desc
    return desc.split("@", 1)[0]


def _write_package_json(dest_dir, deps):
    deps = {name: (ver or "*") for name, ver in deps.items() if name}
    if not deps:
        return False
    _write_json(os.path.join(dest_dir, "package.json"), {
        "name": "restored-package", "version": "1.0.0", "dependencies": deps,
    })
    return True


def _write_composer_json(dest_dir, deps):
    deps = {name: (ver or "*") for name, ver in deps.items() if name and not _skip_composer_name(name)}
    if not deps:
        return False
    _write_json(os.path.join(dest_dir, "composer.json"), {"require": deps})
    return True


def _write_requirements(dest_dir, deps):
    lines = []
    for name, ver in deps.items():
        if not name or name.lower() == "python":
            continue
        pin = _pinned_version(ver)
        lines.append(f"{name}=={pin}" if pin else name)
    if not lines:
        return False
    with open(os.path.join(dest_dir, "requirements.txt"), "w", encoding="utf-8", newline="\n") as file:
        file.write("\n".join(lines) + "\n")
    return True


def _write_gemfile_lock(dest_dir, gems):
    specs = []
    for name, ver in gems.items():
        if not name:
            continue
        pin = _pinned_version(ver)
        specs.append(f"    {name} ({pin})" if pin else f"    {name}")
    if not specs:
        return False
    text = "GEM\n  remote: https://rubygems.org/\n  specs:\n" + "\n".join(specs) + "\n\nPLATFORMS\n  ruby\n"
    with open(os.path.join(dest_dir, "Gemfile.lock"), "w", encoding="utf-8", newline="\n") as file:
        file.write(text)
    return True


def _write_osv_custom(dest_dir, packages):
    if not packages:
        return False
    _write_json(os.path.join(dest_dir, "converted-osv.json"), {
        "results": [{"packages": packages}],
    })
    return True


def _skip_composer_name(name):
    return name == "php" or name.startswith("ext-") or name.startswith("lib-") or name == "composer-plugin-api"


def _convert_npm_lock(lock_path, dest_path):
    with open(lock_path, encoding="utf-8") as file:
        lock_data = json.load(file)
    package_json = {"name": "restored-package", "version": "1.0.0", "dependencies": {}, "devDependencies": {}}
    packages = lock_data.get("packages") or {}
    for pkg_path, info in packages.items():
        if not pkg_path or not isinstance(info, dict):
            continue
        name = info.get("name") or pkg_path.split("node_modules/")[-1]
        version = info.get("version") or ""
        if not name:
            continue
        if info.get("dev"):
            package_json["devDependencies"][name] = version
        else:
            package_json["dependencies"][name] = version
    if not package_json["dependencies"] and not package_json["devDependencies"]:
        for name, info in (lock_data.get("dependencies") or {}).items():
            if not isinstance(info, dict):
                continue
            version = info.get("version", "")
            if info.get("dev"):
                package_json["devDependencies"][name] = version
            else:
                package_json["dependencies"][name] = version
    if not package_json["devDependencies"]:
        del package_json["devDependencies"]
    if not package_json["dependencies"] and "devDependencies" not in package_json:
        return False
    _write_json(dest_path, package_json)
    return True


def _yarn_packages(text):
    deps = {}
    for line in text.splitlines():
        if not line or line[0] in " \t#" or line.startswith("__"):
            continue
        stripped = line.strip().rstrip(":")
        if stripped in ("__metadata",) or stripped.startswith("lockfile"):
            continue
        for part in stripped.split(","):
            name = _npm_name_from_descriptor(part)
            if name:
                deps.setdefault(name, "*")
    return deps


def _pnpm_packages(text):
    deps = {}
    in_packages = False
    for line in text.splitlines():
        if line.startswith("packages:"):
            in_packages = True
            continue
        if not in_packages:
            continue
        if line and line[0] not in " \t":
            break
        if not line.rstrip().endswith(":"):
            continue
        key = line.strip().rstrip(":").strip("\"'")
        if not key or key.startswith("resolution") or key in ("dependencies", "devDependencies", "optionalDependencies"):
            continue
        name = _pnpm_name_from_key(key)
        if name:
            deps.setdefault(name, "*")
    return deps


def _pnpm_name_from_key(key):
    key = key.split("(")[0]
    if key.startswith("/"):
        key = key[1:]
    if not key:
        return ""
    if key.startswith("@"):
        parts = key[1:].split("/")
        if len(parts) < 2:
            return ""
        return "@" + parts[0] + "/" + parts[1].split("@")[0]
    if "@" in key:
        return key.split("@", 1)[0]
    return key.split("/")[0]


def _composer_lock_packages(lock_path):
    data = json.loads(_read_text(lock_path))
    deps = {}
    for key in ("packages", "packages-dev"):
        for pkg in data.get(key) or []:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name") or ""
            if name:
                deps[name] = pkg.get("version") or "*"
    return deps


def _poetry_packages(text):
    deps = {}
    name = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "[[package]]":
            name = None
        elif stripped.startswith("name = "):
            name = stripped.split("=", 1)[1].strip().strip("\"'")
        elif stripped.startswith("version = ") and name:
            deps[name] = stripped.split("=", 1)[1].strip().strip("\"'")
            name = None
    return deps


def _pipfile_lock_packages(lock_path):
    data = json.loads(_read_text(lock_path))
    deps = {}
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            if isinstance(info, dict):
                deps[name] = (info.get("version") or "*").lstrip("=")
            elif isinstance(info, str):
                deps[name] = info
    return deps


def _pyproject_packages(text):
    deps = {}
    in_poetry = False
    in_pep621 = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[tool.poetry.dependencies]") or (
                stripped.startswith("[tool.poetry.group.") and stripped.endswith("dependencies]")):
            in_poetry, in_pep621 = True, False
            continue
        if stripped.startswith("dependencies = ["):
            inner = stripped[len("dependencies = ["):]
            if "]" in inner:
                in_pep621, in_poetry = False, False
                for part in inner.split("]"):
                    for quoted in re.findall(r'["\']([^"\']+)["\']', part):
                        name = re.match(r"([A-Za-z0-9_.-]+)", quoted)
                        if name:
                            ver_match = re.search(r"([0-9][^\"']*)", quoted[len(name.group(1)):])
                            deps[name.group(1)] = ver_match.group(1) if ver_match else "*"
                    break
            else:
                in_pep621, in_poetry = True, False
            continue
        if stripped.startswith("["):
            in_poetry = False
            continue
        if in_pep621:
            if stripped.startswith("]"):
                in_pep621 = False
                continue
            match = re.search(r'["\']([A-Za-z0-9_.-]+)', stripped)
            if match:
                rest = stripped.split(match.group(1), 1)[-1]
                ver_match = re.search(r'([0-9][^"\']*)', rest)
                deps[match.group(1)] = ver_match.group(1) if ver_match else "*"
            continue
        if in_poetry and "=" in stripped:
            name = stripped.split("=", 1)[0].strip().strip("\"'")
            if name and name != "python":
                ver_match = re.search(r'["\']([^"\']+)["\']', stripped.split("=", 1)[1])
                deps[name] = ver_match.group(1) if ver_match else "*"
    return deps


def _gemfile_packages(text):
    deps = {}
    gem_re = re.compile(r'''^\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?''')
    for line in text.splitlines():
        match = gem_re.match(line)
        if match:
            deps[match.group(1)] = match.group(2) or "*"
    return deps


def _pinned_from_json_manifest(path, filename):
    data = json.loads(_read_text(path))
    packages = []
    if filename == "package.json":
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            for name, ver in (data.get(key) or {}).items():
                pin = _pinned_version(str(ver))
                if name and pin:
                    packages.append({"package": {"name": name, "version": pin, "ecosystem": "npm"}})
    elif filename == "composer.json":
        for key in ("require", "require-dev"):
            for name, ver in (data.get(key) or {}).items():
                if _skip_composer_name(name):
                    continue
                pin = _pinned_version(str(ver))
                if name and pin:
                    packages.append({"package": {"name": name, "version": pin, "ecosystem": "Packagist"}})
    return packages


def _confused_target(item):
    filename = item["filename"]
    src = os.path.join(item["dir"], filename)
    dest_dir = item["dir"]
    try:
        if filename in ("package-lock.json", "npm-shrinkwrap.json"):
            if _convert_npm_lock(src, os.path.join(dest_dir, "package.json")):
                return "npm", "package.json"
            return None
        if filename in CONFUSED_LANG:
            return CONFUSED_LANG[filename], filename
        if filename == "yarn.lock":
            return ("npm", "package.json") if _write_package_json(dest_dir, _yarn_packages(_read_text(src))) else None
        if filename == "pnpm-lock.yaml":
            return ("npm", "package.json") if _write_package_json(dest_dir, _pnpm_packages(_read_text(src))) else None
        if filename == "composer.lock":
            return ("composer", "composer.json") if _write_composer_json(dest_dir, _composer_lock_packages(src)) else None
        if filename == "poetry.lock":
            return ("pip", "requirements.txt") if _write_requirements(dest_dir, _poetry_packages(_read_text(src))) else None
        if filename == "Pipfile.lock":
            return ("pip", "requirements.txt") if _write_requirements(dest_dir, _pipfile_lock_packages(src)) else None
        if filename == "pyproject.toml":
            return ("pip", "requirements.txt") if _write_requirements(dest_dir, _pyproject_packages(_read_text(src))) else None
        if filename == "Gemfile":
            return ("rubygems", "Gemfile.lock") if _write_gemfile_lock(dest_dir, _gemfile_packages(_read_text(src))) else None
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        if "-v" in Flags:
            print(f"[v] Failed to convert {item['url']} for confused")
    return None


def _osv_lock_arg(item):
    filename = item["filename"]
    if filename in OSV_NATIVE:
        return filename
    src = os.path.join(item["dir"], filename)
    dest_dir = item["dir"]
    try:
        if filename in ("package.json", "composer.json"):
            if _write_osv_custom(dest_dir, _pinned_from_json_manifest(src, filename)):
                return "osv-scanner:converted-osv.json"
            return None
        if filename == "pyproject.toml":
            return "requirements.txt" if _write_requirements(dest_dir, _pyproject_packages(_read_text(src))) else None
        if filename == "Gemfile":
            gems = _gemfile_packages(_read_text(src))
            if any(_pinned_version(ver) for ver in gems.values()) and _write_gemfile_lock(dest_dir, gems):
                return "Gemfile.lock"
            return None
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        if "-v" in Flags:
            print(f"[v] Failed to convert {item['url']} for osv-scanner")
    return None


def _run_confused(item):
    prepared = _confused_target(item)
    if not prepared:
        return
    lang, scan_file = prepared
    try:
        result = subprocess.run(
            ["confused", "-l", lang, "-f", scan_file],
            cwd=item["dir"], capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
    except OSError:
        print("[e] Error when running confused")
        return
    output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
    try:
        with open(os.path.join(item["dir"], "confused.txt"), "w", encoding="utf-8") as file:
            file.write(output)
    except OSError:
        pass
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line.startswith("[!]"):
            package = line[3:].strip()
            if package:
                Global.DepConfusionFindings.append({
                    "url": item["url"],
                    "package": package,
                    "scoped": package.startswith("@"),
                })


def _cvss_label(score_text):
    try:
        score = float(score_text)
    except (TypeError, ValueError):
        return "unknown"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


def _cdn_npm_name(name):
    name = (name or "").strip()
    key = name.lower()
    if key in _CDN_NAME_ALIASES:
        return _CDN_NAME_ALIASES[key]
    if key.endswith(".js") and len(key) > 3:
        stem = key[:-3]
        if stem in _CDN_NAME_ALIASES:
            return _CDN_NAME_ALIASES[stem]
        if stem in _JS_FILENAME_LIBS:
            return _JS_FILENAME_LIBS[stem]
        return stem
    return name


def _add_js_package(packages, url_map, name, version, url):
    pin = _pinned_version(version)
    if not name or not pin or pin.count(".") < 2:
        return
    key = (name, pin)
    if key in url_map:
        return
    url_map[key] = url
    packages.append({"package": {"name": name, "version": pin, "ecosystem": "npm"}})


def _packages_from_crawled_urls():
    packages = []
    url_map = {}
    seen = set()
    for url in list(Global.CrawledURLs) + list(Global.URLsWithWAF) + list(Global.JSlinks) + _script_srcs_from_katana():
        if not url or url in seen:
            continue
        seen.add(url)
        for regex, remap in _js_cdn_res:
            match = regex.search(url)
            if match:
                name = _cdn_npm_name(match.group(1)) if remap else match.group(1)
                _add_js_package(packages, url_map, name, match.group(2), url)
                break
        else:
            boot = _bootstrapcdn_re.search(url) or _aspnet_bootstrap_re.search(url)
            if boot:
                _add_js_package(packages, url_map, "bootstrap", boot.group(1), url)
                continue
            jqueryui = _aspnet_jqueryui_re.search(url)
            if jqueryui:
                _add_js_package(packages, url_map, "jquery-ui", jqueryui.group(1), url)
                continue
            file_match = _js_filename_re.search(url)
            if file_match:
                name = _JS_FILENAME_LIBS[file_match.group(1).lower()]
                ver = f"{file_match.group(2)}.{file_match.group(3)}.{file_match.group(4)}"
                _add_js_package(packages, url_map, name, ver, url)
                continue
            dir_match = _js_verdir_re.search(url)
            if dir_match:
                name = _JS_FILENAME_LIBS[dir_match.group(2).lower()]
                _add_js_package(packages, url_map, name, dir_match.group(1), url)
    return packages, url_map


def _script_srcs_from_katana():
    urls = []
    src_re = re.compile(r"""<(?:script[^>]+src|link[^>]+href)=["']([^"']+)["']""", re.I)
    for name in ("Katana.jsonl", "Katana_WAF.jsonl"):
        path = os.path.join(Global.RunDir, name)
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8") as file:
                for line in file:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    body = (entry.get("response") or {}).get("body") or ""
                    page = (entry.get("request") or {}).get("endpoint") or ""
                    if not body or not page:
                        continue
                    for src in src_re.findall(body):
                        urls.append(urljoin(page, src))
        except OSError:
            pass
    return urls


def _scan_js_cdn_cves(allowed_severities):
    packages, url_map = _packages_from_crawled_urls()
    if not packages:
        return False
    print("[*] Checking JS/CDN library versions...")
    dest_dir = os.path.join(Global.RunDir, "dep_files", "js_cdn")
    os.makedirs(dest_dir, exist_ok=True)
    if not _write_osv_custom(dest_dir, packages):
        return False
    data = _osv_json(dest_dir, "osv-scanner:converted-osv.json", "JS/CDN URLs")
    if data:
        _store_osv_findings(data, allowed_severities, lambda name, ver: url_map.get((name, ver), ""))
    return True


def _osv_json(cwd, lock_arg, label):
    try:
        result = subprocess.run(
            ["osv-scanner", "scan", "source", "-L", lock_arg, "--format", "json",
             "--output-file", "osv.json", "--verbosity", "error", "--no-resolve"],
            cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
    except OSError:
        print("[e] Error when running osv-scanner")
        return None
    if result.returncode not in (0, 1):
        if "-v" in Flags:
            print(f"[v] osv-scanner skipped {label}: {result.stderr or result.returncode}")
        return None
    out_file = os.path.join(cwd, "osv.json")
    if not os.path.exists(out_file):
        return None
    try:
        with open(out_file, encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError):
        return None


def _store_osv_findings(data, allowed_severities, url_for_pkg):
    for source in data.get("results") or []:
        for pkg_entry in source.get("packages") or []:
            pkg = pkg_entry.get("package") or {}
            name = pkg.get("name") or ""
            version = pkg.get("version") or ""
            if version[:1] in "vV" and len(version) > 1 and version[1].isdigit():
                version = version[1:]
            vulns_by_id = {v.get("id"): v for v in pkg_entry.get("vulnerabilities") or [] if v.get("id")}
            for group in pkg_entry.get("groups") or []:
                aliases = group.get("aliases") or []
                ids = group.get("ids") or []
                vuln_id = next((a for a in aliases if a.startswith("CVE-")), "") or (ids[0] if ids else "")
                if not vuln_id:
                    continue
                severity = _cvss_label(group.get("max_severity"))
                if severity not in allowed_severities:
                    continue
                summary = ""
                for vid in ids:
                    vuln = vulns_by_id.get(vid) or {}
                    summary = vuln.get("summary") or ""
                    if summary:
                        break
                Global.DepCveFindings.append({
                    "url": url_for_pkg(name, version),
                    "package": name,
                    "version": version,
                    "vuln_id": vuln_id,
                    "severity": severity,
                    "summary": summary,
                })


def _run_osv(item, allowed_severities):
    lock_arg = _osv_lock_arg(item)
    if not lock_arg:
        return
    data = _osv_json(item["dir"], lock_arg, item["url"])
    if data:
        _store_osv_findings(data, allowed_severities, lambda name, ver: item["url"])
