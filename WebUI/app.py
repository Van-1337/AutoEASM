"""AutoEASM Web UI — Flask backend.

Serves the single-page configuration interface (toggles instead of CLI flags),
launches `python main.py ...` as a subprocess, streams its console output to
the browser, and lists/serves generated reports.

Run:  python WebUI/app.py   →  http://127.0.0.1:7788
"""

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

from flask import Flask, abort, jsonify, render_template, request, send_from_directory

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent          # folder with main.py
HISTORY_DIR = BASE_DIR / "history"      # per-scan console logs

# Windows consoles often use a legacy codepage (cp1251/cp866): make every
# print safe regardless of the active codepage.
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

app = Flask(__name__)
HISTORY_DIR.mkdir(exist_ok=True)

# Modules: config key → the CLI flag that DISABLES the module.
DISABLE_FLAGS = {
    "subdomains": "-no-subdomains",    # subfinder / dnsx enumeration
    "nuclei": "-no-vulns",             # nuclei vulnerability scan (except takeover)
    "takeover": "-no-takeover",        # subdomain takeover check
    "dast": "-no-params",              # parameter checks on collected links
    "crawl": "-no-crawl",              # katana + uro crawling
    "fuzz": "-no-dirs",                # feroxbuster directory fuzzing
    "byp4xx": "-no-bypass",            # 403/401 bypass
    "waf_bypass": "-no-waf",           # WAF bypass attempts
    "inactive": "-no-inactive",        # access to inactive hosts
    "social": "-no-social",            # social media takeover
    "postman": "-no-postman",          # postleaks
    "leakix": "-no-leakix",            # LeakiX
    "securitytrails": "-no-history",   # SecurityTrails historical-IP checks (needs a paid key)
    "deps": "-no-deps",                # dependency check (confused + osv-scanner)
    "katana_headless": "-no-browser",  # katana headless browser
    "katana_forms": "-no-forms",       # katana automatic form filling
}
# Crawled endpoints → Burp: -burp-all sends everything -burp sends plus the URLs behind a WAF.
# -burp-dirs (fuzzed directories) and -burp-hits (WAF bypasses / old hosts) combine freely.
BURP_ENDPOINT_FLAGS = {"nowaf": "-burp", "all": "-burp-all"}

# The Skip button must reach main.py as a KeyboardInterrupt — that is how the
# CLI implements stage skipping. Console ctrl events proved unreliable
# (Windows Terminal/ConPTY may kill the target instead of signalling it), so
# the scan is launched through this wrapper instead: a daemon thread watches a
# skip-file, and when it appears calls signal.raise_signal(SIGINT) inside the
# scan process — raising KeyboardInterrupt in the main thread exactly like a
# real Ctrl+C, on any console type. Multiple flags → multiple skips.
RUN_WRAPPER = (
    "import os,signal,sys,runpy,threading,time;"
    "SKIP=sys.argv[1];sys.argv=sys.argv[2:]\n"
    "def _w():\n"
    " while 1:\n"
    "  time.sleep(.5)\n"
    "  try:os.remove(SKIP)\n"
    "  except OSError:continue\n"
    "  signal.raise_signal(signal.SIGINT)\n"
    "threading.Thread(target=_w,daemon=True).start();"
    "runpy.run_path(sys.argv[0],run_name='__main__')"
)


# --------------------------------------------------------------- scan state
class ScanState:
    def __init__(self):
        self.lock = threading.Lock()
        self.proc = None            # Popen while a scan is running
        self.output = []             # captured console lines
        self.command = None           # human-readable command tail
        self.started_at = None
        self.finished_at = None
        self.exit_code = None
        self.skip_file = None         # watched by the RUN_WRAPPER thread


state = ScanState()
_log_file = None                     # history file handle of the active scan
for _stale in HISTORY_DIR.glob("*.skip"):   # leftovers from a killed server
    try:
        _stale.unlink()
    except OSError:
        pass


def extra_tool_paths():
    """go\\bin and pipx bin — the external tools AutoEASM shells out to."""
    home = Path.home()
    paths = []
    for candidate in (home / "go" / "bin", home / ".local" / "bin"):
        if candidate.is_dir():
            paths.append(str(candidate))
    return paths


class InputError(Exception):
    """A form value main.py would reject. `code` is translated in the browser."""

    def __init__(self, code, **fields):
        super().__init__(code)
        self.code = code
        self.fields = fields


def _value_arg(flag, value):
    """main.py treats a value that starts with '-' as a missing argument and exits."""
    if value.startswith("-"):
        raise InputError("bad_value", flag=flag, value=value)
    return [flag, value]


def build_command(cfg):
    """Config dict → argv list for main.py. Mirrors the JS builder 1:1 and
    rejects values main.py would refuse, so the error is shown in the UI
    instead of the scan dying right after the start."""
    args = [sys.executable, "main.py"]

    domains = [str(d).strip() for d in cfg.get("domains", []) if str(d).strip()]
    if not domains:
        raise InputError("no_domains")
    for domain in domains:
        args += _value_arg("-domain", domain)

    modules = cfg.get("modules", {})
    for key, flag in DISABLE_FLAGS.items():
        if not modules.get(key, True):
            args.append(flag)

    load_level = cfg.get("load_level")
    if load_level in (1, 3):                     # 2 is the main.py default
        args += ["-load", str(load_level)]
    detail_level = cfg.get("detail_level")
    if detail_level in (1, 3, 4):                # 2 is the main.py default
        args += ["-deep", str(detail_level)]

    rate_limit = str(cfg.get("rate_limit") or "").strip()
    if rate_limit:
        if not rate_limit.isdigit() or int(rate_limit) < 1:
            raise InputError("bad_rate")
        args += ["-rate", str(int(rate_limit))]

    if cfg.get("all_ports"):
        args.append("-all-ports")
    if cfg.get("ip_mode"):
        args.append("-ip")

    for host in cfg.get("exclude", []):
        host = str(host).strip()
        if not host:
            continue
        if "*" in host or "?" in host:           # -exclude is an exact match in the scan modules
            raise InputError("bad_exclude", host=host)
        args += _value_arg("-exclude", host)

    report_name = str(cfg.get("report_name") or "").strip()
    if report_name:
        args += _value_arg("-report", report_name)
    outputs = cfg.get("outputs", {})           # nested on purpose, mirrors the UI groups
    if not outputs.get("open_report", True):
        args.append("-no-open")
    if outputs.get("markdown"):
        args.append("-markdown")
    if outputs.get("verbose"):
        args.append("-verbose")

    burp = cfg.get("burp", {})
    burp_flags = []
    if burp.get("endpoints") in BURP_ENDPOINT_FLAGS:
        burp_flags.append(BURP_ENDPOINT_FLAGS[burp["endpoints"]])
    if burp.get("fuzz"):
        burp_flags.append("-burp-dirs")
    if burp.get("bypass"):
        burp_flags.append("-burp-hits")
    if burp_flags:
        args += burp_flags
        proxy = str(burp.get("proxy") or "").strip()
        if proxy:
            bare = proxy.replace("http://", "").replace("https://", "")
            if bare.count(".") != 3 or ":" not in bare:   # the same check main.py applies to -p
                raise InputError("bad_proxy")
            args += _value_arg("-proxy", proxy)

    if cfg.get("qualys"):
        args.append("-qualys")

    adv = cfg.get("advanced", {})
    for cfg_key, cli_flag in (("user_agent", "-user-agent"), ("templates", "-templates"), ("wordlist", "-wordlist")):
        value = str(adv.get(cfg_key) or "").strip()
        if not value:
            continue
        if cli_flag == "-wordlist" and not (PROJECT_ROOT / value).exists():   # main.py exits on a missing file
            raise InputError("missing_wordlist", value=value)
        args += _value_arg(cli_flag, value)

    return args


def build_env(cfg):
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    sep = ";" if os.name == "nt" else ":"
    env["PATH"] = sep.join(extra_tool_paths()) + sep + env.get("PATH", "")
    adv = cfg.get("advanced", {})
    if str(adv.get("leakix_key") or "").strip():
        env["LeakIX_API_key"] = str(adv["leakix_key"]).strip()
    if str(adv.get("securitytrails_key") or "").strip():
        env["SecurityTrails_API_key"] = str(adv["securitytrails_key"]).strip()
    return env


def _reader(proc, log_file):
    global _log_file
    try:
        for raw in iter(proc.stdout.readline, ""):
            line = raw.rstrip("\r\n")
            with state.lock:
                state.output.append(line)
                if len(state.output) > 30000:          # ring buffer safety cap
                    del state.output[:5000]
            try:
                log_file.write(line + "\n")
                log_file.flush()
            except OSError:
                pass
    finally:
        code = proc.wait()
        with state.lock:
            state.exit_code = code
            state.finished_at = time.time()
            state.proc = None
            if state.skip_file:
                try:
                    state.skip_file.unlink()
                except OSError:
                    pass
                state.skip_file = None
        try:
            log_file.close()
        except OSError:
            pass


# ------------------------------------------------------------------- routes
@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/scan/start")
def scan_start():
    global _log_file
    cfg = request.get_json(force=True, silent=True) or {}
    with state.lock:
        if state.proc is not None:
            return jsonify(error_code="scan_busy"), 409
    try:
        args = build_command(cfg)
    except InputError as exc:
        return jsonify(error_code=exc.code, **exc.fields), 400

    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    stamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    skip_path = HISTORY_DIR / f"{stamp}.skip"
    argv = [sys.executable, "-c", RUN_WRAPPER, str(skip_path)] + args[1:]
    try:
        proc = subprocess.Popen(
            argv, cwd=PROJECT_ROOT, env=build_env(cfg),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
            creationflags=creationflags, start_new_session=(os.name != "nt"))
    except OSError as exc:
        return jsonify(error_code="process_failed", detail=str(exc)), 500

    log_path = HISTORY_DIR / f"{stamp}_console.log"
    meta_path = HISTORY_DIR / f"{stamp}_meta.json"
    log_file = open(log_path, "w", encoding="utf-8", newline="\n")
    _log_file = log_file
    try:
        meta_path.write_text(json.dumps({
            "command": " ".join(args[1:]),
            "domains": cfg.get("domains", []),
            "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass

    with state.lock:
        state.proc = proc
        state.output = []
        state.command = " ".join(args[1:])
        state.started_at = time.time()
        state.finished_at = None
        state.exit_code = None
        state.skip_file = skip_path
    threading.Thread(target=_reader, args=(proc, log_file), daemon=True).start()
    return jsonify(ok=True, command=state.command)


@app.get("/api/scan/status")
def scan_status():
    since = request.args.get("since", 0, type=int)
    with state.lock:
        lines = state.output
        return jsonify(
            running=state.proc is not None,
            exit_code=state.exit_code,
            command=state.command,
            started_at=state.started_at,
            finished_at=state.finished_at,
            total=len(lines),
            lines=lines[since:] if since > 0 else lines[-500:] if lines else [],
        )


@app.post("/api/scan/stop")
def scan_stop():
    with state.lock:
        proc = state.proc
    if proc is None:
        return jsonify(ok=True, stopped=False)
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                       capture_output=True)
    else:
        proc.terminate()
    return jsonify(ok=True, stopped=True)


@app.post("/api/scan/skip")
def scan_skip():
    """Skip the current stage — the web equivalent of pressing Ctrl+C in the
    console: the running tool is aborted, main.py continues with the next
    stage (pressing skip twice within the 5-second window exits the scan,
    just like a double Ctrl+C in the CLI). Implemented without console
    events: the flag file is picked up by the wrapper's watchdog thread which
    raises KeyboardInterrupt inside the scan process (see RUN_WRAPPER)."""
    with state.lock:
        skip_file = state.skip_file
    if skip_file is None or not state.proc:
        return jsonify(ok=False, error_code="scan_not_running"), 409
    try:
        skip_file.write_text("", encoding="utf-8")
    except OSError as exc:
        return jsonify(ok=False, error_code="skip_failed", detail=str(exc)), 500
    return jsonify(ok=True)


@app.get("/api/reports")
def reports():
    items = []
    for path in PROJECT_ROOT.glob("*.html"):
        try:
            stat = path.stat()
        except OSError:
            continue
        items.append({"name": path.name, "size": stat.st_size, "mtime": stat.st_mtime})
    items.sort(key=lambda item: item["mtime"], reverse=True)
    return jsonify(reports=items)


@app.get("/api/report/<path:name>")
def report_file(name):
    if name != os.path.basename(name) or ".." in name:
        abort(400)
    path = PROJECT_ROOT / name
    if not path.is_file():
        abort(404)
    return send_from_directory(PROJECT_ROOT, name)


@app.get("/api/logs")
def logs():
    root = PROJECT_ROOT / "Logs"
    items = []
    if root.is_dir():
        for entry in root.iterdir():
            if entry.is_dir():
                try:
                    items.append({"name": entry.name, "mtime": entry.stat().st_mtime})
                except OSError:
                    pass
    items.sort(key=lambda item: item["mtime"], reverse=True)
    return jsonify(logs=items)


if __name__ == "__main__":
    print("AutoEASM Web UI → http://127.0.0.1:7788")
    print("Остановка сервера: Ctrl+C или закрыть окно (идущий скан при этом продолжится)")
    app.run(host="127.0.0.1", port=7788, debug=False, threaded=True)