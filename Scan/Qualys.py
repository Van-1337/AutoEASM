"""Qualys WAS integration (enabled with the -q flag).

After subdomain discovery, this module pushes the live web services (root domains and
subdomains) into Qualys WAS: every asset that is not already present as a web app is created,
given a scan schedule (copied from the parent root domain's schedule where one exists), and
launched into an immediate one-off scan with the Fast_Scan option profile. A summary email is
sent for the launched scans.

It follows the same conventions as Scan/Leakix.py: credentials come from Global, requests go
through `requests` with a retry/backoff loop on rate limits, results land in
Global.QualysWASResults, and the whole thing is started as a daemon thread from Control.py.

The Qualys WAS REST API is XML-based. Endpoint paths and the reusable parts of the request
bodies follow the Qualys WAS API User Guide (WebApp, WasScanSchedule, OptionProfile, WasScan
references). Areas whose exact field layout depends on the subscription/version are marked with
NOTE comments; a mismatch there surfaces as a per-asset "error" record rather than aborting the
whole run.
"""

from Global import Flags
import Global
import time
import copy
import fnmatch
import os
import re
import smtplib
from email.message import EmailMessage
from urllib.parse import urlparse
from xml.sax.saxutils import escape as xml_escape
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
import requests

from Scan.Helpers import get_host_from_url, QualysWebAppResult


class QualysError(Exception):
    pass


_option_profile_cache = {}  # name -> id (or None)


# ---------------------------------------------------------------------------
# Pure helpers (no network) - safe to unit-test directly
# ---------------------------------------------------------------------------
def resolve_parent(host, domains):
    """Return the longest root domain in `domains` that `host` equals or is a subdomain of.

    Hosts that match no root domain are treated as their own parent (default-schedule path)."""
    host = (host or "").lower()
    match = ""
    for root in domains:
        root = (root or "").strip().lower()
        if not root:
            continue
        if host == root or host.endswith("." + root):
            if len(root) > len(match):
                match = root
    return match or host


def is_parent_level(host, domains):
    """True for a registered root domain or an orphan host (no matching root)."""
    return resolve_parent(host, domains) == host


def normalize_url(url):
    """Canonical form for creating and comparing web app URLs: lowercase scheme and host, no
    trailing slash, no query or fragment - so https://example.com/ and https://example.com are
    the same app instead of two."""
    raw = (url or "").strip()
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path.rstrip('/')}"


def strip_www(host):
    """example.com for www.example.com; every other host unchanged."""
    h = (host or "").strip().lower()
    return h[4:] if h.startswith("www.") else h


def root_key(host, domains):
    """The root domain a host belongs to, counting www.example.com as example.com."""
    return resolve_parent(strip_www(host), domains)


def is_root_level(host, domains):
    """True for a root domain, its www. form, or an orphan host. A www./port variant is root level
    but not the canonical root, so it inherits from the canonical app instead of being bootstrapped
    with the default schedule and no tags."""
    return root_key(host, domains) == strip_www(host)


def build_asset_list():
    """Live web services to sync = HTTPAssets + AssetsWithWAF keys, de-duplicated by host."""
    seen = set()
    assets = []
    for url in list(Global.HTTPAssets) + list(Global.AssetsWithWAF.keys()):
        host = get_host_from_url(url, remove_port=True)
        if not host or host in seen:
            continue
        seen.add(host)
        assets.append((host, url))
    return assets


_ignore_patterns = None  # cached list of exclude patterns (lowercased) for the current run


def _ignore_file_candidates():
    """Paths checked for the exclude file: QUALYS_IGNORE_FILE override + auto-detected
    qualys_exclude.txt (in the working dir, next to main.py, and /src for Docker)."""
    candidates = []
    env_file = os.environ.get("QUALYS_IGNORE_FILE", "").strip()
    if env_file:
        candidates.append(env_file)
    if "--docker" in Flags:
        candidates.append("/src/qualys_exclude.txt")
    candidates.append("qualys_exclude.txt")  # current working directory
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates.append(os.path.join(repo_root, "qualys_exclude.txt"))  # next to main.py, regardless of CWD
    return candidates


def _load_ignore_patterns():
    """Merge exclude patterns from QUALYS_IGNORE_HOSTS (inline) and the exclude file(s). File lines
    are one host/pattern each; blank lines and #-comments are ignored."""
    patterns = [p.strip() for p in (Global.QualysIgnoreHosts or "").split(",") if p.strip()]
    for path in _ignore_file_candidates():
        try:
            if path and os.path.isfile(path):
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.split("#", 1)[0].strip()
                        if line:
                            patterns.append(line)
        except OSError:
            pass
    seen, result = set(), []
    for p in patterns:
        pl = p.lower()
        if pl and pl not in seen:
            seen.add(pl)
            result.append(pl)
    return result


def _refresh_ignore_patterns():
    global _ignore_patterns
    _ignore_patterns = _load_ignore_patterns()
    return _ignore_patterns


def is_ignored(host):
    """True if host matches any exclude pattern - from QUALYS_IGNORE_HOSTS or the auto-detected
    qualys_exclude.txt (exact or fnmatch wildcard, e.g. "dev.example.com", "*.staging.example.com",
    "test-*")."""
    global _ignore_patterns
    if _ignore_patterns is None:
        _ignore_patterns = _load_ignore_patterns()
    h = (host or "").strip().lower()
    return any(fnmatch.fnmatchcase(h, p) for p in _ignore_patterns)


# ---------------------------------------------------------------------------
# XML helpers
# ---------------------------------------------------------------------------
def _local(tag):
    return tag.split('}')[-1] if isinstance(tag, str) else tag


def _find(elem, tag):
    if elem is None:
        return None
    for el in elem.iter():
        if _local(el.tag) == tag:
            return el
    return None


def _findtext(elem, tag, default=""):
    found = _find(elem, tag)
    if found is not None and found.text is not None:
        return found.text.strip()
    return default


def _subtree_xml(parent_elem, tag):
    """Serialize the first `tag` subtree back to an XML string for re-embedding (verbatim copy)."""
    node = _find(parent_elem, tag)
    if node is None:
        return ""
    return ET.tostring(node, encoding="unicode")


def _tag_ids(parent_elem):
    """Collect tag ids under the element's <tags> list/set. Reads the id of each list item
    regardless of its element name (Tag, TagSimple, ...), so it survives WAS response variations."""
    tags = _find(parent_elem, "tags")
    if tags is None:
        return []
    container = _find(tags, "list") or _find(tags, "set") or tags
    ids = []
    for item in list(container):
        if _local(item.tag) == "count":
            continue
        tid = _findtext(item, "id")
        if tid and tid not in ids:
            ids.append(tid)
    return ids


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------
def credentials_configured():
    return (Global.QualysUsername not in ("", "CHANGEME")
            and Global.QualysPassword not in ("", "CHANGEME"))


def resolve_qualys_credentials():
    """Resolve credentials: SSM Parameter Store -> env vars / hardcoded fallbacks.

    When both SSM param names are set, fetch the username and password from AWS SSM and overwrite
    the in-memory Global values. boto3 is imported lazily so it is only required on the SSM path.
    Returns (username, password). Never logs the password."""
    if Global.QualysSSMUserParam and Global.QualysSSMPasswordParam:
        try:
            import boto3
        except ImportError:
            raise QualysError("boto3 is required for SSM Parameter Store credentials. "
                              "Install it with: pip install boto3")
        try:
            client = boto3.client("ssm", region_name=Global.QualysSSMRegion or None)
            user = client.get_parameter(Name=Global.QualysSSMUserParam, WithDecryption=True)["Parameter"]["Value"]
            password = client.get_parameter(Name=Global.QualysSSMPasswordParam, WithDecryption=True)["Parameter"]["Value"]
        except Exception as e:
            raise QualysError(f"could not read Qualys credentials from SSM Parameter Store: {e}")
        Global.QualysUsername = user.strip()
        Global.QualysPassword = password.strip()
        print("[*] Qualys credentials loaded from AWS SSM Parameter Store")
    return Global.QualysUsername, Global.QualysPassword


# ---------------------------------------------------------------------------
# Low-level request wrapper
# ---------------------------------------------------------------------------
def _request(method, path, xml_body=None):
    url = Global.QualysAPIURL.rstrip("/") + path
    headers = {
        "X-Requested-With": "AutoEASM",   # required by Qualys for REST calls
        "Content-Type": "text/xml",
        "Accept": "application/xml",
    }
    if '-v' in Flags:
        print(f"[v] Qualys {method} {path}")
    attempts = 0
    while True:
        try:
            response = requests.request(
                method, url,
                auth=(Global.QualysUsername, Global.QualysPassword),
                headers=headers,
                data=xml_body.encode("utf-8") if xml_body else None,
                timeout=120,  # scan launch on some PODs can be slow to respond
            )
        except requests.RequestException as e:
            raise QualysError(f"request to {path} failed: {e}")
        if response.status_code in (409, 429, 503):  # concurrency / rate limit -> back off
            attempts += 1
            if attempts > 10:
                raise QualysError(f"{path}: rate/concurrency limit not clearing (HTTP {response.status_code})")
            time.sleep(5)
            continue
        break

    if response.status_code == 401:
        raise QualysError("authentication failed (HTTP 401) - check the Qualys username/password and platform URL")
    try:
        root = ET.fromstring(response.content)
    except ET.ParseError as e:
        raise QualysError(f"{path}: could not parse XML response (HTTP {response.status_code}): {e}")
    code = _findtext(root, "responseCode")
    if code and code != "SUCCESS":
        message = _findtext(root, "errorMessage") or code
        raise QualysError(f"{path}: {code} - {message}")
    if response.status_code >= 400 and not code:
        raise QualysError(f"{path}: HTTP {response.status_code}")
    return root


# ---------------------------------------------------------------------------
# Read operations
# ---------------------------------------------------------------------------
def resolve_option_profile_id(name):
    if name in _option_profile_cache:
        return _option_profile_cache[name]
    body = ('<ServiceRequest><filters>'
            f'<Criteria field="name" operator="EQUALS">{xml_escape(name)}</Criteria>'
            '</filters></ServiceRequest>')
    root = _request("POST", "/qps/rest/3.0/search/was/optionprofile", body)
    op = _find(root, "OptionProfile")
    op_id = _findtext(op, "id") if op is not None else ""
    _option_profile_cache[name] = op_id or None
    return _option_profile_cache[name]


def find_webapp(host, url):
    """Id of an existing web app for this asset, else None.

    Tries the normalized url, the same url with a trailing slash (apps created before URLs were
    normalized), the name, and finally any app on the same host whose url matches once normalized -
    without that last step a slash or case difference creates a duplicate app."""
    target = normalize_url(url)
    for field, value in (("url", target), ("url", target + "/"), ("name", host)):
        if not value:
            continue
        body = ('<ServiceRequest><filters>'
                f'<Criteria field="{field}" operator="EQUALS">{xml_escape(value)}</Criteria>'
                '</filters></ServiceRequest>')
        root = _request("POST", "/qps/rest/3.0/search/was/webapp", body)
        wa = _find(root, "WebApp")
        if wa is not None:
            return _findtext(wa, "id")
    if host:
        body = ('<ServiceRequest><filters>'
                f'<Criteria field="url" operator="CONTAINS">{xml_escape(host)}</Criteria>'
                '</filters></ServiceRequest>')
        root = _request("POST", "/qps/rest/3.0/search/was/webapp", body)
        for el in root.iter():
            if _local(el.tag) == "WebApp" and normalize_url(_findtext(el, "url")) == target:
                return _findtext(el, "id")
    return None


def get_webapp(webapp_id):
    root = _request("GET", f"/qps/rest/3.0/get/was/webapp/{webapp_id}")
    return _find(root, "WebApp")


def find_schedule_for_webapp(webapp_id):
    """Best-effort: find a scan schedule attached to the given web app via the search filter.

    Returns None (the caller then falls back to the default schedule template) when the filter is
    unsupported or no schedule matches. We deliberately do NOT enumerate every schedule in the
    subscription - that would fire one GET per schedule and hammer the API."""
    try:
        body = ('<ServiceRequest><filters>'
                f'<Criteria field="webApp.id" operator="EQUALS">{xml_escape(str(webapp_id))}</Criteria>'
                '</filters></ServiceRequest>')
        root = _request("POST", "/qps/rest/3.0/search/was/wasscanschedule", body)
    except QualysError:
        return None
    sched = _find(root, "WasScanSchedule")
    return _findtext(sched, "id") if sched is not None else None


def get_schedule(schedule_id):
    root = _request("GET", f"/qps/rest/3.0/get/was/wasscanschedule/{schedule_id}")
    return _find(root, "WasScanSchedule")


# The API returns a numeric <dayOrder>; a create/update request only accepts the enum.
_DAY_ORDER = {"1": "FIRST", "2": "SECOND", "3": "THIRD", "4": "FOURTH", "5": "LAST", "-1": "LAST"}


def _fix_scheduling(scheduling_xml):
    """Make a copied <scheduling> block acceptable to WAS: translate a numeric <dayOrder> (1..5)
    into FIRST..LAST, and drop the server-computed timeZone <offset>. Without this, copying a
    monthly "first Monday every 3 months" parent schedule fails with INVALID_XML."""
    xml = re.sub(r"<offset>.*?</offset>", "", scheduling_xml or "", flags=re.S)
    return re.sub(r"<dayOrder>\s*(.*?)\s*</dayOrder>",
                  lambda mo: "<dayOrder>" + _DAY_ORDER.get(mo.group(1), mo.group(1)) + "</dayOrder>",
                  xml, flags=re.S)


def _future_start(scheduling_xml, margin_minutes=10):
    """WAS rejects a create whose start time is in the past ("Start Time cannot be before current
    time"), and a parent schedule is usually anchored months ago. Keep the time of day and the
    recurrence, move the date to the next day that is still ahead of now."""
    found = re.search(r"<startDate>(.*?)</startDate>", scheduling_xml or "", flags=re.S)
    if not found:
        return scheduling_xml
    text = found.group(1).strip()
    when = None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ"):
        try:
            when = datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
            break
        except ValueError:
            continue
    if when is None:
        return scheduling_xml
    limit = datetime.now(timezone.utc) + timedelta(minutes=margin_minutes)
    if when > limit:
        return scheduling_xml
    while when <= limit:
        when += timedelta(days=1)
    return (scheduling_xml[:found.start()] + "<startDate>" + when.strftime("%Y-%m-%dT%H:%M:%SZ")
            + "</startDate>" + scheduling_xml[found.end():])


def extract_schedule_config(schedule_elem):
    """Capture the reusable parts of a parent schedule so they can be copied onto a new app.

    The recurrence/timing (`schedule` subtree) and `scannerAppliance` subtree are taken verbatim;
    the option profile is intentionally NOT copied (the new schedule uses the app's default)."""
    if schedule_elem is None:
        return None
    return {
        "type": _findtext(schedule_elem, "type", "VULNERABILITY"),
        "scheduling_xml": _fix_scheduling(_subtree_xml(schedule_elem, "scheduling")),  # recurrence/timing
        "scanner_xml": _subtree_xml(schedule_elem, "scannerAppliance"),
        "notification_xml": _subtree_xml(schedule_elem, "notification"),  # parent's distribution groups + recipients, copied verbatim
    }


def _default_scheduling_xml():
    """Build a <scheduling> block per the WasScanSchedule XSD (SchedulePlanification). Used only
    when bootstrapping a root domain that has no parent schedule to copy - the common path reuses
    the parent's <scheduling> subtree verbatim instead."""
    s = Global.QualysDefaultSchedule or {}
    freq = str(s.get("frequency", "WEEKLY")).upper()
    week_day = str(s.get("weekDays", "SUNDAY")).upper()
    hour = int(s.get("startHour", 3))
    tz = str(s.get("timeZone", "UTC"))

    start = datetime.now(timezone.utc).replace(hour=hour % 24, minute=0, second=0, microsecond=0)
    if start <= datetime.now(timezone.utc):
        start += timedelta(days=1)  # WAS wants a start date in the future
    start_date = start.strftime("%Y-%m-%dT%H:%M:%SZ")

    if freq == "DAILY":
        occ_type = "DAILY"
        occurrence = "<occurrence><dailyOccurrence><everyNDays>1</everyNDays></dailyOccurrence></occurrence>"
    elif freq == "MONTHLY":
        occ_type = "MONTHLY"
        occurrence = ("<occurrence><monthlyOccurrence>"
                      "<occurDayNbInMonth><dayNbMonth>1</dayNbMonth></occurDayNbInMonth>"
                      "</monthlyOccurrence></occurrence>")
    else:
        occ_type = "WEEKLY"
        occurrence = ("<occurrence><weeklyOccurrence><everyNWeeks>1</everyNWeeks>"
                      f"<onDays><WeekDay>{xml_escape(week_day)}</WeekDay></onDays>"
                      "</weeklyOccurrence></occurrence>")
    return ("<scheduling>"
            f"<startDate>{start_date}</startDate>"
            f"<timeZone><code>{xml_escape(tz)}</code></timeZone>"
            f"<occurrenceType>{occ_type}</occurrenceType>"
            f"{occurrence}"
            "</scheduling>")


_default_cfg = None


def default_schedule_cfg():
    """One default schedule config, built once and reused for every default schedule in a run so
    a bootstrapped parent and its subdomains get an identical schedule."""
    global _default_cfg
    if _default_cfg is None:
        _default_cfg = {
            "type": "VULNERABILITY",
            "scheduling_xml": _default_scheduling_xml(),
            "scanner_xml": "<scannerAppliance><type>EXTERNAL</type></scannerAppliance>",
        }
    return _default_cfg


# ---------------------------------------------------------------------------
# Write operations
# ---------------------------------------------------------------------------
_tag_id_cache = {}


def resolve_tag_ids(names):
    """Tag ids for a comma-separated list of tag names (QUALYS_ENSURE_TAGS). Unknown names are
    reported once and skipped - tags cannot be created through the API."""
    ids = []
    for name in [n.strip() for n in (names or "").split(",") if n.strip()]:
        key = name.lower()
        if key not in _tag_id_cache:
            body = ('<ServiceRequest><filters>'
                    f'<Criteria field="name" operator="EQUALS">{xml_escape(name)}</Criteria>'
                    '</filters></ServiceRequest>')
            try:
                root = _request("POST", "/qps/rest/2.0/search/am/tag", body)
            except QualysError as e:
                print(f"[!] Qualys: could not look up tag '{name}' ({e})")
                _tag_id_cache[key] = None
            else:
                tag = _find(root, "Tag")
                _tag_id_cache[key] = _findtext(tag, "id") if tag is not None else None
                if not _tag_id_cache[key]:
                    print(f"[!] Qualys: no tag named '{name}' exists - baseline tag skipped")
        if _tag_id_cache[key]:
            ids.append(_tag_id_cache[key])
    return ids


def create_webapp(host, url, parent_elem, default_profile_id):
    """Create a web app. Subdomains inherit defaultProfile/tags from the parent app; root domains
    use the configured default option profile. Returns (new_id, app_default_profile_id)."""
    parts = [f"<name>{xml_escape(host)}</name>",
             f"<url>{xml_escape(normalize_url(url))}</url>"]   # never with a trailing slash
    profile_id = ""
    if parent_elem is not None:
        dp = _find(parent_elem, "defaultProfile")
        profile_id = _findtext(dp, "id") if dp is not None else ""
    if not profile_id:
        profile_id = str(default_profile_id or "")
    if profile_id:
        parts.append(f"<defaultProfile><id>{xml_escape(profile_id)}</id></defaultProfile>")
    if parent_elem is not None:
        tag_ids = _tag_ids(parent_elem)       # subdomain: whatever the root app carries
        source = "inherited from the parent"
    else:
        tag_ids = resolve_tag_ids(Global.QualysEnsureTags)   # new root: nothing to inherit
        source = "baseline (QUALYS_ENSURE_TAGS)"
    if tag_ids:
        parts.append("<tags><set>"
                     + "".join(f"<Tag><id>{xml_escape(t)}</id></Tag>" for t in tag_ids)
                     + "</set></tags>")
        if '-v' in Flags:
            print(f"[v] Qualys: {len(tag_ids)} tag(s) on {host} - {source}")
    elif '-v' in Flags:
        print(f"[v] Qualys: no tags to set on {host}")
    body = f"<ServiceRequest><data><WebApp>{''.join(parts)}</WebApp></data></ServiceRequest>"
    root = _request("POST", "/qps/rest/3.0/create/was/webapp", body)
    wa = _find(root, "WebApp")
    new_id = _findtext(wa, "id") if wa is not None else ""
    if not new_id:
        raise QualysError(f"web app for {host} was created but no id was returned")
    return new_id, profile_id


def create_schedule(new_app_id, host, schedule_cfg, app_profile_id):
    """Create an ACTIVE scan schedule on the new app via QPS 3.0, copying recurrence (<scheduling>)
    and scanner from the parent schedule (or the default template) and using the app's default
    option profile. Element order follows the WasScanSchedule XSD: name, active, type,
    progressiveScanning, target, profile, scheduling. Distribution groups / recipients are attached
    afterwards via the new WAS REST API (sync_distribution_group) - the QPS 3.0 XML schema has no
    element for them."""
    cfg = schedule_cfg or default_schedule_cfg()
    scanner_xml = cfg.get("scanner_xml") or "<scannerAppliance><type>EXTERNAL</type></scannerAppliance>"
    parts = [
        f"<name>{xml_escape('AutoEASM schedule - ' + host)}</name>",
        "<active>true</active>",  # fresh schedules must be enabled
        f"<type>{xml_escape(cfg.get('type') or 'VULNERABILITY')}</type>",
        f"<progressiveScanning>{xml_escape(Global.QualysProgressiveScanning)}</progressiveScanning>",
        f"<target><webApps><set><WebApp><id>{xml_escape(str(new_app_id))}</id></WebApp></set></webApps>{scanner_xml}</target>",
    ]
    if app_profile_id:
        parts.append(f"<profile><id>{xml_escape(str(app_profile_id))}</id></profile>")
    parts.append(_future_start(_fix_scheduling(cfg.get("scheduling_xml")))
                 or _default_scheduling_xml())
    body = f"<ServiceRequest><data><WasScanSchedule>{''.join(parts)}</WasScanSchedule></data></ServiceRequest>"
    root = _request("POST", "/qps/rest/3.0/create/was/wasscanschedule", body)
    sched = _find(root, "WasScanSchedule")
    return _findtext(sched, "id") if sched is not None else ""


# ---------------------------------------------------------------------------
# New WAS REST 1.0 API (portal host) - used only for distribution groups, which the QPS 3.0 XML
# schema cannot represent. Groups are referenced by UUID. Both APIs share schedule ids, so we
# create via QPS 3.0 then attach the group here. Basic auth is attempted; if the portal requires
# a browser session this is skipped and the schedule still exists (just without the group).
# ---------------------------------------------------------------------------
_newapi_disabled = False


def _new_api_request(method, path, json_body=None):
    url = Global.QualysWebUIURL.rstrip("/") + path
    headers = {"Content-Type": "application/json", "Accept": "application/json", "X-Requested-With": "AutoEASM"}
    if '-v' in Flags:
        print(f"[v] Qualys(new) {method} {path}")
    try:
        resp = requests.request(method, url, auth=(Global.QualysUsername, Global.QualysPassword),
                                headers=headers, json=json_body, timeout=120)
    except requests.RequestException as e:
        raise QualysError(f"new-API request to {path} failed: {e}")
    if resp.status_code in (401, 403):
        raise QualysError(f"new WAS REST API rejected Basic auth (HTTP {resp.status_code}) - portal session auth may be required")
    if resp.status_code >= 400:
        raise QualysError(f"new-API {path}: HTTP {resp.status_code} - {resp.text[:200]}")
    try:
        return resp.json() if resp.content else {}
    except ValueError:
        raise QualysError(f"new-API {path}: non-JSON response - {resp.text[:200]}")


def _unwrap_schedule(payload):
    """Return the schedule object from a new-API response, handling a possible wrapper."""
    if not isinstance(payload, dict):
        return {}
    if "settingsSection" in payload or "schedulingSection" in payload:
        return payload
    for key in ("data", "ServiceResponse", "response", "Schedule", "schedule"):
        value = payload.get(key)
        if isinstance(value, list) and value:
            value = value[0]
        if isinstance(value, dict):
            inner = _unwrap_schedule(value)
            if inner:
                return inner
    return payload


def get_schedule_json(schedule_id):
    return _unwrap_schedule(_new_api_request("GET", f"/was/rest/1.0/scan/schedule/{schedule_id}"))


def distribution_uuids_of_schedule(schedule_id):
    """Return (completion_group_uuids, notification_group_uuids) from the parent schedule so each
    can be copied into the matching section on the child - the two groups may differ."""
    obj = get_schedule_json(schedule_id)
    settings = obj.get("settingsSection") or {}
    notif = obj.get("notificationSection") or {}
    return (settings.get("completionDistributionEmailListUuids") or [],
            notif.get("distributionEmailListUuids") or [])


def _build_put_body(obj, completion_uuids, notification_uuids):
    """Body for PUT /was/rest/1.0/scan/schedule/{id}.

    The endpoint wants the WHOLE schedule echoed back, with two shape fixes, or it answers
    HTTP 500 and the distribution group is never attached:
      * basicSection.owner must be the owner id, not the owner object;
      * targetSection.webApps must be a list of web app ids - the GET returns them under the
        lowercase key "webapps" as objects, and an empty webApps is rejected with
        "At least one target is required".
    Only the notification fields are changed; profile, scheduling and progressive scanning are
    left exactly as the schedule already has them."""
    body = copy.deepcopy(obj or {})

    basic = body.get("basicSection") or {}
    owner = basic.get("owner")
    if isinstance(owner, dict):
        basic["owner"] = owner.get("id")
    body["basicSection"] = basic

    target = body.get("targetSection") or {}
    app_ids = []
    for key in ("webApps", "webapps", "webAppIds"):
        for item in (target.get(key) or []):
            app_id = item.get("id") if isinstance(item, dict) else item
            if app_id and app_id not in app_ids:
                app_ids.append(app_id)
    target["webApps"] = app_ids
    body["targetSection"] = target

    settings = body.get("settingsSection") or {}
    settings["completionDistributionEmailListUuids"] = list(completion_uuids or [])
    settings["sendMail"] = Global.QualysScheduleSendMail   # off by default: no all-admin blast
    body["settingsSection"] = settings

    recipients = (Global.QualysScheduleRecipients or "").strip()
    notif = body.get("notificationSection") or {}
    notif["distributionEmailListUuids"] = list(notification_uuids or [])
    notif["notification"] = bool(notification_uuids) or bool(recipients)
    notif["notificationRecipients"] = recipients
    notif["notificationMessage"] = (Global.QualysNotificationMessage
                                    or "A Qualys scan is scheduled to start soon.")
    body["notificationSection"] = notif
    return body


def apply_schedule_settings(child_schedule_id, parent_schedule_id):
    """Best-effort: configure the created schedule's notifications via the new WAS REST API - turn
    the completion email off (settingsSection.sendMail) to stop the all-admins blast, attach the
    distribution group(s) (copied from the parent or the QUALYS_DISTRIBUTION_UUIDS override), and
    set the pre-scan notification message + additional recipient. No-op if the new API is
    unavailable - the schedule already exists either way."""
    global _newapi_disabled
    if _newapi_disabled or not child_schedule_id:
        return
    try:
        override = [u.strip() for u in (Global.QualysDistributionUuids or "").split(",") if u.strip()]
        if override:
            completion_uuids = notification_uuids = override
        elif parent_schedule_id:  # copy each group from the parent's matching section
            completion_uuids, notification_uuids = distribution_uuids_of_schedule(parent_schedule_id)
        else:
            completion_uuids = notification_uuids = []
        body = _build_put_body(get_schedule_json(child_schedule_id), completion_uuids, notification_uuids)
        _new_api_request("PUT", f"/was/rest/1.0/scan/schedule/{child_schedule_id}", body)
        print(f"[+] Qualys: schedule {child_schedule_id} configured (completion email off; "
              f"notification group(s): {len(notification_uuids)}, from parent schedule {parent_schedule_id or '-'})")
    except QualysError as e:
        print(f"[!] Qualys: could not configure schedule {child_schedule_id} via new API ({e})")
        if "401" in str(e) or "403" in str(e):
            _newapi_disabled = True  # portal needs session auth -> stop retrying this run


def launch_scan(webapp_id, host, profile_id):
    """Launch an immediate one-off vulnerability scan with the Fast_Scan option profile."""
    body = ("<ServiceRequest><data><WasScan>"
            f"<name>{xml_escape('AutoEASM Fast_Scan - ' + host)}</name>"
            "<type>VULNERABILITY</type>"
            "<target>"
            f"<webApp><id>{xml_escape(str(webapp_id))}</id></webApp>"
            "<scannerAppliance><type>EXTERNAL</type></scannerAppliance>"
            "</target>"
            f"<profile><id>{xml_escape(str(profile_id))}</id></profile>"
            f"<sendMail>{'true' if Global.QualysScanSendMail else 'false'}</sendMail>"
            "</WasScan></data></ServiceRequest>")
    root = _request("POST", "/qps/rest/3.0/launch/was/wasscan", body)
    ws = _find(root, "WasScan")
    return _findtext(ws, "id") if ws is not None else ""


# ---------------------------------------------------------------------------
# Notification
# ---------------------------------------------------------------------------
def notify_launched_scans(launched, dry_run=False):
    """Email a single summary of the immediate scans launched this run to QualysNotifyEmail."""
    if not launched:
        return
    lines = [f"AutoEASM launched {len(launched)} Qualys WAS Fast_Scan scan(s):", ""]
    for item in launched:
        lines.append(f"- {item['host']}  (web app id: {item['webapp_id']}, scan id: {item['scan_id']})")
    body = "\n".join(lines)
    subject = f"AutoEASM: {len(launched)} Qualys WAS scan(s) launched"

    if dry_run:
        print(f"[*] [dry-run] Would email this notification to {Global.QualysNotifyEmail}:\n{body}")
        return
    if not Global.SMTPHost:
        print(f"[!] SMTP not configured (SMTP_HOST empty) - notification not emailed. Summary:\n{body}")
        return
    if not (Global.QualysNotifyEmail or "").strip():
        print(f"[!] QUALYS_NOTIFY_EMAIL not set - launched-scan summary not emailed. Summary:\n{body}")
        return
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = Global.SMTPFrom or Global.SMTPUser or Global.QualysNotifyEmail
        msg["To"] = Global.QualysNotifyEmail
        msg.set_content(body)
        with smtplib.SMTP(Global.SMTPHost, Global.SMTPPort, timeout=30) as server:
            if Global.SMTPUseTLS:
                server.starttls()
            if Global.SMTPUser:
                server.login(Global.SMTPUser, Global.SMTPPassword)
            server.send_message(msg)
        print(f"[+] Notification email sent to {Global.QualysNotifyEmail}")
    except Exception as e:
        print(f"[!] Could not send notification email: {e}")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def _abort(message, tag="[e]"):
    """Log why the sync stopped before any asset was processed and record it, so the reason ends up
    in the report instead of only in the console output."""
    print(f"{tag} Qualys: {message}")
    Global.QualysWASResults.append(QualysWebAppResult("sync aborted", "", "error", message=message))


def sync_qualys_was(dry_run=False):
    """Entry point. Sync live web services into Qualys WAS (see module docstring).

    When dry_run=True, all reads run live but nothing is created/scheduled/scanned/emailed -
    intended actions are logged and recorded as "would-..." results instead."""
    print("[*] Qualys WAS sync..." + (" (dry-run)" if dry_run else ""))
    Global.QualysWASResults = []
    try:
        resolve_qualys_credentials()
    except QualysError as e:
        _abort(str(e))
        return
    if not credentials_configured():
        _abort("credentials are not configured - skipping the Qualys WAS sync", "[!]")
        return

    patterns = _refresh_ignore_patterns()
    if patterns:
        print(f"[*] Qualys: {len(patterns)} exclude pattern(s) loaded (QUALYS_IGNORE_HOSTS + qualys_exclude.txt)")

    assets = build_asset_list()
    if not assets:
        _abort("no live websites were found, so there was nothing to sync", "[!]")
        return
    assets.sort(key=lambda a: 0 if is_root_level(a[0], Global.Domains) else 1)  # parents first

    try:
        fast_scan_id = resolve_option_profile_id(Global.QualysScanProfileName)
    except QualysError as e:
        _abort(str(e))
        return
    if not fast_scan_id:
        _abort(f"option profile '{Global.QualysScanProfileName}' was not found in Qualys - cannot launch scans")
        return
    try:
        default_profile_id = resolve_option_profile_id(Global.QualysDefaultProfile) or fast_scan_id
    except QualysError:
        default_profile_id = fast_scan_id

    results = Global.QualysWASResults
    launched = []
    parent_cache = {}  # parent_host -> (webapp_id_or_None, schedule_cfg_or_None)

    def record(host, parent, action, webapp_id="", scan_id="", message=""):
        results.append(QualysWebAppResult(host, parent, action, webapp_id, scan_id, message))
        tag = {"skipped": "[=]", "created": "[+]", "scheduled": "[+]", "scanned": "[+]",
               "error": "[e]"}.get(action.replace("would-", ""), "[*]")
        print(f"{tag} Qualys {action}: {host}" + (f" - {message}" if message else ""))

    def schedule_cfg_for_existing(app_id):
        sid = find_schedule_for_webapp(app_id)
        if not sid:
            return None
        cfg = extract_schedule_config(get_schedule(sid))
        if cfg is not None:
            cfg["parent_schedule_id"] = sid  # so subdomains can copy the parent's distribution group
        return cfg

    def ensure_parent(parent_host):
        """Return (parent_id_or_None, schedule_cfg_or_None), bootstrapping a missing parent."""
        if parent_host in parent_cache:
            return parent_cache[parent_host]
        existing = find_webapp(parent_host, "https://" + parent_host)
        if not existing:      # plenty of roots exist only as www.<domain>
            existing = find_webapp("www." + parent_host, "https://www." + parent_host)
        if existing:
            parent_cache[parent_host] = (existing, schedule_cfg_for_existing(existing))
            return parent_cache[parent_host]
        if is_ignored(parent_host):  # don't bootstrap an ignored parent
            parent_cache[parent_host] = (None, None)
            return parent_cache[parent_host]
        if dry_run:
            record(parent_host, parent_host, "would-create",
                   message="parent root not in Qualys; would create app + schedule + Fast_Scan")
            parent_cache[parent_host] = (None, None)
            return parent_cache[parent_host]
        try:
            new_id, app_profile = create_webapp(parent_host, "https://" + parent_host, None, default_profile_id)
            record(parent_host, parent_host, "created", webapp_id=new_id, message="parent root bootstrapped")
            sid = create_schedule(new_id, parent_host, None, app_profile)
            record(parent_host, parent_host, "scheduled", webapp_id=new_id, message=f"schedule {sid} (default)")
            apply_schedule_settings(sid, None)  # sendMail off + notification message/recipient; group via override if set
            scan_id = launch_scan(new_id, parent_host, fast_scan_id)
            record(parent_host, parent_host, "scanned", webapp_id=new_id, scan_id=scan_id)
            launched.append({"host": parent_host, "webapp_id": new_id, "scan_id": scan_id})
            parent_cache[parent_host] = (new_id, default_schedule_cfg())  # children copy this exact schedule config
        except QualysError as e:
            record(parent_host, parent_host, "error", message=str(e))
            parent_cache[parent_host] = (None, None)
        return parent_cache[parent_host]

    for host, url in assets:
        parent = root_key(host, Global.Domains)
        if is_ignored(host):
            record(host, parent, "skipped", message="ignored (QUALYS_IGNORE_HOSTS)")
            continue
        try:
            existing = find_webapp(host, url)
            if existing:
                record(host, parent, "skipped", webapp_id=existing, message="already exists in Qualys WAS")
                if is_root_level(host, Global.Domains) and host not in parent_cache:
                    parent_cache[host] = (existing, schedule_cfg_for_existing(existing))
                continue

            is_root = is_root_level(host, Global.Domains)
            canonical = root_key(host, Global.Domains)
            parent_elem = None
            schedule_cfg = None
            if not is_root or canonical != host:   # subdomain, or a www./port variant of the root
                p_id, schedule_cfg = ensure_parent(canonical)
                if p_id and not dry_run:
                    parent_elem = get_webapp(p_id)  # inherit profile/tags from the parent app

            if dry_run:
                src = "parent schedule" if schedule_cfg else "default schedule template"
                record(host, parent, "would-create", message=f"create app + {src} + Fast_Scan")
                launched.append({"host": host, "webapp_id": "(dry-run)", "scan_id": "(dry-run)"})
                continue

            new_id, app_profile = create_webapp(host, url, parent_elem, default_profile_id)
            record(host, parent, "created", webapp_id=new_id)
            sid = create_schedule(new_id, host, schedule_cfg, app_profile)
            record(host, parent, "scheduled", webapp_id=new_id,
                   message=f"schedule {sid}" + ("" if schedule_cfg else " (default)"))
            apply_schedule_settings(sid, (schedule_cfg or {}).get("parent_schedule_id"))  # sendMail off + notification + copy parent's group
            scan_id = launch_scan(new_id, host, fast_scan_id)
            record(host, parent, "scanned", webapp_id=new_id, scan_id=scan_id)
            launched.append({"host": host, "webapp_id": new_id, "scan_id": scan_id})
            if is_root and canonical == host:
                parent_cache[host] = (new_id, default_schedule_cfg())  # subdomains copy this schedule
        except QualysError as e:
            record(host, parent, "error", message=str(e))
            continue

    notify_launched_scans(launched, dry_run)
    created = sum(1 for r in results if r.action == "created")
    scanned = sum(1 for r in results if r.action == "scanned")
    skipped = sum(1 for r in results if r.action == "skipped")
    errors = sum(1 for r in results if r.action == "error")
    print(f"[+] Qualys WAS sync done: {created} created, {scanned} scanned, {skipped} skipped, "
          f"{errors} errors" + (" (dry-run)" if dry_run else ""))
