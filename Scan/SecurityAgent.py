"""AWS Security Agent integration (enabled with the -asa flag).

After discovery, every live domain/subdomain that is not excluded (same exclude list as the Qualys
sync: qualys_exclude.txt + QUALYS_IGNORE_HOSTS) is added as a Target URL to a pentest in AWS
Security Agent - one pentest per root domain, named <prefix><root> (e.g. autoeasm_doctorsam_ua).
The pentest is created when missing. Pentests are NOT started - only their targets are updated.

Security Agent only tests verified domains, and a verified root domain covers its subdomains. The
root's verification is re-checked live (VerifyTargetDomain) because a pentest run fails when the
verification TXT record has been removed from DNS - in that case the record to add is reported.
"""

from Global import Flags
import Global
import re

from Scan.Helpers import SecurityAgentResult
from Scan.Qualys import resolve_parent, build_asset_list, is_ignored, _refresh_ignore_patterns

VERIFIED = "VERIFIED"
TXT_PREFIX = "aws-securityagent-domain-verification="


class SecurityAgentError(Exception):
    pass


def _record(host, parent, action, pentest="", message=""):
    Global.SecurityAgentResults.append(SecurityAgentResult(host, parent, action, pentest, message))
    if '-v' in Flags or action not in ("already-in-pentest", "excluded"):
        tag = "[e]" if action == "error" else "[!]" if action.startswith("skipped") else "[*]"
        print(f"{tag} Security Agent: {action}: {host}" + (f" - {message}" if message else ""))


def get_client():
    try:
        import boto3
    except ImportError:
        raise SecurityAgentError("boto3 is required. Install it with: pip install -U boto3")
    try:
        return boto3.client("securityagent", region_name=Global.SecurityAgentRegion or None)
    except Exception as e:
        raise SecurityAgentError(f"cannot create the securityagent client (update boto3?): {e}")


def _paginate(call, key, **kwargs):
    token = None
    while True:
        page = call(**kwargs, **({"nextToken": token} if token else {}))
        yield from page.get(key, [])
        token = page.get("nextToken")
        if not token:
            return


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------
def pentest_title(root):
    """Pentest name for a root domain: 3-100 chars, letters/digits/hyphens/underscores only."""
    title = re.sub(r"[^A-Za-z0-9_-]", "_", Global.SecurityAgentPentestPrefix + root)
    return title[:100].ljust(3, "_")


def endpoint_host(uri):
    uri = (uri or "").strip().lower()
    return re.sub(r"^[a-z]+://", "", uri).split("/")[0].split(":")[0]


def covering_domain(host, target_domains):
    """Longest target domain name that equals `host` or is its parent, or None."""
    best = None
    for name in target_domains:
        if host == name or host.endswith("." + name):
            if best is None or len(name) > len(best):
                best = name
    return best


def txt_hint(td):
    dns = (td.get("verificationDetails") or {}).get("dnsTxt") or {}
    token = dns.get("token") or ""
    if not token:
        return ""
    name = (dns.get("dnsRecordName") or f"_aws_securityagent-challenge.{td['domainName']}").rstrip(".")
    value = token if token.startswith(TXT_PREFIX) else TXT_PREFIX + token
    return f'add DNS TXT record {name} = "{value}" and keep it (it is re-checked on every pentest run)'


# ---------------------------------------------------------------------------
# AWS lookups
# ---------------------------------------------------------------------------
def resolve_agent_space(sa):
    if Global.SecurityAgentSpaceId:
        return Global.SecurityAgentSpaceId
    spaces = list(_paginate(sa.list_agent_spaces, "agentSpaceSummaries"))
    if len(spaces) == 1:
        return spaces[0]["agentSpaceId"]
    names = ", ".join(f"{s.get('name')} ({s['agentSpaceId']})" for s in spaces) or "none"
    raise SecurityAgentError(f"set SECURITY_AGENT_SPACE_ID - found {len(spaces)} agent spaces: {names}")


def load_target_domains(sa):
    """{domain name: TargetDomain} for all target domains in the account."""
    ids = [s["targetDomainId"] for s in _paginate(sa.list_target_domains, "targetDomainSummaries")]
    result = {}
    for i in range(0, len(ids), 50):
        for td in sa.batch_get_target_domains(targetDomainIds=ids[i:i + 50]).get("targetDomains", []):
            result[td["domainName"].lower().rstrip(".")] = td
    return result


def check_verified(sa, td, dry_run):
    """Re-check verification live; returns (ok, reason)."""
    if dry_run:
        return td.get("verificationStatus") == VERIFIED, td.get("verificationStatusReason", "")
    resp = sa.verify_target_domain(targetDomainId=td["targetDomainId"])
    status = resp.get("status") or resp.get("verificationStatus")
    return status == VERIFIED, resp.get("verificationStatusReason", "")


def ensure_in_agent_space(sa, space_id, td_ids, dry_run):
    space = (sa.batch_get_agent_spaces(agentSpaceIds=[space_id]).get("agentSpaces") or [None])[0]
    if space is None:
        raise SecurityAgentError(f"agent space {space_id} not found")
    current = list(space.get("targetDomainIds") or [])
    missing = [i for i in td_ids if i not in current]
    if missing and not dry_run:
        sa.update_agent_space(agentSpaceId=space_id, targetDomainIds=current + missing)
    return missing


def find_pentest(sa, space_id, title):
    for p in _paginate(sa.list_pentests, "pentestSummaries", agentSpaceId=space_id):
        if p.get("title") == title:
            return sa.batch_get_pentests(pentestIds=[p["pentestId"]], agentSpaceId=space_id)["pentests"][0]
    return None


def create_pentest(sa, space_id, title, urls):
    kwargs = {"agentSpaceId": space_id, "title": title, "testScope": {"type": "WEB_APP"},
              "assets": {"endpoints": [{"uri": u} for u in urls]}}
    if Global.SecurityAgentMaxTaskHours:
        kwargs["maxTaskHours"] = float(Global.SecurityAgentMaxTaskHours)
    if Global.SecurityAgentServiceRole:
        kwargs["serviceRole"] = Global.SecurityAgentServiceRole
    return sa.create_pentest(**kwargs)


def add_endpoints(sa, space_id, pentest, urls):
    assets = dict(pentest.get("assets") or {})
    assets["endpoints"] = list(assets.get("endpoints") or []) + [{"uri": u} for u in urls]
    sa.update_pentest(pentestId=pentest["pentestId"], agentSpaceId=space_id, assets=assets)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def sync_security_agent(dry_run=False):
    print("[*] AWS Security Agent pentest targets sync..." + (" (dry-run)" if dry_run else ""))
    Global.SecurityAgentResults = []
    try:
        sa = get_client()
        space_id = resolve_agent_space(sa)
        target_domains = load_target_domains(sa)
    except Exception as e:
        _record("sync aborted", "", "error", message=str(e))
        return
    _refresh_ignore_patterns()
    roots = sorted({d.strip().lower() for d in Global.Domains if d.strip()})

    # Group live, non-excluded hosts by root domain
    by_root = {}
    for host, url in build_asset_list():
        host = host.lower()
        root = resolve_parent(host, roots)
        if is_ignored(host):
            _record(host, root, "excluded", message="in the Qualys exclude list")
            continue
        by_root.setdefault(root, []).append((host, url))

    for root, hosts in sorted(by_root.items()):
        title = pentest_title(root)
        try:
            domain = covering_domain(root, target_domains)
            if domain is None:
                _record(root, root, "skipped-not-verified", title,
                        f"{root} is not a target domain in Security Agent - add and verify it once in the console")
                continue
            td = target_domains[domain]
            ok, reason = check_verified(sa, td, dry_run)
            if not ok:
                _record(root, root, "skipped-not-verified", title,
                        f"verification of {domain} failed ({reason}); {txt_hint(td)}".rstrip("; "))
                continue
            if ensure_in_agent_space(sa, space_id, [td["targetDomainId"]], dry_run):
                _record(domain, root, "would-attach" if dry_run else "attached", message=f"added to agent space {space_id}")

            pentest = find_pentest(sa, space_id, title)
            existing = {endpoint_host(e.get("uri")) for e in ((pentest or {}).get("assets") or {}).get("endpoints") or []}
            new = [(h, u) for h, u in hosts if h not in existing]
            for h, _ in hosts:
                if h in existing:
                    _record(h, root, "already-in-pentest", title)
            if not new:
                continue
            urls = [u for _, u in new]
            if dry_run:
                action = "would-add" if pentest else "would-create-pentest-and-add"
            elif pentest is None:
                create_pentest(sa, space_id, title, urls)
                action = "added (new pentest)"
            else:
                add_endpoints(sa, space_id, pentest, urls)
                action = "added"
            for h, u in new:
                _record(h, root, action, title, u)
        except Exception as e:
            _record(root, root, "error", title, str(e))

    added = sum(1 for r in Global.SecurityAgentResults if r.action.startswith(("added", "would-add", "would-create")))
    errors = sum(1 for r in Global.SecurityAgentResults if r.action == "error")
    print(f"[+] Security Agent sync done: {added} new target URL(s), {errors} error(s). Pentests were not started.")
