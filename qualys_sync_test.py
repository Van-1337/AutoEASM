#!/usr/bin/env python3
"""Standalone tester for the Qualys WAS sync (-q), independent of the EASM discovery pipeline.

It fills the same Global.* lists the real pipeline would, then calls sync_qualys_was() directly.
Use --dry-run first: it performs only read-only lookups and prints what it WOULD create /
schedule / scan / email, without mutating Qualys.

Examples:
  python qualys_sync_test.py -d example.com --assets https://example.com,https://api.example.com --dry-run -v
  python qualys_sync_test.py -d example.com --assets-file assets.txt --user me --password secret
"""
import argparse
import Global


def main():
    parser = argparse.ArgumentParser(description="Standalone Qualys WAS sync tester")
    parser.add_argument("-d", "--domain", action="append", default=[], dest="domains",
                        help="Root (parent) domain; repeatable")
    parser.add_argument("--assets", default="", help="Comma-separated live web service URLs to sync")
    parser.add_argument("--assets-file", default="", help="File with one web service URL per line")
    parser.add_argument("--user", default="", help="Qualys username (overrides env/SSM/hardcoded)")
    parser.add_argument("--password", default="", help="Qualys password (overrides env/SSM/hardcoded)")
    parser.add_argument("--ignore", default="", help="Comma-separated hosts/patterns to skip in Qualys (fnmatch, e.g. 'dev.example.com,*.staging.example.com')")
    parser.add_argument("--ignore-file", default="", help="File with one host/pattern per line to skip in Qualys")
    parser.add_argument("--dry-run", action="store_true", help="Read-only: print intended actions only")
    parser.add_argument("--newapi-get", default="", metavar="SCHEDULE_ID",
                        help="Diagnostic: GET this schedule id via the new WAS REST 1.0 API (portal host) and print the raw JSON, then exit")
    parser.add_argument("-v", action="store_true", help="Verbose: print each Qualys request")
    args = parser.parse_args()

    if args.v:
        Global.Flags.append("-v")
    if args.user:
        Global.QualysUsername = args.user
    if args.password:
        Global.QualysPassword = args.password

    ignore = [Global.QualysIgnoreHosts] if Global.QualysIgnoreHosts else []
    if args.ignore:
        ignore.append(args.ignore)
    if args.ignore_file:
        with open(args.ignore_file, "r", encoding="utf-8") as f:
            ignore.extend(line.strip() for line in f if line.strip())
    Global.QualysIgnoreHosts = ",".join(x for x in ignore if x)

    if args.newapi_get:  # diagnostic: does the portal-host new API accept our Basic auth?
        import json
        from Scan.Qualys import _new_api_request
        print(f"[*] New-API GET schedule {args.newapi_get} from {Global.QualysWebUIURL}")
        try:
            data = _new_api_request("GET", f"/was/rest/1.0/scan/schedule/{args.newapi_get}")
            print(json.dumps(data, indent=2)[:8000])
        except Exception as e:
            print(f"[e] new-API GET failed: {e}")
        return

    Global.Domains = [d.strip() for d in args.domains if d.strip()]

    assets = [a.strip() for a in args.assets.split(",") if a.strip()]
    if args.assets_file:
        with open(args.assets_file, "r", encoding="utf-8") as f:
            assets.extend(line.strip() for line in f if line.strip())
    Global.HTTPAssets = assets
    if not Global.HTTPAssets:
        parser.error("provide assets with --assets or --assets-file")

    from Scan.Qualys import sync_qualys_was  # imported after Global is set up
    sync_qualys_was(dry_run=args.dry_run)

    print("\n=== Results ===")
    for r in Global.QualysWASResults:
        print(f"{r.action:<14} {r.host:<35} parent={r.parent:<25} "
              f"app={r.webapp_id or '-'} scan={r.scan_id or '-'} {r.message}")
    if not Global.QualysWASResults:
        print("(no results)")


if __name__ == "__main__":
    main()
