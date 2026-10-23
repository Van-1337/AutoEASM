#!/usr/bin/env python3
"""Standalone tester for the AWS Security Agent sync (-asa), without the EASM discovery pipeline.

Use --dry-run first: it only reads from AWS and prints what it WOULD add.

Examples:
  python security_agent_sync_test.py -d example.com --assets https://example.com,https://api.example.com --dry-run -v
  python security_agent_sync_test.py -d example.com --assets-file assets.txt --space <agent-space-id>
"""
import argparse
import Global


def main():
    parser = argparse.ArgumentParser(description="Standalone AWS Security Agent sync tester")
    parser.add_argument("-d", "--domain", action="append", default=[], dest="domains", help="Root domain; repeatable")
    parser.add_argument("--assets", default="", help="Comma-separated live web service URLs")
    parser.add_argument("--assets-file", default="", help="File with one web service URL per line")
    parser.add_argument("--region", default="", help="Security Agent region (overrides env)")
    parser.add_argument("--space", default="", help="Agent space id (overrides env)")
    parser.add_argument("--dry-run", action="store_true", help="Read-only: print intended actions only")
    parser.add_argument("-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    if args.v:
        Global.Flags.append("-v")
    Global.SecurityAgentRegion = args.region or Global.SecurityAgentRegion
    Global.SecurityAgentSpaceId = args.space or Global.SecurityAgentSpaceId
    Global.Domains = [d.strip().lower() for d in args.domains if d.strip()]
    assets = [a.strip() for a in args.assets.split(",") if a.strip()]
    if args.assets_file:
        with open(args.assets_file, "r", encoding="utf-8") as f:
            assets.extend(line.strip() for line in f if line.strip())
    Global.HTTPAssets = assets or ["https://" + d for d in Global.Domains]

    from Scan.SecurityAgent import sync_security_agent
    sync_security_agent(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
