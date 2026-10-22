# AutoEASM Web UI

A local web interface for AutoEASM: configure scans with toggles instead of CLI flags,
launch them, watch live console output and open generated reports.

![themes](https://img.shields.io/badge/themes-10-blueviolet)

## Features

- **Toggles instead of flags** — every AutoEASM module (subdomain enumeration, Nuclei,
  fuzzing, WAF bypass, social checks, Postman/LeakiX, Qualys WAS, Burp sending…) is a
  switch; disabled modules automatically add their disable-flag to the command.
- **Live command preview** — the equivalent `python main.py ...` command is built
  on the fly while you toggle, with a copy button.
- **Scan monitor** — live console output with colour-coded lines, a *Skip stage*
  button (the web equivalent of Ctrl+C: a flag-file watchdog raises KeyboardInterrupt
  inside the scan process, so it works regardless of the console type) and a *Stop*
  button (kills the whole scan tree).
- **Reports** — lists every generated `*.html` report with dates and one-click opening.
- **API keys** — LeakiX / SecurityTrails keys are passed to the scan through
  environment variables instead of the command line.
- **10 themes** — design system with dark/light/milk/tiffany/rolex/police/vintage/
  cyber/vyshyvanka/anime palettes, persisted per browser.
- **Config persistence** — the whole scan configuration is remembered in localStorage.

## Requirements

- Python 3.10+ with Flask (`pip install flask`)
- AutoEASM toolchain installed (see the main README)

## Run

```bash
cd AutoEASM
python WebUI/app.py
```

Open http://127.0.0.1:7788. The server binds to localhost only.

Stopping the server with Ctrl+C does not kill a running scan — it continues and
still writes its report to the project folder.

## API

| Method | Endpoint | Purpose |
| --- | --- | --- |
| POST | `/api/scan/start` | Build the command from the JSON config and launch the scan |
| GET | `/api/scan/status?since=N` | Poll captured console lines from line N |
| POST | `/api/scan/skip` | Skip the current stage (Ctrl+C equivalent) |
| POST | `/api/scan/stop` | Terminate the scan and its child tools |
| GET | `/api/reports` | List generated HTML reports |
| GET | `/api/logs` | List run directories in `Logs/` |

One scan at a time (the AutoEASM pipeline is single-instance); a second start
returns HTTP 409.

## Notes

- The scan child runs in its own process group with Ctrl+C disabled, so a stray
  Ctrl+C in the server terminal never kills a running scan.
- Per-scan console logs are written to `WebUI/history/` (git-ignored).
- The `-waf` flag (added upstream) is not exposed in the UI yet — it can be passed
  manually through the copied command if needed.