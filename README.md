# ReconX v1.2

All-in-one recon pipeline:
**BBOT → httpx → subzy → katana → (gowitness) → (FFUF)**

> Use only on assets you are authorized to test.

## What's new in v1.2
- **SecurityTrails key injection** into BBOT (`-c modules.securitytrails.api_key=...`) so BBOT's `securitytrails` module loads even if you haven't edited `~/.config/bbot/bbot.yml`.
- **Safe fallback**: if BBOT fails to produce `subdomains.txt`, ReconX will (a) create an empty subdomains file, (b) run **SecurityTrails direct augment** when a key is available, and (c) skip later stages gracefully if still no subdomains are found — while still writing a `SUMMARY.md`.

## Install prerequisites

```bash
# BBOT
pipx install bbot

# ProjectDiscovery tools (need Go)
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# subzy
go install -v github.com/LukaSikic/subzy@latest

# gowitness (requires Chrome/Chromium installed)
go install github.com/sensepost/gowitness@latest

# FFUF (optional, for content discovery)
go install github.com/ffuf/ffuf/v2@latest

# Optional API server
pip install fastapi uvicorn
```

## SecurityTrails API
- Put your key in a `.env` file (see `.env.example`) and run with `--env-file bbot.env`.
- ReconX will:
  1. **Auto-enable** the BBOT module `securitytrails` if a key is present (via injection).
  2. Optionally **augment** subdomains directly from SecurityTrails (`--st-augment`).

## Run (CLI)

```bash
# single target
python3 reconx.py -d example.com -o reconx-out

# BBOT with SecurityTrails module + direct augment
python3 reconx.py -d example.com \
  --env-file bbot.env \
  --bbot-modules securitytrails \
  --st-augment

# Include FFUF
python3 reconx.py -d example.com \
  --ffuf-wordlist /usr/share/seclists/Discovery/Web-Content/common.txt \
  --ffuf-extensions php,asp,aspx,js \
  --ffuf-threads 80 \
  --ffuf-match-codes 200-299,301,302,307,401,403,405,500 \
  --ffuf-recursion-depth 1
```

Outputs (per target):
```
output/<domain>/
  bbot/
  httpx/
  subzy/
  katana/
  ffuf/
  screenshots/
  SUMMARY.md
```
