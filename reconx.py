#!/usr/bin/env python3
# ReconX — All-in-One Bug Bounty Recon Orchestrator
# v1.2 (SecurityTrails key injection into BBOT + safe fallback to ST augment)
#
# Pipeline:
#   BBOT -> httpx -> subzy -> katana -> (optional) gowitness screenshots -> (optional) FFUF
#
# Requirements (install first):
#   - bbot            (subdomain enumeration; supports provider modules via API keys)
#   - httpx           (ProjectDiscovery)
#   - subzy           (subdomain takeover detection)
#   - katana          (endpoint discovery/crawling)
#   - gowitness       (screenshots; Chrome/Chromium required)
# Optional:
#   - ffuf            (content discovery / directory fuzzing)
#
# Optional API:
#   - SECURITYTRAILS_KEY in environment (for BBOT module and/or direct augment)
#
# Ethical note: Only use on assets you are authorized to test.
#
import argparse, os, sys, subprocess, shutil, datetime, json, time, ssl, urllib.request, urllib.parse
from pathlib import Path
from urllib.parse import urlparse

BANNER = r"""
   ____                       __  __
  / __ \____ ___  ____ ______/ /_/ /_____  ____ ___
 / / / / __ `__ \/ __ `/ ___/ __/ __/ __ \/ __ `__ \
/ /_/ / / / / / / /_/ / /  / /_/ /_/ /_/ / / / / / /
\____/_/ /_/ /_/\__,_/_/   \__/\__/\____/_/ /_/ /_/  v1.2
      All-in-One Bug Bounty Recon Orchestrator
"""

# Core tools required for baseline pipeline (FFUF is optional)
CORE_TOOLS = ["bbot", "httpx", "subzy", "katana", "gowitness"]

def check_tool(name):
    return shutil.which(name) is not None

def run(cmd, cwd=None, capture=False, env=None):
    try:
        res = subprocess.run(
            cmd, cwd=cwd, capture_output=capture, text=True, check=True, env=env
        )
        return (res.stdout if capture else "")
    except subprocess.CalledProcessError as e:
        if capture and e.stdout:
            return e.stdout
        raise

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)
    return p

def ensure_empty_file(p: Path):
    ensure_dir(p.parent)
    p.write_text("", encoding="utf-8")
    return p

def now_stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def write_lines(path: Path, lines):
    ensure_dir(path.parent)
    with open(path, "w", encoding="utf-8") as f:
        for ln in lines:
            f.write(f"{ln}\n")

def read_lines(path: Path):
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [x.strip() for x in f if x.strip()]

def dedupe(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def load_env_file(path):
    if not path:
        return
    if not os.path.exists(path):
        print(f"[!] .env file not found: {path}")
        return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k,v = line.split("=",1)
            os.environ[k.strip()] = v.strip()

# --------------------------
# External tool runners
# --------------------------
def run_bbot(domain, out_scan_dir: Path, preset="subdomain-enum", modules=None):
    """
    Use BBOT to enumerate subdomains and also export a subdomains.txt.
    We set a custom scan name to get deterministic paths.
    """
    scan_name = f"reconx_{domain.replace('.', '_')}_{now_stamp()}"
    cmd = [
        "bbot",
        "-t", domain,
        "-p", preset,
        "-om", "subdomains",
        "-n", scan_name,
        "-o", str(out_scan_dir),
    ]
    if modules:
        for m in modules:
            cmd += ["-m", m]

    # Inject SecurityTrails key to BBOT via -c if found in environment
    st_key = os.environ.get("SECURITYTRAILS_KEY") or os.environ.get("SECURITYTRAILS_API_KEY")
    if st_key:
        cmd += ["-c", f"modules.securitytrails.api_key={st_key}"]

    print(f"[+] Running BBOT for {domain} …")
    run(cmd, env=os.environ)  # ensure env vars flow through (e.g., SECURITYTRAILS_KEY)
    scan_dir = out_scan_dir / scan_name
    subs_file = scan_dir / "subdomains.txt"
    if not subs_file.exists():
        # fallback: try to derive from output.txt (rare)
        txt = scan_dir / "output.txt"
        if txt.exists():
            subs = []
            for line in read_lines(txt):
                if "]" in line:
                    parts = line.split("]\t", 1)
                    if len(parts) == 2 and parts[0].endswith("DNS_NAME"):
                        subs.append(parts[1].strip())
            subs = dedupe(subs)
            write_lines(subs_file, subs)
    if not subs_file.exists():
        raise RuntimeError("Could not locate BBOT subdomains.txt")
    return subs_file

def run_httpx(subs_file: Path, out_dir: Path, threads=100):
    live_urls = out_dir / "live-urls.txt"
    httpx_json = out_dir / "httpx.jsonl"
    print("[+] Probing with httpx …")
    # compact list of reachable URLs
    cmd_list = [
        "httpx",
        "-l", str(subs_file),
        "-silent",
        "-follow-redirects",
        "-threads", str(threads),
        "-o", str(live_urls),
    ]
    run(cmd_list)
    # JSONL with metadata
    cmd_json = [
        "httpx",
        "-l", str(subs_file),
        "-follow-redirects",
        "-sc", "-title", "-td", "-cl",
        "-j",
        "-threads", str(threads),
        "-o", str(httpx_json),
    ]
    run(cmd_json)
    # normalize live-urls (dedupe)
    urls = dedupe(read_lines(live_urls))
    write_lines(live_urls, urls)
    return live_urls, httpx_json

def run_subzy(subs_file: Path, out_dir: Path, concurrency=50, default_https=True):
    out_txt = out_dir / "subzy.txt"
    print("[+] Checking subdomain takeover with subzy …")
    cmd = [
        "subzy", "run",
        "--targets", str(subs_file),
        "--concurrency", str(concurrency),
        "--hide_fails",
    ]
    if default_https:
        cmd += ["--https"]
    try:
        out = run(cmd, capture=True)
    except Exception:
        # Legacy syntax fallback
        cmd = [
            "subzy",
            "-targets", str(subs_file),
            "-concurrency", str(concurrency),
        ]
        if default_https:
            cmd += ["--https"]
        out = run(cmd, capture=True)
    with open(out_txt, "w", encoding="utf-8") as f:
        f.write(out)
    return out_txt

def run_katana(live_file: Path, out_dir: Path, depth=2, js_crawl=True, rate=150):
    urls_txt = out_dir / "katana-urls.txt"
    urls_json = out_dir / "katana.jsonl"
    print("[+] Crawling with katana …")
    cmd = [
        "katana",
        "-list", str(live_file),
        "-d", str(depth),
        "-rl", str(rate),
        "-silent",
        "-o", str(urls_txt),
        "-j",
    ]
    if js_crawl:
        cmd.insert(3, "-jc")
    with open(urls_json, "w", encoding="utf-8") as jf:
        subprocess.run(cmd, stdout=jf, stderr=subprocess.DEVNULL, check=True, text=True)
    write_lines(urls_txt, dedupe(read_lines(urls_txt)))
    return urls_txt, urls_json

def run_gowitness(live_file: Path, shots_dir: Path):
    ensure_dir(shots_dir)
    print("[+] Screenshotting with gowitness … (Chrome/Chromium required)")
    # Try v3 syntax first
    v3 = [
        "gowitness", "scan", "file",
        "--source", str(live_file),
        "--screenshot-path", str(shots_dir),
        "--write-json",
        "--write-csv",
    ]
    try:
        run(v3)
        return
    except Exception:
        # Fallback to classic v2 syntax
        v2 = [
            "gowitness", "file",
            "-f", str(live_file),
            "-P", str(shots_dir),
        ]
        run(v2)

# --------------------------
# SecurityTrails Direct Augment
# --------------------------
def securitytrails_enum(domain: str, out_dir: Path, children_only: bool=False):
    """
    Query SecurityTrails subdomains and write to securitytrails-subdomains.txt
    Requires env var SECURITYTRAILS_KEY or SECURITYTRAILS_API_KEY.
    Endpoint: GET https://api.securitytrails.com/v1/domain/{domain}/subdomains
    Header: APIKEY: <key>
    """
    key = os.environ.get("SECURITYTRAILS_KEY") or os.environ.get("SECURITYTRAILS_API_KEY")
    out = out_dir / "securitytrails-subdomains.txt"
    if not key:
        print("[!] SECURITYTRAILS_KEY not set; skipping direct augment.")
        write_lines(out, [])
        return out

    qs = urllib.parse.urlencode({"children_only": "true" if children_only else "false"})
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?{qs}"
    req = urllib.request.Request(url, headers={"APIKEY": key, "Accept": "application/json"})
    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
            data = json.loads(r.read().decode("utf-8", "ignore"))
            subs = []
            for s in data.get("subdomains", []):
                subs.append(f"{s}.{domain}")  # reconstruct FQDN
            write_lines(out, dedupe(subs))
    except Exception as e:
        print(f"[!] SecurityTrails augment failed: {e}")
        write_lines(out, [])
    return out

# --------------------------
# FFUF helpers + runner
# --------------------------
def sanitize_host_dir(url: str) -> str:
    u = urlparse(url)
    host = (u.netloc or "").replace(":", "_")
    return (u.scheme or "http") + "_" + (host or "unknown")

def base_of(url: str) -> str:
    u = urlparse(url)
    if not u.scheme or not u.netloc:
        return None
    return f"{u.scheme}://{u.netloc}"

def parse_ffuf_json(path: Path) -> list:
    """
    Robust parser: supports -of json (object with 'results') or NDJSON from -json.
    Returns list of URLs.
    """
    urls = []
    try:
        txt = path.read_text(encoding="utf-8", errors="ignore")
        txt_strip = txt.strip()
        if not txt_strip:
            return []
        if txt_strip[0] == "{":
            obj = json.loads(txt_strip)
            for r in obj.get("results", []):
                u = r.get("url") or r.get("host") or ""
                if u:
                    urls.append(u)
        else:
            # newline-delimited JSON
            for line in txt.splitlines():
                line=line.strip()
                if not line: continue
                try:
                    rec = json.loads(line)
                    u = rec.get("url") or rec.get("host") or ""
                    if u:
                        urls.append(u)
                except:
                    pass
    except Exception:
        pass
    return dedupe(urls)

def run_ffuf(live_file: Path, out_dir: Path, wordlist: str, extensions: str,
             threads: int, match_codes: str, recursion_depth: int, rate: int, timeout: int):
    """
    For each live host, fuzz directories: https://host/FUZZ
    Writes per-host ffuf JSON + aggregates matches into ffuf-urls.txt
    """
    ensure_dir(out_dir)
    live = read_lines(live_file)
    bases = dedupe([b for b in (base_of(u) for u in live) if b])
    all_hits = []
    for b in bases:
        host_dir = ensure_dir(out_dir / sanitize_host_dir(b))
        out_json = host_dir / "ffuf.json"
        cmd = [
            "ffuf",
            "-w", wordlist,
            "-u", f"{b}/FUZZ",
            "-t", str(threads),
            "-mc", match_codes,
            "-timeout", str(timeout),
            "-of", "json",
            "-o", str(out_json),
            "-s",
        ]
        if rate and rate > 0:
            cmd += ["-rate", str(rate)]
        if extensions:
            ex = ",".join([e.lstrip(".") for e in extensions.split(",") if e.strip()])
            if ex:
                cmd += ["-e", ex]
        if recursion_depth and recursion_depth > 0:
            cmd += ["-recursion", "-recursion-depth", str(recursion_depth)]

        print(f"[+] FFUF fuzzing {b} …")
        try:
            run(cmd)
            hits = parse_ffuf_json(out_json)
            all_hits.extend(hits)
        except Exception as e:
            print(f"[!] FFUF failed for {b}: {e}")

    out_hits = out_dir / "ffuf-urls.txt"
    write_lines(out_hits, dedupe(all_hits))
    return out_hits

# --------------------------
# Summary writer
# --------------------------
def write_summary(summary_path: Path, domain: str, paths: dict):
    subs = read_lines(paths["bbot_subs"])
    live = read_lines(paths["httpx_live"])
    kat  = read_lines(paths["katana_txt"])

    vuln_lines = []
    if paths["subzy_txt"].exists():
        for ln in read_lines(paths["subzy_txt"]):
            if "VULNERABLE" in ln.upper() or "[ VULNERABLE" in ln:
                vuln_lines.append(ln)

    ffuf_hits = read_lines(paths.get("ffuf_hits", Path(""))) if paths.get("ffuf_hits") else []
    st_subs = read_lines(paths.get("st_augment_file", Path(""))) if paths.get("st_augment_file") else []

    md = []
    md.append(f"# ReconX Summary — {domain}\n")
    md.append(f"- Subdomains found (BBOT): **{len(subs)}**")
    if st_subs:
        md.append(f"- SecurityTrails augment: **{len(st_subs)}** subdomains merged")
    md.append(f"- Live hosts (httpx): **{len(live)}**")
    md.append(f"- Endpoints (katana): **{len(kat)}**")
    md.append(f"- Potential takeovers (subzy): **{len(vuln_lines)}**")
    if ffuf_hits:
        md.append(f"- FFUF hits: **{len(ffuf_hits)}**")
    md.append("\n## Key Files\n")
    for k, p in paths.items():
        md.append(f"- **{k}**: `{p}`")
    if vuln_lines:
        md.append("\n## subzy Highlights")
        md.extend([f"- {ln}" for ln in vuln_lines[:50]])
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md))

# --------------------------
# Main
# --------------------------
def main():
    print(BANNER)
    ap = argparse.ArgumentParser(description="ReconX — All-in-One recon pipeline")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-d", "--domain", help="Single target domain (e.g., example.com)")
    g.add_argument("-L", "--domains-list", help="File with one domain per line")

    ap.add_argument("-o", "--out", default="output", help="Base output directory")
    ap.add_argument("--threads", type=int, default=100, help="httpx threads")
    ap.add_argument("--katana-depth", type=int, default=2, help="katana crawl depth")
    ap.add_argument("--rate", type=int, default=150, help="katana rate-limit per sec")
    ap.add_argument("--no-screenshots", action="store_true", help="Skip gowitness")
    ap.add_argument("--no-subzy", action="store_true", help="Skip takeover check")

    # API keys / modules
    ap.add_argument("--env-file", help="Path to .env with API keys (e.g., SECURITYTRAILS_KEY=...)")
    ap.add_argument("--bbot-modules", nargs="*", default=[], help="Extra BBOT modules (e.g., securitytrails shodan censys)")

    # SecurityTrails direct augment
    ap.add_argument("--st-augment", action="store_true",
                    help="Augment subdomains with direct SecurityTrails API and merge with BBOT")
    ap.add_argument("--st-children-only", action="store_true",
                    help="SecurityTrails: only immediate subdomains (children_only=true)")

    # FFUF
    ap.add_argument("--ffuf-wordlist", help="Path to wordlist (e.g., SecLists/Discovery/Web-Content/common.txt)")
    ap.add_argument("--ffuf-extensions", default="", help="Comma-separated extensions for -e (e.g., php,asp,aspx,js)")
    ap.add_argument("--ffuf-threads", type=int, default=40, help="FFUF -t threads")
    ap.add_argument("--ffuf-match-codes", default="200-299,301,302,307,401,403,405,500",
                    help="FFUF -mc matcher (status codes/ranges)")
    ap.add_argument("--ffuf-recursion-depth", type=int, default=0, help="FFUF -recursion-depth (0 disables recursion)")
    ap.add_argument("--ffuf-rate", type=int, default=0, help="FFUF -rate requests/sec (0 = unlimited)")
    ap.add_argument("--ffuf-timeout", type=int, default=10, help="FFUF -timeout seconds")
    ap.add_argument("--no-ffuf", action="store_true", help="Skip FFUF step")

    args = ap.parse_args()

    # .env
    if args.env_file:
        load_env_file(args.env_file)

    # Check core tools
    missing = [t for t in CORE_TOOLS if not check_tool(t)]
    if missing:
        print(f"[!] Missing required tools: {', '.join(missing)}")
        print("    Install them first (bbot, httpx, subzy, katana, gowitness).")
        sys.exit(1)

    base_out = ensure_dir(Path(args.out))

    # Targets
    if args.domain:
        domains = [args.domain.strip()]
    else:
        domains = [x.strip() for x in read_lines(Path(args.domains_list))]
    domains = [d for d in domains if d and not d.startswith("#")]
    if not domains:
        print("[!] No domains to process.")
        sys.exit(1)

    for dom in domains:
        t0 = time.time()
        print(f"\n========== TARGET: {dom} ==========")
        target_dir = ensure_dir(base_out / dom)
        bbot_dir   = ensure_dir(target_dir / "bbot")
        httpx_dir  = ensure_dir(target_dir / "httpx")
        subzy_dir  = ensure_dir(target_dir / "subzy")
        kat_dir    = ensure_dir(target_dir / "katana")
        ffuf_dir   = ensure_dir(target_dir / "ffuf")
        shot_dir   = ensure_dir(target_dir / "screenshots")

        # Auto-enable bbot securitytrails module if key present and user didn't specify modules
        auto_modules = list(args.bbot_modules)
        if not auto_modules:
            if os.environ.get("SECURITYTRAILS_KEY") or os.environ.get("SECURITYTRAILS_API_KEY"):
                auto_modules.append("securitytrails")

        # 1) BBOT → subdomains.txt (with safe fallback)
        try:
            bbot_subs = run_bbot(dom, bbot_dir, modules=auto_modules)
        except Exception as e:
            print(f"[!] BBOT failed or did not create subdomains.txt: {e}")
            # Create an empty subdomains file so the pipeline can still proceed with ST augment
            bbot_subs = ensure_empty_file(bbot_dir / "subdomains.txt")

        # 2) Optional SecurityTrails direct augment and merge
        merged_subs = bbot_subs
        st_file = None
        should_try_st = args.st_augment or os.environ.get("SECURITYTRAILS_KEY") or os.environ.get("SECURITYTRAILS_API_KEY")
        if should_try_st:
            st_file = securitytrails_enum(dom, bbot_dir, children_only=args.st_children_only)
            merged_subs = bbot_dir / "subdomains_merged.txt"
            subs = dedupe(read_lines(bbot_subs) + read_lines(st_file))
            write_lines(merged_subs, subs)

        # If after merge we still have zero subs, abort gracefully for this domain
        final_subs = read_lines(merged_subs)
        if len(final_subs) == 0:
            print("[!] No subdomains discovered after BBOT and SecurityTrails; skipping remaining stages for this target.")
            # create empty placeholders so we can still write a summary
            httpx_live = ensure_empty_file(httpx_dir / "live-urls.txt")
            httpx_json = ensure_empty_file(httpx_dir / "httpx.jsonl")
            kat_txt    = ensure_empty_file(kat_dir / "katana-urls.txt")
            kat_json   = ensure_empty_file(kat_dir / "katana.jsonl")
            subzy_txt  = ensure_empty_file(subzy_dir / "skipped.txt")
            # summary only
            paths = {
                "bbot_subs": merged_subs,
                "httpx_live": httpx_live,
                "httpx_json": httpx_json,
                "subzy_txt": subzy_txt,
                "katana_txt": kat_txt,
                "katana_json": kat_json,
                "screenshots_dir": shot_dir,
            }
            if st_file:
                paths["st_augment_file"] = st_file
            write_summary(target_dir / "SUMMARY.md", dom, paths)
            dt = time.time() - t0
            print(f"[i] Skipped later stages; wrote summary. (elapsed {int(dt)}s)")
            continue

        targets_subs = merged_subs

        # 3) httpx
        httpx_live, httpx_json = run_httpx(targets_subs, httpx_dir, threads=args.threads)

        # 4) subzy (optional)
        subzy_txt = Path("")
        if not args.no_subzy:
            subzy_txt = run_subzy(targets_subs, subzy_dir)

        # 5) katana
        kat_txt, kat_json = run_katana(httpx_live, kat_dir, depth=args.katana_depth, rate=args.rate)

        # 6) gowitness (optional)
        if not args.no_screenshots:
            run_gowitness(httpx_live, shot_dir)

        # 7) FFUF (optional; only if wordlist provided)
        ffuf_hits = Path("")
        if not args.no_ffuf and args.ffuf_wordlist:
            ffuf_hits = run_ffuf(
                httpx_live, ffuf_dir,
                wordlist=args.ffuf_wordlist,
                extensions=args.ffuf_extensions,
                threads=args.ffuf_threads,
                match_codes=args_ffuf_match_codes if (args_ffuf_match_codes := args.ffuf_match_codes) else "200-299,301,302,307,401,403,405,500",
                recursion_depth=args.ffuf_recursion_depth,
                rate=args.ffuf_rate,
                timeout=args.ffuf_timeout,
            )
        elif not args.no_ffuf:
            print("[!] Skipping FFUF (no --ffuf-wordlist provided)")

        # 8) Summary
        paths = {
            "bbot_subs": merged_subs,
            "httpx_live": httpx_live,
            "httpx_json": httpx_json,
            "subzy_txt": subzy_txt if subzy_txt else (subzy_dir / "skipped.txt"),
            "katana_txt": kat_txt,
            "katana_json": kat_json,
            "screenshots_dir": shot_dir,
        }
        if ffuf_hits:
            paths["ffuf_hits"] = ffuf_hits
        if st_file:
            paths["st_augment_file"] = st_file

        write_summary(target_dir / "SUMMARY.md", dom, paths)

        dt = time.time() - t0
        print(f"[✓] Done: {dom}  (took {int(dt)}s)")
        print(f"    → Results: {target_dir}")

if __name__ == "__main__":
    main()
