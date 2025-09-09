# Optional: FastAPI wrapper to trigger ReconX scans over HTTP
# Start:  uvicorn server:app --host 0.0.0.0 --port 8000
from fastapi import FastAPI, Body
from pydantic import BaseModel
import subprocess

app = FastAPI(title="ReconX API", version="1.2")

class ScanReq(BaseModel):
    domain: str | None = None
    domains_list: str | None = None  # path to file
    out: str = "output"
    env_file: str | None = None
    bbot_modules: list[str] = []
    st_augment: bool = False
    st_children_only: bool = False
    threads: int = 100
    katana_depth: int = 2
    rate: int = 150
    no_screenshots: bool = False
    no_subzy: bool = False
    # FFUF
    ffuf_wordlist: str | None = None
    ffuf_extensions: str = ""
    ffuf_threads: int = 40
    ffuf_match_codes: str = "200-299,301,302,307,401,403,405,500"
    ffuf_recursion_depth: int = 0
    ffuf_rate: int = 0
    ffuf_timeout: int = 10
    no_ffuf: bool = False

@app.post("/scan")
def scan(req: ScanReq = Body(...)):
    cmd = ["python3", "reconx.py", "-o", req.out,
           "--threads", str(req.threads),
           "--katana-depth", str(req.katana_depth),
           "--rate", str(req.rate)]
    if req.env_file:
        cmd += ["--env-file", req.env_file]
    if req.bbot_modules:
        cmd += ["--bbot-modules"] + req.bbot_modules
    if req.st_augment:
        cmd += ["--st-augment"]
    if req.st_children_only:
        cmd += ["--st-children-only"]
    if req.no_screenshots:
        cmd += ["--no-screenshots"]
    if req.no_subzy:
        cmd += ["--no-subzy"]
    # FFUF
    if req.no_ffuf:
        cmd += ["--no-ffuf"]
    if req.ffuf_wordlist:
        cmd += ["--ffuf-wordlist", req.ffuf_wordlist]
        if req.ffuf_extensions:
            cmd += ["--ffuf-extensions", req.ffuf_extensions]
        cmd += ["--ffuf-threads", str(req.ffuf_threads)]
        cmd += ["--ffuf-match-codes", req.ffuf_match_codes]
        cmd += ["--ffuf-recursion-depth", str(req.ffuf_recursion_depth)]
        cmd += ["--ffuf-rate", str(req.ffuf_rate)]
        cmd += ["--ffuf-timeout", str(req.ffuf_timeout)]

    if req.domain:
        cmd += ["-d", req.domain]
    elif req.domains_list:
        cmd += ["-L", req.domains_list]
    else:
        return {"error": "Provide either 'domain' or 'domains_list'."}

    try:
        completed = subprocess.run(cmd, check=True, text=True, capture_output=True)
        return {"ok": True, "stdout": completed.stdout, "stderr": completed.stderr}
    except subprocess.CalledProcessError as e:
        return {"ok": False, "returncode": e.returncode, "stdout": e.stdout, "stderr": e.stderr}
