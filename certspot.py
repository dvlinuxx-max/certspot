#!/usr/bin/env python3
"""certspot — enumerate a domain's subdomains from Certificate Transparency logs.

Every publicly trusted TLS certificate is logged to public CT logs. certspot
queries crt.sh for certificates issued to a domain and extracts the unique
hostnames found in them. This is passive OSINT against public data — no packets
are sent to the target.

Use it for recon of domains you own or are authorized to assess.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

__version__ = "1.0.0"


class Colors:
    GREEN = "\033[32m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls) -> None:
        for n in ("GREEN", "DIM", "BOLD", "RESET"):
            setattr(cls, n, "")


def query_crtsh(domain: str, timeout: float, retries: int = 3) -> list[dict]:
    q = urllib.parse.quote(f"%.{domain}")
    url = f"https://crt.sh/?q={q}&output=json"
    req = urllib.request.Request(
        url, headers={"User-Agent": f"certspot/{__version__}"}
    )
    last: Optional[Exception] = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
            return json.loads(body) if body.strip() else []
        except urllib.error.HTTPError as exc:
            last = exc
            if exc.code not in (502, 503, 504):
                raise
        except (urllib.error.URLError, TimeoutError) as exc:
            last = exc
        if attempt < retries - 1:
            time.sleep(2 * (attempt + 1))  # crt.sh is frequently overloaded
    raise last if last else RuntimeError("crt.sh request failed")


def extract_hosts(rows: list[dict], domain: str) -> list[str]:
    hosts: set[str] = set()
    for row in rows:
        for field in ("name_value", "common_name"):
            value = row.get(field, "")
            for name in value.split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name and (name == domain or name.endswith("." + domain)):
                    hosts.add(name)
    return sorted(hosts)


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="certspot", description=__doc__.splitlines()[0])
    p.add_argument("domain", help="apex domain, e.g. example.com")
    p.add_argument("--json", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--version", action="version", version=__version__)
    args = p.parse_args(argv)

    if args.no_color or args.json or not sys.stdout.isatty():
        Colors.disable()
    c = Colors

    domain = args.domain.strip().lower().lstrip("*.")
    try:
        rows = query_crtsh(domain, args.timeout)
    except Exception as exc:  # noqa: BLE001
        print(f"error: crt.sh lookup failed: {exc}", file=sys.stderr)
        return 2

    hosts = extract_hosts(rows, domain)

    if args.json:
        print(json.dumps({"domain": domain, "count": len(hosts), "hosts": hosts}, indent=2))
        return 0

    if not hosts:
        print(f"no certificates found for {domain}")
        return 1

    print(f"{c.BOLD}certspot{c.RESET} {c.DIM}{domain}{c.RESET}  "
          f"{c.GREEN}{len(hosts)}{c.RESET} unique hostnames\n")
    for h in hosts:
        print(f"  {h}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
