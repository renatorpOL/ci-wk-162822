#!/usr/bin/env python3
"""Next.js pre-filter: cheap GET / + fingerprint check, output only Next.js hosts.

Feeds the scanner only Next.js candidates so the exploit probe isn't wasted on
non-Next.js hosts (the vast majority of raw CT pools).

YIELD FIX (2026-09-10): the old version did ONE pass at a 3s timeout and treated
EVERY failure as "not Next.js". Measured on a 1,500-host sample: 73% DNS-dead,
22.5% resolved, and a ~4% class of hosts that are LIVE but slow / TLS-broken /
connection-dropped (TimeoutError, ClientConnectorError, SSLError). Those were
being silently dropped — and the fingerprint result for such a host is not even
deterministic (the same 5,000-host batch returned 4, then 3, then 0 candidates
across three runs, losing `internal.*` admin subdomains, exactly the high-value
targets). Two-pass now:

  pass 1: 5s timeout, high concurrency  -> fast triage
  pass 2: only the UNRESOLVED set, longer timeout, low concurrency -> recover
          the slow-but-alive hosts
  leftovers: still-unresolved hosts are emitted as CANDIDATES (conservative:
          probing a dead host is cheap, missing a live Next.js app costs a key)

Only the truly dead classes (DNS failure / connection refused) are dropped.
"""
import asyncio
import os
import sys
import time
from collections import Counter

import aiohttp

MARKERS = [b"__next_f", b"/_next/static", b"next/dist", b'id="__next"', b"__NEXT_DATA__"]

# MEASURED 2026-09-18 on 45 known-vulnerable hosts (marker_lift.py):
#   body  /_next/static   43/44 (97.7%)     id="__next"       0/44   <- DEAD (pages-router)
#   body  __next_f        41/44 (93.2%)     __NEXT_DATA__     0/44   <- DEAD (pages-router)
#   body  next/dist        2/44  (4.5%)     hdr x-powered-by 39/44 (88.6%)
#   hdr   x-nextjs-cache  30/44   vary:rsc 31/44   x-nextjs-prerender 30/44
#   random-CT negatives: any body marker 3/27, any header 3/27 (they are usually Next.js, just patched)
# So the header block is a FREE second signal (already in the response) and closes the gap on hosts
# whose HTML is CDN-cached or minified. Body markers are kept (harmless superset) but the header
# check is what recovers hosts the old body-only check called "negative".
HDR_HINTS = ("x-nextjs-cache", "x-nextjs-prerender", "x-matched-path")


def header_hit(headers) -> bool:
    h = {k.lower(): v for k, v in headers.items()}
    return (
        "next.js" in h.get("x-powered-by", "").lower()
        or "rsc" in h.get("vary", "").lower()
        or any(k in h for k in HDR_HINTS)
    )
PREFIXES = ("http://", "https://")

# pass 1 triage / pass 2 recovery
# 2026-09-22: 250 -> 150 (a single pass measured ~483 MB RSS at 250 concurrent
# sockets on this 4 GB/2-core box). NOTE: the swap storm that looked like a
# prefilter-concurrency problem was actually 2.3 GB of the 3.9 GB RAM locked in
# 1,170 RESERVED-AND-UNUSED huge pages (vm.nr_hugepages=1170) — released 2026-09-22,
# which took MemAvailable from 121 MB to 2.6 GB. With that headroom 150 is safe and
# keeps full triage throughput. Override with PREFILTER_CONCURRENCY.
# 2026-10-09: 150 -> 90. Under real pressure (4 prefilters resident + 2.9 GB swap
# in use, load>10 on 2 cores) each 150-concurrency pass ran ~400 MB RSS and the
# box thrashed. On an N-pool host resident cost = N x per-child RSS, so cut the
# per-child number. New prefilters shrink at spawn; running ones finish.
CONCURRENCY = int(os.environ.get("PREFILTER_CONCURRENCY", "90"))
TIMEOUT = int(os.environ.get("PREFILTER_TIMEOUT", "5"))
RETRY_CONCURRENCY = int(os.environ.get("PREFILTER_RETRY_CONCURRENCY", "40"))
RETRY_TIMEOUT = int(os.environ.get("PREFILTER_RETRY_TIMEOUT", "15"))

# Hard cap on hosts passed through unresolved. The unresolved fraction is
# LOAD-DEPENDENT and can snowball: measured 2.5% on a quiet box for one batch,
# but 28% (1,411/5,000) for a dense batch under load. Passing ALL of them to the
# scanner inflates every batch (and the box is a 4 GB/2-core host that must stay
# memory-safe). Measured recovery rate of the unresolved class is ~0.4%, so a
# bounded slice keeps the yield without the blow-up.
MAX_UNPROVEN = int(os.environ.get("PREFILTER_MAX_UNPROVEN", "150"))

# Exception classes that mean "the host is probably DEAD, don't waste a probe":
# DNS failure (no record) / connection refused / unreachable network.
# NOTE: aiohttp's SSL errors SUBCLASS ClientConnectorError, so they must be
# matched FIRST — a Next.js app with a broken cert is still exploitable.
DEAD = (
    aiohttp.ClientConnectorDNSError,
    aiohttp.ClientConnectorError,
)
SSL_LIVE = (
    aiohttp.ClientConnectorSSLError,
    aiohttp.ClientConnectorCertificateError,
)


def _norm(url: str) -> str:
    return url if url.startswith(PREFIXES) else "https://" + url


async def probe(url: str, session: aiohttp.ClientSession, timeout: float):
    """Return (verdict, url) with verdict in {'hit','negative','unknown'}."""
    try:
        async with session.get(_norm(url), ssl=False, allow_redirects=True,
                               timeout=aiohttp.ClientTimeout(total=timeout,
                                                             connect=timeout)) as r:
            body = await r.content.read(131072)  # 128KB
            # any status is fine — auth-gated (401/403) Next.js apps are prime RCE
            # targets and still leak markers in their error/redirect bodies
            if any(m in body for m in MARKERS) or header_hit(r.headers):
                return ("hit", url)
            return ("negative", url)
    except SSL_LIVE:
        return ("unknown", url)       # TLS-broken but alive — retry / keep
    except DEAD:
        return ("negative", url)      # genuinely dead — safe to drop
    except Exception:
        return ("unknown", url)       # slow / dropped — do NOT drop silently


async def run_pass(pairs, conc: int, timeout: float, stats=None):
    conn = aiohttp.TCPConnector(limit=conc, limit_per_host=2, ttl_dns_cache=600)
    async with aiohttp.ClientSession(connector=conn) as session:
        sem = asyncio.Semaphore(conc)

        async def one(u):
            async with sem:
                r = await probe(u, session, timeout)
                if stats is not None:
                    stats["done"] += 1
                return r

        return await asyncio.gather(*[one(u) for u in pairs])


async def main(hosts):
    # PROGRESS: a 300k-host stream gave no signal at all until it finished, which made
    # "is it even scanning?" unanswerable. Emit done/rate/ETA to stderr every 15s.
    stats = {"done": 0, "t0": time.time()}
    total = len(hosts)
    stop = False

    async def watch():
        while not stop:
            await asyncio.sleep(15)
            el = max(time.time() - stats["t0"], 1)
            rate = stats["done"] / el
            eta = int((total - stats["done"]) / rate) if rate > 0 else 0
            print(f"# progress {stats['done']}/{total} {rate:.0f} hosts/s eta {eta}s",
                  file=sys.stderr, flush=True)

    w = asyncio.create_task(watch())
    r1 = await run_pass(hosts, CONCURRENCY, TIMEOUT, stats)
    hits = [u for v, u in r1 if v == "hit"]
    unknown = [u for v, u in r1 if v == "unknown"]

    recovered = []
    still_unknown = []
    if unknown:
        r2 = await run_pass(unknown, RETRY_CONCURRENCY, RETRY_TIMEOUT)
        for v, u in r2:
            if v == "hit":
                recovered.append(u)
            elif v == "unknown":
                still_unknown.append(u)

    # conservative: a host we could never get a clean answer from is passed to the
    # scanner rather than dropped — a wasted probe is cheaper than a missed key.
    stop = True
    w.cancel()
    return hits + recovered, still_unknown, len(r1), len(unknown), len(recovered)


if __name__ == "__main__":
    hosts = [l.strip() for l in sys.stdin if l.strip()]
    if not hosts:
        # keep the completion contract identical to the non-empty path: callers
        # (utah_dispatcher_v6.sh prefilter()) treat a missing summary line as a
        # FAILED run and retry, so never exit silently.
        print("# prefilter: 0/0 nextjs (unknown=0)", file=sys.stderr)
        sys.exit(0)
    confirmed, still_unknown, total, n_unknown, n_recovered = asyncio.run(main(hosts))
    # bounded pass-through: never inflate a batch beyond MAX_UNPROVEN extras
    passed = still_unknown[:MAX_UNPROVEN]
    capped = len(still_unknown) - len(passed)
    for h in confirmed + passed:
        print(h)
    print(f"# prefilter: {len(confirmed)}/{total} nextjs "
          f"(pass2_recovered={n_recovered}/{n_unknown}, "
          f"unproven_passed={len(passed)}, unproven_capped={capped})",
          file=sys.stderr)
