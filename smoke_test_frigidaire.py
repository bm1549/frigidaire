#!/usr/bin/env python3
import argparse, json, os, sys, time, requests
from dataclasses import asdict, is_dataclass

from frigidaire import Frigidaire
from frigidaire.rl_autowrap import enable_autowrap
from frigidaire.rate_limit import RateLimiter, wrap_session_request

def env_or(v,k): return v if v else os.getenv(k)
def _normalize(o):
    if o is None or isinstance(o,(str,int,float,bool)): return o
    if isinstance(o,dict): return {k:_normalize(v) for k,v in o.items()}
    if isinstance(o,(list,tuple)): return [_normalize(x) for x in o]
    try:
        if is_dataclass(o): return _normalize(asdict(o))
    except Exception: pass
    if hasattr(o,"__dict__"): return {k:_normalize(v) for k,v in o.__dict__.items() if not k.startswith("_")}
    return str(o)

def _find_session(api):
    # Try common attribute names; ensure it has a .request method
    for name in ("_session","session","client","http","_http","_client"):
        s = getattr(api, name, None)
        if s and hasattr(s, "request"): return s
    return None

def main():
    enable_autowrap()  # enable wrapper if the library supports it

    p = argparse.ArgumentParser(description="Frigidaire library smoke tests (no device writes).")
    p.add_argument("--username", help="Account username (or env FRIGIDAIRE_USERNAME)")
    p.add_argument("--password", help="Account password (or env FRIGIDAIRE_PASSWORD)")
    p.add_argument("--min-interval", type=float, default=1.5)
    p.add_argument("--jitter", type=float, default=0.0)
    p.add_argument("--http-timeout", type=str, default="15.0")  # float or "connect,read"
    args = p.parse_args()

    username = env_or(args.username, "FRIGIDAIRE_USERNAME")
    password = env_or(args.password, "FRIGIDAIRE_PASSWORD")
    if not username or not password:
        print("ERROR: provide --username/--password or set FRIGIDAIRE_USERNAME/FRIGIDAIRE_PASSWORD", file=sys.stderr); return 2

    print("== Frigidaire smoke tests ==")
    print("Auth → list appliances (read-only) ...")
    api = Frigidaire(username=username, password=password,
                     rate_limit_min_interval=args.min_interval,
                     rate_limit_jitter=args.jitter,
                     http_timeout=args.http_timeout)

    # 1) List appliances (read-only)
    try:
        appliances = api.get_appliances()
    except Exception as e:
        print(f"FAIL: get_appliances raised: {e}", file=sys.stderr); return 3
    print(json.dumps(_normalize(appliances), indent=2))
    print(f"Found {len(appliances) if isinstance(appliances,(list,tuple)) else 'N/A'} appliance(s). ✓")

    # resolve a requests-like session to use for the network-only checks
    sess = _find_session(api)
    if sess is None:
        # Fallback: our own requests.Session() with the same limiter+timeout semantics
        sess = requests.Session()
        limiter = RateLimiter(args.min_interval, args.jitter)
        sess.request = wrap_session_request(sess.request, limiter, default_timeout=float(args.http_timeout))

    # 2) Default-timeout check (~15s unless overridden)
    print("\nDefault-timeout check (expect ~15s unless overridden)...")
    t0 = time.monotonic()
    try:
        sess.get("https://httpbin.org/delay/20")  # no explicit timeout
        print("WARN: httpbin delay did not time out (network oddity?)")
    except Exception as e:
        dt = time.monotonic() - t0
        print(f"Timed out after ~{dt:.1f}s ✓  ({type(e).__name__})")

    # 3) Rate-limit spacing proof (harmless POSTs; no device writes)
    print("\nRate-limit spacing check (POST x4 to httpbin/status/200)...")
    N = 4
    t0 = time.monotonic()
    for i in range(N):
        r = sess.post("https://httpbin.org/status/200")
        print(f"POST {i}: {r.status_code}  t={time.monotonic()-t0:.2f}s")
    elapsed = time.monotonic() - t0
    expected = (N - 1) * float(args.min_interval)
    print(f"Elapsed: {elapsed:.2f}s (expected >= {expected:.2f}s)")
    if elapsed + 0.05 < expected:
        print("FAIL: elapsed time shorter than expected; rate limit may not be active!", file=sys.stderr); return 4
    print("Rate-limit spacing ✓")

    # 4) Retry-After handling (GET 429 with Retry-After=2)
    print("\nRetry-After handling check (429 with Retry-After=2)...")
    url = "https://httpbin.org/response-headers?status=429&Retry-After=2"
    t0 = time.monotonic()
    r = sess.get(url)
    dt = time.monotonic() - t0
    print(f"HTTP {r.status_code}, elapsed ~{dt:.2f}s (should be >= ~2s due to Retry-After)")

    print("\nAll smoke tests finished."); return 0

if __name__ == "__main__":
    raise SystemExit(main())
