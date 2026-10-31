import shutil
from concurrent.futures import ThreadPoolExecutor

from modules.utils import normalize_domain, run_cmd, log

DIG_TIMEOUT = 8          # seconds per record lookup
DNSRECON_LIMIT = 45      # fallback tool ki hard limit
ENABLE_DNSMAP = False    # dnsmap brute-force hai aur bahut slow; zaroorat ho to True karo
DNSMAP_LIMIT = 60

RECORD_TYPES = ["A", "AAAA", "NS", "MX", "TXT", "SOA", "CAA"]


def _dig(name, rtype):
    out, note = run_cmd(["dig", "+short", "+time=3", "+tries=1", rtype, name], DIG_TIMEOUT)
    if note:
        log(f"dig {rtype} {name}: {note}")
    # ';;' wali lines dig ke errors hote hain (timeout etc.), result nahi
    return [l.strip() for l in out.splitlines() if l.strip() and not l.startswith(";")]


def run_dns_recon(target):
    """
    DNS Intel Layer: dig se saare record types parallel mein (fast, ~2-3s).
    Zone transfer (AXFR) hata diya: secured servers use reject karte hain (FORMERR/REFUSED)
    aur wahi scan ko atkata tha. dig na ho to dnsrecon fallback chalta hai.
    Returns dict, jo report table mein saaf dikhta hai.
    """
    domain = normalize_domain(target)
    results = {}

    if shutil.which("dig"):
        jobs = {rtype: (domain, rtype) for rtype in RECORD_TYPES}
        jobs["DMARC"] = (f"_dmarc.{domain}", "TXT")
        with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
            futures = {key: pool.submit(_dig, *args) for key, args in jobs.items()}
            for key, fut in futures.items():
                try:
                    values = fut.result()
                except Exception as exc:
                    log(f"dig {key} crashed: {exc}")
                    continue
                if values:
                    results[key] = ", ".join(values)
    else:
        log("dig not found, falling back to dnsrecon")
        out, note = run_cmd(["dnsrecon", "-d", domain, "-t", "std", "--lifetime", "3"], DNSRECON_LIMIT)
        if note:
            log(f"dnsrecon: {note}")
        # AXFR / FORMERR jaisi noisy lines yahin filter ho jati hain
        lines = [
            l.strip() for l in out.splitlines()
            if l.strip().startswith("[*]") and not any(
                bad in l.upper() for bad in ("AXFR", "FORMERR", "FAILED", "ZONE TRANSFER")
            )
        ]
        if lines:
            results["dnsrecon"] = "\n".join(lines)

    if ENABLE_DNSMAP:
        out, note = run_cmd(["dnsmap", domain], DNSMAP_LIMIT)
        if note:
            log(f"dnsmap: {note}")
        if out.strip():
            results["dnsmap"] = out.strip()

    return results