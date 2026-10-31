from concurrent.futures import ThreadPoolExecutor, as_completed

from modules.utils import normalize_domain, run_cmd, extract_hosts, log

# Hard limits stay below main.py's DISCOVERY_TIMEOUT (120s).
SUBFINDER_LIMIT = 80   # seconds
AMASS_LIMIT = 85
DNSENUM_LIMIT = 60


def _tools(domain):
    """(name, command, hard limit) - sab tools parallel chalte hain."""
    return [
        ("subfinder", ["subfinder", "-d", domain, "-silent", "-timeout", "10", "-max-time", "1"], SUBFINDER_LIMIT),
        ("amass", ["amass", "enum", "-d", domain, "-timeout", "1"], AMASS_LIMIT),
        ("dnsenum", ["dnsenum", "--nocolor", "--noreverse", "--threads", "10", "--timeout", "5", domain], DNSENUM_LIMIT),
    ]


def get_subdomains(target):
    """
    Discovery Layer: subfinder, amass aur dnsenum ek saath (parallel) chalte hain.
    Total time = sabse slow tool ka time (pehle teeno ka total hota tha).
    Timeout par bhi jo partial results mile, wo rakhe jate hain.
    """
    domain = normalize_domain(target)
    found = set()

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {pool.submit(run_cmd, cmd, limit): name for name, cmd, limit in _tools(domain)}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                out, note = fut.result()
            except Exception as exc:  # tool crash se baaki tools na rukein
                log(f"{name} crashed: {exc}")
                continue
            hosts = extract_hosts(out, domain)
            hosts.discard(domain)  # sirf subdomains
            found |= hosts
            log(f"{name}: {len(hosts)} hosts" + (f" | note: {note}" if note else ""))

    return sorted(found)