import io
import os
import re
import sys
import json
import time
import logging
import warnings
from math import ceil
from datetime import datetime
from contextlib import redirect_stdout, redirect_stderr
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

from rich import box
from rich.console import Console
from rich.table import Table
from rich.align import Align
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text

# Import modules
import modules.recon as recon
import modules.scanning as scanning
import modules.dns as dns
import modules.tech as tech
import modules.osint as osint

# Console ko asli stdout se bind kar diya, taake scan ke dauran modules ka print
# (jo hum quiet karte hain) rich ke output ko na bigade.
console = Console(file=sys.stdout)

# ───────────────────────── TURBO SETTINGS ─────────────────────────
MAX_THREADS = 20            # live host check ke liye parallel workers
SOFT_TIMEOUT = 40           # itni der baad "slow, background mein chal raha hai" dikhao
DISCOVERY_TIMEOUT = 120     # subdomain discovery ki hard limit (seconds)
DNS_TIMEOUT = 90            # DNS intel ki hard limit
TECH_TIMEOUT = 60           # tech stack ki hard limit
OSINT_TIMEOUT = 60          # OSINT ki hard limit
FINGERPRINT_TIMEOUT = 60    # live host check ke har chunk ki hard limit

# Ye errors normal hain (secured DNS zone transfer reject karta hai), report mein nahi dikhane
NOISE_RE = re.compile(
    r"AXFR|FORMERR|zone transfer|NOTAUTH|query failed|NoNameservers|not authoritative",
    re.IGNORECASE,
)


BANNER_ART = [
    "███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗███████╗ ██████╗ █████╗ ███╗   ██╗",
    "██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔════╝██╔════╝██╔══██╗████╗  ██║",
    "███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║███████╗██║     ███████║██╔██╗ ██║",
    "╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║╚════██║██║     ██╔══██║██║╚██╗██║",
    "███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝███████║╚██████╗██║  ██║██║ ╚████║",
    "╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝",
]

# Red team look: upar bright red se neeche dark blood red tak
GRADIENT = ["#ff2a2a", "#ee0000", "#d10000", "#b80000", "#9c0000", "#7a0000"]


def print_banner():
    art_width = len(BANNER_ART[0])

    body = Text(justify="center")

    body.append("☠ CLASSIFIED // EYES ONLY ☠\n\n", style="bold red")

    if console.width >= art_width + 8:
        # Bada ASCII banner (gradient ke saath)
        for line, color in zip(BANNER_ART, GRADIENT):
            body.append(line + "\n", style=f"bold {color}")
    else:
        # Chhoti terminal window ke liye compact banner
        body.append("S H A D O W S C A N\n", style="bold #ff2a2a")

    body.append("\n")
    body.append("━━━━━━━  ", style="#7a0000")
    body.append("Recon in silence. Strike from the shadows.", style="italic bold #ff5555")
    body.append("  ━━━━━━━\n\n", style="#7a0000")

    body.append(" v1.0 ", style="bold black on #ff2a2a")
    body.append("  ●  ", style="red")
    body.append("Created by Eth Mesum", style="italic #ff5555")

    # Panel/border hata diya, banner seedha center mein print hota hai
    console.print(Align.center(body))
    console.print()


# ───────────────────────── RESULT FORMATTING ─────────────────────────
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
EMAIL_RE = re.compile(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", re.IGNORECASE)
MAX_ROWS = 10  # table mein har list ke kitne items dikhane hain (poora data JSON report mein hota hai)


def bare_domain(target):
    """'https://Example.com:8080/x' -> 'example.com'"""
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", target.strip().lower())
    return re.split(r"[/?#:]", value.split("@")[-1])[0].strip(".")


def to_lines(value):
    """Kisi bhi type (str/list/dict) ko saaf lines ki list mein badal deta hai (ANSI colors hata kar)."""
    if value is None:
        return []
    if isinstance(value, dict):
        lines = []
        for k, v in value.items():
            if isinstance(v, (list, tuple, set)):
                v = ", ".join(str(x) for x in v)
            lines.append(f"{k}: {v}")
        return lines
    if isinstance(value, (list, tuple, set)):
        lines = []
        for item in value:
            lines.extend(to_lines(item))
        return lines
    text = ANSI_RE.sub("", str(value))
    return [l.rstrip() for l in text.splitlines() if l.strip()]


def host_label(item):
    """Live host ka ek saaf label (str, dict ya tuple, jo bhi module de)."""
    if isinstance(item, dict):
        name = next((str(item[k]) for k in ("url", "host", "domain", "subdomain") if item.get(k)), None)
        if name is None:
            return ", ".join(f"{k}={v}" for k, v in item.items())
        extra = [str(item[k]) for k in ("status", "status_code", "title") if item.get(k)]
        return f"{name}  ({' | '.join(extra)})" if extra else name
    if isinstance(item, (list, tuple)):
        return "  ".join(str(x) for x in item)
    return ANSI_RE.sub("", str(item)).strip()


def extract_emails(value, domain):
    """
    OSINT output (string ya list) se asli email addresses nikalta hai.
    Returns (saare unique emails, sirf target domain wale emails).
    """
    found = sorted({m.lower() for m in EMAIL_RE.findall("\n".join(to_lines(value)))})
    mine = [e for e in found if e.endswith("@" + domain) or e.endswith("." + domain)]
    return found, mine


def dns_values(key, value):
    """DNS record ki values ko alag-alag lines mein todta hai."""
    if not isinstance(value, str):
        return to_lines(value)
    if key in ("A", "AAAA", "NS", "MX", "CAA"):
        return [v for v in value.split(", ") if v]
    if key in ("TXT", "DMARC"):
        return [v for v in re.split(r'(?<="), (?=")', value) if v]
    return to_lines(value)


def tech_lines(value):
    lines = to_lines(value)
    if len(lines) == 1 and ", " in lines[0] and ":" not in lines[0]:
        lines = lines[0].split(", ")
    return lines


def list_cell(summary, items, hint="see JSON report"):
    """Pehli line mein count/summary, phir max MAX_ROWS items, phir '+N more'."""
    cell = Text()
    cell.append(summary, style="bold white")
    for item in items[:MAX_ROWS]:
        cell.append("\n" + item, style="white")
    if len(items) > MAX_ROWS:
        cell.append(f"\n… +{len(items) - MAX_ROWS} more ({hint})", style="dim")
    return cell


def build_report_table(target, domain, results, errors, elapsed):
    table = Table(
        title="☠ SHADOWSCAN RECON REPORT ☠",
        title_style="bold red",
        show_header=True,
        header_style="bold white on #8b0000",
        border_style="red",
        box=box.HEAVY_EDGE,
        show_lines=False,
        padding=(0, 1),
    )
    table.add_column("Metric", style="bold red", no_wrap=True, vertical="top")
    table.add_column("Result", style="white", overflow="fold")

    def warning(key):
        return Text(f"⚠ {short_error(errors[key])}", style="yellow") if key in errors else None

    # Overview
    table.add_row("Target", Text(domain or target, style="bold white"))
    table.add_row("Scan Time", Text(f"{elapsed:.1f}s"))
    table.add_section()

    # Discovery + live hosts
    subs = [host_label(s) for s in results["subdomains"]]
    cell = list_cell(f"{len(subs)} found", subs)
    if warning("discovery"):
        cell.append("\n").append_text(warning("discovery"))
    table.add_row("Subdomains", cell)

    live = [host_label(h) for h in results["live_hosts_list"]]
    cell = list_cell(f"{len(live)} alive", live)
    if warning("fingerprint"):
        cell.append("\n").append_text(warning("fingerprint"))
    table.add_row("Live Hosts", cell)
    table.add_section()

    # DNS: har record type ki apni row
    dns_info = results["dns_info"]
    if isinstance(dns_info, dict) and dns_info:
        for key, value in dns_info.items():
            table.add_row(f"DNS · {key}", Text("\n".join(dns_values(key, value))))
    else:
        text = "\n".join(to_lines(dns_info)) or "No records found"
        table.add_row("DNS", Text(text, style="yellow" if text.startswith(("⚠", "No ")) else "white"))
    table.add_section()

    # Tech stack
    tech = tech_lines(results["tech_stack"])
    text = "\n".join(tech) or "No tech detected"
    table.add_row("Tech Stack", Text(text, style="yellow" if text.startswith(("⚠", "No ")) else "white"))
    table.add_section()

    # Emails: pehle target domain wale
    all_emails, mine = results["emails"], results["emails_on_target"]
    summary = f"{len(all_emails)} found"
    if all_emails:
        summary += f"  ({len(mine)} on {domain})"
    shown = mine if mine else all_emails
    cell = list_cell(summary, shown)
    if warning("osint"):
        cell.append("\n").append_text(warning("osint"))
    table.add_row("Emails", cell)

    return table


def save_report(target, results):
    os.makedirs("reports", exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", target).lstrip(".")
    path = os.path.join("reports", f"{safe}_{stamp}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, default=str)
    return path


def save_debug_log(target, text):
    """Modules ka jo noisy output chhupaya gaya, wo yahan save hota hai (debugging ke liye)."""
    if not text.strip():
        return None
    os.makedirs("reports", exist_ok=True)
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", target).lstrip(".")
    path = os.path.join("reports", f"{safe}_debug.log")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


# ───────────────────────── NOISE SILENCING ─────────────────────────
class QuietIO(io.TextIOBase):
    """Modules ke print()/stderr ko screen par jaane se rokta hai aur memory mein jama karta hai."""

    def __init__(self):
        self.lines = []

    def write(self, s):
        if s:
            self.lines.append(s)
        return len(s)

    def flush(self):
        pass

    def getvalue(self):
        return "".join(self.lines)


def clean_noise(value):
    """AXFR / FORMERR jaisi lines result se hata deta hai (list/dict/str sab par kaam karta hai)."""
    if isinstance(value, str):
        return "\n".join(l for l in value.splitlines() if not NOISE_RE.search(l)).strip()
    if isinstance(value, dict):
        return {
            k: clean_noise(v)
            for k, v in value.items()
            if not NOISE_RE.search(str(k)) and not (isinstance(v, str) and NOISE_RE.search(v))
        }
    if isinstance(value, (list, tuple, set)):
        return [clean_noise(v) for v in value if not (isinstance(v, str) and NOISE_RE.search(v))]
    return value


def short_error(error):
    """Error ko chhota aur saaf message banata hai."""
    if isinstance(error, TimeoutError):
        return str(error)
    msg = str(error).strip().splitlines()[0] if str(error).strip() else type(error).__name__
    if NOISE_RE.search(msg):
        return "non-critical DNS error (details in debug log)"
    return msg[:120]


# ───────────────────────── THREADING ENGINE ─────────────────────────
def safe_call(func, *args):
    """Function chalata hai aur (result, error) return karta hai, thread ke andar crash nahi hota."""
    try:
        return func(*args), None
    except Exception as exc:
        return None, exc


def chunk_list(items, parts):
    """List ko barabar hisson mein baant deta hai (har thread ko ek hissa)."""
    if not items:
        return []
    size = ceil(len(items) / parts)
    return [items[i:i + size] for i in range(0, len(items), size)]


def dedupe(items):
    seen, unique = set(), []
    for item in items:
        key = json.dumps(item, sort_keys=True, default=str) if isinstance(item, (dict, list)) else item
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def run_scan(steps, fingerprint_func, log, status):
    """
    Pipeline scheduler:
      - Sab steps (discovery, dns, tech, osint) ek saath start hote hain, slow wale pehle.
      - Discovery khatam hote hi live-host check shuru ho jata hai, DNS/Tech/OSINT ka intezaar kiye bina.
      - Har step ki apni hard limit hai. Soft limit par "background mein chal raha hai" dikhata hai
        aur baaki kaam rukta nahi.

    steps: [(key, label, func, args, hard_timeout), ...]
    log(msg): finished-step message print karne ke liye
    status(text): spinner ka text update karne ke liye
    """
    pool = ThreadPoolExecutor(max_workers=len(steps) + MAX_THREADS)
    meta = {}
    pending = set()

    outputs, errors = {}, {}
    state = {"fp_total": 0, "fp_done": 0, "live": [], "fp_errors": [], "subdomains": []}

    def submit(kind, key, label, func, args, hard):
        fut = pool.submit(safe_call, func, *args)
        now = time.monotonic()
        meta[fut] = {
            "kind": kind, "key": key, "label": label, "hard_s": hard,
            "hard": now + hard, "soft": now + SOFT_TIMEOUT, "noted": False,
        }
        pending.add(fut)

    def finish(m, result, error):
        if m["kind"] == "step":
            outputs[m["key"]] = result
            if error:
                errors[m["key"]] = error
                log(f"[bold red]✘[/bold red] {m['label']} failed: {short_error(error)}")
            else:
                log(f"[bold green]✔[/bold green] {m['label']} done.")

            if m["key"] == "discovery":
                subs = list(result or [])
                state["subdomains"] = subs
                log(f"   Found [bold]{len(subs)}[/bold] subdomains.")
                chunks = chunk_list(subs, MAX_THREADS)
                state["fp_total"] = len(chunks)
                if chunks:
                    log(f"[bold green]»[/bold green] Fingerprinting {len(subs)} hosts ({len(chunks)} threads)...")
                for i, chunk in enumerate(chunks):
                    submit("fp", i, "Fingerprinting", fingerprint_func, (chunk,), FINGERPRINT_TIMEOUT)
                if not chunks:
                    log("   Fingerprinting skipped (no subdomains).")
        else:
            state["fp_done"] += 1
            if error:
                state["fp_errors"].append(error)
            elif result:
                state["live"].extend(result)
            if state["fp_done"] == state["fp_total"]:
                if state["fp_errors"]:
                    log(f"[bold yellow]![/bold yellow] {len(state['fp_errors'])} fingerprint chunk(s) "
                        f"failed/timed out: {short_error(state['fp_errors'][0])}")
                log("[bold green]✔[/bold green] Fingerprinting Layer done.")

    # Slow steps pehle submit hote hain (priority)
    for key, label, func, args, hard in steps:
        submit("step", key, label, func, args, hard)

    while pending:
        done, _ = wait(pending, timeout=0.25, return_when=FIRST_COMPLETED)
        for fut in done:
            pending.discard(fut)
            result, error = fut.result()
            finish(meta[fut], result, error)

        now = time.monotonic()
        for fut in list(pending):
            m = meta[fut]
            if now >= m["hard"]:
                fut.cancel()
                pending.discard(fut)
                finish(m, None, TimeoutError(f"timed out after {m['hard_s']}s"))
            elif m["kind"] == "step" and not m["noted"] and now >= m["soft"]:
                m["noted"] = True
                log(f"[yellow]⏳[/yellow] {m['label']} is slow, still running in background...")

        running = sorted({meta[f]["label"] for f in pending})
        status("Running: " + ", ".join(running) + "..." if running else "Finalizing...")

    pool.shutdown(wait=False, cancel_futures=True)

    return {
        "outputs": outputs,
        "errors": errors,
        "subdomains": state["subdomains"],
        "live_hosts": dedupe(state["live"]),
    }


def main():
    os.system("clear")
    print_banner()

    target = console.input(
        "[bold red]┌──([/bold red][bold white]root㉿shadowscan[/bold white][bold red])-[[/bold red][white]~/target[/white][bold red]][/bold red]\n"
        "[bold red]└─#[/bold red] [bold white]Enter target domain : [/bold white]"
    ).strip()
    if not target:
        console.print("[bold red]Error: Target domain is required![/bold red]")
        return

    results = {
        "target": target,
        "subdomains_count": 0,
        "live_hosts": 0,
        "dns_info": "Not found",
        "tech_stack": "Not found",
        "emails": [],
    }

    # Slow steps (discovery, dns) pehle, fast steps (tech, osint) baad mein
    steps = [
        ("discovery", "Discovery Layer", recon.get_subdomains, (target,), DISCOVERY_TIMEOUT),
        ("dns", "DNS Intelligence", dns.run_dns_recon, (target,), DNS_TIMEOUT),
        ("tech", "Tech Stack Analysis", tech.get_tech_stack, (target,), TECH_TIMEOUT),
        ("osint", "Intelligence Layer", osint.harvest_emails, (target,), OSINT_TIMEOUT),
    ]

    # Modules ka noisy output (AXFR/FORMERR etc.) screen par nahi aayega
    quiet = QuietIO()
    logging.disable(logging.CRITICAL)
    warnings.filterwarnings("ignore")

    started = time.perf_counter()

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console, transient=True) as progress:
        task = progress.add_task("Starting...", total=None)

        def status(text):
            progress.update(task, description=text)

        with redirect_stdout(quiet), redirect_stderr(quiet):
            scan = run_scan(steps, scanning.check_live_hosts, progress.console.print, status)

    elapsed = time.perf_counter() - started
    outputs, errors = scan["outputs"], scan["errors"]

    domain = bare_domain(target)
    emails_all, emails_mine = extract_emails(outputs.get("osint"), domain)

    results["subdomains_count"] = len(scan["subdomains"])
    results["live_hosts"] = len(scan["live_hosts"])
    results["emails"] = emails_all
    results["emails_on_target"] = emails_mine

    dns_clean = clean_noise(outputs.get("dns")) if outputs.get("dns") else None
    if "dns" in errors and not dns_clean:
        results["dns_info"] = f"⚠ {short_error(errors['dns'])}"
    else:
        results["dns_info"] = dns_clean if dns_clean else "No records found"

    tech_out = outputs.get("tech")
    if "tech" in errors and not tech_out:
        results["tech_stack"] = f"⚠ {short_error(errors['tech'])}"
    else:
        results["tech_stack"] = tech_out if tech_out else "No tech detected"

    results["subdomains"] = scan["subdomains"]
    results["live_hosts_list"] = scan["live_hosts"]
    results["failed_steps"] = {k: short_error(v) for k, v in errors.items()}
    results["scan_time_seconds"] = round(elapsed, 1)

    console.print()
    console.print(build_report_table(target, domain, results, errors, elapsed))

    report_path = save_report(target, results)
    debug_path = save_debug_log(target, quiet.getvalue())

    console.print(f"\n[bold red]☠ Reconnaissance Complete.[/bold red] [white]Report saved to[/white] [bold green]{report_path}[/bold green]")
    if debug_path:
        console.print(f"[dim]Module debug output: {debug_path}[/dim]")
    console.print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan cancelled by user.[/bold red]")
        os._exit(130)  # chal rahe threads ka intezaar kiye bina turant exit
    # Timeout hue steps ke thread background mein atke reh sakte hain; report save ho chuki hai,
    # isliye clean exit karte hain taake terminal wapas turant mil jaye.
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)