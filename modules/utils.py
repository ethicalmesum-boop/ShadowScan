"""Shared helpers for ShadowScan modules: safe command runner, domain validation, host parsing."""
import os
import re
import sys
import signal
import subprocess

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def normalize_domain(target):
    """
    'https://User@Example.com:8080/path' -> 'example.com'
    Invalid input (spaces, ';', leading '-', etc.) raises ValueError, so nothing
    dangerous ever reaches a command line.
    """
    value = str(target).strip().lower()
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value)
    value = value.split("/")[0].split("?")[0].split("#")[0]
    value = value.split("@")[-1]
    value = re.sub(r":\d+$", "", value).strip(".")
    if not DOMAIN_RE.match(value):
        raise ValueError(f"invalid domain: {target!r}")
    return value


def log(message):
    """Debug/error info goes to stderr (main.py saves it to the debug log, not the screen)."""
    print(message, file=sys.stderr)


def run_cmd(args, timeout):
    """
    Run a command (list of args, NO shell) with a hard timeout.
    Returns (stdout, note). On timeout the process group is killed but the
    partial output collected so far is still returned.
    """
    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            start_new_session=True,  # own process group, so children can be killed too
        )
    except FileNotFoundError:
        return "", f"{args[0]} is not installed"
    except OSError as exc:
        return "", f"{args[0]} could not start: {exc}"

    try:
        out, err = proc.communicate(timeout=timeout)
        note = None if proc.returncode == 0 else (err or "").strip()[:200] or f"exit code {proc.returncode}"
        return out or "", note
    except subprocess.TimeoutExpired:
        try:
            if hasattr(os, "killpg"):
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
        except ProcessLookupError:
            pass
        out, _ = proc.communicate()
        return out or "", f"{args[0]} timed out after {timeout}s (partial results kept)"


def extract_hosts(text, domain):
    """Pull every hostname that ends with `domain` out of any tool's output (any format, ANSI-safe)."""
    text = ANSI_RE.sub("", text or "").lower()
    pattern = re.compile(
        r"(?<![a-z0-9._-])((?:[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?\.)+" + re.escape(domain) + r")(?![a-z0-9-])"
    )
    return {m.group(1) for m in pattern.finditer(text)}