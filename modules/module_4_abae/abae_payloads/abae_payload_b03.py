"""
ABAE Payload B-03 — Rapid Process Chain Spawning
=================================================
Sacrificial process: spawned by abae_engine.py from %TEMP%.

Behaviour simulated (zero-day / signature-free):
  1. Spawn 50 cmd.exe child processes in rapid succession (process burst)
  2. Each child runs a reconnaissance LOLBIN command:
       whoami, hostname, ipconfig /all, net user, systeminfo
  3. Build a 4-level deep process chain: python → cmd → cmd → cmd → cmd
     (mimics a malware dropper spawning a chain of child loaders)

AV heuristic signals triggered:
  - High-frequency process creation (process burst detection)
  - Python spawning cmd.exe repeatedly (unusual parent-child relationship)
  - cmd.exe running recon commands automatically (scripted enumeration)
  - Deep process chain depth (dropper/loader chain pattern)
"""

import os
import sys
import time
import subprocess

SENTINEL   = "PAYLOAD_COMPLETE"
BURST_COUNT = int(sys.argv[1]) if len(sys.argv) > 1 else 50
INTERVAL_S  = float(sys.argv[2]) if len(sys.argv) > 2 else 0.02  # 20 ms

# LOLBIN recon commands — all legitimate Windows binaries, suspicious in context
RECON_CMDS = [
    "whoami",
    "hostname",
    "ipconfig /all",
    "net user",
    "systeminfo",
    "tasklist",
    "netstat -ano",
    "dir %APPDATA%",
]

CREATE_NO_WINDOW = 0x08000000


def _run_silent(cmd: list, timeout: int = 5):
    """Run a command silently; return (returncode, stdout)."""
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
        return r.returncode, r.stdout
    except subprocess.TimeoutExpired:
        return -2, ""
    except Exception:
        return -1, ""


def phase1_burst_spawn():
    """Rapidly spawn 50 cmd.exe processes, each running a recon command."""
    for i in range(BURST_COUNT):
        cmd_str = RECON_CMDS[i % len(RECON_CMDS)]
        _run_silent(["cmd.exe", "/c", cmd_str])
        time.sleep(INTERVAL_S)
    print(f"[B03] Burst complete: {BURST_COUNT} processes spawned.", flush=True)


def phase2_process_chain():
    """
    Build a 4-level deep process chain by having each child spawn the next.
    python → cmd /c cmd /c cmd /c cmd /c whoami
    This mimics the dropper → loader → payload chain depth AV engines flag.
    """
    chain_cmd = (
        'cmd /c "cmd /c "cmd /c "cmd /c whoami > nul""""'
    )
    _run_silent(["cmd.exe", "/c", chain_cmd], timeout=10)
    print("[B03] Process chain (depth 4) executed.", flush=True)


def phase3_wmi_enumeration():
    """
    Use WMIC for system enumeration — a common UAC bypass / malware recon step.
    wmic is a LOLBIN frequently abused for lateral movement reconnaissance.
    """
    _run_silent(["wmic", "process", "list", "brief"], timeout=10)
    _run_silent(["wmic", "os", "get", "Caption,Version,OSArchitecture"], timeout=10)
    print("[B03] WMI enumeration complete.", flush=True)


def main():
    phase1_burst_spawn()
    phase2_process_chain()
    phase3_wmi_enumeration()
    print(SENTINEL, flush=True)


if __name__ == "__main__":
    main()
