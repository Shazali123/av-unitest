"""
ABAE Payload B-06 — Multi-Vector Concurrent Storm
==================================================
Sacrificial process: spawned by abae_engine.py from %TEMP%.

This is the MOST AGGRESSIVE payload.  It runs all major behavioral attack
vectors simultaneously on separate threads.  The concurrent multi-vector
pattern is the strongest behavioral signal possible because:

  - No individual action is necessarily malicious alone
  - The COMBINATION and CONCURRENCY is what zero-day threats do
  - Most sandbox AV engines analyse processes in isolation; concurrent
    thread-level activity forces the per-process behavioural analyser
    to observe all signals at once

Threads run in parallel:
  Thread 1 (File Storm)     — Creates and high-entropy-overwrites 300 files
  Thread 2 (Process Burst)  — Spawns 30 cmd.exe children in rapid fire
  Thread 3 (Entropy Cipher) — XOR-encrypts 50 large files simultaneously
  Thread 4 (Registry Churn) — Rapidly writes/deletes 20 registry values

The parent thread acts as a watchdog with a hard 25-second timeout.
If ANY thread is still alive at timeout, we treat it as an anomaly.
"""

import os
import sys
import time
import math
import winreg
import tempfile
import shutil
import threading
import subprocess

SENTINEL         = "PAYLOAD_COMPLETE"
CREATE_NO_WINDOW = 0x08000000
XOR_KEY          = bytes([(i * 97 + 13) % 256 for i in range(256)])

# ── Thread 1: File Storm ──────────────────────────────────────────────────────

def _thread_file_storm(stage_dir: str):
    file_dir = os.path.join(stage_dir, "storm_files")
    os.makedirs(file_dir, exist_ok=True)
    paths = []

    # Rapid creation
    for i in range(300):
        p = os.path.join(file_dir, f"victim_{i:04d}.docx")
        with open(p, "wb") as f:
            f.write(b"DATA_BLOCK_" * 400)          # ~4 KB of low entropy
        paths.append(p)

    # High-entropy overwrite (encryption simulation)
    for p in paths:
        try:
            with open(p, "r+b") as f:
                f.seek(0)
                f.write(os.urandom(4096))
                f.truncate()
        except OSError:
            break

    # Extension rename (.docx → .locked)
    for p in paths:
        try:
            os.rename(p, p.replace(".docx", ".locked"))
        except OSError:
            break

    print("[B06:FileStorm] Complete.", flush=True)


# ── Thread 2: Process Burst ───────────────────────────────────────────────────

def _thread_process_burst():
    lolbin_cmds = ["whoami", "hostname", "ipconfig /all", "net user", "systeminfo"]
    for i in range(30):
        cmd = lolbin_cmds[i % len(lolbin_cmds)]
        try:
            subprocess.run(
                ["cmd.exe", "/c", cmd],
                capture_output=True, timeout=5,
                creationflags=CREATE_NO_WINDOW
            )
            time.sleep(0.02)
        except Exception:
            break
    print("[B06:ProcessBurst] Complete.", flush=True)


# ── Thread 3: Concurrent Entropy Cipher ──────────────────────────────────────

def _xor_bytes(data: bytes) -> bytes:
    key_len = len(XOR_KEY)
    return bytes(b ^ XOR_KEY[i % key_len] for i, b in enumerate(data))


def _thread_entropy_cipher(stage_dir: str):
    enc_dir = os.path.join(stage_dir, "cipher_files")
    os.makedirs(enc_dir, exist_ok=True)
    paths = []

    for i in range(50):
        p = os.path.join(enc_dir, f"blob_{i:03d}.dat")
        with open(p, "wb") as f:
            f.write(os.urandom(8192))   # 8 KB random
        paths.append(p)

    # XOR encrypt in-place (twice — double cipher signal)
    for _ in range(2):
        for p in paths:
            try:
                with open(p, "r+b") as f:
                    data = f.read()
                    f.seek(0)
                    f.write(_xor_bytes(data))
                    f.truncate()
            except OSError:
                break

    print("[B06:EntropyCipher] Complete.", flush=True)


# ── Thread 4: Registry Churn ──────────────────────────────────────────────────

def _thread_registry_churn():
    key_path = r"Software\ABAE_StormTest"
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
        # Rapidly write and delete 20 registry values
        for i in range(20):
            val_name = f"abae_val_{i}"
            winreg.SetValueEx(key, val_name, 0, winreg.REG_SZ, os.urandom(32).hex())
            time.sleep(0.01)
        # Delete all values
        for i in range(20):
            try:
                winreg.DeleteValue(key, f"abae_val_{i}")
            except Exception:
                pass
        winreg.CloseKey(key)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
    except Exception as e:
        print(f"[B06:RegistryChurn] {e}", flush=True)
    print("[B06:RegistryChurn] Complete.", flush=True)


# ── Orchestrator ──────────────────────────────────────────────────────────────

def main():
    stage_dir = tempfile.mkdtemp(prefix="abae_b06_")
    try:
        threads = [
            threading.Thread(target=_thread_file_storm,    args=(stage_dir,), daemon=True),
            threading.Thread(target=_thread_process_burst, daemon=True),
            threading.Thread(target=_thread_entropy_cipher, args=(stage_dir,), daemon=True),
            threading.Thread(target=_thread_registry_churn, daemon=True),
        ]

        # Start all threads simultaneously — the concurrent burst is the signal
        for t in threads:
            t.start()

        # Wait for all threads with a 25-second hard cap
        for t in threads:
            t.join(timeout=25)

        alive = [t.name for t in threads if t.is_alive()]
        if alive:
            print(f"[B06] Warning: {len(alive)} thread(s) still alive at timeout.", flush=True)
        else:
            print("[B06] All threads completed cleanly.", flush=True)

    finally:
        shutil.rmtree(stage_dir, ignore_errors=True)

    print(SENTINEL, flush=True)


if __name__ == "__main__":
    main()
