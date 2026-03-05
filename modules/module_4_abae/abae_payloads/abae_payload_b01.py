"""
ABAE Payload B-01 — Ransomware-Style File Churn
================================================
Sacrificial process: spawned by abae_engine.py from %TEMP%.
This process is intended to be killed by the AV behavioural engine.

Behaviour simulated (zero-day / signature-free):
  1. Rapid creation of 500 files with realistic names + content
  2. In-place overwrite with os.urandom() (high-entropy rewrite = encryption signal)
  3. Bulk rename to .locked extension (ransomware extension swap)
  4. Drop a fake RECOVERY_KEY.txt decoy then delete it (ransom note cycle)
  5. Print PAYLOAD_COMPLETE sentinel — absent if AV killed us first
"""

import os
import sys
import tempfile
import shutil

SENTINEL = "PAYLOAD_COMPLETE"

FILE_COUNT  = int(sys.argv[1]) if len(sys.argv) > 1 else 500
CHUNK_BYTES = 4096   # 4 KB per file — enough to trigger heuristics


def simulate_ransomware(stage_dir: str):
    paths = []

    # ── Phase 1: Rapid file creation ─────────────────────────────────────────
    # Use realistic document-sounding names to look more like real ransomware
    # targeting user files.
    for i in range(FILE_COUNT):
        fname = os.path.join(stage_dir, f"document_{i:04d}.docx")
        with open(fname, "wb") as f:
            # Write semi-structured content so the initial entropy is low
            f.write(b"CONFIDENTIAL REPORT DATA SECTION " * 120)
        paths.append(fname)

    # ── Phase 2: In-place high-entropy overwrite (encryption simulation) ──────
    # This is the key behavioural signal: the same files are immediately
    # overwritten with cryptographically random bytes. AV heuristics see
    # low-entropy → high-entropy transitions across hundreds of files.
    for p in paths:
        with open(p, "r+b") as f:
            f.seek(0)
            f.write(os.urandom(CHUNK_BYTES))
            f.truncate()

    # ── Phase 3: Extension swap (.docx → .locked) ────────────────────────────
    # Classic ransomware indicator: every file changes extension en masse.
    locked_paths = []
    for p in paths:
        new_p = p.replace(".docx", ".locked")
        os.rename(p, new_p)
        locked_paths.append(new_p)

    # ── Phase 4: Ransom note lifecycle ───────────────────────────────────────
    # Create and then delete the decoy note — mimics the ransom note drop +
    # self-cleanup behaviour seen in modern ransomware families.
    note_path = os.path.join(stage_dir, "RECOVERY_KEY.txt")
    with open(note_path, "w") as f:
        f.write(
            "YOUR FILES HAVE BEEN ENCRYPTED.\n"
            "Send 0.5 BTC to recover your data.\n"
            "Contact: abae_benchmark_test@localhost\n"
        )
    # Immediately delete — simulates the note-then-delete pattern
    os.remove(note_path)


def main():
    stage_dir = tempfile.mkdtemp(prefix="abae_b01_")
    try:
        simulate_ransomware(stage_dir)
    finally:
        shutil.rmtree(stage_dir, ignore_errors=True)

    # Sentinel MUST be the last thing printed.
    # If AV kills this process before here, the parent sees no sentinel → DETECTED.
    print(SENTINEL, flush=True)


if __name__ == "__main__":
    main()
