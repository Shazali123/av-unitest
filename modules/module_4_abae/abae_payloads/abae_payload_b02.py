"""
ABAE Payload B-02 — Entropy Storm / In-Place Encryption Simulation
===================================================================
Sacrificial process: spawned by abae_engine.py from %TEMP%.

Behaviour simulated (zero-day / signature-free):
  1. Write 100 × 8 KB files with random data (near-max Shannon entropy)
  2. Read each file back, XOR every byte with a fixed key (fake cipher)
  3. Write the XOR'd output back in place (read-modify-write encryption loop)
  4. Verify entropy delta to confirm the spike actually happened

This is the heuristic tripwire that mature behavioural AV engines (Bitdefender,
Kaspersky, etc.) classify as "suspicious encryption activity":
  - High-entropy write bursts
  - Immediate read-back of files just written
  - In-place modification with bitwise operations on binary content
"""

import os
import sys
import math
import tempfile
import shutil

SENTINEL    = "PAYLOAD_COMPLETE"
FILE_COUNT  = int(sys.argv[1]) if len(sys.argv) > 1 else 100
FILE_BYTES  = int(sys.argv[2]) if len(sys.argv) > 2 else 8192   # 8 KB
# A non-repeating XOR key derived from a fixed seed — simulates a simple cipher
XOR_KEY     = bytes([(i * 137 + 41) % 256 for i in range(256)])


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _xor_bytes(data: bytes) -> bytes:
    """XOR each byte of data with a cycling key — fake symmetric cipher."""
    key_len = len(XOR_KEY)
    return bytes(b ^ XOR_KEY[i % key_len] for i, b in enumerate(data))


def simulate_encryption_storm(stage_dir: str):
    paths = []

    # ── Phase 1: Write high-entropy seed files ───────────────────────────────
    for i in range(FILE_COUNT):
        p = os.path.join(stage_dir, f"enc_{i:04d}.dat")
        raw = os.urandom(FILE_BYTES)
        with open(p, "wb") as f:
            f.write(raw)
        paths.append(p)

    # ── Phase 2: Read-Modify-Write (XOR cipher loop) ─────────────────────────
    # Each file is read, XOR'd, and written back.  This is the canonical
    # behavioural signature of ransomware encryption: same file, immediately
    # modified, entropy stays high but byte values change completely.
    for p in paths:
        with open(p, "r+b") as f:
            original = f.read()
            encrypted = _xor_bytes(original)
            f.seek(0)
            f.write(encrypted)
            f.truncate()

    # ── Phase 3: Second-pass re-encryption (double-cipher signal) ────────────
    # Writing over already-encrypted data again pushes heuristic scores higher.
    for p in paths:
        with open(p, "r+b") as f:
            content = f.read()
            f.seek(0)
            f.write(_xor_bytes(content))
            f.truncate()

    # Verify entropy of a sample file (diagnostic only)
    sample_path = paths[0] if paths else None
    if sample_path:
        with open(sample_path, "rb") as f:
            sample = f.read()
        entropy = _shannon_entropy(sample)
        print(f"[B02] Sample entropy after XOR: {entropy:.4f} bits/byte", flush=True)


def main():
    stage_dir = tempfile.mkdtemp(prefix="abae_b02_")
    try:
        simulate_encryption_storm(stage_dir)
    finally:
        shutil.rmtree(stage_dir, ignore_errors=True)

    print(SENTINEL, flush=True)


if __name__ == "__main__":
    main()
