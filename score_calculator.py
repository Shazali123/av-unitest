"""
Score Calculator — Weighted 8-Point Physical Score
===================================================
Scoring breakdown (out of 8 pts total):

    Detection Score   — 5 pts max  (weighted by test sophistication)
    Performance Score — 3 pts max  (resource overhead penalty)
    Usability Score   — 2 pts max  (20%) → added separately via Google Forms import

Detection weights (total = 5.0 pts)
------------------------------------
  EICAR    : 0.5 pts   binary (detected or not)
             Simple signature test — drop a text file
  GoPhish  : 1.5 pts   binary (detected or not)
             Phishing simulation with live campaign + credential capture
  Atomic   : 3.0 pts   split across 5 ATT&CK sub-tests (0.6 pts each)
             Real MITRE ATT&CK techniques — most rigorous component

  ABAE is EXCLUDED from scoring — supplementary PASS/FAIL only.

Performance sub-score (3 pts max)
----------------------------------
  Start at 3.0, deduct:
    cpu_avg      × 0.010   (was 0.015)
    ram_peak_mb  × 0.002   (was 0.005)
    disk_write_mb× 0.001   (was 0.002)
  Clamped to [0.0, 3.0]

  Calibration targets (same standard for all AVs):
    Light AV  (~30% CPU, ~150 MB RAM)  → ~2.40 / 3.0
    Mid   AV  (~54% CPU, ~250 MB RAM)  → ~1.96 / 3.0
    Heavy AV  (~80% CPU, ~300 MB RAM)  → ~1.60 / 3.0

Detection weights rationale
----------------------------
EICAR is the simplest possible test (a known static signature in a .txt file).
GoPhish is more meaningful — it tests active URL blocking, script detection,
and credential harvesting prevention.
Atomic Red Team covers 5 distinct MITRE ATT&CK techniques (PowerShell abuse,
LSASS dump, LOLBin proxy, ingress tool transfer, exfil simulation) and is
the most comprehensive detection benchmark.
"""

# ---------------------------------------------------------------------------
# Detection weight constants — adjust here to tweak scoring model
# ---------------------------------------------------------------------------
WEIGHT_EICAR   = 0.5    # binary: 0 or 0.5
WEIGHT_GOPHISH = 1.5    # binary: 0 or 1.5
WEIGHT_ATOMIC  = 3.0    # split across N sub-tests

# These names are matched against module result['name'] (case-insensitive)
_EICAR_KEYS   = ("eicar",)
_GOPHISH_KEYS = ("gophish", "phish")
_ATOMIC_KEYS  = ("atomic",)
_ABAE_KEYS    = ("abae", "behavioral", "behavioural")


def _module_type(name: str) -> str:
    """Return 'eicar', 'gophish', 'atomic', 'abae', or 'unknown'."""
    n = name.lower()
    if any(k in n for k in _EICAR_KEYS):   return "eicar"
    if any(k in n for k in _GOPHISH_KEYS): return "gophish"
    if any(k in n for k in _ATOMIC_KEYS):  return "atomic"
    if any(k in n for k in _ABAE_KEYS):    return "abae"
    return "unknown"


def calculate_scores(module_results: list) -> dict:
    """
    Compute the Physical Score from a list of module result dicts.

    Parameters
    ----------
    module_results : list of dicts (each is a module's get_results() output)

    Returns
    -------
    dict with keys:
        detection_score   float  0.0–5.0
        performance_score float  0.0–3.0
        physical_total    float  0.0–8.0
        breakdown         dict   raw inputs used for transparency
    """
    if not module_results:
        return _zero_scores()

    # ------------------------------------------------------------------ #
    # 1. Detection Score (weighted, 5 pts max)                            #
    # ------------------------------------------------------------------ #
    eicar_score   = 0.0
    gophish_score = 0.0
    atomic_score  = 0.0

    eicar_detected   = False
    gophish_detected = False
    atomic_det       = 0
    atomic_total     = 0

    for r in module_results:
        mtype = _module_type(r.get("name", ""))

        if mtype == "eicar":
            eicar_detected = r.get("detected", False)
            eicar_score    = WEIGHT_EICAR if eicar_detected else 0.0

        elif mtype == "gophish":
            gophish_detected = r.get("detected", False)
            gophish_score    = WEIGHT_GOPHISH if gophish_detected else 0.0

        elif mtype == "atomic":
            subs = r.get("test_results", [])
            if subs:
                atomic_det   = sum(1 for s in subs if s.get("detected", False))
                atomic_total = len(subs)
                # Each sub-test worth WEIGHT_ATOMIC / total_sub_tests
                per_test     = WEIGHT_ATOMIC / atomic_total
                atomic_score = round(atomic_det * per_test, 4)
            else:
                # No sub-test detail — fall back to binary
                atomic_det   = 1 if r.get("detected", False) else 0
                atomic_total = 1
                atomic_score = WEIGHT_ATOMIC if r.get("detected", False) else 0.0

        # ABAE is skipped — not counted in detection score

    detection_score = round(eicar_score + gophish_score + atomic_score, 2)

    # ------------------------------------------------------------------ #
    # 2. Performance Score (3 pts max)                                    #
    # ------------------------------------------------------------------ #
    cpu_avgs    = []
    ram_peaks   = []
    disk_writes = []

    for r in module_results:
        m = r.get("metrics", {})
        if m.get("cpu_avg") is not None:
            cpu_avgs.append(m["cpu_avg"])
        if m.get("ram_peak") is not None:
            ram_peaks.append(m["ram_peak"])
        if m.get("disk_write_mb") is not None:
            disk_writes.append(m["disk_write_mb"])

    agg_cpu_avg     = round(sum(cpu_avgs) / len(cpu_avgs), 2) if cpu_avgs    else 0.0
    agg_ram_peak_mb = round(max(ram_peaks), 2)                 if ram_peaks   else 0.0
    agg_disk_write  = round(sum(disk_writes), 2)               if disk_writes else 0.0

    perf_score  = 3.0
    perf_score -= agg_cpu_avg     * 0.010
    perf_score -= agg_ram_peak_mb * 0.002
    perf_score -= agg_disk_write  * 0.001
    performance_score = round(max(0.0, min(3.0, perf_score)), 2)

    # ------------------------------------------------------------------ #
    # 3. Physical Total                                                   #
    # ------------------------------------------------------------------ #
    physical_total = round(detection_score + performance_score, 2)

    return {
        "detection_score":   detection_score,
        "performance_score": performance_score,
        "physical_total":    physical_total,
        "breakdown": {
            "eicar_detected":    eicar_detected,
            "eicar_score":       round(eicar_score, 2),
            "gophish_detected":  gophish_detected,
            "gophish_score":     round(gophish_score, 2),
            "atomic_detected":   atomic_det,
            "atomic_total":      atomic_total,
            "atomic_score":      round(atomic_score, 2),
            "agg_cpu_avg":       agg_cpu_avg,
            "agg_ram_peak_mb":   agg_ram_peak_mb,
            "agg_disk_write_mb": agg_disk_write,
        },
    }


def _zero_scores() -> dict:
    return {
        "detection_score":   0.0,
        "performance_score": 0.0,
        "physical_total":    0.0,
        "breakdown": {
            "eicar_detected":    False,
            "eicar_score":       0.0,
            "gophish_detected":  False,
            "gophish_score":     0.0,
            "atomic_detected":   0,
            "atomic_total":      0,
            "atomic_score":      0.0,
            "agg_cpu_avg":       0.0,
            "agg_ram_peak_mb":   0.0,
            "agg_disk_write_mb": 0.0,
        },
    }
