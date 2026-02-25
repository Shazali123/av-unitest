# AV Benchmark Testing Framework — Phase 5

Modern GUI application for benchmarking antivirus software across four test layers with weighted scoring and server upload.

## Quick Start

```powershell
python main.py
```

## Features

- ✅ **GUI Interface** — Modern dark theme using CustomTkinter
- ✅ **Antivirus Detection** — Automatically detects installed AV
- ✅ **Dynamic Modules** — Add modules without code changes
- ✅ **System Monitoring** — Tracks CPU, RAM, Disk I/O per module
- ✅ **Weighted Scoring** — 8-point Physical Score computed after every run
- ✅ **Results Export** — Saves detailed reports to TXT files
- ✅ **Upload to Server** — POSTs results to Ubuntu SQLite via PHP API

---

## The 4-Layer Evaluation Stack

| Layer | Module | What It Measures |
|-------|--------|----------------|
| 1 | EICAR Test | Basic signature functionality |
| 2 | GoPhish Simulation | User-layer phishing attack resilience |
| 3 | ATT&CK Simulation | Advanced attack technique detection |
| 4 | ABAE Behavioral Engine | Unknown behavioral anomaly defense |

---

## Scoring Model (Physical Score — 8 pts)

> Usability score (2 pts) is added separately by the comparison website. Total = 10 pts.

| Component | Max | Logic |
|-----------|-----|-------|
| **Detection Score** | 5 pts | `(modules_detected / total) × 3` + `max(0, 2 − best_latency_s × 0.15)` |
| **Performance Score** | 3 pts | Start at 3.0, deduct: `cpu_avg × 0.015` + `ram_peak_mb × 0.005` + `disk_write_mb × 0.002` |

Scores appear at the bottom of every TXT report and in the upload payload.

---

## Modules

### Module 1: EICAR Test ✅ FUNCTIONAL
Standard signature detection test using the EICAR test file.

### Module 2: GoPhish Phishing Simulation ✅ FUNCTIONAL
Live phishing simulation against a GoPhish server (Ubuntu VM). Campaign data preserved as evidence.

Configure: `modules/module_2_gophish/gophish_config.json`

### Module 3: ATT&CK Simulation ✅ FUNCTIONAL
5 live MITRE ATT&CK technique tests (Python stdlib only).

| ATT&CK ID | Technique | AV Target |
|-----------|-----------|-----------|
| T1059.001 | PowerShell encoded `IEX`/`DownloadString` | AMSI / script-block logging |
| T1003.001 | LSASS dump via `comsvcs.dll` (rundll32) | Credential-dumping heuristic |
| T1218.011 | Rundll32 `javascript:` LOLBin | Living-off-the-land heuristic |
| T1105     | EICAR string saved as `.exe` on disk | Real-time file scanner |
| T1082     | Sysinfo recon → base64 stage → loopback exfil POST | Behavioural chain |

### Module 4: ABAE Behavioral Engine ✅ FUNCTIONAL
Signature-independent behavioral anomaly detection — 5 tests, no external tools.

| Test | Dimension | Detection Signal |
|------|-----------|-----------------|
| B-01 | Rapid File Manipulation | `PermissionError` on file write/rename during 300-file churn |
| B-02 | Entropy Spike Simulation | AV blocks `os.urandom()` writes (≥7.5 Shannon bits/byte) |
| B-03 | Process Burst Activity | Subprocess spawn denied or file I/O storm blocked |
| B-04 | Registry Modification | `WindowsError` on `HKCU\Software\ABAE_*` write |
| B-05 | Behavioral Consistency | AV detects in majority of 3 repeated variation runs |

**PASS criteria:** ≥ 3 of 5 detected (configurable in `abae_config.json`).

---

## Server Upload (Phase 5)

After each benchmark run, click **📤 Upload to Server** to POST results to the Ubuntu server.

### Python side
- `score_calculator.py` — computes the 8-pt Physical Score from all module metrics
- `results_handler.py` — `build_upload_payload()` + `upload_to_server()` stringify and POST the data
- `main.py` — upload button, background thread, success/fail popup

### Server side (`server/` directory)
| File | Deploy to Ubuntu | Purpose |
|------|-----------------|---------|
| `upload_results.php` | `/var/www/html/upload_results.php` | Receives POST, inserts into SQLite |
| `get_results.php`    | `/var/www/html/get_results.php`    | Comparison website data API |

Server URL configured in `main.py`:
```python
SERVER_URL = "http://192.168.1.121:8090/upload_results.php"
```

#### SQLite Schema
```sql
benchmark_results (id, run_id, av_name, timestamp,
  detection_score, performance_score, physical_total,
  eicar_detected, gophish_detected, atomic_detected, abae_detected, abae_verdict,
  best_detection_latency_s, cpu_avg, ram_peak_mb, disk_write_mb, raw_json)
```

#### Comparison website API
```
GET http://192.168.1.121:8090/get_results.php            → all results (newest first)
GET http://192.168.1.121:8090/get_results.php?av_name=Defender
GET http://192.168.1.121:8090/get_results.php?run_id=run_abc123
GET http://192.168.1.121:8090/get_results.php?limit=5&order=asc
```

---

## Installation

```powershell
pip install -r requirements.txt
```

## Project Structure

```
Major Project/
├── main.py                    # GUI application
├── module_manager.py          # Dynamic module discovery
├── system_monitor.py          # Performance tracking
├── av_detector.py             # Antivirus detection
├── score_calculator.py        # Weighted scoring engine
├── results_handler.py         # Results compilation, export, upload
├── modules/
│   ├── base_module.py
│   ├── module_1_eicar/        # EICAR signature test
│   ├── module_2_gophish/      # GoPhish phishing simulation
│   ├── module_3_atomic/       # MITRE ATT&CK simulation
│   └── module_4_abae/         # Adaptive Behavioral Anomaly Engine
│       ├── module.py
│       ├── abae_engine.py
│       └── abae_config.json
├── server/                    # Deploy these to Ubuntu
│   ├── upload_results.php
│   └── get_results.php
└── results/                   # Exported TXT reports
```

## Requirements

- Python 3.11+
- Windows 10 / 11
- CustomTkinter ≥ 5.2.0
- psutil ≥ 5.9.0
- WMI ≥ 1.5.1

## Phase Status

| Phase | Scope | Status |
|-------|-------|--------|
| Phase 1 | GUI + EICAR | ✅ Complete |
| Phase 2 | GoPhish phishing simulation | ✅ Complete |
| Phase 3 | ATT&CK simulation (5 techniques) | ✅ Complete |
| Phase 4 | ABAE behavioral engine (5 tests) | ✅ Complete |
| Phase 5 | Scoring + server upload (SQLite/PHP) | ✅ Complete |
| Phase 6 | Comparison website frontend | 🔲 Planned |

## License

Educational Project — UNITAR Learn

## Quick Start

```powershell
python main.py
```

## Features

- ✅ **GUI Interface** — Modern dark theme using CustomTkinter
- ✅ **Antivirus Detection** — Automatically detects installed AV
- ✅ **Dynamic Modules** — Add modules without code changes
- ✅ **System Monitoring** — Tracks CPU, RAM, Disk I/O per module
- ✅ **Results Export** — Saves detailed reports to TXT files

---

## The 4-Layer Evaluation Stack

| Layer | Module | What It Measures |
|-------|--------|----------------|
| 1 | EICAR Test | Basic signature functionality |
| 2 | GoPhish Simulation | User-layer phishing attack resilience |
| 3 | ATT&CK Simulation | Advanced attack technique detection |
| 4 | ABAE Behavioral Engine | Unknown behavioral anomaly defense |

---

## Modules

### Module 1: EICAR Test ✅ FUNCTIONAL
Standard signature detection test using the EICAR test file.
- Creates EICAR test file on disk
- Monitors for AV quarantine and detection time

### Module 2: GoPhish Phishing Simulation ✅ FUNCTIONAL
Live phishing simulation against a GoPhish server (Ubuntu VM).
- Creates real campaign via GoPhish REST API
- Windows machine simulates victim clicking phishing link (SmartScreen test)
- Downloads phishing page HTML with EICAR JS payload to disk (file scanner test)
- Submits fake credentials (POST exfiltration test)
- Campaign preserved in GoPhish archive after run

Configure: `modules/module_2_gophish/gophish_config.json`

### Module 3: ATT&CK Simulation ✅ FUNCTIONAL
5 live MITRE ATT&CK technique tests (Python stdlib only).

| ATT&CK ID | Technique | AV Target |
|-----------|-----------|-----------|
| T1059.001 | PowerShell encoded `IEX`/`DownloadString` | AMSI / script-block logging |
| T1003.001 | LSASS dump via `comsvcs.dll` (rundll32) | Credential-dumping heuristic |
| T1218.011 | Rundll32 `javascript:` LOLBin | Living-off-the-land heuristic |
| T1105     | EICAR string saved as `.exe` on disk | Real-time file scanner |
| T1082     | Sysinfo recon → base64 stage → loopback exfil | Behavioural chain |

### Module 4: ABAE Behavioral Engine ✅ FUNCTIONAL (Phase 4)
**Adaptive Behavioral Anomaly Engine** — signature-independent detection evaluation.

Evaluates whether the AV detects _abnormal behavior patterns_ without relying on known signatures. Completely original — no open-source tools.

| Test | Dimension | Technique |
|------|-----------|-----------|
| B-01 | Rapid File Manipulation | 300 files overwritten/renamed at high speed (ransomware-like churn) |
| B-02 | Entropy Spike Simulation | `os.urandom()` written to 50 files (Shannon entropy ≥ 7.5 bits/byte) |
| B-03 | Process Burst Activity | 20 rapid `cmd` spawns + 1000 file I/O ops (malicious exec pattern) |
| B-04 | Registry Modification | Benign write/read/delete in `HKCU\Software\` (persistence simulation) |
| B-05 | Behavioral Consistency | Re-runs B-01/02/03 three times with variation (adaptive defense check) |

**PASS criteria:** ≥ 3 of 5 tests detected (configurable in `abae_config.json`).
**Sandbox:** `BME_TEST/` directory, fully cleaned up after run.
**No admin rights required.**

---

## Installation

```powershell
pip install -r requirements.txt
```

## Usage

1. Launch `python main.py`
2. Review detected antivirus and module list
3. Click **Start Benchmark**
4. Watch real-time console output
5. View per-test results and export to TXT

## Results Output

Each run produces a detailed TXT report under `results/` covering:
- EICAR: detection time
- GoPhish: campaign ID, click/submit counts, URL accessibility
- ATT&CK: per-technique `[DETECTED]` / `[NOT DETECTED]` table + overall count
- ABAE: per-behavioral-test table + entropy/latency/file-count metrics + PASS/FAIL verdict
- CPU avg/peak, RAM Δ, Disk read/write for every module

## Project Structure

```
Major Project/
├── main.py                    # GUI application
├── module_manager.py          # Dynamic module discovery
├── system_monitor.py          # Performance tracking
├── av_detector.py             # Antivirus detection
├── results_handler.py         # Results compilation & export
├── modules/
│   ├── base_module.py
│   ├── module_1_eicar/        # EICAR signature test
│   ├── module_2_gophish/      # GoPhish phishing simulation
│   ├── module_3_atomic/       # MITRE ATT&CK simulation
│   └── module_4_abae/         # Adaptive Behavioral Anomaly Engine
│       ├── module.py
│       ├── abae_engine.py     # All behavioral test logic
│       └── abae_config.json   # Configurable thresholds
└── results/                   # Exported TXT reports
```

## Requirements

- Python 3.11+
- Windows 10 / 11
- CustomTkinter ≥ 5.2.0
- psutil ≥ 5.9.0
- WMI ≥ 1.5.1

## Phase Status

| Phase | Scope | Status |
|-------|-------|--------|
| Phase 1 | GUI + EICAR | ✅ Complete |
| Phase 2 | GoPhish phishing simulation | ✅ Complete |
| Phase 3 | ATT&CK simulation (5 techniques) | ✅ Complete |
| Phase 4 | ABAE behavioral engine (5 tests) | ✅ Complete |
| Phase 5 | Database + server upload | 🔲 Planned |

## License

Educational Project — UNITAR Learn
