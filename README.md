# AV - Unitest: Open-Source Modular Antivirus Benchmarking Platform

Modern, automated GUI application for benchmarking and scoring antivirus software capabilities across multiple attack layers. Designed with modularity and realistic simulation in mind.

## Key Features

- **Public Release (.exe Download)**: The entire platform is distributed as a pre-compiled standalone `.exe` available on the [Releases](#) page. No Python setup required!
- **Extensible Modularity without Recompilation**: Designed so the compiled `.exe` can be fully configured externally. You can drop new folders into the `modules/` directory, and the application will dynamically discover and load them without ever needing to recompile the core base.
- **Centralized Public Dashboard**: After completing a benchmark, clicking "Upload to Server" securely transmits the telemetry and physical scores to an external PHP/SQLite backend. The data is instantly sorted and visualized on a public comparison dashboard: [**https://shazali123.pythonanywhere.com/**](https://shazali123.pythonanywhere.com/)
  - *⚠️ Disclaimer: Only benchmark runs completed with all 4 Core Modules can be successfully uploaded to the central server to maintain scoring integrity.*
- **4-Layer Attack Simulation Stack**: Accurately tests AV from basic signatures to advanced runtime behaviors.
- **Weighted Performance Scoring**: Computes a total 10-point physical score using real-time resource impacts (CPU, RAM, Disk I/O latency) and detection efficiency.
- **Automated AV Detection**: Uses Windows WMI queries to identify the installed Antivirus automatically.

---

## The 4-Layer Evaluation Stack

### Layer 1: Static Signatures (EICAR)
Drops the standard EICAR test string to disk to evaluate baseline static scanning.

### Layer 2: Phishing Simulation (GoPhish)
Automates HTTP GET/POST interactions to simulate victim clicks. Currently, this runs in **standalone mode** locally to safely mimic the behavior of a phishing attack via an L0–L3 heuristic escalation. However, it can seamlessly be linked to a live GoPhish server if wanted to test network filtering and real-time remote telemetry.

### Layer 3: MITRE ATT&CK TTPs
Deploys 5 live techniques directly mapped to the MITRE ATT&CK framework:

| ATT&CK ID | Technique | AV Target |
|-----------|-----------|-----------|
| T1059.001 | PowerShell encoded `IEX`/`DownloadString` | AMSI / script-block logging |
| T1003.001 | LSASS dump via `comsvcs.dll` (rundll32) | Credential-dumping heuristic |
| T1218.011 | Rundll32 `javascript:` LOLBin | Living-off-the-land heuristic |
| T1105     | EICAR string saved as `.exe` on disk | Real-time file scanner |
| T1082     | Sysinfo recon → base64 stage → loopback exfil POST | Behavioural chain |

### Layer 4: ABAE Behavioral Engine 
Signature-independent behavioral anomaly detection — 5 tests, no external tools. ABAE leverages "Sacrificial Lamb" architecture, passing obfuscated script chains to AMSI without relying on Python interpreters.

| Test | Dimension | Detection Signal |
|------|-----------|------------------|
| B-01 | Rapid File Manipulation | `PermissionError` on file write/rename during 300-file churn |
| B-02 | Entropy Spike Simulation | AV blocks `os.urandom()` writes (≥7.5 Shannon bits/byte) |
| B-03 | Process Burst Activity | Subprocess spawn denied or file I/O storm blocked |
| B-04 | Registry Modification | `WindowsError` on `HKCU\Software\ABAE_*` write |
| B-05 | Behavioral Consistency | AV detects in majority of 3 repeated variation runs |

---

## Security Practices & Development Steps

Building a safe benchmarking tool requires strict compartmentalization to prevent actual system harm while simulating malicious behaviors.

### Development Steps Taken
1. **Initial Foundation**: Built the CustomTkinter GUI alongside `module_manager.py` to allow isolated feature development.
2. **Dynamic Compilation Management**: Overcame deployment challenges by injecting specific Windows subsystem flags during PyInstaller compilation to ensure hidden console windows (stealth operations) while keeping the dynamic `modules` loading fully external.
3. **Behavioral Engine Design (ABAE)**: Identified the "Interpreter Shield" flaw (where Python.exe is whitelisted by AVs). Resolved this by designing PowerShell-driven behavioral executions fed directly into AMSI.
4. **Telemetry & Scoring**: Integrated `score_calculator.py` and real-time process monitoring via `psutil` to observe AV resource starvation.
5. **Full Stack Integration**: Designed the ingestion API (`upload_results.php`, `get_results.php`) mapped to a SQLite database. Linked it dynamically to the live public comparison site on PythonAnywhere.

### Web Security Practices Employed (OWASP Top 10)
- **Data Validation & Sanitization**: The upload pipeline serializes data securely into JSON and strictly validates data types before insertion into the SQLite database. 
  - *Deters: **OWASP A03:2021 - Injection (SQLi)***
- **Secure Secret Management**: Hardcoded IPs and sensitive API tokens (e.g., GoPhish keys) were scrubbed from all configuration files and replaced with placeholder variables prior to publication.
  - *Deters: **OWASP A07:2021 - Identification and Authentication Failures / Hardcoded Credentials***
- **Dependency Minimization**: Implemented Python standard library modules (`urllib`, `ssl`) wherever possible rather than downloading external PIP packages.
  - *Deters: **OWASP A06:2021 - Vulnerable and Outdated Components (Supply-Chain Attacks)***
- **Robust Fallback Logic & Error Handling**: If the live GoPhish server cannot be reached, the tool degrades gracefully to a heavily-scoped standalone version without throwing application exceptions or leaking stack traces.
  - *Deters: **OWASP A05:2021 - Security Misconfiguration (Information Exposure)***

*(Note: All payload detonations are also executed in scoped temporary subdirectories and programmatically deleted post-execution to avoid lingering system artifacts).*

---

## Project Structure

```text
AV-Unitest/
├── main.py                    # Core GUI application
├── module_manager.py          # Dynamic module discovery logic
├── system_monitor.py          # Real-time resource impact tracking
├── SCORE_LOGIC                # 10-point heuristic scoring
├── modules/                   # Extensible Modules Directory (External to the EXE)
│   ├── base_module.py
│   ├── module_1_eicar/
│   ├── module_2_gophish/      # Phishing heuristics & Live HTTP
│   ├── module_3_atomic/       # MITRE mapped TTPs
│   └── module_4_abae/         # Adaptive Behavioral tests
├── server/                    # PHP + SQLite API definitions
└── results/                   # Auto-generated TXT summaries
```

---

## Installation & Usage

**Method 1: Pre-Compiled (Recommended)**
1. Navigate to the **Releases** section of this repository.
2. Download the compressed `.zip` containing the `AV-Unitest.exe` and `modules/` folder.
3. Extract and double-click `AV-Unitest.exe` to run.

**Method 2: Source Code**
```powershell
# 1. Clone the repository
git clone https://github.com/Shazali123/av-unitest.git
cd av-unitest

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch the Application
python main.py
```

### Config Notes
The GoPhish module currently runs in Standalone mode by default. To run it securely in Live mode, update `modules/module_2_gophish/gophish_config.json` with your real endpoint IP and API keys.

---
## License

**License:** Licensed under GPL-3.0.

Developer: **Shazali Shaukhi**  
Created as part of Major Project | UNITAR Learn
