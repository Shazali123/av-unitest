AV-Unitest v1.0.0
==================
Modular Antivirus Benchmark Platform

QUICK START
-----------
Double-click AV-Unitest.exe to run.
No installation or configuration needed.

Tests your antivirus across 4 layers:
  1. EICAR signature detection
  2. Phishing simulation (standalone)
  3. MITRE ATT&CK technique simulation
  4. Behavioral anomaly detection (ABAE)

Results upload automatically to the public dashboard:
  https://av-unitest.onrender.com

!! DISCLAIMER !!
-----------------
AV-Unitest performs simulated cyberattacks to test
your antivirus. While the tool contains NO real
malware, the tests may trigger AV responses, modify
registry entries, and spawn processes.

We strongly recommend running AV-Unitest on:
  - Virtual machines (VirtualBox, VMware, Hyper-V)
  - Dedicated test devices
  - NOT your personal/production machine

The author is not responsible for any unintended
side effects caused by running this tool.

ANTIVIRUS WARNING
-----------------
AV-Unitest simulates attack techniques (EICAR, MITRE
ATT&CK, phishing) to TEST your antivirus. Your AV may
flag this tool as a "HackTool" or "PUA" — this is a
FALSE POSITIVE.

To run AV-Unitest:
1. Right-click AV-Unitest.exe → Properties → Unblock
2. Add AV-Unitest.exe to your AV's exclusion list
   - Defender: Settings → Virus Protection →
     Exclusions → Add the .exe

The tool contains NO actual malware. Source code is
available for inspection.

ADDING CUSTOM MODULES
---------------------
Create a folder next to the .exe:
  modules/module_5_mytest/module.py

Your module.py must define a class inheriting from
BaseModule with run() and get_results() methods.
The module will be auto-discovered on next run.

DISABLING BUILT-IN MODULES
---------------------------
Create modules_config.json next to the .exe:

  Disable specific modules:
  { "disabled_modules": ["module_1_eicar"] }

  Run ONLY custom modules:
  { "external_modules_only": true }

No config file = all 4 built-in modules run.

OPTIONAL: GOPHISH SERVER
-------------------------
For full phishing campaign simulation, create
gophish_config.json next to the .exe:

  {
    "host": "https://YOUR_IP:3333",
    "api_key": "YOUR_API_KEY",
    "campaign_name": "AV_Benchmark_Test",
    "smtp_profile": "Your SMTP Profile",
    "email_template": "Your Template",
    "landing_page": "Your Landing Page"
  }

Without this config, Module 2 runs in standalone mode
using a bundled phishing payload for L0-L3 AV tests.

UPDATES
-------
The tool checks for updates on startup. If a new
version is available, a download banner will appear.

LICENSE
-------
Copyright (c) 2026 Shazali. All rights reserved.
Licensed under GPL-3.0. See LICENSE file.

PROJECT
-------
AV-Unitest — UNITAR Learn Major Project
Developed by Shazali
