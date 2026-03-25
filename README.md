# AV - Unitest v1.0.0

Modular Antivirus Benchmark Platform
AV-Unitest is a lightweight, portable security benchmarking tool designed to evaluate the effectiveness of antivirus (AV) software across multiple detection layers. It simulates common attack vectors—from simple signature matches to complex behavioral patterns—without using actual malicious code.

Key Features
The platform tests your security posture across four distinct layers:

EICAR Signature Detection: Validates basic file-system monitoring.

Phishing Simulation: Tests browser and email protection (includes a standalone mode and optional Gophish integration).

MITRE ATT&CK Simulation: Executes techniques aligned with the MITRE framework to test detection of common adversary tactics.

Behavioral Analysis (ABAE): Uses an Anti-Virus Behavioral Analysis Engine to detect anomalies in process execution.

Quick Start
Download the AV-Unitest.exe and modules_config.json from the Latest Release.

Place them in the same folder.

Double-click AV-Unitest.exe to begin the benchmark.

View your results locally in the /results folder or check the Public Dashboard.

Important Disclaimer
Run this tool in a controlled environment (VM/Sandbox) only.

While AV-Unitest contains no real malware, it performs simulated attacks that:

Modify registry entries.

Spawn suspicious processes.

Trigger Antivirus "Heuristic" or "HackTool" alerts.

We strongly recommend using VirtualBox, VMware, or Hyper-V. The author is not responsible for unintended side effects on production systems.

Configuration & Customization
Disabling Modules
If you want to skip specific tests, edit the modules_config.json file:

JSON
{
  "disabled_modules": ["module_1_eicar"],
  "external_modules_only": false
}
Adding Custom Modules
The platform is modular. To add your own test:

Create a directory: modules/module_5_mytest/

Add a module.py that inherits from BaseModule.

The tool will automatically discover and run your script on the next launch.

Phishing (Gophish) Integration
To use a full phishing campaign instead of the standalone test, create a gophish_config.json:

JSON
{
  "host": "https://YOUR_IP:3333",
  "api_key": "YOUR_API_KEY",
  "campaign_name": "AV_Benchmark_Test"
}

License & Project Info
Project: UNITAR Learn Major Project

Developer: Shazali

License: Licensed under GPL-3.0.
