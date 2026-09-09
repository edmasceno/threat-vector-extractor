# Vector Analyzer 🦠🔍

**Vector Analyzer** is an automated Python framework designed for rapid static triage, Indicator of Compromise (IoC) extraction, and tactical capability analysis of suspicious artifacts and malicious installers. 

> **Note:** This is my primary **Detection Engineering and Malware Analysis framework**, built to automate triage workflows, deepen my knowledge in reverse engineering, and reduce *Analyst Fatigue* when dealing with complex, obfuscated payloads (such as modern Electron/Node.js stealers and Java-based threats).

---

## 🚀 Key Features

*   **Automated Threat Intelligence (YARA):** Integrated YARA engine to scan raw binaries and extracted strings against custom-built signatures, instantly identifying malware families and behaviors.
*   **Advanced Payload Extraction:** Recursive unpacking of installers (NSIS, Inno Setup) and nested archives via 7-Zip integration, exposing hidden artifacts.
*   **V8 Bytenode & Obfuscation Heuristics:** Automatically identifies, isolates, and extracts readable strings from compiled Node.js/Electron payloads (commonly used by modern stealers) that masquerade as legitimate scripts.
*   **Java Reverse Engineering:** JADX integration for automated decompilation of `.jar` and `.apk` files, including XOR obfuscation cracking in integer arrays.
*   **MITRE ATT&CK Mapping:** Integrates with Mandiant CAPA to map binary behaviors to MITRE ATT&CK tactics and techniques.
*   **SIEM-Ready Reporting:** Generates a hierarchical, structured JSON report detailing file hashes, extracted network IoCs (C2s, webhooks), host IoCs (crypto wallets, suspicious APIs), and a calculated *Suspicion Score*, ideal for automated ingestion into platforms like Wazuh, Splunk, or QRadar.

---

## 🎯 Detection Capabilities & CTI

Vector Analyzer comes with a suite of custom YARA rules developed through active *in-the-wild* malware reverse engineering. Current detection capabilities include:

*   **Modular Infostealers:** Signatures targeting Electron/Node.js stealers, detecting C2 infrastructure, global configuration variables, and exfiltration API endpoints.
*   **Advanced Evasion Techniques:** Detection of anti-VM and anti-debugging mechanisms, such as WMI hardware enumeration, sandbox process blacklisting, and output suppression.
*   **Credential Access & Injection:** Identifies attempts to hijack Discord core modules (e.g., `betterdiscord.asar` manipulation), extract crypto wallet seeds (e.g., Exodus SECO decryption), and steal 2FA backup codes.

> **🛡️ OpSec Notice:** For Operational Security reasons, specific Command and Control (C2) domains, IP addresses, and threat actor tags in the public `yara_rules_examples` directory have been redacted or neutralized. 

---

## ⚠️ Sanitization & Safety Recommendations

Handling malicious files involves inherent risks. Please follow these safety guidelines before running or testing this tool:

1.  **Isolated Environment (VM):** Always run this tool inside an isolated Virtual Machine (VM) or sandbox (e.g., VirtualBox, VMware, Cuckoo Sandbox). **Never** execute untrusted binaries on your main host machine.
2.  **Network Isolation:** Ensure your analysis VM is completely disconnected from your local network (or set to "Host-Only" mode) to prevent accidental C2 communication, lateral movement, or data leakage.
3.  **Safe Handling:** Treat every sample passed to this script as live malware. Use proper sanitization methods when transferring files to your analysis environment.

---

## 🛠️ Prerequisites

To ensure the framework utilizes 100% of its extraction and analysis capabilities, make sure you have the following binaries added to your operating system's `PATH`:

*   [7-Zip](https://www.7-zip.org/)
*   [JADX](https://github.com/skylot/jadx)
*   [Mandiant CAPA](https://github.com/mandiant/capa)

**Python Dependencies:**
```bash
pip install requests yara-python pefile rich```



## 💻 Quick Start
# Run the analyzer against a suspicious artifact
python analyzer.py path/to/suspicious_installer.exe
