# Vector Analyzer 🦠🔍

**Vector Analyzer** is an automated Python framework designed for rapid static triage, extraction of Indicators of Compromise (IoCs), and tactical capability analysis of suspicious artifacts and malicious installers.

> **Note:** This is my **first custom-built malware static analysis script/framework**, created to automate triage workflows, deepen my knowledge in reverse engineering, and reduce Analyst Fatigue when dealing with complex obfuscated payloads (such as Electron/Node.js stealers and Java-based threats).

---

## 🚀 Key Features

*   **Recursive Unpacking:** Safe extraction of installers (NSIS, Inno Setup) and nested archives via 7-Zip integration.
*   **V8 Bytenode Detection:** Heuristically identifies and isolates compiled Node.js/Electron payloads (commonly used by modern Stealers) attempting to masquerade as legitimate scripts.
*   **Built-in String Dumper:** Extracts Discord webhooks, IPs, URLs, and API keys directly from obfuscated files or raw binaries.
*   **Java Reverse Engineering:** JADX integration for automated decompilation of `.jar` and `.apk` files, including XOR obfuscation cracking in integer arrays.
*   **MITRE ATT&CK Mapping:** Runs Mandiant CAPA in the background to inject identified tactics and techniques directly into the final report.
*   **CTI-Ready Reporting:** The final output is a clean, hierarchical, structured JSON file, ideal for automated ingestion into SIEMs (Splunk, Elastic, Wazuh, QRadar).

---

## 🛡️ Sanitization & Safety Recommendations

Handling malicious files involves inherent risks. Please follow these safety guidelines before running or testing this tool:

1.  **Isolated Environment (VM):** Always run this tool inside an isolated Virtual Machine (VM) or sandbox (such as VirtualBox, VMware, or an isolated Cuckoo Sandbox). Never execute untrusted binaries on your main host machine.
2.  **Network Isolation:** Ensure your analysis VM is completely disconnected from your local network (or set to "Host-Only" / "Internal Network" mode) to prevent accidental C2 communication or data leakage.
3.  **Safe Handling:** Treat every sample passed to this script as live malware. Use proper safety measures when transferring files to your analysis environment.

---

## 🛠️ Prerequisites

To ensure the framework utilizes 100% of its extraction capabilities, make sure you have the following binaries in your operating system's `PATH`:
*   [7-Zip](https://www.7-zip.org/)
*   [JADX](https://github.com/skylot/jadx)
*   [Mandiant CAPA](https://github.com/mandiant/capa)

**Python Dependencies:**
```bash
pip install requests yara-python pefile rich
