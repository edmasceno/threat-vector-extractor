"""
Black Ant Framework
Automated framework for static triage, IoC extraction, and capability analysis (MITRE ATT&CK) 
in suspicious artifacts and malicious installers.
"""

import os
import re
import json
import stat
import socket
import string
import ipaddress
import hashlib
import zipfile
import subprocess
import shutil
import math
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import requests

# Attempt to load optional but highly recommended dependencies
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    # We use Rich to build the interactive CLI dashboard
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt
    from rich import print as rprint
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    class DummyConsole:
        def print(self, *args, **kwargs): print(*args)
        def input(self, *args, **kwargs): return input(args[0] if args else "")
    class DummyPrompt:
        @staticmethod
        def ask(*args, **kwargs): return input(args[0] + ": ")
    console = DummyConsole()
    Prompt = DummyPrompt()

try:
    import google.generativeai as genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False

# ============================================================
# GENERAL CONFIGURATION & LIMITS
# ============================================================
# API keys should be set via environment variables for OPSEC
VT_API_KEY = os.environ.get("VT_API_KEY", "")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

# Safeguards against memory exhaustion when handling massive payloads
MAX_FILE_READ_BYTES = 200 * 1024 * 1024
MAX_DOWNLOAD_BYTES = 20 * 1024 * 1024
MAX_ZIP_MEMBER_UNCOMPRESSED = 50 * 1024 * 1024
MAX_ZIP_TOTAL_UNCOMPRESSED = 300 * 1024 * 1024
MAX_ZIP_MEMBERS = 2000
MAX_RECURSION_DEPTH = 8
MAX_ARCHIVES_TO_EXTRACT = 300
MAX_CUMULATIVE_EXTRACTED_BYTES = 800 * 1024 * 1024
DOWNLOAD_TIMEOUT = (5, 15)
ALLOWED_SCHEMES = {"http", "https"}
MAX_BASE64_SAMPLES = 5
MAX_MANIFEST_SNIPPET = 2000
JADX_TIMEOUT = 120
CAPA_TIMEOUT = 180
YARA_RULES_DIR = "yara_rules"

# Signatures for dynamic class loading, C2 comms, and Discord stealers
SUSPICIOUS_CLASS_PATTERNS = [
    (rb'java/lang/Runtime', "Usage of java.lang.Runtime (possible command execution)"),
    (rb'ProcessBuilder', "Usage of ProcessBuilder (possible command execution)"),
    (rb'java/net/URLClassLoader', "URLClassLoader (dynamic external loading)"),
    (rb'DexClassLoader', "DexClassLoader (dynamic code loading)"),
    (rb'java/lang/reflect', "Usage of reflection (possible bypass/obfuscation)"),
    (rb'setAccessible', "setAccessible call (access control bypass)"),
    (rb'javax/crypto', "Payload encryption usage"),
    (rb'java/util/Base64', "Base64 decoder (payload decoding)"),
    (rb'sun/misc/BASE64Decoder', "Legacy Base64 decoder"),
    (rb'java/net/Socket', "Raw Socket usage"),
    (rb'java/net/HttpURLConnection', "Usage of HttpURLConnection (C2/Exfiltration)"),
    (rb'okhttp', "Usage of OkHttp (HTTP Client)"),
    (rb'discord', "Artifact mentions Discord (possible token/webhook theft)"),
    (rb'webhook', "Artifact mentions webhook"),
    (rb'\.minecraft', "Search for .minecraft directory"),
    (rb'AppData', "Search for AppData directory"),
    (rb'Chrome', "Search related to Google Chrome"),
    (rb'discordapp', "Reference to Discord API endpoints"),
    (rb'v8\.setFlagsFromString', "V8 flags manipulation (Bytenode Loader)"),
    (rb'Module\._extensions\[.*\]\s*=', "Node.js extension hijacking"),
]

BASE64_BLOB_PATTERN = re.compile(rb'(?:[A-Za-z0-9+/]{4}){15,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')

INSTALLER_MARKERS = [
    (rb'NullsoftInst', "NSIS (Nullsoft Scriptable Install System)"),
    (rb'\$PLUGINSDIR', "NSIS (reference to \\$PLUGINSDIR)"),
    (rb'Inno Setup', "Inno Setup"),
    (rb'InstallShield', "InstallShield"),
    (rb'Windows Installer', "Windows Installer (MSI)"),
]

EMBEDDED_ARCHIVE_SIGNATURES = [
    (b'7z\xBC\xAF\x27\x1C', "7-Zip Archive (.7z)"),
    (b'PK\x03\x04', "ZIP/JAR/Office Archive (.zip)"),
    (b'Rar!\x1A\x07', "RAR Archive"),
    (b'MSCF', "Microsoft Cabinet (.cab)"),
]

ARCHIVE_EXTENSIONS = {'.7z', '.zip', '.jar', '.rar', '.cab', '.apk'}
COMMON_KNOWN_EXTENSIONS = {
    '.txt', '.md', '.py', '.java', '.class', '.png', '.jpg', '.jpeg', '.gif',
    '.ico', '.ttf', '.otf', '.woff', '.woff2', '.dll', '.exe', '.json', '.js',
    '.html', '.htm', '.css', '.map', '.node', '.pdb', '.xml', '.yml', '.yaml',
    '.svg', '.wasm', '.bmp', '.webp', '.mp3', '.mp4', '.wav', '.zip', '.7z',
    '.rar', '.cab', '.dat.lock',
}

INT_ARRAY_PATTERN = re.compile(r'(?:private|public|protected)?\s*static\s*final\s+int\[\]\s+(\w+)\s*=\s*\{([^}]+)\}')

MAX_XOR_KEY = 256
MAX_XOR_STEP = 64
MIN_PRINTABLE_RATIO = 0.85
DECODE_KEYWORDS = [b'http', b'https', b'.exe', b'.dll', b'.bat', b'cmd', b'powershell',
                   b'appdata', b'temp', b'tmp', b'discord', b'webhook', b'/c', b'-c']

TIMESTOMPING_PATTERN = re.compile(r'setLastModifiedTime\s*\([^;]*currentTimeMillis\(\)\s*-', re.DOTALL)
EMPTY_CATCH_PATTERN = re.compile(r'catch\s*\([^)]*\)\s*\{\s*\}')
SUPPRESSED_OUTPUT_PATTERN = re.compile(r'Redirect\.DISCARD|redirectOutput\s*\([^)]*DISCARD')
XOR_DECODER_METHOD_PATTERN = re.compile(r'private\s+static\s+\w+\s+\w+\s*\([^)]*\)\s*\{[^}]*\^[^}]*\}', re.DOTALL)
SUSPICIOUS_ENTRYPOINT_NAMES = {
    "java", "system", "runtime", "update", "updater", "loader", "core",
    "utils", "util", "helper", "main", "client", "service", "manager", "init"
}

class SSRFBlockedError(Exception):
    pass

class PurePythonYaraEngine:
    """Fallback YARA engine if the C-based yara-python library is missing"""
    def __init__(self, rules_dir):
        self.rules_dir = Path(rules_dir)
        self.rules = []
        self._load_rules()

    def _load_rules(self):
        if not self.rules_dir.exists() or not self.rules_dir.is_dir(): return
        for yar_file in self.rules_dir.glob("*.yar*"):
            try:
                content = yar_file.read_text(encoding='utf-8', errors='ignore')
                rule_blocks = re.findall(r'rule\s+(\w+)\s*\{([^}]+)\}', content, re.DOTALL)
                for rule_name, body in rule_blocks:
                    meta_match = re.search(r'description\s*=\s*"([^"]+)"', body)
                    description = meta_match.group(1) if meta_match else "No description"
                    strings_block = re.search(r'strings\s*:(.*?)(?:condition\s*:|$)', body, re.DOTALL)
                    string_map = {}
                    if strings_block:
                        str_matches = re.findall(r'(\$\w+)\s*=\s*"([^"]+)"', strings_block.group(1))
                        for s_name, s_val in str_matches:
                            string_map[s_name] = s_val.encode('utf-8', errors='ignore')
                    cond_match = re.search(r'condition\s*:(.*)', body, re.DOTALL)
                    condition_str = cond_match.group(1).strip() if cond_match else "any of them"
                    self.rules.append({
                        "name": rule_name, "description": description, 
                        "strings": string_map, "condition": condition_str
                    })
            except Exception: pass

    def match(self, file_data):
        matched_rules = []
        for r in self.rules:
            found_strings = {s_name: (s_val.lower() in file_data.lower()) for s_name, s_val in r["strings"].items()}
            triggered = False
            cond = r["condition"]
            if "any of them" in cond:
                triggered = any(found_strings.values())
            elif "any of ($" in cond.lower():
                prefix_match = re.search(r'any of \(\$(\w+)\*\)', cond)
                if prefix_match:
                    prefix = prefix_match.group(1)
                    triggered = any(v for k, v in found_strings.items() if k.startswith(f"${prefix}"))
            if not triggered and r["strings"] and all(found_strings.values()):
                triggered = True
            if triggered:
                matched_rules.append({
                    "rule_name": r["name"], "description": r["description"],
                    "matched_strings": [k for k, v in found_strings.items() if v]
                })
        return matched_rules


class BlackAntAnalyzer:
    def __init__(self, file_path):
        self.file_path = Path(file_path)
        self.report_path = self.file_path.parent / f"{self.file_path.stem}_blackant_report.json"
        self.safe_download_dir = self.file_path.parent / "quarantine"
        self.jadx_output_dir = self.file_path.parent / f"{self.file_path.stem}_jadx_decompiled"

        # Regex patterns for fast IoC scraping
        self.url_pattern = re.compile(rb'https?://[a-zA-Z0-9.-]+(?::\d+)?(?:/[^\s"\'\`<>\x00]*)?')
        self.ip_pattern = re.compile(rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::\d+)?\b')
        self.telegram_token_pattern = re.compile(rb'\b\d{8,10}:[A-Za-z0-9_-]{35}\b')
        self.discord_webhook_pattern = re.compile(rb'https?://(?:discord(?:app)?\.com|canary\.discord\.com)/api/webhooks/\d+/[\w-]+')
        self.email_pattern = re.compile(rb'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
        self.crypto_wallet_patterns = [
            re.compile(rb'\b(?:bc1|[13])[a-km-zA-HJ-NP-Z1-9]{25,39}\b'),
            re.compile(rb'\b0x[a-fA-F0-9]{40}\b'),
        ]

        # Load previous analysis state if it exists, otherwise build a fresh CTI structure
        if self.report_path.exists():
            try:
                with open(self.report_path, 'r', encoding='utf-8') as f:
                    self.results = json.load(f)
            except Exception:
                self._initialize_default_results()
        else:
            self._initialize_default_results()

        self._suspicious_api_seen = set()
        self._raw_data_cache = None
        self._cumulative_extracted_bytes = 0
        self._archives_extracted_count = 0

    def _initialize_default_results(self):
        """Hierarchical structure based on CTI/SIEM standards"""
        self.results = {
            "metadata": {
                "target_file": self.file_path.name,
                "analysis_date": datetime.now(timezone.utc).isoformat()
            },
            "file_info": {
                "file_type": "Unknown",
                "hashes": {"md5": "", "sha1": "", "sha256": "", "imphash": None},
                "is_packed": False,
                "payload_location": "None"
            },
            "threat_intel": {
                "is_suspected_vector": False,
                "suspicion_score": 0,
                "suspicion_level": "Low",
                "virustotal_report": None,
                "yara_matches": [],
                "warnings": []
            },
            "capabilities": {
                "downloader_dropper": False,
                "evasion_techniques": {
                    "timestomping_detected": False,
                    "silent_exception_swallowing_count": 0,
                    "process_output_suppressed": False,
                    "obfuscation_functions_detected": 0,
                    "suspicious_entrypoint_naming": None
                },
                "mitre_attack_tactics": []
            },
            "iocs": {
                "network": {
                    "external_urls": [], "ips": [], "discord_webhooks": [], "telegram_bot_tokens": []
                },
                "host": {
                    "emails": [], "crypto_wallets": [], "suspicious_api_calls": [], "pe_network_apis": []
                }
            },
            "deep_analysis": {
                "pe_analysis": {"sections": []},
                "installer_analysis": {
                    "installer_type": None, "embedded_archives": [], "extraction_dir": None,
                    "nested_extractions": [], "converted_modules": []
                },
                "embedded_files": [],
                "manifest": {"main_class": None, "raw_snippet": None},
                "mod_metadata": {"mod_loader": None, "mod_id": None, "entrypoints": {}},
                "jar_classes": [],
                "possible_base64_blobs": {"count": 0, "samples": []},
                "recovered_obfuscated_strings": []
            }
        }

    def get_file_hashes(self, data):
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "imphash": None 
        }

    def defang_indicator(self, indicator):
        # Prevent accidental execution/navigation of malicious URLs
        return indicator.replace(".", "[.]").replace("http", "hxxp")

    def detect_file_type(self, data):
        if data.startswith(b'MZ'): return "PE Executable (.exe/.dll)"
        elif data.startswith(b'PK\x03\x04'): return "Compressed Archive (ZIP/Office/JAR)"
        elif data.startswith(b'\xD0\xCF\x11\xE0'): return "OLE Document (Legacy Office)"
        return "Unknown / Raw Data"

    def _calculate_entropy(self, data):
        # Used to detect packed or encrypted sections
        if not data: return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0: entropy += - p_x * math.log(p_x, 2)
        return entropy

    def run_yara_scan(self, raw_data):
        if YARA_AVAILABLE:
            rules_dir = Path(YARA_RULES_DIR)
            if rules_dir.exists():
                filepaths = {rule_file.stem: str(rule_file) for rule_file in rules_dir.glob("*.yar*")}
                if filepaths:
                    try:
                        compiled_rules = yara.compile(filepaths=filepaths)
                        matches = compiled_rules.match(data=raw_data)
                        if matches:
                            self.results["threat_intel"]["is_suspected_vector"] = True
                            for m in matches:
                                if not any(y["rule_name"] == m.rule for y in self.results["threat_intel"]["yara_matches"]):
                                    self.results["threat_intel"]["yara_matches"].append({"rule_name": m.rule, "description": "Detected via yara-python"})
                    except Exception as e:
                        self.results["threat_intel"]["warnings"].append(f"Yara-python error: {e}")
        else:
            yara_engine = PurePythonYaraEngine(YARA_RULES_DIR)
            if yara_engine.rules:
                matches = yara_engine.match(raw_data)
                if matches:
                    self.results["threat_intel"]["is_suspected_vector"] = True
                    for m in matches:
                        if m not in self.results["threat_intel"]["yara_matches"]:
                            self.results["threat_intel"]["yara_matches"].append(m)

    def _is_ip_blocked(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return True
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified

    def _validate_url_for_ssrf(self, url):
        # Basic SSRF protection before downloading external payloads
        parsed = urlparse(url)
        if parsed.scheme not in ALLOWED_SCHEMES: raise SSRFBlockedError(f"HTTP(S) scheme not allowed: {parsed.scheme}")
        if not parsed.hostname: raise SSRFBlockedError("URL without valid hostname")
        addrinfos = socket.getaddrinfo(parsed.hostname, None)
        resolved_ips = {info[4][0] for info in addrinfos}
        for ip_str in resolved_ips:
            if self._is_ip_blocked(ip_str): raise SSRFBlockedError(f"Restricted destination detected (Internal IP): {ip_str}")
        return True

    def analyze_pe(self):
        if not PEFILE_AVAILABLE: return
        try:
            pe = pefile.PE(data=self._raw_data_cache, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
            try:
                self.results["file_info"]["hashes"]["imphash"] = pe.get_imphash()
            except Exception: pass
            
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
                section_data = section.get_data()
                ent = self._calculate_entropy(section_data)
                self.results["deep_analysis"]["pe_analysis"]["sections"].append({"name": section_name, "entropy": round(ent, 2)})
                if ent > 7.2:
                    self.results["file_info"]["is_packed"] = True
                    self.results["threat_intel"]["is_suspected_vector"] = True
            
            # Map imported network APIs commonly used by droppers
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode('utf-8', 'ignore').lower()
                    if dll in ['wininet.dll', 'urlmon.dll', 'ws2_32.dll', 'winhttp.dll']:
                        self.results["threat_intel"]["is_suspected_vector"] = True
                        for imp in entry.imports:
                            if imp.name:
                                api_str = f"{dll} -> {imp.name.decode('utf-8')}"
                                if api_str not in self.results["iocs"]["host"]["pe_network_apis"]:
                                    self.results["iocs"]["host"]["pe_network_apis"].append(api_str)
        except Exception as e:
            self.results["threat_intel"]["warnings"].append(f"Failed to parse PE header: {e}")

    def check_virustotal(self):
        if not VT_API_KEY:
            self.results["threat_intel"]["virustotal_report"] = "API Key not configured in environment."
            return
        url = f"https://www.virustotal.com/api/v3/files/{self.results['file_info']['hashes']['sha256']}"
        headers = {"x-apikey": VT_API_KEY}
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                total = malicious + stats.get('undetected', 0) + stats.get('harmless', 0)
                self.results["threat_intel"]["virustotal_report"] = f"{malicious} / {total} engines detected"
                if malicious > 0: self.results["threat_intel"]["is_suspected_vector"] = True
            elif response.status_code == 404:
                self.results["threat_intel"]["virustotal_report"] = "Not found (Possible unknown/0-day sample)"
            else:
                self.results["threat_intel"]["virustotal_report"] = f"API communication error: HTTP {response.status_code}"
        except Exception as e:
            self.results["threat_intel"]["virustotal_report"] = f"VT connection failed: {e}"

    def run_capa(self):
        capa_path = shutil.which("capa")
        if not capa_path:
            console.print("[red][-] CAPA executable not found in system PATH.[/red]")
            return
        
        console.print("[cyan][*] Initializing Mandiant CAPA engine (TTP extraction)...[/cyan]")
        capa_json_out = self.file_path.parent / f"{self.file_path.stem}_capa_temp.json"
        
        try:
            subprocess.run([capa_path, "-j", str(self.file_path)], stdout=open(capa_json_out, 'w'), stderr=subprocess.DEVNULL, timeout=CAPA_TIMEOUT)
            
            if capa_json_out.exists():
                with open(capa_json_out, 'r') as f:
                    capa_data = json.load(f)
                
                tactics = set(self.results["capabilities"].get("mitre_attack_tactics", []))
                
                for rule_name, rule_data in capa_data.get("rules", {}).items():
                    if "meta" in rule_data and "att&ck" in rule_data["meta"]:
                        for attack in rule_data["meta"]["att&ck"]:
                            tactic_str = attack.get("tactic", "Unknown") + " [" + attack.get("id", "") + "]"
                            tactics.add(tactic_str)
                
                self.results["capabilities"]["mitre_attack_tactics"] = list(tactics)
                if tactics:
                    self.results["threat_intel"]["is_suspected_vector"] = True
                
                console.print(f"[green][+] Analysis completed: {len(tactics)} TTPs injected into main report.[/green]")
                self.save_report()
                capa_json_out.unlink()
                
        except subprocess.TimeoutExpired:
            console.print("[red][-] CAPA suspended due to execution timeout.[/red]")
        except Exception as e:
            console.print(f"[red][-] CAPA execution error: {e}[/red]")

    def scan_suspicious_content(self, data, filename=""):
        for pattern, description in SUSPICIOUS_CLASS_PATTERNS:
            if re.search(pattern, data, re.IGNORECASE):
                if description not in self._suspicious_api_seen:
                    self._suspicious_api_seen.add(description)
                    self.results["iocs"]["host"]["suspicious_api_calls"].append(description)
                self.results["threat_intel"]["is_suspected_vector"] = True
        
        blobs = BASE64_BLOB_PATTERN.findall(data)
        if blobs:
            self.results["deep_analysis"]["possible_base64_blobs"]["count"] += len(blobs)
            for b in blobs:
                if len(self.results["deep_analysis"]["possible_base64_blobs"]["samples"]) >= MAX_BASE64_SAMPLES: break
                sample = b.decode('ascii', 'ignore')
                truncated = sample[:60] + ("..." if len(sample) > 60 else "")
                if truncated not in self.results["deep_analysis"]["possible_base64_blobs"]["samples"]:
                    self.results["deep_analysis"]["possible_base64_blobs"]["samples"].append(truncated)

    def extract_network_iocs(self, data):
        # Whitelists to reduce noise and false positives during extraction
        whitelist_urls = [b'w3.org', b'schemas.microsoft.com', b'xml.org', b'apache.org']
        whitelist_ips = [b'0.0.0.0', b'1.0.0.0', b'6.0.0.0']

        urls = [u.decode('utf-8', 'ignore') for u in self.url_pattern.findall(data) if not any(w in u.lower() for w in whitelist_urls)]
        ips = [i.decode('utf-8', 'ignore') for i in self.ip_pattern.findall(data) if i not in whitelist_ips]
        t_tokens = [t.decode('utf-8', 'ignore') for t in self.telegram_token_pattern.findall(data)]
        d_webhooks = [w.decode('utf-8', 'ignore') for w in self.discord_webhook_pattern.findall(data)]
        emails = [e.decode('utf-8', 'ignore') for e in self.email_pattern.findall(data)]
        wallets = [w.decode('utf-8', 'ignore') for pat in self.crypto_wallet_patterns for w in pat.findall(data)]

        net = self.results["iocs"]["network"]
        host = self.results["iocs"]["host"]

        net["external_urls"] = list(set(net["external_urls"] + urls))
        net["ips"] = list(set(net["ips"] + ips))
        net["telegram_bot_tokens"] = list(set(net["telegram_bot_tokens"] + t_tokens))
        net["discord_webhooks"] = list(set(net["discord_webhooks"] + d_webhooks))
        host["emails"] = list(set(host["emails"] + emails))
        host["crypto_wallets"] = list(set(host["crypto_wallets"] + wallets))

        if any([urls, ips, t_tokens, d_webhooks, wallets]):
            self.results["threat_intel"]["is_suspected_vector"] = True
            if "External" not in self.results["file_info"]["payload_location"]:
                self.results["file_info"]["payload_location"] = "External Access (URL/IP/C2 detected)"

    def detect_embedded_payloads(self, data):
        mz_index = data.find(b'MZ', 2 if data.startswith(b'MZ') else 0)
        if mz_index != -1:
            self.results["threat_intel"]["is_suspected_vector"] = True
            self.results["file_info"]["payload_location"] = f"Internal (Embedded artifact at offset {mz_index})"
            if not any(e["offset"] == mz_index for e in self.results["deep_analysis"]["embedded_files"]):
                self.results["deep_analysis"]["embedded_files"].append({"type": "PE File", "offset": mz_index})

    def detect_installer_type(self, data):
        found = [label for pattern, label in INSTALLER_MARKERS if re.search(pattern, data)]
        if found:
            self.results["deep_analysis"]["installer_analysis"]["installer_type"] = found[0]
            note = f"Installation framework detected: {', '.join(sorted(set(found)))}"
            if note not in self.results["threat_intel"]["warnings"]: 
                self.results["threat_intel"]["warnings"].append(note)
        return found

    def detect_embedded_archives_by_signature(self, data):
        found = []
        for signature, label in EMBEDDED_ARCHIVE_SIGNATURES:
            start = 0
            while True:
                idx = data.find(signature, start)
                if idx == -1: break
                if idx != 0:
                    item = {"type": label, "offset": idx}
                    found.append(item)
                    if item not in self.results["deep_analysis"]["embedded_files"]:
                        self.results["deep_analysis"]["embedded_files"].append(item)
                start = idx + 1
        
        for f in found:
            if f not in self.results["deep_analysis"]["installer_analysis"]["embedded_archives"]:
                self.results["deep_analysis"]["installer_analysis"]["embedded_archives"].append(f)
                
        if found and self.results["file_info"]["payload_location"] == "None":
            self.results["file_info"]["payload_location"] = "Internal (Embedded archive detected)"
        return found

    def _parse_fabric_mod_json(self, data):
        try:
            meta = json.loads(data.decode('utf-8', 'ignore'))
            self.results["deep_analysis"]["mod_metadata"]["mod_loader"] = "fabric"
            self.results["deep_analysis"]["mod_metadata"]["mod_id"] = meta.get("id")
            flat = {}
            for key, refs in meta.get("entrypoints", {}).items():
                flat[key] = [ref["value"] if isinstance(ref, dict) else ref for ref in refs]
            self.results["deep_analysis"]["mod_metadata"]["entrypoints"] = flat
        except Exception: pass

    def analyze_archive(self):
        try:
            with zipfile.ZipFile(self.file_path, 'r') as zf:
                infos = zf.infolist()[:MAX_ZIP_MEMBERS]
                total_uncompressed = 0
                for info in infos:
                    if info.file_size > MAX_ZIP_MEMBER_UNCOMPRESSED or os.path.isabs(info.filename) or ".." in Path(info.filename).parts:
                        continue
                    total_uncompressed += info.file_size
                    if total_uncompressed > MAX_ZIP_TOTAL_UNCOMPRESSED: break
                    if info.filename.endswith(".class") and info.filename not in self.results["deep_analysis"]["jar_classes"]: 
                        self.results["deep_analysis"]["jar_classes"].append(info.filename)
                    with zf.open(info.filename) as f:
                        data = f.read(MAX_ZIP_MEMBER_UNCOMPRESSED)
                        if info.filename.upper().endswith("MANIFEST.MF"):
                            manifest_text = data.decode('utf-8', 'ignore')
                            self.results["deep_analysis"]["manifest"]["raw_snippet"] = manifest_text[:MAX_MANIFEST_SNIPPET]
                            match = re.search(r'Main-Class:\s*(\S+)', manifest_text)
                            if match: self.results["deep_analysis"]["manifest"]["main_class"] = match.group(1)
                        if info.filename == "fabric.mod.json": self._parse_fabric_mod_json(data)
                        self.extract_network_iocs(data)
                        self.scan_suspicious_content(data, info.filename)
        except zipfile.BadZipFile:
            if "Corrupted/malformed ZIP Archive." not in self.results["threat_intel"]["warnings"]:
                self.results["threat_intel"]["warnings"].append("Corrupted/malformed ZIP Archive.")

    def _decode_int_array_xor(self, values, key, step):
        return bytes([v ^ ((key + (i * step)) & 255) for i, v in enumerate(values)])

    def _printable_ratio(self, data):
        return sum(1 for b in data if 32 <= b < 127) / len(data) if data else 0.0

    def _brute_force_xor_array(self, values):
        # Brute forces basic XOR obfuscation commonly found in malicious Java arrays
        best = None
        for key in range(MAX_XOR_KEY):
            for step in range(MAX_XOR_STEP):
                decoded = self._decode_int_array_xor(values, key, step)
                ratio = self._printable_ratio(decoded)
                if ratio >= MIN_PRINTABLE_RATIO:
                    score = ratio + (1.0 if any(kw in decoded.lower() for kw in DECODE_KEYWORDS) else 0.0)
                    if not best or score > best[0]: best = (score, key, step, decoded)
        if best and best[0] >= MIN_PRINTABLE_RATIO:
            try: text = best[3].decode('utf-8')
            except UnicodeDecodeError: text = best[3].decode('latin-1', errors='replace')
            return {"key": best[1], "step": best[2], "decoded": text}
        return None

    def _check_evasion_techniques(self, text, class_simple_name):
        ev = self.results["capabilities"]["evasion_techniques"]
        if TIMESTOMPING_PATTERN.search(text): ev["timestomping_detected"] = True
        ev["silent_exception_swallowing_count"] += len(EMPTY_CATCH_PATTERN.findall(text))
        if SUPPRESSED_OUTPUT_PATTERN.search(text): ev["process_output_suppressed"] = True
        ev["obfuscation_functions_detected"] += len(XOR_DECODER_METHOD_PATTERN.findall(text))
        
        if class_simple_name and class_simple_name.lower() in SUSPICIOUS_ENTRYPOINT_NAMES:
            ev["suspicious_entrypoint_naming"] = class_simple_name
        
        if any(v for k,v in ev.items() if k != "silent_exception_swallowing_count" and v): 
            self.results["threat_intel"]["is_suspected_vector"] = True

    def scan_decompiled_sources(self):
        if not self.jadx_output_dir.exists(): return
        for java_file in self.jadx_output_dir.rglob("*.java"):
            try:
                text = java_file.read_text(encoding='utf-8', errors='ignore')
                for name, raw_values in INT_ARRAY_PATTERN.findall(text):
                    values = [int(v.strip()) for v in raw_values.split(',') if v.strip()]
                    if len(values) >= 2:
                        res = self._brute_force_xor_array(values)
                        if res:
                            entry = {
                                "source_file": str(java_file.relative_to(self.jadx_output_dir)),
                                "array_name": name, "xor_key": res["key"], "xor_step": res["step"], "decoded_value": res["decoded"]
                            }
                            if entry not in self.results["deep_analysis"]["recovered_obfuscated_strings"]:
                                self.results["deep_analysis"]["recovered_obfuscated_strings"].append(entry)
                if "ProcessBuilder" in text and ("openStream" in text or "openConnection" in text) and "setExecutable" in text:
                    self.results["capabilities"]["downloader_dropper"] = True
                self._check_evasion_techniques(text, java_file.stem)
            except Exception: pass

    def _compute_suspicion_score(self):
        r = self.results
        ti = r["threat_intel"]
        inet = r["iocs"]["network"]
        ihost = r["iocs"]["host"]
        cap = r["capabilities"]
        ev = cap["evasion_techniques"]
        deep = r["deep_analysis"]

        score = sum([
            2 * len(ti["yara_matches"]),
            1 if inet["external_urls"] else 0,
            2 if inet["discord_webhooks"] or inet["telegram_bot_tokens"] else 0,
            1 if ihost["crypto_wallets"] else 0,
            2 if cap["downloader_dropper"] else 0,
            1 if ev["timestomping_detected"] else 0,
            1 if ev["process_output_suppressed"] else 0,
            1 if ev["obfuscation_functions_detected"] else 0,
            1 if ev["suspicious_entrypoint_naming"] else 0,
            1 if ihost["pe_network_apis"] else 0,
            1 if deep["installer_analysis"]["converted_modules"] else 0,
            len(ihost["suspicious_api_calls"]),
            2 * len(cap["mitre_attack_tactics"])
        ])
        ti["suspicion_score"] = score
        ti["suspicion_level"] = "Clean" if score == 0 else "Low" if score <= 2 else "Medium" if score <= 5 else "High"

    def run_analysis(self):
        console.print(f"\n[cyan][*] Initializing triage routine:[/cyan] {self.file_path.name}")
        with open(self.file_path, 'rb') as f:
            self._raw_data_cache = f.read(MAX_FILE_READ_BYTES)

        self.results["file_info"]["hashes"] = self.get_file_hashes(self._raw_data_cache)
        self.results["file_info"]["file_type"] = self.detect_file_type(self._raw_data_cache)

        # Baseline checks on raw binary
        self.run_yara_scan(self._raw_data_cache)
        self.extract_network_iocs(self._raw_data_cache)
        self.detect_embedded_payloads(self._raw_data_cache)
        self.detect_installer_type(self._raw_data_cache)
        self.detect_embedded_archives_by_signature(self._raw_data_cache)
        self.scan_suspicious_content(self._raw_data_cache)

        # File-specific deep inspections
        if "PE Executable" in self.results["file_info"]["file_type"]:
            self.analyze_pe()
            self.check_authenticode()
        elif self.file_path.suffix.lower() == ".lnk":
            self.parse_lnk_file()

        self.check_virustotal()
        self._compute_suspicion_score()
        self.save_report()
        self.interactive_menu()

    def save_report(self):
        # Drop deep_analysis node if it's empty to keep the JSON clean for SIEM ingestion
        if not any(self.results["deep_analysis"].values()):
            self.results.pop("deep_analysis", None)

        with open(self.report_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=4, ensure_ascii=False)

    def _find_7z_binary(self):
        found = shutil.which("7z") or shutil.which("7z.exe") or shutil.which("7zz") or shutil.which("7za")
        if found: return found
        if os.name == "nt":
            for c in [os.path.expandvars(r"%ProgramFiles%\7-Zip\7z.exe"), os.path.expandvars(r"%ProgramFiles(x86)%\7-Zip\7z.exe")]:
                if c and os.path.isfile(c): return c
        return None

    def _list_archive_with_7z(self, archive_path):
        sevenzip = self._find_7z_binary()
        if not sevenzip: return None, "'7z' binary not found in environment variables."
        try:
            result = subprocess.run([sevenzip, "l", "-slt", str(archive_path)], capture_output=True, text=True, timeout=60)
            return result.stdout if result.returncode == 0 else None, result.stderr
        except Exception as e: return None, str(e)

    def _estimate_uncompressed_size_7z(self, listing_text):
        total, count = 0, 0
        for line in listing_text.splitlines():
            if line.strip().startswith("Size ="):
                try:
                    total += int(line.split("=", 1)[1].strip())
                    count += 1
                except ValueError: pass
        return total, count

    def safe_extract_with_7z(self, archive_path, dest_dir):
        sevenzip = self._find_7z_binary()
        if not sevenzip: return False
        listing, _ = self._list_archive_with_7z(archive_path)
        if listing:
            total_size, member_count = self._estimate_uncompressed_size_7z(listing)
            if member_count > MAX_ZIP_MEMBERS or total_size > MAX_ZIP_TOTAL_UNCOMPRESSED: return False
        
        dest_dir.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.run([sevenzip, "x", f"-o{dest_dir}", "-y", str(archive_path)], capture_output=True, timeout=180)
            for p in dest_dir.rglob("*"):
                if p.is_file():
                    try: os.chmod(p, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
                    except Exception: pass
            return True
        except Exception: return False

    def recursive_extract_archives(self, root_dir, base_dir=None, depth=0):
        # Unpacks nested archives (e.g. NSIS installers hiding .7z files which hide the payload)
        if depth > MAX_RECURSION_DEPTH: return
        for p in Path(root_dir).rglob("*"):
            if p.is_file() and p.suffix.lower() in ARCHIVE_EXTENSIONS:
                dest_dir = p.parent / f"{p.name}_extracted"
                if not dest_dir.exists() and self.safe_extract_with_7z(p, dest_dir):
                    entry = {"archive": str(p), "extracted_to": str(dest_dir), "depth": depth + 1}
                    if entry not in self.results["deep_analysis"]["installer_analysis"]["nested_extractions"]:
                        self.results["deep_analysis"]["installer_analysis"]["nested_extractions"].append(entry)
                    self.recursive_extract_archives(dest_dir, base_dir=base_dir, depth=depth + 1)

    def find_and_convert_unusual_modules(self, root_dir):
        # Hunts for known evasion patterns like Electron Stealers wrapped in V8 Bytenode (.nqc)
        converted = []
        for f in Path(root_dir).rglob("*"):
            if f.is_file():
                
                if f.suffix.lower() in ['.py', '.bat', '.ps1', '.vbs', '.cmd']:
                    self.results["threat_intel"]["is_suspected_vector"] = True
                    try:
                        self.run_yara_scan(f.read_bytes())
                    except Exception: pass
                    
                    c = {"original": str(f.name), "converted": str(f.name), "detected_type": f"secondary_script_{f.suffix.lower().strip('.')}"}
                    if c not in self.results["deep_analysis"]["installer_analysis"]["converted_modules"]:
                        self.results["deep_analysis"]["installer_analysis"]["converted_modules"].append(c)
                    continue

                if f.suffix.lower() not in COMMON_KNOWN_EXTENSIONS:
                    try:
                        data = f.read_bytes()
                        kind = None
                        new_extension = None
                        
                        # V8 Bytenode magic header detection
                        if len(data) > 4 and data[2:4] == b'\xde\xc0':
                            self.results["threat_intel"]["is_suspected_vector"] = True
                            
                            printable = set(string.printable.encode('ascii'))
                            strings_found = []
                            current_string = bytearray()
                            
                            for byte in data:
                                if byte in printable:
                                    current_string.append(byte)
                                else:
                                    if len(current_string) >= 10:
                                        strings_found.append(current_string.decode('ascii', 'ignore'))
                                    current_string = bytearray()
                                    
                            if len(current_string) >= 10:
                                strings_found.append(current_string.decode('ascii', 'ignore'))

                            if strings_found:
                                clean_text = " ".join(strings_found).encode('utf-8', 'ignore')
                                self.run_yara_scan(clean_text)
                                
                                for s in strings_found:
                                    if any(kw in s.lower() for kw in ["http", "discord", "api", "webhook", "token", "leveldb", "lsass", "dpapi"]):
                                        entry = {"source_file": f.name, "extracted_string": s}
                                        if entry not in self.results["deep_analysis"]["recovered_obfuscated_strings"]:
                                            self.results["deep_analysis"]["recovered_obfuscated_strings"].append(entry)
                                
                                json_dest = f.with_name(f.name + "_strings.json")
                                with open(json_dest, 'w', encoding='utf-8') as jf:
                                    json.dump({"file": f.name, "total_strings": len(strings_found), "strings": strings_found}, jf, indent=4)
                                
                                converted.append({"original": str(f.name), "converted": str(json_dest.name), "detected_type": "extracted_strings_json"})
                            
                            continue

                        elif f.suffix.lower() == '.nqc':
                            kind = "disguised_javascript"
                            new_extension = ".js"
                        elif data.strip().startswith(b'{'):
                            kind = "json"
                            new_extension = ".json"
                        elif sum(1 for b in data[:8192] if 32 <= b < 127)/8192 > 0.85:
                            kind = "text"
                            new_extension = ".txt"
                        
                        if kind:
                            dest = f.with_name(f.name + new_extension)
                            shutil.copy2(f, dest)
                            converted.append({"original": str(f.name), "converted": str(dest.name), "detected_type": kind})
                    except Exception: pass
        
        for c in converted:
            if c not in self.results["deep_analysis"]["installer_analysis"]["converted_modules"]:
                self.results["deep_analysis"]["installer_analysis"]["converted_modules"].append(c)

    def analyze_installer_pipeline(self):
        console.print("\n[yellow][*] Initializing recursive extraction routine...[/yellow]")
        dest_dir = self.file_path.parent / f"{self.file_path.stem}_extracted_safe"
        if self.safe_extract_with_7z(self.file_path, dest_dir):
            self.results["deep_analysis"]["installer_analysis"]["extraction_dir"] = str(dest_dir)
            self.recursive_extract_archives(dest_dir, dest_dir)
            self.find_and_convert_unusual_modules(dest_dir)
            console.print(f"[green][+] Structure mapped successfully at: {dest_dir}[/green]")

    def safe_download_payload(self, url):
        self.safe_download_dir.mkdir(exist_ok=True)
        dest_path = self.safe_download_dir / "quarantine_payload.vir"
        try:
            self._validate_url_for_ssrf(url)
            with requests.get(url, stream=True, timeout=DOWNLOAD_TIMEOUT) as r:
                r.raise_for_status()
                with open(dest_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192): f.write(chunk)
            console.print(f"[green][+] Remote payload acquisition completed: {dest_path}[/green]")
        except Exception as e:
            console.print(f"[red][-] Failed to acquire remote payload: {e}[/red]")

    def decompile_with_jadx(self):
        jadx_path = shutil.which("jadx")
        if not jadx_path: 
            console.print("[red][-] Missing dependency: JADX not found in system PATH.[/red]")
            return
        self.jadx_output_dir.mkdir(exist_ok=True)
        try:
            subprocess.run([jadx_path, "-d", str(self.jadx_output_dir.resolve()), str(self.file_path.resolve())], timeout=JADX_TIMEOUT)
            self.scan_decompiled_sources()
            self.save_report()
        except Exception as e: pass

    def generate_ai_summary(self):
        """AI-driven threat synthesis using Google Gemini"""
        if not GENAI_AVAILABLE:
            console.print("[red][-] 'google-generativeai' library not installed. Use: pip install google-generativeai[/red]")
            return
        if not GEMINI_API_KEY:
            console.print("[red][-] GEMINI_API_KEY not configured in the environment.[/red]")
            return

        console.print("\n[cyan][*] Orchestrating AI Engine (Gemini) for Tactical JSON Generation...[/cyan]")
        
        ti = self.results.get("threat_intel", {})
        fi = self.results.get("file_info", {})
        cap = self.results.get("capabilities", {})
        deep_inst = self.results.get("deep_analysis", {}).get("installer_analysis", {})
        
        yara_rules = [y.get('rule_name') for y in ti.get('yara_matches', [])] if ti.get('yara_matches') else []
        
        extraction_dir = deep_inst.get("extraction_dir")
        critical_files_content = ""
        
        # Read internal scripts to feed the AI prompt with deep context
        if extraction_dir and os.path.exists(extraction_dir):
            console.print("[dim][*] Extracting intelligence from disk (Reading internal .py and .json)...[/dim]")
            base_path = Path(extraction_dir)
            
            for file_path in base_path.rglob("*"):
                if file_path.is_file():
                    if file_path.suffix == '.py' or file_path.name.endswith('_strings.json'):
                        try:
                            raw_content = file_path.read_text(encoding='utf-8', errors='ignore')
                            if file_path.name.endswith('_strings.json'):
                                try:
                                    json_data = json.loads(raw_content)
                                    strings_list = json_data.get("strings", [])
                                    relevant = [s for s in strings_list if any(k in s.lower() for k in ['http', 'api', 'webhook', 'token', 'login', 'pass', 'discord', 'wallet', 'crypto', 'c:\\'])]
                                    content = "\n".join(relevant[:30]) 
                                except:
                                    content = raw_content[:1500]
                            else:
                                content = raw_content[:2000] + "\n[... truncated code ...]"
                                
                            if content.strip():
                                critical_files_content += f"\n--- File: {file_path.name} ---\n{content}\n"
                        except Exception as e:
                            pass
                            
        critical_files_content = critical_files_content[:15000]

        prompt = f"""
        You are a Cyber Threat Intelligence (CTI) API.
        Analyze the malicious artifact below and return ONLY a valid JSON object, without markdown formatting (no ```json).
        The response MUST be in English.
        
        GENERAL METADATA (Raw Telemetry):
        - Type: {fi.get('file_type')}
        - Packaging Vector: {deep_inst.get('installer_type', 'N/A')}
        - Static Score: {ti.get('suspicion_score')}
        - YARA Rules: {', '.join(yara_rules) if yara_rules else 'None'}
        
        DEEP CONTENT:
        {critical_files_content if critical_files_content else 'None.'}
        
        The response JSON MUST strictly follow this structure:
        {{
            "ai_threat_intelligence": {{
                "risk_level": "LOW, MEDIUM, HIGH or CRITICAL",
                "malware_family": "Deduced name (e.g., Rain Stealer)",
                "classification": "Category (e.g., InfoStealer)",
                "primary_targets": ["Target 1", "Target 2"]
            }},
            "tactics_and_techniques": ["Technique 1", "Technique 2"],
            "soc_playbook": {{
                "containment_actions": ["Action 1", "Action 2"],
                "eradication_actions": ["Action 1", "Action 2"]
            }},
            "executive_summary": "Threat summary in plain text"
        }}
        """

        try:
            genai.configure(api_key=GEMINI_API_KEY)
            model = genai.GenerativeModel('gemini-1.5-flash-latest')
            response = model.generate_content(prompt)
            
            # Clean text if the AI tries to send formatting
            json_text = response.text.strip()
            if json_text.startswith("```json"):
                json_text = json_text[7:]
            if json_text.endswith("```"):
                json_text = json_text[:-3]
            json_text = json_text.strip()

            try:
                ai_report_data = json.loads(json_text)
                
                # Save the SECOND JSON report (AI output)
                ai_report_path = self.file_path.parent / f"{self.file_path.stem}_ai_report.json"
                with open(ai_report_path, 'w', encoding='utf-8') as f:
                    json.dump(ai_report_data, f, indent=4, ensure_ascii=False)
                
                console.print("\n")
                console.print(Panel(
                    f"[bold red]Risk Level (AI):[/bold red] {ai_report_data['ai_threat_intelligence']['risk_level']}\n"
                    f"[bold yellow]Family/Type:[/bold yellow] {ai_report_data['ai_threat_intelligence']['malware_family']} ({ai_report_data['ai_threat_intelligence']['classification']})\n\n"
                    f"[bold cyan]Executive Summary:[/bold cyan]\n{ai_report_data['executive_summary']}\n\n"
                    f"[green][+] AI Report saved to: {ai_report_path.name}[/green]", 
                    title="[bold magenta]🤖 JSON AI Engine Successfully Generated[/bold magenta]", border_style="magenta", expand=False
                ))

                # Dynamically update the main JSON severity if AI flags it as highly dangerous
                risk = ai_report_data['ai_threat_intelligence']['risk_level'].upper()
                if risk in ['HIGH', 'CRITICAL']:
                    self.results["threat_intel"]["suspicion_level"] = risk
                    self.results["threat_intel"]["suspicion_score"] = max(self.results["threat_intel"]["suspicion_score"], 10)
                    self.save_report()
                    
            except json.JSONDecodeError:
                console.print("[red][-] AI did not return a valid JSON. Raw response received:[/red]")
                console.print(response.text)
            
        except Exception as e:
            console.print(f"[red][-] Integration with AI failed: {e}[/red]")

    def check_authenticode(self):
        """Digital signature validation (Authenticode)"""
        if not PEFILE_AVAILABLE or not self._raw_data_cache.startswith(b'MZ'):
            return

        try:
            pe = pefile.PE(data=self._raw_data_cache, fast_load=True)
            security_dir = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
            sig_address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_dir].VirtualAddress
            sig_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_dir].Size

            has_signature = sig_address != 0 and sig_size > 0
            self.results["deep_analysis"]["pe_analysis"]["digital_signature"] = {
                "signed": has_signature,
                "cert_table_address": hex(sig_address),
                "cert_size": sig_size
            }

            if not has_signature:
                self.results["threat_intel"]["warnings"].append("Executável não assinado digitalmente (Sem Authenticode).")
        except Exception as e:
            self.results["threat_intel"]["warnings"].append(f"Falha ao validar Authenticode: {e}")

    def parse_lnk_file(self):
        """Initial Access parser: extracts hidden arguments and destinations in .lnk shortcuts"""
        if self.file_path.suffix.lower() != ".lnk":
            return

        self.results["file_info"]["file_type"] = "Windows Shortcut (.lnk)"
        data = self._raw_data_cache

        # Scrape readable strings (ASCII and UTF-16LE commonly found in ShellLink structures)
        ascii_strings = re.findall(rb'[\x20-\x7E]{4,}', data)
        unicode_strings = [m.decode('utf-16le', 'ignore') for m in re.findall(rb'(?:[\x20-\x7E]\x00){4,}', data)]
        decoded_ascii = [s.decode('ascii', 'ignore') for s in ascii_strings]

        combined = " ".join(decoded_ascii + unicode_strings)

        # Look for interpreters often abused in initial access campaigns
        suspicious_terms = ["powershell", "cmd.exe", "mshta", "cscript", "wscript", "rundll32", "regsvr32", "http", "ftp"]
        found_commands = [term for term in suspicious_terms if term in combined.lower()]

        if found_commands:
            self.results["threat_intel"]["is_suspected_vector"] = True
            self.results["capabilities"]["mitre_attack_tactics"].append("Execution: Command and Scripting Interpreter [T1059]")
            self.results["threat_intel"]["warnings"].append(f"Atalho .LNK contém comandos interpretados: {', '.join(set(found_commands))}")

    def run_floss(self):
        """Mandiant FLOSS wrapper to recover advanced obfuscated stack strings"""
        floss_path = shutil.which("floss")
        if not floss_path:
            console.print("[red][-] Mandiant FLOSS não localizado no PATH do sistema.[/red]")
            return

        console.print("[cyan][*] Executando Mandiant FLOSS (Desofuscação de Stack Strings)...[/cyan]")
        try:
            result = subprocess.run([floss_path, "--quiet", str(self.file_path.resolve())], capture_output=True, text=True, timeout=120)
            if result.returncode == 0 and result.stdout:
                extracted = [line.strip() for line in result.stdout.splitlines() if len(line.strip()) > 6]
                self.results["deep_analysis"]["floss_strings"] = extracted[:50]
                console.print(f"[green][+] FLOSS finalizado: {len(extracted)} strings recuperadas.[/green]")
                self.save_report()
        except Exception as e:
            console.print(f"[red][-] Erro na execução do FLOSS: {e}[/red]")

    def interactive_menu(self):
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            
            console.print("\n")
            console.print(Panel(f"[bold white]BLACK ANT - THREAT VECTOR:[/bold white] [bold cyan]{self.file_path.name}[/bold cyan]", border_style="cyan"))
            
            ti = self.results["threat_intel"]
            fi = self.results["file_info"]
            
            status_color = "bold red" if ti['is_suspected_vector'] else "bold green"
            console.print(f"[{status_color}]>> Threat Score: {'CRITICAL' if ti['is_suspected_vector'] else 'LOW'}[/{status_color}] | [white]Severity: {ti['suspicion_score']} ({ti['suspicion_level']})[/white]")
            
            vt_status = ti["virustotal_report"] or "Pending validation"
            console.print(f"[bold yellow]>> VirusTotal Integration:[/bold yellow] {vt_status}\n")

            hash_table = Table(show_header=True, header_style="bold magenta", box=None)
            hash_table.add_column("Algorithm")
            hash_table.add_column("Checksum", style="dim")
            hash_table.add_row("MD5", fi["hashes"]["md5"])
            hash_table.add_row("SHA256", fi["hashes"]["sha256"])
            if fi["hashes"]["imphash"]:
                hash_table.add_row("Imphash", fi["hashes"]["imphash"])
            console.print(hash_table)
            
            if fi["is_packed"]:
                console.print("\n[on red][bold white] ALERT [/bold white][/on red] [red]Anomalous entropy detected (> 7.2). Possible packer/cryptor present.[/red]")
            if ti['yara_matches']:
                try:
                    console.print(f"[on red][bold white] YARA [/bold white][/on red] [red]Matching signatures:[/red] {', '.join([m['rule_name'] if isinstance(m, dict) else m.rule for m in ti['yara_matches']])}")
                except Exception: pass
            if self.results["capabilities"]["mitre_attack_tactics"]:
                console.print(f"[on yellow][bold black] MITRE [/bold black][/on yellow] [yellow]{len(self.results['capabilities']['mitre_attack_tactics'])} operational tactics mapped.[/yellow]")

            can_download = "External" in fi["payload_location"] and self.results["iocs"]["network"]["external_urls"]
            can_extract_raw = bool(self.results["deep_analysis"].get("embedded_files"))
            can_jadx = "Archive" in fi["file_type"] or "PE Executable" in fi["file_type"]
            can_extract_7z = bool(self.results["deep_analysis"]["installer_analysis"]["installer_type"] or self.results["deep_analysis"]["installer_analysis"]["embedded_archives"])

            console.print("\n")
            menu = Table(title="[bold white]OPERATIONAL CONTROL[/bold white]", show_header=True, header_style="bold cyan", expand=True)
            menu.add_column("ID", justify="center", style="bold cyan", width=5)
            menu.add_column("Analysis Routine", justify="left")
            menu.add_column("Module Status", justify="center", width=25)

            menu.add_row("1", "Remote Payload Acquisition (Network/C2)", "[green]Available[/green]" if can_download else "[dim]Inactive[/dim]")
            menu.add_row("2", "Embedded Artifact Dumping (Base offset)", "[green]Available[/green]" if can_extract_raw else "[dim]Inactive[/dim]")
            menu.add_row("3", "Static Reversing (JADX Decompilation)", "[yellow]Optional[/yellow]" if can_jadx else "[dim]Inactive[/dim]")
            menu.add_row("4", "Structural Unpacking (Archive/Installer)", "[bold green]Recommended[/bold green]" if can_extract_7z else "[dim]Inactive[/dim]")
            menu.add_row("5", "MITRE ATT&CK Integration (Mandiant CAPA)", "[bold yellow]Highly Recommended[/bold yellow]")
            
            status_ai = "[bold magenta]Ready[/bold magenta]" if GEMINI_API_KEY else "[dim]Requires API Key[/dim]"
            menu.add_row("6", "Executive Tactical Synthesis (AI Engine)", status_ai)
            menu.add_row("7", "Obfuscated String Recovery (Mandiant FLOSS)", "[green]Available[/green]" if shutil.which("floss") else "[dim]Inactive[/dim]")
            menu.add_row("0", "Exit Triage", "")

            console.print(menu)

            choice = Prompt.ask("\n[bold cyan]Module selection[/bold cyan]", choices=["0", "1", "2", "3", "4", "5", "6", "7"], default="0")
            
            if choice == '0':
                console.print("[bold green]\n[+] Analysis session closed.[/bold green]")
                break
                
            elif choice == '1':
                if can_download:
                    for url in self.results["iocs"]["network"]["external_urls"]:
                        if "http" in url.lower() and Prompt.ask(f"Confirm acquisition from {self.defang_indicator(url)}?", choices=["y", "n"]) == 'y':
                            self.safe_download_payload(url)
                            break
                else:
                    console.print("[red][-] No active C2/URL instances for capture.[/red]")
                    
            elif choice == '2':
                if can_extract_raw:
                    self.safe_download_dir.mkdir(exist_ok=True)
                    for item in self.results["deep_analysis"]["embedded_files"]:
                        offset = item["offset"]
                        extracted_path = self.safe_download_dir / f"extracted_payload_{offset}.vir"
                        with open(extracted_path, 'wb') as f:
                            f.write(self._raw_data_cache[offset:offset + MAX_DOWNLOAD_BYTES])
                        console.print(f"[+] Artifact isolated at: {extracted_path}")
                else:
                    console.print("[red][-] Embedded files not found in the original binary.[/red]")
                    
            elif choice == '3':
                if can_jadx:
                    self.decompile_with_jadx()
                else:
                    console.print("[red][-] Incompatible file signature for JADX.[/red]")
                    
            elif choice == '4':
                if can_extract_7z:
                    self.analyze_installer_pipeline()
                    self._compute_suspicion_score()
                    self.save_report()
                else:
                    console.print("[red][-] The artifact does not require archive unpacking.[/red]")
                    
            elif choice == '5':
                self.run_capa()
                
            elif choice == '6':
                self.generate_ai_summary()
                
            elif choice == '7':
                self.run_floss()

            console.input("\n[dim]Press ENTER to return to the central dashboard...[/dim]")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        analyzer = BlackAntAnalyzer(sys.argv[1])
        analyzer.run_analysis()
    else:
        print("Usage: analyzer.py <suspicious_file>")
