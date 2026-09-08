"""
Vector Analyzer Framework
Ferramenta automatizada para triagem estática, extração de IoCs e análise de capacidades (MITRE ATT&CK) 
em artefatos suspeitos e instaladores maliciosos.
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

# ============================================================
# CONFIGURAÇÕES GERAIS E LIMITES
# ============================================================
# Recomenda-se exportar a variável de ambiente VT_API_KEY no sistema.
VT_API_KEY = os.environ.get("VT_API_KEY", "")

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

SUSPICIOUS_CLASS_PATTERNS = [
    (rb'java/lang/Runtime', "Uso de java.lang.Runtime (possível execução de comandos)"),
    (rb'ProcessBuilder', "Uso de ProcessBuilder (possível execução de comandos)"),
    (rb'java/net/URLClassLoader', "URLClassLoader (carregamento dinâmico externo)"),
    (rb'DexClassLoader', "DexClassLoader (carregamento dinâmico de código)"),
    (rb'java/lang/reflect', "Uso de reflection (possível bypass/ofuscação)"),
    (rb'setAccessible', "Chamada setAccessible (bypass de controles de acesso)"),
    (rb'javax/crypto', "Uso de criptografia de payload"),
    (rb'java/util/Base64', "Base64 decoder (decodificação de payload)"),
    (rb'sun/misc/BASE64Decoder', "Base64 decoder legado"),
    (rb'java/net/Socket', "Uso de Socket bruto"),
    (rb'java/net/HttpURLConnection', "Uso de HttpURLConnection (C2/Exfiltração)"),
    (rb'okhttp', "Uso de OkHttp (Cliente HTTP)"),
    (rb'discord', "Artefato menciona o Discord (possível roubo de token/webhook)"),
    (rb'webhook', "Artefato menciona webhook"),
    (rb'\.minecraft', "Busca pelo diretório .minecraft"),
    (rb'AppData', "Busca pelo diretório AppData"),
    (rb'Chrome', "Busca relacionada ao Google Chrome"),
    (rb'discordapp', "Referência aos endpoints da API do Discord"),
    (rb'v8\.setFlagsFromString', "Manipulação de flags V8 (Loader Bytenode)"),
    (rb'Module\._extensions\[.*\]\s*=', "Sequestro de extensão do Node.js"),
]

BASE64_BLOB_PATTERN = re.compile(rb'(?:[A-Za-z0-9+/]{4}){15,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')

INSTALLER_MARKERS = [
    (rb'NullsoftInst', "NSIS (Nullsoft Scriptable Install System)"),
    (rb'\$PLUGINSDIR', "NSIS (referência a \\$PLUGINSDIR)"),
    (rb'Inno Setup', "Inno Setup"),
    (rb'InstallShield', "InstallShield"),
    (rb'Windows Installer', "Windows Installer (MSI)"),
]

EMBEDDED_ARCHIVE_SIGNATURES = [
    (b'7z\xBC\xAF\x27\x1C', "Archive 7-Zip (.7z)"),
    (b'PK\x03\x04', "Archive ZIP/JAR/Office (.zip)"),
    (b'Rar!\x1A\x07', "Archive RAR"),
    (b'MSCF', "Cabinet Microsoft (.cab)"),
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
                    description = meta_match.group(1) if meta_match else "Sem descrição"
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

class SafeVectorAnalyzer:
    def __init__(self, file_path):
        self.file_path = Path(file_path)
        self.report_path = self.file_path.parent / f"{self.file_path.stem}_vector_report.json"
        self.safe_download_dir = self.file_path.parent / "quarantine"
        self.jadx_output_dir = self.file_path.parent / f"{self.file_path.stem}_jadx_decompiled"

        self.url_pattern = re.compile(rb'https?://[a-zA-Z0-9.-]+(?::\d+)?(?:/[^\s"\'\`<>\x00]*)?')
        self.ip_pattern = re.compile(rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::\d+)?\b')
        self.telegram_token_pattern = re.compile(rb'\b\d{8,10}:[A-Za-z0-9_-]{35}\b')
        self.discord_webhook_pattern = re.compile(rb'https?://(?:discord(?:app)?\.com|canary\.discord\.com)/api/webhooks/\d+/[\w-]+')
        self.email_pattern = re.compile(rb'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
        self.crypto_wallet_patterns = [
            re.compile(rb'\b(?:bc1|[13])[a-km-zA-HJ-NP-Z1-9]{25,39}\b'),
            re.compile(rb'\b0x[a-fA-F0-9]{40}\b'),
        ]

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
        """Estrutura hierárquica baseada em padrões CTI/SIEM"""
        self.results = {
            "metadata": {
                "target_file": self.file_path.name,
                "analysis_date": datetime.now(timezone.utc).isoformat()
            },
            "file_info": {
                "file_type": "Desconhecido",
                "hashes": {"md5": "", "sha1": "", "sha256": "", "imphash": None},
                "is_packed": False,
                "payload_location": "Nenhum"
            },
            "threat_intel": {
                "is_suspected_vector": False,
                "suspicion_score": 0,
                "suspicion_level": "Baixo",
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
                    "urls_externas": [], "ips": [], "discord_webhooks": [], "telegram_bot_tokens": []
                },
                "host": {
                    "emails": [], "crypto_wallets": [], "suspicious_api_calls": [], "apis_de_rede_pe": []
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
        return indicator.replace(".", "[.]").replace("http", "hxxp")

    def detect_file_type(self, data):
        if data.startswith(b'MZ'): return "Executável PE (.exe/.dll)"
        elif data.startswith(b'PK\x03\x04'): return "Arquivo Compactado (ZIP/Office/JAR)"
        elif data.startswith(b'\xD0\xCF\x11\xE0'): return "Documento OLE (Office Antigo)"
        return "Desconhecido / Raw Data"

    def _calculate_entropy(self, data):
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
                                    self.results["threat_intel"]["yara_matches"].append({"rule_name": m.rule, "description": "Detectado via yara-python"})
                    except Exception as e:
                        self.results["threat_intel"]["warnings"].append(f"Erro no yara-python: {e}")
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
        parsed = urlparse(url)
        if parsed.scheme not in ALLOWED_SCHEMES: raise SSRFBlockedError(f"Esquema HTTP(S) não permitido: {parsed.scheme}")
        if not parsed.hostname: raise SSRFBlockedError("URL sem hostname válido")
        addrinfos = socket.getaddrinfo(parsed.hostname, None)
        resolved_ips = {info[4][0] for info in addrinfos}
        for ip_str in resolved_ips:
            if self._is_ip_blocked(ip_str): raise SSRFBlockedError(f"Destino restrito detectado (IP interno): {ip_str}")
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
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode('utf-8', 'ignore').lower()
                    if dll in ['wininet.dll', 'urlmon.dll', 'ws2_32.dll', 'winhttp.dll']:
                        self.results["threat_intel"]["is_suspected_vector"] = True
                        for imp in entry.imports:
                            if imp.name:
                                api_str = f"{dll} -> {imp.name.decode('utf-8')}"
                                if api_str not in self.results["iocs"]["host"]["apis_de_rede_pe"]:
                                    self.results["iocs"]["host"]["apis_de_rede_pe"].append(api_str)
        except Exception as e:
            self.results["threat_intel"]["warnings"].append(f"Falha ao parsear header PE: {e}")

    def check_virustotal(self):
        if not VT_API_KEY:
            self.results["threat_intel"]["virustotal_report"] = "API Key não configurada no ambiente."
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
                self.results["threat_intel"]["virustotal_report"] = f"{malicious} / {total} motores detectaram"
                if malicious > 0: self.results["threat_intel"]["is_suspected_vector"] = True
            elif response.status_code == 404:
                self.results["threat_intel"]["virustotal_report"] = "Não encontrado (Possível amostra desconhecida/0-day)"
            else:
                self.results["threat_intel"]["virustotal_report"] = f"Erro de comunicação com a API: HTTP {response.status_code}"
        except Exception as e:
            self.results["threat_intel"]["virustotal_report"] = f"Falha de conexão VT: {e}"

    def run_capa(self):
        capa_path = shutil.which("capa")
        if not capa_path:
            console.print("[red][-] Executável CAPA não encontrado no PATH do sistema.[/red]")
            return
        
        console.print("[cyan][*] Inicializando engine Mandiant CAPA (TTP extraction)...[/cyan]")
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
                
                console.print(f"[green][+] Análise concluída: {len(tactics)} TTPs injetados no relatório principal.[/green]")
                self.save_report()
                capa_json_out.unlink()
                
        except subprocess.TimeoutExpired:
            console.print("[red][-] CAPA suspenso devido a timeout de execução.[/red]")
        except Exception as e:
            console.print(f"[red][-] Erro de execução CAPA: {e}[/red]")

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
        # Whitelist de domínios benignos para redução de falsos positivos
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

        net["urls_externas"] = list(set(net["urls_externas"] + urls))
        net["ips"] = list(set(net["ips"] + ips))
        net["telegram_bot_tokens"] = list(set(net["telegram_bot_tokens"] + t_tokens))
        net["discord_webhooks"] = list(set(net["discord_webhooks"] + d_webhooks))
        host["emails"] = list(set(host["emails"] + emails))
        host["crypto_wallets"] = list(set(host["crypto_wallets"] + wallets))

        if any([urls, ips, t_tokens, d_webhooks, wallets]):
            self.results["threat_intel"]["is_suspected_vector"] = True
            if "Externo" not in self.results["file_info"]["payload_location"]:
                self.results["file_info"]["payload_location"] = "Acesso Externo (URL/IP/C2 detectado)"

    def detect_embedded_payloads(self, data):
        mz_index = data.find(b'MZ', 2 if data.startswith(b'MZ') else 0)
        if mz_index != -1:
            self.results["threat_intel"]["is_suspected_vector"] = True
            self.results["file_info"]["payload_location"] = f"Interno (Artifact embutido no offset {mz_index})"
            if not any(e["offset"] == mz_index for e in self.results["deep_analysis"]["embedded_files"]):
                self.results["deep_analysis"]["embedded_files"].append({"tipo": "PE File", "offset": mz_index})

    def detect_installer_type(self, data):
        found = [label for pattern, label in INSTALLER_MARKERS if re.search(pattern, data)]
        if found:
            self.results["deep_analysis"]["installer_analysis"]["installer_type"] = found[0]
            note = f"Framework de instalação detectado: {', '.join(sorted(set(found)))}"
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
                    item = {"tipo": label, "offset": idx}
                    found.append(item)
                    if item not in self.results["deep_analysis"]["embedded_files"]:
                        self.results["deep_analysis"]["embedded_files"].append(item)
                start = idx + 1
        
        for f in found:
            if f not in self.results["deep_analysis"]["installer_analysis"]["embedded_archives"]:
                self.results["deep_analysis"]["installer_analysis"]["embedded_archives"].append(f)
                
        if found and self.results["file_info"]["payload_location"] == "Nenhum":
            self.results["file_info"]["payload_location"] = "Interno (Archive embutido detectado)"
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
            if "Archive ZIP corrompido/malformado." not in self.results["threat_intel"]["warnings"]:
                self.results["threat_intel"]["warnings"].append("Archive ZIP corrompido/malformado.")

    def _decode_int_array_xor(self, values, key, step):
        return bytes([v ^ ((key + (i * step)) & 255) for i, v in enumerate(values)])

    def _printable_ratio(self, data):
        return sum(1 for b in data if 32 <= b < 127) / len(data) if data else 0.0

    def _brute_force_xor_array(self, values):
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
            1 if inet["urls_externas"] else 0,
            2 if inet["discord_webhooks"] or inet["telegram_bot_tokens"] else 0,
            1 if ihost["crypto_wallets"] else 0,
            2 if cap["downloader_dropper"] else 0,
            1 if ev["timestomping_detected"] else 0,
            1 if ev["process_output_suppressed"] else 0,
            1 if ev["obfuscation_functions_detected"] else 0,
            1 if ev["suspicious_entrypoint_naming"] else 0,
            1 if ihost["apis_de_rede_pe"] else 0,
            1 if deep["installer_analysis"]["converted_modules"] else 0,
            len(ihost["suspicious_api_calls"]),
            2 * len(cap["mitre_attack_tactics"])
        ])
        ti["suspicion_score"] = score
        ti["suspicion_level"] = "Limpo" if score == 0 else "Baixa" if score <= 2 else "Média" if score <= 5 else "Alta"

    def run_analysis(self):
        console.print(f"\n[cyan][*] Inicializando rotina de triagem:[/cyan] {self.file_path.name}")
        with open(self.file_path, 'rb') as f:
            self._raw_data_cache = f.read(MAX_FILE_READ_BYTES)

        self.results["file_info"]["hashes"] = self.get_file_hashes(self._raw_data_cache)
        self.results["file_info"]["file_type"] = self.detect_file_type(self._raw_data_cache)

        self.run_yara_scan(self._raw_data_cache)
        self.extract_network_iocs(self._raw_data_cache)
        self.detect_embedded_payloads(self._raw_data_cache)
        self.detect_installer_type(self._raw_data_cache)
        self.detect_embedded_archives_by_signature(self._raw_data_cache)
        self.scan_suspicious_content(self._raw_data_cache)

        if "Executável PE" in self.results["file_info"]["file_type"]: self.analyze_pe()
        elif "Arquivo Compactado" in self.results["file_info"]["file_type"]: self.analyze_archive()

        self.check_virustotal()
        self._compute_suspicion_score()
        self.save_report()
        self.interactive_menu()

    def save_report(self):
        # Remove nó deep_analysis se vazio para otimizar ingestão no SIEM
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
        if not sevenzip: return None, "Binário '7z' não localizado nas variáveis de ambiente."
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
        converted = []
        for f in Path(root_dir).rglob("*"):
            if f.is_file() and f.suffix.lower() not in COMMON_KNOWN_EXTENSIONS:
                try:
                    data = f.read_bytes()
                    kind = None
                    nova_extensao = None
                    
                    # Identificação de V8 Bytenode via assinatura binária
                    if len(data) > 4 and data[2:4] == b'\xde\xc0':
                        self.results["threat_intel"]["is_suspected_vector"] = True
                        
                        # Extração bruta de strings legíveis para hunting de IoCs
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
                            # ---> O YARA ENTRA AQUI <---
                            # Roda o YARA nas strings limpas que acabamos de desobfuscar!
                            texto_limpo = " ".join(strings_found).encode('utf-8', 'ignore')
                            self.run_yara_scan(texto_limpo)
                            
                            # 1. Alimenta o relatório geral com as strings mais críticas
                            for s in strings_found:
                                if any(kw in s.lower() for kw in ["http", "discord", "api", "webhook", "token", "leveldb"]):
                                    entry = {"source_file": f.name, "extracted_string": s}
                                    if entry not in self.results["deep_analysis"]["recovered_obfuscated_strings"]:
                                        self.results["deep_analysis"]["recovered_obfuscated_strings"].append(entry)
                            
                            # 2. Transforma o arquivo inútil em um .json 100% legível com TODAS as strings
                            json_dest = f.with_name(f.name + "_strings.json")
                            with open(json_dest, 'w', encoding='utf-8') as jf:
                                json.dump({"arquivo": f.name, "total_strings": len(strings_found), "strings": strings_found}, jf, indent=4)
                            
                            converted.append({"original": str(f.name), "convertido": str(json_dest.name), "tipo_detectado": "strings_extraidas_json"})
                        
                        # Ignora o resto das verificações e NÃO copia o arquivo .v8c ilegível
                        continue

                    elif f.suffix.lower() == '.nqc':
                        kind = "javascript_disfarçado"
                        nova_extensao = ".js"
                    elif data.strip().startswith(b'{'):
                        kind = "json"
                        nova_extensao = ".json"
                    elif sum(1 for b in data[:8192] if 32 <= b < 127)/8192 > 0.85:
                        kind = "text"
                        nova_extensao = ".txt"
                    
                    if kind:
                        dest = f.with_name(f.name + nova_extensao)
                        shutil.copy2(f, dest)
                        converted.append({"original": str(f.name), "convertido": str(dest.name), "tipo_detectado": kind})
                except Exception: pass
        
        for c in converted:
            if c not in self.results["deep_analysis"]["installer_analysis"]["converted_modules"]:
                self.results["deep_analysis"]["installer_analysis"]["converted_modules"].append(c)

    def analyze_installer_pipeline(self):
        console.print("\n[yellow][*] Inicializando rotina de extração recursiva...[/yellow]")
        dest_dir = self.file_path.parent / f"{self.file_path.stem}_extracted_safe"
        if self.safe_extract_with_7z(self.file_path, dest_dir):
            self.results["deep_analysis"]["installer_analysis"]["extraction_dir"] = str(dest_dir)
            self.recursive_extract_archives(dest_dir, dest_dir)
            self.find_and_convert_unusual_modules(dest_dir)
            console.print(f"[green][+] Estrutura mapeada com sucesso em: {dest_dir}[/green]")

    def safe_download_payload(self, url):
        self.safe_download_dir.mkdir(exist_ok=True)
        dest_path = self.safe_download_dir / "quarentena_payload.vir"
        try:
            self._validate_url_for_ssrf(url)
            with requests.get(url, stream=True, timeout=DOWNLOAD_TIMEOUT) as r:
                r.raise_for_status()
                with open(dest_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192): f.write(chunk)
            console.print(f"[green][+] Captura de payload finalizada: {dest_path}[/green]")
        except Exception as e:
            console.print(f"[red][-] Falha na captura do payload remoto: {e}[/red]")

    def decompile_with_jadx(self):
        jadx_path = shutil.which("jadx")
        if not jadx_path: 
            console.print("[red][-] Dependência ausente: JADX não localizado no PATH do sistema.[/red]")
            return
        self.jadx_output_dir.mkdir(exist_ok=True)
        try:
            subprocess.run([jadx_path, "-d", str(self.jadx_output_dir), str(self.file_path)], timeout=JADX_TIMEOUT)
            self.scan_decompiled_sources()
            self.save_report()
        except Exception as e: pass

    def interactive_menu(self):
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            
            console.print("\n")
            console.print(Panel(f"[bold white]VETOR DE AMEAÇA:[/bold white] [bold cyan]{self.file_path.name}[/bold cyan]", border_style="cyan"))
            
            ti = self.results["threat_intel"]
            fi = self.results["file_info"]
            
            status_color = "bold red" if ti['is_suspected_vector'] else "bold green"
            console.print(f"[{status_color}]>> Score de Ameaça: {'CRÍTICO' if ti['is_suspected_vector'] else 'BAIXO'}[/{status_color}] | [white]Severidade: {ti['suspicion_score']} ({ti['suspicion_level']})[/white]")
            
            vt_status = ti["virustotal_report"] or "Pendente de validação"
            console.print(f"[bold yellow]>> Integração VirusTotal:[/bold yellow] {vt_status}\n")

            hash_table = Table(show_header=True, header_style="bold magenta", box=None)
            hash_table.add_column("Algoritmo")
            hash_table.add_column("Checksum", style="dim")
            hash_table.add_row("MD5", fi["hashes"]["md5"])
            hash_table.add_row("SHA256", fi["hashes"]["sha256"])
            if fi["hashes"]["imphash"]:
                hash_table.add_row("Imphash", fi["hashes"]["imphash"])
            console.print(hash_table)
            
            if fi["is_packed"]:
                console.print("\n[on red][bold white] ALERT [/bold white][/on red] [red]Entropia anômala detectada (> 7.2). Possível packer/cryptor presente.[/red]")
            if ti['yara_matches']:
                console.print(f"[on red][bold white] YARA [/bold white][/on red] [red]Assinaturas correspondentes:[/red] {', '.join([m['rule_name'] for m in ti['yara_matches']])}")
            if self.results["capabilities"]["mitre_attack_tactics"]:
                console.print(f"[on yellow][bold black] MITRE [/bold black][/on yellow] [yellow]{len(self.results['capabilities']['mitre_attack_tactics'])} táticas operacionais mapeadas.[/yellow]")

            can_download = "Externo" in fi["payload_location"] and self.results["iocs"]["network"]["urls_externas"]
            can_extract_raw = bool(self.results["deep_analysis"].get("embedded_files"))
            can_jadx = "Arquivo Compactado" in fi["file_type"] or "Executável PE" in fi["file_type"]
            can_extract_7z = bool(self.results["deep_analysis"]["installer_analysis"]["installer_type"] or self.results["deep_analysis"]["installer_analysis"]["embedded_archives"])

            console.print("\n")
            menu = Table(title="[bold white]CONTROLE OPERACIONAL[/bold white]", show_header=True, header_style="bold cyan", expand=True)
            menu.add_column("ID", justify="center", style="bold cyan", width=5)
            menu.add_column("Rotina de Análise", justify="left")
            menu.add_column("Status do Módulo", justify="center", width=25)

            menu.add_row("1", "Aquisição de Payload Remoto (Network/C2)", "[green]Disponível[/green]" if can_download else "[dim]Inativo[/dim]")
            menu.add_row("2", "Dumping de Artifact Embutido (Offset base)", "[green]Disponível[/green]" if can_extract_raw else "[dim]Inativo[/dim]")
            menu.add_row("3", "Reversing Estático (Decompilação JADX)", "[yellow]Opcional[/yellow]" if can_jadx else "[dim]Inativo[/dim]")
            menu.add_row("4", "Desempacotamento Estrutural (Archive/Installer)", "[bold green]Recomendado[/bold green]" if can_extract_7z else "[dim]Inativo[/dim]")
            menu.add_row("5", "Integração MITRE ATT&CK (Mandiant CAPA)", "[bold yellow]Altamente Recomendado[/bold yellow]")
            menu.add_row("0", "Finalizar Triagem", "")

            console.print(menu)

            escolha = Prompt.ask("\n[bold cyan]Seleção de módulo[/bold cyan]", choices=["0", "1", "2", "3", "4", "5"], default="0")
            
            if escolha == '0':
                console.print("[bold green]\n[+] Sessão de análise encerrada.[/bold green]")
                break
                
            elif escolha == '1':
                if can_download:
                    for url in self.results["iocs"]["network"]["urls_externas"]:
                        if "http" in url.lower() and Prompt.ask(f"Confirmar aquisição de {self.defang_indicator(url)}?", choices=["s", "n"]) == 's':
                            self.safe_download_payload(url)
                            break
                else:
                    console.print("[red][-] Sem instâncias ativas de C2/URLs para captura.[/red]")
                    
            elif escolha == '2':
                if can_extract_raw:
                    self.safe_download_dir.mkdir(exist_ok=True)
                    for item in self.results["deep_analysis"]["embedded_files"]:
                        offset = item["offset"]
                        extracted_path = self.safe_download_dir / f"extracted_payload_{offset}.vir"
                        with open(extracted_path, 'wb') as f:
                            f.write(self._raw_data_cache[offset:offset + MAX_DOWNLOAD_BYTES])
                        console.print(f"[+] Artifact isolado em: {extracted_path}")
                else:
                    console.print("[red][-] Arquivos embutidos não localizados no binário original.[/red]")
                    
            elif escolha == '3':
                if can_jadx:
                    self.decompile_with_jadx()
                else:
                    console.print("[red][-] Assinatura de arquivo incompatível com o JADX.[/red]")
                    
            elif escolha == '4':
                if can_extract_7z:
                    self.analyze_installer_pipeline()
                    self._compute_suspicion_score()
                    self.save_report()
                else:
                    console.print("[red][-] O artefato não requer desempacotamento de archives.[/red]")
                    
            elif escolha == '5':
                self.run_capa()

            console.input("\n[dim]Pressione ENTER para retornar ao painel central...[/dim]")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        analyzer = SafeVectorAnalyzer(sys.argv[1])
        analyzer.run_analysis()
    else:
        print("Uso: python vector_malware.py <arquivo_suspeito>")
