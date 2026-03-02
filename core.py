#!/usr/bin/env python3

from __future__ import annotations
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from typing import List, Optional, Tuple


# -------------------- Reporting dataclass --------------------
@dataclass
class Finding:
    severity: str   # HIGH/MEDIUM/LOW/INFO
    rule_id: str
    file: str
    line: int
    message: str
    snippet: Optional[str] = None

    def to_row(self) -> Tuple[str, str, str, str]:
        loc = f"{self.file}:{self.line}" if self.line and self.line > 0 else self.file
        return (self.severity, self.rule_id, loc, self.message)


SEV_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


# -------------------- Helpers --------------------
def run_cmd(cmd: List[str], cwd: Optional[str] = None, timeout: int = 300) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"


def safe_read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


# -------------------- APK / manifest extraction --------------------
def try_androguard_load(apk_path: str):
    try:
        from androguard.core.bytecodes.apk import APK
        return APK(apk_path)
    except Exception:
        return None


def extract_with_apktool(apk_path: str, outdir: str) -> bool:
    code, _out, _err = run_cmd(["apktool", "d", "-f", "-o", outdir, apk_path])
    return code == 0


def unzip_apk(apk_path: str, outdir: str) -> None:
    with zipfile.ZipFile(apk_path, "r") as z:
        z.extractall(outdir)


# -------------------- Manifest scanning --------------------
DANGEROUS_PERMS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
}


def scan_manifest_from_androguard(apk_obj) -> List[Finding]:
    findings: List[Finding] = []

    # debuggable
    try:
        if apk_obj.is_debuggable():
            findings.append(
                Finding(
                    "HIGH",
                    "manifest-debuggable",
                    "AndroidManifest.xml",
                    0,
                    "APK marked as debuggable",
                )
            )
    except Exception:
        pass

    # dangerous permissions
    try:
        perms = apk_obj.get_permissions() or []
        dangerous = sorted(p for p in perms if p in DANGEROUS_PERMS)
        if dangerous:
            findings.append(
                Finding(
                    "INFO",
                    "manifest-dangerous-permissions",
                    "AndroidManifest.xml",
                    0,
                    "Dangerous permissions requested: " + ", ".join(dangerous),
                )
            )
    except Exception:
        pass

    # activities
    try:
        for a in apk_obj.get_activities() or []:
            findings.append(
                Finding(
                    "INFO",
                    "manifest-activity",
                    f"activity:{a}",
                    0,
                    f"Activity declared: {a} — review exported/permission",
                )
            )
    except Exception:
        pass

    # providers
    try:
        for p in apk_obj.get_providers() or []:
            name = p["name"] if isinstance(p, dict) and "name" in p else str(p)
            findings.append(
                Finding(
                    "INFO",
                    "manifest-provider",
                    f"provider:{name}",
                    0,
                    "Provider declared; review read/write/grantUriPermissions",
                )
            )
    except Exception:
        pass

    # targetSdk heuristic
    try:
        target = apk_obj.get_target_sdk_version()
        if target is not None:
            try:
                t = int(target)
                if t < 30:
                    findings.append(
                        Finding(
                            "INFO",
                            "manifest-targetSdk-outdated",
                            "AndroidManifest.xml",
                            0,
                            f"targetSdkVersion={t} — consider updating to recent SDK (>=30)",
                        )
                    )
            except Exception:
                pass
    except Exception:
        pass

    return findings


def scan_manifest_xml_manifest_path(manifest_path: str) -> List[Finding]:
    findings: List[Finding] = []
    txt = safe_read(manifest_path)
    if not txt:
        return findings

    if re.search(r'android:debuggable\s*=\s*"true"', txt):
        findings.append(
            Finding(
                "HIGH",
                "manifest-debuggable",
                manifest_path,
                1,
                "application is debuggable",
            )
        )
    if re.search(r'android:allowBackup\s*=\s*"true"', txt):
        findings.append(
            Finding(
                "MEDIUM",
                "manifest-allowBackup",
                manifest_path,
                1,
                "allowBackup is true",
            )
        )
    if re.search(r'usesCleartextTraffic\s*=\s*"true"', txt):
        findings.append(
            Finding(
                "MEDIUM",
                "manifest-cleartext",
                manifest_path,
                1,
                "usesCleartextTraffic is true",
            )
        )

    # exported components
    for m in re.finditer(r"<(activity|service|receiver|provider)[^>]*>", txt):
        tag = m.group(1)
        block = m.group(0)
        name_m = re.search(r'android:name\s*=\s*"([^"]+)"', block)
        name = name_m.group(1) if name_m else tag
        exported = re.search(r'android:exported\s*=\s*"(true|false)"', block)
        perm = re.search(r'android:permission\s*=\s*"([^"]+)"', block)
        has_intent = re.search(r"<intent-filter", txt[m.end() : m.end() + 500]) is not None
        if (exported is None and has_intent) or (exported and exported.group(1) == "true"):
            if not perm:
                findings.append(
                    Finding(
                        "HIGH",
                        f"manifest-exported-{tag}",
                        manifest_path,
                        1,
                        f"{tag} '{name}' is exported without permission",
                    )
                )

    # dangerous permissions
    for m in re.finditer(r'<uses-permission[^>]*android:name\s*=\s*"([^"]+)"', txt):
        perm = m.group(1)
        if perm in DANGEROUS_PERMS:
            findings.append(
                Finding(
                    "INFO",
                    "manifest-dangerous-permissions",
                    manifest_path,
                    1,
                    perm,
                )
            )

    # targetSdk
    tmatch = re.search(r'<uses-sdk[^>]*android:targetSdkVersion\s*=\s*"(\d+)"', txt)
    if tmatch:
        try:
            t = int(tmatch.group(1))
            if t < 30:
                findings.append(
                    Finding(
                        "INFO",
                        "manifest-targetSdk-outdated",
                        manifest_path,
                        1,
                        f"targetSdkVersion={t} — consider updating to recent SDK (>=30)",
                    )
                )
        except Exception:
            pass

    # SYSTEM_ALERT_WINDOW
    if re.search(r"android.permission.SYSTEM_ALERT_WINDOW", txt):
        findings.append(
            Finding(
                "HIGH",
                "manifest-overlay-permission",
                manifest_path,
                1,
                "SYSTEM_ALERT_WINDOW requested — overlay/tapjacking risk",
            )
        )

    return findings


# -------------------- Smali/dex/textual scanning --------------------
CODE_RULES = [
    # WebView and JS bridges
    (re.compile(r"addJavascriptInterface\(|@JavascriptInterface", re.I),
     "HIGH", "webview-jsi", "WebView addJavascriptInterface or @JavascriptInterface detected"),
    (re.compile(r"setJavaScriptEnabled\(\s*true\s*\)", re.I),
     "MEDIUM", "webview-js", "WebView JavaScript enabled"),
    (re.compile(r"setAllowFileAccess\(\s*true\s*\)", re.I),
     "HIGH", "webview-file", "WebView allows file access"),
    (re.compile(r"loadUrl\(|loadDataWithBaseURL\(|evaluateJavascript\(", re.I),
     "MEDIUM", "webview-loadurl", "WebView dynamic content loading"),

    # Dynamic/dangerous loading
    (re.compile(r"DexClassLoader|PathClassLoader|dalvik\.system\.DexClassLoader", re.I),
     "HIGH", "dynamic-code-loading", "Dynamic code loading (DexClassLoader/PathClassLoader)"),

    # SSL/TLS bypass
    (re.compile(r"HostnameVerifier\b[\s\S]*?return\s+true", re.I),
     "HIGH", "ssl-hostname-bypass", "HostnameVerifier that returns true (SSL bypass)"),
    (re.compile(r"checkServerTrusted\b[\s\S]*?\{\s*\}", re.I),
     "HIGH", "ssl-trustmanager-bypass", "TrustManager with empty checkServerTrusted (trust-all)"),

    # Crypto rules
    (re.compile(r'(Cipher\.getInstance\s*\(\s*"[^"]*ECB|const-string\s+[vp]\d+,\s*"[^"]*ECB)', re.I),
     "HIGH", "crypto-ecb", "AES/ECB mode detected"),
    (re.compile(r'Cipher\.getInstance\([^)]*(?:DES|DESede|3DES)', re.I),
     "HIGH", "crypto-des", "DES/3DES detected (weak cipher)"),
    (re.compile(r'MessageDigest\.getInstance\s*\(\s*"(?:MD5|SHA[-]?1)"', re.I),
     "HIGH", "crypto-weak-hash", "Weak hash algorithm (MD5 or SHA-1) detected"),
    (re.compile(r'IvParameterSpec\s*\(\s*(?:new\s+byte\[\]\s*\{[^}]*\}|"[^"]+"|\{[^}]*\})', re.I),
     "MEDIUM", "crypto-static-iv", "Possible static IV (IvParameterSpec initialized with literal)"),
    (re.compile(r'SecretKeyFactory\.getInstance\s*\(\s*"(?:PBKDF2WithHmacSHA1|PBKDF2WithHmacSHA256)"', re.I),
     "MEDIUM", "crypto-pbkdf2", "PBKDF2 usage detected — check for static salt/password and adequate iterations"),
    (re.compile(r'Cipher\.getInstance\s*\(\s*"(?:RSA/ECB/NoPadding|RSA/None/NoPadding)"', re.I),
     "HIGH", "crypto-rsa-nopadding", "RSA with NoPadding detected (insecure)"),

    # Randomness
    (re.compile(r'\b(new\s+Random\(|java\.util\.Random\b)', re.I),
     "MEDIUM", "random-secrets", "java.util.Random detected; avoid for secrets"),
    (re.compile(r'new\s+SecureRandom\s*\(\s*["\']', re.I),
     "HIGH", "secure-random-seed", "SecureRandom is being seeded with a literal (predictable)"),

    # Hard-coded credentials
    (re.compile(r'(?:api[_-]?key|secret|password|token)[\s:=]+["\']?[A-Za-z0-9\-\_=]{8,}["\']?', re.I),
     "HIGH", "hardcoded-api-key", "Hard-coded credential-like string"),

    # Private key PEM markers
    (re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----|-----BEGIN PRIVATE KEY-----', re.I),
     "HIGH", "private-key-pem", "Embedded private key literal in source"),

    # Logging sensitive info
    (re.compile(r'Log\.(?:d|e|i|w)\s*\([^,]+,\s*.*(?:password|passwd|pwd|token|secret|api[_-]?key|ssn|creditcard)', re.I),
     "HIGH", "log-sensitive", "Logging sensitive information to Log.* — sensitive data exposure"),

    # Intent extras with sensitive keys
    (re.compile(r'putExtra\s*\(\s*["\']?(?:password|passwd|pwd|token|secret|api[_-]?key|auth|apikey)\b', re.I),
     "HIGH", "intent-extra-sensitive", "Intent putExtra with sensitive key — may leak data via intents"),

    # Broadcasts & sticky intents
    (re.compile(r'\.(sendBroadcast|sendStickyBroadcast|sendOrderedBroadcast|sendStickyBroadcastAsUser)\s*\(', re.I),
     "MEDIUM", "insecure-broadcast", "Broadcast being sent — check for sensitive data/exposure"),
    (re.compile(r'\bsendStickyBroadcast\b', re.I),
     "HIGH", "sticky-intent", "sendStickyBroadcast used — sticky broadcasts can leak data"),

    # PendingIntent usage
    (re.compile(r'PendingIntent\.get(?:Activity|Service|Broadcast)\s*\(', re.I),
     "HIGH", "pendingintent-creation", "PendingIntent created — review flags and mutability"),

    # World-readable / writable
    (re.compile(r'\bMODE_WORLD_READABLE\b|\bMODE_WORLD_WRITEABLE\b', re.I),
     "HIGH", "file-world-readable", "Use of MODE_WORLD_READABLE / MODE_WORLD_WRITEABLE"),
    (re.compile(r'openFileOutput\s*\([^,]+,\s*(?:Context\.)?MODE_WORLD_READABLE|openFileOutput\s*\([^,]+,\s*(?:Context\.)?MODE_WORLD_WRITEABLE', re.I),
     "HIGH", "file-open-world", "openFileOutput with MODE_WORLD_READABLE/WRITEABLE"),
    (re.compile(r'\bsetReadable\s*\(\s*true\s*,\s*false\s*\)', re.I),
     "HIGH", "file-set-world-readable", "File.setReadable to world-readable"),
    (re.compile(r'\bsetWritable\s*\(\s*true\s*,\s*false\s*\)', re.I),
     "HIGH", "file-set-world-writable", "File.setWritable to world-writable"),

    # External storage usage
    (re.compile(r'(?:getExternalStorageDirectory|Environment\.getExternalStorageDirectory)\(|FILE_PROVIDER_PATHS', re.I),
     "MEDIUM", "external-storage", "Use of external storage paths; review for sensitive data exposure"),

    # Preference Activities / fragments
    (re.compile(r'PreferenceActivity|PreferenceFragment|android\.preference', re.I),
     "INFO", "preference-activity", "PreferenceActivity/Fragment used — check if exported or exposing sensitive settings"),

    # Overlay permission string inside code
    (re.compile(r'android.permission.SYSTEM_ALERT_WINDOW', re.I),
     "HIGH", "overlay-permission", "SYSTEM_ALERT_WINDOW requested — overlay/tapjacking risk"),

    # targetSdk in gradle
    (re.compile(r'targetSdkVersion\s+["\']?(\d+)["\']?', re.I),
     "INFO", "target-sdk-gradle", "targetSdkVersion declared — check if outdated"),
]


def scan_text_for_rules(path: str, text: str) -> List[Finding]:
    findings: List[Finding] = []
    for creg, sev, rid, msg in CODE_RULES:
        for m in creg.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            snippet = text[max(0, m.start() - 80) : m.end() + 80]
            findings.append(Finding(sev, rid, path, line, msg, snippet=snippet))
    return findings


# -------------------- High-level orchestrator --------------------
def analyze_apk(apk_path: str) -> List[Finding]:
    findings: List[Finding] = []
    tmp = tempfile.mkdtemp(prefix="miniqark_")
    andro = try_androguard_load(apk_path)

    try:
        if andro:
            # Androguard path
            findings.extend(scan_manifest_from_androguard(andro))
            try:
                for fpath in andro.get_files():
                    if any(
                        fpath.endswith(ext)
                        for ext in (
                            ".xml",
                            ".smali",
                            ".java",
                            ".kt",
                            ".kts",
                            ".properties",
                            ".json",
                        )
                    ):
                        b = andro.get_file(fpath)
                        if b:
                            txt = b.decode("utf-8", errors="ignore")
                            findings.extend(scan_text_for_rules(f"{fpath}", txt))
                    elif fpath.endswith(".dex") or fpath.endswith("classes.dex"):
                        b = andro.get_file(fpath)
                        if b:
                            s = re.sub(
                                r"[^\x20-\x7E]+",
                                " ",
                                b.decode("latin-1", errors="ignore"),
                            )
                            findings.extend(scan_text_for_rules(f"{fpath}", s))
            except Exception:
                pass

        else:
            # apktool path
            apktool_ok = False
            apktool_out = os.path.join(tmp, "apktool_out")
            if shutil.which("apktool"):
                apktool_ok = extract_with_apktool(apk_path, apktool_out)
                if apktool_ok:
                    manifest_path = os.path.join(apktool_out, "AndroidManifest.xml")
                    findings.extend(scan_manifest_xml_manifest_path(manifest_path))
                    for root, _dirs, files in os.walk(apktool_out):
                        for fname in files:
                            if fname.endswith(
                                (".smali", ".xml", ".kt", ".kts", ".java", ".properties", ".json")
                            ):
                                p = os.path.join(root, fname)
                                txt = safe_read(p)
                                findings.extend(scan_text_for_rules(p, txt))

            # unzip fallback
            if not apktool_ok:
                unzip_dir = os.path.join(tmp, "unzipped")
                os.makedirs(unzip_dir, exist_ok=True)
                unzip_apk(apk_path, unzip_dir)
                joined = ""
                for root, _dirs, files in os.walk(unzip_dir):
                    for fname in files:
                        p = os.path.join(root, fname)
                        if fname.endswith(
                            (".xml", ".txt", ".json", ".properties", ".smali", ".java", ".kt")
                        ):
                            txt = safe_read(p)
                            findings.extend(scan_text_for_rules(p, txt))
                        elif fname.endswith(".dex") or (
                            fname.startswith("classes") and fname.endswith(".dex")
                        ):
                            try:
                                with open(p, "rb") as f:
                                    raw = f.read()
                                s = re.sub(
                                    r"[^\x20-\x7E]+",
                                    " ",
                                    raw.decode("latin-1", errors="ignore"),
                                )
                                findings.extend(scan_text_for_rules(p, s))
                            except Exception:
                                pass
                        joined += safe_read(p) + "\n"

                if re.search(r'android:debuggable\s*=\s*"true"', joined):
                    findings.append(
                        Finding(
                            "HIGH",
                            "manifest-debuggable",
                            apk_path,
                            0,
                            "application is debuggable (heuristic)",
                        )
                    )

    finally:
        try:
            shutil.rmtree(tmp)
        except Exception:
            pass


    dedup = {}  # key = (rule_id, file)

    for f in findings:
        key = (f.rule_id, f.file)
        if key not in dedup:
            dedup[key] = f
        else:
            # keep lower line number (first occurrence)
            if f.line > 0 and dedup[key].line > 0:
                if f.line < dedup[key].line:
                    dedup[key] = f

    return list(dedup.values())

