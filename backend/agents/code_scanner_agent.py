"""
Code Scanner Agent — White-box AI Source Code Security Scanner
Clones a GitHub repo, parses source files, and uses LLM to find vulnerabilities.
"""
import os
import re
import json
import time
import shutil
import subprocess
import tempfile
from typing import List, Dict, Callable, Optional
from backend.core.llm_provider import llm

# File extensions to scan
SCAN_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php',
    '.cs', '.cpp', '.c', '.h', '.rs', '.scala', '.kt', '.swift'
}

# Directories to skip
SKIP_DIRS = {
    'node_modules', '.git', '__pycache__', 'venv', 'env', '.venv',
    'dist', 'build', '.next', 'vendor', '.tox', 'eggs', '.eggs',
    'migrations', 'static', 'public', 'assets', '.idea', '.vscode'
}

# Max file size to send to LLM (characters)
MAX_FILE_CHARS = 15000
# Max lines per chunk for large files  
CHUNK_SIZE = 400
CHUNK_OVERLAP = 50

SECURITY_SYSTEM_PROMPT = """You are an expert application security researcher performing a white-box source code audit.
Analyze the provided source code for security vulnerabilities. Focus on:

1. **SQL Injection** — unsanitized user input in SQL queries
2. **Cross-Site Scripting (XSS)** — unescaped user input rendered in HTML
3. **Command Injection** — user input passed to os.system, subprocess, exec
4. **Path Traversal** — user input in file paths without sanitization
5. **SSRF** — user-controlled URLs in server-side requests
6. **Hardcoded Secrets** — API keys, passwords, tokens in source code
7. **Insecure Deserialization** — pickle.loads, yaml.load without SafeLoader
8. **Authentication Bypass** — weak auth checks, missing authorization
9. **Broken Access Control** — IDOR, missing permission checks
10. **Insecure Cryptography** — weak hashing (MD5/SHA1 for passwords), ECB mode

For each vulnerability found, respond with a JSON array. Each item must have:
- "line": the approximate line number (integer)
- "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
- "type": vulnerability category (e.g. "SQL Injection")
- "description": one-line explanation of the vulnerability
- "code_snippet": the vulnerable line(s) of code
- "suggested_fix": concrete code fix suggestion
- "confidence": 0.0 to 1.0

If NO vulnerabilities are found, return an empty array: []

IMPORTANT: Return ONLY the JSON array, no markdown, no explanation outside JSON."""


class CodeScannerAgent:
    """Scans source code repositories for security vulnerabilities using AI."""

    def __init__(self, log_callback: Callable[[str], None] = None):
        self.log_callback = log_callback or print
        self.findings: List[Dict] = []
        self.files_scanned = 0
        self.total_files = 0
        self.is_running = False
        self.scan_dir = None

    def log(self, message: str):
        self.log_callback(message)

    def scan_repo(self, repo_url: str) -> List[Dict]:
        """Main entry point: clone repo and scan all source files."""
        self.is_running = True
        self.findings = []
        self.files_scanned = 0
        self._repo_url = repo_url

        try:
            # Phase 1: Clone
            self.log("CODE_SCAN_PHASE:clone")
            self.log(f"[CodeScanner] Cloning repository: {repo_url}")
            self.scan_dir = self._clone_repo(repo_url)
            if not self.scan_dir:
                self.log("[CodeScanner] ❌ Failed to clone repository")
                return []

            # Phase 2: Discover files
            self.log("CODE_SCAN_PHASE:discover")
            source_files = self._discover_files(self.scan_dir)
            self.total_files = len(source_files)
            self.log(f"[CodeScanner] Found {self.total_files} source files to analyze")
            self.log(f"CODE_SCAN_TOTAL:{self.total_files}")

            if self.total_files == 0:
                self.log("[CodeScanner] No source files found in repository")
                return []

            # Phase 3: Analyze each file
            self.log("CODE_SCAN_PHASE:analyze")
            for filepath in source_files:
                if not self.is_running:
                    break

                rel_path = os.path.relpath(filepath, self.scan_dir)
                self._analyze_file(filepath, rel_path)
                self.files_scanned += 1
                progress = int((self.files_scanned / self.total_files) * 100)
                self.log(f"CODE_SCAN_PROGRESS:{progress}|{self.files_scanned}|{self.total_files}")

            # Phase 4: Summary
            self.log("CODE_SCAN_PHASE:complete")
            self._emit_summary(repo_url)

            return self.findings

        except Exception as e:
            self.log(f"[CodeScanner] ❌ Error: {e}")
            return self.findings
        finally:
            self.is_running = False
            # Cleanup cloned repo
            if self.scan_dir and os.path.exists(self.scan_dir):
                try:
                    shutil.rmtree(self.scan_dir)
                    self.log("[CodeScanner] Cleaned up temporary files")
                except:
                    pass

    def scan_local(self, directory: str) -> List[Dict]:
        """Scan a local directory (no cloning)."""
        self.is_running = True
        self.findings = []
        self.files_scanned = 0
        self.scan_dir = directory

        try:
            self.log("CODE_SCAN_PHASE:discover")
            source_files = self._discover_files(directory)
            self.total_files = len(source_files)
            self.log(f"[CodeScanner] Found {self.total_files} source files to analyze")
            self.log(f"CODE_SCAN_TOTAL:{self.total_files}")

            self.log("CODE_SCAN_PHASE:analyze")
            for filepath in source_files:
                if not self.is_running:
                    break
                rel_path = os.path.relpath(filepath, directory)
                self._analyze_file(filepath, rel_path)
                self.files_scanned += 1
                progress = int((self.files_scanned / self.total_files) * 100)
                self.log(f"CODE_SCAN_PROGRESS:{progress}|{self.files_scanned}|{self.total_files}")

            self.log("CODE_SCAN_PHASE:complete")
            self._emit_summary()
            return self.findings
        except Exception as e:
            self.log(f"[CodeScanner] ❌ Error: {e}")
            return self.findings
        finally:
            self.is_running = False

    def stop(self):
        self.is_running = False

    def _clone_repo(self, repo_url: str) -> Optional[str]:
        """Clone a git repo to a temp directory."""
        # Normalize URL
        url = repo_url.strip()
        if not url.endswith('.git') and 'github.com' in url:
            url = url.rstrip('/') + '.git'

        tmp_dir = tempfile.mkdtemp(prefix='penswarm_codescan_')

        try:
            result = subprocess.run(
                ['git', 'clone', '--depth', '1', '--single-branch', url, tmp_dir],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode != 0:
                self.log(f"[CodeScanner] Git clone error: {result.stderr.strip()}")
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return None

            self.log(f"[CodeScanner] ✅ Repository cloned successfully")
            return tmp_dir
        except subprocess.TimeoutExpired:
            self.log("[CodeScanner] ❌ Clone timed out (>120s)")
            shutil.rmtree(tmp_dir, ignore_errors=True)
            return None
        except Exception as e:
            self.log(f"[CodeScanner] ❌ Clone failed: {e}")
            shutil.rmtree(tmp_dir, ignore_errors=True)
            return None

    def _discover_files(self, directory: str) -> List[str]:
        """Walk directory tree and collect scannable source files."""
        source_files = []

        for root, dirs, files in os.walk(directory):
            # Skip ignored directories
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in SCAN_EXTENSIONS:
                    filepath = os.path.join(root, f)
                    # Skip very large files (>500KB)
                    try:
                        if os.path.getsize(filepath) < 500_000:
                            source_files.append(filepath)
                    except OSError:
                        pass

        # Sort by priority: Python/JS first (most common vulns)
        def priority(f):
            ext = os.path.splitext(f)[1]
            order = {'.py': 0, '.js': 1, '.ts': 2, '.jsx': 3, '.tsx': 4,
                     '.java': 5, '.go': 6, '.php': 7, '.rb': 8}
            return order.get(ext, 9)

        source_files.sort(key=priority)
        return source_files

    def _analyze_file(self, filepath: str, rel_path: str):
        """Send a file to the LLM for security analysis."""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            self.log(f"[CodeScanner] Skipping {rel_path}: {e}")
            return

        if not content.strip():
            return

        # Add line numbers
        lines = content.split('\n')
        numbered = '\n'.join(f"{i+1}: {line}" for i, line in enumerate(lines))

        self.log(f"[CodeScanner] 🔍 Analyzing: {rel_path} ({len(lines)} lines)")

        # Chunk large files
        if len(lines) > CHUNK_SIZE:
            chunks = self._chunk_content(lines)
            for chunk_idx, (start_line, chunk_text) in enumerate(chunks):
                if not self.is_running:
                    return
                self.log(f"[CodeScanner]   Chunk {chunk_idx+1}/{len(chunks)} (lines {start_line}-{start_line + CHUNK_SIZE})")
                self._query_llm_for_file(rel_path, chunk_text, start_line)
        else:
            self._query_llm_for_file(rel_path, numbered, 0)

    def _chunk_content(self, lines: List[str]) -> List[tuple]:
        """Split large files into overlapping chunks with line numbers."""
        chunks = []
        start = 0
        while start < len(lines):
            end = min(start + CHUNK_SIZE, len(lines))
            chunk_lines = lines[start:end]
            numbered = '\n'.join(f"{start+i+1}: {line}" for i, line in enumerate(chunk_lines))
            chunks.append((start + 1, numbered))
            start += CHUNK_SIZE - CHUNK_OVERLAP
        return chunks

    def _query_llm_for_file(self, rel_path: str, content: str, line_offset: int):
        """Query LLM to analyze a file/chunk for security vulnerabilities."""
        # Truncate if still too long
        if len(content) > MAX_FILE_CHARS:
            content = content[:MAX_FILE_CHARS] + "\n... [truncated]"

        prompt = f"""Analyze the following source file for security vulnerabilities.

**File:** `{rel_path}`

```
{content}
```

Find ALL security vulnerabilities in this code. Return a JSON array of findings."""

        try:
            response = llm.query(
                prompt=prompt,
                system_role=SECURITY_SYSTEM_PROMPT,
                temperature=0.3
            )

            if not response or len(response.strip()) < 3:
                return

            findings = self._parse_findings(response, rel_path)
            for finding in findings:
                self.findings.append(finding)
                severity_emoji = {
                    'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'
                }.get(finding.get('severity', ''), '⚪')

                self.log(f"CODE_FINDING:{json.dumps(finding)}")
                self.log(f"[CodeScanner] {severity_emoji} {finding['severity']}: "
                        f"{finding['type']} in {rel_path}:{finding.get('line', '?')} — {finding['description']}")

        except Exception as e:
            self.log(f"[CodeScanner] ⚠️ LLM error on {rel_path}: {e}")

    def _parse_findings(self, response: str, rel_path: str) -> List[Dict]:
        """Parse LLM response into structured findings."""
        # Strip markdown code fences
        text = response.strip()
        text = re.sub(r'^```(?:json)?\s*', '', text)
        text = re.sub(r'\s*```$', '', text)

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Try to extract JSON array from response
            match = re.search(r'\[.*\]', text, re.DOTALL)
            if match:
                try:
                    data = json.loads(match.group())
                except json.JSONDecodeError:
                    return []
            else:
                return []

        if not isinstance(data, list):
            return []

        findings = []
        for item in data:
            if not isinstance(item, dict):
                continue
            finding = {
                'file': rel_path,
                'line': item.get('line', 0),
                'severity': str(item.get('severity', 'MEDIUM')).upper(),
                'type': item.get('type', 'Security Issue'),
                'description': item.get('description', 'No description'),
                'code_snippet': item.get('code_snippet', ''),
                'suggested_fix': item.get('suggested_fix', ''),
                'confidence': float(item.get('confidence', 0.5))
            }
            # Validate severity
            if finding['severity'] not in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
                finding['severity'] = 'MEDIUM'
            findings.append(finding)

        return findings

    def _emit_summary(self, repo_url: str = ''):
        """Emit final scan summary and generate report."""
        total = len(self.findings)
        by_severity = {}
        for f in self.findings:
            sev = f.get('severity', 'MEDIUM')
            by_severity[sev] = by_severity.get(sev, 0) + 1

        self.log(f"[CodeScanner] ═══════════════════════════════════════")
        self.log(f"[CodeScanner] Scan Complete: {self.files_scanned} files analyzed")
        self.log(f"[CodeScanner] Total Findings: {total}")

        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = by_severity.get(sev, 0)
            if count > 0:
                emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}[sev]
                self.log(f"[CodeScanner]   {emoji} {sev}: {count}")

        self.log(f"[CodeScanner] ═══════════════════════════════════════")

        # Generate report
        if total > 0:
            report_path = self._generate_report(repo_url, by_severity)
            if report_path:
                self.log(f"[CodeScanner] 📄 Report saved: {report_path}")

        # Emit structured summary for frontend
        self.log(f"CODE_SCAN_SUMMARY:{json.dumps({'total': total, 'by_severity': by_severity, 'files_scanned': self.files_scanned})}")

    def _generate_report(self, repo_url: str, by_severity: dict) -> Optional[str]:
        """Generate a single consolidated markdown report."""
        from datetime import datetime

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        # Extract repo name from URL
        repo_name = repo_url.rstrip('/').split('/')[-1].replace('.git', '') if repo_url else 'local'
        report_dir = f"reports/codescan_{timestamp}_{repo_name}"
        os.makedirs(report_dir, exist_ok=True)

        report_path = os.path.join(report_dir, "source_code_audit.md")
        total = len(self.findings)

        # Group findings by file
        by_file = {}
        for f in self.findings:
            fname = f.get('file', 'unknown')
            by_file.setdefault(fname, []).append(f)

        severity_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}

        lines = []
        lines.append("# 🛡️ Source Code Security Audit Report\n")
        lines.append(f"| Property | Value |")
        lines.append(f"|----------|-------|")
        lines.append(f"| **Repository** | `{repo_url or 'Local Directory'}` |")
        lines.append(f"| **Scan Date** | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |")
        lines.append(f"| **Files Scanned** | {self.files_scanned} |")
        lines.append(f"| **Total Findings** | {total} |")
        lines.append(f"| **Scanner** | PenSwarm AI Source Code Scanner |")
        lines.append("")

        # Severity breakdown
        lines.append("---\n")
        lines.append("## 📊 Severity Breakdown\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = by_severity.get(sev, 0)
            lines.append(f"| {severity_emoji.get(sev, '')} **{sev}** | {count} |")
        lines.append("")

        # Findings by file
        lines.append("---\n")
        lines.append("## 🔍 Findings\n")

        finding_num = 0
        for filepath in sorted(by_file.keys()):
            file_findings = by_file[filepath]
            lines.append(f"### 📄 `{filepath}`\n")

            for f in sorted(file_findings, key=lambda x: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].index(x.get('severity', 'MEDIUM'))):
                finding_num += 1
                sev = f.get('severity', 'MEDIUM')
                emoji = severity_emoji.get(sev, '⚪')
                conf = f.get('confidence', 0.5)

                lines.append(f"#### {emoji} Finding #{finding_num}: {f.get('type', 'Security Issue')}\n")
                lines.append(f"| Property | Value |")
                lines.append(f"|----------|-------|")
                lines.append(f"| **Severity** | {emoji} **{sev}** |")
                lines.append(f"| **Line** | {f.get('line', '?')} |")
                lines.append(f"| **Confidence** | {int(conf * 100)}% |")
                lines.append("")

                lines.append(f"**Description:** {f.get('description', 'N/A')}\n")

                snippet = f.get('code_snippet', '')
                if snippet:
                    lines.append("**Vulnerable Code:**")
                    lines.append(f"```")
                    lines.append(snippet)
                    lines.append(f"```\n")

                fix = f.get('suggested_fix', '')
                if fix:
                    lines.append(f"**Suggested Fix:** {fix}\n")

                lines.append("---\n")

        # Footer
        lines.append("\n*Report generated by PenSwarm AI Source Code Scanner*\n")

        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            return report_path
        except Exception as e:
            self.log(f"[CodeScanner] ⚠️ Failed to save report: {e}")
            return None

