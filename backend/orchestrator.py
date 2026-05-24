import requests
import threading
import time
import os
import json
import queue
import shlex
from datetime import datetime
from typing import List, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from backend.core.config import Config, MissionProfile, ALL_CATEGORIES
from backend.core.safety import ConstraintWrapper
from backend.core.models import Finding
from backend.core.reporting import ReportGenerator
from backend.agents.crawler_agent import CrawlerAgent
from backend.agents.thinker_agent import ThinkerAgent
from backend.agents.executor_agent import ExecutorAgent
from backend.agents.verification import ValidatorAgent, VerifierAgent
from backend.agents.auth_agent import AuthAgent
from backend.agents.workflows import StoredXSSWorkflow
from backend.agents.recon_agent import ReconAgent, PlaywrightReconAgent
import re

try:
    from langsmith import traceable
    from langsmith.run_helpers import get_current_run_tree, tracing_context, trace as ls_trace
    LANGSMITH_AVAILABLE = True
except ImportError:
    def traceable(**kwargs):
        def decorator(func):
            return func
        return decorator
    def get_current_run_tree():
        return None
    def tracing_context(**kwargs):
        import contextlib
        return contextlib.nullcontext()
    def ls_trace(*args, **kwargs):
        import contextlib
        return contextlib.nullcontext()
    LANGSMITH_AVAILABLE = False

class SwarmOrchestrator:
    def __init__(self, mission_profile: MissionProfile, log_callback: Callable[[str], None] = None):
        self.mission = mission_profile
        self.safety = ConstraintWrapper()
        self.log_callback = log_callback
        self.is_running = False
        
        # Initialize Agents
        self.crawler = CrawlerAgent()
        self.thinker = ThinkerAgent()
        self.executor = ExecutorAgent()
        self.validator = ValidatorAgent()
        self.verifier = VerifierAgent()
        self.recon = ReconAgent()
        self.deep_recon = PlaywrightReconAgent()
        
        # Authentication and Stored XSS support
        self.auth_agent = AuthAgent(mission_profile.target_url)
        self.stored_xss = None  # Initialized after auth
        
        self.findings: List[Finding] = []
        self.verification_queue = queue.Queue()  # Real-time verification queue
        self.verified_findings: List[Finding] = []
        self.rejected_findings: List[Finding] = []
        self.auth_headers = {} # Store auth headers for curl commands
        self.report_dir = None  # Will be set when mission starts
        self.finding_count = 0 
        self._verifier_thread = None
        self._seen_endpoint_categories = set()  # Dedup: (endpoint, category) combos

        
        # Progress tracking
        self.total_work = 0
        self.completed_work = 0
        self.current_endpoint = ""
        self.current_category = ""

    def log(self, message: str):
        # Color coding for terminal output
        color_code = ""
        reset_code = "\033[0m"
        
        if "VULNERABILITY CONFIRMED" in message or "SUCCESS" in message:
            color_code = "\033[92m" # Green
        elif "REJECTED" in message or "failed" in message.lower() or "error" in message.lower() or "Critical" in message:
            color_code = "\033[91m" # Red
        elif "Hypothesis" in message:
            color_code = "\033[94m" # Blue
        elif "Safety Valve" in message or "Skipping" in message:
            color_code = "\033[93m" # Yellow
            
        print(f"{color_code}[Orchestrator] {message}{reset_code}")
        
        if self.log_callback:
            self.log_callback(message)
    
    def emit_progress(self):
        """Emit structured progress event for frontend."""
        if self.total_work > 0:
            percent = int((self.completed_work / self.total_work) * 100)
        else:
            percent = 0
        
        progress_data = f"PROGRESS:{percent}|{self.completed_work}|{self.total_work}|{self.current_endpoint[:40]}|{self.current_category}"
        if self.log_callback:
            self.log_callback(progress_data)

    def _create_report_directory(self):
        """Create a unique report directory for this scan run."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_name = self.mission.target_url.replace("https://", "").replace("http://", "").replace("/", "_")[:30]
        dir_name = f"reports/scan_{timestamp}_{target_name}"
        os.makedirs(dir_name, exist_ok=True)
        self.report_dir = dir_name
        self.log(f"Report directory created: {dir_name}")
        return dir_name

    def start(self):
        self.is_running = True
        self._create_report_directory()
        self.log(f"Starting Swarm on {self.mission.target_url}")
        self.log(f"Active Modules: {', '.join(self.mission.selected_modules)}")
        
        thread = threading.Thread(target=self._run_mission)
        thread.start()

    def stop(self):
        self.log("Stopping Swarm...")
        self.is_running = False

    @traceable(run_type="chain", name="PenTest Scan")
    def _run_mission(self):
        # Capture parent trace for thread context propagation
        self._parent_run = get_current_run_tree() if LANGSMITH_AVAILABLE else None
        try:
            # 0.5. Reconnaissance Phase (Shannon Integration)
            # 0.5. Reconnaissance Phase
            self.log("Phase 0.5: Asset Discovery...")
            try:
                recon_data = self.recon.run_recon(self.mission.target_url)
                num_subs = len(recon_data.get('subdomains', []))
                domain = list(recon_data.get('open_ports', {}).keys())[0] if recon_data.get('open_ports') else "target"
                num_ports = len(recon_data.get('open_ports', {}).get(domain, []))
                self.log(f"Recon Complete. Found {num_subs} subdomains, {num_ports} open ports.")
                
                # Store recon data for other agents to use
                self.mission.context['recon'] = recon_data
            except Exception as e:
                self.log(f"Reconnaissance failed (non-critical): {e}")

            # 1. Manual Authentication Headers overriding (if provided via UI)
            if hasattr(self.mission, 'headers') and self.mission.headers:
                self.log(f"Applying {len(self.mission.headers)} manual authentication headers...")
                session = self.auth_agent.get_session()
                session.headers.update(self.mission.headers)
                self.auth_headers.update(self.mission.headers)
                self.executor.session = session
                
                # Also pass manual headers to the stored XSS browser context if possible
                browser_context = getattr(self.auth_agent, 'browser_context', None)
                self.stored_xss = StoredXSSWorkflow(session, browser_context)

            # 2. Automated Authentication Phase (Optional but enables more testing)
            else:
                self.log("Phase 0: Authentication setup...")
                auth_success = self.auth_agent.setup_auth(self.mission.target_url)
                if auth_success:
                    self.log("✅ Authenticated - will test protected endpoints")
                    # Use authenticated session for executor
                    session = self.auth_agent.get_session()
                    self.executor.session = session
                    
                    # Extract headers for curl commands (Cookie, Authorization)
                    if session.headers:
                        # Exclude Accept-Encoding to prevent gzip responses that curl/python fail to decode without --compressed
                        self.auth_headers.update({k: v for k, v in session.headers.items() if k.lower() not in ['content-length', 'host', 'content-type', 'accept-encoding']})
                    if session.cookies:
                        cookie_str = "; ".join([f"{c.name}={c.value}" for c in session.cookies])
                        self.auth_headers['Cookie'] = cookie_str
                    
                    # Initialize stored XSS workflow with auth session AND browser context
                    browser_context = getattr(self.auth_agent, 'browser_context', None)
                    self.stored_xss = StoredXSSWorkflow(self.auth_agent.get_session(), browser_context)
                else:
                    self.log("⚠️ Automated Authentication failed - testing unauthenticated only (or using manual headers if provided)")
                    session = self.auth_agent.get_session()
                    self.executor.session = session
                    self.stored_xss = StoredXSSWorkflow(session, None)
            
            # Start real-time verification worker
            self._start_verification_worker()
            
            # 0.7. Deep Recon Phase (Playwright-powered traffic interception)
            deep_recon_endpoints = {}
            if hasattr(self.mission, 'headers') and self.mission.headers:
                self.log("Phase 0.7: Deep Recon (Playwright traffic interception)...")
                try:
                    deep_recon_endpoints = self.deep_recon.discover(
                        self.mission.target_url, 
                        headers_a=self.mission.headers,
                        nav_depth=5
                    )
                    self.log(f"Deep Recon discovered {len(deep_recon_endpoints)} API endpoints")
                    
                    # Run IDOR check if Session B headers are provided
                    headers_b = getattr(self.mission, 'headers_b', {})
                    if headers_b:
                        self.log("Phase 0.8: IDOR Cross-Account Testing...")
                        idor_results = self.deep_recon.run_idor_check(
                            self.mission.headers, headers_b, log_callback=self.log
                        )
                        for idor in idor_results:
                            self.finding_count += 1
                            self.log(f"VULNERABILITY CONFIRMED #{self.finding_count}: Access Control (IDOR) at {idor['url']}")
                            finding = Finding(
                                id=self.finding_count,
                                category="Access Control",
                                endpoint=idor['url'],
                                description=f"IDOR: Session B accessed {idor['method']} {idor['url']}",
                                evidence=idor['evidence'],
                                curl_command=f"curl \"{idor['url']}\" -H \"Cookie: [SESSION_B_COOKIE]\""
                            )
                            self.findings.append(finding)
                            ReportGenerator.generate_finding_report(finding, self.report_dir)
                except Exception as e:
                    self.log(f"Deep Recon failed (non-critical): {e}")
            
            # 1. Discovery Phase (HTML Crawler — merged with Deep Recon results)
            self.log("Phase I: Discovery initiated.")
            endpoint_data = self.crawler.discover_endpoints(self.mission.target_url, Config.MAX_CRAWL_DEPTH)
            
            # Merge deep recon endpoints into crawler results
            for ep, params in deep_recon_endpoints.items():
                if ep not in endpoint_data:
                    endpoint_data[ep] = params
                else:
                    endpoint_data[ep] = set(endpoint_data[ep]) | set(params)
            
            # DOM Analysis deferred to Phase IV (end of scan)
            
            # Merge API endpoints discovered during authentication (CRITICAL for SPAs)
            if self.auth_agent and hasattr(self.auth_agent, 'discovered_apis') and self.auth_agent.discovered_apis:
                count = 0
                for api_url in self.auth_agent.discovered_apis:
                    base_api = api_url.split('?')[0]
                    if base_api not in endpoint_data:
                        # Seed with common ID parameters for testing
                        endpoint_data[base_api] = ['id', 'q']
                        count += 1
                if count > 0:
                    self.log(f"Merged {count} API endpoints found during authentication")
            
            # Filter out static assets (not worth testing)
            STATIC_EXTENSIONS = ('.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', 
                                 '.woff', '.woff2', '.ttf', '.eot', '.map', '.webp', '.mp4', '.mp3',
                                 '.pdf', '.zip', '.tar', '.gz', '.rar', '.json')  # .json added to avoid translation files
            filtered_endpoints = {}
            for ep, params in endpoint_data.items():
                ep_lower = ep.lower().split('?')[0]  # Strip query params for extension check
                if not any(ep_lower.endswith(ext) for ext in STATIC_EXTENSIONS):
                    filtered_endpoints[ep] = params
                else:
                    self.log(f"Skipping static asset: {ep.split('/')[-1]}")
            
            endpoint_data = filtered_endpoints
            
            # Filter out endpoints that don't belong to the target app's root domain
            # E.g., for Gruyere with instance ID /571.../, filter out /0, /1, /start etc.
            from urllib.parse import urlparse as _ep_urlparse
            from backend.core.config import get_root_domain
            
            target_parsed = _ep_urlparse(self.mission.target_url)
            target_domain = target_parsed.netloc.split(':')[0]
            target_root_domain = get_root_domain(target_domain)
            target_path_prefix = target_parsed.path.rstrip('/')
            
            valid_endpoints = {}
            for ep, params in endpoint_data.items():
                ep_parsed = _ep_urlparse(ep)
                ep_domain = ep_parsed.netloc.split(':')[0]
                
                # Skip endpoints on completely different root domains
                if ep_domain and get_root_domain(ep_domain) != target_root_domain:
                    self.log(f"Skipping off-domain: {ep}")
                    continue
                
                ep_path = ep_parsed.path.rstrip('/')
                
                # If target has a long path prefix (like Gruyere instance ID),
                # skip endpoints that are just short root paths (/0, /1, /start)
                if len(target_path_prefix) > 5 and ep_domain == target_domain:
                    # Target has a significant path - endpoint should share it or be an API path
                    if not ep_path.startswith(target_path_prefix) and len(ep_path) < 10:
                        self.log(f"Skipping invalid path: {ep} (missing target prefix)")
                        continue
                
                valid_endpoints[ep] = params
            
            endpoint_data = valid_endpoints
            
            # Prioritize high-value endpoints (login, user, admin, search, API) first
            def endpoint_priority(item):
                ep = item[0].lower()
                params = item[1]
                score = 50  # Default priority
                
                # High-value patterns (lower score = tested first)
                if any(kw in ep for kw in ['login', 'signin', 'auth', 'token']):
                    score = 5
                elif any(kw in ep for kw in ['user', 'account', 'profile', 'admin']):
                    score = 10
                elif any(kw in ep for kw in ['search', 'query', 'find', 'filter']):
                    score = 15
                elif '/api/' in ep or '/rest/' in ep:
                    score = 20
                elif any(kw in ep for kw in ['password', 'reset', 'register', 'signup']):
                    score = 25
                elif any(kw in ep for kw in ['upload', 'file', 'import', 'export']):
                    score = 30
                elif any(kw in ep for kw in ['redirect', 'callback', 'return', 'next']):
                    score = 35
                
                # Endpoints with more params are more interesting
                if isinstance(params, (set, list)) and len(params) > 2:
                    score -= 5
                    
                return score
            
            sorted_endpoints = sorted(endpoint_data.items(), key=endpoint_priority)
            endpoint_data = dict(sorted_endpoints)
            
            num_endpoints = len(endpoint_data)
            num_categories = len(self.mission.selected_modules)
            self.total_work = num_endpoints * num_categories
            self.completed_work = 0
            self.log(f"Testing {num_endpoints} dynamic endpoints. Total tests: {self.total_work} ({num_endpoints} endpoints × {num_categories} categories)")
            self.emit_progress()
            
            # Log ALL discovered endpoints
            self.log(f"ENDPOINTS_LIST_START:{num_endpoints}")
            for idx, (ep, params) in enumerate(endpoint_data.items(), 1):
                param_str = ', '.join(str(p) for p in params) if params else 'none'
                self.log(f"ENDPOINT:[{idx}/{num_endpoints}] {ep} (params: {param_str})")
            self.log(f"ENDPOINTS_LIST_END:{num_endpoints}")
            
            self.log(f"Launching parallel scan with 10 workers...")
            with ThreadPoolExecutor(max_workers=10) as scan_pool:
                scan_futures = []
                
                for endpoint, discovered_params in endpoint_data.items():
                    if not self.is_running: break
                    
                    # Check forbidden paths
                    if self.safety.is_forbidden(endpoint):
                        self.log(f"Skipping forbidden path: {endpoint}")
                        continue

                    # Wait for rate limit capacity (blocks instead of skipping)
                    self.safety.acquire_request_slot()
                    
                    for category_name in self.mission.selected_modules:
                        if not self.is_running: break
                        # Pass discovered_params explicitly to avoid race conditions
                        # Wrap with tracing context so LangSmith shows as child of root trace
                        parent_run = self._parent_run
                        def _traced_endpoint(ep, cat, params, _pr=parent_run):
                            if _pr and LANGSMITH_AVAILABLE:
                                with tracing_context(parent=_pr):
                                    with ls_trace(name=f"Test: {cat} @ {ep.split('/')[-1] or ep.split('/')[-2]}", run_type="chain"):
                                        return self._process_endpoint_category(ep, cat, params)
                            return self._process_endpoint_category(ep, cat, params)
                        future = scan_pool.submit(_traced_endpoint, endpoint, category_name, discovered_params)
                        scan_futures.append(future)
                
                # Wait for completion and update progress
                for future in as_completed(scan_futures):
                    if not self.is_running: 
                        scan_pool.shutdown(wait=False)
                        break
                    try:
                        future.result()
                        self.completed_work += 1
                        self.emit_progress()
                    except Exception as e:
                        self.log(f"Scan task failed: {e}")
            
            # 3. Stored XSS Testing Phase (if authenticated and Cross-Site enabled)
            if self.stored_xss and 'Cross-Site' in self.mission.selected_modules:
                self.log("Phase III: Testing for Stored XSS... [DISABLED]")
                # stored_findings = self.stored_xss.test_stored_xss(self.mission.target_url)
                stored_findings = []
                
                for sf in stored_findings:
                    self.finding_count += 1
                    self.log(f"STORED XSS CONFIRMED #{self.finding_count}: {sf['type']} at {sf['endpoint']}")
                    
                    finding = Finding(
                        title=f"Stored XSS #{self.finding_count} in {sf['endpoint']}",
                        category="Cross-Site (Stored)",
                        confidence=1.0,
                        reproduction_steps=[
                            f"Login to application",
                            f"Submit payload to {sf.get('submit_url', 'form')}",
                            f"Navigate to {sf['endpoint']}",
                            f"Payload: {sf['payload']}"
                        ],
                        http_trace={
                            "request": f"POST {sf.get('submit_url', 'form')}", 
                            "response": sf['evidence']
                        },
                        termination_reason="Payload persisted and reflected unescaped"
                    )
                    self.findings.append(finding)
                    self._save_finding_report(finding)
                
                # Also test file upload XSS
                file_findings = self.stored_xss.test_file_upload_xss(self.mission.target_url)
                for ff in file_findings:
                    self.finding_count += 1
                    self.log(f"FILE UPLOAD XSS #{self.finding_count}: {ff['type']}")
                    
                    finding = Finding(
                        title=f"File Upload XSS #{self.finding_count}",
                        category="Cross-Site (File Upload)",
                        confidence=0.9,
                        reproduction_steps=[
                            f"Login to application",
                            f"Upload HTML file to {ff['endpoint']}",
                            f"Access uploaded file"
                        ],
                        http_trace={
                            "request": f"UPLOAD {ff['endpoint']}", 
                            "response": ff['evidence']
                        },
                        termination_reason="HTML file with script accepted for upload"
                    )
                    self.findings.append(finding)
                    self._save_finding_report(finding)
            
            # === Phase IV: Static JS / DOM Analysis ===
            # Moved here so it doesn't block the main attack scan
            js_files = list(getattr(self.crawler, 'js_files', set()))
            if js_files and self.is_running:
                total_js = len(js_files)
                self.log(f"Phase IV: DOM Analysis — {total_js} JS files")
                self.log(f"DOM_CHECKLIST_START:{total_js}")
                dom_vulns_found = 0
                
                for idx, js_url in enumerate(js_files, 1):
                    if not self.is_running: break
                    js_name = js_url.split('/')[-1][:40]
                    try:
                        resp = requests.get(js_url, timeout=10)
                        if resp.status_code == 200:
                            vulns = self.thinker.analyze_js_data_flow(js_url, resp.text)
                            if vulns:
                                vuln_types = [v.get('type', 'Unknown') for v in vulns if v.get('type')]
                                dom_vulns_found += len(vuln_types)
                                for v in vulns:
                                    if not v.get('type'): continue
                                    self.findings.append({
                                        "category": "Client-Side",
                                        "endpoint": js_url,
                                        "description": f"Static Analysis detected {v.get('type')}",
                                        "evidence": json.dumps(v, indent=2)
                                    })
                                self.log(f"DOM_CHECK:[{idx}/{total_js}] ✅ {js_name} — {len(vuln_types)} issue(s)")
                            else:
                                self.log(f"DOM_CHECK:[{idx}/{total_js}] — {js_name} — clean")
                        else:
                            self.log(f"DOM_CHECK:[{idx}/{total_js}] ⚠️ {js_name} — HTTP {resp.status_code}")
                    except Exception as e:
                        self.log(f"DOM_CHECK:[{idx}/{total_js}] ❌ {js_name} — error")
                
                self.log(f"DOM_CHECKLIST_END:{dom_vulns_found}")
                self.log(f"Phase IV Complete: {dom_vulns_found} potential DOM vulnerabilities found in {total_js} JS files")
            
        except Exception as e:
            import traceback
            self.log(f"Critical Error: {str(e)}\n{traceback.format_exc()}")
        finally:
            # Signal verification thread to finish and wait for it
            self.verification_queue.put(None)  # Sentinel to stop the worker
            if self._verifier_thread and self._verifier_thread.is_alive():
                self.log("Waiting for verification to finish...")
                self._verifier_thread.join(timeout=120)
            
            # Generate summary report
            if self.verified_findings or self.rejected_findings:
                self._generate_summary_report()
            self.log(f"Mission Complete. Verified: {len(self.verified_findings)} | Rejected: {len(self.rejected_findings)}")
            self.is_running = False

    def _start_verification_worker(self):
        """Start background thread that verifies findings in real-time as they're queued."""
        def worker():
            self.log("[Verifier] Background verification thread started.")
            with ThreadPoolExecutor(max_workers=10) as pool:
                futures = {}
                
                while True:
                    try:
                        finding = self.verification_queue.get(timeout=2)
                    except queue.Empty:
                        # Check completed futures while waiting
                        self._collect_verified(futures)
                        continue
                    
                    if finding is None:  # Sentinel — scan is done
                        # Wait for remaining futures
                        self._collect_verified(futures, wait_all=True)
                        self.log(f"[Verifier] Thread finished. Verified: {len(self.verified_findings)} | Rejected: {len(self.rejected_findings)}")
                        break
                    
                    # Submit for verification with trace context
                    parent_run = getattr(self, '_parent_run', None)
                    def _traced_verify(f, _pr=parent_run):
                        if _pr and LANGSMITH_AVAILABLE:
                            with tracing_context(parent=_pr):
                                with ls_trace(name=f"Verify: {f.title[:40]}", run_type="chain"):
                                    return self._verify_one(f)
                        return self._verify_one(f)
                    future = pool.submit(_traced_verify, finding)
                    futures[future] = finding
                    
                    # Collect any already-completed results
                    self._collect_verified(futures)
        
        self._verifier_thread = threading.Thread(target=worker, daemon=True)
        self._verifier_thread.start()
    
    @traceable(run_type="chain", name="Verify Finding")
    def _verify_one(self, finding):
        """Verify a single finding and emit result immediately via SSE."""
        # Extract finding number from title (e.g., "Injection #2 in ..." → "2")
        import re
        num_match = re.search(r'#(\d+)', finding.title)
        finding_num = num_match.group(1) if num_match else '0'
        
        try:
            result = self.verifier.verify_finding(finding)
            status = 'verified' if result.get('verified', False) else 'rejected'
            
            # Emit structured message for reliable frontend parsing
            self.log(f"FINDING_STATUS:{finding_num}|{status}|{finding.title}")
            
            # Also emit human-readable message for the log pane
            if status == 'verified':
                self.log(f"✅ VERIFIED: {finding.title} — {result.get('verdict', '')}")
            else:
                self.log(f"❌ REJECTED: {finding.title} — {result.get('verdict', '')}")
            return finding, result
        except Exception as e:
            print(f"[Verifier] Error: {e}")
            self.log(f"FINDING_STATUS:{finding_num}|rejected|{finding.title}")
            self.log(f"❌ REJECTED: {finding.title} — Error: {e}")
            return finding, {"verified": False, "verdict": f"Error: {e}", "curl_output": ""}
    
    def _collect_verified(self, futures: dict, wait_all: bool = False):
        """Collect completed verification results and save reports immediately."""
        done = [f for f in futures if f.done()] if not wait_all else list(futures.keys())
        
        if wait_all and futures:
            from concurrent.futures import wait
            wait(futures.keys())
            done = list(futures.keys())
        
        for future in done:
            finding, result = future.result()
            del futures[future]
            
            if result.get('verified', False):
                # TRUE POSITIVE — save report immediately
                finding.http_trace['verification_verdict'] = result.get('verdict', '')
                finding.http_trace['verification_curl_output'] = result.get('curl_output', '')
                finding.http_trace['verified'] = True
                self.verified_findings.append(finding)
                
                report_filename = f"finding_{len(self.verified_findings)}_{finding.category.replace(' ', '_').lower()}.md"
                report_path = os.path.join(self.report_dir, report_filename)
                ReportGenerator.save_report(finding, report_path)
                self.log(f"Report saved: {report_path}")
            else:
                # FALSE POSITIVE — reject, no report
                finding.http_trace['verification_verdict'] = result.get('verdict', '')
                finding.http_trace['verified'] = False
                self.rejected_findings.append(finding)
                self._log_rejected_finding(finding, result) # Log to file for audit

    @traceable(run_type="chain", name="Generate Summary Report")
    def _generate_summary_report(self):
        """Generate a summary report of all findings with verification status."""
        summary_path = os.path.join(self.report_dir, "SUMMARY.md")
        with open(summary_path, "w") as f:
            f.write(f"# Vulnerability Scan Summary\n\n")
            f.write(f"**Target:** {self.mission.target_url}\n")
            f.write(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Verified Vulnerabilities:** {len(self.verified_findings)}\n")
            f.write(f"**Rejected (False Positives):** {len(self.rejected_findings)}\n\n")
            
            if self.verified_findings:
                f.write("## ✅ Verified Findings\n\n")
                f.write("| # | Category | Endpoint | Confidence | Verdict |\n")
                f.write("|---|----------|----------|------------|---------|\n")
                for i, finding in enumerate(self.verified_findings, 1):
                    endpoint_short = finding.title.split(" in ")[-1][:40]
                    verdict = finding.http_trace.get('verification_verdict', '')[:50]
                    f.write(f"| {i} | {finding.category} | {endpoint_short}... | {finding.confidence * 100:.0f}% | {verdict} |\n")
            
            if self.rejected_findings:
                f.write(f"\n## ❌ Rejected Findings (False Positives)\n\n")
                f.write("| # | Category | Endpoint | Rejection Reason |\n")
                f.write("|---|----------|----------|-----------------|\n")
                for i, finding in enumerate(self.rejected_findings, 1):
                    endpoint_short = finding.title.split(" in ")[-1][:40]
                    verdict = finding.http_trace.get('verification_verdict', '')[:60]
                    f.write(f"| {i} | {finding.category} | {endpoint_short}... | {verdict} |\n")
            
            f.write(f"\n---\n\nSee individual report files for verified findings.\n")
        self.log(f"Summary report generated: {summary_path}")

    def _take_screenshot(self, finding_id: int, url: str, payload: str = None, method: str = 'GET', param: str = None, category: str = 'Security') -> str:
        """Take a screenshot of the vulnerable page with payload for PoC evidence."""
        try:
            from playwright.sync_api import sync_playwright
            from urllib.parse import urlencode, quote
            
            screenshot_path = os.path.join(self.report_dir, f"screenshot_{finding_id}.png")
            
            # Build the PoC URL with the ORIGINAL payload (not popup version)
            # We'll inject the popup overlay via Playwright after the page loads
            poc_url = url
            if payload:
                if 'INJECT_HERE' in url:
                    # Path-based injection - use original payload
                    poc_url = url.replace('INJECT_HERE', quote(payload))
                elif param and param.lower() not in ['null', 'none', '']:
                    # Parameter-based injection
                    poc_url = f"{url}?{param}={quote(payload)}"
                else:
                    # Default: append as query
                    poc_url = f"{url}?payload={quote(payload)}"
            
            # Popup overlay JS to inject via Playwright (not in URL)
            # Dynamic message based on vulnerability category
            category_upper = category.upper().replace('-', ' ')
            popup_overlay_js = f"""
            (function(){{
                var overlay=document.createElement('div');
                overlay.style.cssText='position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.6);z-index:999998;display:flex;justify-content:center;align-items:center';
                var popup=document.createElement('div');
                popup.style.cssText='background:white;border-radius:12px;padding:30px 50px;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.4);font-family:system-ui,sans-serif;max-width:400px';
                popup.innerHTML='<div style="font-size:48px;margin-bottom:15px">⚠️</div><div style="font-size:22px;font-weight:bold;color:#c00;margin-bottom:10px">{category_upper} VULNERABILITY CONFIRMED</div><div style="font-size:14px;color:#666;margin-bottom:20px">Security issue detected on this page</div><div style="background:#0066cc;color:white;padding:10px 40px;border-radius:6px;font-size:14px;font-weight:500;display:inline-block">OK</div>';
                overlay.appendChild(popup);
                document.body.appendChild(overlay);
            }})()
            """
            
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                
                if method == 'POST' and payload:
                    # For POST endpoints: send actual POST request and display the response
                    import json as json_mod
                    
                    # Navigate to a blank page first
                    page.goto('about:blank')
                    
                    # Build the POST body
                    post_body = {}
                    if param and param.lower() not in ['null', 'none', '']:
                        post_body[param] = payload
                    
                    try:
                        # Use Playwright's API to make the actual POST request
                        api_response = page.request.post(url, data=json_mod.dumps(post_body), headers={
                            'Content-Type': 'application/json'
                        })
                        response_text = api_response.text()
                        response_status = api_response.status
                        
                        # Try to pretty-format JSON responses
                        try:
                            parsed = json_mod.loads(response_text)
                            display_body = json_mod.dumps(parsed, indent=2)
                        except:
                            display_body = response_text[:2000]
                        
                        # Render the response in the browser as a nice PoC page
                        display_body_escaped = display_body.replace('\\', '\\\\').replace('`', '\\`').replace('$', '\\$')
                        page.evaluate(f"""() => {{
                            document.title = 'POST {url} — Status {response_status}';
                            document.body.style.cssText = 'background:#1a1a2e;color:#e0e0e0;font-family:monospace;padding:30px;margin:0';
                            document.body.innerHTML = `
                                <div style="max-width:900px;margin:0 auto">
                                    <h2 style="color:#00d4ff;margin-bottom:5px">POST {url}</h2>
                                    <div style="color:#888;margin-bottom:15px">Status: <span style="color:{'#4caf50' if response_status < 400 else '#ff5252'}">{response_status}</span></div>
                                    <div style="background:#16213e;padding:8px 12px;border-radius:6px;margin-bottom:15px;font-size:13px">
                                        <span style="color:#888">Request Body:</span> <span style="color:#ffd54f">{json_mod.dumps(post_body)}</span>
                                    </div>
                                    <div style="background:#0f3460;padding:15px;border-radius:8px;overflow-x:auto;white-space:pre-wrap;font-size:12px;line-height:1.5;max-height:400px;overflow-y:auto">${display_body_escaped}</div>
                                </div>
                            `;
                        }}""")
                    except Exception as post_err:
                        # If POST fails, just show the base URL of the application
                        base_url = '/'.join(url.split('/')[:3])
                        page.goto(base_url, timeout=10000)
                else:
                    # For GET, navigate to the PoC URL with payload
                    page.goto(poc_url, timeout=10000, wait_until='networkidle')
                
                page.wait_for_timeout(500)  # Let page render
                
                # Inject popup overlay AFTER page loads
                try:
                    page.evaluate(popup_overlay_js)
                except:
                    pass  # If JS injection fails, still take screenshot
                
                page.wait_for_timeout(300)  # Let popup render
                page.screenshot(path=screenshot_path)
                browser.close()
            
            self.log(f"Screenshot captured: {screenshot_path}")
            return screenshot_path
        except Exception as e:
            self.log(f"Screenshot failed: {str(e)}")
            return None

    def _build_curl_command(self, endpoint: str, method: str, param: str, payload: str, 
                         additional_params: dict = None, result: dict = None) -> str:
        """Build a reproducible curl command from the actual request the executor sent, including AUTH."""
        import json
        import shlex
        from urllib.parse import quote, urlencode
        
        # Build headers string
        headers_str = ""
        if self.auth_headers:
            for k, v in self.auth_headers.items():
                headers_str += f' -H "{k}: {v}"'
        
        # Handle path-based injection: replace INJECT_HERE placeholder with actual payload
        if 'INJECT_HERE' in endpoint:
            resolved_url = endpoint.replace('INJECT_HERE', quote(payload))
            return f'curl "{resolved_url}"{headers_str}'
        
        # If executor provided exact request details, use them
        if result and 'req_type' in result and 'req_data' in result:
            req_type = result['req_type']
            req_data = result['req_data']
            
            if req_type == 'json' and isinstance(req_data, dict):
                body_str = json.dumps(req_data)
                return f'curl -X POST "{endpoint}"{headers_str} -H "Content-Type: application/json" -d {shlex.quote(body_str)}'
            elif req_type == 'form' and isinstance(req_data, dict):
                form_str = urlencode(req_data)
                return f'curl -X POST "{endpoint}"{headers_str} -d "{form_str}"'
            elif req_type == 'query' and isinstance(req_data, dict):
                query_str = urlencode(req_data)
                return f'curl "{endpoint}?{query_str}"{headers_str}'
        
        # Fallback: generic curl construction
        if method.upper() == 'POST':
            body = {}
            if param and str(param).lower() not in ['null', 'none', '']:
                body[param] = payload
            if additional_params:
                body.update(additional_params)
            body_str = json.dumps(body)
            return f'curl -X POST "{endpoint}"{headers_str} -H "Content-Type: application/json" -d {shlex.quote(body_str)}'
        else:
            if param and str(param).lower() not in ['null', 'none', '']:
                return f'curl "{endpoint}?{param}={quote(payload)}"{headers_str}'
            else:
                return f'curl "{endpoint}"{headers_str}'

    def _log_rejected_finding(self, finding: Finding, result: dict):
        """Append rejected finding details to a markdown log for manual review."""
        if not self.report_dir: return
        
        log_path = os.path.join(self.report_dir, "rejected_findings.md")
        
        # Create file with header if it doesn't exist
        if not os.path.exists(log_path):
            with open(log_path, "w") as f:
                f.write("# ❌ Rejected Findings Log\n")
                f.write("Findings rejected by the Validator. Review for false negatives.\n\n")
                
        with open(log_path, "a") as f:
            f.write(f"## {finding.title}\n")
            f.write(f"- **Verdict:** {result.get('verdict', 'Unknown')}\n")
            f.write(f"- **Curl:** `{finding.http_trace.get('curl_command', 'N/A')}`\n")
            f.write(f"- **Reason:** Validator failed to confirm exploitation.\n")
            # f.write(f"- **Evidence:** ```{finding.http_trace.get('response', '')[:200]}```\n")
            f.write("---\n")

    def _save_finding_report(self, finding: Finding):
        """Save a finding report to the reports directory."""
        if not self.report_dir:
            return
            
        # Create a safe filename
        safe_title = re.sub(r'[^a-zA-Z0-9]', '_', finding.title.lower())
        filename = f"finding_{len(self.findings)}_{safe_title}.md"
        filepath = os.path.join(self.report_dir, filename)
        
        ReportGenerator.save_report(finding, filepath)
        self.log(f"Report saved: {filename}")

    @traceable(run_type="chain", name="Test Endpoint")
    def _process_endpoint_category(self, endpoint: str, category_name: str, discovered_params: List[str] = None):
        # Get application context from deep recon (if available)
        endpoint_context = ''
        if hasattr(self, 'deep_recon') and self.deep_recon:
            endpoint_context = self.deep_recon.get_context_for_endpoint(endpoint)
        
        # Generate Hypothesis
        hypothesis_data = self.thinker.generate_hypothesis(endpoint, category_name, context=endpoint_context)
        
        if not hypothesis_data:
            return

        current_confidence = hypothesis_data['confidence']
        payloads = hypothesis_data['payloads']
        hypothesis_text = hypothesis_data['hypothesis']
        
        self.log(f"Hypothesis ({category_name}): {hypothesis_text} (Conf: {current_confidence})")
        
        # Emit Progress Event for Frontend
        if self.total_work > 0:
            percent = int((self.completed_work / self.total_work) * 100)
            # Format: PROGRESS:percent|completed|total|endpoint|category
            self.log(f"PROGRESS:{percent}|{self.completed_work}|{self.total_work}|{endpoint}|{category_name}")
        
        mutation_count = 0
        vulns_found_this_hypothesis = 0
        
        for payload in payloads:
            if not self.is_running: break
            
            # Sanitize payload (LLM might return dict/list instead of string)
            if isinstance(payload, (dict, list)):
                import json
                try:
                    payload = json.dumps(payload)
                except:
                    payload = str(payload)
            elif payload is None:
                payload = ""
            else:
                payload = str(payload)
            
            # Safety Check: Mutations
            if mutation_count >= Config.MAX_MUTATIONS_PER_PARAM:
                self.log(f"Max mutations reached for {endpoint}. Moving to next.")
                break
                
            mutation_count += 1
            
            # 3. Execution Phase
            target_parameter = hypothesis_data.get('target_parameter')
            http_method = hypothesis_data.get('http_method', 'GET')
            result = self.executor.verify_payload(endpoint, payload, {
                'target_parameter': target_parameter, 
                'http_method': http_method,
                'category': category_name,
                'discovered_params': discovered_params or []
            })
            
            if self.validator.evaluate_results(result):
                # Dedup: Skip if this endpoint+category was already reported
                dedup_key = (endpoint, category_name)
                if dedup_key in self._seen_endpoint_categories:
                    self.log(f"Skipping duplicate: {category_name} at {endpoint} (already reported)")
                    continue
                self._seen_endpoint_categories.add(dedup_key)
                
                # SUCCESS - Found a vulnerability
                self.finding_count += 1
                vulns_found_this_hypothesis += 1
                
                # Use actual vulnerable param if identified during execution
                actual_param = result.get('vulnerable_param', target_parameter)
                
                self.log(f"VULNERABILITY CONFIRMED #{self.finding_count}: {category_name} at {endpoint}")
                
                # Build curl command from the ACTUAL request the executor sent
                curl_cmd = self._build_curl_command(endpoint, http_method, actual_param, payload, result=result)
                
                # Resolve INJECT_HERE placeholder for display purposes
                from urllib.parse import quote
                display_endpoint = endpoint.replace('INJECT_HERE', quote(payload)) if 'INJECT_HERE' in endpoint else endpoint
                
                finding = Finding(
                    title=f"{category_name} #{self.finding_count} in {display_endpoint}",
                    category=category_name,
                    confidence=1.0,
                    reproduction_steps=[
                        f"Navigate to {display_endpoint}", 
                        f"Inject payload: {payload}",
                        f"Observe the vulnerability in the response"
                    ],
                    http_trace={
                        "request": f"{http_method} {display_endpoint}?{actual_param}={payload}" if 'INJECT_HERE' not in endpoint else f"{http_method} {display_endpoint}", 
                        "response": result['evidence'],
                        "curl_command": curl_cmd
                    },
                    termination_reason="Exploit Verified"
                )
                self.findings.append(finding)
                self.verification_queue.put(finding)
                
                # Try to capture screenshot with actual payload for PoC
                screenshot_path = self._take_screenshot(
                    self.finding_count, 
                    endpoint, 
                    payload=payload,
                    method=http_method,
                    param=actual_param,
                    category=category_name
                )
                if screenshot_path:
                    finding.http_trace["screenshot"] = screenshot_path
                
                self.log(f"Finding queued for verification: {finding.title}")
                
                # CONTINUE testing other payloads - don't return!
                # Only skip if we've found too many of the same type
                if vulns_found_this_hypothesis >= 3:
                    self.log(f"Found {vulns_found_this_hypothesis} vulns for this hypothesis. Moving on.")
                    break
            
            else:
                # FAILURE - Decay Confidence
                current_confidence -= Config.DECAY_RATE
                # Decay log removed
                
                # === AI SELF-HEALING ===
                # If the error response contains clues, ask AI to fix the payload
                error_evidence = result.get('evidence', '')
                # If the error response contains clues, ask AI to fix the payload
                error_evidence = result.get('evidence', '')
                if error_evidence:
                    # self.log(f"✨ Self-Healing Triggered: Analyzing failure for {endpoint}...")
                    # Allow concurrent healing (removed shared _healing_active flag)
                    
                    adaptation = self.thinker.adapt_payload(
                        endpoint=endpoint,
                        category=category_name,
                        original_payload=payload,
                        error_response=error_evidence,
                        target_parameter=target_parameter,
                        http_method=http_method
                    )
                    
                    if adaptation:
                        corrected_payload = adaptation.get('corrected_payload', '')
                        additional_params = adaptation.get('additional_params', {})
                        adapted_method = adaptation.get('http_method', http_method)
                        adapted_param = adaptation.get('target_parameter', target_parameter)
                        
                        self.log(f"✨ Self-Healing Triggered: Retrying with corrected payload: {str(corrected_payload)[:50]}...")
                        if additional_params:
                            self.log(f"[Self-Healing] Adding missing params: {additional_params}")
                        
                        # Retry with AI-corrected payload
                        healed_result = self.executor.verify_payload(endpoint, str(corrected_payload), {
                            'target_parameter': adapted_param,
                            'http_method': adapted_method,
                            'category': category_name,
                            'discovered_params': discovered_params or [],
                            'additional_params': additional_params
                        })
                        
                        if self.validator.evaluate_results(healed_result):
                            # SELF-HEALING SUCCESS!
                            self.finding_count += 1
                            vulns_found_this_hypothesis += 1
                            actual_param = healed_result.get('vulnerable_param', adapted_param)
                            curl_cmd = self._build_curl_command(endpoint, adapted_method, actual_param, str(corrected_payload), additional_params)
                            
                            self.log(f"[Self-Healing] SUCCESS! Vulnerability #{self.finding_count} confirmed after adaptation.")
                            
                            finding = Finding(
                                title=f"{category_name} #{self.finding_count} in {endpoint}",
                                category=category_name,
                                confidence=1.0,
                                reproduction_steps=[
                                    f"Navigate to {endpoint}",
                                    f"Original payload failed: {payload}",
                                    f"AI-corrected payload: {corrected_payload}",
                                    f"Additional params needed: {additional_params}" if additional_params else "No additional params needed"
                                ],
                                http_trace={
                                    "request": f"{adapted_method} {endpoint}?{actual_param}={corrected_payload}",
                                    "response": healed_result['evidence'],
                                    "curl_command": curl_cmd,
                                    "self_healed": True
                                },
                                termination_reason="Exploit Verified (Self-Healed)"
                            )
                            self.findings.append(finding)
                            self.verification_queue.put(finding)
                            
                            screenshot_path = self._take_screenshot(
                                self.finding_count, endpoint,
                                payload=str(corrected_payload),
                                method=adapted_method,
                                param=actual_param,
                                category=category_name
                            )
                            if screenshot_path:
                                finding.http_trace["screenshot"] = screenshot_path
                            
                            self.log(f"[Self-Healing] Finding queued for verification: {finding.title}")
                        else:
                            self.log(f"[Self-Healing] Corrected payload also failed. Moving on.")
                    
                    self._healing_active = False  # Reset healing flag
                
                # Force Save "Low Confidence" Findings
                if "SQL Error" in result.get('evidence', ''):
                    self.finding_count += 1
                    self.log(f"Potential Vulnerability detected: {result['evidence'][:100]}...")
                    curl_cmd = self._build_curl_command(endpoint, http_method, 'p', payload)
                    finding = Finding(
                        title=f"Potential {category_name} #{self.finding_count} in {endpoint}",
                        category=category_name,
                        confidence=current_confidence,
                        reproduction_steps=[f"Navigate to {endpoint}", f"Inject: {payload}"],
                        http_trace={"request": f"{http_method} {endpoint}?p={payload}", "response": result['evidence'], "curl_command": curl_cmd},
                        termination_reason="Partial Evidence"
                    )
                    self.findings.append(finding)
                    report_filename = f"finding_{self.finding_count}_potential.md"
                    report_path = os.path.join(self.report_dir, report_filename)
                    ReportGenerator.save_report(finding, report_path)
                    self.log(f"Partial Report generated: {report_path}")
                
                if current_confidence < Config.CONFIDENCE_THRESHOLD:
                    self.log("Confidence too low. Abandoning hypothesis.")
                    break
