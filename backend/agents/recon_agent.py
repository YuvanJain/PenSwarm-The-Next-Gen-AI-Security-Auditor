import subprocess
import time
import requests
import socket
import json
import re
import shutil
import os
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

class ReconAgent:
    """
    Reconnaissance Agent.
     Performs Asset Discovery (Subdomains, Ports, Tech Stack) using Nmap (if available) or Python native tools.
    """
    def __init__(self):
        self.assets = set()
        self.ports = {}
        self.tech_stack = {}

    def discover_subdomains(self, domain: str):
        """Query crt.sh for subdomains."""
        print(f"[Recon] Enumerating subdomains for {domain}...")
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            headers = {'User-Agent': 'Mozilla/5.0 (Security Scanner)'}
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name_value = entry['name_value']
                    subdomains = name_value.split('\n')
                    for sub in subdomains:
                        if '*' not in sub:
                            self.assets.add(sub)
            print(f"[Recon] Found {len(self.assets)} subdomains.")
        except Exception as e:
            print(f"[Recon] Subdomain enum failed: {e}")

    def _check_nmap(self) -> str:
        """Check if nmap is available and return path."""
        path = shutil.which("nmap")
        if path: return path
        
        # Check common paths
        common_paths = [
            "/usr/local/bin/nmap",
            "/opt/homebrew/bin/nmap",
            "/usr/bin/nmap"
        ]
        for p in common_paths:
            if os.path.exists(p):
                return p
        return None

    def _scan_nmap(self, host: str, nmap_path: str) -> bool:
        """Run nmap scan."""
        print(f"[Recon] Running Nmap on {host} using {nmap_path}...")
        try:
            # -F: Fast mode (top 100 ports)
            # -T4: Aggressive timing
            # --open: Only show open ports
            cmd = [nmap_path, "-F", "-T4", "--open", host]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                # Parse output for open ports
                ports = []
                for line in result.stdout.splitlines():
                    if "/tcp" in line and "open" in line:
                        try:
                            port = int(line.split('/')[0])
                            ports.append(port)
                        except: pass
                self.ports[host] = ports
                print(f"[Recon] Nmap found ports: {ports}")
                return True
        except Exception as e:
            print(f"[Recon] Nmap failed: {e}")
        return False

    def scan_ports(self, host: str):
        """Scan ports using Nmap (preferred) or Python sockets."""
        # Try Nmap first
        nmap_path = self._check_nmap()
        if nmap_path:
            if self._scan_nmap(host, nmap_path):
                return
        
        # Fallback to Python Sockets
        top_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        print(f"[Recon] Scanning top {len(top_ports)} ports on {host} (Python Fallback)...")
        
        open_ports = []
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass

        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(check_port, top_ports)
            
        self.ports[host] = open_ports
        print(f"[Recon] Open ports on {host}: {open_ports}")

    def detect_tech(self, url: str):
        """Identify technologies from headers."""
        print(f"[Recon] Detecting tech stack for {url}...")
        try:
            resp = requests.get(url, timeout=5, verify=False)
            headers = resp.headers
            stack = []
            
            if 'Server' in headers:
                stack.append(f"Server: {headers.get('Server')}")
            if 'X-Powered-By' in headers:
                stack.append(f"PoweredBy: {headers.get('X-Powered-By')}")
            if 'X-AspNet-Version' in headers:
                stack.append("ASP.NET")
            if 'X-Generator' in headers: # WordPress etc
                 stack.append(f"Generator: {headers.get('X-Generator')}")
            
            # Simple body checks
            if "wp-content" in resp.text:
                stack.append("WordPress")
            if "react" in resp.text.lower() or "React" in resp.text:
                stack.append("React")
            if "angular" in resp.text.lower():
                stack.append("Angular")
            
            self.tech_stack[url] = stack
            print(f"[Recon] Tech identified: {stack}")
        except Exception as e:
            print(f"[Recon] Tech detection failed: {e}")

    def run_recon(self, target_url: str) -> dict:
        """Run full reconnaissance on target."""
        domain = urlparse(target_url).netloc.split(':')[0]
        print(f"[Recon] Starting analysis for: {domain}")
        
        # 1. Subdomain Enumeration (crt.sh)
        self.discover_subdomains(domain)
        
        # 2. Port Scanning (Top 20)
        self.scan_ports(domain)
        
        # 3. Tech Stack Detection
        self.detect_tech(target_url)
        
        return {
            "subdomains": list(self.assets),
            "open_ports": self.ports,
            "tech_stack": self.tech_stack
        }

class PlaywrightReconAgent:
    """
    Deep reconnaissance agent using Playwright to intercept live API traffic,
    extract page context, parse JS bundles, and perform multi-account IDOR testing.
    """
    
    def __init__(self):
        self.captured_apis = []       # List of dicts: {url, method, headers, body, status, response_snippet, content_type}
        self.page_contexts = []       # List of dicts: {page_url, title, headings, buttons, fields, description}
        self.js_api_endpoints = set() # API paths extracted from JS bundles
    
    def discover(self, target_url: str, headers_a: dict = None, nav_depth: int = 3) -> dict:
        """
        Navigate the target application using Playwright, intercepting all API traffic.
        Returns: Dict mapping endpoint URLs to discovered parameters + metadata.
        """
        print(f"[DeepRecon] Starting Playwright deep recon on {target_url}...")
        
        endpoint_data = {}  # url -> set of params
        api_details = []    # Full request/response metadata
        visited_pages = set()
        pages_to_visit = [target_url]
        
        try:
            from playwright.sync_api import sync_playwright
            from urllib.parse import urlparse, urljoin, parse_qs, urlencode
            import re as regex
            
            base_parsed = urlparse(target_url)
            base_domain = base_parsed.netloc
            base_scheme = base_parsed.scheme
            
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                
                # Create context with manual auth headers (cookies)
                context_options = {}
                if headers_a and 'Cookie' in headers_a:
                    # Parse cookie string into Playwright cookie format
                    cookie_str = headers_a['Cookie']
                    cookies = []
                    for part in cookie_str.split(';'):
                        part = part.strip()
                        if '=' in part:
                            name, value = part.split('=', 1)
                            cookies.append({
                                'name': name.strip(),
                                'value': value.strip(),
                                'domain': base_domain,
                                'path': '/'
                            })
                    context = browser.new_context()
                    context.add_cookies(cookies)
                else:
                    context = browser.new_context()
                
                # Add extra headers (Authorization, etc.)
                if headers_a:
                    extra_headers = {k: v for k, v in headers_a.items() if k.lower() != 'cookie'}
                    if extra_headers:
                        context.set_extra_http_headers(extra_headers)
                
                page = context.new_page()
                page.set_default_timeout(15000)
                
                # Get the root domain of the target to allow related subdomains (e.g., gate.sendbird.com from dashboard.sendbird.com)
                from backend.core.config import get_root_domain
                target_root_domain = get_root_domain(base_domain)
                
                # Common 3rd party domains to ignore even if they somehow match heuristically
                ignore_domains = {'google-analytics.com', 'sentry.io', 'mixpanel.com', 'segment.com', 'hotjar.com', 'newrelic.com', 'datadoghq.com', 'appdynamics.com', 'optimizely.com', 'googletagmanager.com'}
                
                # ── Traffic Interception ──
                def on_request(request):
                    try:
                        req_url = request.url
                        parsed = urlparse(req_url)
                        req_domain = parsed.netloc.split(':')[0]
                        
                        # Allow same-domain OR same-root-domain APIs (skip 3rd party analytics/CDN)
                        if req_domain in ignore_domains:
                            return
                            
                        # If it's not the exact domain, check if it shares the root domain
                        if req_domain != base_domain:
                            if get_root_domain(req_domain) != target_root_domain:
                                return
                                
                        # Skip static assets
                        static_exts = ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', 
                                      '.woff', '.woff2', '.ttf', '.eot', '.map', '.webp')
                        if any(parsed.path.lower().endswith(ext) for ext in static_exts):
                            return
                        
                        api_details.append({
                            'url': req_url.split('?')[0],  # Base URL without query
                            'full_url': req_url,
                            'method': request.method,
                            'post_data': request.post_data,
                            'resource_type': request.resource_type,
                        })
                    except Exception:
                        pass
                
                def on_response(response):
                    try:
                        resp_url = response.url.split('?')[0]
                        req = response.request
                        parsed = urlparse(response.url)
                        resp_domain = parsed.netloc.split(':')[0]
                        
                        if resp_domain in ignore_domains:
                            return
                            
                        if resp_domain != base_domain:
                            if get_root_domain(resp_domain) != target_root_domain:
                                return
                        
                        content_type = response.headers.get('content-type', '')
                        status = response.status
                        
                        # Try to get response body for API calls (JSON)
                        body_snippet = ''
                        if 'json' in content_type.lower() or 'api' in parsed.path.lower():
                            try:
                                body = response.text()
                                body_snippet = body[:500]
                            except Exception:
                                pass
                        
                        # Update captured_apis with response info
                        for api in api_details:
                            if api['url'] == resp_url and api['method'] == req.method:
                                api['status'] = status
                                api['content_type'] = content_type
                                api['response_snippet'] = body_snippet
                                break
                    except Exception:
                        pass
                
                page.on('request', on_request)
                page.on('response', on_response)
                
                # ── SPA Navigation ──
                depth = 0
                while pages_to_visit and depth < nav_depth:
                    current_batch = pages_to_visit[:20]  # Explore more pages per depth
                    pages_to_visit = pages_to_visit[20:]
                    
                    for page_url in current_batch:
                        if page_url in visited_pages:
                            continue
                        visited_pages.add(page_url)
                        
                        try:
                            page.goto(page_url, wait_until='networkidle', timeout=15000)
                            time.sleep(1)  # Let async JS requests complete
                            
                            # ── Context Extraction ──
                            page_context = page.evaluate("""
                                () => {
                                    const ctx = {
                                        title: document.title || '',
                                        headings: [],
                                        buttons: [],
                                        fields: [],
                                        links: []
                                    };
                                    
                                    // Headings
                                    document.querySelectorAll('h1, h2, h3').forEach(h => {
                                        const text = h.innerText?.trim();
                                        if (text && text.length < 100) ctx.headings.push(text);
                                    });
                                    
                                    // Buttons and clickable actions
                                    document.querySelectorAll('button, [role="button"], a.btn, input[type="submit"]').forEach(b => {
                                        const text = (b.innerText || b.value || b.getAttribute('aria-label') || '').trim();
                                        if (text && text.length < 50) ctx.buttons.push(text);
                                    });
                                    
                                    // Form fields
                                    document.querySelectorAll('input[name], textarea[name], select[name]').forEach(f => {
                                        ctx.fields.push(f.name);
                                    });
                                    
                                    // Navigation links (for further crawling)
                                    document.querySelectorAll('a[href]').forEach(a => {
                                        if (a.href && !a.href.startsWith('javascript:') && !a.href.startsWith('#')) {
                                            ctx.links.push(a.href);
                                        }
                                    });
                                    
                                    // Sidebar / nav items (click to trigger API calls)
                                    document.querySelectorAll('nav a, [role="navigation"] a, .sidebar a, .nav-item a').forEach(a => {
                                        if (a.href) ctx.links.push(a.href);
                                    });
                                    
                                    return ctx;
                                }
                            """)
                            
                            # Build context description for AI
                            desc_parts = []
                            if page_context.get('title'):
                                desc_parts.append(f"Page: {page_context['title']}")
                            if page_context.get('headings'):
                                desc_parts.append(f"Sections: {', '.join(page_context['headings'][:5])}")
                            if page_context.get('buttons'):
                                desc_parts.append(f"Actions: {', '.join(page_context['buttons'][:8])}")
                            if page_context.get('fields'):
                                desc_parts.append(f"Fields: {', '.join(page_context['fields'][:8])}")
                            
                            context_desc = '. '.join(desc_parts) if desc_parts else 'Unknown page'
                            
                            self.page_contexts.append({
                                'page_url': page_url,
                                'description': context_desc,
                                'raw': page_context
                            })
                            
                            print(f"[DeepRecon] Mapped: {page_url[:60]} → {context_desc[:80]}")
                            
                            # Add discovered links for further crawling
                            for link in page_context.get('links', []):
                                link_parsed = urlparse(link)
                                if link_parsed.netloc == base_domain and link not in visited_pages:
                                    pages_to_visit.append(link)
                            
                            # ── Deep SPA Exploration: aggressive clicking + scroll discovery ──
                            try:
                                # Broad set of selectors covering most SPA UI patterns
                                spa_selectors = [
                                    'nav a', 'nav button', '.sidebar a', '.sidebar button',
                                    '.nav-link', '.nav-item a', '.nav-item button',
                                    '[role="tab"]', '[role="menuitem"]', '[role="button"]',
                                    '[data-tab]', '[data-toggle]', '[data-target]',
                                    '.tab', '.menu-item', '.list-item',
                                    'a[href^="/"]',  # Internal links
                                    'button:not([disabled])',
                                    '.card[onclick]', 'tr[onclick]', '[onclick]',
                                    'details > summary', '.accordion-header',
                                    '.dropdown-toggle', '[aria-haspopup="true"]',
                                    '[aria-expanded]', '.collapse-toggle',
                                    '[data-bs-toggle]', '[data-testid]',
                                ]
                                
                                clicked_labels = set()
                                click_count = 0
                                max_clicks = 25  # Aggressive but bounded
                                
                                for selector in spa_selectors:
                                    if click_count >= max_clicks:
                                        break
                                    try:
                                        elements = page.query_selector_all(selector)
                                        for elem in elements:
                                            if click_count >= max_clicks:
                                                break
                                            try:
                                                # Get a label to deduplicate
                                                label = (elem.inner_text() or '').strip()[:40]
                                                tag = elem.evaluate('el => el.tagName')
                                                href = elem.get_attribute('href') or ''
                                                dedup_key = f"{tag}:{label}:{href}"
                                                
                                                if dedup_key in clicked_labels or not label:
                                                    continue
                                                clicked_labels.add(dedup_key)
                                                
                                                # Skip logout/delete/dangerous actions
                                                lower_label = label.lower()
                                                if any(d in lower_label for d in ['logout', 'sign out', 'delete', 'remove', 'destroy', 'reset']):
                                                    continue
                                                
                                                # Click and wait for API calls to fire
                                                elem.click(timeout=3000)
                                                click_count += 1
                                                
                                                # Wait for network activity to settle
                                                try:
                                                    page.wait_for_load_state('networkidle', timeout=3000)
                                                except Exception:
                                                    time.sleep(1)
                                                
                                            except Exception:
                                                continue
                                    except Exception:
                                        continue
                                
                                # Scroll to bottom to trigger lazy-loaded content / infinite scroll APIs
                                try:
                                    for scroll_i in range(3):
                                        page.evaluate('window.scrollBy(0, window.innerHeight)')
                                        try:
                                            page.wait_for_load_state('networkidle', timeout=2000)
                                        except Exception:
                                            time.sleep(0.5)
                                except Exception:
                                    pass
                                
                                if click_count > 0:
                                    print(f"[DeepRecon] Clicked {click_count} interactive elements on {page_url[:50]}")
                                    
                            except Exception as spa_err:
                                print(f"[DeepRecon] SPA exploration error: {spa_err}")
                                
                        except Exception as e:
                            print(f"[DeepRecon] Navigation error on {page_url[:60]}: {e}")
                            continue
                    
                    depth += 1
                
                # ── JS Bundle API Extraction ──
                self._extract_js_apis(page, base_domain)
                
                browser.close()
            
            # ── Process captured API traffic into endpoint_data ──
            from urllib.parse import parse_qs
            
            for api in api_details:
                url = api['url']
                method = api.get('method', 'GET')
                
                # Extract query params from the full URL
                full_url = api.get('full_url', url)
                parsed = urlparse(full_url)
                params = set(parse_qs(parsed.query).keys())
                
                # Extract body params for POST/PUT
                post_data = api.get('post_data', '')
                if post_data:
                    try:
                        import json as json_mod
                        body_json = json_mod.loads(post_data)
                        if isinstance(body_json, dict):
                            params.update(body_json.keys())
                    except Exception:
                        # Try form-encoded
                        if '=' in post_data:
                            for pair in post_data.split('&'):
                                if '=' in pair:
                                    params.add(pair.split('=')[0])
                
                if url not in endpoint_data:
                    endpoint_data[url] = set()
                endpoint_data[url].update(params)
                
                # If no params discovered, add generic ones for testing
                if not endpoint_data[url]:
                    endpoint_data[url] = {'id', 'q'}
            
            # Add JS-extracted endpoints
            for js_ep in self.js_api_endpoints:
                full_ep = f"{base_scheme}://{base_domain}{js_ep}"
                if full_ep not in endpoint_data:
                    endpoint_data[full_ep] = {'id', 'q'}
            
            self.captured_apis = api_details
            
            print(f"\n[DeepRecon] === Deep Recon Summary ===")
            print(f"  Pages visited: {len(visited_pages)}")
            print(f"  API calls captured: {len(api_details)}")
            print(f"  JS-extracted endpoints: {len(self.js_api_endpoints)}")
            print(f"  Total unique endpoints: {len(endpoint_data)}")
            print(f"  Page contexts captured: {len(self.page_contexts)}")
            print(f"========================================\n")
            
            return endpoint_data
            
        except Exception as e:
            print(f"[DeepRecon] Fatal error: {e}")
            import traceback
            traceback.print_exc()
            return endpoint_data

    def _extract_js_apis(self, page, base_domain: str):
        """Extract API endpoint patterns from loaded JS bundles."""
        import re as regex
        
        try:
            # Get all script sources
            scripts = page.evaluate("""
                () => {
                    const srcs = [];
                    document.querySelectorAll('script[src]').forEach(s => {
                        if (s.src) srcs.push(s.src);
                    });
                    return srcs;
                }
            """)
            
            for script_url in scripts[:10]:  # Limit to 10 JS files
                try:
                    resp = requests.get(script_url, timeout=10, verify=False)
                    if resp.status_code == 200 and len(resp.text) > 100:
                        # Find API path patterns
                        patterns = [
                            r'["\'](/api/[a-zA-Z0-9/_\-{}]+)["\']',      # "/api/v2/users"
                            r'["\'](/v[0-9]+/[a-zA-Z0-9/_\-{}]+)["\']',  # "/v2/organizations"
                            r'fetch\(["\']([^"\']+)["\']',                 # fetch("/endpoint")
                            r'axios\.[a-z]+\(["\']([^"\']+)["\']',         # axios.get("/endpoint")
                            r'\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']',  # .post("/endpoint")
                        ]
                        
                        for pattern in patterns:
                            matches = regex.findall(pattern, resp.text)
                            for match in matches:
                                # Only keep paths that look like real API routes
                                if match.startswith('/') and not match.endswith(('.js', '.css', '.png', '.svg')):
                                    # Replace path parameters like {id} with test values
                                    clean = regex.sub(r'\{[^}]+\}', '1', match)
                                    self.js_api_endpoints.add(clean)
                                    
                        if self.js_api_endpoints:
                            print(f"[DeepRecon] Extracted {len(self.js_api_endpoints)} API paths from {script_url.split('/')[-1][:30]}")
                except Exception:
                    continue
        except Exception as e:
            print(f"[DeepRecon] JS extraction error: {e}")
    
    def get_context_for_endpoint(self, endpoint: str) -> str:
        """Return the page context description for a given endpoint, if available."""
        # Try to match endpoint to a page context
        for ctx in self.page_contexts:
            # Check if the endpoint was likely loaded from this page
            if ctx.get('description'):
                return ctx['description']
        return ''
    
    def run_idor_check(self, headers_a: dict, headers_b: dict, log_callback=None) -> list:
        """
        Replay captured API calls from Session A using Session B's credentials.
        Returns list of IDOR findings.
        """
        if not self.captured_apis:
            print("[DeepRecon] No captured APIs to test for IDOR.")
            return []
        
        print(f"[DeepRecon] Starting IDOR check: replaying {len(self.captured_apis)} API calls with Session B...")
        idor_findings = []
        
        session_b = requests.Session()
        session_b.headers.update({'User-Agent': 'Mozilla/5.0 (Security Scanner)'})
        session_b.verify = False
        
        # Apply Session B headers
        for key, value in headers_b.items():
            if key.lower() == 'cookie':
                for part in value.split(';'):
                    part = part.strip()
                    if '=' in part:
                        name, val = part.split('=', 1)
                        session_b.cookies.set(name.strip(), val.strip())
            else:
                session_b.headers[key] = value
        
        tested = set()
        
        for api in self.captured_apis:
            url = api.get('url', '')
            method = api.get('method', 'GET')
            status_a = api.get('status', 0)
            
            # Only test API endpoints that returned data (200-299) for Session A
            if status_a < 200 or status_a >= 300:
                continue
            
            # Skip duplicates
            key = f"{method}:{url}"
            if key in tested:
                continue
            tested.add(key)
            
            # Skip non-data endpoints
            content_type = api.get('content_type', '')
            if 'html' in content_type.lower() and 'api' not in url.lower():
                continue
            
            try:
                if method.upper() == 'GET':
                    resp_b = session_b.get(api.get('full_url', url), timeout=10)
                elif method.upper() == 'POST':
                    post_data = api.get('post_data', '')
                    ct = 'application/json' if post_data and post_data.startswith('{') else 'application/x-www-form-urlencoded'
                    resp_b = session_b.post(url, data=post_data, headers={'Content-Type': ct}, timeout=10)
                else:
                    continue
                
                # IDOR Detection Logic
                if resp_b.status_code in [200, 201]:
                    resp_a_snippet = api.get('response_snippet', '')
                    resp_b_text = resp_b.text[:500]
                    
                    # If Session B gets a successful response with actual data
                    if len(resp_b_text) > 50 and resp_b.status_code == status_a:
                        finding_msg = f"IDOR: Session B accessed {method} {url} (Status: {resp_b.status_code}, Body length: {len(resp_b.text)})"
                        print(f"[DeepRecon] ⚠️ {finding_msg}")
                        
                        idor_findings.append({
                            'url': url,
                            'method': method,
                            'status_a': status_a,
                            'status_b': resp_b.status_code,
                            'evidence': f"Session B received {len(resp_b.text)} bytes from {method} {url}. Response snippet: {resp_b_text[:200]}",
                            'body_b_snippet': resp_b_text[:300]
                        })
                        
                        if log_callback:
                            log_callback(f"⚠️ Potential IDOR: {method} {url} — Session B got {resp_b.status_code} with {len(resp_b.text)} bytes")
                
                elif resp_b.status_code in [401, 403]:
                    # Access correctly denied — this endpoint is properly protected
                    pass
                    
            except Exception as e:
                continue
        
        print(f"[DeepRecon] IDOR check complete. Found {len(idor_findings)} potential IDOR(s).")
        return idor_findings

