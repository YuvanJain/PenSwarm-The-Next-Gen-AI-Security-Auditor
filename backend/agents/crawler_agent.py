import time
import requests
import json
import re
from typing import Dict, Set

from backend.agents.base_agent import BaseAgent
from backend.core.llm_provider import llm
from backend.core.config import Config

class CrawlerAgent(BaseAgent):
    """Uses Playwright to dynamically crawl and discover endpoints."""
    
    def __init__(self):
        super().__init__()
        self.js_files = set()

    def discover_endpoints(self, url: str, max_depth: int) -> dict:
        """
        Crawl the target URL and discover all endpoints with their parameters.
        Returns: Dict mapping endpoint URLs to list of discovered parameters.
        """
        print(f"[Crawler] Crawling {url} (Depth: {max_depth})...")
        
        # Map of endpoint -> list of parameters discovered for that endpoint
        endpoint_params: dict[str, set] = {}
        visited = set()
        to_visit = [url]
        api_calls = []
        all_params = set()  # All params discovered anywhere
        
        try:
            from playwright.sync_api import sync_playwright
            from urllib.parse import urlparse, urljoin, parse_qs
            
            base_domain = urlparse(url).netloc.split(':')[0]
            from backend.core.config import get_root_domain
            target_root_domain = get_root_domain(base_domain)
            ignore_domains = {'google-analytics.com', 'sentry.io', 'mixpanel.com', 'segment.com', 'hotjar.com', 'newrelic.com', 'datadoghq.com', 'appdynamics.com', 'optimizely.com', 'googletagmanager.com'}
            
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context()
                page = context.new_page()
                
                # Intercept all network requests
                def handle_request(request):
                    req_url = request.url
                    parsed = urlparse(req_url)
                    req_domain = parsed.netloc.split(':')[0]
                    
                    if req_domain in ignore_domains:
                        return
                    
                    if req_domain == base_domain or get_root_domain(req_domain) == target_root_domain:
                        api_calls.append(req_url)
                
                page.on('request', handle_request)
                page.set_default_timeout(20000)
                
                # BFS crawl up to max_depth
                depth = 0
                while to_visit and depth < max_depth:
                    current_batch = to_visit[:]
                    to_visit = []
                    
                    for page_url in current_batch:
                        if page_url in visited:
                            continue
                        
                        # STRICT: Only crawl pages on the exact target domain
                        page_domain = urlparse(page_url).netloc.split(':')[0]
                        if page_domain and page_domain != base_domain:
                            continue
                        visited.add(page_url)
                        
                        try:
                            page.goto(page_url, wait_until='domcontentloaded', timeout=20000)
                            time.sleep(0.5)
                            
                            # === SPA INTERACTION: Click navigation elements to trigger API calls ===
                            # This captures API calls made by Angular/React/Vue route changes
                            try:
                                page.evaluate("""
                                    () => {
                                        // Collect all clickable navigation elements
                                        const navSelectors = [
                                            'nav a', 'nav button',
                                            '[routerLink]', '[routerlink]',
                                            '[mat-list-item]', 'mat-list-item',
                                            '.sidebar a', '.sidebar button',
                                            '.nav-link', '.menu-item',
                                            '[role="menuitem"]', '[role="tab"]',
                                            'mat-toolbar a', 'mat-toolbar button',
                                            '.mat-tab-label',
                                            'header a', 'header button',
                                        ];
                                        const clicked = new Set();
                                        for (const selector of navSelectors) {
                                            document.querySelectorAll(selector).forEach(el => {
                                                const key = el.textContent.trim().substring(0, 30);
                                                if (!clicked.has(key) && key.length > 0) {
                                                    clicked.add(key);
                                                    try { el.click(); } catch(e) {}
                                                }
                                            });
                                        }
                                        // Scroll to bottom to trigger lazy-loaded modules
                                        window.scrollTo(0, document.body.scrollHeight);
                                    }
                                """)
                                time.sleep(2)  # Wait for SPA route changes and API calls
                            except Exception as spa_err:
                                pass  # Non-critical: SPA interaction is best-effort
                            
                            # Extract links, forms, and inputs
                            page_data = page.evaluate("""
                                () => {
                                    const data = {links: [], forms: [], inputs: [], scripts: []};
                                    
                                    // All anchor links
                                    document.querySelectorAll('a[href]').forEach(a => {
                                        if (a.href) data.links.push(a.href);
                                    });
                                    
                                    // SPA route links (Angular routerLink, React Link, etc.)
                                    document.querySelectorAll('[routerLink], [routerlink], [href]').forEach(el => {
                                        const rl = el.getAttribute('routerLink') || el.getAttribute('routerlink');
                                        if (rl && rl.startsWith('/')) {
                                            data.links.push(window.location.origin + rl);
                                        }
                                    });

                                    // All scripts
                                    document.querySelectorAll('script[src]').forEach(s => {
                                        if (s.src) data.scripts.push(s.src);
                                    });
                                    
                                    // All form actions with their input names
                                    document.querySelectorAll('form').forEach(f => {
                                        const formData = {
                                            action: f.action || window.location.href,
                                            method: f.method || 'GET',
                                            inputs: []
                                        };
                                        f.querySelectorAll('input, textarea, select').forEach(i => {
                                            if (i.name) formData.inputs.push(i.name);
                                        });
                                        data.forms.push(formData);
                                    });
                                    
                                    // Standalone inputs outside forms
                                    document.querySelectorAll('input[name], textarea[name]').forEach(i => {
                                        data.inputs.push(i.name);
                                    });
                                    
                                    return data;
                                }
                            """)
                            
                            # Process scripts for later analysis
                            for script_url in page_data.get('scripts', []):
                                self.js_files.add(script_url)
                            
                            # Process links
                            for link in page_data.get('links', []):
                                try:
                                    parsed = urlparse(link)
                                    req_domain = parsed.netloc.split(':')[0]
                                    
                                    if req_domain in ignore_domains:
                                        continue
                                    
                                    # STRICT: Only follow links on exact target domain
                                    full_url = link if parsed.netloc else urljoin(page_url, link)
                                    full_parsed = urlparse(full_url)
                                    full_domain = full_parsed.netloc.split(':')[0]
                                    
                                    if full_domain and full_domain != base_domain:
                                        continue
                                    
                                    base_url = full_url.split('?')[0].split('#')[0]
                                    
                                    # Extract params from query string
                                    if '?' in full_url:
                                        query_params = parse_qs(urlparse(full_url).query)
                                        for param in query_params.keys():
                                            all_params.add(param)
                                            if base_url not in endpoint_params:
                                                endpoint_params[base_url] = set()
                                            endpoint_params[base_url].add(param)
                                    
                                    if base_url not in endpoint_params:
                                        endpoint_params[base_url] = set()
                                    
                                    if base_url not in visited:
                                        to_visit.append(base_url)
                                except:
                                    continue
                            
                            # Process forms - extract action URL and associated parameters
                            for form in page_data.get('forms', []):
                                action = form.get('action', page_url)
                                if action and not action.startswith('ref:'):
                                    # Resolve to absolute URL
                                    action_full = action if urlparse(action).netloc else urljoin(page_url, action)
                                    action_domain = urlparse(action_full).netloc.split(':')[0]
                                    
                                    # STRICT: Skip forms pointing to off-domain URLs
                                    if action_domain and action_domain != base_domain:
                                        continue
                                    
                                    action_base = action_full.split('?')[0].split('#')[0]
                                    if action_base not in endpoint_params:
                                        endpoint_params[action_base] = set()
                                    
                                    inputs = form.get('inputs', [])
                                    for param in inputs:
                                        endpoint_params[action_base].add(param)
                                        all_params.add(param)
                                    
                                    if inputs:
                                        print(f"[Crawler] Found form: {action_base} params={inputs}")
                                    
                        except Exception as e:
                            print(f"[Crawler] Error crawling {page_url}: {str(e)[:50]}")
                            continue
                    
                    depth += 1
                    print(f"[Crawler] Depth {depth}: visited {len(visited)}, endpoints {len(endpoint_params)}")
                
                browser.close()
            
            # Add captured API/network calls
            for api_url in set(api_calls):
                base = api_url.split('?')[0]
                if base not in endpoint_params:
                    endpoint_params[base] = set()

        except Exception as e:
            print(f"[Crawler] Playwright failed: {e}")

        # Fallback: Explicitly add common SPA bundles if they exist
        common_bundles = ['main.js', 'vendor.js', 'polyfills.js', 'runtime.js', 'app.js', 'bundle.js']
        
        try:
            from urllib.parse import urlparse
            base_url_obj = urlparse(url)
            base_url_root = f"{base_url_obj.scheme}://{base_url_obj.netloc}"
            
            for bundle in common_bundles:
                candidate = f"{base_url_root}/{bundle}"
                if candidate not in self.js_files:
                    # Quick check if exists
                    try:
                        # Allow redirects to handle http->https
                        head = self.session.head(candidate, timeout=2, allow_redirects=True)
                        if head.status_code == 200:
                            self.js_files.add(candidate)
                            print(f"[Crawler] Fallback found: {candidate}")
                    except:
                        pass
        except Exception as e:
            print(f"[Crawler] Fallback error: {e}")

        # Static Analysis of JS files
        try:
            from urllib.parse import urlparse as _urlparse
            _parsed = _urlparse(url)
            _base_root = f"{_parsed.scheme}://{_parsed.netloc}"
            
            js_endpoints = self._extract_endpoints_from_js(url, self.js_files)
            js_added = 0
            for ep, params in js_endpoints.items():
                # Convert relative paths to absolute URLs
                if ep.startswith('/'):
                    full_ep = _base_root + ep
                elif not ep.startswith('http'):
                    full_ep = _base_root + '/' + ep
                else:
                    full_ep = ep
                
                if full_ep not in endpoint_params:
                    endpoint_params[full_ep] = params
                    js_added += 1
                else:
                    endpoint_params[full_ep].update(params)
            print(f"[Crawler] 📊 JS Analysis: {len(js_endpoints)} found, {js_added} new endpoints added")
        except Exception as e:
            print(f"[Crawler] JS Analysis error: {e}")
        
        # OpenAPI/Swagger Auto-Discovery (standard framework convention paths)
        try:
            openapi_eps = self._discover_openapi(url)
            for ep, params in openapi_eps.items():
                if ep not in endpoint_params:
                    endpoint_params[ep] = params
                else:
                    endpoint_params[ep].update(params)
        except Exception as e:
            print(f"[Crawler] OpenAPI discovery error: {e}")
            
        # Fallback to basic crawl ONLY if no endpoints found
        if not endpoint_params:
            print(f"[Crawler] No endpoints found via Playwright/JS, falling back to basic crawl...")
            try:
                for ep in self._basic_crawl(url):
                    if ep not in endpoint_params:
                        endpoint_params[ep] = set()
            except Exception as e:
                print(f"[Crawler] Basic crawl failed: {e}")
        
        # Probe common API patterns for SPAs (only if enabled)
        if Config.PROBE_API_ENDPOINTS:
            probed_apis = self._probe_rest_apis(url)
            for api_ep, params in probed_apis.items():
                if api_ep not in endpoint_params:
                    endpoint_params[api_ep] = params
                else:
                    endpoint_params[api_ep].update(params)
        
        # Always check sitemaps/robots.txt (Safe, standard discovery)
        sitemap_eps = self._check_sitemaps(url)
        for ep, params in sitemap_eps.items():
            if ep not in endpoint_params:
                endpoint_params[ep] = params
        
        # Add all discovered params to endpoints that have none
        for ep in endpoint_params:
            if not endpoint_params[ep]:
                endpoint_params[ep] = all_params.copy()
        
        print(f"[Crawler] Discovered {len(endpoint_params)} endpoints with {len(all_params)} unique params")
        
        # Convert sets to lists and prioritize endpoints
        result = {ep: list(params) for ep, params in endpoint_params.items()}
        
        # Sort endpoints by priority
        form_eps = {k: v for k, v in result.items() if any(x in k.lower() for x in ['snippet', 'newsnippet', 'upload', 'newaccount'])}
        login_eps = {k: v for k, v in result.items() if any(x in k.lower() for x in ['login', 'auth', 'signin']) and k not in form_eps}
        other_eps = {k: v for k, v in result.items() if k not in form_eps and k not in login_eps}
        
        # Merge in priority order
        sorted_result = {}
        sorted_result.update(form_eps)
        sorted_result.update(login_eps)
        sorted_result.update(other_eps)
        
        return sorted_result
        
    def _check_sitemaps(self, url: str) -> dict:
        """Fetch robots.txt and sitemaps to discover endpoints."""
        discovered = {}
        try:
            from urllib.parse import urlparse, urljoin
            import requests
            
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            # Try robots.txt
            try:
                robots_url = f"{base_url}/robots.txt"
                resp = self.session.get(robots_url, timeout=5)
                if resp.status_code == 200:
                    for line in resp.text.splitlines():
                        if "Disallow: " in line or "Allow: " in line:
                            path = line.split(": ")[1].strip()
                            if path and not '*' in path:
                                full_url = urljoin(base_url, path)
                                discovered[full_url] = set()
            except:
                pass
                
            # Try basic sitemap
            try:
                sitemap_url = f"{base_url}/sitemap.xml"
                resp = self.session.get(sitemap_url, timeout=5)
                if resp.status_code == 200:
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(resp.text, 'xml')
                    for loc in soup.find_all('loc'):
                        if loc.text:
                            discovered[loc.text] = set()
            except:
                pass
                
        except Exception as e:
            print(f"[Crawler] Sitemap check error: {e}")
            
        return discovered
        
    def _discover_openapi(self, url: str) -> dict:
        """Look for common OpenAPI/Swagger definition endpoints."""
        discovered = {}
        import requests
        from urllib.parse import urlparse
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        common_paths = [
            '/api-docs', '/v2/api-docs', '/v3/api-docs', '/swagger.json',
            '/api/swagger.json', '/docs/swagger.json', '/openapi.json'
        ]
        
        found_spec = None
        for path in common_paths:
            try:
                test_url = base_url + path
                resp = self.session.get(test_url, timeout=3)
                if resp.status_code == 200 and 'json' in resp.headers.get('Content-Type', '').lower():
                    found_spec = resp.json()
                    print(f"[Crawler] ✅ Found OpenAPI spec at {test_url}")
                    break
            except:
                continue
                
        if found_spec and 'paths' in found_spec:
            # Extract endpoints and parameters from OpenAPI spec
            paths = found_spec.get('paths', {})
            for path, methods in paths.items():
                full_path = base_url + path
                params = set()
                
                # Extract defined parameters
                for method, details in methods.items():
                    if 'parameters' in details:
                        for p in details['parameters']:
                            if 'name' in p:
                                params.add(p['name'])
                
                discovered[full_path] = params
                
        return discovered
        
    def _extract_endpoints_from_js(self, base_url: str, js_files: Set[str]) -> dict:
        """Regex scanning through collected JS bundles for API paths."""
        discovered = {}
        import re
        import requests
        
        # Regex patterns for finding API paths in JS bundles
        # Match paths like '/api/Users', '/rest/products/search'
        path_pattern = re.compile(r'["\'](\/(?:api|rest|v[1-9]|graphql)\/[a-zA-Z0-9_\-\/{}:]+)["\']')
        # Match fetch/axios calls
        api_pattern = re.compile(r'(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*["\'\'`]([^"\'\'`]+)["\'\'`]')
        # Match Angular HttpClient: this.http.get('/api/...')
        angular_pattern = re.compile(r'\.http(?:Client)?\s*\.\s*(?:get|post|put|delete|patch)\s*[<(]\s*["\'\'`]([^"\'\'`]+)["\'\'`]')
        # Match common Juice Shop / web app API paths in string literals
        path_string_pattern = re.compile(r'["\'](\/(?:rest|api|ftp|redirect|profile|admin|b2b|accounting|track|recycle|complaint|feedback|basket|card|delivery|address|wallet|order|challenge|snippet|user|product|quantit|captcha|security|erasure|saveLoginIp|memories|chatbot)[\/a-zA-Z0-9_\-{}:]*)["\']')
        
        candidates = set()
        
        for js_url in js_files:
            try:
                resp = self.session.get(js_url, timeout=10)
                if resp.status_code == 200:
                    js_text = resp.text
                    # Method 1: Look for common API prefixes
                    for path in path_pattern.findall(js_text):
                        candidates.add(path)
                    # Method 2: Specific API calls (axios/fetch)
                    for match in api_pattern.findall(js_text):
                        candidates.add(match)
                    # Method 3: Angular HttpClient calls
                    for match in angular_pattern.findall(js_text):
                        candidates.add(match)
                    # Method 4: Known app path patterns
                    for match in path_string_pattern.findall(js_text):
                        candidates.add(match)
            except:
                continue
        
        if not candidates:
            return discovered

        print(f"[Crawler] Found {len(candidates)} candidate strings in JS. Asking AI to identify APIs...")
        
        # Chunk candidates for LLM
        candidate_list = list(candidates)
        chunk_size = 50
        
        for i in range(0, len(candidate_list), chunk_size):
            chunk = candidate_list[i:i+chunk_size]
            prompt = f"""Analyze these strings extracted from JavaScript code. Identify which ones are likely API endpoints (REST, GraphQL, etc.) or significant application paths (e.g. for logic/admin).
            
            Ignore static assets, UI routes, or random ID strings.
            Format output as a JSON list of strings.
            
            Strings: {json.dumps(chunk)}
            
            Return ONLY logic/API paths."""
            
            try:
                response = llm.query(prompt, system_role="Security Analyst", use_coder=False)
                # Parse JSON
                if '```' in response:
                    response = response.split('```')[1].replace('json', '', 1)
                
                valid_paths = json.loads(response.strip())
                if isinstance(valid_paths, list):
                    for path in valid_paths:
                        full_url = base_url.rstrip('/') + path
                        discovered[full_url] = set() # No params known yet
            except Exception as e:
                print(f"[Crawler] AI Analysis failed for chunk: {e}")
                continue
                
        if discovered:
            print(f"[Crawler] AI Verification: Found {len(discovered)} endpoints (e.g. {list(discovered.keys())[:3]})")
            
        return discovered

    def _probe_rest_apis(self, base_url: str) -> dict:
        """Probe for common REST API endpoints and return with potential params."""
        # Returns dict: {url: set(params)}
        discovered = {}
        import requests
        
        print(f"[Crawler] asking AI to generate probe list for {base_url}...")
        
        prompt = f"""Generate a list of 20 likely API endpoints to probe for a security assessment of: {base_url}
        Focus on common REST patterns, authentication, user management, and business logic (e.g. products, cart, feedback).
        Include methods and potential parameters.
        
        Return valid JSON list of objects: {{"path": "/example", "method": "GET", "params": ["id"]}}
        """
        
        try:
            response = llm.query(prompt, system_role="Security Analyst", use_coder=False)
            if '```' in response:
                response = response.split('```')[1].replace('json', '', 1)
            
            api_paths_data = json.loads(response.strip())
            
            # Convert to tuple format used by loop
            api_paths = []
            for item in api_paths_data:
                api_paths.append((item.get('path', ''), item.get('method', 'GET'), set(item.get('params', []))))
                
        except Exception as e:
            print(f"[Crawler] AI Probe Generation Failed: {e}")
            # Fallback to a tiny list if AI fails entirely
            api_paths = [
                ('/robots.txt', 'GET', set()),
                ('/sitemap.xml', 'GET', set()),
                ('/api/health', 'GET', set())
            ]
        
        base = base_url.rstrip('/')
        
        print("[Crawler] Probing common API endpoints...")
        
        for path_info in api_paths:
            path, method, params = path_info
            test_url = base + path
            
            try:
                if method == 'POST':
                    resp = self.session.post(test_url, json={'test': 'probe'}, timeout=3)
                else:
                    resp = self.session.get(test_url, timeout=3)
                
                # Check if it's a valid API endpoint
                # 1. Not 404
                # 2. Not HTML (avoids SPA index.html catch-all)
                content_type = resp.headers.get('Content-Type', '').lower()
                is_html = 'text/html' in content_type
                
                if resp.status_code != 404 and (not is_html or resp.status_code in [401, 403]):
                    # It's likely a real API endpoint
                    clean_url = test_url.split('?')[0]
                    if clean_url not in discovered:
                        discovered[clean_url] = set()
                    
                    # Add default params
                    for p in params:
                        discovered[clean_url].add(p)
                        
                    print(f"[Crawler] Discovered API: {clean_url} (Status: {resp.status_code}, Type: {content_type})")
                    
            except Exception as e:
                # print(f"Probe error {test_url}: {e}")
                continue
        
        return discovered
    
    def _basic_crawl(self, url: str) -> set:
        """Fallback basic crawling using requests + BeautifulSoup."""
        discovered = set()
        discovered.add(url)
        
        try:
            from urllib.parse import urlparse, urljoin
            
            response = self.session.get(url, timeout=10)
            
            # Try to parse HTML for links
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.text, 'html.parser')
                
                base_domain = urlparse(url).netloc.split(':')[0]
                from backend.core.config import get_root_domain
                target_root_domain = get_root_domain(base_domain)
                
                for a in soup.find_all('a', href=True):
                    link = a['href']
                    full_url = urljoin(url, link)
                    req_domain = urlparse(full_url).netloc.split(':')[0]
                    if req_domain == base_domain or get_root_domain(req_domain) == target_root_domain:
                        discovered.add(full_url)
                
                for form in soup.find_all('form', action=True):
                    action = form['action']
                    full_url = urljoin(url, action)
                    req_domain = urlparse(full_url).netloc.split(':')[0]
                    if req_domain == base_domain or get_root_domain(req_domain) == target_root_domain:
                        discovered.add(full_url)
                        
            except ImportError:
                print("[Crawler] BeautifulSoup not available, using regex...")
                # Basic regex fallback
                import re
                hrefs = re.findall(r'href=["\']([^"\']+)["\']', response.text)
                for href in hrefs:
                    if href.startswith('/'):
                        discovered.add(url.rstrip('/') + href)
                    elif href.startswith('http'):
                        discovered.add(href)
                        
        except Exception as e:
            print(f"[Crawler] Basic crawl error: {e}")
        
        return discovered
