import time
from backend.agents.base_agent import BaseAgent
from backend.core.llm_provider import llm

class AuthAgent(BaseAgent):
    """Handles authentication flows for authenticated vulnerability testing."""
    
    def __init__(self, base_url: str):
        super().__init__(base_url)
        self.authenticated = False
        self.discovered_apis = set()
        self.username = None
    
    def setup_auth(self, target_url: str, username: str = None, password: str = None) -> bool:
        """
        Setup authentication for the target.
        Tries to register a new account, then login.
        """
        self.base_url = target_url.rstrip('/')
        self.username = username or f"pentest_{int(time.time())}"
        password = password or "pentest123"
        
        print(f"[Auth] Setting up authentication for {self.base_url}")
        print(f"[Auth] Using username: {self.username}")
        
        # Try Gruyere-specific registration/login
        if 'gruyere' in target_url.lower():
            return self._gruyere_auth(self.username, password)
        
        # Generic auth attempt
        success = self._generic_auth(self.username, password)
        if success:
            self.explore_authenticated()
        return success
    
    def _gruyere_auth(self, username: str, password: str) -> bool:
        """Gruyere-specific authentication flow using Playwright."""
        try:
            from playwright.sync_api import sync_playwright
            import time
            
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context()
                page = context.new_page()
                
                # Navigate to base URL
                page.goto(self.base_url, wait_until='domcontentloaded', timeout=10000)
                time.sleep(1)
                
                # Try registration first
                try:
                    # Go to registration
                    page.goto(f"{self.base_url}/newaccount.gtl", timeout=10000)
                    time.sleep(0.5)
                    
                    # Fill registration form
                    page.fill('input[name="uid"]', username, timeout=5000)
                    page.fill('input[name="pw"]', password, timeout=5000)
                    
                    # Submit registration
                    page.evaluate("document.forms[0].submit()")
                    time.sleep(1)
                    print(f"[Auth] Registration attempted for {username}")
                except Exception as e:
                    print(f"[Auth] Registration skipped: {e}")
                
                # Now login
                page.goto(f"{self.base_url}/login.gtl", timeout=10000)
                time.sleep(0.5)
                
                # Fill login form
                page.fill('input[name="uid"]', username, timeout=5000)
                page.fill('input[name="pw"]', password, timeout=5000)
                
                # Submit login
                page.evaluate("document.forms[0].submit()")
                time.sleep(1)
                print(f"[Auth] Login attempted for {username}")
                
                # Check if logged in by looking for "Sign out" or New Snippet link
                page.goto(f"{self.base_url}/snippets.gtl", timeout=10000)
                time.sleep(0.5)
                
                content = page.content()
                content_lower = content.lower()
                
                # Store the browser page for later use in stored XSS testing
                self.browser_page = page
                self.browser_context = context
                self.browser = browser
                
                if 'sign out' in content_lower or username.lower() in content_lower or 'new snippet' in content_lower:
                    self.authenticated = True
                    print(f"[Auth] ✅ Successfully authenticated as {username} (Playwright)")
                    
                    # Get cookies from context and apply to requests session
                    cookies = context.cookies()
                    for cookie in cookies:
                        self.session.cookies.set(cookie['name'], cookie['value'], domain=cookie['domain'])
                    print(f"[Auth] Captured {len(cookies)} cookies")
                    
                    return True
                else:
                    print(f"[Auth] ❌ Login verification failed")
                    browser.close()
                    return False
                    
        except Exception as e:
            print(f"[Auth] Error during Gruyere Playwright auth: {e}")
            return False
    
    def _generic_auth(self, username: str, password: str) -> bool:
        """AI-driven authentication - discovers endpoints and generates payloads dynamically."""
        email = f"{username}@test.local"
        
        try:
            from playwright.sync_api import sync_playwright
            
            # Step 1: Use Playwright to discover auth-related endpoints
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context()
                page = context.new_page()
                
                api_calls = []
                def handle_request(request):
                    if any(kw in request.url.lower() for kw in ['user', 'auth', 'login', 'register', 'signup']):
                        api_calls.append({'url': request.url, 'method': request.method})
                
                page.on('request', handle_request)
                page.set_default_timeout(30000)
                
                try:
                    page.goto(self.base_url, wait_until='networkidle')
                    forms_info = page.evaluate("""() => {
                        const authLinks = Array.from(document.querySelectorAll('a, button'))
                            .filter(el => /login|sign|register|account/i.test(el.textContent || ''))
                            .map(el => ({text: el.textContent.trim(), href: el.href})).slice(0, 5);
                        return {authLinks};
                    }""")
                    browser.close()
                except Exception as e:
                    print(f"[Auth] Discovery error: {e}")
                    browser.close()
                    forms_info = {'authLinks': []}
            
            # Step 2: Use LLM to generate auth strategy
            context_info = f"Target: {self.base_url}\nDiscovered: {api_calls[:5]}\nLinks: {forms_info.get('authLinks', [])}"
            
            prompt = f"""Analyze this app and generate auth endpoints/payloads.
{context_info}

Return JSON with:
- register_endpoints: list of full URLs to try for registration
- register_payloads: list of JSON bodies (use email={email}, password={password})
- login_endpoints: list of full URLs for login
- login_payloads: list of JSON bodies

Consider patterns like /api/Users, /rest/user/login, email/password/passwordRepeat fields.
Return ONLY valid JSON."""

            response = llm.query(prompt, system_role="Security testing assistant", use_coder=False)
            
            # Parse response
            import json
            try:
                response = response.strip()
                if '```' in response:
                    response = response.split('```')[1].replace('json', '', 1)
                auth_strategy = json.loads(response)
            except:
                # Fallback
                auth_strategy = {
                    "register_endpoints": [f"{self.base_url}/api/Users"],
                    "register_payloads": [{"email": email, "password": password, "passwordRepeat": password, "securityQuestion": {"id": 1}, "securityAnswer": "test"}],
                    "login_endpoints": [f"{self.base_url}/rest/user/login"],
                    "login_payloads": [{"email": email, "password": password}]
                }
            for ep in auth_strategy.get('register_endpoints', [])[:3]:
                for pl in auth_strategy.get('register_payloads', [])[:2]:
                    try:
                        resp = self.session.post(ep, json=pl, timeout=10)
                        if resp.status_code in [200, 201]:
                            print(f"[Auth] ✅ Registered via {ep}")
                            break
                    except:
                        continue
            
            # Step 4: Try login
            for ep in auth_strategy.get('login_endpoints', [])[:3]:
                for pl in auth_strategy.get('login_payloads', [])[:2]:
                    try:
                        resp = self.session.post(ep, json=pl, timeout=10)
                        if resp.status_code == 200 and any(x in resp.text.lower() for x in ['token', 'jwt', 'session']):
                            self.authenticated = True
                            print(f"[Auth] ✅ Authenticated via {ep}")
                            try:
                                data = resp.json()
                                token = data.get('authentication', {}).get('token') or data.get('token')
                                if token:
                                    self.session.headers['Authorization'] = f'Bearer {token}'
                            except:
                                pass
                            return True
                    except:
                        continue
            
            return False
        except Exception as e:
            print(f"[Auth] Error: {e}")
            return False
    
    def get_session(self):
        """Return the authenticated session."""
        return self.session

    def explore_authenticated(self):
        """Use Playwright to click around after auth to discover endpoints."""
        if not self.authenticated: return
        
        # Extract token from session headers
        token = None
        auth_header = self.session.headers.get('Authorization')
        if auth_header and 'Bearer' in auth_header:
            token = auth_header.split(' ')[1]
            
        if not token: 
            print("[Auth] No token found for exploration")
            return

        print("[Auth] Exploring authenticated state with Playwright...")
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                # Inject storage state
                context = browser.new_context()
                
                # Setup capturing
                def handle_request(request):
                    if any(x in request.url for x in ['/api/', '/rest/', 'graphql']):
                        self.discovered_apis.add(request.url)
                
                page = context.new_page()
                page.on('request', handle_request)
                
                # Go to page and inject token
                page.goto(self.base_url)
                page.evaluate(f"localStorage.setItem('token', '{token}');")
                page.reload(wait_until='domcontentloaded')
                
                # Click navigation and common elements
                try:
                    page.evaluate("""() => {
                        // Click basket, feedback, account, etc.
                        const keywords = ['basket', 'cart', 'feedback', 'contact', 'account', 'profile', 'order', 'wallet'];
                        document.querySelectorAll('button, a[href], mat-icon').forEach(el => {
                            const text = (el.textContent || '').toLowerCase();
                            const aria = (el.getAttribute('aria-label') || '').toLowerCase();
                            if (keywords.some(k => text.includes(k) || aria.includes(k))) {
                                el.click();
                            }
                        });
                    }""")
                    page.wait_for_timeout(3000)
                except:
                    pass
                
                browser.close()
                print(f"[Auth] Exploration discovered {len(self.discovered_apis)} API endpoints")
        except Exception as e:
            print(f"[Auth] Exploration error: {e}")
