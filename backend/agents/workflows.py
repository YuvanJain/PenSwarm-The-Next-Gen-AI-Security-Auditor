import time
import requests
from typing import List, Dict

class StoredXSSWorkflow:
    """Handles stored XSS testing - submit payload, then check if it persists."""
    
    def __init__(self, session: requests.Session = None, browser_context = None):
        self.session = session or requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Security Scanner)'})
        self.browser_context = browser_context
    
    def test_stored_xss(self, base_url: str, payloads: List[str] = None) -> List[Dict]:
        """
        Test for stored XSS vulnerabilities.
        Returns list of confirmed vulnerabilities.
        """
        base_url = base_url.rstrip('/')
        findings = []
        
        payloads = payloads or [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            '"><script>alert("XSS")</script>',
        ]
        
        # Gruyere-specific: Test snippet creation
        if 'gruyere' in base_url.lower():
            if self.browser_context:
                findings.extend(self._test_gruyere_snippets_playwright(base_url, payloads))
            else:
                findings.extend(self._test_gruyere_snippets(base_url, payloads))
        
        return findings

    def _test_gruyere_snippets_playwright(self, base_url: str, payloads: List[str]) -> List[Dict]:
        """Test stored XSS via Gruyere snippets using Playwright."""
        findings = []
        from playwright.sync_api import sync_playwright
        from urllib.parse import urlparse
        
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context()
                
                # Sync cookies from requests session to Playwright
                try:
                    hostname = urlparse(base_url).hostname
                    pw_cookies = []
                    for cookie in self.session.cookies:
                        c_dict = {
                            'name': cookie.name,
                            'value': cookie.value,
                            'domain': cookie.domain if cookie.domain else hostname,
                            'path': cookie.path if cookie.path else '/'
                        }
                        pw_cookies.append(c_dict)
                    
                    if pw_cookies:
                        context.add_cookies(pw_cookies)
                        print(f"[StoredXSS] Synced {len(pw_cookies)} cookies to Playwright")
                except Exception as e:
                    print(f"[StoredXSS] Warning: Cookie sync failed: {e}")

                page = context.new_page()
                
                for i, payload in enumerate(payloads):
                    try:
                        # Submit snippet using browser
                        page.goto(f"{base_url}/newsnippet", timeout=10000)
                        page.fill('textarea[name="snippet"]', payload, timeout=5000)
                        page.click('input[type="submit"]', timeout=5000)
                        
                        print(f"[StoredXSS] (Playwright) Submitted payload {i+1}: {payload[:30]}...")
                        
                        # Check snippets page
                        page.goto(f"{base_url}/snippets.gtl", timeout=10000)
                        content = page.content()
                        
                        # Check for unescaped reflection
                        if payload in content:
                            evidence_start = max(0, content.find(payload) - 50)
                            evidence_end = evidence_start + len(payload) + 100
                            evidence = content[evidence_start:evidence_end]
                            
                            finding = {
                                'type': 'Stored XSS',
                                'endpoint': f"{base_url}/snippets.gtl",
                                'payload': payload,
                                'evidence': evidence,
                                'submit_url': f"{base_url}/newsnippet"
                            }
                            findings.append(finding)
                            print(f"[StoredXSS] ✅ CONFIRMED: Stored XSS with payload: {payload[:30]}...")
                            
                        elif '&lt;script&gt;' in content or '&lt;img' in content:
                            print(f"[StoredXSS] Payload neutralized (escaped).")
                            
                    except Exception as e:
                        print(f"[StoredXSS] Error testing payload {payload[:10]}...: {e}")
                
                browser.close()
                
        except Exception as e:
            print(f"[StoredXSS] Playwright launch error: {e}")
            
        return findings
    
    def _test_gruyere_snippets(self, base_url: str, payloads: List[str]) -> List[Dict]:
        """Test stored XSS via Gruyere snippets (Legacy requests-based)."""
        findings = []
        
        for i, payload in enumerate(payloads):
            try:
                # Submit snippet with XSS payload
                submit_url = f"{base_url}/newsnippet"
                snippet_data = {'snippet': payload}
                
                resp = self.session.post(submit_url, data=snippet_data, timeout=10)
                print(f"[StoredXSS] Submitted payload {i+1}: {payload[:30]}...")
                
                if resp.status_code not in [200, 302]:
                    continue
                
                # Check if payload appears on snippets page
                time.sleep(0.5)  # Small delay for storage
                view_url = f"{base_url}/snippets.gtl"
                view_resp = self.session.get(view_url, timeout=10)
                
                # Check for unescaped reflection (stored XSS)
                if payload in view_resp.text:
                    # Payload reflected without escaping = Stored XSS!
                    evidence_start = max(0, view_resp.text.find(payload) - 50)
                    evidence_end = evidence_start + len(payload) + 100
                    evidence = view_resp.text[evidence_start:evidence_end]
                    
                    finding = {
                        'type': 'Stored XSS',
                        'endpoint': view_url,
                        'payload': payload,
                        'evidence': evidence,
                        'submit_url': submit_url
                    }
                    findings.append(finding)
                    print(f"[StoredXSS] ✅ CONFIRMED: Stored XSS with payload: {payload[:30]}...")
                    
                elif '&lt;script&gt;' in view_resp.text or '&lt;img' in view_resp.text:
                    print(f"[StoredXSS] Payload was escaped (safe)")
                else:
                    print(f"[StoredXSS] Payload not found in response")
                    
            except Exception as e:
                print(f"[StoredXSS] Error testing payload: {e}")
                continue
        
        return findings
    
    def test_file_upload_xss(self, base_url: str) -> List[Dict]:
        """Test XSS via file upload (HTML files with scripts)."""
        findings = []
        base_url = base_url.rstrip('/')
        
        if 'gruyere' not in base_url.lower():
            return findings
        
        try:
            # Create HTML file with XSS
            xss_html = '<html><body><script>alert("XSS")</script></body></html>'
            filename = f"xss_test_{int(time.time())}.html"
            
            upload_url = f"{base_url}/upload"
            files = {'upload': (filename, xss_html, 'text/html')}
            
            resp = self.session.post(upload_url, files=files, timeout=10)
            print(f"[FileUploadXSS] Upload response: {resp.status_code}")
            
            if resp.status_code in [200, 302]:
                # Try to access the uploaded file
                # Check profile page for upload location
                profile_resp = self.session.get(f"{base_url}/snippets.gtl", timeout=10)
                
                finding = {
                    'type': 'File Upload XSS',
                    'endpoint': upload_url,
                    'payload': xss_html,
                    'evidence': 'HTML file uploaded successfully - may execute on access',
                    'filename': filename
                }
                findings.append(finding)
                print(f"[FileUploadXSS] ⚠️ File uploaded: {filename}")
                
        except Exception as e:
            print(f"[FileUploadXSS] Error: {e}")
        
        return findings
