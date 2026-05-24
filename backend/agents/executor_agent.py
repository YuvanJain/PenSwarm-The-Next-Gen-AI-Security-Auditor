from typing import Dict
from backend.core.msf_bridge import MetasploitBridge

class ExecutorAgent:
    """Executes attack payloads and collects evidence."""
    
    def __init__(self):
        self.msf = MetasploitBridge()
        self.session = None  # Can be set to authenticated session

    def verify_payload(self, endpoint: str, payload: str, context: Dict) -> Dict:
        """Execute a payload against an endpoint and check for vulnerabilities."""
        if payload is None: payload = ""
        print(f"[Executor] Firing payload: {payload[:30]}... at {endpoint}")
        
        from urllib.parse import unquote
        decoded_payload = unquote(payload)
        
        category = context.get('category', 'Injection')
        
        import requests
        try:
            params_to_test = []
            target_param = context.get('target_parameter')
            discovered_params = context.get('discovered_params', [])
            method = context.get('http_method', 'GET').upper()
            
            if target_param and str(target_param).lower() not in ["null", "none", ""]:
                params_to_test.append(target_param)
            
            # Use discovered params from crawler
            if discovered_params:
                for p in discovered_params:
                    if p not in params_to_test:
                        params_to_test.append(p)
            
            # If still no params, use minimal fallback
            if not params_to_test:
                params_to_test = ['q', 'id', 'search']
            
            success = False
            evidence = ""
            
            # Use authenticated session if available, else create new
            if self.session:
                session = self.session
            else:
                session = requests.Session()
                session.headers.update({'User-Agent': 'Mozilla/5.0 (Security Scanner)'})
            
            # Path-based injection test
            if "INJECT_HERE" in endpoint:
                result = self._test_path_injection(session, endpoint, payload, decoded_payload, category)
                if result['success']:
                    return result
            
            # Parameter-based testing
            for param in params_to_test:
                result = self._test_parameter(session, endpoint, param, payload, decoded_payload, method, category)
                if result['success']:
                    return result
                if result['evidence']:
                    evidence = result['evidence']
            
            # Metasploit enhancement for Injection category
            if self.msf.is_available() and category == "Injection":
                msf_evidence = self._run_metasploit_check(endpoint)
                if msf_evidence:
                    evidence += f"\n{msf_evidence}"

            return {"success": success, "evidence": evidence}
            
        except Exception as e:
            return {"success": False, "evidence": str(e)}
    
    def _test_path_injection(self, session, endpoint: str, payload: str, decoded: str, category: str) -> Dict:
        """Test for path-based injection vulnerabilities."""
        path_url = endpoint.replace("INJECT_HERE", payload)
        try:
            response = session.get(path_url, timeout=10)
            
            # Check for reflection
            if decoded in response.text or payload in response.text:
                idx = response.text.find(decoded) if decoded in response.text else response.text.find(payload)
                start = max(0, idx - 50)
                end = min(len(response.text), idx + len(decoded) + 50)
                evidence = f"Payload reflected in path: ...{response.text[start:end]}..."
                
                if "<script>" in decoded and "<script>" in response.text[start:end]:
                    return {"success": True, "evidence": evidence + " [CONFIRMED: Unescaped Script]"}
            
            # Check for SQL errors
            if self._check_sql_errors(response.text):
                return {"success": True, "evidence": f"SQL error detected after path injection"}
                
        except Exception as e:
            print(f"[Executor] Path test error: {e}")
        
        return {"success": False, "evidence": ""}
    
    def _test_parameter(self, session, endpoint: str, param: str, payload: str, decoded: str, method: str, category: str) -> Dict:
        """Test a specific parameter for vulnerabilities."""
        try:
            responses = []
            
            # Determine if this is a REST/JSON API endpoint
            is_rest_api = any(x in endpoint.lower() for x in ['/rest/', '/api/', '/graphql'])
            
            if method == "POST":
                # Try JSON body first for REST APIs
                if is_rest_api:
                    # Common login field variations
                    json_payloads = [
                        {param: decoded},
                        {param: decoded, 'password': 'test'},
                        {'email': decoded, 'password': 'test'},
                        {'username': decoded, 'password': 'test'}
                    ]
                    for json_body in json_payloads:
                        try:
                            resp = session.post(endpoint, json=json_body, timeout=10)
                            
                            # Self-Healing: Check for missing parameter error
                            # e.g. "WHERE parameter "ProductId" has invalid "undefined" value"
                            if resp.status_code == 500 and "invalid" in resp.text and "undefined" in resp.text:
                                import re
                                match = re.search(r'parameter ["\'](\w+)["\'] has invalid ["\']undefined["\']', resp.text)
                                if match:
                                    missing_param = match.group(1)
                                    print(f"[Executor] Self-Healing: Detected missing param '{missing_param}'. Retrying with default value...")
                                    
                                    # Inject dependency
                                    refined_body = json_body.copy()
                                    # Use integer 1 for IDs, or string "1" if needed. 
                                    # Most IDs in Juice Shop (ProductId, BasketId, etc.) accept 1.
                                    refined_body[missing_param] = 1
                                    
                                    # Nested retry (one level deep)
                                    resp = session.post(endpoint, json=refined_body, timeout=10)
                                    # Update body for reporting
                                    json_body = refined_body

                            responses.append(('json', json_body, resp))
                        except:
                            pass
                
                # Also try form data
                try:
                    resp = session.post(endpoint, data={param: decoded}, timeout=10)
                    
                    # Self-Healing for Form Data
                    if resp.status_code == 500 and "invalid" in resp.text and "undefined" in resp.text:
                         import re
                         match = re.search(r'parameter ["\'](\w+)["\'] has invalid ["\']undefined["\']', resp.text)
                         if match:
                             missing_param = match.group(1)
                             print(f"[Executor] Self-Healing: Detected missing param '{missing_param}' in Form. Retrying...")
                             
                             refined_data = {param: decoded}
                             refined_data[missing_param] = 1
                             resp = session.post(endpoint, data=refined_data, timeout=10)
                             
                    responses.append(('form', {param: decoded}, resp))
                except:
                    pass
            else:
                # GET request
                try:
                    resp = session.get(endpoint, params={param: decoded}, timeout=10)
                    responses.append(('query', {param: decoded}, resp))
                except:
                    pass
            
            # Analyze all responses
            for req_type, req_data, response in responses:
                # SKIP responses that are just missing-parameter errors (NOT real SQLi)
                # e.g. 'WHERE parameter "captchaId" has invalid "undefined" value'
                if response.status_code == 500 and 'invalid' in response.text and 'undefined' in response.text:
                    import re
                    if re.search(r'parameter ["\']\w+["\'] has invalid ["\']undefined["\']', response.text):
                        continue  # Skip this response — it's a missing-param error, not SQLi
                
                # 1. Check for SQL errors (error-based SQLi)
                if self._check_sql_errors(response.text):
                     return {"success": True, "evidence": f"SQL error in response ({req_type} {param}): {response.text[:200]}", "vulnerable_param": param, "req_type": req_type, "req_data": req_data, "http_method": method}
                
                # 2. Check for authentication bypass (only for auth-related categories)
                # Without this restriction, ANY endpoint returning a JWT (like login) would
                # be flagged as vulnerable for every category (XSS, SSRF, Logic Flaws, etc.)
                auth_categories = ['broken auth', 'access control', 'injection']
                if category.lower() in auth_categories and self._check_auth_bypass(response):
                     return {"success": True, "evidence": f"Authentication bypass detected! SQLi via {req_type} ({param}). Response: {response.text[:300]}", "vulnerable_param": param, "req_type": req_type, "req_data": req_data, "http_method": method}
                
                # 3. Check for XSS / general reflection
                if decoded in response.text or payload in response.text:
                    idx = response.text.find(decoded) if decoded in response.text else response.text.find(payload)
                    start = max(0, idx - 50)
                    end = min(len(response.text), idx + len(decoded) + 50)
                    snippet = response.text[start:end]
                    evidence = f"Payload reflected ({req_type} {param}): ...{snippet}..."
                    
                    # Any clean reflection of our payload counts as a preliminary hit for the Verifier to analyze
                    return {"success": True, "evidence": evidence + " [PRELIMINARY CONFIRMED: Reflected]", "vulnerable_param": param, "req_type": req_type, "req_data": req_data, "http_method": method}
                
                # 4. Check for path traversal
                if "root:x:0:0" in response.text:
                    return {"success": True, "evidence": f"Path traversal successful ({req_type} {param})", "vulnerable_param": param, "req_type": req_type, "req_data": req_data, "http_method": method}
                
                # 5. Check for data exposure (IDOR/info disclosure)
                if self._check_data_exposure(response, category):
                    return {"success": True, "evidence": f"Data exposure detected ({req_type} {param}): {response.text[:300]}", "vulnerable_param": param, "req_type": req_type, "req_data": req_data, "http_method": method}
                    
        except Exception as e:
            print(f"[Executor] Parameter test error: {e}")
        
        # Collect evidence for self-healing if potential issues found (status 400+ or 'error')
        evidence_list = []
        for req_type, req_data, resp in responses:
            if resp.status_code >= 400 or "error" in resp.text.lower() or "syntax" in resp.text.lower():
                evidence_list.append(f"{req_type.upper()} {resp.status_code}: {resp.text[:300]}")
        
        return {"success": False, "evidence": "\n".join(evidence_list)}
    
    def _check_auth_bypass(self, response) -> bool:
        """Check if response indicates successful authentication bypass."""
        if response.status_code != 200:
            return False
        
        text = response.text.lower()
        
        # If the response indicates an error, it's not a bypass even if it contains a token
        error_indicators = ['"error"', '"success":false', '"success": false', 'invalid', 'failed', 'denied', 'unauthorized', 'not found', 'unauthenticated']
        if any(err in text for err in error_indicators):
            return False
            
        # Look for indicators of successful auth
        auth_indicators = [
            '"token":', '"authentication":', '"jwt":', '"access_token":',
            '"session":', '"logged_in":true', '"success":true', '"authenticated":',
            'bearer ', '"role":"admin"', '"isadmin":true'
        ]
        return any(ind in text for ind in auth_indicators)
    
    def _check_data_exposure(self, response, category: str) -> bool:
        """Check if response contains exposed sensitive data (not translation keys)."""
        if response.status_code != 200:
            return False
        
        text = response.text
        text_lower = text.lower()
        
        # Skip if this looks like a translation/i18n/config file
        translation_indicators = [
            'label_', 'placeholder_', 'nav_', 'title_', 'mandatory_', 
            'btn_', 'msg_', 'error_', 'success_', 'validation_',
            '"language":', '"locale":', '"translation":'
        ]
        if any(ind in text_lower for ind in translation_indicators):
            return False
        
        # Look for ACTUAL sensitive data with values (not just keys)
        # Pattern: "password": "actual_password_value" (value must be non-empty)
        import re
        sensitive_patterns = [
            r'"password"\s*:\s*"[^"]{3,}"',           # password with value > 2 chars
            r'"email"\s*:\s*"[^@]+@[^"]+"',           # email with @ symbol
            r'"creditcard"\s*:\s*"[\d\-]{10,}"',      # credit card numbers
            r'"ssn"\s*:\s*"[\d\-]{7,}"',              # SSN patterns
            r'"token"\s*:\s*"[^"]{20,}"',             # tokens > 20 chars
            r'"api_key"\s*:\s*"[^"]{10,}"',           # API keys
            r'"secret"\s*:\s*"[^"]{5,}"',             # secrets with values
            r'private_key',                           # private keys
            r'-----BEGIN.*PRIVATE KEY-----'           # PEM format keys
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        
        return False
    
    def _check_sql_errors(self, text: str) -> bool:
        """Check for common SQL error patterns."""
        # First, EXCLUDE known false positives:
        # ORM/Sequelize errors about missing required parameters are NOT SQL injection
        if 'has invalid' in text and 'undefined' in text:
            import re
            if re.search(r'parameter ["\']\w+["\'] has invalid ["\']undefined["\']', text):
                return False  # This is a missing-param app error, not SQLi
                
        # Exclude JSON parsing errors (common when injecting quotes into JSON body)
        text_lower = text.lower()
        if 'json' in text_lower and ('unexpected token' in text_lower or 'parse error' in text_lower or 'syntaxerror' in text_lower):
            return False

        patterns = [
            "sql syntax", "mysql", "sqlite", "postgresql", "ora-", 
            "db error", "syntax error", "unclosed quotation", "sqlstate",
            "microsoft sql", "odbc", "jdbc"
        ]
        return any(p in text_lower for p in patterns)
    
    def _run_curl(self, curl_command: str, timeout: int = 15) -> Dict:
        """Run a curl command via subprocess and return the result."""
        import subprocess
        import shlex
        
        try:
            # Add -s (silent) and -w for status code if not already present
            cmd = curl_command
            if ' -s ' not in cmd and not cmd.startswith('curl -s'):
                cmd = cmd.replace('curl ', 'curl -s -w "\\n%{http_code}" ', 1)
            
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            output = result.stdout
            status_code = 0
            
            # Extract status code from the last line (added by -w)
            if output.strip():
                lines = output.strip().rsplit('\n', 1)
                if len(lines) == 2 and lines[1].strip().isdigit():
                    status_code = int(lines[1].strip())
                    output = lines[0]
            
            return {
                "success": True,
                "body": output,
                "status_code": status_code,
                "error": result.stderr
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "body": "", "status_code": 0, "error": "Curl timeout"}
        except Exception as e:
            return {"success": False, "body": "", "status_code": 0, "error": str(e)}

    def _run_metasploit_check(self, endpoint: str) -> str:
        """Run Metasploit auxiliary modules for additional reconnaissance."""
        try:
            print("[Executor] Running Metasploit checks...")
            output = self.msf.check_db_version(endpoint)
            if output and "version" in output.lower():
                return f"[Metasploit] {output.strip()}"
        except:
            pass
        return ""


