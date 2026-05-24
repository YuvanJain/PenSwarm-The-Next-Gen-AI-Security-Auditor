import json
from typing import Dict
from backend.core.llm_provider import llm
from backend.agents.executor_agent import ExecutorAgent

class ValidatorAgent:
    """Validates and confirms vulnerability findings using LLM."""
    
    def evaluate_results(self, technician_result: Dict) -> bool:
        """Evaluate if the evidence confirms a real vulnerability."""
        evidence = technician_result.get("evidence", "")
        
        # Quick pass if already confirmed
        if technician_result.get("success", False):
            return True
        
        if not evidence:
            return False
        
        # Use LLM for edge cases
        system_prompt = "You are a senior security auditor reviewing penetration test results."
        user_prompt = f"""
Evidence collected during testing:
{evidence}

Does this evidence confirm a successful security vulnerability exploit?
Consider: Is the payload actually being executed/interpreted, or just displayed as text?

Reply with ONLY 'YES' or 'NO'.
"""
        
        try:
            response = llm.query(user_prompt, system_role=system_prompt, use_coder=False)
            return "YES" in response.upper()
        except:
            return False


class VerifierAgent:
    """Independent verification agent that re-tests findings using curl to confirm true positives."""
    
    def __init__(self):
        self.executor = ExecutorAgent()
    
    def verify_finding(self, finding) -> Dict:
        """Verify a finding by re-executing its curl command and analyzing the response."""
        curl_command = finding.http_trace.get('curl_command', '')
        
        if not curl_command:
            return {"verified": False, "verdict": "No curl command available", "curl_output": ""}
        
        print(f"[Verifier] Testing: {curl_command[:80]}...")
        
        # Step 1: Run the curl command
        curl_result = self.executor._run_curl(curl_command)
        curl_output = curl_result.get('body', '')
        status_code = curl_result.get('status_code', 0)
        
        if not curl_output and curl_result.get('error'):
            return {
                "verified": False, 
                "verdict": f"Curl execution failed: {curl_result['error']}", 
                "curl_output": curl_result['error']
            }
        
        # Step 2: AI analysis — strict true/false positive classification
        system_prompt = """You are an expert security auditor performing INDEPENDENT VERIFICATION of vulnerability findings.
You must be VERY STRICT. A finding is only a TRUE POSITIVE if the curl output shows CONCRETE PROOF of exploitation.

TRUE POSITIVE indicators:
- Authentication bypass: JWT token, session cookie, or user data returned
- SQL Injection: Database syntax errors (e.g. "SQL syntax", "SQLite error", "MySQL Error", "Unclosed quotation mark") OR data leakage
- XSS: Script payload stored and reflected back unescaped in HTML context
- Data exposure: Sensitive user data (emails, passwords, tokens) visible

FALSE POSITIVE indicators:
- Generic HTTP 500/400 errors without specific DB error messages
- Application returning "Invalid email or password" or similar rejection
- "Parameter has invalid value" validation errors
- Payload is URL-encoded/escaped in the response (not executed)
- No meaningful difference from a normal response"""

        user_prompt = f"""
FINDING CLAIMED: {finding.title}
CATEGORY: {finding.category}
ORIGINAL EVIDENCE: {finding.http_trace.get('response', 'N/A')[:500]}

CURL COMMAND: {curl_command}
CURL HTTP STATUS: {status_code}
CURL OUTPUT (first 8000 chars):
{curl_output[:8000]}

Based on the curl output, is this vulnerability CONFIRMED (true positive) or REJECTED (false positive)?

You MUST respond in this exact JSON format:
{{
    "verified": true or false,
    "verdict": "One sentence explaining your reasoning",
    "severity": "CRITICAL/HIGH/MEDIUM/LOW/NONE"
}}
"""
        
        try:
            response_text = llm.query(user_prompt, system_role=system_prompt, use_coder=False)
            
            # Clean and parse
            import re
            json_match = re.search(r'\{[^}]+\}', response_text, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                verified = data.get('verified', False)
                verdict = data.get('verdict', 'Unknown')
                severity = data.get('severity', 'UNKNOWN')
                
                status = "✅ VERIFIED" if verified else "❌ REJECTED"
                print(f"[Verifier] {status}: {verdict}")
                
                return {
                    "verified": verified,
                    "verdict": verdict,
                    "severity": severity,
                    "curl_output": curl_output[:2000],
                    "status_code": status_code
                }
        except Exception as e:
            print(f"[Verifier] AI analysis failed: {e}")
        
        # Fallback: if AI fails, do basic heuristic checks
        return self._heuristic_verify(finding, curl_output, status_code)
    
    def _heuristic_verify(self, finding, curl_output: str, status_code: int) -> Dict:
        """Fallback verification using heuristic checks when AI is unavailable."""
        curl_lower = curl_output.lower()
        
        # Check for auth bypass indicators
        if any(x in curl_lower for x in ['"token":', '"authentication":', '"jwt":', '"access_token":']):
            return {"verified": True, "verdict": "Auth bypass confirmed: token in response", "curl_output": curl_output[:2000], "status_code": status_code}
        
        # Check for data exposure
        if '"password":' in curl_lower and '@' in curl_output:
            return {"verified": True, "verdict": "Data leak confirmed: credentials in response", "curl_output": curl_output[:2000], "status_code": status_code}
        
        # Check for missing param errors (false positive)
        if 'has invalid' in curl_output and 'undefined' in curl_output:
            return {"verified": False, "verdict": "Missing parameter error, not a real vulnerability", "curl_output": curl_output[:2000], "status_code": status_code}
        
        # Check for simple rejection
        if status_code == 401 or 'invalid email or password' in curl_lower:
            return {"verified": False, "verdict": "Application rejected the payload", "curl_output": curl_output[:2000], "status_code": status_code}
        
        # Default: unverified
        return {"verified": False, "verdict": "Could not independently confirm exploitation", "curl_output": curl_output[:2000], "status_code": status_code}



