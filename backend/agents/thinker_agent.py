import json
import re
from typing import Dict, Optional

from backend.agents.base_agent import BaseAgent
from backend.core.llm_provider import llm

class ThinkerAgent:
    """Reasoning agent that generates attack hypotheses and payloads using LLM."""
    
    def generate_hypothesis(self, endpoint: str, category: str, context: str = '') -> Optional[Dict]:
        """Generate attack hypothesis and payloads for a given endpoint and category."""
        model_name = getattr(llm, 'coder_model', 'LLM')
        print(f"[Thinker ({model_name})] Analyzing {endpoint} for {category}...")
        
        # Category-specific guidance for the LLM
        category_guidance = self._get_category_guidance(category)
        
        # Application context from deep recon (if available)
        context_block = ""
        if context:
            context_block = f"\nApplication Context: {context}\nUse this context to generate more targeted and realistic payloads.\n"
        
        system_prompt = f"""You are an elite penetration tester and vulnerability researcher.
Your task is to analyze a URL endpoint and generate specific attack payloads for {category} vulnerabilities.

{category_guidance}

You must output ONLY valid JSON, no explanations or markdown."""

        user_prompt = f"""
Target Endpoint: {endpoint}
Vulnerability Category: {category}
{context_block}
Analyze this endpoint and:
1. Identify the most likely attack vector for {category} vulnerabilities
2. Determine which parameter or input field to target (analyze the URL structure)
3. Generate 5 effective {category} payloads that would work on real applications
4. Determine if GET or POST is more appropriate

Output ONLY this JSON format:
{{
    "hypothesis": "One sentence describing the attack vector",
    "target_parameter": "parameter_name or null if path-based",
    "http_method": "GET or POST",
    "payloads": ["payload1", "payload2", "payload3", "payload4", "payload5"],
    "confidence": 0.7
}}
"""
        
        try:
            response_text = llm.query(user_prompt, system_role=system_prompt, use_coder=False)  # GPT-5 for thinking
            print(f"[DEBUG] Raw Response: {response_text[:200]}...")
            
            # Clean response
            response_text = self._clean_response(response_text)
            data = json.loads(response_text)
            
            # Validate response structure
            if 'payloads' not in data or not data['payloads']:
                raise ValueError("No payloads in response")
            
            return data
            
        except Exception as e:
            print(f"[Thinker] Error: {e}")
            return None

    def analyze_js_data_flow(self, js_url: str, js_content: str) -> list:
        """
        [Shannon-Style] Perform static data flow analysis on JS code to find client-side vulns.
        Identifies Sources (user input) flowing into Sinks (execution).
        """
        model_name = getattr(llm, 'coder_model', 'LLM')
        print(f"[Thinker ({model_name})] Analyzing Data Flow in {js_url}...")
        
        system_prompt = """You are an expert Static Application Security Testing (SAST) engine.
Your goal is to analyze JavaScript code for DOM-based vulnerabilities (XSS, Open Redirect, etc).
Trace data flow from Sources (location.*, document.cookie, input.value) to Sinks (innerHTML, eval, setTimeout, location.href).
"""
        # Truncate content if too large (TOKEN LIMIT SAFETY)
        content_snippet = js_content[:15000]
        
        user_prompt = f"""
Analyze this JavaScript code from {js_url}:
```javascript
{content_snippet}
```

Identify potential vulnerabilities where user input flows into dangerous sinks WITHOUT validation.
Output JSON list:
[
  {{
    "type": "DOM XSS",
    "source": "location.search",
    "sink": "document.write",
    "line_number": 123,
    "confidence": "High/Medium/Low",
    "snippet": "code snippet"
  }}
]
If none, output [].
"""
        try:
            response_text = llm.query(user_prompt, system_role=system_prompt, use_coder=False)
            response_text = self._clean_response(response_text)
            data = json.loads(response_text)
            return data
        except Exception as e:
            print(f"[Thinker] Data flow analysis failed: {e}")
            return []
    
    def _get_category_guidance(self, category: str) -> str:
        """Get category-specific guidance for the LLM."""
        guidance = {
            "Injection": """For SQL/NoSQL Injection, generate payloads that EVADE WAFs:
- Use URL encoding (e.g., %27 instead of ') or Hex encoding
- Use alternative whitespace characters (e.g., /**/ instead of space)
- Use string concatenation or fragmented queries
- Test for Blind SQLi (time-based delays, e.g., pg_sleep(5), WAITFOR DELAY)
Example patterns: %27%20OR%201%3D1--, admin'/**/OR/**/'1'='1, {"$ne": null}, etc.""",

            "Cross-Site": """For XSS vulnerabilities, generate payloads that EVADE WAFs:
- AVOID basic <script>alert(1)</script> which gets blocked immediately
- Use HTML Entity encoding, Unicode escapes, or URL encoding
- Use unconventional event handlers (e.g., onpageshow, ontransitionend)
- Use fragmented payloads or data URIs (e.g., <object data="data:text/html;base64,...">)
Example patterns: <svg/onload=alert(1)>, %3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E, etc.""",

            "Broken Auth": """For authentication bypass, generate payloads that EVADE WAFs:
- Test for JWT manipulation (None algorithm, key confusion)
- Test for JSON body injection (e.g., {"username": {"$ne": null}})
- Test default/weak credentials if form-based
- Try parameter pollution or HTTP Verb Tampering
Example patterns: admin' --, {"$gt": ""}, etc.""",

            "Access Control": """CRITICAL: For Access Control flaws (IDOR / BOLA), focus on OBJECT IDENTIFIERS.
- Identify IDs in the URL path (e.g., /users/123/profile) or parameters (e.g., ?user_id=123, ?account=ABC)
- Generate payloads that mutate these IDs (e.g., change 123 to 124, change UUID to another format)
- Test privilege escalation by altering roles (e.g., {"role":"admin"}) or bypassing tenant boundaries.
- The goal is to access DATA belonging to ANOTHER user without authorization.
Example patterns: user_id=9999, account_id=0, ../../../etc/passwd, etc.""",

            "Server-Side": """For server-side vulnerabilities (SSRF, XXE), generate payloads that EVADE WAFs:
- Use alternative IP representations for SSRF (e.g., 2130706433 instead of 127.0.0.1, or 0.0.0.0, [::])
- Use DNS rebinding domains or tricky schemes (e.g., dict://, gopher://, file://)
- For XXE, try out-of-band (OOB) interactions or parameter entities if blocked.
Example patterns: http://2130706433, file:///etc/passwd, http://169.254.169.254/latest/meta-data/""",

            "Logic Flaws": """For business logic flaws, analyze the application CONTEXT deeply:
- Identify numeric parameters affecting cost/quantity and inject negative values (e.g., price=-100), zero, or max-int
- Identify workflow steps and skip them (e.g., going straight to /checkout/confirm without paying)
- Test parameter manipulation that breaks the expected state machine (e.g., transferring $0, manipulating discounts)
Example patterns: price=-1, quantity=999999999, discount=100%, etc."""
        }
        return guidance.get(category, "Generate appropriate security testing payloads.")
    
    def _clean_response(self, response: str) -> str:
        """Clean LLM response to extract JSON."""
        # Remove <think> tags
        if "<think>" in response:
            response = re.sub(r'<think>.*?</think>', '', response, flags=re.DOTALL).strip()
        
        # Extract from code blocks
        if "```json" in response:
            response = response.split("```json")[1].split("```")[0].strip()
        elif "```" in response:
            response = response.split("```")[1].split("```")[0].strip()
        
        return response

    def adapt_payload(self, endpoint: str, category: str, original_payload: str, 
                      error_response: str, target_parameter: str = None, 
                      http_method: str = 'GET') -> Optional[Dict]:
        """AI Self-Healing: Analyze why a payload failed and generate a corrected one."""
        model_name = getattr(llm, 'coder_model', 'LLM')
        print(f"[Self-Healing ({model_name})] Adapting payload for {endpoint}...")
        
        system_prompt = """You are an elite penetration tester debugging a failed exploit.
A payload was sent to an endpoint but FAILED. You are given the error response.
Analyze WHY it failed and generate a CORRECTED payload that addresses the specific issue.

Common failure reasons:
- Missing required parameters (e.g., captchaId, ProductId, BasketId)
- Wrong HTTP method (GET vs POST)
- Wrong Content-Type (form vs JSON)
- Wrong parameter name
- Payload needs URL encoding

You must output ONLY valid JSON, no explanations or markdown."""

        user_prompt = f"""
Target Endpoint: {endpoint}
Category: {category}
HTTP Method: {http_method}
Target Parameter: {target_parameter}
Original Payload: {original_payload}

Error Response (why it failed):
{error_response[:1500]}

Analyze the error and generate a corrected attack. If the error mentions a missing parameter
(like "captchaId has invalid undefined value"), include that parameter with a reasonable value.

Output ONLY this JSON:
{{
    "analysis": "One sentence: why the original payload failed",
    "corrected_payload": "the fixed payload string",
    "additional_params": {{"param_name": "value"}},
    "http_method": "GET or POST",
    "target_parameter": "parameter_name",
    "content_type": "json or form"
}}
"""
        try:
            response_text = llm.query(user_prompt, system_role=system_prompt, use_coder=False)
            response_text = self._clean_response(response_text)
            data = json.loads(response_text)
            
            if 'corrected_payload' not in data:
                raise ValueError("No corrected payload in response")
            
            print(f"[Self-Healing] Analysis: {data.get('analysis', 'N/A')}")
            return data
            
        except Exception as e:
            print(f"[Self-Healing] Adaptation failed: {e}")
            return None
