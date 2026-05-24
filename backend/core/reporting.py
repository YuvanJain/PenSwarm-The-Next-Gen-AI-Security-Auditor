import os
from backend.core.models import Finding

class ReportGenerator:
    @staticmethod
    def get_remediation_advice(category: str) -> str:
        """Returns standard remediation advice based on vulnerability category."""
        advice = {
            "Injection": (
                "**Remediation:**\n"
                "- Use parameterized queries (Prepared Statements) for SQL.\n"
                "- Use input validation and sanitization libraries.\n"
                "- Avoid dynamic query construction with user input."
            ),
            "Broken Auth": (
                "**Remediation:**\n"
                "- Implement strong password policies and MFA.\n"
                "- Use standard session management libraries (do not roll your own).\n"
                "- Sign and verify JWTs correctly; enforce algorithm checks."
            ),
            "Cross-Site": (
                "**Remediation:**\n"
                "- Context-aware output encoding (HTML, JavaScript, CSS).\n"
                "- Implement Content Security Policy (CSP).\n"
                "- Use anti-CSRF tokens for state-changing requests."
            ),
            "Access Control": (
                "**Remediation:**\n"
                "- Implement server-side access control checks for every request.\n"
                "- Use indirect object references (randomized IDs/UUIDs).\n"
                "- Follow the Principle of Least Privilege."
            ),
            "Server-Side": (
                "**Remediation:**\n"
                "- Disable XML external entity processing.\n"
                "- Validate and sanitize paths (allowlist approach).\n"
                "- Restrict outbound network calls from the server."
            ),
            "Logic Flaws": (
                "**Remediation:**\n"
                "- Enforce transactional integrity.\n"
                "- Validate business flow state on every step.\n"
                "- Implement rate limiting and consistency checks."
            )
        }
        return advice.get(category, "**Remediation:**\n- Apply defense-in-depth principles.")

    @staticmethod
    def get_severity_badge(confidence: float) -> str:
        """Generate a severity indicator based on confidence."""
        if confidence >= 0.9:
            return "🔴 **CRITICAL**"
        elif confidence >= 0.7:
            return "🟠 **HIGH**"
        elif confidence >= 0.5:
            return "🟡 **MEDIUM**"
        else:
            return "🟢 **LOW**"

    @staticmethod
    def generate_full_report(finding: Finding) -> str:
        """Generates a comprehensive report including PoC and Remediation."""
        severity = ReportGenerator.get_severity_badge(finding.confidence)
        
        report = f"# 🛡️ Security Finding: {finding.title}\n\n"
        report += f"| Property | Value |\n"
        report += f"|----------|-------|\n"
        report += f"| **Severity** | {severity} |\n"
        report += f"| **Category** | {finding.category} |\n"
        report += f"| **Confidence** | {finding.confidence * 100:.0f}% |\n"
        report += f"| **Timestamp** | {finding.timestamp} |\n"
        report += f"| **Status** | {finding.termination_reason} |\n\n"
        
        report += "---\n\n"
        
        report += "## 📋 Executive Summary\n\n"
        report += f"A **{finding.category}** vulnerability was detected with "
        report += f"**{finding.confidence * 100:.0f}%** confidence in the target application.\n\n"
        
        report += "## 🔄 Reproduction Steps\n\n"
        for i, step in enumerate(finding.reproduction_steps, 1):
            report += f"{i}. {step}\n"
        
        report += "\n## 🔍 Evidence\n\n"
        report += "### HTTP Request\n"
        report += f"```http\n{finding.http_trace.get('request', 'N/A')}\n```\n\n"
        report += "### Response Evidence\n"
        report += f"```\n{finding.http_trace.get('response', 'N/A')}\n```\n\n"
        
        # Include screenshot if available
        if 'screenshot' in finding.http_trace:
            screenshot_path = finding.http_trace['screenshot']
            # Use relative path for embedding
            screenshot_name = os.path.basename(screenshot_path)
            report += "### Screenshot Evidence\n\n"
            report += f"![Vulnerability Screenshot]({screenshot_name})\n\n"
        
        # Include curl command for replication
        if 'curl_command' in finding.http_trace:
            report += "### 🔁 Curl Command for Replication\n\n"
            report += "Copy-paste this command to reproduce the vulnerability:\n"
            report += f"```bash\n{finding.http_trace['curl_command']}\n```\n\n"
            
            # Note if this was self-healed
            if finding.http_trace.get('self_healed'):
                report += "> ⚡ *This payload was auto-corrected by AI Self-Healing after the original payload failed.*\n\n"
        
        # Include verification result
        if finding.http_trace.get('verified'):
            report += "### ✅ Independent Verification\n\n"
            report += "> **VERIFIED BY INDEPENDENT CURL TEST**\n\n"
            verdict = finding.http_trace.get('verification_verdict', '')
            if verdict:
                report += f"**Verdict:** {verdict}\n\n"
            curl_output = finding.http_trace.get('verification_curl_output', '')
            if curl_output:
                report += "**Curl Re-Test Output:**\n"
                report += f"```\n{curl_output[:1000]}\n```\n\n"
        
        report += "---\n\n"
        
        remediation = ReportGenerator.get_remediation_advice(finding.category)
        report += f"## 🛠️ Remediation\n\n{remediation}\n\n"
        
        report += "---\n\n"
        report += "*Report generated by PenSwarm AI Security Scanner*\n"
        
        return report

    @staticmethod
    def save_report(finding: Finding, filename: str):
        # Ensure directory exists
        dir_path = os.path.dirname(filename)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
        
        content = ReportGenerator.generate_full_report(finding)
        with open(filename, "w") as f:
            f.write(content)
        return filename
