import subprocess
import time
import re
from typing import Dict, Optional

class MetasploitBridge:
    def __init__(self, msf_path: str = "/opt/metasploit-framework/bin/msfconsole"):
        self.msf_path = msf_path

    def is_available(self) -> bool:
        """Checks if msfconsole executable exists."""
        import os
        # Check default path first
        if os.path.exists(self.msf_path) and os.access(self.msf_path, os.X_OK):
            print(f"[Metasploit] Binary found at {self.msf_path}")
            return True
        return False

    def execute_module(self, module: str, options: Dict[str, str], timeout: int = 120) -> str:
        """
        Executes a specific MSF module in non-interactive mode (-x).
        Example: execute_module('auxiliary/scanner/http/http_version', {'RHOSTS': 'example.com', 'RPORT': '80'})
        """
        # Construct resource script commands
        commands = [f"use {module}"]
        for key, value in options.items():
            commands.append(f"set {key} {value}")
        commands.append("run")
        commands.append("exit")
        
        command_str = "; ".join(commands)
        
        # Build full CLI command
        # -q: Quiet
        # -x: Execute commands
        full_cmd = [self.msf_path, "-q", "-x", command_str]
        
        try:
            print(f"[Metasploit] Running: {module} with {options}")
            result = subprocess.run(
                full_cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            
            if result.returncode != 0:
                print(f"[Metasploit] Error: {result.stderr}")
                return f"Error: {result.stderr}"
                
            return result.stdout
            
        except subprocess.TimeoutExpired:
            return "Error: Metasploit command timed out."
        except Exception as e:
            return f"Error: {str(e)}"

    def check_db_version(self, target_url: str) -> str:
        """Helper to run a DB version check on a target."""
        # Clean target URL to hostname/IP
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        return self.execute_module(
            "auxiliary/scanner/http/http_version", 
            {"RHOSTS": host, "RPORT": str(port)}
        )
