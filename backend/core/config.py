from dataclasses import dataclass
from typing import List, Dict

@dataclass
class VulnerabilityCategory:
    name: str
    strategies: List[str]

# Define available categories
INJECTION = VulnerabilityCategory("Injection", ["SQLi", "NoSQLi", "Command Injection"])
BROKEN_AUTH = VulnerabilityCategory("Broken Auth", ["JWT Bypass", "OAuth Misconfig", "Brute-force"])
CROSS_SITE = VulnerabilityCategory("Cross-Site", ["Reflected XSS", "DOM XSS", "CSRF"])
ACCESS_CONTROL = VulnerabilityCategory("Access Control", ["IDOR", "Privilege Escalation"])
SERVER_SIDE = VulnerabilityCategory("Server-Side", ["SSRF", "XXE", "Path Traversal"])
LOGIC_FLAWS = VulnerabilityCategory("Logic Flaws", ["Race Conditions", "Business Logic Bypass"])

ALL_CATEGORIES = {
    "Injection": INJECTION,
    "Broken Auth": BROKEN_AUTH,
    "Cross-Site": CROSS_SITE,
    "Access Control": ACCESS_CONTROL,
    "Server-Side": SERVER_SIDE,
    "Logic Flaws": LOGIC_FLAWS
}

class Config:
    # Safety Valve / Realism Layer Constraints
    MAX_REQUESTS_PER_SECOND = 50
    MAX_CRAWL_DEPTH = 4
    MAX_MUTATIONS_PER_PARAM = 15
    FORBIDDEN_PATHS = ["/logout", "/delete-account", "/reset-db", "/admin/destroy"]
    
    # Endpoint Discovery Options
    PROBE_API_ENDPOINTS = False  # Disabled: AI probe list is non-deterministic, causing varying endpoint counts per run
    
    # Intelligence / Logic Settings
    CONFIDENCE_THRESHOLD = 0.0  # Never abandon - test ALL payloads
    DECAY_RATE = 0.0            # No decay - full testing per endpoint
    
    # Target Settings (Default)
    DEFAULT_TARGET_URL = "https://preview.owasp-juice.shop/"

class MissionProfile:
    def __init__(self, target_url: str, selected_modules: list, headers: dict = None, headers_b: dict = None):
        self.target_url = target_url
        self.selected_modules = selected_modules  # List of category names, e.g., ["Injection", "Broken Auth"]
        self.headers = headers or {}  # Custom headers for manual authentication (Session A)
        self.headers_b = headers_b or {}  # Custom headers for IDOR testing (Session B)
        self.context = {}  # Shared mission context for data passing
        
    def is_module_active(self, category_name: str) -> bool:
        return category_name in self.selected_modules

import urllib.parse
def get_root_domain(url_or_domain: str) -> str:
    """Extracts the root domain (e.g., example.com from api.example.com)."""
    if "://" in url_or_domain:
        domain = urllib.parse.urlparse(url_or_domain).netloc
    else:
        domain = url_or_domain
    domain = domain.split(':')[0] # Remove port
    parts = domain.split('.')
    if len(parts) > 2 and parts[-2] in ('co', 'com', 'org', 'net', 'gov', 'edu', 'ac'):
        return '.'.join(parts[-3:])
    elif len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain
