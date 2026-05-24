import requests
import random

def _random_browser_headers() -> dict:
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0'
    ]
    return {
        'User-Agent': random.choice(user_agents),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Upgrade-Insecure-Requests': '1'
    }

class BaseAgent:
    """Base class providing shared HTTP session capabilities for all agents."""
    
    def __init__(self, base_url: str = None, session: requests.Session = None):
        self.base_url = base_url.rstrip('/') if base_url else None
        
        if session:
            self.session = session
        else:
            self.session = requests.Session()
            # Default headers to mimic a normal browser and avoid basic WAF blocks
            self.session.headers.update(_random_browser_headers())
    
    def update_session_auth(self, auth_headers: dict = None, cookies: dict = None):
        """Inject authentication state dynamically into the agent's requests session."""
        if auth_headers:
            self.session.headers.update(auth_headers)
        if cookies:
            self.session.cookies.update(cookies)
