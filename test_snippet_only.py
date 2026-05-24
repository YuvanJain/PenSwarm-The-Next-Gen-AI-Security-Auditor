from config import MissionProfile
from orchestrator import SwarmOrchestrator
from agents import PlaywrightAgent
import sys

# Gruyere Target
TARGET_URL = "https://google-gruyere.appspot.com/571486264604118090326035032602781716276/"

def test_snippet_vuln():
    print("Locked & Loaded: Targeted Snippet Test...")
    
    # Configure Mission - targeted
    mission = MissionProfile(
        target_url=TARGET_URL,
        selected_modules=["Cross-Site"] # Only XSS
    )
    
    # Initialize Orchestrator
    swarm = SwarmOrchestrator(mission)
    
    # Manually override discovery to ONLY return /snippet
    # masking the real discover method
    swarm.playwright.discover_endpoints = lambda url, depth: [f"{url}/snippet"]

    # Start Mission
    swarm.start()
    
    # Keep main thread alive
    import time
    try:
        while swarm.is_running:
            time.sleep(1)
    except KeyboardInterrupt:
        swarm.stop()

if __name__ == "__main__":
    test_snippet_vuln()
