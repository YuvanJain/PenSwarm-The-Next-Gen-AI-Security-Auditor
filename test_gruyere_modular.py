import time
import threading
import sys
from orchestrator import SwarmOrchestrator
from config import MissionProfile, Config
from models import Finding

def log_callback(msg):
    # print(f"[TEST LOG] {msg}")
    pass

def test_gruyere_modular():
    print("Locked & Loaded: Testing Modular Swarm on Google Gruyere...")
    
    # 1. Setup Mission Profile
    # Target specific instance as requested
    target = "https://google-gruyere.appspot.com/571486264604118090326035032602781716276/"
    modules = ["Cross-Site", "Server-Side"] # Testing XSS and Path Traversal
    
    profile = MissionProfile(target, modules)
    orchestrator = SwarmOrchestrator(profile, log_callback=log_callback)
    
    # 2. Launch Swarm
    orchestrator.start()
    
    # 3. Wait for completion or timeout
    max_wait = 600 # seconds - Increased for Real LLM latency and strict rate limits
    start_time = time.time()
    
    while orchestrator.is_running:
        if time.time() - start_time > max_wait:
            print("TIMEOUT: Swarm took too long.")
            orchestrator.stop()
            break
        time.sleep(1)
        
    # 4. Assert Results
    print("\n--- Mission Report ---")
    print(f"Total Findings: {len(orchestrator.findings)}")
    
    xss_found = False
    traversal_found = False
    
    for finding in orchestrator.findings:
        print(f"  [+] Found: {finding.title} (Confidence: {finding.confidence})")
        if "Cross-Site" in finding.category and "feed" in finding.http_trace['request']:
            xss_found = True
        if "Server-Side" in finding.category and "upload" in finding.http_trace['request']:
            traversal_found = True
            
    if xss_found and traversal_found:
        print("\nSUCCESS: Both XSS and Path Traversal vulnerabilities were detected.")
        sys.exit(0)
    else:
        print("\nFAILURE: Did not detect all expected vulnerabilities.")
        sys.exit(1)

if __name__ == "__main__":
    test_gruyere_modular()
