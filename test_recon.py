from recon import ReconAgent
import sys

def test():
    print("Initializing ReconAgent...")
    try:
        agent = ReconAgent()
        print("ReconAgent initialized.")
        
        nmap_path = agent._check_nmap()
        if nmap_path:
            print(f"✅ Nmap found at: {nmap_path}")
        else:
            print("⚠️ Nmap not found. Using Python fallback.")
            
        print("ReconAgent test passed.")
    except Exception as e:
        print(f"❌ ReconAgent test failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    test()
