from llm_provider import llm
import os

print(f"Provider: {llm.provider}")
print(f"Model: {llm.primary_model}")
print(f"Endpoint: {llm.endpoint}")
print(f"Client initialized: {llm.client is not None}")

try:
    print("Sending test query...")
    response = llm.query("Test query: verify connection", use_coder=False)
    print(f"Response received (len {len(response)}): {response[:50]}...")
except Exception as e:
    print(f"Error: {e}")
