import os
import re
import json
import time
import threading
from dotenv import load_dotenv

try:
    from langsmith import traceable
    LANGSMITH_AVAILABLE = True
except ImportError:
    # Fallback: no-op decorator if langsmith is not installed
    def traceable(**kwargs):
        def decorator(func):
            return func
        return decorator
    LANGSMITH_AVAILABLE = False

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    import boto3
    from botocore.exceptions import ClientError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

load_dotenv()

class LLMProvider:
    """Unified LLM provider with Round-Robin Rotation for Rate Limit Evasion."""
    
    def __init__(self):
        self.provider = os.getenv("LLM_PROVIDER", "azure").lower()
        self.enable_rotation = os.getenv("ENABLE_LLM_ROTATION", "false").lower() == "true"
        
        # Primary static model (used if rotation is disabled or fails)
        if self.provider == "groq":
            self.endpoint = "https://api.groq.com/openai/v1"
            self.api_key = os.getenv("GROQ_API_KEY")
            self.primary_model = os.getenv("LLM_MODEL", "llama-3.3-70b-versatile")
        elif self.provider == "aws":
            self.endpoint = None
            self.api_key = os.getenv("AWS_ACCESS_KEY_ID")
            self.primary_model = os.getenv("LLM_MODEL", "moonshotai.kimi-k2.5")
        else:
            self.endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
            self.api_key = os.getenv("AZURE_OPENAI_API_KEY")
            self.primary_model = os.getenv("LLM_MODEL", "grok-4-fast-reasoning")
        
        self.coder_model = os.getenv("LLM_CODER_MODEL", "qwen.qwen3-vl-235b-a22b") if self.provider == "aws" else os.getenv("LLM_CODER_MODEL", self.primary_model)
        
        # Primary static client
        self.client = None
        self.aws_client = None
        
        if self.provider == "aws" and BOTO3_AVAILABLE:
            aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
            aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
            aws_region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
            
            # Use credentials natively from ENV if not explicitly passed, boto3 fetches them automatically
            boto_kwargs = {'region_name': aws_region}
            if aws_access_key and aws_secret_key:
                boto_kwargs.update({'aws_access_key_id': aws_access_key, 'aws_secret_access_key': aws_secret_key})
                
            self.aws_client = boto3.client('bedrock-runtime', **boto_kwargs)
            
        elif OPENAI_AVAILABLE and self.endpoint and self.api_key:
            self.client = OpenAI(base_url=self.endpoint, api_key=self.api_key)
            
        # --- Rotation Pool Setup ---
        self.rotation_pool = []
        self.pool_size = 0
        self.current_pool_index = 0
        self.pool_lock = threading.Lock()
        
        if self.enable_rotation:
            self._init_rotation_pool()

    def _init_rotation_pool(self):
        """Parse LLM_ROTATION_POOL from .env and build client configs."""
        pool_json = os.getenv("LLM_ROTATION_POOL", "")
        if not pool_json:
            return
            
        try:
            pool_configs = json.loads(pool_json)
            for config in pool_configs:
                provider = config.get("provider", "")
                if provider == "aws":
                    if BOTO3_AVAILABLE:
                        aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
                        aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
                        aws_region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
                        
                        boto_kwargs = {'region_name': aws_region}
                        if aws_access_key and aws_secret_key:
                            boto_kwargs.update({'aws_access_key_id': aws_access_key, 'aws_secret_access_key': aws_secret_key})
                            
                        client = boto3.client('bedrock-runtime', **boto_kwargs)
                        
                        self.rotation_pool.append({
                            "provider": "aws",
                            "model": config["model"],
                            "client": client
                        })
                else:
                    api_key = os.getenv(config.get("api_key_env", ""))
                    if api_key:
                        self.rotation_pool.append({
                            "provider": provider,
                            "model": config["model"],
                            "client": OpenAI(base_url=config["base_url"], api_key=api_key)
                        })
            self.pool_size = len(self.rotation_pool)
            print(f"[LLM] Initialized Rotation Pool with {self.pool_size} models.")
        except Exception as e:
            print(f"[LLM] Error parsing rotation pool: {e}")

    def _get_next_pool_client(self) -> dict:
        """Thread-safe round-robin selection of the next model in the pool."""
        if self.pool_size == 0:
            return None
        with self.pool_lock:
            config = self.rotation_pool[self.current_pool_index]
            self.current_pool_index = (self.current_pool_index + 1) % self.pool_size
            return config

    @traceable(run_type="llm", name="LLM Query")
    def query(self, prompt: str, system_role: str = "You are a helpful assistant.", 
              use_coder: bool = False, temperature: float = 0.7) -> str:
        """Query the LLM, with automatic fallback on 429 Rate Limit errors."""
        
        task_type = "coding" if use_coder else "thinking"
        
        # If rotation is disabled or pool is empty, use standard static client
        if not self.enable_rotation or self.pool_size == 0:
            model = self.coder_model if use_coder else self.primary_model
            client = self.aws_client if self.provider == "aws" else self.client
            provider = self.provider
            
            print(f"[LLM] Using {model} ({task_type})")
            return self._execute_query(client, model, system_role, prompt, temperature, provider)

        # --- Round-Robin Execution with Fallback ---
        # Try up to N times (where N is the pool size)
        for attempt in range(self.pool_size):
            pool_config = self._get_next_pool_client()
            client = pool_config["client"]
            model = pool_config["model"]
            provider = pool_config["provider"]
            
            print(f"[LLM] Using {model} ({task_type})")
            
            try:
                response = self._execute_query(client, model, system_role, prompt, temperature, provider)
                
                # Check if it's a simulated or intercepted 429 string
                if "rate limit" in response.lower() or "429" in response:
                    raise Exception(f"429 Rate Limit hit manually parsed from response")
                
                # Guard: If response is too short (< 10 chars), it's likely garbage
                # Models on Bedrock sometimes return "No", "{}", or blank answers
                if len(response.strip()) < 10 and attempt < self.pool_size - 1:
                    print(f"[LLM] ⚠️ Response too short ({len(response.strip())} chars) from {model}. Rotating...")
                    continue
                    
                return response
                
            except Exception as e:
                error_str = str(e).lower()
                if "429" in error_str or "rate limit" in error_str or "too many requests" in error_str:
                    print(f"[LLM] ⚠️ Rate limit hit on {model}. Rotating to next model...")
                    continue  # Try next in pool
                else:
                    return f"LLM Error: {str(e)}"
                    
        return "LLM Error: All models in rotation pool exhausted due to rate limits."

    @traceable(run_type="llm", name="LLM Execute")
    def _execute_query(self, client, model: str, system_role: str, prompt: str, temperature: float, provider: str = "openai") -> str:
        """Raw execution wrapper with LangSmith tracing."""
        start_time = time.time()
        
        if provider == "aws" and client:
            try:
                response = client.converse(
                    modelId=model,
                    messages=[
                        {
                            "role": "user",
                            "content": [{"text": prompt}]
                        }
                    ],
                    system=[{"text": system_role}],
                    inferenceConfig={
                        "temperature": temperature,
                        "maxTokens": 4096
                    }
                )
                # Handle thinking models (e.g. kimi-k2-thinking) that return
                # [reasoningContent, text] instead of just [text]
                content_blocks = response['output']['message']['content']
                result = None
                for block in content_blocks:
                    if 'text' in block:
                        result = block['text']
                if result is None:
                    result = str(content_blocks)
                
                elapsed = round(time.time() - start_time, 2)
                print(f"[LLM] ✅ {model} responded in {elapsed}s ({len(result)} chars)")
                return result
            except Exception as e:
                raise e
                
        if not client:
            return "Error: LLM client not initialized."
            
        try:
            completion = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_role},
                    {"role": "user", "content": prompt}
                ],
                temperature=temperature,
                max_tokens=4096
            )
            result = completion.choices[0].message.content
            elapsed = round(time.time() - start_time, 2)
            print(f"[LLM] ✅ {model} responded in {elapsed}s ({len(result)} chars)")
            return result
        except Exception as e:
            # Let the caller catch the error to trigger fallback
            raise e

# Singleton instance
llm = LLMProvider()
