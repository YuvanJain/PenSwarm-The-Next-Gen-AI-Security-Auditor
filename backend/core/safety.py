import time
import threading
from urllib.parse import urlparse
from backend.core.config import Config

class ConstraintWrapper:
    def __init__(self):
        self.request_timestamps = []
        self._lock = threading.Lock()

    def is_forbidden(self, url: str) -> bool:
        """Checks if URL path is in forbidden list."""
        parsed_url = urlparse(url)
        path = parsed_url.path
        for forbidden in Config.FORBIDDEN_PATHS:
            if forbidden in path:
                return True
        return False

    def acquire_request_slot(self):
        """Blocks until a request slot is available (thread-safe)."""
        while True:
            with self._lock:
                current_time = time.time()
                # Prune old timestamps
                self.request_timestamps = [t for t in self.request_timestamps if current_time - t < 1.0]
                
                if len(self.request_timestamps) < Config.MAX_REQUESTS_PER_SECOND:
                    self.request_timestamps.append(current_time)
                    return
            
            # Wait a bit before checking again
            time.sleep(0.05)

    def validate_depth(self, current_depth: int) -> bool:
        """Checks if the current crawl depth is within limits."""
        return current_depth <= Config.MAX_CRAWL_DEPTH

    def validate_mutations(self, attempt_count: int) -> bool:
        """Checks if mutation count is within limits."""
        return attempt_count <= Config.MAX_MUTATIONS_PER_PARAM
