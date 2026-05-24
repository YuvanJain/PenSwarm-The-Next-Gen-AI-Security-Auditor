import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime

@dataclass
class Finding:
    title: str
    category: str
    confidence: float  # 0.0 to 1.0
    reproduction_steps: List[str]
    http_trace: Dict[str, str]  # Simplified for example: {"request": "...", "response": "..."}
    termination_reason: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self):
        return {
            "title": self.title,
            "category": self.category,
            "confidence": self.confidence,
            "reproduction_steps": self.reproduction_steps,
            "http_trace": self.http_trace,
            "termination_reason": self.termination_reason,
            "timestamp": self.timestamp
        }

    def generate_report(self) -> str:
        """Generates a standalone Markdown report for this finding."""
        report = f"# Security Finding: {self.title}\n\n"
        report += f"**Category:** {self.category}\n"
        report += f"**Confidence:** {self.confidence}\n"
        report += f"**Timestamp:** {self.timestamp}\n\n"
        
        report += "## 1. Executive Summary\n"
        report += f"The swarm detected a {self.confidence * 100:.1f}% confidence vulnerability in the target application.\n"
        
        report += "## 2. Reproduction Steps\n"
        for i, step in enumerate(self.reproduction_steps, 1):
            report += f"{i}. {step}\n"
            
        report += "\n## 3. Evidence (HTTP Trace)\n"
        report += "### Request\n"
        report += f"```http\n{self.http_trace.get('request', 'N/A')}\n```\n"
        report += "### Response\n"
        report += f"```http\n{self.http_trace.get('response', 'N/A')}\n```\n"
        
        return report

