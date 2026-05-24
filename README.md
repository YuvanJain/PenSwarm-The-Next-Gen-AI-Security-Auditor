# 🛡️ PenSwarm

### *Agentic AI Penetration Testing Swarm & White-Box Source Code Security Audit Framework*

PenSwarm is an advanced, multi-agent security framework designed to perform comprehensive black-box penetration testing and white-box source code audits. Powered by LLM reasoning, Playwright browser automation, and a concurrent swarm architecture, PenSwarm discovers, exploits, verifies, and reports vulnerabilities in real-time.

---

## 🌟 Key Features

### 🕸️ Multi-Agent Swarm Orchestration
PenSwarm operates via a collaborative agent swarm, where specialized agents focus on specific phases of the lifecycle—Recon, Discovery, Attack Formulation, Execution, and Multi-Stage Verification.

### 🧪 Dual-Mode Operations
1. **Black-Box Web Application Swarm**:
   - Automated authentication and multi-session capabilities (Session A / Session B).
   - Playwright-powered traffic interception and deep reconnaissance.
   - Real-time IDOR testing, XSS testing, Path Traversal, and SQL Injection verification.
2. **White-Box Source Code Security Scanner**:
   - Clones remote git repositories or walks local directories.
   - Parses code in chunks, prioritizing critical files (Python, JavaScript, Go, etc.).
   - Utilizes advanced LLM code reasoning to identify vulnerabilities and suggest code fixes.

### ⚡ Live Dashboard & Progress Tracking
- **Interactive UI**: Flask-powered control panel with SSE (Server-Sent Events) live log stream.
- **Visual Analytics**: Interactive infographics describing the codebase architecture, comparison metrics, and swarm structures.

### 📸 Auto-Proof-of-Concept & Screenshots
- Captures automated screenshots of confirmed exploits using headless Playwright.
- Generates reproducible `curl` commands with matching authentication headers.

---

## 🏗️ Architecture & Agent Roles

```mermaid
graph TD
    User([User / Web UI]) -->|Configure & Launch| Orchestrator[Swarm Orchestrator]
    
    subgraph Recon & Discovery
        Orchestrator --> ReconAgent[Recon Agent]
        Orchestrator --> PWRecon[Playwright Recon Agent]
        Orchestrator --> Crawler[Crawler Agent]
    end
    
    subgraph Attack & Exploitation
        Orchestrator --> Thinker[Thinker Agent (LLM)]
        Orchestrator --> Executor[Executor Agent]
    end
    
    subgraph Verification & Safety
        Orchestrator --> Safety[Constraint Wrapper]
        Executor --> Val[Validator & Verifier Agents]
        Val -->|Exploit Confirmed| PoC[Playwright Screenshot & PoC]
    end
    
    subgraph Reporting
        Val -->|Verified Findings| Report[Report Generator]
        Orchestrator -->|Final Report| Summary[Consolidated SUMMARY.md]
    end
```

### 👥 Agent Roles Breakdown

*   **Recon Agent & Playwright Recon Agent**: Handles subdomain discovery, port scanning, and active HTTP traffic monitoring.
*   **Crawler Agent**: Recursively extracts endpoints, parameters, and forms, filtering static assets and prioritizing high-value auth/login paths.
*   **Thinker Agent**: Acts as the brain. Evaluates context, designs targeted payloads, and performs static JS data-flow analysis to detect client-side vulnerabilities.
*   **Executor Agent**: Delivers payloads safely under strict rate-limiting rules.
*   **Validator & Verifier Agents**: Filters out false positives by re-executing payloads and verifying proof-of-exploitation. Emits verified findings to the reporting engine and initiates Playwright to take screenshots of the vuln.
*   **Auth Agent**: Automates login flows and handles session management to discover authenticated endpoints.
*   **Code Scanner Agent**: Clones remote Git repositories or scans local projects, sending chunks of source files to the LLM to identify hardcoded secrets, injection flaws, path traversals, and cryptographic issues.

---

## ⚙️ Technology Stack

- **Backend**: Python, Flask, ThreadPoolExecutor
- **Frontend**: HTML5, Vanilla CSS, Javascript
- **Security Tools**: Playwright (Browser Automation), Requests (HTTP Execution)
- **Intelligence**: LLM API integration (OpenAI / Gemini)
- **Reporting**: Markdown, Mermaid, HTML Infographics

---

## 🚀 Quick Start

### 📋 Prerequisites

- **Python**: v3.10+
- **Git**: Installed and available in PATH
- **Playwright System Dependencies**: Required for browser automation

### 🔧 Installation & Setup

1. **Clone the Repository** (or navigate to the workspace directory):
   ```bash
   cd penswarm
   ```

2. **Create and Activate a Virtual Environment**:
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Install Playwright Browsers**:
   ```bash
   playwright install
   ```

5. **Configure Environment Variables**:
   Create a `.env` file in the root of the project with your API keys:
   ```env
   OPENAI_API_KEY=your_openai_api_key
   # Or configure alternative providers as needed
   ```

### 💻 Running the Web Dashboard

Launch the Flask web server:
```bash
python app.py
```
Open your browser and navigate to **`http://localhost:5001`**.

---

## 📊 Visual Infographics

PenSwarm includes pre-compiled interactive HTML visualizers to understand the codebase and swarm behavior:
- `swarm_infographic.html`: Displays swarm structure, agent nodes, and operational phases.
- `codebase_infographic.html`: Illustrates directory structures and module relationships.
- `techstack_infographic.html`: Details technologies, tools, and libraries utilized.
- `comparison_infographic.html`: Comparative analysis metrics for different modules.

Open these files in any modern web browser to view the visual models.

---

## 📁 Output Reports Directory

All scan runs output comprehensive audit reports in the `reports/` folder:
- **`SUMMARY.md`**: Consolidated executive summary showing verified vulnerabilities, confidence metrics, and false-positive rejections.
- **`finding_[ID]_[category].md`**: Individual technical finding reports containing descriptions, suggested fixes, code snippets, HTTP request/response traces, and screenshot paths.
- **`screenshot_[ID].png`**: Visual proof-of-concept for verified vulnerabilities.
- **`rejected_findings.md`**: Audit trail of rejected hypotheses for verification and false-negative evaluation.

---

## ⚠️ Disclaimer & Safety Guidelines

> [!WARNING]
> **Authorized Testing Only**: PenSwarm must ONLY be run against web applications and codebases for which you have explicit, written authorization. Running scanning tools on targets without permission is illegal and violates terms of service.
> Always utilize the `ConstraintWrapper` and configure `FORBIDDEN_PATHS` (such as `/logout`, `/delete-account`, etc.) to prevent unintended side effects on staging and production environments.
