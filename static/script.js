// ===== DOM Elements =====
const targetInput = document.getElementById('target-url');
const launchBtn = document.getElementById('launch-btn');
const abortBtn = document.getElementById('abort-btn');
const logConsole = document.getElementById('log-console');
const statusIndicator = document.getElementById('status-indicator');
const statusText = document.getElementById('system-status');
const clearLogsBtn = document.getElementById('clear-logs');

// Stats
const endpointsCount = document.getElementById('endpoints-count');
const testsCount = document.getElementById('tests-count');
const verifiedCount = document.getElementById('verified-count');
const rejectedCount = document.getElementById('rejected-count');
const _countedFindings = new Set(); // Dedup: track finding numbers already counted in KPIs

// Progress
const progressFill = document.getElementById('progress-fill');
const progressLabel = document.getElementById('progress-label');
const progressPercent = document.getElementById('progress-percent');
const findingsList = document.getElementById('findings-list');

// ===== State =====
let eventSource = null;
let stats = { endpoints: 0, tests: 0, verified: 0, rejected: 0 };
let currentPhase = 'discovery';
let progress = 0;

// ===== Helper Functions =====

function getLogType(message) {
    const msg = message.toLowerCase();
    if (msg.includes('confirmed') || msg.includes('success') || msg.includes('vulnerability') || msg.includes('verified')) return 'success';
    if (msg.includes('error') || msg.includes('failed') || msg.includes('blocked') || msg.includes('rejected')) return 'error';
    if (msg.includes('hypothesis') || msg.includes('firing') || msg.includes('analyzing')) return 'warning';
    if (msg.includes('phase') || msg.includes('starting') || msg.includes('discovered')) return 'info';
    return 'system';
}

function getBadgeText(type) {
    const badges = {
        'success': 'VULN',
        'error': 'ERROR',
        'warning': 'TEST',
        'info': 'INFO',
        'system': 'SYS'
    };
    return badges[type] || 'LOG';
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function updateProgress(value, label = null) {
    progress = value;
    progressFill.style.width = `${value}%`;
    progressPercent.textContent = `${Math.round(value)}%`;
    if (label) progressLabel.textContent = label;
}

function setPhase(phase) {
    currentPhase = phase;
    document.querySelectorAll('.phase').forEach(el => {
        const phaseName = el.getAttribute('data-phase');
        el.classList.remove('active', 'complete');

        const phases = ['discovery', 'analysis', 'testing', 'reporting'];
        const currentIndex = phases.indexOf(phase);
        const phaseIndex = phases.indexOf(phaseName);

        if (phaseIndex < currentIndex) {
            el.classList.add('complete');
        } else if (phaseIndex === currentIndex) {
            el.classList.add('active');
        }
    });
}

function setStatus(text, state = 'online') {
    statusText.textContent = text;
    const dot = statusIndicator.querySelector('.status-dot');

    // Remove scanning class by default
    statusIndicator.classList.remove('scanning');
    progressFill.classList.remove('scanning');

    if (state === 'scanning') {
        dot.style.background = '#f59e0b';
        dot.style.boxShadow = '0 0 10px #f59e0b';
        statusText.style.color = '#f59e0b';
        statusIndicator.classList.add('scanning');
        progressFill.classList.add('scanning');
    } else if (state === 'success') {
        dot.style.background = '#10b981';
        dot.style.boxShadow = '0 0 10px #10b981';
        statusText.style.color = '#10b981';
    } else {
        dot.style.background = '#10b981';
        dot.style.boxShadow = '0 0 10px #10b981';
        statusText.style.color = '#10b981';
    }
}

function resetState() {
    stats = { endpoints: 0, tests: 0, verified: 0, rejected: 0 };
    progress = 0;
    endpointsCount.textContent = '0';
    testsCount.textContent = '0';
    verifiedCount.textContent = '0';
    rejectedCount.textContent = '0';
    updateProgress(0, 'Awaiting target acquisition...');
    setPhase('discovery');
    findingsList.innerHTML = `
        <div class="finding-empty">
            <div class="empty-icon glow-icon">✓</div>
            <span>Awaiting target acquisition...</span>
        </div>`;
}

function normalizeTitle(title) {
    // Ensure title is in format: "#{Number} {Type} in {Endpoint}"
    // Input might be: "Cross-Site #1 in http://..." or "Stored XSS #1 in http://..."
    // Goal: "#1 Cross-Site in http://..."

    // Regex to match "Type #N in Endpoint"
    const match = title.match(/^(.+?) #(\d+) in (.+)$/);
    if (match) {
        // match[1] = "Cross-Site"
        // match[2] = "1"
        // match[3] = "http://..."
        return `#${match[2]} ${match[1]} in ${match[3]}`;
    }

    // Also handle "Type #N at Endpoint" just in case
    const matchAt = title.match(/^(.+?) #(\d+) at (.+)$/);
    if (matchAt) {
        return `#${matchAt[2]} ${matchAt[1]} in ${matchAt[3]}`;
    }

    return title;
}

function addFinding(message, initialStatus = 'detected') {
    // Remove empty state
    const emptyState = findingsList.querySelector('.finding-empty');
    if (emptyState) emptyState.remove();

    // Parse finding details
    let title = message;
    let rank = "?";

    // Handle multiple log formats from backend:
    // "VULNERABILITY CONFIRMED #N: category at endpoint"
    // "FILE UPLOAD XSS #N: type"
    // "STORED XSS CONFIRMED #N: type at endpoint"
    const confirmedMatch = message.match(/CONFIRMED #(\d+):\s*(.+)/);
    const fileUploadMatch = message.match(/FILE UPLOAD XSS #(\d+):\s*(.+)/);
    const storedXssMatch = message.match(/STORED XSS CONFIRMED #(\d+):\s*(.+)/);
    const genericMatch = message.match(/XSS #(\d+):\s*(.+)/);

    const match = confirmedMatch || fileUploadMatch || storedXssMatch || genericMatch;
    if (match) {
        rank = match[1];
        const content = match[2].trim();

        let type = content;
        let endpoint = "";

        if (content.includes(' at ')) {
            type = content.split(' at ')[0].trim();
            endpoint = content.split(' at ')[1].trim();
            title = `#${rank} ${type} in ${endpoint}`;
        } else {
            title = `#${rank} ${content}`;
        }
    } else if (message.includes('Confirmed:')) {
        title = message.split('Confirmed:')[1].trim();
    }

    // Normalize to be safe
    const id = 'finding-' + title.replace(/[^a-zA-Z0-9]/g, '-');
    if (document.getElementById(id)) {
        // If it exists, update its status if needed
        if (initialStatus !== 'detected') {
            updateFindingStatus(title, initialStatus);
        }
        return;
    }

    let category = 'Security Vulnerability';
    let severity = 'critical';

    if (title.toLowerCase().includes('cross-site') || title.toLowerCase().includes('xss')) {
        category = 'Cross-Site Scripting (XSS)';
        severity = 'critical';
    } else if (title.toLowerCase().includes('sql') || title.toLowerCase().includes('injection')) {
        category = 'SQL Injection';
        severity = 'critical';
    } else if (title.toLowerCase().includes('auth')) {
        category = 'Authentication Bypass';
        severity = 'high';
    }

    const finding = document.createElement('div');
    finding.id = id;
    finding.className = `finding-item ${severity}`;

    const statusLabel = initialStatus === 'detected' ? 'DETECTED' :
        initialStatus === 'queued' ? 'VERIFYING...' :
            initialStatus.toUpperCase();
    const statusColor = initialStatus === 'detected' ? '#f59e0b' :
        initialStatus === 'queued' ? '#f59e0b' : '#6b7280';

    finding.innerHTML = `
        <div class="finding-icon">⚠️</div>
        <div class="finding-info">
            <div class="finding-title">${escapeHtml(title)}</div>
            <div class="finding-category" style="color: ${statusColor}">${statusLabel}</div>
        </div>
        <div class="finding-confidence">100%</div>
    `;
    findingsList.appendChild(finding);

    if (initialStatus !== 'detected') {
        updateFindingStatus(title, initialStatus);
    }

    progressFill.classList.add('scanning');
}

function updateFindingStatus(title, status) {
    // Sanitize title for ID usage (simple hash/slug)
    const id = 'finding-' + title.replace(/[^a-zA-Z0-9]/g, '-');

    let findingEl = document.getElementById(id);

    // Fuzzy fallback: if exact ID match fails, search by finding number + category
    if (!findingEl) {
        const numMatch = title.match(/#(\d+)/);
        if (numMatch) {
            const findingNum = numMatch[1];
            // Search all finding items for one with matching number
            const allFindings = document.querySelectorAll('.finding-item');
            for (const el of allFindings) {
                const elTitle = el.querySelector('.finding-title')?.textContent || '';
                if (elTitle.includes(`#${findingNum}`)) {
                    findingEl = el;
                    console.log(`[UI] Fuzzy matched finding #${findingNum}: "${elTitle}" for status "${status}"`);
                    break;
                }
            }
        }
    }

    if (!findingEl) {
        // Create new if not exists
        addFinding(title, status);
        findingEl = document.getElementById(id);
        if (!findingEl) return;
    }

    // Prevent reverting a resolved finding back to VERIFYING (e.g. if self-healing re-discovers it)
    if (status === 'queued' && (findingEl.classList.contains('verified') || findingEl.classList.contains('rejected'))) {
        console.log(`[UI] Ignoring 'queued' status update for finding because it is already resolved.`);
        return;
    }

    // Update visuals
    const icon = findingEl.querySelector('.finding-icon');
    const badge = findingEl.querySelector('.finding-category');

    findingEl.classList.remove('queued', 'verified', 'rejected', 'critical', 'high');

    if (status === 'verified') {
        findingEl.classList.add('verified');
        findingEl.style.borderColor = '#10b981';
        findingEl.style.background = 'rgba(16, 185, 129, 0.1)';
        icon.textContent = '✅';
        icon.style.background = '#10b981';
        badge.textContent = 'VERIFIED';
        badge.style.color = '#10b981';
    } else if (status === 'rejected') {
        findingEl.classList.add('rejected');
        findingEl.style.borderColor = '#6b7280';
        findingEl.style.background = 'rgba(107, 114, 128, 0.1)';
        icon.textContent = '❌';
        icon.style.background = '#6b7280';
        badge.textContent = 'REJECTED';
        badge.style.color = '#6b7280';
    } else if (status === 'queued') {
        findingEl.classList.add('queued');
        icon.textContent = '⏳';
        icon.style.background = '#f59e0b';
        badge.textContent = 'VERIFYING...';
        badge.style.color = '#f59e0b';
    }
}

function updateProgressFromBackend(percent, completed, total, endpoint, category) {
    // Update progress bar with accurate data from backend
    progressFill.style.width = `${percent}%`;
    progressPercent.textContent = `${percent}%`;

    // Show what's being tested
    const shortEndpoint = endpoint.split('/').slice(-2).join('/') || endpoint;
    if (total > 0 && percent < 100) {
        progressLabel.textContent = `Testing ${category} on ${shortEndpoint} (${completed}/${total})`;
        progressFill.classList.add('scanning');
    } else if (percent >= 100) {
        progressLabel.textContent = 'Scan complete!';
        progressFill.classList.remove('scanning');
    }

    // Update phase based on progress
    if (percent < 10) {
        setPhase('discovery');
    } else if (percent < 90) {
        setPhase('testing');
    } else if (percent < 100) {
        setPhase('reporting');
    }
}

function parseLogMessage(message) {
    // Extract endpoints discovered
    const endpointMatch = message.match(/(?:Discovered|Testing) (\d+) (?:dynamic )?endpoints/i);
    if (endpointMatch) {
        stats.endpoints = parseInt(endpointMatch[1]);
        endpointsCount.textContent = stats.endpoints;
    }

    // Findings status updates
    if (message.includes('Finding queued for verification:')) {
        let rawTitle = message.split('verification:')[1].trim();
        const title = normalizeTitle(rawTitle);
        updateFindingStatus(title, 'queued');
    } else if (message.includes('VERIFIED:') && !message.includes('Mission Complete') && !message.includes('Thread finished')) {
        // Match both 'Verified:' and 'VERIFIED:'
        const match = message.match(/(Verified:|VERIFIED:)(.+)/);
        if (match) {
            let rawTitle = match[2].split('—')[0].trim();
            const title = normalizeTitle(rawTitle);

            // Don't increment stats here — FINDING_STATUS handler is the single source of truth
            // to avoid double-counting (both VERIFIED: and FINDING_STATUS: fire for each finding)
            updateFindingStatus(title, 'verified');
        }
    } else if (message.match(/REJECTED:/)) {
        let rawTitle = message.split('REJECTED:')[1].split('—')[0].trim();
        const title = normalizeTitle(rawTitle);
        // Don't increment stats here — FINDING_STATUS handler is the single source of truth
        updateFindingStatus(title, 'rejected');
    } else if (message.includes('VULNERABILITY CONFIRMED') ||
        message.includes('FILE UPLOAD XSS #') ||
        message.includes('STORED XSS CONFIRMED') ||
        message.includes('DOM XSS') ||
        message.match(/XSS #\d+:/) ||
        message.match(/Vulnerability #\d+ confirmed/) ||
        message.match(/CONFIRMED #{1}\d+:/)) {
        // Initial detection — catch all finding types from backend
        addFinding(message, 'detected');
    }

    // Mission complete
    if (message.toLowerCase().includes('mission complete')) {
        progressFill.classList.remove('scanning');
        progressLabel.textContent = 'Scan complete!';
        progressFill.style.width = '100%';
        progressPercent.textContent = '100%';
        setStatus('Complete', 'success');
        // Resolve any remaining VERIFYING findings
        resolveStaleFindings();
    }
}

function resolveStaleFindings() {
    const staleFindings = document.querySelectorAll('.finding-item.queued');
    if (staleFindings.length === 0) return;

    // Collect all log text to check for VERIFIED/REJECTED messages
    const logText = logConsole.innerText || '';

    staleFindings.forEach(el => {
        const titleEl = el.querySelector('.finding-title');
        const title = titleEl ? titleEl.textContent : '';
        const numMatch = title.match(/#(\d+)/);
        const findingNum = numMatch ? numMatch[1] : '';

        // Check if the log already has a VERIFIED or REJECTED entry for this finding
        const icon = el.querySelector('.finding-icon');
        const badge = el.querySelector('.finding-category');
        el.classList.remove('queued');

        const verifiedPattern = new RegExp(`VERIFIED:.*#${findingNum}\\b|VERIFIED:.*${findingNum}\\b`, 'i');
        const rejectedPattern = new RegExp(`REJECTED:.*#${findingNum}\\b|REJECTED:.*${findingNum}\\b`, 'i');

        if (findingNum && verifiedPattern.test(logText)) {
            // Was verified — apply green status
            el.classList.add('verified');
            el.style.borderColor = '#10b981';
            el.style.background = 'rgba(16, 185, 129, 0.1)';
            if (icon) { icon.textContent = '✅'; icon.style.background = '#10b981'; }
            if (badge) { badge.textContent = 'VERIFIED'; badge.style.color = '#10b981'; }
            console.log(`[UI] Resolved #${findingNum} as VERIFIED (from log)`);
        } else if (findingNum && rejectedPattern.test(logText)) {
            // Was rejected — apply grey status
            el.classList.add('rejected');
            el.style.borderColor = '#6b7280';
            el.style.background = 'rgba(107, 114, 128, 0.1)';
            if (icon) { icon.textContent = '❌'; icon.style.background = '#6b7280'; }
            if (badge) { badge.textContent = 'REJECTED'; badge.style.color = '#6b7280'; }
            console.log(`[UI] Resolved #${findingNum} as REJECTED (from log)`);
        } else {
            // Truly unverified — scan was cancelled before verification
            el.style.borderColor = '#f59e0b';
            el.style.background = 'rgba(245, 158, 11, 0.08)';
            if (icon) { icon.textContent = '⚠️'; icon.style.background = '#f59e0b'; }
            if (badge) { badge.textContent = 'UNVERIFIED'; badge.style.color = '#f59e0b'; }
            console.log(`[UI] Resolved #${findingNum} as UNVERIFIED (no verdict in log)`);
        }
    });
    console.log(`[UI] Resolved ${staleFindings.length} stale findings`);
}

function appendLog(message, type = null) {
    // Handle structured PROGRESS: events (don't display in log)
    if (message.includes('PROGRESS:')) {
        const progressMatch = message.match(/PROGRESS:(\d+)\|(\d+)\|(\d+)\|(.*?)\|(.*)$/);
        if (progressMatch) {
            const [, percent, completed, total, endpoint, category] = progressMatch;
            stats.tests = parseInt(completed);
            testsCount.textContent = stats.tests;
            updateProgressFromBackend(parseInt(percent), parseInt(completed), parseInt(total), endpoint, category);
        }
        return; // Don't add to log console
    }

    // Handle structured FINDING_STATUS: events — reliable status updates
    if (message.includes('FINDING_STATUS:')) {
        const statusMatch = message.match(/FINDING_STATUS:(\d+)\|(verified|rejected)\|(.+)/);
        if (statusMatch) {
            const findingNum = statusMatch[1];
            const status = statusMatch[2];
            const findingTitle = statusMatch[3].trim();
            console.log(`[UI] FINDING_STATUS received: #${findingNum} → ${status}`);

            // Dedup: only count each finding number once in KPIs
            const dedupKey = `${findingNum}-${status}`;
            const isNewCount = !_countedFindings.has(dedupKey);
            if (isNewCount) {
                _countedFindings.add(dedupKey);
                // Always increment counter regardless of card existence
                if (status === 'verified') {
                    stats.verified++;
                    verifiedCount.textContent = stats.verified;
                } else {
                    stats.rejected++;
                    rejectedCount.textContent = stats.rejected;
                }
            }

            // Find or create the finding card
            let foundEl = null;
            const allFindings = document.querySelectorAll('.finding-item');
            for (const el of allFindings) {
                const elTitle = el.querySelector('.finding-title')?.textContent || '';
                if (elTitle.includes(`#${findingNum}`)) {
                    foundEl = el;
                    break;
                }
            }

            // If no card exists yet, create one from the status message
            if (!foundEl) {
                addFinding(`VULNERABILITY CONFIRMED #${findingNum}: ${findingTitle}`, 'detected');
                // Re-find the newly created card
                const newFindings = document.querySelectorAll('.finding-item');
                for (const el of newFindings) {
                    const elTitle = el.querySelector('.finding-title')?.textContent || '';
                    if (elTitle.includes(`#${findingNum}`)) {
                        foundEl = el;
                        break;
                    }
                }
            }

            // Update the card visuals
            if (foundEl) {
                const icon = foundEl.querySelector('.finding-icon');
                const badge = foundEl.querySelector('.finding-category');
                foundEl.classList.remove('queued', 'verified', 'rejected', 'critical', 'high');

                if (status === 'verified') {
                    foundEl.classList.add('verified');
                    foundEl.style.borderColor = '#10b981';
                    foundEl.style.background = 'rgba(16, 185, 129, 0.1)';
                    if (icon) { icon.textContent = '✅'; icon.style.background = '#10b981'; }
                    if (badge) { badge.textContent = 'VERIFIED'; badge.style.color = '#10b981'; }
                } else {
                    foundEl.classList.add('rejected');
                    foundEl.style.borderColor = '#6b7280';
                    foundEl.style.background = 'rgba(107, 114, 128, 0.1)';
                    if (icon) { icon.textContent = '❌'; icon.style.background = '#6b7280'; }
                    if (badge) { badge.textContent = 'REJECTED'; badge.style.color = '#6b7280'; }
                }
                console.log(`[UI] Updated finding #${findingNum} to ${status}`);
            }
        }
        return; // Don't add structured message to log console
    }

    const logType = type || getLogType(message);
    const time = new Date().toLocaleTimeString('en-US', { hour12: false });

    const entry = document.createElement('div');
    entry.className = `log-entry log-${logType}`;
    entry.innerHTML = `
        <span class="log-time">${time}</span>
        <span class="log-badge">${getBadgeText(logType)}</span>
        <span class="log-msg">${escapeHtml(message)}</span>
    `;

    logConsole.appendChild(entry);
    logConsole.scrollTop = logConsole.scrollHeight;

    // Parse message for stats updates
    parseLogMessage(message);
}

// ===== Event Handlers =====
function startLogStream() {
    if (eventSource) eventSource.close();

    eventSource = new EventSource('/api/stream');

    eventSource.onmessage = function (event) {
        if (event.data.startsWith(':')) return; // Skip keep-alive
        appendLog(event.data);
    };

    eventSource.onerror = function () {
        console.log("Stream connection lost.");
        // Server was killed (Ctrl+C) — resolve stale findings after delay
        setTimeout(resolveStaleFindings, 3000);
    };
}

launchBtn.addEventListener('click', async () => {
    const target = targetInput.value.trim();
    const checkboxes = document.querySelectorAll('.module-pill input[type="checkbox"]:checked, .module-card input[type="checkbox"]:checked');
    const modules = Array.from(checkboxes).map(cb => cb.value);

    // Parse Manual Headers (Session A)
    const manualHeadersText = document.getElementById('manual-headers').value.trim();
    const headersObj = {};
    if (manualHeadersText) {
        manualHeadersText.split('\n').forEach(line => {
            const separatorIdx = line.indexOf(':');
            if (separatorIdx > 0) {
                const key = line.slice(0, separatorIdx).trim();
                const val = line.slice(separatorIdx + 1).trim();
                if (key && val) {
                    headersObj[key] = val;
                }
            }
        });
    }

    // Parse Manual Headers (Session B — for IDOR testing)
    const headersBText = document.getElementById('manual-headers-b').value.trim();
    const headersBObj = {};
    if (headersBText) {
        headersBText.split('\n').forEach(line => {
            const separatorIdx = line.indexOf(':');
            if (separatorIdx > 0) {
                const key = line.slice(0, separatorIdx).trim();
                const val = line.slice(separatorIdx + 1).trim();
                if (key && val) {
                    headersBObj[key] = val;
                }
            }
        });
    }

    if (!target) {
        alert("Please enter a target URL.");
        return;
    }

    if (modules.length === 0) {
        alert("Select at least one vulnerability module.");
        return;
    }

    // Reset and start
    resetState();
    logConsole.innerHTML = '';

    launchBtn.disabled = true;
    abortBtn.disabled = false;
    setStatus('Scanning', 'scanning');
    updateProgress(5, 'Initializing scan...');

    appendLog(`Initializing scan for ${target}`, 'info');
    appendLog(`Active modules: ${modules.join(', ')}`, 'info');
    if (Object.keys(headersObj).length > 0) {
        appendLog(`Loaded ${Object.keys(headersObj).length} manual auth headers (Session A)`, 'success');
    }
    if (Object.keys(headersBObj).length > 0) {
        appendLog(`Loaded ${Object.keys(headersBObj).length} IDOR headers (Session B)`, 'success');
    }

    try {
        const res = await fetch('/api/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, modules, headers: headersObj, headers_b: headersBObj })
        });

        const data = await res.json();
        if (data.status === 'success') {
            appendLog('Swarm deployed successfully', 'success');
            updateProgress(10, 'Discovering endpoints...');
            startLogStream();
        } else {
            throw new Error(data.message);
        }
    } catch (e) {
        appendLog(`Deployment failed: ${e.message}`, 'error');
        launchBtn.disabled = false;
        abortBtn.disabled = true;
        setStatus('Error', 'error');
    }
});

abortBtn.addEventListener('click', async () => {
    try {
        const res = await fetch('/api/stop', { method: 'POST' });
        const data = await res.json();
        if (data.status === 'success') {
            appendLog('Mission aborted by user', 'error');
            if (eventSource) eventSource.close();
            launchBtn.disabled = false;
            abortBtn.disabled = true;
            setStatus('Aborted', 'error');
            updateProgress(progress, 'Scan aborted');
        }
    } catch (e) {
        console.error(e);
    }
});

clearLogsBtn.addEventListener('click', () => {
    logConsole.innerHTML = '';
    appendLog('Log console cleared', 'system');
});

// ===== SOURCE CODE SCANNER =====

// Tab switching
const tabDynamic = document.getElementById('tab-dynamic');
const tabSource = document.getElementById('tab-source');
const contentDynamic = document.getElementById('content-dynamic');
const contentSource = document.getElementById('content-source');

function switchTab(tab) {
    tabDynamic.classList.toggle('active', tab === 'dynamic');
    tabSource.classList.toggle('active', tab === 'source');
    contentDynamic.style.display = tab === 'dynamic' ? 'flex' : 'none';
    contentSource.style.display = tab === 'source' ? 'flex' : 'none';
}

tabDynamic.addEventListener('click', () => switchTab('dynamic'));
tabSource.addEventListener('click', () => switchTab('source'));

// Code scan elements
const codeScanBtn = document.getElementById('code-scan-btn');
const codeAbortBtn = document.getElementById('code-abort-btn');
const repoUrlInput = document.getElementById('repo-url');
const codeLogConsole = document.getElementById('code-log-console');
const codeFindingsList = document.getElementById('code-findings-list');
const clearCodeLogsBtn = document.getElementById('clear-code-logs');

// Code scan stats
const csFilesCount = document.getElementById('cs-files-count');
const csCriticalCount = document.getElementById('cs-critical-count');
const csHighCount = document.getElementById('cs-high-count');
const csMediumCount = document.getElementById('cs-medium-count');
const csProgressFill = document.getElementById('cs-progress-fill');
const csProgressLabel = document.getElementById('cs-progress-label');
const csProgressPercent = document.getElementById('cs-progress-percent');

let codeEventSource = null;
let codeStats = { critical: 0, high: 0, medium: 0, low: 0, files: 0 };

function resetCodeStats() {
    codeStats = { critical: 0, high: 0, medium: 0, low: 0, files: 0 };
    csFilesCount.textContent = '0';
    csCriticalCount.textContent = '0';
    csHighCount.textContent = '0';
    csMediumCount.textContent = '0';
    csProgressFill.style.width = '0%';
    csProgressLabel.textContent = 'Starting scan...';
    csProgressPercent.textContent = '0%';
    codeFindingsList.innerHTML = '';
    // Reset phases
    ['cs-phase-clone', 'cs-phase-discover', 'cs-phase-analyze', 'cs-phase-complete'].forEach(id => {
        const el = document.getElementById(id);
        el.classList.remove('active', 'complete');
    });
    document.getElementById('cs-phase-clone').classList.add('active');
}

function appendCodeLog(message, type = 'system') {
    const logType = type || 'system';
    const time = new Date().toLocaleTimeString('en-US', { hour12: false });
    const badges = {
        system: '<span class="log-badge badge-sys">SYS</span>',
        info: '<span class="log-badge badge-info">SCAN</span>',
        success: '<span class="log-badge badge-success">FOUND</span>',
        error: '<span class="log-badge badge-error">ERR</span>',
        warning: '<span class="log-badge badge-warning">WARN</span>'
    };
    const badge = badges[logType] || badges.system;
    const entry = document.createElement('div');
    entry.className = `log-entry log-${logType}`;
    entry.innerHTML = `<span class="log-time">[${time}]</span> ${badge} <span class="log-msg">${message}</span>`;
    codeLogConsole.appendChild(entry);
    codeLogConsole.scrollTop = codeLogConsole.scrollHeight;
}

function setCodePhase(phase) {
    const phases = ['clone', 'discover', 'analyze', 'complete'];
    const idx = phases.indexOf(phase);
    phases.forEach((p, i) => {
        const el = document.getElementById(`cs-phase-${p}`);
        el.classList.remove('active', 'complete');
        if (i < idx) el.classList.add('complete');
        else if (i === idx) el.classList.add('active');
    });
}

function addCodeFinding(finding) {
    // Remove empty state
    const empty = codeFindingsList.querySelector('.finding-empty');
    if (empty) empty.remove();

    const sev = (finding.severity || 'MEDIUM').toLowerCase();
    const card = document.createElement('div');
    card.className = `code-finding-card severity-${sev}`;
    card.innerHTML = `
        <div class="code-finding-header">
            <span class="code-finding-severity ${sev}">${finding.severity}</span>
            <span class="code-finding-type">${finding.type}</span>
            <span class="code-finding-file">${finding.file}:${finding.line}</span>
        </div>
        <div class="code-finding-desc">${finding.description}</div>
        ${finding.code_snippet ? `<div class="code-finding-snippet">${escapeHtml(finding.code_snippet)}</div>` : ''}
        ${finding.suggested_fix ? `<div class="code-finding-fix">💡 Fix: ${escapeHtml(finding.suggested_fix)}</div>` : ''}
        <span class="code-finding-expand">▶ Details</span>
    `;

    card.addEventListener('click', () => {
        card.classList.toggle('expanded');
        const expandText = card.querySelector('.code-finding-expand');
        expandText.textContent = card.classList.contains('expanded') ? '▼ Hide' : '▶ Details';
    });

    codeFindingsList.prepend(card);

    // Update severity stats
    const sevKey = sev === 'critical' ? 'critical' : sev === 'high' ? 'high' : sev === 'medium' ? 'medium' : 'low';
    codeStats[sevKey]++;
    csCriticalCount.textContent = codeStats.critical;
    csHighCount.textContent = codeStats.high;
    csMediumCount.textContent = codeStats.medium;
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function processCodeMessage(rawMessage) {
    // Strip timestamp prefix
    const message = rawMessage.replace(/^\[\d{2}:\d{2}:\d{2}\]\s*/, '');

    // Phase updates
    if (message.startsWith('CODE_SCAN_PHASE:')) {
        const phase = message.split(':')[1];
        setCodePhase(phase);
        const labels = { clone: 'Cloning repository...', discover: 'Discovering source files...', analyze: 'Analyzing with AI...', complete: 'Scan complete!' };
        csProgressLabel.textContent = labels[phase] || phase;
        return;
    }

    // Progress updates
    if (message.startsWith('CODE_SCAN_PROGRESS:')) {
        const parts = message.split(':')[1].split('|');
        const pct = parts[0];
        const done = parts[1];
        const total = parts[2];
        csProgressFill.style.width = pct + '%';
        csProgressPercent.textContent = pct + '%';
        csFilesCount.textContent = done;
        csProgressLabel.textContent = `Analyzing file ${done}/${total}...`;
        return;
    }

    // Total files
    if (message.startsWith('CODE_SCAN_TOTAL:')) {
        return; // handled by progress
    }

    // Findings
    if (message.startsWith('CODE_FINDING:')) {
        try {
            const finding = JSON.parse(message.substring('CODE_FINDING:'.length));
            addCodeFinding(finding);
        } catch (e) { /* ignore parse errors */ }
        return;
    }

    // Summary
    if (message.startsWith('CODE_SCAN_SUMMARY:')) {
        csProgressFill.style.width = '100%';
        csProgressPercent.textContent = '100%';
        csProgressLabel.textContent = 'Scan complete!';
        codeScanBtn.disabled = false;
        codeAbortBtn.disabled = true;
        return;
    }

    // Regular log messages
    let type = 'system';
    if (message.includes('✅')) type = 'success';
    else if (message.includes('❌') || message.includes('Error')) type = 'error';
    else if (message.includes('⚠️')) type = 'warning';
    else if (message.includes('🔍') || message.includes('[CodeScanner]')) type = 'info';

    appendCodeLog(message, type);
}

// Start code scan
codeScanBtn.addEventListener('click', async () => {
    const repoUrl = repoUrlInput.value.trim();
    if (!repoUrl) {
        appendCodeLog('Please enter a GitHub repository URL', 'error');
        return;
    }

    resetCodeStats();
    codeScanBtn.disabled = true;
    codeAbortBtn.disabled = false;
    appendCodeLog(`Starting source code scan: ${repoUrl}`, 'info');

    try {
        const res = await fetch('/api/code-scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ repo_url: repoUrl })
        });
        const data = await res.json();

        if (data.status !== 'success') {
            appendCodeLog(`Error: ${data.message}`, 'error');
            codeScanBtn.disabled = false;
            codeAbortBtn.disabled = true;
            return;
        }

        // Connect SSE
        if (codeEventSource) codeEventSource.close();
        codeEventSource = new EventSource('/api/code-stream');
        codeEventSource.onmessage = (e) => processCodeMessage(e.data);
        codeEventSource.onerror = () => {
            appendCodeLog('SSE connection lost', 'warning');
        };
    } catch (e) {
        appendCodeLog(`Error: ${e.message}`, 'error');
        codeScanBtn.disabled = false;
        codeAbortBtn.disabled = true;
    }
});

// Abort code scan
codeAbortBtn.addEventListener('click', async () => {
    try {
        const res = await fetch('/api/code-stop', { method: 'POST' });
        const data = await res.json();
        if (data.status === 'success') {
            appendCodeLog('Code scan aborted by user', 'error');
            if (codeEventSource) codeEventSource.close();
            codeScanBtn.disabled = false;
            codeAbortBtn.disabled = true;
        }
    } catch (e) {
        console.error(e);
    }
});

// Clear code logs
clearCodeLogsBtn.addEventListener('click', () => {
    codeLogConsole.innerHTML = '';
    appendCodeLog('Log console cleared', 'system');
});

// Initialize
setStatus('Operational', 'online');

// Module pill toggle
document.querySelectorAll('.module-pill input[type="checkbox"]').forEach(cb => {
    cb.addEventListener('change', () => {
        cb.closest('.module-pill').classList.toggle('active-pill', cb.checked);
    });
});
