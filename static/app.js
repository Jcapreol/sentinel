// ======================================================
// SENTINEL  app.js
// ======================================================

// ── Tier config — single source of truth (FR14, NFR16) ──
const TIER_CONFIG = {
    0: { label: "Benign",        color: "#6b7280" },
    1: { label: "Investigating", color: "#d97706" },
    2: { label: "Probable",      color: "#ea580c" },
    3: { label: "Confirmed",     color: "#dc2626" },
};

// Scenario descriptions pre-filled when user selects a demo
const SCENARIO_DESCRIPTIONS = {
    "tor-exit-node":            "Sustained outbound traffic to 185.220.101.45:443 from prod-db-01",
    "lsass-credential-dumping": "rundll32.exe accessed lsass.exe memory (PID 4812) via scheduled task",
    "urlhaus-malware-ip":       "HTTP POST to 91.92.109.44:8080 with 60-second beacon interval",
    "ssh-brute-force":          "47 failed SSH auth attempts on bastion-01 port 22 in 3 minutes",
    "google-benign":            "DNS query for google.com resolved to 142.250.185.46",
};

// ── Utilities ─────────────────────────────────────────────
function escapeHtml(str) {
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// ── Badge rendering ───────────────────────────────────────
function renderTierBadge(tier) {
    const cfg = TIER_CONFIG[tier] ?? TIER_CONFIG[1];
    return `<span class="tier-badge" style="background:${cfg.color}">● ${escapeHtml(cfg.label)}</span>`;
}

// ── Blind spot rendering ──────────────────────────────────
function renderBlindSpot(bs) {
    const nextStep = bs.next_step
        ? `<p class="blind-spot-next">Next step: ${escapeHtml(bs.next_step)}</p>`
        : "";
    return `<div class="blind-spot">
            <div class="blind-spot-source">Coverage gap — ${escapeHtml(bs.source)}</div>
            <p class="blind-spot-reason">${escapeHtml(bs.reason)}</p>
            ${nextStep}
        </div>`;
}

// ── MITRE tag extraction from citation findings ───────────
function extractMitreTags(citations) {
    const tags = new Set();
    const re = /T\d{4}(?:\.\d{3})?/g;
    for (const c of (citations || [])) {
        const matches = (c.finding || "").match(re) || [];
        matches.forEach(function(t) { tags.add(t); });
    }
    return Array.from(tags).sort();
}

// ── Full verdict panel rendering ──────────────────────────
function renderVerdict(result) {
    const tier = result.confidence_tier;
    const citations = result.citations || [];
    const blindSpots = result.blind_spots || [];
    const methodology = result.methodology || [];

    // Group citations by source (preserves insertion order)
    const citationsBySource = {};
    for (const c of citations) {
        const src = c.source;
        if (!citationsBySource[src]) citationsBySource[src] = [];
        citationsBySource[src].push(c.finding);
    }

    // Evidence chain blocks
    const agentBlocksHtml = Object.entries(citationsBySource).map(function(entry) {
        const src = entry[0];
        const findings = entry[1];
        return `<div class="agent-block">
                <div class="agent-name">${escapeHtml(src)}</div>
                ${findings.map(function(f) {
                    return `<p class="agent-finding">${escapeHtml(f)}</p>`;
                }).join("")}
            </div>`;
    }).join("");

    // Coverage gaps (blind spots)
    const blindSpotsHtml = blindSpots.length > 0
        ? `<div class="verdict-section">
                <h3>Coverage Gaps</h3>
                ${blindSpots.map(renderBlindSpot).join("")}
            </div>`
        : "";

    // MITRE ATT&CK tags extracted from citation text
    const mitreTags = extractMitreTags(citations);
    const mitreHtml = mitreTags.length > 0
        ? `<div class="verdict-section">
                <h3>MITRE ATT&amp;CK Techniques</h3>
                <div class="mitre-tags">
                    ${mitreTags.map(function(t) {
                        return `<span class="mitre-tag">${escapeHtml(t)}</span>`;
                    }).join("")}
                </div>
            </div>`
        : "";

    // Expandable methodology steps
    const methodHtml = methodology.length > 0
        ? `<div class="verdict-section">
                <h3>Agent Methodology</h3>
                <button class="method-toggle"
                    onclick="toggleMethodology()"
                    aria-expanded="false"
                    aria-controls="method-list">
                    Show steps &#9660;
                </button>
                <ol class="method-list" id="method-list" hidden>
                    ${methodology.map(function(m) {
                        const dotClass = m.status === "success"
                            ? "method-dot-success"
                            : "method-dot-error";
                        const errorSuffix = m.error
                            ? `: ${escapeHtml(m.error)}`
                            : "";
                        return `<li class="method-item">
                                <span class="${dotClass}">●</span>
                                <span class="method-detail">${escapeHtml(m.agent)} — ${escapeHtml(m.status)}${errorSuffix}</span>
                            </li>`;
                    }).join("")}
                </ol>
            </div>`
        : "";

    // Independence + timing meta
    const indText = result.source_independence_confirmed
        ? "✓ Sources are independent"
        : "⚠ Source independence not confirmed";
    const execTime = typeof result.execution_time_seconds === "number"
        ? result.execution_time_seconds.toFixed(2) + "s"
        : "N/A";

    return `<div class="verdict-header">
            <span class="verdict-label">Verdict</span>
            ${renderTierBadge(tier)}
        </div>
        <div class="verdict-meta">
            <span>${escapeHtml(indText)}</span>
            <span>Analysis time: ${escapeHtml(execTime)}</span>
        </div>
        <div class="verdict-section">
            <h3>Evidence Chain</h3>
            ${agentBlocksHtml || "<p>No findings recorded.</p>"}
        </div>
        ${blindSpotsHtml}
        ${mitreHtml}
        ${methodHtml}`;
}

// ── Methodology expand/collapse ───────────────────────────
function toggleMethodology() {
    const btn = document.querySelector(".method-toggle");
    const list = document.getElementById("method-list");
    if (!btn || !list) return;
    const expanded = btn.getAttribute("aria-expanded") === "true";
    btn.setAttribute("aria-expanded", String(!expanded));
    btn.innerHTML = expanded
        ? "Show steps &#9660;"
        : "Hide steps &#9650;";
    list.hidden = expanded;
}

// ── Loading state ─────────────────────────────────────────
let _analysisInProgress = false;

function setLoading(active) {
    _analysisInProgress = active;
    const btn = document.getElementById("submit-btn");
    const progressPanel = document.getElementById("progress-panel");
    btn.disabled = active;
    progressPanel.hidden = !active;
}

function updateProgress(step) {
    const label = document.getElementById("progress-label");
    if (label) label.textContent = step;
}

// ── Verdict and error display ─────────────────────────────
function showVerdict(html) {
    const panel = document.getElementById("verdict-panel");
    panel.innerHTML = html;
    panel.hidden = false;
    setLoading(false);
}

function showError(message) {
    showVerdict(
        `<div class="verdict-section">
            <h3>Analysis Error</h3>
            ${renderBlindSpot({ source: "sentinel-engine", reason: message, next_step: null })}
        </div>`
    );
}

// ── sessionStorage history ────────────────────────────────
function appendHistory(alertText, result) {
    try {
        const raw = sessionStorage.getItem("sentinel_history");
        const history = raw ? JSON.parse(raw) : [];
        history.push({
            id: Date.now(),
            timestamp: result.timestamp || new Date().toISOString(),
            indicator: (alertText || "").slice(0, 80) || "(demo)",
            confidence_tier: result.confidence_tier,
            execution_time: result.execution_time_seconds,
            full_result: result,
        });
        sessionStorage.setItem("sentinel_history", JSON.stringify(history));
    } catch (_) {
        // sessionStorage may be unavailable; silently skip
    }
}

// ── SSE chunk parser ──────────────────────────────────────
let _sseBuffer = "";

function processSSEChunk(text) {
    _sseBuffer += text;
    const events = [];
    let pos = 0;

    while (true) {
        const end = _sseBuffer.indexOf("\n\n", pos);
        if (end === -1) break;

        const block = _sseBuffer.slice(pos, end);
        pos = end + 2;

        for (const line of block.split("\n")) {
            if (line.startsWith("data: ")) {
                try {
                    events.push(JSON.parse(line.slice(6)));
                } catch (_) {
                    // discard malformed line
                }
            }
        }
    }

    _sseBuffer = _sseBuffer.slice(pos);
    return events;
}

// ── Submit handler ────────────────────────────────────────
async function handleSubmit() {
    if (_analysisInProgress) return;

    const alertText = document.getElementById("alert-text").value.trim();
    const scenarioSlug = document.getElementById("scenario-select").value || null;

    if (!alertText && !scenarioSlug) {
        document.getElementById("alert-text").focus();
        return;
    }

    // Reset SSE buffer and start loading state
    _sseBuffer = "";
    setLoading(true);
    updateProgress("Initializing analysis…");
    // Hide previous verdict while loading
    document.getElementById("verdict-panel").hidden = true;

    try {
        const response = await fetch("/analyze/stream", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                alert_text: alertText,
                scenario_slug: scenarioSlug,
            }),
        });

        if (!response.ok) {
            if (response.status === 404) {
                showError(
                    "Analysis endpoint not yet available — /analyze/stream has not been implemented. " +
                    "Start the full Sentinel web server to enable live analysis."
                );
            } else {
                showError(
                    `Server returned HTTP ${response.status} — analysis could not be completed.`
                );
            }
            return;
        }

        if (!response.body) {
            showError("Server response has no body — streaming is not supported.");
            return;
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let lastResult = null;

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            const events = processSSEChunk(decoder.decode(value, { stream: true }));

            for (const msg of events) {
                if (msg.type === "progress") {
                    updateProgress(msg.step);
                } else if (msg.type === "result") {
                    lastResult = msg.data;
                    showVerdict(renderVerdict(msg.data));
                    appendHistory(alertText, msg.data);
                } else if (msg.type === "error") {
                    showVerdict(
                        `<div class="verdict-section">
                            <h3>Coverage Gaps</h3>
                            ${renderBlindSpot(msg.blind_spot)}
                        </div>`
                    );
                }
            }
        }

        // If stream ended without a result event, leave whatever was shown
        if (!lastResult && document.getElementById("verdict-panel").hidden) {
            showError("Analysis completed but no result was returned.");
        }

    } catch (err) {
        showError(
            "Could not reach the analysis engine — verify the server is running."
        );
    } finally {
        setLoading(false);
    }
}

// ── Scenario dropdown ─────────────────────────────────────
function handleScenarioChange() {
    const slug = document.getElementById("scenario-select").value;
    if (slug) {
        document.getElementById("alert-text").value =
            SCENARIO_DESCRIPTIONS[slug] || "";
    }
}

// ── Init ──────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", function() {
    document.getElementById("submit-btn")
        .addEventListener("click", handleSubmit);

    document.getElementById("scenario-select")
        .addEventListener("change", handleScenarioChange);

    document.getElementById("alert-text")
        .addEventListener("keydown", function(e) {
            if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
                handleSubmit();
            }
        });
});
