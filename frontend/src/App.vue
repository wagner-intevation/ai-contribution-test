<!--
SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

SPDX-License-Identifier: Apache-2.0
-->

<template>
  <div id="app">

    <!-- ===== TOP NAV BAR ===== -->
    <!-- Minimal header: logo mark + tool name + live status badge -->
    <header class="site-header">
      <div class="header-inner">
        <!-- ASCII-style bracket logo for a "terminal" feel -->
        <span class="logo-mark">[&nbsp;CSAF&nbsp;]</span>
        <span class="header-title">Provider Online Check</span>
        <!-- System-health indicator: polls /api/health and shows a pulsing dot -->
        <span class="status-badge" :class="healthStatus.ok ? 'badge-ok' : 'badge-warn'">
          <span class="status-dot"></span>
          {{ healthStatus.label }}
        </span>
      </div>
    </header>

    <main class="main-content">

      <!-- ===== HERO / EXPLANATION SECTION ===== -->
      <!--
        This section explains what CSAF is and what the tool does.
        It replaces the terse "About" card at the bottom with a proper
        introduction that appears before the scan form.
      -->
      <section class="hero-section">
        <div class="hero-tag">// security tooling</div>
        <h1 class="hero-title">
          Validate your<br>
          <span class="accent">CSAF Provider</span>
        </h1>
        <p class="hero-lead">
          <strong>CSAF</strong> (Common Security Advisory Framework) is the
          international standard — defined in
          <a href="https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html" target="_blank" rel="noopener">OASIS CSAF 2.0</a> —
          for machine-readable security advisories. It enables automated
          vulnerability management across the entire software supply chain.
        </p>

        <!-- Three feature chips explain the three main use cases -->
        <div class="feature-chips">
          <!-- Chip 1: self-assessment during setup -->
          <div class="chip">
            <span class="chip-icon">⬡</span>
            <div>
              <strong>Self-assessment</strong>
              <p>Check your own provider during initial setup or after changes to catch misconfiguration early.</p>
            </div>
          </div>
          <!-- Chip 2: third-party monitoring -->
          <div class="chip">
            <span class="chip-icon">⬡</span>
            <div>
              <strong>Third-party monitoring</strong>
              <p>Spot-check external providers to detect issues that break automated advisory ingestion.</p>
            </div>
          </div>
          <!-- Chip 3: developer convenience wrapper -->
          <div class="chip">
            <span class="chip-icon">⬡</span>
            <div>
              <strong>Easy csaf_checker</strong>
              <p>Run the official BSI <code>csaf_checker</code> and validator without local installation — just enter a domain.</p>
            </div>
          </div>
        </div>
      </section>

      <!-- ===== SCAN FORM CARD ===== -->
      <section class="scan-section">
        <div class="scan-card">

          <!-- Card label (top-left corner accent) -->
          <div class="card-label">// scan target</div>

          <h2 class="scan-title">Enter a Domain</h2>
          <p class="scan-subtitle">
            Provide the root domain of the CSAF provider you want to validate.
            The checker will follow the
            <a href="https://www.csaf.io/rolledout.html" target="_blank" rel="noopener">CSAF discovery chain</a>
            automatically (DNS SDSS, well-known paths, ROLIE feeds).
          </p>

          <!-- Scan form — preventDefault keeps Vue in control of the submit -->
          <form @submit.prevent="startScan" class="scan-form" autocomplete="off">
            <div class="input-row">
              <!-- Domain input: accepts bare hostnames, no protocol needed -->
              <div class="input-wrapper">
                <span class="input-prefix">https://</span>
                <input
                  type="text"
                  id="domainInput"
                  class="domain-input"
                  v-model="domain"
                  placeholder="example.com"
                  :disabled="loading"
                  required
                  spellcheck="false"
                  autocorrect="off"
                  autocapitalize="none"
                >
              </div>

              <!-- Submit button shows a spinner while the scan is in flight -->
              <button type="submit" class="scan-btn" :disabled="loading">
                <span v-if="loading" class="btn-spinner" aria-hidden="true"></span>
                <span v-if="!loading" class="btn-icon">▶</span>
                {{ loading ? 'Scanning…' : 'Run Check' }}
              </button>
            </div>

            <!-- Inline hint explaining what happens after submit -->
            <p class="input-hint">
              Scanning may take up to a minute for large providers.
              The backend runs the official
              <a href="https://github.com/csaf-tools/csaf-checker" target="_blank" rel="noopener">csaf_checker</a>
              and validator tools against the live provider.
            </p>
          </form>

          <!-- ===== SCAN RESULTS ===== -->
          <!--
            Results are shown in the same card so the user doesn't need to
            scroll far. We distinguish three states:
              1. result.status === 'ERROR'  → backend ran but found a hard error
              2. result.status !== 'ERROR'  → scan completed successfully
              3. error (JS exception)       → network / HTTP error before response
          -->
          <transition name="fade">
            <div v-if="result || error" class="results-area">

              <!-- ── Hard error returned by the backend ── -->
              <div v-if="result && result.status === 'ERROR'" class="result-block result-error">
                <div class="result-header">
                  <span class="result-icon">✕</span>
                  <span class="result-status">Scan Error</span>
                  <span class="result-domain">{{ result.domain }}</span>
                </div>
                <p class="result-message">{{ result.error }}</p>
              </div>

              <!-- ── Successful scan ── -->
              <div v-if="result && result.status !== 'ERROR'" class="result-block result-success">
                <div class="result-header">
                  <span class="result-icon">✔</span>
                  <span class="result-status">Scan Complete</span>
                  <span class="result-domain">{{ result.domain }}</span>
                  <!-- Status badge mirrors the backend enum value -->
                  <span class="result-pill">{{ result.status }}</span>
                </div>

                <!--
                  Checker JSON results: pretty-printed in a <pre> block.
                  The backend returns a structured JSON object from csaf_checker
                  containing per-category pass/fail counts and messages.
                -->
                <div v-if="result.results_checker" class="result-json-wrapper">
                  <div class="result-section-label">Checker results (JSON)</div>
                  <pre class="result-json">{{ formatJson(result.results_checker) }}</pre>
                </div>
              </div>

              <!--
                Runtime log: an array of strings streamed from the csaf_checker
                process. Each entry is one line of stdout/stderr output.
                Displayed as a terminal-style log regardless of success/error.
              -->
              <div v-if="result && result.runtime_output && result.runtime_output.length" class="result-block result-log">
                <div class="result-section-label">
                  Runtime log
                  <!-- Entry count gives a quick sense of how much happened -->
                  <span class="log-count">{{ result.runtime_output.length }} lines</span>
                </div>
                <div class="log-scroll">
                  <!-- v-for key uses index; log lines have no stable identity -->
                  <div
                    v-for="(line, index) in result.runtime_output"
                    :key="index"
                    class="log-line"
                  >
                    <!-- Line number prefix mimics a real terminal -->
                    <span class="log-num">{{ String(index + 1).padStart(3, '0') }}</span>
                    <span class="log-text">{{ line }}</span>
                  </div>
                </div>
              </div>

              <!-- ── Network / JS exception (no backend response) ── -->
              <div v-if="error" class="result-block result-error">
                <div class="result-header">
                  <span class="result-icon">✕</span>
                  <span class="result-status">Request Failed</span>
                </div>
                <p class="result-message">{{ error }}</p>
                <p class="result-hint">
                  Check that the backend is running on port
                  <code>{{ backendPort }}</code> and is reachable.
                </p>
              </div>

            </div>
          </transition>

        </div><!-- /scan-card -->
      </section>

      <!-- ===== ABOUT / INFO GRID ===== -->
      <!--
        Three info boxes below the scan card give additional context
        without cluttering the primary workflow above.
      -->
      <section class="info-grid">

        <!-- Box 1: what the tool checks -->
        <div class="info-box">
          <div class="info-box-label">What gets checked</div>
          <ul class="info-list">
            <li>CSAF provider metadata (provider-metadata.json)</li>
            <li>ROLIE feed structure and references</li>
            <li>Individual advisory file format &amp; schema</li>
            <li>TLS configuration and HTTP headers</li>
            <li>Document signing / checksums (SHA-256, SHA-512)</li>
          </ul>
        </div>

        <!-- Box 2: resource/rate-limit notice (important for large providers) -->
        <div class="info-box">
          <div class="info-box-label">Resource &amp; rate limits</div>
          <p>
            Scans are queued across up to <strong>{{ healthStatus.totalSlots }}</strong> concurrent slots.
            Large providers with thousands of advisories may take several minutes.
            The tool throttles outbound requests to avoid overloading the target.
          </p>
          <p class="info-note">
            Run in a container with restricted network access when scanning
            untrusted providers to prevent data exfiltration risks.
          </p>
        </div>

        <!-- Box 3: links to project resources -->
        <div class="info-box">
          <div class="info-box-label">Project &amp; standards</div>
          <ul class="link-list">
            <li><a href="https://github.com/csaf-tools/provider-online-check" target="_blank" rel="noopener">Source code (GitHub)</a></li>
            <li><a :href="apiDocsUrl" target="_blank" rel="noopener">REST API documentation (Swagger)</a></li>
            <li><a href="https://www.csaf.io" target="_blank" rel="noopener">CSAF ecosystem overview</a></li>
            <li><a href="https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html" target="_blank" rel="noopener">OASIS CSAF 2.0 spec</a></li>
          </ul>
        </div>

      </section>

    </main>

    <!-- ===== FOOTER ===== -->
    <footer class="site-footer">
      <span>
        A project of the
        <a href="https://www.bsi.bund.de" target="_blank" rel="noopener">German Federal Office for Information Security (BSI)</a>
        &nbsp;·&nbsp;
        Engineering by <a href="https://intevation.de" target="_blank" rel="noopener">Intevation GmbH</a>
        &nbsp;·&nbsp;
        Apache-2.0
      </span>
      <!-- VITE_FOOTER_TEXT allows operators to inject custom HTML (e.g. hosted-by notice) -->
      <span v-if="footerText" v-html="footerText" class="footer-custom"></span>
    </footer>

  </div><!-- /#app -->
</template>

<script>
import axios from 'axios'

export default {
  name: 'App',

  data() {
    return {
      // The domain the user typed into the scan form
      domain: '',

      // Static session ID — the backend uses this to coalesce concurrent
      // requests from the same browser tab onto one slot
      session_id: '1',

      // True while the HTTP request to /api/scan/start is in flight
      loading: false,

      // Backend scan response (ScanResponse model), or null before first scan
      result: null,

      // JS-level error message (network failure, 4xx/5xx before JSON body)
      error: null,

      // Summary of /api/health response, shown in the header status badge
      healthStatus: {
        ok: false,
        label: 'Checking…',
        totalSlots: 10,   // fallback; replaced by live value from /api/health
      },
    }
  },

  computed: {
    // Dynamically build the backend base URL from the current browser location
    // so the app works behind a reverse proxy at any port without hardcoding
    backendUrl() {
      const protocol = window.location.protocol
      const hostname = window.location.hostname
      const port     = import.meta.env.VITE_BACKEND_PORT || 48090
      return `${protocol}//${hostname}:${port}`
    },

    // Convenience: the port number alone (used in the error hint message)
    backendPort() {
      return import.meta.env.VITE_BACKEND_PORT || 48090
    },

    // Full URL for the Swagger UI link in the info grid
    apiDocsUrl() {
      return `${this.backendUrl}/api/docs`
    },

    // Optional operator-supplied HTML footer (injected via VITE_FOOTER_TEXT env var)
    footerText() {
      return import.meta.env.VITE_FOOTER_TEXT || ''
    },
  },

  methods: {
    // ── startScan ──────────────────────────────────────────────────────────
    // Called when the user submits the scan form.
    // POSTs to /api/scan/start and stores the response for the template to render.
    async startScan() {
      // Reset previous results so stale data is never shown alongside new data
      this.loading = true
      this.result  = null
      this.error   = null

      try {
        const response = await axios.post(`${this.backendUrl}/api/scan/start`, {
          domain:     this.domain,
          session_id: this.session_id,
        })
        this.result = response.data
      } catch (err) {
        // Prefer the structured detail message from FastAPI's error body;
        // fall back to the raw JS error string as a last resort
        this.error = err.response?.data?.detail || err.message || 'An unexpected error occurred.'
      } finally {
        // Always re-enable the form, even if the request failed
        this.loading = false
      }
    },

    // ── fetchHealth ────────────────────────────────────────────────────────
    // Polls /api/health once on mount to populate the header status badge
    // and the slot count shown in the info grid.
    async fetchHealth() {
      try {
        const { data } = await axios.get(`${this.backendUrl}/api/health`)
        this.healthStatus = {
          ok:         data.status === 'healthy',
          label:      data.status === 'healthy' ? 'Backend online' : 'Degraded',
          totalSlots: data.total_slots ?? 10,
        }
      } catch {
        // Backend unreachable — show a warning in the header badge
        this.healthStatus = { ok: false, label: 'Backend offline', totalSlots: '?' }
      }
    },

    // ── formatJson ─────────────────────────────────────────────────────────
    // Pretty-prints the checker JSON result with 2-space indentation.
    // Returns the raw value as a string if it is already a primitive.
    formatJson(value) {
      if (typeof value === 'string') return value
      try {
        return JSON.stringify(value, null, 2)
      } catch {
        return String(value)
      }
    },
  },

  // Fetch health status as soon as the component is mounted in the DOM
  mounted() {
    this.fetchHealth()
  },
}
</script>

<style scoped>
/* ============================================================
   DESIGN TOKENS — change these to retheme the whole UI
   ============================================================ */
:root {
  --bg-base:        #0a0e17;   /* deep space background              */
  --bg-surface:     #0f1620;   /* card / panel surfaces              */
  --bg-elevated:    #141e2d;   /* hover states, nested panels        */
  --border:         #1e2e45;   /* subtle panel borders               */
  --border-bright:  #1e4976;   /* accent borders on focus / hover    */
  --accent:         #00d4ff;   /* primary cyan accent                */
  --accent-dim:     #007ea8;   /* muted version of accent            */
  --accent-glow:    rgba(0, 212, 255, 0.15);
  --green:          #00ff9d;   /* success / online indicators        */
  --green-glow:     rgba(0, 255, 157, 0.15);
  --red:            #ff3b5c;   /* error indicators                   */
  --text-primary:   #e2eaf5;   /* main body text                     */
  --text-secondary: #6b849e;   /* labels, hints                      */
  --text-code:      #a9d7ff;   /* monospace / code spans             */
  --font-sans:      'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
  --radius:         6px;
  --transition:     0.2s ease;
}

/* ============================================================
   GLOBAL RESETS — scoped to #app
   ============================================================ */
#app {
  min-height: 100vh;
  background-color: var(--bg-base);
  color: var(--text-primary);
  font-family: var(--font-sans);
  font-size: 14px;
  line-height: 1.6;
  /* Subtle hex-grid background via repeating-linear-gradient */
  background-image:
    repeating-linear-gradient(
      60deg,
      transparent,
      transparent 40px,
      rgba(0, 212, 255, 0.02) 40px,
      rgba(0, 212, 255, 0.02) 41px
    ),
    repeating-linear-gradient(
      -60deg,
      transparent,
      transparent 40px,
      rgba(0, 212, 255, 0.02) 40px,
      rgba(0, 212, 255, 0.02) 41px
    );
}

a {
  color: var(--accent);
  text-decoration: none;
}
a:hover {
  text-decoration: underline;
}

code {
  color: var(--text-code);
  background: rgba(0, 212, 255, 0.08);
  padding: 1px 5px;
  border-radius: 3px;
  font-size: 0.9em;
}

/* ============================================================
   HEADER
   ============================================================ */
.site-header {
  position: sticky;
  top: 0;
  z-index: 100;
  background: rgba(10, 14, 23, 0.9);
  /* Frosted-glass blur (progressively enhanced) */
  backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--border);
}

.header-inner {
  max-width: 900px;
  margin: 0 auto;
  padding: 0 24px;
  height: 52px;
  display: flex;
  align-items: center;
  gap: 16px;
}

/* ASCII bracket logo */
.logo-mark {
  font-size: 13px;
  font-weight: 700;
  color: var(--accent);
  letter-spacing: 2px;
  border: 1px solid var(--border-bright);
  padding: 2px 8px;
  border-radius: var(--radius);
}

.header-title {
  font-size: 13px;
  color: var(--text-secondary);
  letter-spacing: 1px;
  flex: 1;
}

/* ── Status badge ── */
.status-badge {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 11px;
  padding: 3px 10px;
  border-radius: 20px;
  border: 1px solid;
}

.badge-ok {
  color: var(--green);
  border-color: rgba(0, 255, 157, 0.3);
  background: var(--green-glow);
}

.badge-warn {
  color: var(--red);
  border-color: rgba(255, 59, 92, 0.3);
  background: rgba(255, 59, 92, 0.08);
}

/* Pulsing dot inside the badge */
.status-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: currentColor;
  animation: pulse 2s ease-in-out infinite;
}

@keyframes pulse {
  0%, 100% { opacity: 1;   transform: scale(1);    }
  50%       { opacity: 0.4; transform: scale(0.75); }
}

/* ============================================================
   MAIN CONTENT WRAPPER
   ============================================================ */
.main-content {
  max-width: 900px;
  margin: 0 auto;
  padding: 48px 24px 80px;
}

/* ============================================================
   HERO / EXPLANATION SECTION
   ============================================================ */
.hero-section {
  margin-bottom: 56px;
}

/* Small "// tag" above the headline, like a code comment */
.hero-tag {
  font-size: 11px;
  color: var(--accent-dim);
  letter-spacing: 2px;
  text-transform: uppercase;
  margin-bottom: 12px;
}

.hero-title {
  font-size: clamp(28px, 5vw, 44px);
  font-weight: 700;
  line-height: 1.15;
  margin: 0 0 20px;
  color: var(--text-primary);
}

/* Highlighted word in the hero title */
.accent {
  color: var(--accent);
  /* Subtle glow so it reads as "energized" */
  text-shadow: 0 0 20px rgba(0, 212, 255, 0.4);
}

.hero-lead {
  max-width: 620px;
  color: var(--text-secondary);
  font-size: 14px;
  margin-bottom: 32px;
}

/* ── Feature chips ── */
.feature-chips {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 16px;
}

.chip {
  display: flex;
  gap: 14px;
  padding: 16px;
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  transition: border-color var(--transition), background var(--transition);
}

.chip:hover {
  border-color: var(--border-bright);
  background: var(--bg-elevated);
}

/* Hexagon icon (rendered as text) */
.chip-icon {
  color: var(--accent);
  font-size: 20px;
  flex-shrink: 0;
  margin-top: 2px;
}

.chip strong {
  display: block;
  font-size: 13px;
  color: var(--text-primary);
  margin-bottom: 4px;
}

.chip p {
  margin: 0;
  font-size: 12px;
  color: var(--text-secondary);
}

/* ============================================================
   SCAN CARD
   ============================================================ */
.scan-section {
  margin-bottom: 48px;
}

.scan-card {
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 32px;
  position: relative;
  /* Top-left corner accent line */
  box-shadow:
    inset 0 0 0 0 transparent,
    0 0 0 0 transparent;
}

/* The "// scan target" label pinned to the top-left of the card */
.card-label {
  position: absolute;
  top: -1px;
  left: 20px;
  font-size: 10px;
  color: var(--accent-dim);
  letter-spacing: 2px;
  text-transform: uppercase;
  background: var(--bg-surface);
  padding: 0 8px;
  transform: translateY(-50%);
}

.scan-title {
  font-size: 20px;
  font-weight: 600;
  margin: 0 0 8px;
  color: var(--text-primary);
}

.scan-subtitle {
  font-size: 13px;
  color: var(--text-secondary);
  margin: 0 0 24px;
  max-width: 580px;
}

/* ── Input row (input + button side by side) ── */
.scan-form {
  margin-bottom: 0;
}

.input-row {
  display: flex;
  gap: 12px;
  align-items: stretch;
  flex-wrap: wrap;
}

/* Wrapper adds the "https://" prefix label inside the input field */
.input-wrapper {
  flex: 1;
  display: flex;
  align-items: center;
  background: var(--bg-base);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  min-width: 200px;
  transition: border-color var(--transition), box-shadow var(--transition);
}

.input-wrapper:focus-within {
  border-color: var(--accent);
  box-shadow: 0 0 0 2px var(--accent-glow);
}

.input-prefix {
  padding: 0 10px 0 14px;
  color: var(--text-secondary);
  font-size: 13px;
  white-space: nowrap;
  user-select: none;   /* prefix is decorative, not selectable */
}

.domain-input {
  flex: 1;
  background: transparent;
  border: none;
  outline: none;
  color: var(--text-primary);
  font-family: var(--font-sans);
  font-size: 14px;
  padding: 12px 14px 12px 0;
}

.domain-input::placeholder {
  color: var(--text-secondary);
  opacity: 0.5;
}

.domain-input:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

/* ── Run Check button ── */
.scan-btn {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  background: var(--accent);
  color: #000;
  font-family: var(--font-sans);
  font-size: 13px;
  font-weight: 700;
  letter-spacing: 1px;
  border: none;
  border-radius: var(--radius);
  cursor: pointer;
  white-space: nowrap;
  transition: background var(--transition), box-shadow var(--transition);
}

.scan-btn:hover:not(:disabled) {
  background: #33ddff;
  box-shadow: 0 0 16px var(--accent-glow);
}

.scan-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

/* Spinner ring that appears while loading */
.btn-spinner {
  width: 14px;
  height: 14px;
  border: 2px solid rgba(0, 0, 0, 0.3);
  border-top-color: #000;
  border-radius: 50%;
  display: inline-block;
  animation: spin 0.7s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.btn-icon {
  font-size: 11px;
}

.input-hint {
  margin: 10px 0 0;
  font-size: 11px;
  color: var(--text-secondary);
  opacity: 0.7;
}

/* ============================================================
   RESULTS AREA
   ============================================================ */
.results-area {
  margin-top: 28px;
  display: flex;
  flex-direction: column;
  gap: 16px;
}

/* Base panel shared by all result blocks */
.result-block {
  border-radius: var(--radius);
  overflow: hidden;
  border: 1px solid;
}

.result-success {
  border-color: rgba(0, 255, 157, 0.25);
  background: rgba(0, 255, 157, 0.04);
}

.result-error {
  border-color: rgba(255, 59, 92, 0.25);
  background: rgba(255, 59, 92, 0.04);
}

/* Log block uses a neutral dark surface — not success or error */
.result-log {
  border-color: var(--border);
  background: var(--bg-base);
}

/* Horizontal bar at the top of each result block */
.result-header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 16px;
  border-bottom: 1px solid inherit;
  font-size: 13px;
}

.result-success .result-header { border-bottom-color: rgba(0, 255, 157, 0.15); }
.result-error   .result-header { border-bottom-color: rgba(255, 59, 92, 0.15); }

.result-icon {
  font-size: 12px;
}

.result-success .result-icon { color: var(--green); }
.result-error   .result-icon { color: var(--red);   }

.result-status {
  font-weight: 700;
  font-size: 12px;
  letter-spacing: 1px;
}

.result-success .result-status { color: var(--green); }
.result-error   .result-status { color: var(--red);   }

.result-domain {
  color: var(--text-secondary);
  font-size: 12px;
  margin-left: auto;
}

/* Small pill showing the raw backend status enum value */
.result-pill {
  font-size: 10px;
  padding: 2px 8px;
  border-radius: 20px;
  background: rgba(0, 212, 255, 0.1);
  color: var(--accent);
  border: 1px solid var(--border-bright);
  letter-spacing: 1px;
}

.result-message {
  padding: 12px 16px;
  margin: 0;
  font-size: 13px;
  color: var(--text-secondary);
}

.result-hint {
  padding: 0 16px 12px;
  margin: 0;
  font-size: 12px;
  color: var(--text-secondary);
  opacity: 0.7;
}

/* Section label inside a result block (e.g. "Checker results (JSON)") */
.result-section-label {
  padding: 10px 16px;
  font-size: 10px;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--text-secondary);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 8px;
}

/* Pretty-printed JSON block */
.result-json-wrapper {
  /* No extra padding here; the label handles top spacing */
}

.result-json {
  margin: 0;
  padding: 16px;
  font-family: var(--font-sans);
  font-size: 12px;
  color: var(--text-code);
  background: transparent;
  overflow-x: auto;
  white-space: pre;
  line-height: 1.5;
}

/* ── Runtime log ── */
.log-count {
  margin-left: auto;
  font-size: 10px;
  color: var(--text-secondary);
  font-variant-numeric: tabular-nums;
}

/* Scrollable container for log lines; max-height prevents it from taking over the page */
.log-scroll {
  max-height: 280px;
  overflow-y: auto;
  padding: 8px 0;
  /* Custom scrollbar for webkit browsers */
  scrollbar-width: thin;
  scrollbar-color: var(--border) transparent;
}

.log-scroll::-webkit-scrollbar       { width: 4px; }
.log-scroll::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

/* Individual log line */
.log-line {
  display: flex;
  gap: 16px;
  padding: 2px 16px;
  transition: background var(--transition);
}

.log-line:hover {
  background: rgba(255, 255, 255, 0.03);
}

/* Dim left-aligned line numbers, monospace-aligned */
.log-num {
  color: var(--text-secondary);
  opacity: 0.4;
  font-size: 11px;
  user-select: none;   /* not useful to copy line numbers */
  flex-shrink: 0;
  font-variant-numeric: tabular-nums;
}

.log-text {
  font-size: 12px;
  color: var(--text-secondary);
  word-break: break-all;
}

/* ============================================================
   FADE TRANSITION (results appear)
   ============================================================ */
.fade-enter-active, .fade-leave-active {
  transition: opacity 0.3s ease, transform 0.3s ease;
}
.fade-enter-from {
  opacity: 0;
  transform: translateY(8px);
}
.fade-leave-to {
  opacity: 0;
}

/* ============================================================
   INFO GRID (below the scan card)
   ============================================================ */
.info-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 16px;
}

.info-box {
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 20px;
}

/* Bold label line at the top of each info box */
.info-box-label {
  font-size: 10px;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--accent-dim);
  margin-bottom: 12px;
}

.info-box p {
  margin: 0 0 8px;
  font-size: 13px;
  color: var(--text-secondary);
}

.info-note {
  font-size: 11px !important;
  opacity: 0.7;
}

/* Bullet list inside info boxes */
.info-list {
  margin: 0;
  padding: 0 0 0 16px;
  font-size: 13px;
  color: var(--text-secondary);
}

.info-list li {
  margin-bottom: 4px;
}

/* Plain link list (no bullets) */
.link-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.link-list li::before {
  content: '→ ';
  color: var(--accent-dim);
}

/* ============================================================
   FOOTER
   ============================================================ */
.site-footer {
  border-top: 1px solid var(--border);
  padding: 20px 24px;
  text-align: center;
  font-size: 11px;
  color: var(--text-secondary);
  opacity: 0.7;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.footer-custom {
  display: block;
}
</style>
