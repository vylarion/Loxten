<script lang="ts">
  import type { Threat, SecurityData, AIAnalysis } from './types';
  import { ShieldWarning, EyeSlash, LockSimple, MagnifyingGlass, FishSimple, Eye, ArrowsClockwise, CheckCircle, XCircle, Globe, Certificate, Brain, Warning } from 'phosphor-svelte';

  export let securityData: SecurityData;
  export let runQuickScan: () => Promise<void>;
  export let currentUrl: string = '';
  export let isHttps: boolean = false;

  let isScanning = false;

  async function handleScan(): Promise<void> {
    isScanning = true;
    try {
      await runQuickScan();
    } catch (error) {
      console.error('Scan failed:', error);
    } finally {
      isScanning = false;
    }
  }

  function getGrade(riskScore: number): string {
    if (riskScore < 20) return 'A+';
    if (riskScore < 30) return 'A';
    if (riskScore < 40) return 'B';
    if (riskScore < 60) return 'C';
    if (riskScore < 80) return 'D';
    return 'F';
  }

  function getCookieCount(): string {
    try {
      if (typeof document !== 'undefined') {
        const cookies = document.cookie.split(';').filter(c => c.trim());
        return cookies.length.toString();
      }
    } catch {}
    return '—';
  }

  function getProtocol(): string {
    try {
      const url = new URL(currentUrl);
      return url.protocol.replace(':', '').toUpperCase();
    } catch {
      return '—';
    }
  }

  $: grade = getGrade(securityData.riskScore);
  $: safeScore = 100 - securityData.riskScore;
  $: dashOffset = 251.2 - (251.2 * safeScore / 100);
</script>

<div class="status">
  <!-- Score card -->
  <div class="score-card">
    <div class="ring-wrap">
      <svg class="ring" viewBox="0 0 88 88">
        <circle class="ring-bg" cx="44" cy="44" r="40" />
        <circle
          class="ring-fill"
          cx="44" cy="44" r="40"
          style="stroke-dashoffset:{dashOffset}"
        />
      </svg>
      <div class="ring-label">
        <span class="ring-grade">{grade}</span>
        <span class="ring-score">{safeScore}</span>
      </div>
    </div>
    <div class="score-info">
      <h3 class="score-title">
        {#if securityData.isSecure}
          <CheckCircle size={15} weight="fill" />
          Site is Secure
        {:else}
          <XCircle size={15} weight="fill" />
          Issues Found
        {/if}
      </h3>
      <p class="score-desc">
        {#if securityData.riskScore < 30}
          No major security concerns detected on this site.
        {:else if securityData.riskScore < 60}
          Some potential issues found. Browse with caution.
        {:else}
          Multiple threats detected. Consider leaving this site.
        {/if}
      </p>
    </div>
  </div>

  <!-- Stats row -->
  <div class="stats-row">
    <div class="stat">
      <div class="stat-icon"><ShieldWarning size={14} /></div>
      <span class="stat-val">{securityData.threats.length}</span>
      <span class="stat-lbl">Threats</span>
    </div>
    <div class="stat-divider"></div>
    <div class="stat">
      <div class="stat-icon"><EyeSlash size={14} /></div>
      <span class="stat-val">{securityData.trackersBlocked}</span>
      <span class="stat-lbl">Blocked</span>
    </div>
    <div class="stat-divider"></div>
    <div class="stat">
      <div class="stat-icon"><LockSimple size={14} /></div>
      <span class="stat-val">{isHttps ? 'Yes' : 'No'}</span>
      <span class="stat-lbl">HTTPS</span>
    </div>
  </div>

  <!-- Analysis -->
  <div class="section-card">
    <h4 class="section-label">Analysis</h4>
    <div class="analysis-list">
      <div class="analysis-row">
        <div class="analysis-icon">
          <MagnifyingGlass size={13} weight="bold" />
        </div>
        <span class="analysis-name">Malware Scan</span>
        <span class="analysis-val">{securityData.riskScore < 30 ? 'Clean' : 'Issues'}</span>
      </div>
      <div class="analysis-row">
        <div class="analysis-icon">
          <FishSimple size={13} weight="bold" />
        </div>
        <span class="analysis-name">Phishing</span>
        <span class="analysis-val">
          {securityData.threats.some((t: Threat) => t.type === 'phishing') ? 'Detected' : 'Clear'}
        </span>
      </div>
      <div class="analysis-row">
        <div class="analysis-icon">
          <Eye size={13} weight="bold" />
        </div>
        <span class="analysis-name">Trackers</span>
        <span class="analysis-val">
          {securityData.trackersBlocked > 0 ? `${securityData.trackersBlocked} blocked` : 'None'}
        </span>
      </div>
    </div>
  </div>

  <!-- AI Analysis -->
  <div class="section-card ai-section">
    <h4 class="section-label">
      <Brain size={12} weight="fill" />
      AI Analysis
    </h4>
    {#if securityData.aiAnalysis}
      <div class="ai-summary">
        <p class="ai-text">{securityData.aiAnalysis.ai_summary}</p>
      </div>
      {#if securityData.aiAnalysis.is_phishing}
        <div class="ai-alert phishing">
          <Warning size={13} weight="fill" />
          <span>Phishing detected{securityData.aiAnalysis.impersonating ? `: impersonating ${securityData.aiAnalysis.impersonating}` : ''}</span>
        </div>
      {/if}
      {#if securityData.aiAnalysis.privacy_concerns.length > 0}
        <div class="ai-privacy">
          <span class="ai-privacy-label">Privacy</span>
          <ul class="ai-privacy-list">
            {#each securityData.aiAnalysis.privacy_concerns as concern}
              <li>{concern}</li>
            {/each}
          </ul>
        </div>
      {/if}
    {:else}
      <div class="ai-pending">
        <div class="ai-pulse"></div>
        <span>Analyzing page...</span>
      </div>
    {/if}
  </div>

  <!-- Site Details -->
  <div class="section-card">
    <h4 class="section-label">Site Details</h4>
    <div class="details-grid">
      <div class="detail-item">
        <div class="detail-icon">
          <LockSimple size={12} weight="bold" />
        </div>
        <div class="detail-info">
          <span class="detail-key">Connection</span>
          <span class="detail-val">{isHttps ? 'Encrypted (TLS)' : 'Not Encrypted'}</span>
        </div>
      </div>
      <div class="detail-item">
        <div class="detail-icon">
          <Globe size={12} weight="bold" />
        </div>
        <div class="detail-info">
          <span class="detail-key">Protocol</span>
          <span class="detail-val">{getProtocol()}</span>
        </div>
      </div>
      <div class="detail-item">
        <div class="detail-icon">
          <Certificate size={12} weight="bold" />
        </div>
        <div class="detail-info">
          <span class="detail-key">Certificate</span>
          <span class="detail-val">{isHttps ? 'Valid' : 'N/A'}</span>
        </div>
      </div>
    </div>
  </div>

  <!-- Scan button -->
  <button 
    class="scan-btn" 
    class:scanning={isScanning}
    on:click={handleScan}
    disabled={isScanning}
  >
    {#if isScanning}
      <div class="btn-spin"></div>
      Scanning...
    {:else}
      <ArrowsClockwise size={13} weight="bold" />
      Run Scan
    {/if}
  </button>
</div>

<style>
  .status {
    display: flex;
    flex-direction: column;
    gap: 14px;
  }

  /* Score card */
  .score-card {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 20px;
    background: #0a0a0a;
    border: 1px solid #181818;
    border-radius: 14px;
  }

  .ring-wrap {
    position: relative;
    width: 72px;
    height: 72px;
    flex-shrink: 0;
  }

  .ring {
    width: 100%;
    height: 100%;
    transform: rotate(-90deg);
  }

  .ring-bg {
    fill: none;
    stroke: #161616;
    stroke-width: 5;
  }

  .ring-fill {
    fill: none;
    stroke: #707070;
    stroke-width: 5;
    stroke-linecap: round;
    stroke-dasharray: 251.2;
    transition: stroke-dashoffset 0.6s ease;
  }

  .ring-label {
    position: absolute;
    inset: 0;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
  }

  .ring-grade {
    font-size: 18px;
    font-weight: 800;
    color: #e0e0e0;
    line-height: 1;
    letter-spacing: -0.03em;
  }

  .ring-score {
    font-size: 10px;
    color: #606060;
    font-weight: 600;
    margin-top: 1px;
  }

  .score-info {
    flex: 1;
    min-width: 0;
  }

  .score-title {
    display: flex;
    align-items: center;
    gap: 6px;
    margin: 0 0 6px;
    font-size: 13px;
    font-weight: 600;
    color: #d0d0d0;
  }

  .score-desc {
    margin: 0;
    font-size: 11px;
    color: #808080;
    line-height: 1.5;
  }

  /* Stats */
  .stats-row {
    display: flex;
    align-items: center;
    background: #0a0a0a;
    border: 1px solid #181818;
    border-radius: 12px;
    padding: 14px 0;
  }

  .stat {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
  }

  .stat-icon {
    color: #606060;
  }

  .stat-val {
    font-size: 16px;
    font-weight: 700;
    color: #d0d0d0;
    line-height: 1;
  }

  .stat-lbl {
    font-size: 9px;
    color: #606060;
    text-transform: uppercase;
    font-weight: 600;
    letter-spacing: 0.06em;
  }

  .stat-divider {
    width: 1px;
    height: 28px;
    background: #181818;
  }

  /* Section cards */
  .section-card {
    background: #0a0a0a;
    border: 1px solid #181818;
    border-radius: 12px;
    padding: 14px 16px;
  }

  .section-label {
    margin: 0 0 12px;
    font-size: 10px;
    font-weight: 600;
    color: #606060;
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }

  .analysis-list {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .analysis-row {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .analysis-icon {
    width: 26px;
    height: 26px;
    border-radius: 6px;
    background: #131313;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #707070;
    flex-shrink: 0;
  }

  .analysis-name {
    flex: 1;
    font-size: 12px;
    font-weight: 500;
    color: #9a9a9a;
  }

  .analysis-val {
    font-size: 11px;
    font-weight: 600;
    color: #808080;
  }

  /* Site Details */
  .details-grid {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .detail-item {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .detail-icon {
    width: 26px;
    height: 26px;
    border-radius: 6px;
    background: #131313;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #707070;
    flex-shrink: 0;
  }

  .detail-info {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .detail-key {
    font-size: 12px;
    font-weight: 500;
    color: #9a9a9a;
  }

  .detail-val {
    font-size: 11px;
    font-weight: 600;
    color: #808080;
  }

  /* Scan button */
  .scan-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    width: 100%;
    padding: 11px;
    border: 1px solid #1e1e1e;
    border-radius: 10px;
    background: #0e0e0e;
    color: #909090;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.15s ease;
    font-family: inherit;
  }

  .scan-btn:hover:not(:disabled) {
    background: #181818;
    color: #d0d0d0;
    border-color: #252525;
  }

  .scan-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .scan-btn.scanning {
    color: #606060;
  }

  .btn-spin {
    width: 12px;
    height: 12px;
    border: 2px solid #252525;
    border-top-color: #707070;
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  /* AI Section */
  .ai-section .section-label {
    display: flex;
    align-items: center;
    gap: 5px;
  }

  .ai-summary {
    margin-bottom: 10px;
  }

  .ai-text {
    margin: 0;
    font-size: 11.5px;
    color: #9a9a9a;
    line-height: 1.55;
  }

  .ai-alert {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 8px 10px;
    border-radius: 8px;
    font-size: 11px;
    font-weight: 600;
    margin-bottom: 10px;
  }

  .ai-alert.phishing {
    background: #1a0a0a;
    border: 1px solid #2a1515;
    color: #cc6666;
  }

  .ai-privacy {
    margin-top: 8px;
  }

  .ai-privacy-label {
    font-size: 10px;
    font-weight: 600;
    color: #606060;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .ai-privacy-list {
    margin: 6px 0 0;
    padding: 0 0 0 14px;
    list-style: disc;
  }

  .ai-privacy-list li {
    font-size: 11px;
    color: #808080;
    line-height: 1.6;
  }

  .ai-pending {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 11px;
    color: #606060;
  }

  .ai-pulse {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #505050;
    animation: pulse-anim 1.5s ease-in-out infinite;
  }

  @keyframes pulse-anim {
    0%, 100% { opacity: 0.3; transform: scale(0.8); }
    50% { opacity: 1; transform: scale(1.1); }
  }
</style>