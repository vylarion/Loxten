<script lang="ts">
  import type { Threat } from './types';
  import { Prohibit, FishSimple, Eye, Bug, Code, CurrencyBtc, CursorClick, Robot, Warning, ShieldCheck, Lightbulb, CaretDown, Flag, BookOpen, Info, X, ListPlus } from 'phosphor-svelte';
  import { createEventDispatcher } from 'svelte';

  export let threats: Threat[] = [];

  const dispatch = createEventDispatcher();

  function getThreatIcon(type: string) {
    const icons: Record<string, any> = {
      malicious_domain: Prohibit,
      phishing: FishSimple,
      tracker: Eye,
      malware: Bug,
      suspicious_script: Code,
      cryptomining: CurrencyBtc,
      clickjacking: CursorClick,
      ai_detection: Robot,
    };
    return icons[type] || Warning;
  }

  function getSeverityLabel(severity: string): string {
    const labels: Record<string, string> = {
      low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical'
    };
    return labels[severity] || 'Unknown';
  }

  function formatType(type: string): string {
    return type.split('_').map((w: string) => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
  }

  function getRecommendation(threat: Threat): string {
    const recs: Record<string, string> = {
      malicious_domain: 'Leave this website immediately. Do not share personal information.',
      phishing: 'Do not enter passwords or personal details. This may be a phishing attempt.',
      tracker: 'Your browsing may be monitored. Consider using privacy mode.',
      malware: 'This site may contain harmful software. Scan your device.',
      suspicious_script: 'Potentially malicious code detected. Avoid downloads.',
      cryptomining: 'This site may be using your device to mine cryptocurrency.',
      clickjacking: 'This page may trick you into clicking hidden elements.',
      ai_detection: 'AI flagged this content as potentially suspicious.'
    };
    return recs[threat.type] || 'Exercise caution when browsing this website.';
  }

  function toggleDetails(threat: Threat): void {
    threat.showDetails = !threat.showDetails;
    threats = threats;
  }

  function ignoreThreat(index: number): void {
    threats[index].ignored = true;
    threats = threats;
  }

  function undoIgnore(index: number): void {
    threats[index].ignored = false;
    threats = threats;
  }

  $: activeThreats = threats.filter(t => !t.ignored);
  $: ignoredThreats = threats.filter(t => t.ignored);
</script>

<div class="threats">
  {#if threats.length === 0}
    <div class="clear-state">
      <div class="clear-icon">
        <ShieldCheck size={32} weight="light" />
      </div>
      <h3 class="clear-title">All Clear</h3>
      <p class="clear-desc">No security threats were found on this website.</p>
      <div class="tips">
        <h4 class="tips-label">
          <Info size={11} weight="bold" />
          Stay Safe
        </h4>
        <ul>
          <li>Verify URLs before entering personal information</li>
          <li>Look for HTTPS in the address bar</li>
          <li>Be wary of urgent requests for credentials</li>
          <li>Keep your browser and extensions updated</li>
        </ul>
      </div>
    </div>
  {:else}
    <div class="threats-head">
      <div class="threats-count">
        <Warning size={13} weight="fill" />
        <span>{activeThreats.length} {activeThreats.length === 1 ? 'Threat' : 'Threats'} Active</span>
      </div>
      {#if ignoredThreats.length > 0}
        <p class="threats-sub">{ignoredThreats.length} ignored</p>
      {:else}
        <p class="threats-sub">Security issues found on this website</p>
      {/if}
    </div>

    <div class="threats-scroll">
      {#each threats as threat, i}
        <div class="card" class:ignored={threat.ignored}>
          <div class="card-head">
            <div class="card-icon">
              <svelte:component this={getThreatIcon(threat.type)} size={15} weight="bold" />
            </div>
            <div class="card-meta">
              <span class="card-type">{formatType(threat.type)}</span>
              <span class="card-badge sev-{threat.severity}">
                {getSeverityLabel(threat.severity)}
              </span>
            </div>
          </div>

          {#if !threat.ignored}
            <p class="card-desc">{threat.description}</p>
            <div class="card-rec">
              <Lightbulb size={11} weight="bold" />
              <span>{getRecommendation(threat)}</span>
            </div>

            <!-- Quick actions -->
            <div class="quick-actions">
              <button class="qa-btn" on:click={() => ignoreThreat(i)} title="Dismiss this threat">
                <X size={10} weight="bold" />
                Ignore
              </button>
              <button class="qa-btn" on:click={() => alert('Whitelist feature coming in backend update')} title="Add domain to whitelist">
                <ListPlus size={10} weight="bold" />
                Whitelist
              </button>
            </div>

            {#if threat.details}
              <button class="details-btn" on:click={() => toggleDetails(threat)}>
                <span>{threat.showDetails ? 'Hide' : 'Show'} Details</span>
                <CaretDown size={10} weight="bold" class={threat.showDetails ? 'rotated' : ''} />
              </button>
              {#if threat.showDetails}
                <pre class="details-code">{JSON.stringify(threat.details, null, 2)}</pre>
              {/if}
            {/if}
          {:else}
            <div class="ignored-row">
              <span class="ignored-text">Dismissed</span>
              <button class="undo-btn" on:click={() => undoIgnore(i)}>Undo</button>
            </div>
          {/if}
        </div>
      {/each}
    </div>

    <div class="threats-actions">
      <button class="action-btn" on:click={() => alert('Report feature coming soon')}>
        <Flag size={11} weight="bold" />
        Report
      </button>
      <button class="action-btn" on:click={() => alert('Learn more coming soon')}>
        <BookOpen size={11} weight="bold" />
        Learn More
      </button>
    </div>
  {/if}
</div>

<style>
  .threats {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  /* Clear state */
  .clear-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    padding: 28px 20px;
    background: #0a0a0a;
    border: 1px solid #181818;
    border-radius: 14px;
  }

  .clear-icon {
    color: #707070;
    margin-bottom: 12px;
  }

  .clear-title {
    margin: 0 0 6px;
    font-size: 15px;
    font-weight: 600;
    color: #d0d0d0;
  }

  .clear-desc {
    margin: 0 0 20px;
    font-size: 11px;
    color: #808080;
    line-height: 1.5;
  }

  .tips {
    width: 100%;
    background: #070707;
    border: 1px solid #161616;
    border-radius: 10px;
    padding: 14px 16px;
    text-align: left;
  }

  .tips-label {
    display: flex;
    align-items: center;
    gap: 6px;
    margin: 0 0 10px;
    font-size: 10px;
    font-weight: 600;
    color: #606060;
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }

  .tips ul {
    margin: 0;
    padding-left: 16px;
    color: #808080;
  }

  .tips li {
    font-size: 11px;
    margin-bottom: 4px;
    line-height: 1.5;
  }

  /* Threats header */
  .threats-head {
    text-align: center;
    padding: 14px;
    background: #0a0a0a;
    border: 1px solid #181818;
    border-radius: 12px;
  }

  .threats-count {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    font-size: 13px;
    font-weight: 600;
    color: #d0d0d0;
    margin-bottom: 4px;
  }

  .threats-sub {
    margin: 0;
    font-size: 11px;
    color: #606060;
  }

  /* Cards */
  .threats-scroll {
    display: flex;
    flex-direction: column;
    gap: 8px;
    max-height: 320px;
    overflow-y: auto;
    padding-right: 2px;
  }

  .threats-scroll::-webkit-scrollbar {
    width: 3px;
  }

  .threats-scroll::-webkit-scrollbar-thumb {
    background: #1e1e1e;
    border-radius: 2px;
  }

  .card {
    background: #0a0a0a;
    border: 1px solid #181818;
    border-left: 2px solid #404040;
    border-radius: 10px;
    padding: 14px 16px;
    transition: opacity 0.2s ease;
  }

  .card.ignored {
    opacity: 0.5;
    border-left-color: #1e1e1e;
  }

  .card-head {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 10px;
  }

  .card.ignored .card-head {
    margin-bottom: 0;
  }

  .card-icon {
    width: 30px;
    height: 30px;
    border-radius: 7px;
    background: #131313;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #808080;
    flex-shrink: 0;
  }

  .card-meta {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .card-type {
    font-size: 12px;
    font-weight: 600;
    color: #b0b0b0;
  }

  .card-badge {
    font-size: 9px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    padding: 3px 8px;
    border-radius: 6px;
    color: #909090;
    background: #161616;
    border: 1px solid #1e1e1e;
  }

  .card-badge.sev-high,
  .card-badge.sev-critical {
    color: #b0b0b0;
    border-color: #303030;
  }

  .card-desc {
    margin: 0 0 10px;
    font-size: 11px;
    color: #808080;
    line-height: 1.5;
  }

  .card-rec {
    display: flex;
    align-items: flex-start;
    gap: 6px;
    padding: 10px 12px;
    background: #080808;
    border: 1px solid #161616;
    border-radius: 8px;
    font-size: 11px;
    color: #808080;
    line-height: 1.5;
  }

  .card-rec :global(svg) {
    flex-shrink: 0;
    margin-top: 1px;
  }

  /* Quick Actions */
  .quick-actions {
    display: flex;
    gap: 6px;
    margin-top: 10px;
  }

  .qa-btn {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 5px 10px;
    border: 1px solid #1e1e1e;
    border-radius: 6px;
    background: #0e0e0e;
    color: #707070;
    font-size: 10px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.15s ease;
    font-family: inherit;
  }

  .qa-btn:hover {
    background: #181818;
    color: #a0a0a0;
    border-color: #282828;
  }

  /* Ignored state */
  .ignored-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-top: 8px;
  }

  .ignored-text {
    font-size: 11px;
    color: #606060;
    font-style: italic;
  }

  .undo-btn {
    padding: 4px 10px;
    border: 1px solid #1e1e1e;
    border-radius: 5px;
    background: transparent;
    color: #707070;
    font-size: 10px;
    font-weight: 500;
    cursor: pointer;
    font-family: inherit;
    transition: all 0.15s ease;
  }

  .undo-btn:hover {
    background: #181818;
    color: #a0a0a0;
  }

  /* Details */
  .details-btn {
    display: flex;
    align-items: center;
    gap: 4px;
    margin-top: 10px;
    padding: 0;
    border: none;
    background: none;
    color: #606060;
    font-size: 11px;
    font-weight: 500;
    cursor: pointer;
    font-family: inherit;
    transition: color 0.15s ease;
  }

  .details-btn:hover {
    color: #909090;
  }

  .details-btn :global(.rotated) {
    transform: rotate(180deg);
  }

  .details-code {
    margin: 8px 0 0;
    padding: 10px 12px;
    background: #070707;
    border: 1px solid #161616;
    border-radius: 8px;
    font-size: 10px;
    color: #808080;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    overflow-x: auto;
    white-space: pre-wrap;
  }

  /* Actions */
  .threats-actions {
    display: flex;
    gap: 8px;
  }

  .action-btn {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 5px;
    padding: 9px;
    border: 1px solid #1e1e1e;
    border-radius: 8px;
    background: #0e0e0e;
    color: #707070;
    font-size: 11px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.15s ease;
    font-family: inherit;
  }

  .action-btn:hover {
    background: #181818;
    color: #909090;
    border-color: #282828;
  }
</style>