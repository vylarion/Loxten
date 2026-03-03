<script lang="ts">
	import type { SecurityData } from './types';
	import {
		Globe,
		LockSimple,
		Link as LinkIcon,
		Certificate,
		Clock,
		ShieldCheck,
		MagnifyingGlass,
		CheckCircle,
		XCircle
	} from 'phosphor-svelte';

	export let currentUrl: string = '';
	export let isHttps: boolean = false;
	export let securityData: SecurityData;

	function getDomain(): string {
		try {
			return new URL(currentUrl).hostname;
		} catch {
			return '—';
		}
	}

	function getProtocol(): string {
		try {
			const url = new URL(currentUrl);
			return url.protocol.replace(':', '').toUpperCase();
		} catch {
			return '—';
		}
	}

	function getPort(): string {
		try {
			const url = new URL(currentUrl);
			return url.port || (isHttps ? '443' : '80');
		} catch {
			return '—';
		}
	}

	function getPathname(): string {
		try {
			const url = new URL(currentUrl);
			return url.pathname === '/' ? '/' : url.pathname;
		} catch {
			return '—';
		}
	}

	$: sourcesChecked = securityData.sourcesChecked || ['heuristics'];
	$: vtDetections = securityData.vtDetections || 0;
	$: vtTotalEngines = securityData.vtTotalEngines || 0;
</script>

<div class="details">
	<!-- Connection Info -->
	<div class="section-card">
		<h4 class="section-label">Connection</h4>
		<div class="details-grid">
			<div class="detail-row">
				<div class="detail-icon"><Globe size={11} weight="bold" /></div>
				<span class="detail-key">Domain</span>
				<span class="detail-val">{getDomain()}</span>
			</div>
			<div class="detail-row">
				<div class="detail-icon"><LockSimple size={11} weight="bold" /></div>
				<span class="detail-key">Connection</span>
				<span class="detail-val">{isHttps ? 'Encrypted (TLS)' : 'Not Encrypted'}</span>
			</div>
			<div class="detail-row">
				<div class="detail-icon"><LinkIcon size={11} weight="bold" /></div>
				<span class="detail-key">Protocol</span>
				<span class="detail-val">{getProtocol()}</span>
			</div>
			<div class="detail-row">
				<div class="detail-icon"><Certificate size={11} weight="bold" /></div>
				<span class="detail-key">Certificate</span>
				<span class="detail-val">{isHttps ? 'Valid' : 'N/A'}</span>
			</div>
			<div class="detail-row">
				<div class="detail-icon"><Clock size={11} weight="bold" /></div>
				<span class="detail-key">Port</span>
				<span class="detail-val">{getPort()}</span>
			</div>
			<div class="detail-row">
				<div class="detail-icon"><LinkIcon size={11} weight="bold" /></div>
				<span class="detail-key">Path</span>
				<span class="detail-val path">{getPathname()}</span>
			</div>
		</div>
	</div>

	<!-- Sources -->
	<div class="section-card">
		<h4 class="section-label">Scan Sources</h4>
		<div class="sources-list">
			<div class="source-row">
				<div class="source-icon"><MagnifyingGlass size={11} weight="bold" /></div>
				<span class="source-name">Local Heuristics</span>
				<span class="source-badge on">Active</span>
			</div>
			<div class="source-row">
				<div class="source-icon"><ShieldCheck size={11} weight="bold" /></div>
				<span class="source-name">VirusTotal</span>
				{#if sourcesChecked.includes('virustotal')}
					<span class="source-badge on">
						{vtDetections > 0 ? `${vtDetections}/${vtTotalEngines}` : `0/${vtTotalEngines}`}
					</span>
				{:else}
					<span class="source-badge off">Off</span>
				{/if}
			</div>
			<div class="source-row">
				<div class="source-icon"><Globe size={11} weight="bold" /></div>
				<span class="source-name">Safe Browsing</span>
				{#if sourcesChecked.includes('safebrowsing')}
					<span class="source-badge on">
						{#if securityData.gsbThreats && securityData.gsbThreats.length > 0}
							{securityData.gsbThreats.length} flag{securityData.gsbThreats.length !== 1 ? 's' : ''}
						{:else}
							Clean
						{/if}
					</span>
				{:else}
					<span class="source-badge off">Off</span>
				{/if}
			</div>
		</div>
	</div>
</div>

<style>
	.details {
		display: flex;
		flex-direction: column;
		gap: 10px;
	}

	.section-card {
		background: #0a0a0a;
		border: 1px solid var(--border-color, #181818);
		border-radius: 3px;
		padding: 12px 14px;
	}

	.section-label {
		margin: 0 0 8px;
		font-size: 10px;
		font-weight: 600;
		color: #808080;
		text-transform: uppercase;
		letter-spacing: 0.06em;
	}

	.details-grid {
		display: flex;
		flex-direction: column;
	}

	.detail-row {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 5px 0;
		border-bottom: 1px solid #151515;
	}

	.detail-row:last-child {
		border-bottom: none;
	}

	.detail-icon {
		width: 22px;
		height: 22px;
		border-radius: 2px;
		background: #131313;
		display: flex;
		align-items: center;
		justify-content: center;
		color: #606060;
		flex-shrink: 0;
	}

	.detail-key {
		flex: 1;
		font-size: 11px;
		font-weight: 500;
		color: #909090;
	}

	.detail-val {
		font-size: 11px;
		font-weight: 600;
		color: #b0b0b0;
		max-width: 140px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		text-align: right;
	}

	.detail-val.path {
		font-family: 'JetBrains Mono', 'Fira Code', monospace;
		font-size: 10px;
		color: #808080;
	}

	/* Sources */
	.sources-list {
		display: flex;
		flex-direction: column;
		gap: 6px;
	}

	.source-row {
		display: flex;
		align-items: center;
		gap: 8px;
	}

	.source-icon {
		width: 22px;
		height: 22px;
		border-radius: 2px;
		background: #131313;
		display: flex;
		align-items: center;
		justify-content: center;
		color: #606060;
		flex-shrink: 0;
	}

	.source-name {
		flex: 1;
		font-size: 11px;
		font-weight: 500;
		color: #909090;
	}

	.source-badge {
		font-size: 10px;
		font-weight: 600;
		padding: 2px 8px;
		border-radius: 2px;
	}

	.source-badge.on {
		background: #0e1a0e;
		color: #4ade80;
		border: 1px solid #1a2e1a;
	}

	.source-badge.off {
		background: #1a1a1a;
		color: #606060;
		border: 1px solid #252525;
	}
</style>
