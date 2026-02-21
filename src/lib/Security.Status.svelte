<script lang="ts">
	import type { Threat, SecurityData } from './types';
	import {
		ShieldWarning,
		EyeSlash,
		LockSimple,
		MagnifyingGlass,
		FishSimple,
		Eye,
		ArrowsClockwise,
		CheckCircle,
		XCircle,
		Globe,
		Certificate,
		Link as LinkIcon,
		Clock,
		Info
	} from 'phosphor-svelte';

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

	$: grade = getGrade(securityData.riskScore);
	$: safeScore = 100 - securityData.riskScore;
	$: dashOffset = 251.2 - (251.2 * safeScore) / 100;
</script>

<div class="status">
	<!-- Score card -->
	<div class="score-card">
		<div class="ring-wrap">
			<svg class="ring" viewBox="0 0 88 88">
				<circle class="ring-bg" cx="44" cy="44" r="40" />
				<circle class="ring-fill" cx="44" cy="44" r="40" style="stroke-dashoffset:{dashOffset}" />
			</svg>
			<div class="ring-label">
				<span class="ring-grade">{grade}</span>
				<span class="ring-score">{safeScore}</span>
			</div>
		</div>
		<div class="score-info">
			<h3 class="score-title">
				{#if securityData.isSecure}
					<CheckCircle size={14} weight="fill" />
					Site is Secure
				{:else}
					<XCircle size={14} weight="fill" />
					Issues Found
				{/if}
			</h3>
			<p class="score-desc">
				{#if securityData.riskScore < 30}
					No major security concerns detected.
				{:else if securityData.riskScore < 60}
					Some potential issues found.
				{:else}
					Multiple threats detected.
				{/if}
			</p>
		</div>
	</div>

	<!-- Stats row -->
	<div class="stats-row">
		<div class="stat">
			<div class="stat-icon"><ShieldWarning size={13} /></div>
			<span class="stat-val">{securityData.threats.length}</span>
			<span class="stat-lbl">Threats</span>
		</div>
		<div class="stat-divider"></div>
		<div class="stat">
			<div class="stat-icon"><EyeSlash size={13} /></div>
			<span class="stat-val">{securityData.trackersBlocked}</span>
			<span class="stat-lbl">Blocked</span>
		</div>
		<div class="stat-divider"></div>
		<div class="stat">
			<div class="stat-icon"><LockSimple size={13} /></div>
			<span class="stat-val">{isHttps ? 'Yes' : 'No'}</span>
			<span class="stat-lbl">HTTPS</span>
		</div>
	</div>

	<!-- Analysis -->
	<div class="section-card">
		<h4 class="section-label">Analysis</h4>
		<div class="analysis-list">
			<div class="analysis-row">
				<div class="analysis-icon"><MagnifyingGlass size={12} weight="bold" /></div>
				<span class="analysis-name">Malware</span>
				<span class="analysis-val">{securityData.riskScore < 30 ? 'Clean' : 'Issues'}</span>
			</div>
			<div class="analysis-row">
				<div class="analysis-icon"><FishSimple size={12} weight="bold" /></div>
				<span class="analysis-name">Phishing</span>
				<span class="analysis-val">
					{securityData.threats.some((t: Threat) => t.type === 'phishing') ? 'Detected' : 'Clear'}
				</span>
			</div>
			<div class="analysis-row">
				<div class="analysis-icon"><Eye size={12} weight="bold" /></div>
				<span class="analysis-name">Trackers</span>
				<span class="analysis-val">
					{securityData.trackersBlocked > 0 ? `${securityData.trackersBlocked} blocked` : 'None'}
				</span>
			</div>
		</div>
	</div>

	<!-- Scan + Site Details row -->
	<div class="bottom-row">
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

		<!-- Site Details - pure CSS hover -->
		<div class="details-trigger-wrap">
			<button class="details-trigger" type="button">
				<Info size={13} weight="bold" />
			</button>
			<div class="details-tooltip">
				<h4 class="details-title">Site Details</h4>
				<div class="details-grid">
					<div class="detail-row">
						<div class="detail-icon"><Globe size={10} weight="bold" /></div>
						<span class="detail-key">Domain</span>
						<span class="detail-val">{getDomain()}</span>
					</div>
					<div class="detail-row">
						<div class="detail-icon"><LockSimple size={10} weight="bold" /></div>
						<span class="detail-key">Connection</span>
						<span class="detail-val">{isHttps ? 'Encrypted (TLS)' : 'Not Encrypted'}</span>
					</div>
					<div class="detail-row">
						<div class="detail-icon"><LinkIcon size={10} weight="bold" /></div>
						<span class="detail-key">Protocol</span>
						<span class="detail-val">{getProtocol()}</span>
					</div>
					<div class="detail-row">
						<div class="detail-icon"><Certificate size={10} weight="bold" /></div>
						<span class="detail-key">Certificate</span>
						<span class="detail-val">{isHttps ? 'Valid' : 'N/A'}</span>
					</div>
					<div class="detail-row">
						<div class="detail-icon"><Clock size={10} weight="bold" /></div>
						<span class="detail-key">Port</span>
						<span class="detail-val">{getPort()}</span>
					</div>
					<div class="detail-row">
						<div class="detail-icon"><LinkIcon size={10} weight="bold" /></div>
						<span class="detail-key">Path</span>
						<span class="detail-val path">{getPathname()}</span>
					</div>
				</div>
			</div>
		</div>
	</div>
</div>

<style>
	.status {
		display: flex;
		flex-direction: column;
		gap: 10px;
	}

	/* Score card — compact */
	.score-card {
		display: flex;
		align-items: center;
		gap: 14px;
		padding: 14px 16px;
		background: #0a0a0a;
		border: 1px solid var(--border-color, #181818);
		border-radius: 3px;
	}

	.ring-wrap {
		position: relative;
		width: 60px;
		height: 60px;
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
		stroke: #909090;
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
		font-size: 16px;
		font-weight: 800;
		color: #e8e8e8;
		line-height: 1;
		letter-spacing: -0.03em;
	}

	.ring-score {
		font-size: 9px;
		color: #808080;
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
		gap: 5px;
		margin: 0 0 4px;
		font-size: 13px;
		font-weight: 600;
		color: #d8d8d8;
	}

	.score-desc {
		margin: 0;
		font-size: 11px;
		color: #909090;
		line-height: 1.4;
	}

	/* Stats — compact */
	.stats-row {
		display: flex;
		align-items: center;
		background: #0a0a0a;
		border: 1px solid var(--border-color, #181818);
		border-radius: 3px;
		padding: 10px 0;
	}

	.stat {
		flex: 1;
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 3px;
	}

	.stat-icon {
		color: #808080;
	}

	.stat-val {
		font-size: 15px;
		font-weight: 700;
		color: #d8d8d8;
		line-height: 1;
	}

	.stat-lbl {
		font-size: 9px;
		color: #808080;
		text-transform: uppercase;
		font-weight: 600;
		letter-spacing: 0.06em;
	}

	.stat-divider {
		width: 1px;
		height: 24px;
		background: #1a1a1a;
	}

	/* Section cards — compact */
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

	.analysis-list {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}

	.analysis-row {
		display: flex;
		align-items: center;
		gap: 8px;
	}

	.analysis-icon {
		width: 24px;
		height: 24px;
		border-radius: 2px;
		background: #131313;
		display: flex;
		align-items: center;
		justify-content: center;
		color: #808080;
		flex-shrink: 0;
	}

	.analysis-name {
		flex: 1;
		font-size: 12px;
		font-weight: 500;
		color: #b0b0b0;
	}

	.analysis-val {
		font-size: 11px;
		font-weight: 600;
		color: #909090;
	}

	/* Bottom row */
	.bottom-row {
		display: flex;
		gap: 8px;
	}

	.scan-btn {
		flex: 1;
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 6px;
		padding: 10px;
		border: 1px solid var(--border-color, #181818);
		border-radius: 3px;
		background: #0e0e0e;
		color: #a0a0a0;
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
		color: #707070;
	}

	.btn-spin {
		width: 12px;
		height: 12px;
		border: 2px solid #252525;
		border-top-color: #808080;
		border-radius: 50%;
		animation: spin 0.7s linear infinite;
	}

	@keyframes spin {
		to {
			transform: rotate(360deg);
		}
	}

	/* Site Details — pure CSS hover */
	.details-trigger-wrap {
		position: relative;
	}

	.details-trigger {
		width: 36px;
		height: 36px;
		border: 1px solid var(--border-color, #181818);
		border-radius: 3px;
		background: #0e0e0e;
		color: #808080;
		display: flex;
		align-items: center;
		justify-content: center;
		cursor: pointer;
		transition: all 0.15s ease;
	}

	.details-trigger:hover {
		background: #181818;
		color: #c0c0c0;
		border-color: #252525;
	}

	/* Tooltip: always in DOM, hidden by default, shown on hover via CSS */
	.details-tooltip {
		position: absolute;
		bottom: calc(100% + 4px);
		right: 0;
		width: 260px;
		background: #0c0c0c;
		border: 1px solid #222;
		border-radius: 3px;
		padding: 12px 14px;
		box-shadow: 0 8px 24px rgba(0, 0, 0, 0.6);
		z-index: 100;
		opacity: 0;
		visibility: hidden;
		transform: translateY(4px);
		transition:
			opacity 0.15s ease,
			transform 0.15s ease,
			visibility 0.15s ease;
		pointer-events: none;
	}

	/* Show on hover of the entire wrap (button + tooltip area) */
	.details-trigger-wrap:hover .details-tooltip {
		opacity: 1;
		visibility: visible;
		transform: translateY(0);
		pointer-events: auto;
	}

	.details-title {
		margin: 0 0 8px;
		font-size: 9px;
		font-weight: 600;
		color: #707070;
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
		gap: 7px;
		padding: 5px 0;
		border-bottom: 1px solid #151515;
	}

	.detail-row:last-child {
		border-bottom: none;
	}

	.detail-icon {
		width: 20px;
		height: 20px;
		border-radius: 2px;
		background: #131313;
		display: flex;
		align-items: center;
		justify-content: center;
		color: #505050;
		flex-shrink: 0;
	}

	.detail-key {
		flex: 1;
		font-size: 10px;
		font-weight: 500;
		color: #808080;
	}

	.detail-val {
		font-size: 10px;
		font-weight: 600;
		color: #a0a0a0;
		max-width: 120px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		text-align: right;
	}

	.detail-val.path {
		font-family: 'JetBrains Mono', 'Fira Code', monospace;
		font-size: 9px;
		color: #808080;
	}
</style>
