<script lang="ts">
	import type { Threat, SecurityData } from './types';
	import {
		ShieldWarning,
		EyeSlash,
		LockSimple,
		FishSimple,
		Eye,
		CheckCircle,
		XCircle,
		Certificate,
		ClockCounterClockwise,
		Warning,
		CaretDown,
		ShieldCheck
	} from 'phosphor-svelte';

	export let securityData: SecurityData;
	export let isHttps: boolean = false;

	let headersExpanded: boolean = false;

	function getGrade(riskScore: number): string {
		if (riskScore < 20) return 'A+';
		if (riskScore < 30) return 'A';
		if (riskScore < 40) return 'B';
		if (riskScore < 60) return 'C';
		if (riskScore < 80) return 'D';
		return 'F';
	}

	function formatDomainAge(days: number): string {
		if (days >= 365) return `${Math.floor(days / 365)}y ${Math.floor((days % 365) / 30)}mo`;
		if (days >= 30) return `${Math.floor(days / 30)}mo`;
		return `${days}d`;
	}

	function formatThreatType(type: string): string {
		return type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
	}

	$: grade = getGrade(securityData.riskScore);
	$: safeScore = 100 - securityData.riskScore;
	$: dashOffset = 251.2 - (251.2 * safeScore) / 100;
	$: headerGrade = securityData.headerAudit?.grade || '—';
	$: domainAgeDays = securityData.domainAge?.ageDays;
	$: hasThreats = securityData.threats.length > 0;
	$: isWhitelisted = securityData.whitelisted === true;
</script>

<div class="status">
	<!-- Score -->
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
				{#if isWhitelisted}
					<ShieldCheck size={14} weight="fill" />
					Trusted Site
				{:else if securityData.isSecure}
					<CheckCircle size={14} weight="fill" />
					Site Looks Safe
				{:else}
					<XCircle size={14} weight="fill" />
					Issues Detected
				{/if}
			</h3>
			<p class="score-desc">
				{#if isWhitelisted}
					This domain is on your trusted sites list. Analysis is bypassed.
				{:else if securityData.riskScore < 30}
					No major concerns for this site.
				{:else if securityData.riskScore < 60}
					Some potential issues — review below.
				{:else}
					High risk — proceed with caution.
				{/if}
			</p>
		</div>
	</div>

	<!-- Key Metrics -->
	<div class="metrics-row">
		<div class="metric">
			<div class="metric-icon"><EyeSlash size={13} /></div>
			<span class="metric-val">{securityData.trackersBlocked}</span>
			<span class="metric-lbl">Trackers Blocked</span>
		</div>
		<div class="metric-divider"></div>
		<div class="metric">
			<div class="metric-icon"><Certificate size={13} /></div>
			<span class="metric-val">{headerGrade}</span>
			<span class="metric-lbl">Header Grade</span>
		</div>
		<div class="metric-divider"></div>
		<div class="metric">
			<div class="metric-icon"><LockSimple size={13} /></div>
			<span class="metric-val">{isHttps ? 'Yes' : 'No'}</span>
			<span class="metric-lbl">HTTPS</span>
		</div>
		{#if domainAgeDays !== undefined && domainAgeDays !== null}
			<div class="metric-divider"></div>
			<div class="metric">
				<div class="metric-icon"><ClockCounterClockwise size={13} /></div>
				<span class="metric-val" class:warn-val={domainAgeDays < 30}>{formatDomainAge(domainAgeDays)}</span>
				<span class="metric-lbl">Domain Age</span>
			</div>
		{/if}
	</div>

	<!-- Threats (inline) -->
	{#if hasThreats}
		<div class="section-card threats-section">
			<h4 class="section-label">
				<ShieldWarning size={12} weight="bold" />
				{securityData.threats.length} Threat{securityData.threats.length !== 1 ? 's' : ''} Found
			</h4>
			<div class="threats-list">
				{#each securityData.threats as threat}
					<div class="threat-item" class:high={threat.severity === 'high' || threat.severity === 'critical'}>
						<div class="threat-header">
							<span class="threat-type">{formatThreatType(threat.type)}</span>
							<span class="threat-severity sev-{threat.severity}">{threat.severity}</span>
						</div>
						<p class="threat-desc">{threat.description}</p>
					</div>
				{/each}
			</div>
		</div>
	{/if}

	<!-- Security Headers (collapsible) -->
	{#if securityData.headerAudit}
		<div class="section-card">
			<button class="section-toggle" on:click={() => headersExpanded = !headersExpanded}>
				<h4 class="section-label">
					<Certificate size={12} weight="bold" />
					Security Headers
					<span class="grade-badge grade-{headerGrade.replace('+', 'plus')}">{headerGrade}</span>
				</h4>
				<CaretDown size={12} class="toggle-caret {headersExpanded ? 'open' : ''}" />
			</button>
			{#if headersExpanded}
				<div class="headers-list">
					{#each securityData.headerAudit.checks as check}
						<div class="header-row">
							<div class="header-status">
								{#if check.status === 'pass'}
									<CheckCircle size={12} weight="fill" />
								{:else}
									<XCircle size={12} weight="fill" />
								{/if}
							</div>
							<span class="header-name">{check.name}</span>
							<span class="header-detail" class:fail={check.status === 'fail'} title={check.detail}>{check.detail}</span>
						</div>
					{/each}
				</div>
			{/if}
		</div>
	{/if}
</div>

<style>
	.status {
		display: flex;
		flex-direction: column;
		gap: 10px;
	}

	/* Score card */
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
		stroke: #a0a0a0;
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
		color: #f0f0f0;
		line-height: 1;
		letter-spacing: -0.03em;
	}

	.ring-score {
		font-size: 9px;
		color: #a0a0a0;
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
		color: #e8e8e8;
	}

	.score-desc {
		margin: 0;
		font-size: 11px;
		color: #b0b0b0;
		line-height: 1.4;
	}

	/* Metrics row */
	.metrics-row {
		display: flex;
		align-items: center;
		background: #0a0a0a;
		border: 1px solid var(--border-color, #181818);
		border-radius: 3px;
		padding: 10px 0;
	}

	.metric {
		flex: 1;
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 3px;
	}

	.metric-icon {
		color: #a0a0a0;
	}

	.metric-val {
		font-size: 15px;
		font-weight: 700;
		color: #e0e0e0;
		line-height: 1;
	}

	.metric-val.warn-val {
		color: #e8a040;
	}

	.metric-lbl {
		font-size: 9px;
		color: #a0a0a0;
		text-transform: uppercase;
		font-weight: 600;
		letter-spacing: 0.04em;
	}

	.metric-divider {
		width: 1px;
		height: 24px;
		background: #1a1a1a;
	}

	/* Section cards */
	.section-card {
		background: #0a0a0a;
		border: 1px solid var(--border-color, #181818);
		border-radius: 3px;
		padding: 12px 14px;
	}

	.section-label {
		margin: 0;
		font-size: 10px;
		font-weight: 600;
		color: #b0b0b0;
		text-transform: uppercase;
		letter-spacing: 0.06em;
		display: flex;
		align-items: center;
		gap: 6px;
	}

	/* Threats */
	.threats-section {
		border-color: #2a1a1a;
	}

	.threats-section .section-label {
		color: #e0a050;
		margin-bottom: 10px;
	}

	.threats-list {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}

	.threat-item {
		padding: 10px 12px;
		background: #0e0e0e;
		border-radius: 3px;
		border-left: 3px solid #555555;
	}

	.threat-item.high {
		border-left-color: #cc4444;
	}

	.threat-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		margin-bottom: 4px;
	}

	.threat-type {
		font-size: 12px;
		font-weight: 600;
		color: #dddddd;
	}

	.threat-severity {
		font-size: 9px;
		font-weight: 700;
		text-transform: uppercase;
		letter-spacing: 0.06em;
		padding: 2px 7px;
		border-radius: 2px;
		background: #161616;
		border: 1px solid #1e1e1e;
	}

	.sev-low {
		color: #b0b0b0;
	}

	.sev-medium {
		color: #e0a050;
	}

	.sev-high, .sev-critical {
		color: #cc4444;
	}

	.threat-desc {
		margin: 0;
		font-size: 11px;
		color: #aaaaaa;
		line-height: 1.5;
	}

	/* Headers toggle */
	.section-toggle {
		display: flex;
		align-items: center;
		justify-content: space-between;
		width: 100%;
		background: none;
		border: none;
		padding: 0;
		cursor: pointer;
		font-family: inherit;
		color: inherit;
	}

	.section-toggle :global(.toggle-caret) {
		color: #888888;
		transition: transform 0.2s ease;
	}

	.section-toggle :global(.toggle-caret.open) {
		transform: rotate(180deg);
	}

	/* Grade badge */
	.grade-badge {
		font-size: 10px;
		font-weight: 700;
		padding: 2px 6px;
		border-radius: 2px;
		margin-left: auto;
		margin-right: 6px;
	}

	.grade-Aplus, :global(.grade-A) {
		background: #0e1a0e;
		color: #4ade80;
		border: 1px solid #1a2e1a;
	}

	.grade-B {
		background: #1a1a0e;
		color: #a0c060;
		border: 1px solid #2e2e1a;
	}

	.grade-C {
		background: #1a1a0a;
		color: #e8a040;
		border: 1px solid #2e2a1a;
	}

	.grade-D, .grade-F {
		background: #1a0e0e;
		color: #e06060;
		border: 1px solid #2e1a1a;
	}

	/* Headers list */
	.headers-list {
		display: flex;
		flex-direction: column;
		gap: 4px;
		margin-top: 10px;
		padding-top: 10px;
		border-top: 1px solid #151515;
	}

	.header-row {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 4px 0;
	}

	.header-status {
		flex-shrink: 0;
		display: flex;
		align-items: center;
		color: #4ade80;
	}

	.header-row:has(.header-detail.fail) .header-status {
		color: #666666;
	}

	.header-name {
		font-size: 11px;
		font-weight: 600;
		color: #cccccc;
		min-width: 100px;
	}

	.header-detail {
		flex: 1;
		font-size: 10px;
		color: #999999;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		text-align: right;
	}

	.header-detail.fail {
		color: #b08860;
	}
</style>
