<script lang="ts">
	import { onMount } from 'svelte';
	import type { Settings, Stats, ChromeStorageResult, WhitelistEntry, BreachResult } from './types';
	import {
		Shield,
		Bell,
		ChartBar,
		GearSix,
		ArrowCounterClockwise,
		Trash,
		EnvelopeSimple,
		MagnifyingGlass,
		Plus,
		X,
		Globe,
		Info
	} from 'phosphor-svelte';

	let settings: Settings = {
		realTimeProtection: true,
		blockMaliciousSites: true,
		blockPhishing: true,
		blockTrackers: true,
		blockCryptominers: true,
		showWarnings: true,
		autoScan: true,
		notificationLevel: 'medium',
		scanFrequency: 'realtime',
		whitelistMode: false
	};

	let stats: Stats = {
		sitesScanned: 0,
		threatsBlocked: 0,
		trackersBlocked: 0,
		malwareDetected: 0,
		phishingBlocked: 0
	};

	let whitelist: WhitelistEntry[] = [];
	let newDomain: string = '';
	let breachEmail: string = '';
	let breachResult: BreachResult | null = null;
	let breachChecking: boolean = false;

	let isExtension = false;

	onMount(async () => {
		isExtension = typeof chrome !== 'undefined' && !!chrome.storage;

		if (isExtension) {
			await loadSettings();
			await loadStats();
			await loadWhitelist();
			await loadBreachResult();
		}
	});

	async function loadSettings(): Promise<void> {
		try {
			if (chrome?.storage?.sync) {
				const result: ChromeStorageResult = await chrome.storage.sync.get('loxten_settings');
				if (result.loxten_settings) {
					settings = { ...settings, ...result.loxten_settings };
				}
			}
		} catch (error) {
			console.error('Failed to load settings:', error);
		}
	}

	async function loadStats(): Promise<void> {
		try {
			if (chrome?.storage?.local) {
				const result: ChromeStorageResult = await chrome.storage.local.get('loxten_stats');
				if (result.loxten_stats) {
					stats = { ...stats, ...result.loxten_stats };
				}
			}
		} catch (error) {
			console.error('Failed to load stats:', error);
		}
	}

	async function loadWhitelist(): Promise<void> {
		try {
			if (chrome?.storage?.sync) {
				const result: ChromeStorageResult = await chrome.storage.sync.get('loxten_whitelist');
				if (result.loxten_whitelist) {
					whitelist = result.loxten_whitelist;
				}
			}
		} catch (error) {
			console.error('Failed to load whitelist:', error);
		}
	}

	async function loadBreachResult(): Promise<void> {
		try {
			if (chrome?.storage?.local) {
				const result: ChromeStorageResult = await chrome.storage.local.get('loxten_breach');
				if (result.loxten_breach) {
					breachResult = result.loxten_breach;
					breachEmail = result.loxten_breach.email;
				}
			}
		} catch (error) {
			console.error('Failed to load breach result:', error);
		}
	}

	async function saveSettings(): Promise<void> {
		try {
			if (isExtension && chrome?.storage?.sync) {
				await chrome.storage.sync.set({ loxten_settings: settings });
			}
			if (isExtension && chrome?.runtime?.sendMessage) {
				await chrome.runtime.sendMessage({ type: 'settings_updated', settings });
			}
		} catch (error) {
			console.error('Failed to save settings:', error);
		}
	}

	async function saveWhitelist(): Promise<void> {
		try {
			if (isExtension && chrome?.storage?.sync) {
				await chrome.storage.sync.set({ loxten_whitelist: whitelist });
			}
		} catch (error) {
			console.error('Failed to save whitelist:', error);
		}
	}

	async function addToWhitelist(): Promise<void> {
		const domain = newDomain
			.trim()
			.toLowerCase()
			.replace(/^https?:\/\//, '')
			.replace(/\/+$/, '');
		if (!domain) return;
		if (whitelist.some((w) => w.domain === domain)) return;

		whitelist = [...whitelist, { domain, addedAt: Date.now() }];
		newDomain = '';
		await saveWhitelist();
	}

	async function removeFromWhitelist(domain: string): Promise<void> {
		whitelist = whitelist.filter((w) => w.domain !== domain);
		await saveWhitelist();
	}

	async function checkBreach(): Promise<void> {
		if (!breachEmail.trim()) return;
		breachChecking = true;

		// Placeholder — will connect to HIBP API in backend phase
		setTimeout(() => {
			breachResult = {
				email: breachEmail,
				breached: false,
				breachCount: 0,
				lastChecked: Date.now()
			};
			breachChecking = false;
		}, 1200);
	}

	async function resetSettings(): Promise<void> {
		settings = {
			realTimeProtection: true,
			blockMaliciousSites: true,
			blockPhishing: true,
			blockTrackers: true,
			blockCryptominers: true,
			showWarnings: true,
			autoScan: true,
			notificationLevel: 'medium',
			scanFrequency: 'realtime',
			whitelistMode: false
		};
		await saveSettings();
	}

	async function clearData(): Promise<void> {
		if (confirm('This will clear all saved scan history and statistics. Continue?')) {
			try {
				if (isExtension && chrome?.storage?.local) {
					await chrome.storage.local.clear();
				}
				stats = {
					sitesScanned: 0,
					threatsBlocked: 0,
					trackersBlocked: 0,
					malwareDetected: 0,
					phishingBlocked: 0
				};
				breachResult = null;
			} catch (error) {
				console.error('Failed to clear data:', error);
			}
		}
	}

	function handleToggle(): void {
		saveSettings();
		// Notify Hero.svelte about protection state change
		if (typeof window !== 'undefined') {
			window.dispatchEvent(
				new CustomEvent('loxten:protection', {
					detail: { enabled: settings.realTimeProtection }
				})
			);
		}
	}

	function setNotificationLevel(level: 'low' | 'medium' | 'high'): void {
		settings.notificationLevel = level;
		saveSettings();
	}

	function setScanFrequency(freq: 'realtime' | 'periodic' | 'manual'): void {
		settings.scanFrequency = freq;
		saveSettings();
	}

	function formatNum(n: number): string {
		if (n >= 1000) return (n / 1000).toFixed(1) + 'k';
		return n.toString();
	}

	function handleKeydown(e: KeyboardEvent): void {
		if (e.key === 'Enter') addToWhitelist();
	}
</script>

<div class="settings">
	<!-- Protection -->
	<section>
		<h3 class="section-title"><Shield size={13} weight="bold" /> Protection</h3>
		<div class="toggle-list">
			<label class="toggle-row">
				<span class="toggle-label">Real-Time Protection</span>
				<input
					type="checkbox"
					class="toggle"
					bind:checked={settings.realTimeProtection}
					on:change={handleToggle}
				/>
			</label>
			<label class="toggle-row">
				<span class="toggle-label">Block Malicious Sites</span>
				<input
					type="checkbox"
					class="toggle"
					bind:checked={settings.blockMaliciousSites}
					on:change={handleToggle}
				/>
			</label>
			<label class="toggle-row">
				<span class="toggle-label">Block Phishing</span>
				<input
					type="checkbox"
					class="toggle"
					bind:checked={settings.blockPhishing}
					on:change={handleToggle}
				/>
			</label>
			<label class="toggle-row">
				<span class="toggle-label">Block Trackers</span>
				<input
					type="checkbox"
					class="toggle"
					bind:checked={settings.blockTrackers}
					on:change={handleToggle}
				/>
			</label>
			<label class="toggle-row">
				<span class="toggle-label">Block Cryptominers</span>
				<input
					type="checkbox"
					class="toggle"
					bind:checked={settings.blockCryptominers}
					on:change={handleToggle}
				/>
			</label>
		</div>
	</section>

	<!-- Notifications -->
	<section>
		<h3 class="section-title"><Bell size={13} weight="bold" /> Notifications</h3>
		<div class="toggle-list">
			<label class="toggle-row">
				<span class="toggle-label">Show Warnings</span>
				<input
					type="checkbox"
					class="toggle"
					bind:checked={settings.showWarnings}
					on:change={handleToggle}
				/>
			</label>
		</div>
		<div class="segment-group">
			<span class="segment-label">Alert Level</span>
			<div class="segment">
				<button
					class="seg-btn"
					class:active={settings.notificationLevel === 'low'}
					on:click={() => setNotificationLevel('low')}>Low</button
				>
				<button
					class="seg-btn"
					class:active={settings.notificationLevel === 'medium'}
					on:click={() => setNotificationLevel('medium')}>Med</button
				>
				<button
					class="seg-btn"
					class:active={settings.notificationLevel === 'high'}
					on:click={() => setNotificationLevel('high')}>High</button
				>
			</div>
		</div>
	</section>

	<!-- Scanning -->
	<section>
		<h3 class="section-title"><GearSix size={13} weight="bold" /> Scanning</h3>
		<div class="toggle-list">
			<label class="toggle-row">
				<span class="toggle-label">Auto Scan</span>
				<input
					type="checkbox"
					class="toggle"
					bind:checked={settings.autoScan}
					on:change={handleToggle}
				/>
			</label>
		</div>
		<div class="segment-group">
			<span class="segment-label">Frequency</span>
			<div class="segment">
				<button
					class="seg-btn"
					class:active={settings.scanFrequency === 'realtime'}
					on:click={() => setScanFrequency('realtime')}>Live</button
				>
				<button
					class="seg-btn"
					class:active={settings.scanFrequency === 'periodic'}
					on:click={() => setScanFrequency('periodic')}>Periodic</button
				>
				<button
					class="seg-btn"
					class:active={settings.scanFrequency === 'manual'}
					on:click={() => setScanFrequency('manual')}>Manual</button
				>
			</div>
		</div>
	</section>

	<!-- Breach Check -->
	<section>
		<h3 class="section-title"><EnvelopeSimple size={13} weight="bold" /> Breach Check</h3>
		<p class="section-desc">Check if your email has appeared in known data breaches.</p>
		<div class="breach-input-row">
			<input
				type="email"
				class="text-input"
				placeholder="you@example.com"
				bind:value={breachEmail}
				on:keydown={(e) => {
					if (e.key === 'Enter') checkBreach();
				}}
			/>
			<button
				class="icon-btn"
				on:click={checkBreach}
				disabled={breachChecking || !breachEmail.trim()}
			>
				{#if breachChecking}
					<div class="mini-spin"></div>
				{:else}
					<MagnifyingGlass size={13} weight="bold" />
				{/if}
			</button>
		</div>
		{#if breachResult}
			<div class="breach-result">
				{#if breachResult.breached}
					<span class="breach-warn"
						>Found in {breachResult.breachCount} breach{breachResult.breachCount !== 1
							? 'es'
							: ''}</span
					>
				{:else}
					<span class="breach-safe">No breaches found</span>
				{/if}
			</div>
		{/if}
	</section>

	<!-- Whitelist -->
	<section>
		<h3 class="section-title"><Globe size={13} weight="bold" /> Trusted Sites</h3>
		<p class="section-desc">Whitelisted domains will not be scanned.</p>
		<div class="breach-input-row">
			<input
				type="text"
				class="text-input"
				placeholder="example.com"
				bind:value={newDomain}
				on:keydown={handleKeydown}
			/>
			<button class="icon-btn" on:click={addToWhitelist} disabled={!newDomain.trim()}>
				<Plus size={13} weight="bold" />
			</button>
		</div>
		{#if whitelist.length > 0}
			<div class="whitelist-items">
				{#each whitelist as entry}
					<div class="wl-item">
						<span class="wl-domain">{entry.domain}</span>
						<button class="wl-remove" on:click={() => removeFromWhitelist(entry.domain)}>
							<X size={10} weight="bold" />
						</button>
					</div>
				{/each}
			</div>
		{/if}
	</section>

	<!-- Stats -->
	<section>
		<h3 class="section-title"><ChartBar size={13} weight="bold" /> Statistics</h3>
		<div class="stats-grid">
			<div class="stat-box">
				<span class="stat-num">{formatNum(stats.sitesScanned)}</span>
				<span class="stat-lbl">Scanned</span>
			</div>
			<div class="stat-box">
				<span class="stat-num">{formatNum(stats.threatsBlocked)}</span>
				<span class="stat-lbl">Threats</span>
			</div>
			<div class="stat-box">
				<span class="stat-num">{formatNum(stats.trackersBlocked)}</span>
				<span class="stat-lbl">Trackers</span>
			</div>
			<div class="stat-box">
				<span class="stat-num">{formatNum(stats.phishingBlocked)}</span>
				<span class="stat-lbl">Phishing</span>
			</div>
		</div>
	</section>

	<!-- About -->
	<section>
		<h3 class="section-title"><Info size={13} weight="bold" /> About</h3>
		<div class="about-rows">
			<div class="about-row">
				<span class="about-key">Version</span>
				<span class="about-val">1.0.0</span>
			</div>
			<div class="about-row">
				<span class="about-key">Engine</span>
				<span class="about-val">Loxten Core</span>
			</div>
		</div>
	</section>

	<!-- Actions -->
	<div class="actions">
		<button class="action-btn" on:click={resetSettings}>
			<ArrowCounterClockwise size={11} weight="bold" />
			Reset
		</button>
		<button class="action-btn" on:click={clearData}>
			<Trash size={11} weight="bold" />
			Clear Data
		</button>
	</div>
</div>

<style>
	.settings {
		display: flex;
		flex-direction: column;
		gap: 14px;
	}

	/* Section */
	section {
		background: #0a0a0a;
		border: 1px solid var(--border-color, #181818);
		border-radius: 3px;
		padding: 14px 16px;
	}

	.section-title {
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

	.section-desc {
		margin: 0 0 12px;
		font-size: 11px;
		color: #707070;
		line-height: 1.5;
	}

	/* Toggle rows */
	.toggle-list {
		display: flex;
		flex-direction: column;
	}

	.toggle-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 9px 0;
		border-bottom: 1px solid #131313;
		cursor: pointer;
	}

	.toggle-row:last-child {
		border-bottom: none;
	}

	.toggle-label {
		font-size: 12px;
		font-weight: 500;
		color: #9a9a9a;
	}

	/* Custom toggle switch */
	.toggle {
		-webkit-appearance: none;
		-moz-appearance: none;
		appearance: none;
		width: 34px;
		height: 18px;
		border-radius: 9px;
		background: #1e1e1e;
		position: relative;
		cursor: pointer;
		transition: background 0.2s ease;
		flex-shrink: 0;
		margin: 0;
		border: none;
	}

	.toggle::before {
		content: '';
		position: absolute;
		top: 2px;
		left: 2px;
		width: 14px;
		height: 14px;
		border-radius: 50%;
		background: #505050;
		transition: all 0.2s ease;
	}

	.toggle:checked {
		background: #353535;
	}

	.toggle:checked::before {
		transform: translateX(16px);
		background: #d4d4d4;
	}

	/* Segment controls */
	.segment-group {
		display: flex;
		align-items: center;
		justify-content: space-between;
		margin-top: 12px;
		padding-top: 12px;
		border-top: 1px solid #131313;
	}

	.segment-label {
		font-size: 12px;
		font-weight: 500;
		color: #9a9a9a;
	}

	.segment {
		display: flex;
		gap: 2px;
		padding: 2px;
		background: #131313;
		border-radius: 3px;
	}

	.seg-btn {
		padding: 5px 11px;
		border: none;
		border-radius: 2px;
		background: transparent;
		color: #606060;
		font-size: 10px;
		font-weight: 600;
		cursor: pointer;
		transition: all 0.15s ease;
		font-family: inherit;
	}

	.seg-btn:hover {
		color: #909090;
	}

	.seg-btn.active {
		background: #212121;
		color: #d4d4d4;
	}

	/* Text input (shared for breach + whitelist) */
	.breach-input-row {
		display: flex;
		gap: 6px;
	}

	.text-input {
		flex: 1;
		padding: 8px 12px;
		border: 1px solid #1e1e1e;
		border-radius: 2px;
		background: #080808;
		color: #c0c0c0;
		font-size: 12px;
		font-family: inherit;
		outline: none;
		transition: border-color 0.15s ease;
	}

	.text-input::placeholder {
		color: #505050;
	}

	.text-input:focus {
		border-color: #303030;
	}

	.icon-btn {
		width: 34px;
		height: 34px;
		border: 1px solid #1e1e1e;
		border-radius: 2px;
		background: #0e0e0e;
		color: #808080;
		display: flex;
		align-items: center;
		justify-content: center;
		cursor: pointer;
		transition: all 0.15s ease;
		flex-shrink: 0;
	}

	.icon-btn:hover:not(:disabled) {
		background: #181818;
		color: #c0c0c0;
		border-color: #282828;
	}

	.icon-btn:disabled {
		opacity: 0.4;
		cursor: not-allowed;
	}

	.mini-spin {
		width: 11px;
		height: 11px;
		border: 2px solid #252525;
		border-top-color: #707070;
		border-radius: 50%;
		animation: spin 0.7s linear infinite;
	}

	@keyframes spin {
		to {
			transform: rotate(360deg);
		}
	}

	/* Breach result */
	.breach-result {
		margin-top: 10px;
		padding: 8px 12px;
		background: #080808;
		border: 1px solid #1a1a1a;
		border-radius: 2px;
		font-size: 11px;
		font-weight: 500;
	}

	.breach-safe {
		color: #909090;
	}

	.breach-warn {
		color: #d0d0d0;
		font-weight: 600;
	}

	/* Whitelist items */
	.whitelist-items {
		display: flex;
		flex-direction: column;
		gap: 4px;
		margin-top: 10px;
		max-height: 120px;
		overflow-y: auto;
	}

	.whitelist-items::-webkit-scrollbar {
		width: 3px;
	}

	.whitelist-items::-webkit-scrollbar-thumb {
		background: #1e1e1e;
		border-radius: 2px;
	}

	.wl-item {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 6px 10px;
		background: #080808;
		border: 1px solid #161616;
		border-radius: 2px;
	}

	.wl-domain {
		font-size: 11px;
		color: #909090;
		font-weight: 500;
	}

	.wl-remove {
		width: 20px;
		height: 20px;
		border: none;
		border-radius: 2px;
		background: transparent;
		color: #505050;
		display: flex;
		align-items: center;
		justify-content: center;
		cursor: pointer;
		transition: all 0.15s ease;
	}

	.wl-remove:hover {
		background: #1e1e1e;
		color: #a0a0a0;
	}

	/* Stats grid */
	.stats-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 6px;
	}

	.stat-box {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 2px;
		padding: 12px;
		background: #070707;
		border: 1px solid #141414;
		border-radius: 2px;
	}

	.stat-num {
		font-size: 18px;
		font-weight: 700;
		color: #d0d0d0;
		line-height: 1;
	}

	.stat-lbl {
		font-size: 9px;
		font-weight: 600;
		color: #606060;
		text-transform: uppercase;
		letter-spacing: 0.06em;
	}

	/* About */
	.about-rows {
		display: flex;
		flex-direction: column;
		gap: 0;
	}

	.about-row {
		display: flex;
		justify-content: space-between;
		padding: 7px 0;
		border-bottom: 1px solid #131313;
	}

	.about-row:last-child {
		border-bottom: none;
	}

	.about-key {
		font-size: 12px;
		color: #9a9a9a;
		font-weight: 500;
	}

	.about-val {
		font-size: 12px;
		color: #707070;
		font-weight: 500;
	}

	/* Action buttons */
	.actions {
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
		border-radius: 2px;
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
