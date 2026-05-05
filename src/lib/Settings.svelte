<script lang="ts">
	import { onMount } from 'svelte';
	import type { Settings, Stats, ChromeStorageResult, WhitelistEntry } from './types';
	import {
		Shield,
		Bell,
		ChartBar,
		ArrowCounterClockwise,
		Trash,
		Plus,
		X,
		Globe
	} from 'phosphor-svelte';

	let settings: Settings = {
		realTimeProtection: true,
		blockPhishing: true,
		blockTrackers: true,
		blockAnnoyances: true,
		linkSafetyPreview: false,
		showWarnings: true,
		autoScan: true,
		notificationLevel: 'medium',
	};

	let stats: Stats = {
		sitesScanned: 0,
		threatsBlocked: 0,
		trackersBlocked: 0,
		phishingBlocked: 0
	};

	let whitelist: WhitelistEntry[] = [];
	let newDomain: string = '';

	onMount(async (): Promise<void> => {
		try {
			if (typeof chrome !== 'undefined' && chrome.storage) {
				const syncData: ChromeStorageResult = await chrome.storage.sync.get('loxten_settings');
				if (syncData.loxten_settings) settings = { ...settings, ...syncData.loxten_settings };

				const localData = await chrome.storage.local.get(['loxten_stats', 'loxten_whitelist']);
				if (localData.loxten_stats) stats = { ...stats, ...localData.loxten_stats };
				if (localData.loxten_whitelist) whitelist = localData.loxten_whitelist;
			}
		} catch (e) {
			console.error('Failed to load settings:', e);
		}
	});

	async function saveSettings(): Promise<void> {
		try {
			if (chrome?.storage?.sync) {
				await chrome.storage.sync.set({ loxten_settings: settings });
			}
			if (chrome?.runtime?.sendMessage) {
				chrome.runtime.sendMessage({ type: 'settings_updated', settings });
			}
		} catch (e) {
			console.error('Failed to save settings:', e);
		}
	}

	function handleToggle(): void {
		saveSettings();
		if (settings.realTimeProtection !== undefined) {
			window.dispatchEvent(new CustomEvent('loxten:protection', {
				detail: { enabled: settings.realTimeProtection }
			}));
		}
	}

	function setNotificationLevel(level: 'low' | 'medium' | 'high'): void {
		settings.notificationLevel = level;
		saveSettings();
	}

	async function addToWhitelist(): Promise<void> {
		const domain = newDomain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*/, '');
		if (!domain || whitelist.some(e => e.domain === domain)) return;
		whitelist = [...whitelist, { domain, addedAt: Date.now() }];
		newDomain = '';
		try {
			if (chrome?.storage?.local) await chrome.storage.local.set({ loxten_whitelist: whitelist });
		} catch (_) {}
	}

	function handleKeydown(e: KeyboardEvent): void {
		if (e.key === 'Enter') addToWhitelist();
	}

	async function removeFromWhitelist(domain: string): Promise<void> {
		whitelist = whitelist.filter(e => e.domain !== domain);
		try {
			if (chrome?.storage?.local) await chrome.storage.local.set({ loxten_whitelist: whitelist });
		} catch (_) {}
	}

	async function resetSettings(): Promise<void> {
		settings = {
			realTimeProtection: true,
			blockPhishing: true,
			blockTrackers: true,
			blockAnnoyances: true,
			linkSafetyPreview: false,
			showWarnings: true,
			autoScan: true,
			notificationLevel: 'medium',
		};
		await saveSettings();
	}

	async function clearData(): Promise<void> {
		try {
			if (chrome?.storage) {
				await chrome.storage.local.clear();
				stats = {
					sitesScanned: 0,
					threatsBlocked: 0,
					trackersBlocked: 0,
					phishingBlocked: 0
				};
				whitelist = [];
			}
		} catch (e) {
			console.error('Failed to clear data:', e);
		}
	}

	function formatNum(n: number): string {
		if (n >= 1000) return (n / 1000).toFixed(1) + 'k';
		return n.toString();
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
				<span class="toggle-label">Block Annoyances</span>
				<input
					type="checkbox"
					class="toggle"
					bind:checked={settings.blockAnnoyances}
					on:change={handleToggle}
				/>
			</label>
			<p class="toggle-hint">Cookie banners, chat widgets, newsletter popups, push prompts.</p>
			<label class="toggle-row">
				<span class="toggle-label">Highlight Link Mismatches</span>
				<input
					type="checkbox"
					class="toggle"
					bind:checked={settings.linkSafetyPreview}
					on:change={handleToggle}
				/>
			</label>
			<p class="toggle-hint">Marks links where visible text differs from the actual destination URL.</p>
		</div>
	</section>

	<!-- Notifications -->
	<section>
		<h3 class="section-title"><Bell size={13} weight="bold" /> Warnings</h3>
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

	<!-- Whitelist -->
	<section>
		<h3 class="section-title"><Globe size={13} weight="bold" /> Trusted Sites</h3>
		<div class="input-row">
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
		color: #b0b0b0;
		text-transform: uppercase;
		letter-spacing: 0.06em;
	}

	/* Toggle rows */
	.toggle-list {
		display: flex;
		flex-direction: column;
		gap: 0;
	}

	.toggle-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 7px 0;
		border-bottom: 1px solid #131313;
		cursor: pointer;
	}

	.toggle-row:last-of-type {
		border-bottom: none;
	}

	.toggle-label {
		font-size: 12px;
		font-weight: 500;
		color: #cccccc;
	}

	.toggle-hint {
		margin: 2px 0 0;
		padding: 0;
		font-size: 10px;
		color: #888888;
		line-height: 1.4;
	}

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

	/* Segment control */
	.segment-group {
		display: flex;
		align-items: center;
		gap: 10px;
		margin-top: 10px;
	}

	.segment-label {
		font-size: 12px;
		font-weight: 500;
		color: #cccccc;
	}

	.segment {
		display: flex;
		gap: 2px;
		padding: 2px;
		background: #0e0e0e;
		border-radius: 2px;
		border: 1px solid #1a1a1a;
	}

	.seg-btn {
		padding: 5px 11px;
		border: none;
		border-radius: 2px;
		background: transparent;
		color: #999999;
		font-size: 10px;
		font-weight: 600;
		cursor: pointer;
		transition: all 0.15s ease;
		font-family: inherit;
	}

	.seg-btn:hover {
		color: #cccccc;
	}

	.seg-btn.active {
		background: #1e1e1e;
		color: #e0e0e0;
	}

	/* Input row */
	.input-row {
		display: flex;
		gap: 6px;
	}

	.text-input {
		flex: 1;
		padding: 8px 10px;
		border: 1px solid #1e1e1e;
		border-radius: 2px;
		background: #0e0e0e;
		color: #d0d0d0;
		font-size: 12px;
		font-family: inherit;
		outline: none;
		transition: border-color 0.15s ease;
	}

	.text-input::placeholder {
		color: #888888;
	}

	.text-input:focus {
		border-color: #303030;
	}

	.icon-btn {
		width: 34px;
		border: 1px solid #1e1e1e;
		border-radius: 2px;
		background: #0e0e0e;
		color: #b0b0b0;
		display: flex;
		align-items: center;
		justify-content: center;
		cursor: pointer;
		transition: all 0.15s ease;
		flex-shrink: 0;
	}

	.icon-btn:hover:not(:disabled) {
		background: #1a1a1a;
		color: #e0e0e0;
	}

	.icon-btn:disabled {
		opacity: 0.4;
		cursor: not-allowed;
	}

	/* Whitelist */
	.whitelist-items {
		display: flex;
		flex-direction: column;
		gap: 2px;
		margin-top: 8px;
	}

	.wl-item {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 6px 8px;
		background: #0e0e0e;
		border-radius: 2px;
	}

	.wl-domain {
		font-size: 11px;
		color: #bbbbbb;
		font-weight: 500;
	}

	.wl-remove {
		width: 20px;
		height: 20px;
		border: none;
		border-radius: 2px;
		background: transparent;
		color: #888888;
		display: flex;
		align-items: center;
		justify-content: center;
		cursor: pointer;
		transition: all 0.15s ease;
	}

	.wl-remove:hover {
		background: #1e1e1e;
		color: #cc4444;
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
		gap: 3px;
		padding: 10px 0;
		background: #0e0e0e;
		border-radius: 2px;
	}

	.stat-num {
		font-size: 18px;
		font-weight: 700;
		color: #e0e0e0;
		line-height: 1;
	}

	.stat-lbl {
		font-size: 9px;
		font-weight: 600;
		color: #999999;
		text-transform: uppercase;
		letter-spacing: 0.06em;
	}

	/* Actions */
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
		color: #999999;
		font-size: 11px;
		font-weight: 500;
		cursor: pointer;
		transition: all 0.15s ease;
		font-family: inherit;
	}

	.action-btn:hover {
		background: #181818;
		color: #cccccc;
		border-color: #282828;
	}
</style>
