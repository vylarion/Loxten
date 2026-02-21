<script lang="ts">
	import { onMount } from 'svelte';
	import {
		ShieldCheck,
		Globe,
		Warning,
		GearSix,
		LockSimple,
		LockSimpleOpen
	} from 'phosphor-svelte';
	import SecurityStatus from './Security.Status.svelte';
	import ThreatsList from './ThreatsList.svelte';
	import Settings from './Settings.svelte';
	import type { Threat, SecurityData, ChromeResponse, ChromeStorageResult } from './types';

	let currentUrl: string = '';
	let isHttps: boolean = false;
	let securityData: SecurityData = {
		isSecure: true,
		riskScore: 0,
		threats: [],
		trackersBlocked: 0,
		lastScan: null
	};
	let activeTab: 'security' | 'threats' | 'settings' = 'security';
	let isLoading: boolean = true;
	let extensionError: boolean = false;
	let protectionEnabled: boolean = true;

	onMount((): (() => void) => {
		// Listen for protection state changes from Settings
		window.addEventListener('loxten:protection', handleProtectionChange as EventListener);

		// Initialize data
		(async () => {
			if (typeof chrome !== 'undefined' && chrome.tabs) {
				await loadCurrentTabData();
				await loadSecurityAnalysis();
				await loadProtectionState();
			} else {
				extensionError = true;
				currentUrl = 'https://example.com';
				isHttps = true;
				securityData = {
					isSecure: true,
					riskScore: 25,
					threats: [
						{
							type: 'tracker',
							severity: 'medium',
							description: 'Sample tracker detected for demo purposes'
						}
					],
					trackersBlocked: 5,
					lastScan: new Date()
				};
				isLoading = false;
			}
		})();

		// Cleanup runs client-side only
		return () => {
			window.removeEventListener('loxten:protection', handleProtectionChange as EventListener);
		};
	});

	async function loadCurrentTabData(): Promise<void> {
		try {
			if (chrome?.tabs?.query) {
				const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
				const tab = tabs[0];
				currentUrl = tab?.url || 'Unknown';
				isHttps = currentUrl.startsWith('https://');
			}
		} catch (error) {
			console.error('Failed to get current tab:', error);
			currentUrl = 'Error loading URL';
		}
	}

	async function loadSecurityAnalysis(): Promise<void> {
		isLoading = true;
		try {
			if (chrome?.runtime?.sendMessage) {
				const response: ChromeResponse = await chrome.runtime.sendMessage({
					type: 'get_analysis',
					url: currentUrl
				});

				if (response) {
					securityData = {
						isSecure: (response.riskScore || 0) < 30,
						riskScore: response.riskScore || 0,
						threats: response.threats || [],
						trackersBlocked: response.trackersBlocked || 0,
						lastScan: response.timestamp ? new Date(response.timestamp) : new Date()
					};
				}
			}
		} catch (error) {
			console.error('Failed to load security analysis:', error);
		} finally {
			isLoading = false;
		}
	}

	async function loadProtectionState(): Promise<void> {
		try {
			if (chrome?.storage?.sync) {
				const result: ChromeStorageResult = await chrome.storage.sync.get('loxten_settings');
				if (result.loxten_settings) {
					protectionEnabled = result.loxten_settings.realTimeProtection !== false;
				}
			}
		} catch (error) {
			console.error('Failed to load protection state:', error);
		}
	}

	function handleProtectionChange(e: CustomEvent): void {
		protectionEnabled = e.detail.enabled;
	}

	async function runQuickScan(): Promise<void> {
		isLoading = true;
		try {
			if (chrome?.runtime?.sendMessage) {
				await chrome.runtime.sendMessage({
					type: 'force_scan',
					url: currentUrl
				});
				await loadSecurityAnalysis();
			} else {
				setTimeout(() => {
					securityData.riskScore = Math.floor(Math.random() * 100);
					securityData.lastScan = new Date();
					isLoading = false;
				}, 1000);
			}
		} catch (error) {
			console.error('Failed to run scan:', error);
			isLoading = false;
		}
	}

	function formatUrl(url: string): string {
		try {
			const urlObj = new URL(url);
			return urlObj.hostname;
		} catch {
			return url;
		}
	}

	function setActiveTab(tab: 'security' | 'threats' | 'settings'): void {
		activeTab = tab;
	}

	$: borderColor = protectionEnabled ? '#1a7a2e' : '#7a1a1a';
</script>

<main class="lox-popup" style="--border-color: {borderColor}">
	{#if extensionError}
		<div class="dev-bar">
			<span class="dev-dot"></span>
			Dev Mode
		</div>
	{/if}

	<!-- Header -->
	<header class="header">
		<div class="brand">
			<div class="brand-icon">
				<ShieldCheck size={16} weight="bold" />
			</div>
			<span class="brand-name">Loxten</span>
		</div>
		<div class="url-chip">
			<span class="url-lock" class:secure={isHttps}>
				{#if isHttps}
					<LockSimple size={10} weight="bold" />
				{:else}
					<LockSimpleOpen size={10} weight="bold" />
				{/if}
			</span>
			<span class="url-text" title={currentUrl}>
				{formatUrl(currentUrl)}
			</span>
		</div>
	</header>

	<!-- Content -->
	<div class="content">
		{#if isLoading}
			<div class="loader-wrap">
				<div class="loader"></div>
				<p class="loader-text">Analyzing...</p>
			</div>
		{:else}
			<!-- Tabs -->
			<nav class="tab-bar">
				<button
					class="tab"
					class:active={activeTab === 'security'}
					on:click={() => setActiveTab('security')}
				>
					<ShieldCheck size={13} weight={activeTab === 'security' ? 'fill' : 'regular'} />
					Security
				</button>
				<button
					class="tab"
					class:active={activeTab === 'threats'}
					on:click={() => setActiveTab('threats')}
				>
					<Warning size={13} weight={activeTab === 'threats' ? 'fill' : 'regular'} />
					Threats
					{#if securityData.threats.length > 0}
						<span class="tab-badge">{securityData.threats.length}</span>
					{/if}
				</button>
				<button
					class="tab"
					class:active={activeTab === 'settings'}
					on:click={() => setActiveTab('settings')}
				>
					<GearSix size={13} weight={activeTab === 'settings' ? 'fill' : 'regular'} />
					Settings
				</button>
			</nav>

			<!-- Tab content -->
			<div class="tab-panel">
				{#if activeTab === 'security'}
					<SecurityStatus {securityData} {runQuickScan} {currentUrl} {isHttps} />
				{:else if activeTab === 'threats'}
					<ThreatsList threats={securityData.threats} />
				{:else if activeTab === 'settings'}
					<Settings />
				{/if}
			</div>
		{/if}
	</div>

	<!-- Footer -->
	<footer class="footer">
		{#if securityData.lastScan}
			<span class="scan-time">Last scan: {securityData.lastScan.toLocaleTimeString()}</span>
		{/if}
	</footer>
</main>

<style>
	.lox-popup {
		width: 380px;
		min-height: 520px;
		font-family:
			'Inter',
			-apple-system,
			BlinkMacSystemFont,
			'Segoe UI',
			system-ui,
			sans-serif;
		background: #050505;
		color: #d4d4d4;
		display: flex;
		flex-direction: column;
		overflow: visible;
	}

	/* Dev bar */
	.dev-bar {
		display: flex;
		align-items: center;
		gap: 6px;
		padding: 6px 16px;
		background: #0a0a0a;
		border-bottom: 1px solid #141414;
		font-size: 10px;
		font-weight: 500;
		color: #707070;
		letter-spacing: 0.04em;
		text-transform: uppercase;
	}

	.dev-dot {
		width: 5px;
		height: 5px;
		border-radius: 50%;
		background: #606060;
	}

	/* Header */
	.header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 16px 20px;
		border-bottom: 1px solid #141414;
	}

	.brand {
		display: flex;
		align-items: center;
		gap: 10px;
	}

	.brand-icon {
		width: 28px;
		height: 28px;
		border-radius: 2px;
		background: #141414;
		border: 1px solid var(--border-color, #181818);
		display: flex;
		align-items: center;
		justify-content: center;
		color: #a0a0a0;
		flex-shrink: 0;
	}

	.brand-name {
		font-size: 15px;
		font-weight: 700;
		color: #e5e5e5;
		letter-spacing: -0.02em;
	}

	.url-chip {
		display: flex;
		align-items: center;
		gap: 6px;
		padding: 6px 12px;
		border-radius: 3px;
		background: #0e0e0e;
		border: 1px solid var(--border-color, #181818);
		font-size: 11px;
		color: #808080;
		max-width: 170px;
		overflow: hidden;
	}

	.url-lock {
		display: flex;
		align-items: center;
		color: #606060;
		flex-shrink: 0;
	}

	.url-lock.secure {
		color: #a0a0a0;
	}

	.url-text {
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	/* Content area */
	.content {
		flex: 1;
		display: flex;
		flex-direction: column;
		overflow: visible;
	}

	/* Loading */
	.loader-wrap {
		flex: 1;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: 14px;
	}

	.loader {
		width: 24px;
		height: 24px;
		border: 2px solid #1a1a1a;
		border-top-color: #606060;
		border-radius: 50%;
		animation: spin 0.8s linear infinite;
	}

	@keyframes spin {
		to {
			transform: rotate(360deg);
		}
	}

	.loader-text {
		font-size: 11px;
		color: #606060;
		font-weight: 500;
		margin: 0;
		letter-spacing: 0.02em;
	}

	/* Tabs */
	.tab-bar {
		display: flex;
		gap: 2px;
		margin: 16px 20px 0;
		padding: 3px;
		background: #0a0a0a;
		border-radius: 3px;
		border: 1px solid var(--border-color, #181818);
	}

	.tab {
		flex: 1;
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 5px;
		padding: 9px 0;
		border: none;
		border-radius: 2px;
		background: transparent;
		color: #606060;
		font-size: 11px;
		font-weight: 600;
		cursor: pointer;
		transition: all 0.15s ease;
		position: relative;
		font-family: inherit;
	}

	.tab:hover {
		color: #909090;
	}

	.tab.active {
		background: #181818;
		color: #d4d4d4;
	}

	.tab-badge {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-width: 15px;
		height: 15px;
		padding: 0 4px;
		border-radius: 2px;
		background: #ffffff;
		color: #000000;
		font-size: 9px;
		font-weight: 700;
	}

	/* Tab content */
	.tab-panel {
		flex: 1;
		padding: 20px;
		overflow: visible;
	}

	.tab-panel::-webkit-scrollbar {
		width: 3px;
	}

	.tab-panel::-webkit-scrollbar-track {
		background: transparent;
	}

	.tab-panel::-webkit-scrollbar-thumb {
		background: #1e1e1e;
		border-radius: 2px;
	}

	/* Footer */
	.footer {
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 10px 20px;
		border-top: 1px solid #141414;
		font-size: 11px;
	}

	.scan-time {
		color: #505050;
		font-weight: 500;
		font-size: 10px;
	}
</style>
