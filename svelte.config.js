import adapter from 'sveltekit-adapter-chrome-extension';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: vitePreprocess(),

	kit: {
		adapter: adapter({
			// Remove fallback for popup - not needed for Chrome extensions
			// Chrome extensions don't use traditional routing
			pages: 'build',
			assets: 'build',
			fallback: undefined,
			precompress: false,
			strict: true,
			// Simple fix to prevent underscore files
			emitTypes: false
		}),
		
		// Prevent files with underscore prefixes
		appDir: 'app',
		inlineStyleThreshold: 0,
		
		// Disable service worker for Chrome extension
		serviceWorker: {
			register: false
		},
		
		// Optimize for extension popup size constraints
		prerender: {
			handleHttpError: 'warn'
		}
	},

	};

export default config;