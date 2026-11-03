import { defineConfig } from 'vitest/config';

// The live test reads production and runs only with SEALKEEPER_LIVE=1.
export default defineConfig({
	test: {
		include: ['test/**/*.test.ts'],
		provide: { live: process.env.SEALKEEPER_LIVE === '1' },
	},
});
