import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    // Force Vitest to prefer Node.js exports over browser exports
    alias: [
      { find: /^@noble\/curves\/p256$/, replacement: '@noble/curves/p256' }
    ],
    server: {
      deps: {
        // Ensure these packages are processed correctly
        inline: ['@noble/curves', '@noble/hashes']
      }
    }
  },
  resolve: {
    // This is the key fix: prioritize 'node' and 'default' conditions
    conditions: ['node', 'import', 'default']
  }
});