import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],  // The entry point we just created
  format: ['cjs', 'esm'],   // Build for both CommonJS (Node) and ESM (Modern web)
  dts: true,                // Generate .d.ts type definitions
  splitting: false,
  sourcemap: true,
  clean: true,              // Clean the dist folder before building
});