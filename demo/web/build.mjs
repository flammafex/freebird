import { build } from 'esbuild';
import { copyFile, mkdir, readFile, readdir, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const root = fileURLToPath(new URL('.', import.meta.url));
const dist = join(root, 'dist');
// Clear the generated `dist` directory so that stale files are not deployed.
await rm(dist, { recursive: true, force: true });
await mkdir(join(dist, 'assets/workers'), { recursive: true });
await build({
  absWorkingDir: root,
  entryPoints: ['src/main.mjs'],
  outfile: 'dist/assets/app.js',
  bundle: true,
  // Resolve the shared client's peer from `demo/web/node_modules` so that the bundle uses the pinned copy.
  nodePaths: [join(root, 'node_modules')],
  format: 'esm',
  platform: 'browser',
  target: ['chrome120', 'firefox128'],
  minify: true,
  legalComments: 'eof',
  logLevel: 'info',
});
for (const [source, destination] of [
  ['public/index.html', 'index.html'],
  ['public/favicon.svg', 'favicon.svg'],
  ['public/demo.css', 'assets/demo.css'],
  ['node_modules/altcha/dist/external/altcha.css', 'assets/altcha.css'],
  ['node_modules/altcha/dist/workers/pbkdf2.js', 'assets/workers/pbkdf2.js'],
  ['node_modules/altcha/dist/workers/sha.js', 'assets/workers/sha.js'],
]) {
  await copyFile(join(root, source), join(dist, destination));
}

// Copy license and notice files so that they are distributed with the dependencies in the bundle.
const lock = JSON.parse(await readFile(join(root, 'package-lock.json'), 'utf8'));
for (const packagePath of Object.keys(lock.packages).filter(path => path.startsWith('node_modules/'))) {
  let files;
  try {
    files = await readdir(join(root, packagePath), { withFileTypes: true });
  } catch (error) {
    if (error.code === 'ENOENT') continue; // Skip optional packages that were not installed on this platform.
    throw error;
  }
  for (const file of files.filter(entry => entry.isFile() && /^(license|licence|notice|copying)([.-]|$)/i.test(entry.name))) {
    const destination = join(dist, 'licenses', packagePath.slice('node_modules/'.length));
    await mkdir(destination, { recursive: true });
    await copyFile(join(root, packagePath, file.name), join(destination, file.name));
  }
}

// Reject dynamic code and inline assets that the demo's Content Security Policy does not allow.
// Run the browser smoke test to check that the policy works with the built files.
for (const relative of ['assets/app.js', 'assets/workers/pbkdf2.js', 'assets/workers/sha.js']) {
  const source = await readFile(join(dist, relative), 'utf8');
  if (/\beval\s*\(|\b(?:new\s+)?Function\s*\(|\bWebAssembly\s*[.(]/.test(source)) {
    throw new Error(`CSP-incompatible dynamic code found in ${relative}`);
  }
}
const html = await readFile(join(dist, 'index.html'), 'utf8');
if (/<style\b|\sstyle\s*=|\son[a-z]+\s*=|<script\b(?![^>]*\bsrc=)/i.test(html)) {
  throw new Error('Inline script/style found in index.html');
}
const css = await readFile(join(dist, 'assets/altcha.css'), 'utf8');
if (/@import\b|url\(/i.test(css)) throw new Error('Unexpected external asset in ALTCHA CSS');
console.log(`Built ${dist}; CSP checks passed; workers: ${(await readdir(join(dist, 'assets/workers'))).join(', ')}.`);
