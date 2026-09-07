// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
//
// Emit the web bundle manifest (PQR item 6 / OSP §"Verification flow (web
// client)" / R2): after `vite build`, hash every file in the static output and
// write `build/.well-known/signet-bundle-manifest.json`, served with the
// bundle. A verifier fetches the manifest, re-fetches each listed file, and
// compares hashes — the WASM asset's entry is what makes the ML-KEM module
// SRI-verifiable (spec §9.3).
//
// This is the GENERATION seam only. The publish half — committing the
// manifest hash to the public prsnex/signet-drive-public-hashes repo at
// deploy time — is launch provisioning (Punch-List R2, travels with §2-10).
//
// Deterministic by construction: sorted paths, no timestamps; the commit SHA
// comes from git (or SIGNET_WEB_BUILD_COMMIT for builders without git — the
// same override svelte.config.js honors for kit.version.name).

import { execSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const buildDir = fileURLToPath(new URL('../build', import.meta.url));
const manifestDir = join(buildDir, '.well-known');
const manifestPath = join(manifestDir, 'signet-bundle-manifest.json');

function resolveBuildCommit() {
  if (process.env.SIGNET_WEB_BUILD_COMMIT) return process.env.SIGNET_WEB_BUILD_COMMIT;
  try {
    return execSync('git rev-parse HEAD', { encoding: 'utf8' }).trim();
  } catch {
    throw new Error(
      'SIGNET_WEB_BUILD_COMMIT must be set when git is unavailable ' +
        '(Docker builds pass it as a build arg — see server/Dockerfile)',
    );
  }
}
const commit = resolveBuildCommit();

function* walk(dir) {
  for (const entry of readdirSync(dir).sort()) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) yield* walk(path);
    else yield path;
  }
}

const files = {};
for (const path of walk(buildDir)) {
  const rel = relative(buildDir, path).split(sep).join('/');
  if (rel === '.well-known/signet-bundle-manifest.json') continue; // never self-referential
  files[rel] = createHash('sha256').update(readFileSync(path)).digest('hex');
}

mkdirSync(manifestDir, { recursive: true });
writeFileSync(manifestPath, `${JSON.stringify({ build_commit_sha: commit, files }, null, 2)}\n`);

const wasm = Object.keys(files).filter((f) => f.endsWith('.wasm'));
if (wasm.length === 0) {
  console.error(
    'bundle manifest: no .wasm asset found in the build output — the ML-KEM module is missing',
  );
  process.exit(1);
}
console.log(
  `bundle manifest: ${Object.keys(files).length} files @ ${commit.slice(0, 12)}; wasm: ${wasm
    .map((f) => `${f} ${files[f].slice(0, 12)}…`)
    .join(', ')}`,
);
