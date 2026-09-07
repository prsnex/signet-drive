import { execSync } from 'node:child_process';
import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

// Object-storage origin allowed in the CSP connect-src for the direct-to-storage
// data plane (the client PUTs/GETs ciphertext straight to the bucket via presigned
// URLs; Inventory Cat 2 + the Large-File design). Build-time + env-overridable:
// production builds default to the OVH BHS S3 endpoint — the SAME host for staging
// AND prod (path-style: the bucket is in the path, not the origin). A local/e2e
// build sets SIGNET_WEB_S3_ORIGIN to the MinIO host.
const s3Origin = process.env.SIGNET_WEB_S3_ORIGIN || 'https://s3.bhs.io.cloud.ovh.net';

// Reproducible builds (R5-web, Gus S002): SvelteKit's version.name defaults to
// Date.now() — the one nondeterminism on the web floor. Pin it to the build
// commit instead, so two builds of the same source are byte-identical (the
// bundle-manifest / SRI story depends on it). Git-less builders (the Docker
// web-builder stage — no git, no .git) MUST inject SIGNET_WEB_BUILD_COMMIT
// (server/Dockerfile ARG ← smoke.sh / release-image.yml); the throw keeps the
// failure actionable instead of a bare `git: not found`.
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
const buildCommit = resolveBuildCommit();

/** @type {import('@sveltejs/kit').Config} */
const config = {
  preprocess: vitePreprocess(),
  compilerOptions: {
    // Force runes mode project-wide (Svelte 5). Removable in Svelte 6.
    runes: ({ filename }) => (filename.split(/[/\\]/).includes('node_modules') ? undefined : true),
  },
  kit: {
    // SPA mode: a zero-knowledge client. All crypto + the session KEM key live
    // only in the browser, so there is no SSR (see src/routes/+layout.ts). The
    // static adapter emits the shell + an index.html fallback for client routing;
    // in production the bundle is baked into the server image and served by the
    // Rust server via ServeDir (SIGNET_WEB_ROOT; Infrastructure-Inventory Cat 11),
    // with Caddy in front for TLS + security headers. In dev, `vite dev` serves it.
    adapter: adapter({ fallback: 'index.html' }),

    version: { name: buildCommit },

    // Content-Security-Policy (Inventory Cat 11). Caddy deliberately does NOT set
    // CSP: the SPA emits one inline hydration script (verified: 1 inline <script>,
    // 0 external), so hash mode emits a <meta> CSP whose script-src carries that
    // script's hash — a strict policy with NO 'unsafe-inline' for scripts.
    csp: {
      mode: 'hash',
      directives: {
        'default-src': ['self'],
        // 'wasm-unsafe-eval' (PQR item 6): permits WebAssembly COMPILATION
        // only — a named, narrow relaxation for the ML-KEM module
        // (src/lib/crypto/mlkem-wasm/), far narrower than 'unsafe-eval' (JS
        // eval stays blocked). The asset itself is same-origin (connect-src
        // 'self' covers its fetch) and its hash is committed into the bundle
        // manifest (§9.3/SRI).
        'script-src': ['self', 'wasm-unsafe-eval', 'https://challenges.cloudflare.com'],
        'style-src': ['self', 'unsafe-inline'],
        // 'self' = same-origin /v1 API; s3Origin = direct-to-storage uploads/
        // downloads (the Cat 11 spec omitted this — it predates S036); the
        // Cloudflare host = Turnstile (widget not wired yet — forward-compatible).
        'connect-src': ['self', s3Origin, 'https://challenges.cloudflare.com'],
        'frame-src': ['https://challenges.cloudflare.com'],
        'img-src': ['self', 'data:'],
        'object-src': ['none'],
        'base-uri': ['self'],
        'form-action': ['self'],
      },
    },
  },
};

export default config;
