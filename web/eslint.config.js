import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      'coverage',
      'dist',
      'build',
      '.svelte-kit',
      'test-results',
      'playwright-report',
      'src/lib/paraglide', // inlang-generated message code
      'project.inlang', // inlang tooling config + fetched-plugin cache
      'src/lib/crypto/mlkem-wasm', // wasm-pack-generated pkg (committed; crypto-wasm/build-web-pkg.sh)
    ],
  },
  ...tseslint.configs.recommended,
);
