// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { hexDecode, hexEncode, type Bytes } from './bytes';
import { importEcdhPrivateJwk } from './ecdh';
import {
  hybridUnwrapDek,
  hybridUnwrapMetadataKey,
  hybridWrapDek,
  hybridWrapMetadataKey,
  parseHybridWrapEnvelope,
} from './hybrid_wrap';
import { initMlkem } from './mlkem';

// The hybrid cross-surface goldens (PQR §11.4 — the P2 exit gate), the web
// half: this suite loads the SAME committed fixture the Rust twin
// (cli/tests/hybrid_crossover.rs) loads and unwraps the RUST-produced
// envelopes through the real web path — WebCrypto ECDH (the recipient JWK
// imported non-extractable) + wasm ML-KEM decap from the seed — while the
// Rust twin unwraps the WEB-produced envelopes. Byte-identical keys on both
// surfaces from both producers = the S059/S068 crossover over the hybrid
// alg-ID. Regenerate the web half with:
//   GEN_HYBRID_CROSSOVER=1 npx vitest run src/lib/crypto/hybrid.crossover.test.ts

interface Golden {
  recipient: {
    p256_private_jwk: JsonWebKey;
    p256_public_x963_hex: string;
    mlkem_seed_hex: string;
    mlkem_ek_hex: string;
  };
  key_hex: string;
  root_folder_id_hex: string;
  rust_envelope_dek: unknown;
  rust_envelope_metadata: unknown;
  web_envelope_dek?: unknown;
  web_envelope_metadata?: unknown;
}

const goldenPath = fileURLToPath(
  new URL('../../../../docs/design/test-vectors/golden/hybrid-crossover.json', import.meta.url),
);
const golden: Golden = JSON.parse(readFileSync(goldenPath, 'utf8'));

beforeAll(async () => {
  await initMlkem(
    readFileSync(
      fileURLToPath(new URL('./mlkem-wasm/signet_crypto_wasm_bg.wasm', import.meta.url)),
    ),
  );
});

async function fixture() {
  return {
    priv: await importEcdhPrivateJwk(golden.recipient.p256_private_jwk),
    pubX963: hexDecode(golden.recipient.p256_public_x963_hex),
    seed: hexDecode(golden.recipient.mlkem_seed_hex),
    ek: hexDecode(golden.recipient.mlkem_ek_hex),
    key: hexDecode(golden.key_hex),
    root: hexDecode(golden.root_folder_id_hex),
  };
}

describe('hybrid crossover goldens (PQR §11.4 — the P2 exit gate)', () => {
  it('unwraps the RUST-produced envelopes (the crossover direction)', async () => {
    const f = await fixture();
    const dek = await hybridUnwrapDek(
      f.priv,
      f.seed,
      parseHybridWrapEnvelope(golden.rust_envelope_dek),
      f.pubX963,
      f.ek,
    );
    expect(hexEncode(dek)).toBe(golden.key_hex);
    const mk = await hybridUnwrapMetadataKey(
      f.priv,
      f.seed,
      parseHybridWrapEnvelope(golden.rust_envelope_metadata),
      f.pubX963,
      f.ek,
      f.root,
    );
    expect(hexEncode(mk)).toBe(golden.key_hex);
  });

  it('unwraps the WEB-produced envelopes (the same-surface baseline)', async () => {
    const f = await fixture();
    const dek = await hybridUnwrapDek(
      f.priv,
      f.seed,
      parseHybridWrapEnvelope(golden.web_envelope_dek),
      f.pubX963,
      f.ek,
    );
    expect(hexEncode(dek)).toBe(golden.key_hex);
    const mk = await hybridUnwrapMetadataKey(
      f.priv,
      f.seed,
      parseHybridWrapEnvelope(golden.web_envelope_metadata),
      f.pubX963,
      f.ek,
      f.root,
    );
    expect(hexEncode(mk)).toBe(golden.key_hex);
  });

  it.runIf(process.env.GEN_HYBRID_CROSSOVER)(
    'GENERATOR: write the web half into the fixture',
    async () => {
      const f = await fixture();
      const dekEnv = await hybridWrapDek(f.pubX963, f.ek, f.key as Bytes);
      const metaEnv = await hybridWrapMetadataKey(f.pubX963, f.ek, f.key as Bytes, f.root as Bytes);
      const merged = {
        ...(JSON.parse(readFileSync(goldenPath, 'utf8')) as Record<string, unknown>),
        web_envelope_dek: dekEnv,
        web_envelope_metadata: metaEnv,
      };
      writeFileSync(goldenPath, `${JSON.stringify(merged, null, 2)}\n`);
      expect(merged.web_envelope_dek).toBeDefined();
    },
  );
});
