/**
 * T-DET — determinism / seeded-PRNG reproducibility.
 * ============================================================================
 * Same seed  → byte-identical ZK-relevant fixture content (publicInputs +
 *              witness + expected + _invalidReason). The IKOF chain (ikof.*) and
 *              the XML that embeds it are EXCLUDED: they depend on the synthetic
 *              RSA keypair, which Node cannot seed (it is cached, not seeded —
 *              see src/rsa.ts). All ZK-relevant values come from the seeded PRNG.
 * Diff seed  → per-fixture C, D and salt DIFFER (seeded record + salt). NOTE:
 *              sellersRoot is INTENTIONALLY seed-INDEPENDENT — the registered-TIN
 *              set is a fixed synthetic reserved range (buildRegisteredTins), not
 *              seeded — so it is asserted EQUAL across seeds (documented deviation
 *              from the task's literal "C,D,sellersRoot,salt differ").
 * ----------------------------------------------------------------------------
 */

import { buildDataset } from '../src/fixtures.js';
import { DEFAULT_CONFIG } from '../src/synthetic.js';
import type { Fixture } from '../src/schema.js';
import { group, ok, eq, test } from './harness.js';

group('T-DET');

/** ZK-relevant + firewall core (drops key-dependent ikof + embedding xml). */
function core(fx: Fixture) {
  return {
    id: fx.id,
    publicInputs: fx.publicInputs,
    witness: fx.witness,
    expected: fx.expected,
    _invalidReason: fx._invalidReason,
  };
}

const seedA = DEFAULT_CONFIG.seed;
const seedB = 'FOUNDATION-LOCK-ALT-SEED';

test('same seed → identical ZK-relevant fixture content', () => {
  const a = buildDataset({ ...DEFAULT_CONFIG, seed: seedA }).fixtures.map(core);
  const b = buildDataset({ ...DEFAULT_CONFIG, seed: seedA }).fixtures.map(core);
  eq(
    JSON.parse(JSON.stringify(a)),
    JSON.parse(JSON.stringify(b)),
    'same-seed ZK-relevant content must be byte-identical',
  );
});

test('IKOF chain is present (key-dependent, excluded from determinism core)', () => {
  const fx = buildDataset({ ...DEFAULT_CONFIG, seed: seedA }).fixtures[0]!;
  ok(typeof fx.ikof.ikof === 'string' && fx.ikof.ikof.length === 32, 'IKOF 32 hex present');
});

test('different seed → C, D, salt differ per valid fixture', () => {
  const a = buildDataset({ ...DEFAULT_CONFIG, seed: seedA }).fixtures;
  const b = buildDataset({ ...DEFAULT_CONFIG, seed: seedB }).fixtures;
  const n = DEFAULT_CONFIG.validCount;
  for (let i = 0; i < n; i++) {
    ok(a[i]!.publicInputs.C !== b[i]!.publicInputs.C, `valid[${i}] C must differ across seeds`);
    ok(a[i]!.publicInputs.D.hex !== b[i]!.publicInputs.D.hex, `valid[${i}] D.hex must differ across seeds`);
    ok(a[i]!.witness.salt !== b[i]!.witness.salt, `valid[${i}] salt must differ across seeds`);
  }
});

test('different seed → sellersRoot EQUAL (registry is seed-independent by design)', () => {
  const a = buildDataset({ ...DEFAULT_CONFIG, seed: seedA }).fixtures[0]!;
  const b = buildDataset({ ...DEFAULT_CONFIG, seed: seedB }).fixtures[0]!;
  ok(
    a.publicInputs.sellersRoot === b.publicInputs.sellersRoot,
    'sellersRoot must be identical across seeds (fixed reserved-range registry)',
  );
});
