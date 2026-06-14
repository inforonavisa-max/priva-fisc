/**
 * T-PURITY — circuit-shared modules must stay o1js-pure (permanent invariant).
 * ============================================================================
 * The circuit-shared modules (encoding.ts, commitments.ts, merkle.ts) will be
 * imported by the future ZkProgram, so they MUST NOT pull in the byte/SHA-256
 * path: they must NOT import src/canonical.ts and MUST NOT import node:crypto.
 * This scans their source text and fails if either appears — so the SHA-256 D
 * path can never silently leak back into the circuit-shared layer.
 *
 * (node:crypto legitimately lives only in the generator-only modules
 * canonical.ts, rsa.ts, prng.ts, which the circuit path never imports.)
 * ----------------------------------------------------------------------------
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { group, ok, test } from './harness.js';

group('T-PURITY');

const CIRCUIT_SHARED = ['encoding.ts', 'commitments.ts', 'merkle.ts'];

const FORBIDDEN: { label: string; re: RegExp }[] = [
  { label: 'node:crypto import', re: /(from\s+['"]node:crypto['"]|require\(\s*['"]node:crypto['"])/ },
  { label: 'canonical.ts import', re: /(from\s+['"][./]*canonical(\.js)?['"]|require\(\s*['"][./]*canonical)/ },
];

function src(file: string): string {
  return readFileSync(join(process.cwd(), 'src', file), 'utf8');
}

for (const file of CIRCUIT_SHARED) {
  test(`${file} is o1js-pure (no node:crypto, no canonical.ts import)`, () => {
    const text = src(file);
    for (const f of FORBIDDEN) {
      ok(!f.re.test(text), `src/${file} must not contain a ${f.label}`);
    }
  });
}

test('generator-only modules DO use node:crypto (sanity: invariant is meaningful)', () => {
  // If these stopped using node:crypto the purity test above would be vacuous.
  const usesCrypto = (f: string) => /node:crypto/.test(src(f));
  ok(usesCrypto('canonical.ts'), 'canonical.ts should use node:crypto (SHA-256)');
  ok(usesCrypto('rsa.ts'), 'rsa.ts should use node:crypto');
});
