/**
 * PRIVA-FISC v0-A — synthetic fixture generator CLI (`npm run gen`)
 * ============================================================================
 * Generates N synthetic EFI fixtures (valid + invalid) into ./fixtures/.
 *
 * This is the SYNTHETIC DATA generator only — NOT the ZK circuit. The circuit
 * (ZkProgram) is the NEXT task and is intentionally absent here. See
 * ../spec/SPEC.md (relation) and ../README.md (scope, data firewall).
 *
 * Usage:
 *   npm run gen
 *   npm run gen -- --valid=10 --invalid-per-reason=2 --registry=32 --seed=foo
 *   npm run gen -- --out=./fixtures
 * ----------------------------------------------------------------------------
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildDataset } from './fixtures.js';
import {
  DEFAULT_CONFIG,
  type GeneratorConfig,
} from './synthetic.js';
import { INVALID_REASONS, type InvalidReason } from './schema.js';

const O1JS_VERSION = 'o1js@2.15.0';

function parseArgs(argv: string[]): { config: GeneratorConfig; outDir: string } {
  const opts = new Map<string, string>();
  for (const a of argv) {
    const m = /^--([^=]+)=(.*)$/.exec(a);
    if (m) opts.set(m[1] as string, m[2] as string);
  }
  const config: GeneratorConfig = {
    seed: opts.get('seed') ?? DEFAULT_CONFIG.seed,
    validCount: opts.has('valid')
      ? Number(opts.get('valid'))
      : DEFAULT_CONFIG.validCount,
    registrySize: opts.has('registry')
      ? Number(opts.get('registry'))
      : DEFAULT_CONFIG.registrySize,
    invalidCounts: { ...DEFAULT_CONFIG.invalidCounts },
  };
  if (opts.has('invalid-per-reason')) {
    const n = Number(opts.get('invalid-per-reason'));
    for (const r of INVALID_REASONS) config.invalidCounts[r as InvalidReason] = n;
  }
  const outDir = opts.get('out') ?? join(process.cwd(), 'fixtures');
  return { config, outDir };
}

function main(): void {
  const { config, outDir } = parseArgs(process.argv.slice(2));
  mkdirSync(outDir, { recursive: true });

  const { fixtures, summary } = buildDataset(config, O1JS_VERSION);

  const files: string[] = [];
  for (const fx of fixtures) {
    const file = `${fx.id}.json`;
    writeFileSync(join(outDir, file), JSON.stringify(fx, null, 2) + '\n', 'utf8');
    files.push(file);
  }
  writeFileSync(
    join(outDir, 'manifest.json'),
    JSON.stringify({ ...summary, files }, null, 2) + '\n',
    'utf8',
  );

  console.log('PRIVA-FISC v0-A — synthetic fixtures generated');
  console.log('  seed         :', summary.seed);
  console.log('  o1js         :', summary.o1jsVersion);
  console.log('  registry     :', summary.registrySize, 'slots, height', summary.merkleHeight);
  console.log('  sellersRoot  :', summary.sellersRoot);
  console.log('  valid        :', summary.valid);
  console.log('  invalid      :', summary.invalid, JSON.stringify(summary.invalidByReason));
  console.log('  out          :', outDir, `(${files.length + 1} files)`);
  console.log('  ⚠  SYNTHETIC TEST DATA — NO REAL PII — NOT FOR PRODUCTION');
}

main();
