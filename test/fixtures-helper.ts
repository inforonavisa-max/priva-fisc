/**
 * Shared test helper: generate fixtures in-memory and serialize them exactly as
 * `npm run gen` would (JSON round-trip), so guards test the EMITTED form without
 * depending on files on disk. Hermetic and faithful (index.ts emits
 * JSON.stringify(fixture)).
 */

import { buildDataset } from '../src/fixtures.js';
import { DEFAULT_CONFIG, type GeneratorConfig } from '../src/synthetic.js';
import type { Fixture } from '../src/schema.js';

export function generateFixtures(
  config: GeneratorConfig = DEFAULT_CONFIG,
): Fixture[] {
  const { fixtures } = buildDataset(config);
  return fixtures.map((f) => JSON.parse(JSON.stringify(f)) as Fixture);
}
