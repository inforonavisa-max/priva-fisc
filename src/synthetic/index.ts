/**
 * PRIVA-FISC v0-A — synthetic generator (compatibility re-export).
 *
 * The synthetic EFI generator now lives in the flat `src/` modules
 * (`../synthetic.ts` record generation, `../fixtures.ts` envelope assembly,
 * `../index.ts` CLI). This file is kept as a stable re-export so the original
 * `src/synthetic/` entry point continues to resolve.
 *
 * SYNTHETIC, schema-shaped test data ONLY. No real PII / certificates / keys.
 * See ../../README.md (scope + D5 data firewall) and ../../spec/SPEC.md.
 */

export * from '../synthetic.js';
export { buildDataset, type Dataset } from '../fixtures.js';
