/**
 * PRIVA-FISC v0-A — minimal zero-dependency test harness.
 * ============================================================================
 * NETWORK ACCESS: NONE — no jest/vitest installed (and none may be fetched), so
 * this is a tiny harness over Node's built-in `node:assert`. Tests register via
 * `test(name, fn)`; the runner calls `runAll()` which prints PASS/FAIL per case
 * and exits non-zero if anything fails (so `npm test` fails loudly).
 * ----------------------------------------------------------------------------
 */

import assert from 'node:assert/strict';

type TestFn = () => void | Promise<void>;
interface Case {
  group: string;
  name: string;
  fn: TestFn;
}

const cases: Case[] = [];
let currentGroup = '(ungrouped)';

/** Set the group label for subsequently-registered tests. */
export function group(label: string): void {
  currentGroup = label;
}

export function test(name: string, fn: TestFn): void {
  cases.push({ group: currentGroup, name, fn });
}

// Plain void wrappers over node:assert (NOT `asserts` signatures — keeps TS from
// requiring explicit annotations at every call site, TS2775).
export function eq<T>(actual: T, expected: T, msg?: string): void {
  assert.deepStrictEqual(actual, expected, msg);
}
export function strictEq<T>(actual: T, expected: T, msg?: string): void {
  assert.strictEqual(actual, expected, msg);
}
export function ok(cond: boolean, msg: string): void {
  assert.ok(cond, msg);
}

export async function runAll(): Promise<void> {
  let passed = 0;
  const failures: { id: string; err: string }[] = [];
  let lastGroup = '';
  for (const c of cases) {
    if (c.group !== lastGroup) {
      console.log(`\n— ${c.group} —`);
      lastGroup = c.group;
    }
    try {
      await c.fn();
      console.log(`  [PASS] ${c.name}`);
      passed++;
    } catch (e) {
      const err = e instanceof Error ? e.message : String(e);
      console.log(`  [FAIL] ${c.name}\n         ${err.replace(/\n/g, '\n         ')}`);
      failures.push({ id: `${c.group} :: ${c.name}`, err });
    }
  }
  console.log(`\nPRIVA-FISC v0-A foundation guards: ${passed}/${cases.length} passed`);
  if (failures.length > 0) {
    console.error(`✗ ${failures.length} FAILED:`);
    for (const f of failures) console.error(`  - ${f.id}`);
    process.exit(1);
  }
  console.log('✓ all foundation regression guards green.');
}
