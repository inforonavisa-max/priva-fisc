/**
 * T-LEAK — structural privacy guard (D5 / SPEC §5.1).
 * ============================================================================
 * For every emitted fixture, prove NO private (witness-group) field leaks into
 * the public group (PublicInputs). Approach is structural + name + value:
 *
 *   (1) PublicInputs has EXACTLY {C, D, sellersRoot, PK_ref, rateParams}.
 *   (2) C, D, sellersRoot are pure decimal Poseidon outputs (/^[0-9]+$/) — they
 *       cannot embed any private string.
 *   (3) rateParams deep-equals the fixed public statutory params; PK_ref is the
 *       fixed null placeholder. So the public surface is fully characterized as
 *       {one-way hashes} ∪ {fixed public constants} — nothing witness-derived.
 *   (4) NAME check: no witness field-name (camel or snake) appears as a key or a
 *       string value anywhere in PublicInputs.
 *   (5) VALUE check: no distinctive witness VALUE (len ≥ 10: ids, datetime, salt,
 *       itemsCommit, siblings) appears as a substring of the serialized public
 *       group. Short numerics (TIN, amounts, indices) are EXCLUDED from substring
 *       search (a short digit run can coincidentally occur inside a hash); their
 *       privacy is established by (1)–(3) structurally, not by substring.
 * ----------------------------------------------------------------------------
 */

import { RATE_PARAMS, type Fixture } from '../src/schema.js';
import { generateFixtures } from './fixtures-helper.js';
import { group, ok, eq, test } from './harness.js';

group('T-LEAK');

const fixtures = generateFixtures();

const PUBLIC_KEYS = ['C', 'D', 'sellersRoot', 'PK_A', 'rateParams'].sort();

// Private field names (witness keys + spec snake-case synonyms).
const PRIVATE_NAMES = new Set<string>([
  // witness object keys (camelCase)
  'sellerTin', 'datetime', 'invoiceNo', 'businessUnit', 'enuTcr', 'softwareCode',
  'totalCents', 'vatBaseCents', 'vatRateBp', 'vatAmountCents', 'buyerId',
  'lineItems', 'marginCents', 'itemsCommit', 'salt', 'sigReceipt', 'M',
  'merklePath', 'merkleIndexBits', 'merkleIndex',
  // SPEC §4.1 snake-case names
  'seller_tin', 'invoice_no', 'business_unit', 'enu_tcr', 'software_code',
  'vat_base', 'vat_rate', 'vat_rate_bp', 'vat_amount', 'buyer_id', 'line_items',
  'margin', 'total',
]);

function collect(node: unknown, keys: Set<string>, vals: Set<string>): void {
  if (node === null || node === undefined) return;
  if (typeof node === 'string') { vals.add(node); return; }
  if (typeof node !== 'object') return;
  if (Array.isArray(node)) { for (const v of node) collect(v, keys, vals); return; }
  for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
    keys.add(k);
    collect(v, keys, vals);
  }
}

/** Distinctive witness values worth substring-checking (len ≥ 10). */
function distinctiveWitnessValues(fx: Fixture): string[] {
  const w = fx.witness;
  const vals: string[] = [
    w.sellerTin, w.datetime, w.invoiceNo, w.businessUnit, w.enuTcr,
    w.softwareCode, w.buyerId, w.salt, w.itemsCommit, w.sigReceipt, w.M,
    ...w.lineItems.map((it) => it.name),
    ...w.merklePath.map((p) => p.sibling),
  ];
  return vals.filter((v) => typeof v === 'string' && v.length >= 10);
}

test('every fixture: PublicInputs has exactly the 5 public keys', () => {
  for (const fx of fixtures) {
    eq(Object.keys(fx.publicInputs).sort(), PUBLIC_KEYS, `${fx.id}: public keys`);
  }
});

test('every fixture: C/sellersRoot pure decimal; D = {hi,lo decimal, hex 64-hex}', () => {
  const dec = /^[0-9]+$/;
  const hex64 = /^[0-9a-f]{64}$/;
  for (const fx of fixtures) {
    ok(dec.test(fx.publicInputs.C), `${fx.id}: C not pure decimal`);
    ok(dec.test(fx.publicInputs.sellersRoot), `${fx.id}: sellersRoot not pure decimal`);
    ok(dec.test(fx.publicInputs.D.hi), `${fx.id}: D.hi not pure decimal`);
    ok(dec.test(fx.publicInputs.D.lo), `${fx.id}: D.lo not pure decimal`);
    ok(hex64.test(fx.publicInputs.D.hex), `${fx.id}: D.hex not 64-char lowercase hex`);
  }
});

test('every fixture: rateParams == fixed public params; PK_A is a base58 pubkey', () => {
  for (const fx of fixtures) {
    eq(fx.publicInputs.rateParams, RATE_PARAMS, `${fx.id}: rateParams drift`);
    ok(
      typeof fx.publicInputs.PK_A === 'string' && /^B62[1-9A-HJ-NP-Za-km-z]+$/.test(fx.publicInputs.PK_A),
      `${fx.id}: PK_A not a base58 Mina public key`,
    );
  }
});

test('NAME check: no private field-name appears as key/value in PublicInputs', () => {
  for (const fx of fixtures) {
    const keys = new Set<string>();
    const vals = new Set<string>();
    collect(fx.publicInputs, keys, vals);
    for (const k of keys) {
      ok(!PRIVATE_NAMES.has(k), `${fx.id}: private name '${k}' used as a public key`);
    }
    for (const v of vals) {
      ok(!PRIVATE_NAMES.has(v), `${fx.id}: private name '${v}' appears as a public value`);
    }
  }
});

test('VALUE check: no distinctive witness value leaks into the public group', () => {
  for (const fx of fixtures) {
    const publicJson = JSON.stringify(fx.publicInputs);
    for (const v of distinctiveWitnessValues(fx)) {
      ok(
        !publicJson.includes(v),
        `${fx.id}: witness value '${v.slice(0, 24)}…' leaked into PublicInputs`,
      );
    }
  }
});
