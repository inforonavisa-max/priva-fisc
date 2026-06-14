/**
 * T-ORDER — ordering pin + D construction (foundation lock).
 * ============================================================================
 * Transcribes the SPEC's authoritative orderings as explicit literals (with the
 * spec lines quoted alongside) and asserts the code equals them. Reordering T /
 * C / leaf is a binding-semantic change → these FAIL loudly on drift.
 *
 * Step-1 verdict baked in: T order == SPEC §4.1, C order == SPEC §7-C2,
 * leaf == SPEC §7-C4 (all MATCH; only annotation: vat_rate → vat_rate_bp unit).
 *
 * D is now D = SHA-256(canonical(P)) (SPEC §7-C5/§13). Pins here:
 *   • D-CONSTRUCTION: independent node:crypto SHA-256(canonicalize(rec)) (+ own
 *     limb split) == canonical.digestD(rec).
 *   • NON-VACUITY: mutating ANY §4.1 field (and itemsCommit) changes D; and a
 *     field-ORDER sensitivity check (canonicalize follows T_FIELD_ORDER).
 * ----------------------------------------------------------------------------
 */

import { Field, Poseidon } from 'o1js';
import { createHash } from 'node:crypto';
import {
  DS,
  encodeAmount,
  encodeRateBp,
  encodeStringToField,
  T_FIELD_ORDER,
} from '../src/encoding.js';
import { commitC, sellerLeaf } from '../src/commitments.js';
import { canonicalize, digestD } from '../src/canonical.js';
import type { EfiRecord } from '../src/schema.js';
import { group, ok, strictEq, test } from './harness.js';

group('T-ORDER');

// ── SPEC §4.1 — receipt payload `P` field SET + ORDER (quoted verbatim) ──────
//   | `seller_tin`    | `datetime`   | `invoice_no` | `business_unit` |
//   | `enu_tcr`       | `software_code` | `total`   | `vat_base`      |
//   | `vat_rate`      | `vat_amount` | `buyer_id`   | `line_items`    | `margin` |
const SPEC_T_ORDER: readonly string[] = [
  'seller_tin', 'datetime', 'invoice_no', 'business_unit', 'enu_tcr',
  'software_code', 'total', 'vat_base', 'vat_rate', 'vat_amount', 'buyer_id',
  'line_items', 'margin',
];

// Only-permitted code annotation: vat_rate carried in basis points → `vat_rate_bp`.
const PERMITTED_RENAME: Record<string, string> = { vat_rate: 'vat_rate_bp' };

test('code T_FIELD_ORDER == SPEC §4.1 order (field-by-field)', () => {
  ok(
    T_FIELD_ORDER.length === SPEC_T_ORDER.length,
    `T length ${T_FIELD_ORDER.length} != spec ${SPEC_T_ORDER.length}`,
  );
  SPEC_T_ORDER.forEach((specTok, i) => {
    const expected = PERMITTED_RENAME[specTok] ?? specTok;
    strictEq(T_FIELD_ORDER[i], expected, `T[${i}]: spec '${specTok}' but code '${T_FIELD_ORDER[i]}'`);
  });
});

// ── SPEC §7-C2 — commitment C field SET + ORDER (quoted verbatim) ────────────
//   C = H( DS_commit, seller_tin, buyer_id, H(line_items), margin, vat_base,
//          vat_amount, vat_rate, total, salt )
test('commitC order == SPEC §7-C2 (distinct sentinels make order binding)', () => {
  const rec: EfiRecord = {
    sellerTin: 'C-SELLER', datetime: 'unused', invoiceNo: 'unused',
    businessUnit: 'unused', enuTcr: 'unused', softwareCode: 'unused',
    totalCents: 555n, vatBaseCents: 222n, vatRateBp: 444, vatAmountCents: 333n,
    buyerId: 'C-BUYER', lineItems: [], marginCents: 111n,
  };
  const itemsCommitSentinel = Field(900001n);
  const saltSentinel = Field(700007n);
  const expected = Poseidon.hash([
    DS.COMMIT,
    encodeStringToField('C-SELLER'),
    encodeStringToField('C-BUYER'),
    itemsCommitSentinel,
    encodeAmount(111n),
    encodeAmount(222n),
    encodeAmount(333n),
    encodeRateBp(444),
    encodeAmount(555n),
    saltSentinel,
  ]);
  strictEq(
    commitC(rec, itemsCommitSentinel, saltSentinel).toString(),
    expected.toString(),
    'commitC field order diverged from SPEC §7-C2',
  );
});

// ── SPEC §7-C4 — registry leaf: leaf = H( DS_leaf, seller_tin ) ──────────────
test('sellerLeaf == SPEC §7-C4 leaf = H(DS_leaf, seller_tin)', () => {
  const expected = Poseidon.hash([DS.LEAF, encodeStringToField('LEAF-TIN')]);
  strictEq(sellerLeaf('LEAF-TIN').toString(), expected.toString(), 'sellerLeaf diverged from §7-C4');
});

// ── D = SHA-256(canonical(P)) — construction pin + limb split (SPEC §7-C5/§13) ─
function sampleRec(): EfiRecord {
  return {
    sellerTin: '90900001', datetime: '2026-01-01T09:00:00.000Z',
    invoiceNo: 'SYNTH-INV-2026-000001', businessUnit: 'SYNTH-BU-006',
    enuTcr: 'SYNTH-TCR-007', softwareCode: 'SYNTH-SW-06', totalCents: 6080025n,
    vatBaseCents: 5024814n, vatRateBp: 2100, vatAmountCents: 1055211n,
    buyerId: 'SYNTH-BUYER-0001', lineItems: [], marginCents: 753722n,
  };
}
const IC = Field(123456789n); // sentinel itemsCommit

function beDec(bytes: Buffer): string {
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) | BigInt(b);
  return acc.toString();
}

test('digestD == independent SHA-256(canonicalize(rec)) with correct limb split', () => {
  const rec = sampleRec();
  const digest = createHash('sha256').update(canonicalize(rec, IC)).digest();
  const expected = {
    hi: beDec(digest.subarray(0, 16)),
    lo: beDec(digest.subarray(16, 32)),
    hex: digest.toString('hex'),
  };
  const got = digestD(rec, IC);
  strictEq(got.hi, expected.hi, 'D.hi != SHA-256 high limb');
  strictEq(got.lo, expected.lo, 'D.lo != SHA-256 low limb');
  strictEq(got.hex, expected.hex, 'D.hex != SHA-256 hex');
  // limbs are each < 2^128 (safe single Field; well under the Pallas modulus)
  ok(BigInt(got.hi) < (1n << 128n) && BigInt(got.lo) < (1n << 128n), 'limb >= 2^128');
});

test('NON-VACUITY: mutating any §4.1 field (and itemsCommit) changes D', () => {
  const baseHex = digestD(sampleRec(), IC).hex;
  const muts: ((r: EfiRecord) => void)[] = [
    (r) => (r.sellerTin += 'X'), (r) => (r.datetime += 'X'), (r) => (r.invoiceNo += 'X'),
    (r) => (r.businessUnit += 'X'), (r) => (r.enuTcr += 'X'), (r) => (r.softwareCode += 'X'),
    (r) => (r.totalCents += 1n), (r) => (r.vatBaseCents += 1n), (r) => (r.vatRateBp += 1),
    (r) => (r.vatAmountCents += 1n), (r) => (r.buyerId += 'X'), (r) => (r.marginCents += 1n),
  ];
  for (const [k, m] of muts.entries()) {
    const r = sampleRec(); m(r);
    ok(digestD(r, IC).hex !== baseHex, `D insensitive to field mutation #${k}`);
  }
  ok(digestD(sampleRec(), Field(987654321n)).hex !== baseHex, 'D insensitive to itemsCommit');
});

test('FIELD-ORDER sensitivity: swapping two field values changes D', () => {
  // canonicalize iterates T_FIELD_ORDER, so business_unit and enu_tcr occupy
  // distinct positions; swapping their (equal-length) values must change D.
  const a = sampleRec(); a.businessUnit = 'AAA'; a.enuTcr = 'BBB';
  const b = sampleRec(); b.businessUnit = 'BBB'; b.enuTcr = 'AAA';
  ok(digestD(a, IC).hex !== digestD(b, IC).hex, 'canonicalize must be position-sensitive');
});
