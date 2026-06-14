/**
 * T-RANGE — range / overflow consistency (verifies the MAXBITS=52 decision).
 * ============================================================================
 * For EVERY valid fixture: all monetary fields (vat_base, vat_amount, total,
 * margin, each item unit price) ∈ [0, MAX_AMOUNT_CENTS], AND total is the honest
 * sum base+vat, AND base*rateBp + roundingBias < 2^64 (the bound that justifies
 * MAXBITS=52). Explicitly checks the edge concern: can a VALID record produce
 * total > MAX? (If so the circuit's range check on total would reject a "valid"
 * record — a real bug.) Empirically: max valid total sits ~5.6e8× below MAX.
 *
 * Also confirms the OUT_OF_RANGE negative fixture really has an out-of-range
 * amount, so the range predicate genuinely distinguishes the two classes.
 * ----------------------------------------------------------------------------
 */

import { MAX_AMOUNT_CENTS } from '../src/encoding.js';
import { computeVatCents, totalCentsFromBaseVat } from '../src/schema.js';
import { generateFixtures } from './fixtures-helper.js';
import { group, ok, test } from './harness.js';

group('T-RANGE');

const TWO_POW_64 = 1n << 64n;
const fixtures = generateFixtures();

function monetary(fx: { witness: { vatBaseCents: string; vatAmountCents: string; totalCents: string; marginCents: string; lineItems: { unitPriceCents: string }[] } }): bigint[] {
  const w = fx.witness;
  return [
    BigInt(w.vatBaseCents),
    BigInt(w.vatAmountCents),
    BigInt(w.totalCents),
    BigInt(w.marginCents),
    ...w.lineItems.map((it) => BigInt(it.unitPriceCents)),
  ];
}

test('every VALID fixture: all monetary fields (incl. total) ∈ [0, MAX]', () => {
  let maxTotal = 0n;
  for (const fx of fixtures) {
    if (!fx.expected.valid) continue;
    for (const v of monetary(fx)) {
      ok(v >= 0n && v <= MAX_AMOUNT_CENTS, `${fx.id}: amount ${v} out of [0, MAX]`);
    }
    const total = BigInt(fx.witness.totalCents);
    if (total > maxTotal) maxTotal = total;
  }
  // Edge concern: valid totals stay far below MAX (huge headroom).
  ok(maxTotal * 1000n < MAX_AMOUNT_CENTS, `valid total headroom too small (maxTotal=${maxTotal})`);
});

test('every VALID fixture: total == base + computeVat(base, rate) (honest sum)', () => {
  for (const fx of fixtures) {
    if (!fx.expected.valid) continue;
    const base = BigInt(fx.witness.vatBaseCents);
    const vat = computeVatCents(base, fx.witness.vatRateBp);
    const total = totalCentsFromBaseVat(base, vat);
    ok(BigInt(fx.witness.vatAmountCents) === vat, `${fx.id}: stored VAT != computed`);
    ok(BigInt(fx.witness.totalCents) === total, `${fx.id}: stored total != base+vat`);
  }
});

test('every fixture: base*rateBp + roundingBias < 2^64 (MAXBITS=52 justification)', () => {
  for (const fx of fixtures) {
    const base = BigInt(fx.witness.vatBaseCents);
    const rate = BigInt(fx.witness.vatRateBp);
    const prod = base * rate + 5000n;
    ok(prod < TWO_POW_64, `${fx.id}: base*rateBp+bias ${prod} >= 2^64`);
  }
});

test('OUT_OF_RANGE fixture genuinely has an amount > MAX', () => {
  const oor = fixtures.find((f) => f._invalidReason === 'OUT_OF_RANGE');
  ok(!!oor, 'expected an OUT_OF_RANGE fixture');
  const anyOver = monetary(oor!).some((v) => v > MAX_AMOUNT_CENTS);
  ok(anyOver, 'OUT_OF_RANGE fixture must contain an amount > MAX');
});
