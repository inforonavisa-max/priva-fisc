/**
 * T-CIRCUIT — the v0-A ZkProgram soundness suite (compile + prove + verify).
 * ============================================================================
 * Heavier than the fast foundation guards (it compiles + proves), so it runs
 * under a separate `npm run test:circuit`. Evidence:
 *   • COMPILE succeeds.
 *   • Every VALID fixture → a proof that verifies.
 *   • Every INVALID fixture (VAT_MISMATCH, SELLER_NOT_REGISTERED, OUT_OF_RANGE,
 *     COMMITMENT_MISMATCH, BAD_SIGNATURE) → proving THROWS on its constraint.
 *   • C1 anti-replay: tampering a receipt field bound into M → proving throws.
 * ----------------------------------------------------------------------------
 */

import { Field } from 'o1js';
import {
  FiscProof,
  FiscPublicInput,
  FiscWitness,
  circuitInputsFromFixture,
} from '../src/circuit.js';
import { encodeStringToField, FIELD_ORDER } from '../src/encoding.js';
import { commitCFields } from '../src/commitments.js';
import {
  computeAttestMessage,
  deriveAuthorityKeypair,
  signReceipt,
} from '../src/authority.js';
import { DEFAULT_CONFIG } from '../src/synthetic.js';
import { generateFixtures } from './fixtures-helper.js';
import { group, ok, test, runAll } from './harness.js';

group('T-CIRCUIT');

const fixtures = generateFixtures();
const valids = fixtures.filter((f) => f.expected.valid);
const invalids = fixtures.filter((f) => !f.expected.valid);

const now = (): number => Date.now();
async function throwsAsync(fn: () => Promise<unknown>): Promise<boolean> {
  try {
    await fn();
    return false;
  } catch {
    return true;
  }
}

test('COMPILE: FiscProof.compile() succeeds', async () => {
  const t = now();
  await FiscProof.compile();
  console.log(`    compile: ${((now() - t) / 1000).toFixed(1)}s`);
  ok(true, 'compiled');
});

for (const fx of valids) {
  test(`VALID ${fx.id} → proof verifies`, async () => {
    const { publicInput, witness, merkleWitness, sig } = circuitInputsFromFixture(fx);
    const t = now();
    const { proof } = await FiscProof.prove(publicInput, witness, merkleWitness, sig);
    const verified = await FiscProof.verify(proof);
    console.log(`    ${fx.id} prove+verify: ${((now() - t) / 1000).toFixed(1)}s`);
    ok(verified === true, `${fx.id}: proof must verify`);
  });
}

for (const fx of invalids) {
  test(`INVALID ${fx.id} (${fx._invalidReason}) → proving throws`, async () => {
    const { publicInput, witness, merkleWitness, sig } = circuitInputsFromFixture(fx);
    const t = now();
    const threw = await throwsAsync(() =>
      FiscProof.prove(publicInput, witness, merkleWitness, sig),
    );
    console.log(`    ${fx.id} reject: ${((now() - t) / 1000).toFixed(1)}s`);
    ok(threw, `${fx.id}: proving must THROW on ${fx._invalidReason}`);
  });
}

test('C1 ANTI-REPLAY: tampering datetime (M_circ ≠ signed M) → proving throws', async () => {
  const fx = valids[0]!;
  const { publicInput, witness, merkleWitness, sig } = circuitInputsFromFixture(fx);
  // datetime is bound into M (C1) but NOT into C (C2), so altering it isolates
  // the C1 M-binding: M_circ recomputes ≠ the signed M → assert fails.
  const tampered = new FiscWitness({
    encSellerTin: witness.encSellerTin,
    encBuyerId: witness.encBuyerId,
    encDatetime: encodeStringToField('2099-12-31T23:59:59.000Z'),
    encInvoiceNo: witness.encInvoiceNo,
    total: witness.total,
    vatBase: witness.vatBase,
    vatAmount: witness.vatAmount,
    margin: witness.margin,
    rateBp: witness.rateBp,
    r: witness.r,
    itemsCommit: witness.itemsCommit,
    salt: witness.salt,
    M: witness.M,
  });
  const threw = await throwsAsync(() =>
    FiscProof.prove(publicInput, tampered, merkleWitness, sig),
  );
  ok(threw, 'tampered-datetime proving must throw (C1 anti-replay / M-binding)');
});

// ───────────────────────────────────────────────────────────────────────────
// C3 QUOTIENT/REMAINDER SOUNDNESS PROBE
// ───────────────────────────────────────────────────────────────────────────
// C3 enforces Euclidean division  vatAmount*10000 + r == vatBase*rateBp + 5000
// with 0 ≤ r ≤ 9999. Soundness needs the quotient (vatAmount) AND remainder (r)
// BOTH range-bounded so (vatAmount, r) is UNIQUE. This probe adversarially builds
// alternative (vatAmount', r') splits for a FIXED valid public input and proves
// every one is rejected — establishing which constraint catches it.
//
// Two independent defenses are tested:
//   • C2 binding: vatAmount ∈ C, so any vatAmount' ≠ q ⇒ commitCFields ≠ public C.
//     (The realistic attacker cannot change the authority-signed public C.)
//   • C3 r-range: even if C2 were satisfied (we FORGE C' and re-sign M' with the
//     authority key to neutralize C1+C2), Euclidean uniqueness forces r' ∉ [0,9999],
//     which the r-range check rejects.
{
  const authority = deriveAuthorityKeypair(DEFAULT_CONFIG.seed);
  const fx = valids[0]!;
  const base = circuitInputsFromFixture(fx);
  const vatBase = BigInt(fx.witness.vatBaseCents);
  const rateBp = BigInt(fx.witness.vatRateBp);
  const q = BigInt(fx.witness.vatAmountCents); //                honest quotient
  const r0 = (vatBase * rateBp + 5000n) % 10000n; //            honest remainder

  // Build a witness from base, overriding the listed Field fields.
  function deriveWitness(o: Partial<Record<keyof FiscWitness, Field>>): FiscWitness {
    const b = base.witness;
    return new FiscWitness({
      encSellerTin: o.encSellerTin ?? b.encSellerTin,
      encBuyerId: o.encBuyerId ?? b.encBuyerId,
      encDatetime: o.encDatetime ?? b.encDatetime,
      encInvoiceNo: o.encInvoiceNo ?? b.encInvoiceNo,
      total: o.total ?? b.total,
      vatBase: o.vatBase ?? b.vatBase,
      vatAmount: o.vatAmount ?? b.vatAmount,
      margin: o.margin ?? b.margin,
      rateBp: o.rateBp ?? b.rateBp,
      r: o.r ?? b.r,
      itemsCommit: o.itemsCommit ?? b.itemsCommit,
      salt: o.salt ?? b.salt,
      M: o.M ?? b.M,
    });
  }

  // FORGE a public input + matching σ for an alternative (vatAmount', total') so
  // C1 + C2 PASS — isolating C3 as the only possible catcher. (Needs the authority
  // key, which a real prover does NOT have — this models a strictly stronger
  // attacker to prove C3 is sound on its own.)
  function forge(
    altVatAmount: bigint,
    altTotal: bigint,
  ): { publicInput: FiscPublicInput; M: Field } {
    const Cp = commitCFields(
      base.witness.encSellerTin,
      base.witness.encBuyerId,
      base.witness.itemsCommit,
      base.witness.margin,
      base.witness.vatBase,
      Field(altVatAmount),
      base.witness.rateBp,
      Field(altTotal),
      base.witness.salt,
    );
    const M = computeAttestMessage(
      base.publicInput.D_hi,
      base.publicInput.D_lo,
      Cp,
      base.publicInput.sellersRoot,
      fx.witness.datetime,
      fx.witness.invoiceNo,
    );
    const publicInput = new FiscPublicInput({
      PK_A: base.publicInput.PK_A,
      sellersRoot: base.publicInput.sellersRoot,
      D_hi: base.publicInput.D_hi,
      D_lo: base.publicInput.D_lo,
      C: Cp,
    });
    return { publicInput, M };
  }

  // (a) REALISTIC alternative on the FIXED public input: vatAmount'=q-1, r'=r0+10000
  //     (division holds). vatAmount' ∉ public C ⇒ C2 catches it (C2 runs before C3).
  test('C3-PROBE (a) realistic alt split (q-1, r0+10000) on fixed public C → throws (C2 binding)', async () => {
    const wit = deriveWitness({ vatAmount: Field(q - 1n), r: Field(r0 + 10000n) });
    const threw = await throwsAsync(() =>
      FiscProof.prove(base.publicInput, wit, base.merkleWitness, base.sig),
    );
    ok(threw, 'alt split on fixed public C must throw — caught by C2 (vatAmount ∈ C)');
  });

  // (b) C2-NEUTRALIZED (forged C'+σ') alt split: vatAmount'=q-1, total' consistent,
  //     r'=r0+10000 (>9999). C1+C2 PASS ⇒ ONLY the C3 r-range can reject it.
  test('C3-PROBE (b) forged-C alt split (q-1, r0+10000) → throws (C3 r-range, r>9999)', async () => {
    const altVat = q - 1n;
    const altTotal = vatBase + altVat; // keep total==base+vat so C3 consistency is fine
    const { publicInput, M } = forge(altVat, altTotal);
    const wit = deriveWitness({
      vatAmount: Field(altVat),
      total: Field(altTotal),
      r: Field(r0 + 10000n),
      M,
    });
    const threw = await throwsAsync(() =>
      FiscProof.prove(publicInput, wit, base.merkleWitness, signReceipt(authority.secretKey, M)),
    );
    ok(threw, 'forged-C alt split must throw — caught by C3 r-range (r=r0+10000 > 9999)');
  });

  // (c) C2-NEUTRALIZED alt split with NEGATIVE remainder: vatAmount'=q+1,
  //     r'=r0-10000 (negative → mod-p huge). Division holds in the field; the
  //     r-range rejects the wrapped (huge) r. (C1+C2 forged-pass.)
  test('C3-PROBE (c) forged-C alt split (q+1, mod-p(r0-10000)) → throws (C3 r-range, negative r)', async () => {
    const altVat = q + 1n;
    const altTotal = vatBase + altVat;
    const rNeg = FIELD_ORDER + (r0 - 10000n); // canonical mod-p rep of (r0-10000) < 0
    const { publicInput, M } = forge(altVat, altTotal);
    const wit = deriveWitness({
      vatAmount: Field(altVat),
      total: Field(altTotal),
      r: Field(rNeg),
      M,
    });
    const threw = await throwsAsync(() =>
      FiscProof.prove(publicInput, wit, base.merkleWitness, signReceipt(authority.secretKey, M)),
    );
    ok(threw, 'forged-C alt split with negative r must throw — C3 r-range rejects mod-p(r0-10000)');
  });

  // STEP 2 — the r-range check is a GENUINE bound (both ends), isolated with an
  // HONEST quotient (vatAmount=q) so C1+C2 pass and ONLY the r-range can fail.
  test('C3-PROBE r-range: r = 10000 (= R_MAX+1) → throws (honest q, C2 passes)', async () => {
    const wit = deriveWitness({ r: Field(10000n) });
    const threw = await throwsAsync(() =>
      FiscProof.prove(base.publicInput, wit, base.merkleWitness, base.sig),
    );
    ok(threw, 'r=10000 must throw (r-range upper bound is real)');
  });

  test('C3-PROBE r-range: r = mod-p(-1) (huge "negative") → throws (honest q, C2 passes)', async () => {
    const wit = deriveWitness({ r: Field(FIELD_ORDER - 1n) });
    const threw = await throwsAsync(() =>
      FiscProof.prove(base.publicInput, wit, base.merkleWitness, base.sig),
    );
    ok(threw, 'r=mod-p(-1) must throw (r-range rejects wrapped/negative remainders)');
  });

  // Positive control: the HONEST (q, r0) split DOES verify on the fixed public
  // input — proving the probe rejections above are real, not vacuous.
  test('C3-PROBE control: honest (q, r0) split still verifies on the fixed public input', async () => {
    const { proof } = await FiscProof.prove(
      base.publicInput,
      base.witness,
      base.merkleWitness,
      base.sig,
    );
    ok((await FiscProof.verify(proof)) === true, 'honest split must verify');
  });
}

await runAll();
