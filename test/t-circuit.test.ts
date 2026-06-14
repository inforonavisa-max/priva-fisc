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

import {
  FiscProof,
  FiscWitness,
  circuitInputsFromFixture,
} from '../src/circuit.js';
import { encodeStringToField } from '../src/encoding.js';
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

await runAll();
