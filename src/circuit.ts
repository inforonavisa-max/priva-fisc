/**
 * PRIVA-FISC v0-A — ZkProgram (the v0-A relation: C1–C4 + C5 limit)
 * ============================================================================
 * Proves SPEC §7 constraints C1–C4 over a synthetic EFI receipt, revealing only
 * the public statement. Built on the LOCKED, o1js-pure shared cores
 * (commitCFields / leafFromEncTin from commitments.ts) so the in-circuit hashes
 * are byte-identical to the generator's.
 *
 * SCHEME (SPEC §11.1 open → default): o1js native `Signature` — Schnorr over
 * Pallas, Poseidon-based; verified in-circuit via `sig.verify(PK, [M]).assertTrue()`.
 *
 * ── PUBLIC INTERFACE (SPEC §6 + the approved D2 realization) ─────────────────
 * publicInput  = { PK_A, sellersRoot (R_reg), D_hi, D_lo, C }   publicOutput = void.
 * ⚠️  §6 labels `C` the "published on-chain OUTPUT". v0-A realizes C as a
 *     CONSTRAINED PUBLIC INPUT (the circuit asserts commitCFields(witness)==C) so
 *     the COMMITMENT_MISMATCH soundness case can be exercised (a wrong published C
 *     is rejected). This is verifier-equivalent (C is part of the verified public
 *     statement either way) but an ARCHITECTURAL ROLE CHANGE from §6's "output";
 *     production / Phase-5 revisits whether C is a circuit output or input.
 * rateParams (statutory rate set + denominator + bias) are IN-CIRCUIT CONSTANTS
 * (sourced from schema.ts), not a per-proof public input (they are fixed by law).
 *
 * ── WITNESS ENCODING (honest scope) ─────────────────────────────────────────
 * The circuit witnesses PRE-ENCODED Fields: the prover runs encodeStringToField /
 * encodeAmount OFF-circuit and feeds the resulting Fields as private inputs. The
 * circuit proves relations over these committed Field encodings; the tie to the
 * actual string/amount bytes lives in D = SHA-256(canonical(P)), which is an
 * OPAQUE public input here (NOT recomputed in-circuit — that is the §7-C5 /
 * Phase-5 step). So C1 proves "the authority signed THIS (D,C,R_reg,datetime,
 * invoice_no)", NOT "D is the SHA-256 of these specific fields".
 * ----------------------------------------------------------------------------
 */

import { Field, Poseidon, PublicKey, Signature, Struct, ZkProgram } from 'o1js';
import { DS, encodeStringToField, MAX_AMOUNT_CENTS } from './encoding.js';
import { commitCFields, leafFromEncTin } from './commitments.js';
import { SellersWitness, deserializePath } from './merkle.js';
import {
  ALLOWED_VAT_RATES_BP,
  RATE_DENOMINATOR,
  ROUNDING_BIAS,
  type Fixture,
} from './schema.js';

/** Public statement (SPEC §6 set; D as two 128-bit limbs; C as constrained input — D2). */
export class FiscPublicInput extends Struct({
  PK_A: PublicKey,
  sellersRoot: Field,
  D_hi: Field,
  D_lo: Field,
  C: Field,
}) {}

/** Private witness — all PRE-ENCODED Fields (see header). */
export class FiscWitness extends Struct({
  encSellerTin: Field, // encodeStringToField(seller_tin)
  encBuyerId: Field, //   encodeStringToField(buyer_id)
  encDatetime: Field, //  encodeStringToField(datetime)
  encInvoiceNo: Field, // encodeStringToField(invoice_no)
  total: Field, //        amount (cents)
  vatBase: Field, //      amount (cents)
  vatAmount: Field, //    amount (cents)
  margin: Field, //       amount (cents)
  rateBp: Field, //       statutory rate (basis points)
  r: Field, //            VAT remainder (= (vat_base*rateBp + bias) mod denom)
  itemsCommit: Field, //  H(line_items)
  salt: Field, //         commitment randomness
  M: Field, //            §7-C1 binding message (cross-checked in-circuit)
}) {}

const MAX = Field(MAX_AMOUNT_CENTS); //   2^52 - 1 (MAXBITS=52, §7-C3)
const DENOM = Field(RATE_DENOMINATOR); //    10000
const BIAS = Field(ROUNDING_BIAS); //        5000
const R_MAX = Field(RATE_DENOMINATOR - 1n); // 9999 (remainder upper bound)

export const FiscProof = ZkProgram({
  name: 'priva-fisc-v0a',
  publicInput: FiscPublicInput,
  // publicOutput: void — a verifying proof IS the statement (D2: C is a
  // constrained public input, not an output).
  methods: {
    prove: {
      privateInputs: [FiscWitness, SellersWitness, Signature],
      async method(
        pub: FiscPublicInput,
        w: FiscWitness,
        merkleWitness: SellersWitness,
        sig: Signature,
      ) {
        // ── C1 — Attestation validity / signature binding (SPEC §7-C1) ──────
        //   M = H( DS_attest, D, C, R_reg, datetime, invoice_no )  (D → hi,lo)
        // Recompute M from PUBLIC (D_hi,D_lo,C,sellersRoot) + witness datetime/
        // invoice_no and bind it to the witnessed M (anti-replay: the attestation
        // cannot be lifted onto a different receipt), then verify σ over M.
        const mCirc = Poseidon.hash([
          DS.ATTEST,
          pub.D_hi,
          pub.D_lo,
          pub.C,
          pub.sellersRoot,
          w.encDatetime,
          w.encInvoiceNo,
        ]);
        mCirc.assertEquals(w.M);
        sig.verify(pub.PK_A, [w.M]).assertTrue();
        // §7-C5 limit (DOCUMENT, no code): v0-A does NOT recompute
        // D = SHA-256(canonical(P)) in-circuit — D is opaque. Phase-5 adds the
        // in-circuit digest, removing the attester-trust on D↔fields (§9 v0-B).

        // ── C2 — Commitment correctness (SPEC §7-C2) ────────────────────────
        // COMMITMENT_MISMATCH throws here (published C ≠ C(witness)).
        commitCFields(
          w.encSellerTin,
          w.encBuyerId,
          w.itemsCommit,
          w.margin,
          w.vatBase,
          w.vatAmount,
          w.rateBp,
          w.total,
          w.salt,
        ).assertEquals(pub.C);

        // ── C3 — VAT correctness, bounded integers (SPEC §7-C3) ─────────────
        // Range-check every monetary witness to MAXBITS=52 so field-wrap cannot
        // forge the arithmetic. Field.assertLessThanOrEqual compares canonical
        // integers in [0,p), so any value > MAX (incl. huge field elements) is
        // rejected. (OUT_OF_RANGE throws here.)
        w.vatBase.assertLessThanOrEqual(MAX);
        w.vatAmount.assertLessThanOrEqual(MAX);
        w.total.assertLessThanOrEqual(MAX);
        w.margin.assertLessThanOrEqual(MAX);

        // Statutory rate membership: Π (rateBp − allowed) == 0 ⇔ rateBp ∈ set.
        // (A degree-|set| polynomial has exactly |set| roots in the field, so this
        // also bounds rateBp small ⇒ no wrap in vat_base*rateBp below.)
        let rateMembership = Field(1);
        for (const allowed of ALLOWED_VAT_RATES_BP) {
          rateMembership = rateMembership.mul(w.rateBp.sub(Field(BigInt(allowed))));
        }
        rateMembership.assertEquals(Field(0));

        // VAT round-half-up, EXACTLY computeVatCents (schema.ts):
        //   vat = floor((vat_base*rateBp + bias)/denom)
        //   ⇔ vat*denom + r == vat_base*rateBp + bias,  0 ≤ r < denom
        // (VAT_MISMATCH throws here — no valid r closes the wrong-vat equation.)
        w.r.assertLessThanOrEqual(R_MAX); // 0 ≤ r ≤ 9999 (strict r < denom)
        w.vatAmount
          .mul(DENOM)
          .add(w.r)
          .assertEquals(w.vatBase.mul(w.rateBp).add(BIAS));

        // Consistency: total == vat_base + vat_amount.
        w.total.assertEquals(w.vatBase.add(w.vatAmount));

        // ── C4 — Seller registration / anchored membership (SPEC §7-C4) ─────
        // leaf = H(DS_leaf, enc(seller_tin)); Merkle path must recompute R_reg.
        // seller_tin stays private (§5.1). (SELLER_NOT_REGISTERED throws here.)
        const leaf = leafFromEncTin(w.encSellerTin);
        merkleWitness.calculateRoot(leaf).assertEquals(pub.sellersRoot);
      },
    },
  },
});

/** The compiled proof class (for typing test code). */
export class FiscProofClass extends ZkProgram.Proof(FiscProof) {}

/** Off-circuit builder: fixture → { publicInput, witness, merkleWitness, sig }. */
export function circuitInputsFromFixture(fx: Fixture): {
  publicInput: FiscPublicInput;
  witness: FiscWitness;
  merkleWitness: SellersWitness;
  sig: Signature;
} {
  const w = fx.witness;
  const vatBase = BigInt(w.vatBaseCents);
  const rateBp = BigInt(w.vatRateBp);
  // r = honest VAT remainder (matches computeVatCents); derived, not stored.
  const r = (vatBase * rateBp + ROUNDING_BIAS) % RATE_DENOMINATOR;

  const publicInput = new FiscPublicInput({
    PK_A: PublicKey.fromBase58(fx.publicInputs.PK_A),
    sellersRoot: Field(BigInt(fx.publicInputs.sellersRoot)),
    D_hi: Field(BigInt(fx.publicInputs.D.hi)),
    D_lo: Field(BigInt(fx.publicInputs.D.lo)),
    C: Field(BigInt(fx.publicInputs.C)),
  });

  const witness = new FiscWitness({
    encSellerTin: encodeStringToField(w.sellerTin),
    encBuyerId: encodeStringToField(w.buyerId),
    encDatetime: encodeStringToField(w.datetime),
    encInvoiceNo: encodeStringToField(w.invoiceNo),
    total: Field(BigInt(w.totalCents)),
    vatBase: Field(vatBase),
    vatAmount: Field(BigInt(w.vatAmountCents)),
    margin: Field(BigInt(w.marginCents)),
    rateBp: Field(rateBp),
    r: Field(r),
    itemsCommit: Field(BigInt(w.itemsCommit)),
    salt: Field(BigInt(w.salt)),
    M: Field(BigInt(w.M)),
  });

  const merkleWitness = new SellersWitness(deserializePath(w.merklePath));
  const sig = Signature.fromBase58(w.sigReceipt);
  return { publicInput, witness, merkleWitness, sig };
}
