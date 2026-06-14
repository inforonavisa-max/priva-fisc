/**
 * PRIVA-FISC v0-A — generator self-check (`npm run check`)
 * ============================================================================
 * Independently re-derives, FOR EVERY FIXTURE, the same relations the next
 * task's ZK circuit will enforce — using the SHARED src/ modules (encoding,
 * commitments, merkle, schema VAT rule, IKOF). This is a PLAIN self-check, NOT
 * the ZK circuit.
 *
 * For each VALID fixture it asserts:
 *   (a) VAT relation holds         — SPEC §7-C3
 *   (b) all amounts in range       — SPEC §7-C3
 *   (c) Merkle path → sellersRoot  — SPEC §7-C4
 *   (d) itemsCommit, D, C recompute from the witness == published — SPEC §7 C2/D
 *   (e) IKOF chain verifies        — SPEC §2/§13 (RSA-SHA256 verify + MD5)
 *
 * For each INVALID fixture it asserts the tagged `_invalidReason` violation is
 * actually present. Exits non-zero on any failure.
 * ----------------------------------------------------------------------------
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createPublicKey } from 'node:crypto';
import { Field, PublicKey, Signature } from 'o1js';

import {
  computeVatCents,
  totalCentsFromBaseVat,
  type EfiRecord,
  type Fixture,
} from '../src/schema.js';
import { fieldFromJSON, isAmountInRange } from '../src/encoding.js';
import { commitC, itemsCommit, sellerLeaf } from '../src/commitments.js';
import { digestD } from '../src/canonical.js';
import { computeAttestMessage } from '../src/authority.js';
import { recomputeIndex, recomputeRoot } from '../src/merkle.js';
import { buildIkofInput } from '../src/ikof.js';
import { md5UpperHex, rsaSha256Verify } from '../src/rsa.js';

const FIXTURES_DIR = join(process.cwd(), 'fixtures');

function witnessToRecord(w: Fixture['witness']): EfiRecord {
  return {
    sellerTin: w.sellerTin,
    datetime: w.datetime,
    invoiceNo: w.invoiceNo,
    businessUnit: w.businessUnit,
    enuTcr: w.enuTcr,
    softwareCode: w.softwareCode,
    totalCents: BigInt(w.totalCents),
    vatBaseCents: BigInt(w.vatBaseCents),
    vatRateBp: w.vatRateBp,
    vatAmountCents: BigInt(w.vatAmountCents),
    buyerId: w.buyerId,
    lineItems: w.lineItems.map((it) => ({
      name: it.name,
      quantity: BigInt(it.quantity),
      unitPriceCents: BigInt(it.unitPriceCents),
    })),
    marginCents: BigInt(w.marginCents),
  };
}

interface Predicates {
  vatOk: boolean;
  rangeOk: boolean;
  rootOk: boolean;
  indexOk: boolean;
  itemsCommitOk: boolean;
  digestOk: boolean;
  commitOk: boolean;
  ikofOk: boolean;
  mOk: boolean; //   M == H(DS.ATTEST, D_hi, D_lo, C, R_reg, datetime, invoice_no)
  sigOk: boolean; // Verify(PK_A, M, σ_rcpt)  (SPEC §7-C1)
}

function evaluate(fx: Fixture): Predicates {
  const rec = witnessToRecord(fx.witness);

  // (a) VAT relation (recompute from base + rate; check stored vat + total).
  const expectedVat = computeVatCents(rec.vatBaseCents, rec.vatRateBp);
  const expectedTotal = totalCentsFromBaseVat(rec.vatBaseCents, expectedVat);
  const vatOk =
    rec.vatAmountCents === expectedVat && rec.totalCents === expectedTotal;

  // (b) range
  const amounts = [
    rec.vatBaseCents,
    rec.vatAmountCents,
    rec.totalCents,
    rec.marginCents,
    ...rec.lineItems.map((it) => it.unitPriceCents),
  ];
  const rangeOk = amounts.every(isAmountInRange);

  // (c)(d) commitments via shared modules
  const ic = itemsCommit(rec.lineItems);
  const itemsCommitOk = ic.toString() === fx.witness.itemsCommit;
  const salt = fieldFromJSON(fx.witness.salt);
  const recomputedC = commitC(rec, ic, salt);
  const commitOk = recomputedC.toString() === fx.publicInputs.C;
  const recomputedD = digestD(rec, ic); // { hi, lo, hex } = SHA-256(canonical(P))
  const D = fx.publicInputs.D;
  const digestOk =
    recomputedD.hi === D.hi && recomputedD.lo === D.lo && recomputedD.hex === D.hex;

  // (c) Merkle membership
  const leaf = sellerLeaf(rec.sellerTin);
  const root = recomputeRoot(leaf, fx.witness.merklePath);
  const rootOk = root.toString() === fx.publicInputs.sellersRoot;
  const recomputedIndex = recomputeIndex(fx.witness.merklePath);
  // index bits LSB-first must equal the recomputed index, and the stored index.
  const bitsValue = fx.witness.merkleIndexBits.reduce(
    (acc, bit, k) => acc + (bit ? 1n << BigInt(k) : 0n),
    0n,
  );
  const indexOk =
    recomputedIndex === BigInt(fx.witness.merkleIndex) &&
    bitsValue === recomputedIndex;

  // (e) IKOF chain
  const ikofInput = buildIkofInput(rec);
  let ikofOk = false;
  try {
    const pub = createPublicKey(fx.ikof.sellerRsaPublicKeyPem);
    const sig = Buffer.from(fx.ikof.iicSignatureHex, 'hex');
    ikofOk =
      ikofInput === fx.ikof.ikofInput &&
      rsaSha256Verify(ikofInput, sig, pub) &&
      md5UpperHex(sig) === fx.ikof.ikof;
  } catch {
    ikofOk = false;
  }

  // (f) C1 authority attestation (SPEC §7-C1): recompute M from public+witness,
  //     then verify σ_rcpt against (PK_A, M).
  const M = fieldFromJSON(fx.witness.M);
  const recomputedM = computeAttestMessage(
    fieldFromJSON(D.hi),
    fieldFromJSON(D.lo),
    fieldFromJSON(fx.publicInputs.C),
    fieldFromJSON(fx.publicInputs.sellersRoot),
    rec.datetime,
    rec.invoiceNo,
  );
  const mOk = recomputedM.toString() === M.toString();
  let sigOk = false;
  try {
    const pkA = PublicKey.fromBase58(fx.publicInputs.PK_A);
    const sigR = Signature.fromBase58(fx.witness.sigReceipt);
    sigOk = sigR.verify(pkA, [M]).toBoolean();
  } catch {
    sigOk = false;
  }

  return {
    vatOk,
    rangeOk,
    rootOk,
    indexOk,
    itemsCommitOk,
    digestOk,
    commitOk,
    ikofOk,
    mOk,
    sigOk,
  };
}

interface Result {
  id: string;
  pass: boolean;
  failures: string[];
}

function checkValid(fx: Fixture, p: Predicates): Result {
  const failures: string[] = [];
  if (!p.vatOk) failures.push('VAT relation (C3) failed');
  if (!p.rangeOk) failures.push('range (C3) failed');
  if (!p.rootOk) failures.push('Merkle root (C4) mismatch');
  if (!p.indexOk) failures.push('Merkle index/bits inconsistent');
  if (!p.itemsCommitOk) failures.push('itemsCommit mismatch');
  if (!p.digestOk) failures.push('D mismatch');
  if (!p.commitOk) failures.push('C (C2) mismatch');
  if (!p.mOk) failures.push('M ≠ H(DS.ATTEST, D_hi, D_lo, C, R_reg, datetime, invoice_no) (C1)');
  if (!p.sigOk) failures.push('authority signature (C1) failed to verify');
  if (!p.ikofOk) failures.push('IKOF chain failed to verify');
  return { id: fx.id, pass: failures.length === 0, failures };
}

function checkInvalid(fx: Fixture, p: Predicates): Result {
  const reason = fx._invalidReason;
  let violationPresent = false;
  switch (reason) {
    case 'VAT_MISMATCH':
      violationPresent = !p.vatOk;
      break;
    case 'SELLER_NOT_REGISTERED':
      violationPresent = !p.rootOk;
      break;
    case 'OUT_OF_RANGE':
      violationPresent = !p.rangeOk;
      break;
    case 'COMMITMENT_MISMATCH':
      violationPresent = !p.commitOk;
      break;
    case 'BAD_SIGNATURE':
      violationPresent = !p.sigOk; // σ_rcpt does not verify against (PK_A, M)
      break;
    default:
      return {
        id: fx.id,
        pass: false,
        failures: [`unknown _invalidReason: ${String(reason)}`],
      };
  }
  return {
    id: fx.id,
    pass: violationPresent,
    failures: violationPresent
      ? []
      : [`tagged violation ${reason} NOT present (fixture is not actually invalid)`],
  };
}

function main(): void {
  let files: string[];
  try {
    files = readdirSync(FIXTURES_DIR).filter(
      (f) => f.endsWith('.json') && f !== 'manifest.json',
    );
  } catch {
    console.error(`check: cannot read ${FIXTURES_DIR} — run \`npm run gen\` first.`);
    process.exit(1);
    return;
  }
  if (files.length === 0) {
    console.error('check: no fixtures found — run `npm run gen` first.');
    process.exit(1);
    return;
  }

  const results: Result[] = [];
  let validCount = 0;
  let invalidCount = 0;

  for (const f of files.sort()) {
    const fx = JSON.parse(readFileSync(join(FIXTURES_DIR, f), 'utf8')) as Fixture;
    // Firewall sanity: every fixture must carry the synthetic markers.
    if (fx._synthetic !== true || !fx._warning.includes('SYNTHETIC')) {
      results.push({
        id: fx.id ?? f,
        pass: false,
        failures: ['missing _synthetic / _warning markers'],
      });
      continue;
    }
    const p = evaluate(fx);
    if (fx.expected.valid) {
      validCount++;
      results.push(checkValid(fx, p));
    } else {
      invalidCount++;
      results.push(checkInvalid(fx, p));
    }
  }

  let passed = 0;
  for (const r of results) {
    const tag = r.pass ? 'PASS' : 'FAIL';
    console.log(`  [${tag}] ${r.id}${r.failures.length ? ' — ' + r.failures.join('; ') : ''}`);
    if (r.pass) passed++;
  }

  const total = results.length;
  console.log('');
  console.log(`PRIVA-FISC v0-A self-check: ${passed}/${total} fixtures OK`);
  console.log(`  valid checked  : ${validCount}`);
  console.log(`  invalid checked: ${invalidCount}`);
  if (passed !== total) {
    console.error(`  ✗ ${total - passed} fixture(s) failed.`);
    process.exit(1);
  }
  console.log('  ✓ all relations recompute via shared modules.');
}

main();
