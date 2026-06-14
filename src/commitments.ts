/**
 * PRIVA-FISC v0-A — Poseidon commitments & digest (SPEC §7 C2, and D)
 * ============================================================================
 * All Poseidon hashing for the relation, built on the SSOT encoding (./encoding).
 *
 *   itemsCommit = Poseidon([DS.ITEMS, count, ...itemFields])   (SPEC §7-C2 H(line_items))
 *   C           = Poseidon([DS.COMMIT, …sensitive fields…, salt]) (SPEC §7-C2)
 *   leaf        = Poseidon([DS.LEAF, enc(seller_tin)])          (SPEC §7-C4)
 *
 * NOTE: the receipt digest D = SHA-256(canonical(P)) (SPEC §7-C5/§13) is NOT here
 * — it is a BYTE hash, not Poseidon, and lives in the generator-only module
 * src/canonical.ts. This module stays o1js-ONLY (no node:crypto), so it remains
 * importable by the future ZkProgram. (Enforced by the T-PURITY guard.)
 *
 * ⚠️  COMMITMENT SCOPE — SPEC-vs-prompt reconciliation (read this).
 *     The task prompt's shorthand was `C = Poseidon(buyerId, itemsCommit,
 *     margin, salt)`. We instead implement the FULL SPEC §7-C2 commitment:
 *       C = H(DS_commit, seller_tin, buyer_id, H(line_items), margin,
 *             vat_base, vat_amount, vat_rate, total, salt)
 *     because:
 *       (1) SPEC.md is the declared single source of truth, and the NEXT task's
 *           circuit will enforce C2 — using the reduced 4-field form here would
 *           guarantee the exact generator↔circuit mismatch the prompt warns
 *           against ("silently breaks the C1 binding").
 *       (2) SPEC §5.1 explicitly requires seller_tin to be *included in C*; the
 *           reduced shorthand omits it (and the vat/total fields), contradicting
 *           the prompt's own §5.1 design decision.
 *     The prompt's four fields are a strict subset of C2, so nothing is lost.
 *     Flagged in README + docs/o1js-notes.md + the task report.
 *
 * o1js primitives: `Field`, `Poseidon.hash` (verified o1js@2.15.0).
 * ----------------------------------------------------------------------------
 */

import { Field, Poseidon } from 'o1js';
import type { EfiRecord, LineItem } from './schema.js';
import {
  DS,
  encodeAmount,
  encodeRateBp,
  encodeStringToField,
} from './encoding.js';

/**
 * itemsCommit = Poseidon([DS.ITEMS, Field(count), per-item triples...]).
 * Per-item vector layout (fixed, documented): for each item, in array order,
 *   [ encodeStringToField(name), encodeAmount(unitPriceCents), Field(quantity) ].
 */
export function itemsCommit(items: LineItem[]): Field {
  const flat: Field[] = [];
  for (const it of items) {
    flat.push(encodeStringToField(it.name));
    flat.push(encodeAmount(it.unitPriceCents));
    flat.push(encodeAmount(it.quantity)); // quantity is a non-negative integer
  }
  return Poseidon.hash([DS.ITEMS, Field(BigInt(items.length)), ...flat]);
}

// ─── Provable Field-only cores (in-circuit-safe) ────────────────────────────
// These take ALREADY-ENCODED Fields and do nothing but Poseidon — so they run
// unchanged inside a ZkProgram (src/circuit.ts) AND back the generator wrappers
// below, byte-for-byte. They keep this module o1js-pure (T-PURITY). DO NOT
// REORDER the hash inputs (circuit-shared; pinned by T-ORDER).

/**
 * Provable core of the registry leaf (SPEC §7-C4):
 *   leaf = Poseidon([DS.LEAF, encTin]).
 */
export function leafFromEncTin(encTin: Field): Field {
  return Poseidon.hash([DS.LEAF, encTin]);
}

/**
 * Provable core of the commitment C (SPEC §7-C2). Field order (DO NOT REORDER):
 *   [ DS.COMMIT, seller_tin, buyer_id, H(line_items), margin,
 *     vat_base, vat_amount, vat_rate, total, salt ]
 * All arguments are pre-encoded Fields (encodeStringToField for strings,
 * encodeAmount for amounts, encodeRateBp for the rate, itemsCommit, salt).
 */
export function commitCFields(
  encSellerTin: Field,
  encBuyerId: Field,
  itemsCommitField: Field,
  margin: Field,
  vatBase: Field,
  vatAmount: Field,
  rateBp: Field,
  total: Field,
  salt: Field,
): Field {
  return Poseidon.hash([
    DS.COMMIT,
    encSellerTin,
    encBuyerId,
    itemsCommitField,
    margin,
    vatBase,
    vatAmount,
    rateBp,
    total,
    salt,
  ]);
}

// ─── Generator wrappers (JS string/bigint → encoded Fields → cores) ─────────
// Behaviour is BYTE-IDENTICAL to the previous direct implementations; they now
// delegate to the Provable cores so the circuit and generator share one hash.

/**
 * Registry leaf (SPEC §7-C4): leaf = Poseidon([DS.LEAF, encodeStringToField(tin)]).
 * `seller_tin` stays private; only this leaf (and the root) are ever exposed.
 */
export function sellerLeaf(sellerTin: string): Field {
  return leafFromEncTin(encodeStringToField(sellerTin));
}

/**
 * Commitment C = SPEC §7-C2 (full), generator-side wrapper over commitCFields.
 */
export function commitC(
  rec: EfiRecord,
  itemsCommitField: Field,
  salt: Field,
): Field {
  return commitCFields(
    encodeStringToField(rec.sellerTin),
    encodeStringToField(rec.buyerId),
    itemsCommitField,
    encodeAmount(rec.marginCents),
    encodeAmount(rec.vatBaseCents),
    encodeAmount(rec.vatAmountCents),
    encodeRateBp(rec.vatRateBp),
    encodeAmount(rec.totalCents),
    salt,
  );
}
