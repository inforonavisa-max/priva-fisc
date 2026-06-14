/**
 * PRIVA-FISC v0-A — CANONICAL ENCODING (SINGLE SOURCE OF TRUTH)
 * ============================================================================
 * This module defines EXACTLY how every schema field (SPEC §4.1) is encoded
 * into o1js `Field` element(s) for Poseidon hashing.
 *
 * ⚠️  CRITICAL: This module is imported by the synthetic generator NOW and will
 *     be imported by the ZK circuit (ZkProgram) in the NEXT task. They MUST
 *     share it byte-for-byte. A divergence between generator-encoding and
 *     circuit-encoding silently breaks the C1 signature binding and the C2
 *     commitment (the prover's `C`/`D` would never equal the circuit's) — so
 *     all field→Field encoding lives here and ONLY here.
 *
 * Source of truth for the *relation*: ../spec/SPEC.md (v0-A). See §3, §4.1, §7.
 *
 * o1js primitives used (verified against installed o1js@2.15.0 — see
 * ../docs/o1js-notes.md): `Field`, `Poseidon.hash`.
 * ----------------------------------------------------------------------------
 */

import { Field, Poseidon } from 'o1js';

// ----------------------------------------------------------------------------
// Monetary range bound (SPEC §7-C3) — resolved §11.4 build decision
// ----------------------------------------------------------------------------
//
// Money is carried as INTEGER MINOR UNITS (euro cents; Montenegro is euroized,
// SPEC §3). The VAT rule (see ./schema.ts + ./synthetic.ts) is, per the baked-in
// task decision, applied at BASIS-POINT precision:
//
//     vatCents = floor((baseCents * vatRateBp + 5000) / 10000)
//
// with vatRateBp ∈ {2100, 700, 0}. The largest multiplier is 2100 (< 2^12).
// The task requires `baseCents * vatRateBp < 2^64` (uint64 headroom for a future
// UInt64-based circuit). Therefore:
//
//     MAXBITS = 52   →   MAX_AMOUNT_CENTS = 2^52 - 1
//     2^52 * 2100 ≈ 9.46e18  <  2^64 ≈ 1.845e19   ✓ (with room for the +5000
//                                                     bias and total=base+vat).
//
// NOTE: SPEC §7-C3 gives the example "MAXBITS e.g. 53" for the *percent* form
// (vat_rate ∈ {0,7,21}, multiplier ≤ 21 ≈ 2^5). The basis-point form used by
// this generator needs ~12 bits of multiplier headroom instead of ~5, so we
// pin MAXBITS = 52 (tighter than the SPEC example, on purpose). This is the
// §11.4 "resolved during build" decision; documented in README.
export const MAXBITS = 52;
export const MAX_AMOUNT_CENTS: bigint = (1n << BigInt(MAXBITS)) - 1n;

// Pallas base field order (o1js native `Field`). Cached as a constant for range
// reasoning/documentation; verified == Field.ORDER at module load (below).
export const FIELD_ORDER: bigint =
  28948022309329048855892746252171976963363056481941560715954676764349967630337n;

// Defensive: fail fast if the installed o1js field order ever changes under us.
if (Field.ORDER !== FIELD_ORDER) {
  throw new Error(
    `encoding.ts: Field.ORDER mismatch — installed o1js uses ${Field.ORDER}, ` +
      `this module was written against ${FIELD_ORDER}. Re-verify the encoding.`,
  );
}

// Max bytes that pack losslessly into one Field: 31 bytes = 248 bits < 255-bit
// field order. (Verified in docs/o1js-notes.md.)
export const BYTES_PER_FIELD = 31;

// ----------------------------------------------------------------------------
// Domain-separation tags (SPEC §7 uses H(DS_*, …); concrete values per §11.7)
// ----------------------------------------------------------------------------
//
// TODO(confirm): final DS_* values are pinned in build per SPEC §11.7. These
// small distinct integers are the v0-A choice — concrete, documented, and
// sufficient for domain separation between the three Poseidon uses below.
//
// NOTE: there is no DS tag for the receipt digest D — D = SHA-256(canonical(P))
// is a BYTE hash (SPEC §7-C5/§13), not a Poseidon hash; see src/canonical.ts.
export const DS = {
  /** C = Poseidon([DS.COMMIT, …])     — SPEC §7-C2 sensitive-field commitment */
  COMMIT: Field(2),
  /** leaf = Poseidon([DS.LEAF, encTin])— SPEC §7-C4 registry leaf            */
  LEAF: Field(3),
  /** itemsCommit = Poseidon([DS.ITEMS, …]) — SPEC §7-C2 H(line_items)        */
  ITEMS: Field(4),
} as const;

// ----------------------------------------------------------------------------
// String → Field encoding
// ----------------------------------------------------------------------------
//
// Method (the v0-A canonical string encoding):
//   1. s → UTF-8 bytes.
//   2. Split bytes into BYTES_PER_FIELD (=31) big-endian chunks; each chunk →
//      one Field via base-256 big-endian interpretation.
//   3. encodeStringToField(s) = Poseidon([Field(byteLength), ...chunkFields]).
//
// Properties:
//   • Deterministic and total (defined for every UTF-8 string, any length).
//   • Collision-resistant: length-prefixed + chunked, so distinct strings (and
//     distinct lengths that would otherwise share a packed value, e.g. "A" vs
//     "A\0…") map to distinct digests.
//   • Always yields exactly ONE Field (keeps the field-tuple T fixed-arity).
//
// A short field (≤31 bytes, the common case: TINs, codes) reduces to
// Poseidon([Field(len), Field(packedBytes)]).
export function utf8Bytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function bigIntFromBE(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) | BigInt(b);
  return acc;
}

/** Pack arbitrary bytes into big-endian 31-byte Field chunks. */
export function bytesToFields(bytes: Uint8Array): Field[] {
  const out: Field[] = [];
  for (let i = 0; i < bytes.length; i += BYTES_PER_FIELD) {
    out.push(Field(bigIntFromBE(bytes.subarray(i, i + BYTES_PER_FIELD))));
  }
  return out;
}

/** Canonical string → single Field (length-prefixed Poseidon over packed bytes). */
export function encodeStringToField(s: string): Field {
  const bytes = utf8Bytes(s);
  return Poseidon.hash([Field(bytes.length), ...bytesToFields(bytes)]);
}

// ----------------------------------------------------------------------------
// Amount (cents) → Field encoding
// ----------------------------------------------------------------------------
//
// Money fields are encoded as the non-negative integer cents value directly:
//   encodeAmount(cents) = Field(cents).
//
// Encoding is intentionally permissive (it does NOT enforce MAX_AMOUNT_CENTS):
// an out-of-range value is still a valid Field element (< FIELD_ORDER). RANGE
// enforcement (SPEC §7-C3) is a *validity predicate* (see isAmountInRange /
// ../synthetic.ts), NOT an encoding error — this lets the generator emit the
// deliberate OUT_OF_RANGE negative fixtures. Negatives are never valid synthetic
// money and are rejected here.
export function encodeAmount(cents: bigint): Field {
  if (cents < 0n) {
    throw new Error(`encodeAmount: negative cents not allowed (${cents})`);
  }
  if (cents >= FIELD_ORDER) {
    throw new Error(`encodeAmount: value ${cents} ≥ field order`);
  }
  return Field(cents);
}

/** SPEC §7-C3 range predicate: 0 ≤ cents ≤ MAX_AMOUNT_CENTS. */
export function isAmountInRange(cents: bigint): boolean {
  return cents >= 0n && cents <= MAX_AMOUNT_CENTS;
}

/** VAT rate (basis points) → Field. Small statutory integer; see schema.ts. */
export function encodeRateBp(rateBp: number): Field {
  if (!Number.isInteger(rateBp) || rateBp < 0) {
    throw new Error(`encodeRateBp: invalid basis points ${rateBp}`);
  }
  return Field(BigInt(rateBp));
}

// ----------------------------------------------------------------------------
// Field-tuple field ORDER (SSOT — mirrors SPEC §4.1 row order)
// ----------------------------------------------------------------------------
//
// T_FIELD_ORDER is the canonical §4.1 field ORDER (the single source of truth for
// field ordering). `line_items` is represented by its sub-commitment `itemsCommit`
// (= H(line_items), SPEC §7-C2). It is consumed by the BYTE canonicalizer
// (src/canonical.ts, which drives D = SHA-256(canonical(P))) and is asserted
// against §4.1 by the T-ORDER guard.
//
// Canonical order (index → field), DO NOT REORDER (the circuit depends on it):
export const T_FIELD_ORDER = [
  'seller_tin', // 0  string  (private; SPEC §5.1)
  'datetime', //   1  string
  'invoice_no', //  2  string
  'business_unit', // 3 string
  'enu_tcr', //     4  string
  'software_code', // 5 string
  'total', //       6  amount (cents)
  'vat_base', //    7  amount (cents)
  'vat_rate_bp', // 8  basis points
  'vat_amount', //  9  amount (cents)
  'buyer_id', //    10 string
  'line_items', //  11 itemsCommit (Field) — represents H(line_items)
  'margin', //      12 amount (cents)
] as const;

export const T_LENGTH = T_FIELD_ORDER.length; // 13

// (The former `toFieldTuple` Field-vector builder was removed: its sole consumer
//  was the old Poseidon `D`, now replaced by D = SHA-256(canonical(P)) in
//  src/canonical.ts. The per-field encoders below remain in use by C / leaf /
//  itemsCommit, and T_FIELD_ORDER now drives the byte canonicalizer.)

// ----------------------------------------------------------------------------
// JSON (de)serialization helpers for fixtures (Field/bigint are not JSON-native)
// ----------------------------------------------------------------------------
//
// Convention: every Field and every money/amount value is serialized as a
// DECIMAL STRING. Round-trip via these helpers so the self-check reads back the
// exact values the generator hashed.
export function fieldToJSON(f: Field): string {
  return f.toString();
}
export function fieldFromJSON(s: string): Field {
  return Field(BigInt(s));
}
export function amountToJSON(cents: bigint): string {
  return cents.toString();
}
export function amountFromJSON(s: string): bigint {
  return BigInt(s);
}
