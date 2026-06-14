/**
 * PRIVA-FISC v0-A — Canonical BYTE serialization + receipt digest D
 * ============================================================================
 * ⚠️  GENERATOR-ONLY MODULE. This file uses `node:crypto` (SHA-256). The
 *     circuit-shared modules (encoding.ts, commitments.ts, merkle.ts) MUST NEVER
 *     import it — that invariant is enforced by the T-PURITY regression guard.
 *
 * Per SPEC §7-C5 / §13, the receipt digest is `D = SHA-256(canonical(P))` — the
 * value the authority signature is over, taken as an OPAQUE PUBLIC INPUT in v0-A
 * and recomputed in-circuit only in Phase-5 (§7-C1 Phase-5; §9 v0-B). v0-A's
 * circuit never recomputes D, so the SHA-256 lives here, off-circuit.
 *
 * TWO REPRESENTATIONS, BY NECESSITY:
 *   • This BYTE form (length-prefixed) feeds the SHA-256 / RSA family (byte hashes).
 *   • The o1js Field encodings (encoding.ts) feed Poseidon (C / leaf / itemsCommit).
 * They are deliberately distinct: Poseidon consumes Fields, SHA-256/RSA consume
 * bytes. `line_items` is bound here via the SAME Poseidon sub-commitment
 * `itemsCommit` that the §4.1 field-tuple uses (full per-item byte expansion is a
 * Phase-5 realism refinement; v0-A binds items via itemsCommit, consistent with T).
 *
 * ── BYTE FORMAT (canonical, injective) ──────────────────────────────────────
 * For each field, in `T_FIELD_ORDER` (= SPEC §4.1) order, append:
 *     4-byte big-endian length  ‖  field bytes
 * Field bytes by type:
 *   • string fields  → UTF-8 of the value
 *   • amount fields  → ASCII decimal of the integer (cents), no leading zeros,
 *                      no separators ("0" for zero)
 *   • vat_rate_bp    → ASCII decimal of the basis-point integer
 *   • line_items     → ASCII decimal of the itemsCommit Field
 * Explicit per-field length-prefixing makes the concatenation uniquely decodable
 * ⇒ the map P → bytes is INJECTIVE (distinct payloads never collide), so SHA-256
 * over it is a sound digest. T_FIELD_ORDER is the field-order SSOT: canonicalize
 * iterates it, so a reorder there reorders the bytes (covered by T-ORDER).
 * ----------------------------------------------------------------------------
 */

import { createHash } from 'node:crypto';
import type { Field } from 'o1js';
import type { EfiRecord } from './schema.js';
import { T_FIELD_ORDER } from './encoding.js';

/** 4-byte big-endian length-prefixed chunk. */
function lp(bytes: Uint8Array): Buffer {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(bytes.length);
  return Buffer.concat([len, Buffer.from(bytes)]);
}

function lpString(s: string): Buffer {
  return lp(Buffer.from(s, 'utf8'));
}

/** ASCII decimal of a non-negative integer (no leading zeros, no separators). */
function lpDecimal(n: bigint): Buffer {
  if (n < 0n) throw new Error(`canonicalize: negative integer ${n}`);
  return lp(Buffer.from(n.toString(), 'ascii'));
}

/**
 * The SINGLE canonical byte serialization of payload P (SPEC §7-C5 `canonical(P)`).
 * Driven by T_FIELD_ORDER so field order stays the §4.1 SSOT.
 */
export function canonicalize(rec: EfiRecord, itemsCommitField: Field): Uint8Array {
  const parts: Buffer[] = [];
  for (const token of T_FIELD_ORDER) {
    switch (token) {
      case 'seller_tin': parts.push(lpString(rec.sellerTin)); break;
      case 'datetime': parts.push(lpString(rec.datetime)); break;
      case 'invoice_no': parts.push(lpString(rec.invoiceNo)); break;
      case 'business_unit': parts.push(lpString(rec.businessUnit)); break;
      case 'enu_tcr': parts.push(lpString(rec.enuTcr)); break;
      case 'software_code': parts.push(lpString(rec.softwareCode)); break;
      case 'total': parts.push(lpDecimal(rec.totalCents)); break;
      case 'vat_base': parts.push(lpDecimal(rec.vatBaseCents)); break;
      case 'vat_rate_bp': parts.push(lpDecimal(BigInt(rec.vatRateBp))); break;
      case 'vat_amount': parts.push(lpDecimal(rec.vatAmountCents)); break;
      case 'buyer_id': parts.push(lpString(rec.buyerId)); break;
      case 'line_items': parts.push(lpString(itemsCommitField.toString())); break;
      case 'margin': parts.push(lpDecimal(rec.marginCents)); break;
      default: {
        const _exhaustive: never = token;
        throw new Error(`canonicalize: unhandled field token ${_exhaustive as string}`);
      }
    }
  }
  return Buffer.concat(parts);
}

/** Big-endian bytes → decimal string (for the 128-bit limbs). */
function beToDecimal(bytes: Uint8Array): string {
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) | BigInt(b);
  return acc.toString();
}

export interface DigestD {
  /** High 128 bits of SHA-256(canonical(P)), big-endian, as decimal. */
  hi: string;
  /** Low 128 bits, big-endian, as decimal. */
  lo: string;
  /** Full 32-byte digest as 64-char lowercase hex (informational / cross-check). */
  hex: string;
}

/**
 * D = SHA-256(canonical(P)), split into two 128-bit big-endian limbs.
 * SHA-256's 256-bit output exceeds the Pallas field modulus (~2^254.86), so a
 * single Field cannot hold it losslessly; each 128-bit limb (< 2^128) is a safe
 * single Field for the future in-circuit (Phase-5) digest binding.
 */
export function digestD(rec: EfiRecord, itemsCommitField: Field): DigestD {
  const digest = createHash('sha256')
    .update(canonicalize(rec, itemsCommitField))
    .digest();
  return {
    hi: beToDecimal(digest.subarray(0, 16)),
    lo: beToDecimal(digest.subarray(16, 32)),
    hex: digest.toString('hex'),
  };
}
