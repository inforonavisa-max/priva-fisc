/**
 * PRIVA-FISC v0-A — Synthetic IKOF / IIC chain (SPEC §2, §13)
 * ============================================================================
 * Builds the synthetic IKOF chain for a receipt:
 *
 *   ikofInput      = "|"-join of 7 fields (issuer TIN, datetime, invoice no,
 *                    business unit, TCR/ENU code, software code, total)
 *   iicSignature   = RSA-SHA256(ikofInput)            (raw signature; hex below)
 *   IKOF (IIC)     = uppercase(MD5(iicSignature))     (32 hex chars)
 *   JIKR (FIC)     = authority confirmation ID        (SYNTHETIC placeholder)
 *
 * Per SPEC §13: in the real protocol the seller POS produces IKOF client-side;
 * the raw RSA signature is the separate `IICSignature` field; and JIKR is the
 * tax server's confirmation ID — NOT a signature/hash (so v0-A's authority
 * attestation, SPEC §2 trust note, is itself a Phase-5 adoption dependency).
 *
 * NONE of this is verified in-circuit in v0-A.
 * ----------------------------------------------------------------------------
 */

import type { KeyObject } from 'node:crypto';
import { createHash } from 'node:crypto';
import type { EfiRecord, IkofChain } from './schema.js';
import { md5UpperHex, rsaSha256Sign } from './rsa.js';

/** cents → decimal string with 2 fraction digits, e.g. 12345n → "123.45". */
export function centsToDecimalString(cents: bigint): string {
  const neg = cents < 0n;
  const abs = neg ? -cents : cents;
  const whole = abs / 100n;
  const frac = abs % 100n;
  return `${neg ? '-' : ''}${whole}.${frac.toString().padStart(2, '0')}`;
}

/**
 * Build the 7-field, "|"-joined IKOF input string (SPEC §2 / §13).
 *
 * TODO(confirm): the exact field set, ORDER, and value formatting (date format,
 * total formatting, separators) for the real Montenegro IKOF must be confirmed
 * against the official "Tehnička uputstva". The order below is the commonly
 * documented IIC field set — synthetic-shape only, NOT an authoritative claim.
 *
 * Order used here:
 *   1. issuer TIN (seller PIB)
 *   2. issue datetime (ISO-8601)
 *   3. invoice ordinal number
 *   4. business-unit code
 *   5. TCR/ENU cash-register code
 *   6. software code
 *   7. total price (gross), decimal string
 */
export function buildIkofInput(rec: EfiRecord): string {
  return [
    rec.sellerTin,
    rec.datetime,
    rec.invoiceNo,
    rec.businessUnit,
    rec.enuTcr,
    rec.softwareCode,
    centsToDecimalString(rec.totalCents),
  ].join('|');
}

/**
 * Deterministic SYNTHETIC JIKR/FIC placeholder. Clearly mock — the real JIKR is
 * issued by the Tax Administration server and is out of any prover's control.
 * Derived deterministically from the IKOF input so it is stable per record.
 */
export function syntheticJikr(ikofInput: string): string {
  const h = createHash('sha256').update(ikofInput, 'utf8').digest('hex');
  // Shape a UUID-ish, obviously-synthetic token (NOT a real JIKR format).
  const a = h.slice(0, 8);
  const b = h.slice(8, 12);
  const c = h.slice(12, 16);
  const d = h.slice(16, 20);
  const e = h.slice(20, 32);
  return `SYNTH-JIKR-${a}-${b}-${c}-${d}-${e}`;
}

/** Assemble the full synthetic IKOF chain for a record. */
export function buildIkofChain(
  rec: EfiRecord,
  privateKey: KeyObject,
  sellerRsaPublicKeyPem: string,
): IkofChain {
  const ikofInput = buildIkofInput(rec);
  const iicSignature = rsaSha256Sign(ikofInput, privateKey);
  return {
    ikofInput,
    iicSignatureHex: iicSignature.toString('hex'),
    ikof: md5UpperHex(iicSignature),
    jikr: syntheticJikr(ikofInput),
    sellerRsaPublicKeyPem,
  };
}
