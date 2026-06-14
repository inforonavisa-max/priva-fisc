/**
 * PRIVA-FISC v0-A — SCHEMA (mirrors SPEC §4.1 receipt payload `P`)
 * ============================================================================
 * TypeScript shapes for the synthetic EFI-shaped receipt and the v0-A fixture
 * envelope. Money is carried as `bigint` cents everywhere (exact; no floats).
 *
 * Source of truth: ../spec/SPEC.md §4.1 (data model), §6 (circuit interface),
 * §7 (constraints). Field encoding lives in ./encoding.ts (the SSOT).
 * ----------------------------------------------------------------------------
 */

// ----------------------------------------------------------------------------
// Statutory VAT rate set + rounding convention (baked-in build decision)
// ----------------------------------------------------------------------------
//
// TODO(confirm): VAT rate set + rounding convention against Montenegro
// "Tehnička uputstva". Do NOT treat as authoritative — these are PLACEHOLDER
// values for the synthetic generator only.
//
// vat_rate is carried in BASIS POINTS (1% = 100 bp). SPEC §7-C3 expresses the
// statutory set in percent {0,7,21}; in basis points that is {0,700,2100}.
export const ALLOWED_VAT_RATES_BP: readonly number[] = [2100, 700, 0] as const;
export type VatRateBp = (typeof ALLOWED_VAT_RATES_BP)[number] | number;

// VAT rule (default, round-half-up at basis-point precision):
//   vatCents   = floor((baseCents * vatRateBp + ROUNDING_BIAS) / RATE_DENOMINATOR)
//   totalCents = baseCents + vatCents
export const RATE_DENOMINATOR = 10000n; // basis points → fraction
export const ROUNDING_BIAS = 5000n; //     +half of denominator ⇒ round-half-up

/** Statutory rate parameters published in the fixture (circuit C3 inputs). */
export interface RateParams {
  /** Allowed statutory rates, basis points (SPEC §7-C3 statutory set). */
  allowedRatesBp: number[];
  /** Basis-point denominator (10000). */
  denominator: string;
  /** Round-half-up bias (5000). */
  roundingBias: string;
  /** Human label for the rounding convention. */
  roundingMode: 'half-up';
}

export const RATE_PARAMS: RateParams = {
  allowedRatesBp: [...ALLOWED_VAT_RATES_BP],
  denominator: RATE_DENOMINATOR.toString(),
  roundingBias: ROUNDING_BIAS.toString(),
  roundingMode: 'half-up',
};

/**
 * The v0-A VAT rule (SSOT — used by BOTH the generator and the self-check):
 *   vatCents = floor((baseCents * vatRateBp + ROUNDING_BIAS) / RATE_DENOMINATOR)
 * Round-half-up at basis-point precision. Operands are non-negative so bigint
 * division floors as intended.
 */
export function computeVatCents(baseCents: bigint, vatRateBp: number): bigint {
  if (baseCents < 0n) throw new Error('computeVatCents: negative base');
  if (vatRateBp < 0) throw new Error('computeVatCents: negative rate');
  return (baseCents * BigInt(vatRateBp) + ROUNDING_BIAS) / RATE_DENOMINATOR;
}

/** total = base + vat (SPEC §7-C3 consistency). */
export function totalCentsFromBaseVat(baseCents: bigint, vatCents: bigint): bigint {
  return baseCents + vatCents;
}

// ----------------------------------------------------------------------------
// Line item (SPEC §4.1 `line_items` — representation open per §11.2)
// ----------------------------------------------------------------------------
//
// v0-A representation choice: fixed-tuple-per-item, hashed into a single
// `itemsCommit` (see ./commitments.ts). Synthetic, opaque names only.
export interface LineItem {
  /** Opaque synthetic item label, never a real product/PII. */
  name: string;
  /** Integer quantity. */
  quantity: bigint;
  /** Unit price in cents. */
  unitPriceCents: bigint;
}

// ----------------------------------------------------------------------------
// Receipt payload `P` — the 13 §4.1 fields (all PRIVATE witness in v0-A)
// ----------------------------------------------------------------------------
export interface EfiRecord {
  // — string-typed identity/metadata fields —
  /** Seller PIB (tax ID). PRIVATE (SPEC §5.1). Synthetic reserved range. */
  sellerTin: string;
  /** ISO-8601 issue time. Binds anti-replay (SPEC §4.1, §7-C1). */
  datetime: string;
  /** Invoice ordinal. */
  invoiceNo: string;
  /** Business-unit code. */
  businessUnit: string;
  /** ENU/TCR cash-register code. */
  enuTcr: string;
  /** Software code. */
  softwareCode: string;

  // — monetary fields (cents) —
  /** Gross total (cents). MUST equal vatBase + vatAmount (SPEC §7-C3). */
  totalCents: bigint;
  /** Net base (cents). */
  vatBaseCents: bigint;
  /** Applied statutory rate (basis points). Private (SPEC §5.3 / §11.5). */
  vatRateBp: number;
  /** VAT amount (cents). */
  vatAmountCents: bigint;

  // — sensitive commercial fields —
  /** Buyer identity — opaque synthetic id, never real PII. */
  buyerId: string;
  /** Item-level detail. */
  lineItems: LineItem[];
  /** Seller margin (cents). */
  marginCents: bigint;
}

// ----------------------------------------------------------------------------
// Invalid-reason taxonomy (negative fixtures for the next task's circuit tests)
// ----------------------------------------------------------------------------
export const INVALID_REASONS = [
  'VAT_MISMATCH', //          violates SPEC §7-C3 arithmetic/consistency
  'SELLER_NOT_REGISTERED', // violates SPEC §7-C4 Merkle membership
  'OUT_OF_RANGE', //          violates SPEC §7-C3 range bound (> MAX_AMOUNT_CENTS)
  'COMMITMENT_MISMATCH', //   violates SPEC §7-C2 (published C ≠ C(witness))
] as const;
export type InvalidReason = (typeof INVALID_REASONS)[number];

// ----------------------------------------------------------------------------
// Synthetic-data firewall markers (D5) — present on every emitted record
// ----------------------------------------------------------------------------
export const SYNTHETIC_FLAG = true as const;
export const SYNTHETIC_WARNING =
  'SYNTHETIC TEST DATA — NO REAL PII — NOT FOR PRODUCTION' as const;

export interface SyntheticMarkers {
  _synthetic: typeof SYNTHETIC_FLAG;
  _warning: typeof SYNTHETIC_WARNING;
}

// ----------------------------------------------------------------------------
// Fixture envelope (SPEC §6 interface + self-check witness)
// ----------------------------------------------------------------------------
//
// All Field/amount values are DECIMAL STRINGS (see ./encoding.ts JSON helpers).

/** IKOF chain artifacts (SPEC §2/§13). */
export interface IkofChain {
  /** 7-field, "|"-joined IKOF input string (the RSA-signed message). */
  ikofInput: string;
  /** Raw RSA-SHA256 signature, hex (the real protocol's `IICSignature`). */
  iicSignatureHex: string;
  /** IKOF (IIC) = uppercase(MD5(IICSignature)), 32 hex chars. */
  ikof: string;
  /** JIKR/FIC — authority confirmation ID. SYNTHETIC placeholder (SPEC §13). */
  jikr: string;
  /** Seller RSA public key (SPKI PEM) used to verify `iicSignatureHex`. */
  sellerRsaPublicKeyPem: string;
}

/** Public inputs/outputs (SPEC §6). C is public OUTPUT; D, R_reg, PK_A inputs. */
export interface PublicInputs {
  /** C — Poseidon commitment, public output (SPEC §6, §7-C2). */
  C: string;
  /**
   * D — receipt digest = SHA-256(canonical(P)) (SPEC §7-C5, §13), disclosed
   * public input. Two 128-bit big-endian limbs (a 256-bit digest exceeds the
   * Pallas field, so it cannot be one Field) + full hex. See src/canonical.ts.
   */
  D: { hi: string; lo: string; hex: string };
  /** R_reg — registered-sellers Merkle root (SPEC §6 `R_reg`). */
  sellersRoot: string;
  /**
   * PK_A reference — authority key. The v0-A authority ZK-signature
   * (Schnorr/EdDSA-native, SPEC §3/§7-C1) and σ_rcpt/σ_reg attestations are
   * produced by the CIRCUIT task, not this generator; this is a documented
   * placeholder. (The *seller* RSA key for the IKOF chain is separate —
   * see IkofChain.sellerRsaPublicKeyPem.)
   */
  PK_ref: {
    scheme: 'zk-native-signature (deferred to circuit task)';
    note: string;
    value: null;
  };
  /** Statutory rate parameters (SPEC §7-C3). */
  rateParams: RateParams;
}

/** Private witness (SPEC §6) — everything needed to recompute C, D, leaf, root. */
export interface FixtureWitness {
  // all T (§4.1) fields:
  sellerTin: string;
  datetime: string;
  invoiceNo: string;
  businessUnit: string;
  enuTcr: string;
  softwareCode: string;
  totalCents: string; //    decimal string
  vatBaseCents: string; //  decimal string
  vatRateBp: number;
  vatAmountCents: string; // decimal string
  buyerId: string;
  lineItems: { name: string; quantity: string; unitPriceCents: string }[];
  /** SPEC §7-C2 commits `margin`; carried explicitly (== marginCents). */
  marginCents: string; //   decimal string
  /** itemsCommit = H(line_items); carried so the self-check can cross-verify. */
  itemsCommit: string;
  /** Commitment randomness `salt` (SPEC §6, §7-C2), Field decimal string. */
  salt: string;
  /** Merkle inclusion path: leaf→root siblings (SPEC §7-C4 `path_reg`). */
  merklePath: { sibling: string; isLeft: boolean }[];
  /** Leaf index bits, LSB-first (bit k = isLeft[k] ? 0 : 1; see o1js-notes). */
  merkleIndexBits: number[];
  /** Leaf index (decimal), for convenience/self-check. */
  merkleIndex: number;
}

export interface Fixture extends SyntheticMarkers {
  /** Stable id, e.g. "valid-000" / "invalid-vat_mismatch-000". */
  id: string;
  publicInputs: PublicInputs;
  witness: FixtureWitness;
  expected: { valid: boolean };
  /** Present iff expected.valid === false. */
  _invalidReason?: InvalidReason;
  /** IKOF chain artifacts (SPEC §2/§13). */
  ikof: IkofChain;
  /** Synthetic EFI record + lightweight (NON-C14N) XML rendering for realism. */
  efi: {
    record: {
      sellerTin: string;
      datetime: string;
      invoiceNo: string;
      businessUnit: string;
      enuTcr: string;
      softwareCode: string;
      totalCents: string;
      vatBaseCents: string;
      vatRateBp: number;
      vatAmountCents: string;
      buyerId: string;
      lineItems: { name: string; quantity: string; unitPriceCents: string }[];
      marginCents: string;
    };
    /**
     * Lightweight synthetic EFI XML. NOTE: byte-exact enveloped XML-DSig /
     * Exclusive-C14N is NOT performed in v0-A (Phase-5; SPEC §3, §13). The
     * circuit's canonical form is the field-tuple Poseidon digest D, NOT this
     * XML. This string exists only for shape/realism.
     */
    xmlSyntheticNonCanonical: string;
    _note: string;
  };
}
