/**
 * PRIVA-FISC v0-A — Deterministic synthetic EFI record + registry generation
 * ============================================================================
 * Generates SYNTHETIC, schema-shaped records (SPEC §4.1) and a synthetic
 * registered-sellers list. Everything is reproducible from a string seed.
 *
 * ⚠️  D5 DATA FIREWALL (absolute): NO real PII, NO real fiscal data, NO real
 *     certificates. Seller PIBs come from an obviously-synthetic reserved range;
 *     buyers/items are opaque fabricated IDs. See README "Data firewall".
 * ----------------------------------------------------------------------------
 */

import {
  computeVatCents,
  totalCentsFromBaseVat,
  ALLOWED_VAT_RATES_BP,
  type EfiRecord,
  type InvalidReason,
  type LineItem,
} from './schema.js';
import { MAX_AMOUNT_CENTS } from './encoding.js';
import { DeterministicPrng } from './prng.js';

export const DEFAULT_SEED = 'PRIVA-FISC-v0-A';

// ---- Synthetic identifier ranges (D5 firewall) -----------------------------
//
// TODO(confirm): real PIB format/checksum. Montenegrin PIB is ~8 digits; the
// values below are SYNTHETIC-SHAPE ONLY (no checksum/format fidelity claimed).
// Registered sellers use the reserved "9090" prefix; deliberately-unregistered
// sellers use "9099" so they can never collide with a registry slot.
const PIB_REGISTERED_PREFIX = '9090';
const PIB_UNREGISTERED_PREFIX = '9099';

function syntheticPib(prefix: string, n: number): string {
  return `${prefix}${n.toString().padStart(4, '0')}`;
}

// Fixed base instant for deterministic ISO datetimes (NOT wall-clock "now").
const BASE_EPOCH_MS = Date.UTC(2026, 0, 1, 9, 0, 0); // 2026-01-01T09:00:00Z

function syntheticDatetime(index: number): string {
  return new Date(BASE_EPOCH_MS + index * 3_600_000).toISOString();
}

// Modest synthetic money range (far below MAX_AMOUNT_CENTS): €1.00 .. €100,000.00
const MIN_BASE_CENTS = 100n;
const MAX_BASE_CENTS = 10_000_000n;

function syntheticLineItems(prng: DeterministicPrng): LineItem[] {
  const count = prng.nextIntInRange(1, 3);
  const items: LineItem[] = [];
  for (let i = 0; i < count; i++) {
    items.push({
      name: `SYNTH-ITEM-${(i + 1).toString().padStart(2, '0')}`,
      quantity: BigInt(prng.nextIntInRange(1, 5)),
      unitPriceCents: BigInt(prng.nextIntInRange(50, 250_000)),
    });
  }
  return items;
}

/** Common synthetic scaffolding shared by every record. */
function baseRecordFields(prng: DeterministicPrng, index: number) {
  return {
    datetime: syntheticDatetime(index),
    invoiceNo: `SYNTH-INV-2026-${(index + 1).toString().padStart(6, '0')}`,
    businessUnit: `SYNTH-BU-${prng.nextIntInRange(1, 9).toString().padStart(3, '0')}`,
    enuTcr: `SYNTH-TCR-${prng.nextIntInRange(1, 9).toString().padStart(3, '0')}`,
    softwareCode: `SYNTH-SW-${prng.nextIntInRange(1, 9).toString().padStart(2, '0')}`,
    buyerId: `SYNTH-BUYER-${(index + 1).toString().padStart(4, '0')}`,
    lineItems: syntheticLineItems(prng),
  };
}

/** A well-formed, arithmetically-correct record for the given seller TIN. */
export function makeValidRecord(
  prng: DeterministicPrng,
  index: number,
  sellerTin: string,
): EfiRecord {
  const common = baseRecordFields(prng, index);
  const vatRateBp = prng.pick(ALLOWED_VAT_RATES_BP);
  const baseCents =
    MIN_BASE_CENTS + prng.nextBigIntBelow(MAX_BASE_CENTS - MIN_BASE_CENTS + 1n);
  const vatAmountCents = computeVatCents(baseCents, vatRateBp);
  const totalCents = totalCentsFromBaseVat(baseCents, vatAmountCents);
  // margin = 5..40% of base (kept well in range).
  const marginPct = BigInt(prng.nextIntInRange(5, 40));
  const marginCents = (baseCents * marginPct) / 100n;

  return {
    sellerTin,
    ...common,
    vatBaseCents: baseCents,
    vatRateBp,
    vatAmountCents,
    totalCents,
    marginCents,
  };
}

/** The set of registered seller TINs assigned to registry slots [0..size). */
export function buildRegisteredTins(size: number): string[] {
  return Array.from({ length: size }, (_, i) =>
    syntheticPib(PIB_REGISTERED_PREFIX, i + 1),
  );
}

export interface GeneratorConfig {
  seed: string;
  validCount: number;
  /** How many of each invalid reason to emit. */
  invalidCounts: Record<InvalidReason, number>;
  /** Number of registry slots to populate. */
  registrySize: number;
}

export const DEFAULT_CONFIG: GeneratorConfig = {
  seed: DEFAULT_SEED,
  validCount: 5,
  invalidCounts: {
    VAT_MISMATCH: 1,
    SELLER_NOT_REGISTERED: 1,
    OUT_OF_RANGE: 1,
    COMMITMENT_MISMATCH: 1,
  },
  registrySize: 16,
};

/**
 * Mutation applied to a fresh valid record to realize one invalid reason.
 * Returns the mutated record plus a flag describing what (besides the record)
 * the fixture assembler must corrupt (e.g. the published commitment, or the
 * Merkle path). Exactly ONE constraint is violated per fixture.
 */
export interface InvalidMutation {
  record: EfiRecord;
  reason: InvalidReason;
  /** For SELLER_NOT_REGISTERED: seller is absent from the registry. */
  sellerUnregistered: boolean;
  /** For COMMITMENT_MISMATCH: publish a C that differs from C(witness). */
  corruptPublishedCommitment: boolean;
}

export function makeInvalidMutation(
  prng: DeterministicPrng,
  index: number,
  reason: InvalidReason,
  registeredTin: string,
  unregisteredTin: string,
): InvalidMutation {
  const valid = makeValidRecord(prng, index, registeredTin);

  switch (reason) {
    case 'VAT_MISMATCH': {
      // Break the rate arithmetic: stored VAT ≠ round(base·rate). Keep total
      // consistent with the (wrong) stored VAT so ONLY the rate relation fails.
      const wrongVat = valid.vatAmountCents + 1n;
      return {
        record: {
          ...valid,
          vatAmountCents: wrongVat,
          totalCents: totalCentsFromBaseVat(valid.vatBaseCents, wrongVat),
        },
        reason,
        sellerUnregistered: false,
        corruptPublishedCommitment: false,
      };
    }
    case 'SELLER_NOT_REGISTERED': {
      // Seller TIN is from the unregistered range; the fixture assembler will
      // attach a path that cannot recompute to the registry root.
      return {
        record: { ...valid, sellerTin: unregisteredTin },
        reason,
        sellerUnregistered: true,
        corruptPublishedCommitment: false,
      };
    }
    case 'OUT_OF_RANGE': {
      // base exceeds MAX_AMOUNT_CENTS; VAT relation kept internally consistent.
      const baseCents = MAX_AMOUNT_CENTS + 1n;
      const vatAmountCents = computeVatCents(baseCents, valid.vatRateBp);
      return {
        record: {
          ...valid,
          vatBaseCents: baseCents,
          vatAmountCents,
          totalCents: totalCentsFromBaseVat(baseCents, vatAmountCents),
        },
        reason,
        sellerUnregistered: false,
        corruptPublishedCommitment: false,
      };
    }
    case 'COMMITMENT_MISMATCH': {
      // Record is fully valid; the published C will be corrupted by the assembler.
      return {
        record: valid,
        reason,
        sellerUnregistered: false,
        corruptPublishedCommitment: true,
      };
    }
    default: {
      const _exhaustive: never = reason;
      throw new Error(`unhandled invalid reason: ${_exhaustive as string}`);
    }
  }
}

export { PIB_UNREGISTERED_PREFIX, syntheticPib };
