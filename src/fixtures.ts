/**
 * PRIVA-FISC v0-A — Fixture assembly (SPEC §6 interface envelope)
 * ============================================================================
 * Ties the pieces together into the fixture envelope consumed by scripts/check.ts
 * (now) and the ZkProgram tests (next task): publicInputs {C,D,sellersRoot,
 * PK_ref,rateParams} · witness {…T, marginCents, itemsCommit, salt, merklePath,
 * merkleIndexBits} · expected {valid} · _invalidReason? · ikof · efi.
 *
 * `expected.valid` reflects the GENERATOR-CHECKABLE relation subset (SPEC §7
 * C2/C3/C4 + structural well-formedness). C1 (the authority ZK-signature) is
 * NOT generated here — it is the next (circuit) task; see PublicInputs.PK_ref.
 * ----------------------------------------------------------------------------
 */

import { Field } from 'o1js';
import {
  RATE_PARAMS,
  SYNTHETIC_FLAG,
  SYNTHETIC_WARNING,
  type EfiRecord,
  type Fixture,
  type FixtureWitness,
  type InvalidReason,
} from './schema.js';
import { amountToJSON, fieldToJSON } from './encoding.js';
import { centsToDecimalString } from './ikof.js';
import { commitC, itemsCommit, sellerLeaf } from './commitments.js';
import { digestD } from './canonical.js';
import {
  buildSellersTree,
  inclusionPath,
  MERKLE_HEIGHT,
  recomputeRoot,
  type InclusionPath,
  type SellersTree,
} from './merkle.js';
import { buildIkofChain } from './ikof.js';
import { loadOrCreateSellerKeypair, type SyntheticRsaKeypair } from './rsa.js';
import {
  buildRegisteredTins,
  DEFAULT_CONFIG,
  makeInvalidMutation,
  makeValidRecord,
  PIB_UNREGISTERED_PREFIX,
  syntheticPib,
  type GeneratorConfig,
} from './synthetic.js';
import { DeterministicPrng } from './prng.js';

const PK_REF_PLACEHOLDER = {
  scheme: 'zk-native-signature (deferred to circuit task)' as const,
  note:
    'Authority ZK-signature (Schnorr/EdDSA-native, SPEC §3/§7-C1) and the ' +
    'σ_rcpt/σ_reg attestations are produced by the NEXT (circuit) task, not ' +
    'this generator. The seller RSA key for the IKOF chain is separate ' +
    '(see ikof.sellerRsaPublicKeyPem).',
  value: null,
};

/** Lightweight synthetic EFI XML (NOT C14N, NOT signed — shape/realism only). */
function renderSyntheticXml(rec: EfiRecord, ikof: string, jikr: string): string {
  const items = rec.lineItems
    .map(
      (it) =>
        `    <Item name="${it.name}" qty="${it.quantity}" unitPrice="${centsToDecimalString(
          it.unitPriceCents,
        )}"/>`,
    )
    .join('\n');
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<!-- SYNTHETIC EFI — NOT Exclusive-C14N canonicalized, NOT XML-DSig signed.',
    '     v0-A canonical form is the Poseidon field-tuple digest D, not this XML. -->',
    '<EFInvoice _synthetic="true">',
    `  <Seller><TIN>${rec.sellerTin}</TIN></Seller>`,
    `  <Header dateTime="${rec.datetime}" invoiceNo="${rec.invoiceNo}"`,
    `          businessUnit="${rec.businessUnit}" tcr="${rec.enuTcr}"`,
    `          softwareCode="${rec.softwareCode}"/>`,
    `  <Amounts vatBase="${centsToDecimalString(rec.vatBaseCents)}" vatRateBp="${rec.vatRateBp}"`,
    `           vatAmount="${centsToDecimalString(rec.vatAmountCents)}" total="${centsToDecimalString(
      rec.totalCents,
    )}"/>`,
    `  <Buyer><Id>${rec.buyerId}</Id></Buyer>`,
    '  <Items>',
    items,
    '  </Items>',
    `  <IKOF>${ikof}</IKOF>`,
    `  <JIKR>${jikr}</JIKR>`,
    '</EFInvoice>',
  ].join('\n');
}

function recordToWitness(
  rec: EfiRecord,
  itemsCommitField: Field,
  salt: Field,
  path: InclusionPath,
): FixtureWitness {
  return {
    sellerTin: rec.sellerTin,
    datetime: rec.datetime,
    invoiceNo: rec.invoiceNo,
    businessUnit: rec.businessUnit,
    enuTcr: rec.enuTcr,
    softwareCode: rec.softwareCode,
    totalCents: amountToJSON(rec.totalCents),
    vatBaseCents: amountToJSON(rec.vatBaseCents),
    vatRateBp: rec.vatRateBp,
    vatAmountCents: amountToJSON(rec.vatAmountCents),
    buyerId: rec.buyerId,
    lineItems: rec.lineItems.map((it) => ({
      name: it.name,
      quantity: it.quantity.toString(),
      unitPriceCents: amountToJSON(it.unitPriceCents),
    })),
    marginCents: amountToJSON(rec.marginCents),
    itemsCommit: fieldToJSON(itemsCommitField),
    salt: fieldToJSON(salt),
    merklePath: path.merklePath,
    merkleIndexBits: path.merkleIndexBits,
    merkleIndex: path.merkleIndex,
  };
}

interface AssembleParams {
  id: string;
  rec: EfiRecord;
  salt: Field;
  path: InclusionPath;
  tree: SellersTree;
  keypair: SyntheticRsaKeypair;
  expectedValid: boolean;
  invalidReason?: InvalidReason;
  /** COMMITMENT_MISMATCH: publish a C ≠ C(witness). */
  corruptPublishedCommitment: boolean;
}

function assembleFixture(p: AssembleParams): Fixture {
  const itemsCommitField = itemsCommit(p.rec.lineItems);
  const realC = commitC(p.rec, itemsCommitField, p.salt);
  const publishedC = p.corruptPublishedCommitment ? realC.add(Field(1)) : realC;
  const D = digestD(p.rec, itemsCommitField); // { hi, lo, hex }

  const ikof = buildIkofChain(p.rec, p.keypair.privateKey, p.keypair.publicPem);
  const xml = renderSyntheticXml(p.rec, ikof.ikof, ikof.jikr);

  const fixture: Fixture = {
    _synthetic: SYNTHETIC_FLAG,
    _warning: SYNTHETIC_WARNING,
    id: p.id,
    publicInputs: {
      C: fieldToJSON(publishedC),
      D,
      sellersRoot: fieldToJSON(p.tree.root),
      PK_ref: PK_REF_PLACEHOLDER,
      rateParams: RATE_PARAMS,
    },
    witness: recordToWitness(p.rec, itemsCommitField, p.salt, p.path),
    expected: { valid: p.expectedValid },
    ikof,
    efi: {
      record: {
        sellerTin: p.rec.sellerTin,
        datetime: p.rec.datetime,
        invoiceNo: p.rec.invoiceNo,
        businessUnit: p.rec.businessUnit,
        enuTcr: p.rec.enuTcr,
        softwareCode: p.rec.softwareCode,
        totalCents: amountToJSON(p.rec.totalCents),
        vatBaseCents: amountToJSON(p.rec.vatBaseCents),
        vatRateBp: p.rec.vatRateBp,
        vatAmountCents: amountToJSON(p.rec.vatAmountCents),
        buyerId: p.rec.buyerId,
        lineItems: p.rec.lineItems.map((it) => ({
          name: it.name,
          quantity: it.quantity.toString(),
          unitPriceCents: amountToJSON(it.unitPriceCents),
        })),
        marginCents: amountToJSON(p.rec.marginCents),
      },
      xmlSyntheticNonCanonical: xml,
      _note:
        'Byte-exact Exclusive-C14N + enveloped XML-DSig is NOT done in v0-A ' +
        '(Phase-5; SPEC §3, §13). Canonical form = Poseidon field-tuple digest D.',
    },
  };
  if (!p.expectedValid && p.invalidReason) {
    fixture._invalidReason = p.invalidReason;
  }
  return fixture;
}

export interface Dataset {
  fixtures: Fixture[];
  summary: {
    seed: string;
    o1jsVersion: string;
    merkleHeight: number;
    registrySize: number;
    valid: number;
    invalid: number;
    invalidByReason: Record<string, number>;
    sellersRoot: string;
    generatedFrom: string;
  };
}

/** Drive the full deterministic dataset from a config. */
export function buildDataset(
  config: GeneratorConfig = DEFAULT_CONFIG,
  o1jsVersion = 'o1js@2.15.0',
): Dataset {
  const prng = new DeterministicPrng(config.seed);
  const keypair = loadOrCreateSellerKeypair();
  const registeredTins = buildRegisteredTins(config.registrySize);
  const tree = buildSellersTree(registeredTins);

  const fixtures: Fixture[] = [];
  let recordCounter = 0;

  // ---- VALID fixtures ----
  for (let i = 0; i < config.validCount; i++) {
    const registryIndex = i % config.registrySize;
    const tin = registeredTins[registryIndex] as string;
    const rec = makeValidRecord(prng, recordCounter++, tin);
    const salt = Field(prng.nextFieldBigInt());
    const path = inclusionPath(tree.tree, registryIndex);

    // Sanity: a valid registered seller's path MUST recompute to the root.
    if (recomputeRoot(sellerLeaf(tin), path.merklePath).toString() !== tree.root.toString()) {
      throw new Error(`internal: valid path failed to recompute root for ${tin}`);
    }

    fixtures.push(
      assembleFixture({
        id: `valid-${i.toString().padStart(3, '0')}`,
        rec,
        salt,
        path,
        tree,
        keypair,
        expectedValid: true,
        corruptPublishedCommitment: false,
      }),
    );
  }

  // ---- INVALID fixtures ----
  const reasons = Object.keys(config.invalidCounts) as InvalidReason[];
  let unregisteredCounter = 0;
  for (const reason of reasons) {
    const count = config.invalidCounts[reason];
    for (let j = 0; j < count; j++) {
      const registryIndex = recordCounter % config.registrySize;
      const registeredTin = registeredTins[registryIndex] as string;
      const unregisteredTin = syntheticPib(
        PIB_UNREGISTERED_PREFIX,
        ++unregisteredCounter,
      );
      const mutation = makeInvalidMutation(
        prng,
        recordCounter++,
        reason,
        registeredTin,
        unregisteredTin,
      );
      const salt = Field(prng.nextFieldBigInt());

      // SELLER_NOT_REGISTERED uses some slot's path with a non-matching leaf so
      // the root recomputation deliberately fails; others use the true path.
      const path = mutation.sellerUnregistered
        ? inclusionPath(tree.tree, 0)
        : inclusionPath(tree.tree, registryIndex);

      fixtures.push(
        assembleFixture({
          id: `invalid-${reason.toLowerCase()}-${j.toString().padStart(3, '0')}`,
          rec: mutation.record,
          salt,
          path,
          tree,
          keypair,
          expectedValid: false,
          invalidReason: reason,
          corruptPublishedCommitment: mutation.corruptPublishedCommitment,
        }),
      );
    }
  }

  const invalidByReason: Record<string, number> = {};
  for (const r of reasons) invalidByReason[r] = config.invalidCounts[r];
  const invalid = Object.values(config.invalidCounts).reduce((a, b) => a + b, 0);

  return {
    fixtures,
    summary: {
      seed: config.seed,
      o1jsVersion,
      merkleHeight: MERKLE_HEIGHT,
      registrySize: config.registrySize,
      valid: config.validCount,
      invalid,
      invalidByReason,
      sellersRoot: fieldToJSON(tree.root),
      generatedFrom: 'src/index.ts (npm run gen)',
    },
  };
}
