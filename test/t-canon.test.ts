/**
 * T-CANON — canonical byte form sanity.
 * ============================================================================
 * `canonicalize(P)` (src/canonical.ts) is the SINGLE byte serialization the
 * SHA-256 digest D is taken over (SPEC §7-C5/§13). Asserts:
 *   • DETERMINISTIC: same input → identical bytes.
 *   • INJECTIVE: length-prefixing removes field-boundary ambiguity, so payloads
 *     that would collide under naive concatenation produce distinct bytes; a
 *     one-char change and a same-type value swap also change the bytes.
 *   • ONE-WAY: canonical.ts exports NO de-canonicalize / byte→record inverse; the
 *     bytes are consumed for hashing, never parsed back. (encoding.ts likewise
 *     exports no field→plaintext decoder.)
 *   • digestD deterministic + sensitive to every field.
 *   • encodeStringToField deterministic + length-distinguishing.
 * ----------------------------------------------------------------------------
 */

import { Field } from 'o1js';
import * as canonical from '../src/canonical.js';
import { canonicalize, digestD } from '../src/canonical.js';
import * as encoding from '../src/encoding.js';
import { encodeStringToField } from '../src/encoding.js';
import type { EfiRecord } from '../src/schema.js';
import { group, ok, eq, test } from './harness.js';

group('T-CANON');

function sampleRec(): EfiRecord {
  return {
    sellerTin: '90900001', datetime: '2026-01-01T09:00:00.000Z',
    invoiceNo: 'SYNTH-INV-2026-000001', businessUnit: 'SYNTH-BU-006',
    enuTcr: 'SYNTH-TCR-007', softwareCode: 'SYNTH-SW-06', totalCents: 6080025n,
    vatBaseCents: 5024814n, vatRateBp: 2100, vatAmountCents: 1055211n,
    buyerId: 'SYNTH-BUYER-0001', lineItems: [], marginCents: 753722n,
  };
}
const IC = Field(123456789n);
const hex = (u: Uint8Array): string => Buffer.from(u).toString('hex');

test('canonicalize is deterministic (same input → same bytes)', () => {
  eq(hex(canonicalize(sampleRec(), IC)), hex(canonicalize(sampleRec(), IC)),
    'canonicalize must be deterministic');
});

test('canonicalize is INJECTIVE — length-prefixing removes boundary ambiguity', () => {
  // Naive concat 'AB'+'' == 'A'+'B'; length-prefixing must distinguish them.
  const r1 = sampleRec(); r1.sellerTin = 'AB'; r1.datetime = '';
  const r2 = sampleRec(); r2.sellerTin = 'A'; r2.datetime = 'B';
  ok(hex(canonicalize(r1, IC)) !== hex(canonicalize(r2, IC)),
    'field-boundary ambiguity not prevented');
});

test('canonicalize: one-char change and same-type value swap both change bytes', () => {
  const base = hex(canonicalize(sampleRec(), IC));
  const oneChar = sampleRec(); oneChar.buyerId += 'X';
  ok(hex(canonicalize(oneChar, IC)) !== base, 'one-char change did not change bytes');
  const swap = sampleRec(); swap.businessUnit = 'AAA'; swap.enuTcr = 'BBB';
  const swap2 = sampleRec(); swap2.businessUnit = 'BBB'; swap2.enuTcr = 'AAA';
  ok(hex(canonicalize(swap, IC)) !== hex(canonicalize(swap2, IC)),
    'same-type value swap not position-sensitive');
});

test('canonicalize is ONE-WAY: canonical.ts exports no inverse/de-canonicalize', () => {
  const forbidden = Object.keys(canonical).filter((n) =>
    /(decanon|decode|frombytes|bytestorecord|parse|invert|reverse|deserialize)/i.test(n));
  eq(forbidden, [], `canonical.ts must expose no byte→record inverse (found: ${forbidden})`);
});

test('digestD is deterministic', () => {
  ok(digestD(sampleRec(), IC).hex === digestD(sampleRec(), IC).hex, 'digestD must be deterministic');
});

test('digestD is sensitive to every payload field (+ itemsCommit)', () => {
  const baseHex = digestD(sampleRec(), IC).hex;
  const muts: ((r: EfiRecord) => void)[] = [
    (r) => (r.sellerTin += 'X'), (r) => (r.datetime += 'X'), (r) => (r.invoiceNo += 'X'),
    (r) => (r.businessUnit += 'X'), (r) => (r.enuTcr += 'X'), (r) => (r.softwareCode += 'X'),
    (r) => (r.totalCents += 1n), (r) => (r.vatBaseCents += 1n), (r) => (r.vatRateBp += 1),
    (r) => (r.vatAmountCents += 1n), (r) => (r.buyerId += 'X'), (r) => (r.marginCents += 1n),
  ];
  for (const [k, m] of muts.entries()) {
    const r = sampleRec(); m(r);
    ok(digestD(r, IC).hex !== baseHex, `digestD insensitive to mutation #${k}`);
  }
  ok(digestD(sampleRec(), Field(987654321n)).hex !== baseHex, 'digestD insensitive to itemsCommit');
});

test('encoding is one-way: encoding.ts exports no decoder/inverse', () => {
  const forbidden = Object.keys(encoding).filter((n) =>
    /(decode|fromField(s)?ToString|unpack|parseTuple|invert|reverse)/i.test(n));
  eq(forbidden, [], `encoding must expose no inverse decoder (found: ${forbidden})`);
});

test('encodeStringToField deterministic + length-distinguishing', () => {
  ok(encodeStringToField('abc').toString() === encodeStringToField('abc').toString(),
    'string encoding must be deterministic');
  ok(encodeStringToField('A').toString() !== encodeStringToField('A ').toString(),
    'length-prefix must distinguish "A" (1 byte) from "A " (2 bytes)');
  ok(encodeStringToField('').toString() !== encodeStringToField(' ').toString(),
    'empty string vs single space (different lengths) must differ');
});
