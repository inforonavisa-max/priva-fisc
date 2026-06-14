/**
 * T-D5 — synthetic-data firewall markers.
 * ============================================================================
 * Every fixture must carry `_synthetic:true` + the EXACT `_warning` string, must
 * not contain any real-looking PRIVATE key/secret, and seller TINs must be in the
 * documented synthetic reserved range. Buyer ids must be opaque SYNTH ids.
 * ----------------------------------------------------------------------------
 */

import { SYNTHETIC_WARNING } from '../src/schema.js';
import { generateFixtures } from './fixtures-helper.js';
import { group, ok, strictEq, test } from './harness.js';

group('T-D5');

const fixtures = generateFixtures();

// Registered sellers: "9090" + 4 digits; deliberately-unregistered: "9099" + 4.
const SYNTH_TIN = /^90(90|99)\d{4}$/;
const SYNTH_BUYER = /^SYNTH-BUYER-\d{4}$/;

test('every fixture has _synthetic:true and the exact _warning string', () => {
  for (const fx of fixtures) {
    strictEq(fx._synthetic, true, `${fx.id}: _synthetic not true`);
    strictEq(fx._warning, SYNTHETIC_WARNING, `${fx.id}: _warning text drift`);
  }
});

test('no fixture contains PRIVATE key / secret material', () => {
  for (const fx of fixtures) {
    const json = JSON.stringify(fx);
    ok(!/PRIVATE KEY/.test(json), `${fx.id}: contains a PRIVATE KEY block`);
    ok(!/BEGIN [A-Z ]*PRIVATE/.test(json), `${fx.id}: contains a private-key header`);
  }
});

test('the only PEM present is the synthetic seller PUBLIC key (IKOF verify)', () => {
  for (const fx of fixtures) {
    const pem = fx.ikof.sellerRsaPublicKeyPem;
    ok(/BEGIN PUBLIC KEY/.test(pem), `${fx.id}: expected a PUBLIC KEY PEM`);
    ok(!/PRIVATE/.test(pem), `${fx.id}: public-key field must not contain PRIVATE`);
  }
});

test('seller TINs are in the synthetic reserved range (9090/9099 + 4 digits)', () => {
  for (const fx of fixtures) {
    ok(
      SYNTH_TIN.test(fx.witness.sellerTin),
      `${fx.id}: TIN '${fx.witness.sellerTin}' outside synthetic reserved range`,
    );
  }
});

test('buyer ids are opaque SYNTH ids', () => {
  for (const fx of fixtures) {
    ok(SYNTH_BUYER.test(fx.witness.buyerId), `${fx.id}: buyerId '${fx.witness.buyerId}' not opaque`);
  }
});
