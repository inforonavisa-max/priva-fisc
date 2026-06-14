/**
 * PRIVA-FISC v0-A — Synthetic attestation authority (generator-only)
 * ============================================================================
 * ⚠️  GENERATOR-ONLY MODULE. Uses node:crypto (seed→key derivation). The
 *     circuit-shared modules never import it. The MOCK tax-authority keypair is
 *     SYNTHETIC / NON-PRODUCTION — it stands in for the Montenegro Tax
 *     Administration key (SPEC §2). The SECRET key is derived deterministically
 *     from the generator seed, kept in memory, and NEVER serialized/committed;
 *     only the PUBLIC key (PK_A) goes into fixtures.
 *
 * Scheme: o1js native `Signature` — Schnorr over the Pallas curve, Poseidon-based
 * (SPEC §11.1 left the v0-A scheme open → default to the ZK-native framework
 * signature, in-circuit-verifiable via `signature.verify(PK, [M]) : Bool`).
 *
 * Registry anchoring (SPEC §11.3): ONE signature — R_reg is bound by being inside
 * the message M (§7-C1). No separate σ_reg.
 * ----------------------------------------------------------------------------
 */

import { createHash } from 'node:crypto';
import { Field, Poseidon, PrivateKey, type PublicKey, type Signature, Signature as Sig } from 'o1js';
import { DS, encodeStringToField } from './encoding.js';

export interface AuthorityKeypair {
  secretKey: PrivateKey;
  publicKey: PublicKey;
}

/**
 * Deterministic synthetic authority keypair from the generator seed.
 * scalar = big-endian of SHA-256(seed || "/authority")[0..31]  (248 bits < the
 * Pallas scalar field order, so it is always a valid private scalar). Reproducible
 * across runs — no cached key file needed (unlike the RSA IKOF key).
 */
export function deriveAuthorityKeypair(seed: string): AuthorityKeypair {
  const h = createHash('sha256').update(`${seed}/authority`, 'utf8').digest();
  const scalar = BigInt(`0x${h.subarray(0, 31).toString('hex')}`); // 248-bit
  const secretKey = PrivateKey.fromBigInt(scalar);
  return { secretKey, publicKey: secretKey.toPublicKey() };
}

/**
 * Binding message M (SPEC §7-C1, verbatim):
 *   `M = H( DS_attest, D, C, R_reg, datetime, invoice_no )`
 * v0-A limb expansion: D is the SHA-256 digest carried as TWO 128-bit Field limbs
 * (D_hi, D_lo) where §7-C1 lists `D`, so the Poseidon vector is
 *   [ DS.ATTEST, D_hi, D_lo, C, R_reg, encStr(datetime), encStr(invoice_no) ].
 * datetime/invoice_no enter via the same encodeStringToField used elsewhere.
 * This is the SINGLE off-circuit M builder, shared by the generator and the
 * self-check; the ZkProgram (src/circuit.ts) recomputes the identical vector
 * in-circuit and asserts equality (anti-replay, §7-C1).
 */
export function computeAttestMessage(
  dHi: Field,
  dLo: Field,
  C: Field,
  rReg: Field,
  datetime: string,
  invoiceNo: string,
): Field {
  return Poseidon.hash([
    DS.ATTEST,
    dHi,
    dLo,
    C,
    rReg,
    encodeStringToField(datetime),
    encodeStringToField(invoiceNo),
  ]);
}

/** σ_rcpt = Sign(authoritySecretKey, [M]) — the authority attestation over M. */
export function signReceipt(secretKey: PrivateKey, M: Field): Signature {
  return Sig.create(secretKey, [M]);
}
