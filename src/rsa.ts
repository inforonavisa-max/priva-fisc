/**
 * PRIVA-FISC v0-A — SYNTHETIC RSA + hashing primitives (IKOF chain only)
 * ============================================================================
 * Generates a SYNTHETIC RSA-2048 keypair and provides RSA-SHA256 (PKCS#1 v1.5)
 * signing + MD5, used ONLY to build the synthetic IKOF/IICSignature chain
 * (SPEC §2/§13). This is NOT the v0-A authority ZK-signature (SPEC §3/§7-C1),
 * and NONE of this is verified in-circuit in v0-A (real RSA-in-circuit = Phase-5).
 *
 * ⚠️  D5 FIREWALL: the keypair is FRESHLY, LOCALLY generated and is NON-PRODUCTION.
 *     It is written to ../synthetic-keys/ (git-ignored) with a DO-NOT-USE marker.
 *     No real taxpayer certificate / Tax-Administration key ever enters this repo.
 *
 * Reproducibility: Node's RSA keygen is NOT seedable, so the keypair is generated
 * ONCE and CACHED. The ZK-relation public values (C, D, sellersRoot, salt) come
 * solely from the seeded PRNG (./prng.ts) and are byte-identical across runs even
 * with a fresh key. Only the IKOF artifacts (iicSignatureHex, ikof, synthetic XML)
 * depend on the key, so they are stable ONLY as long as the cached key is
 * preserved; deleting synthetic-keys/ (git-ignored, documented safe-to-delete)
 * regenerates the key and changes those IKOF fields — never the C/D/root relation.
 * ----------------------------------------------------------------------------
 */

import {
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  createHash,
  constants as cryptoConstants,
  type KeyObject,
  createPrivateKey,
  createPublicKey,
} from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
// build/src/rsa.js → repo root is two levels up.
const REPO_ROOT = join(__dirname, '..', '..');
export const SYNTHETIC_KEYS_DIR = join(REPO_ROOT, 'synthetic-keys');

const PRIVATE_PEM_PATH = join(SYNTHETIC_KEYS_DIR, 'seller-rsa-private.pem');
const PUBLIC_PEM_PATH = join(SYNTHETIC_KEYS_DIR, 'seller-rsa-public.pem');
const MARKER_PATH = join(SYNTHETIC_KEYS_DIR, 'DO-NOT-USE-NON-PRODUCTION.txt');

const MARKER_TEXT = [
  'NON-PRODUCTION — DO NOT USE',
  '',
  'This directory holds a SYNTHETIC RSA-2048 keypair generated locally by the',
  'PRIVA-FISC v0-A synthetic EFI generator. It exists ONLY to produce synthetic',
  'IKOF/IICSignature values for test fixtures.',
  '',
  '  • NOT a real taxpayer certificate.',
  '  • NOT issued by Posta Crne Gore / CoreIT or any CA.',
  '  • NOT tied to any real PIB, person, or Tax Administration.',
  '  • Safe to delete; it will be regenerated on the next `npm run gen`.',
  '',
  'This directory is git-ignored and must NEVER be committed.',
  '',
].join('\n');

export interface SyntheticRsaKeypair {
  privateKey: KeyObject;
  publicKey: KeyObject;
  privatePem: string;
  publicPem: string;
}

function ensureMarker(): void {
  if (!existsSync(SYNTHETIC_KEYS_DIR)) {
    mkdirSync(SYNTHETIC_KEYS_DIR, { recursive: true });
  }
  // Always (re)write the marker so the warning is present whenever the dir is.
  writeFileSync(MARKER_PATH, MARKER_TEXT, { encoding: 'utf8' });
}

/**
 * Load the cached synthetic keypair, or generate + persist one on first run.
 * RSA-2048 with PKCS#1 v1.5 signatures (matches Montenegro "RSA-SHA256" — no PSS).
 */
export function loadOrCreateSellerKeypair(): SyntheticRsaKeypair {
  ensureMarker();

  if (existsSync(PRIVATE_PEM_PATH) && existsSync(PUBLIC_PEM_PATH)) {
    const privatePem = readFileSync(PRIVATE_PEM_PATH, 'utf8');
    const publicPem = readFileSync(PUBLIC_PEM_PATH, 'utf8');
    return {
      privatePem,
      publicPem,
      privateKey: createPrivateKey(privatePem),
      publicKey: createPublicKey(publicPem),
    };
  }

  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicExponent: 0x10001,
  });
  const privatePem = privateKey
    .export({ type: 'pkcs8', format: 'pem' })
    .toString();
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();

  writeFileSync(PRIVATE_PEM_PATH, privatePem, { encoding: 'utf8', mode: 0o600 });
  writeFileSync(PUBLIC_PEM_PATH, publicPem, { encoding: 'utf8' });

  return { privateKey, publicKey, privatePem, publicPem };
}

/**
 * RSA-SHA256 (PKCS#1 v1.5) signature over `message` bytes → raw signature Buffer.
 * This is the synthetic protocol's `IICSignature`.
 */
export function rsaSha256Sign(message: string, privateKey: KeyObject): Buffer {
  return cryptoSign('sha256', Buffer.from(message, 'utf8'), {
    key: privateKey,
    padding: cryptoConstants.RSA_PKCS1_PADDING,
  });
}

/** Verify an RSA-SHA256 (PKCS#1 v1.5) signature (used by the self-check). */
export function rsaSha256Verify(
  message: string,
  signature: Buffer,
  publicKey: KeyObject,
): boolean {
  return cryptoVerify(
    'sha256',
    Buffer.from(message, 'utf8'),
    { key: publicKey, padding: cryptoConstants.RSA_PKCS1_PADDING },
    signature,
  );
}

/**
 * MD5 over raw bytes → uppercase 32-char hex.
 *
 * TODO(confirm): Montenegro IIC is MD5 of the IICSignature. Whether MD5 is taken
 * over the raw signature BYTES (as here) or over its hex/base64 text encoding is
 * a "Tehnička uputstva" detail — confirm before any Phase-5 fidelity claim.
 */
export function md5UpperHex(bytes: Buffer): string {
  return createHash('md5').update(bytes).digest('hex').toUpperCase();
}
