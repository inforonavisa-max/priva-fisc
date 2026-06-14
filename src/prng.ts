/**
 * PRIVA-FISC v0-A — Deterministic seeded PRNG (reproducible fixtures)
 * ============================================================================
 * A small counter-based CSPRNG-style stream: block_i = SHA-256(seed || i_be64).
 * Deterministic and reproducible from a string seed — the SAME seed always
 * yields the SAME fixtures. (The synthetic RSA keypair is the one non-seeded
 * artifact — Node RSA keygen is not seedable — so it is cached instead; see
 * ./rsa.ts.) NOT for cryptographic key material; fixtures only.
 * ----------------------------------------------------------------------------
 */

import { createHash } from 'node:crypto';
import { FIELD_ORDER } from './encoding.js';

export class DeterministicPrng {
  private readonly seedBuf: Buffer;
  private counter = 0n;
  private pool: Buffer = Buffer.alloc(0);

  constructor(seed: string) {
    this.seedBuf = Buffer.from(seed, 'utf8');
  }

  private refill(): void {
    const ctr = Buffer.alloc(8);
    ctr.writeBigUInt64BE(this.counter);
    this.counter += 1n;
    const block = createHash('sha256')
      .update(this.seedBuf)
      .update(ctr)
      .digest();
    this.pool = Buffer.concat([this.pool, block]);
  }

  nextBytes(n: number): Buffer {
    while (this.pool.length < n) this.refill();
    const out = this.pool.subarray(0, n);
    this.pool = this.pool.subarray(n);
    return Buffer.from(out);
  }

  /** Uniform-ish bigint in [0, max) via rejection-free wide reduction. */
  nextBigIntBelow(max: bigint): bigint {
    if (max <= 0n) throw new Error('nextBigIntBelow: max must be > 0');
    // Draw 16 extra bytes beyond max's width to keep modulo bias negligible.
    const bits = max.toString(2).length;
    const bytes = Math.ceil(bits / 8) + 16;
    let acc = 0n;
    for (const b of this.nextBytes(bytes)) acc = (acc << 8n) | BigInt(b);
    return acc % max;
  }

  /** Inclusive integer in [min, max]. */
  nextIntInRange(min: number, max: number): number {
    if (max < min) throw new Error('nextIntInRange: max < min');
    const span = BigInt(max - min + 1);
    return min + Number(this.nextBigIntBelow(span));
  }

  /** Non-zero Field element in [1, FIELD_ORDER). Used for salts. */
  nextFieldBigInt(): bigint {
    const v = this.nextBigIntBelow(FIELD_ORDER - 1n);
    return v + 1n;
  }

  pick<T>(arr: readonly T[]): T {
    if (arr.length === 0) throw new Error('pick: empty array');
    return arr[this.nextIntInRange(0, arr.length - 1)] as T;
  }
}
