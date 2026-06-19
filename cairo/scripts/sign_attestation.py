#!/usr/bin/env python3
"""Synthetic Stark-curve ECDSA signer for the PRIVA-FISC × STRK20 PoC.

Stands in for the fiscal authority `A`. Pure-Python (no deps), so the PoC's
authority attestation (C1) is reproducible. Signs a message hash `M` (a Poseidon
field element emitted by the Cairo `_emit_signing_material` test) and prints
(PK_A, SIG_R, SIG_S) to paste into tests/poc_test.cairo.

SYNTHETIC KEY ONLY — not a real fiscal-authority key. Matches the Cairo corelib
`check_ecdsa_signature` verification (StarkWare ECDSA on the Stark curve).

Usage:  python3 sign_attestation.py <M>
"""
import sys

# Stark curve parameters (must match core::ec::stark_curve).
P = 2**251 + 17 * 2**192 + 1
A = 1
N = 0x800000000000010FFFFFFFFFFFFFFFFB781126DCAE7B2321E66A241ADC64D2F  # ORDER
GX = 0x1EF15C18599971B7BECED415A40F0C7DEACFD9B0D1819E03D723D8BC943CFCA
GY = 0x5668060AA49730B7BE4801DF46EC62DE53ECD11ABE43A32873000C36E8DC1F
G = (GX, GY)

# Synthetic authority private key (clearly fake).
D_PRIV = 0x0F15CA1A07480817E55EC000DEADBEEF42  # "fiscalia" + nonsense


def inv(a, m):
    return pow(a, -1, m)


def ec_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    (x1, y1), (x2, y2) = p, q
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p == q:
        m = (3 * x1 * x1 + A) * inv(2 * y1, P) % P
    else:
        m = (y2 - y1) * inv(x2 - x1, P) % P
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)


def ec_mul(k, p):
    r = None
    k %= N
    while k:
        if k & 1:
            r = ec_add(r, p)
        p = ec_add(p, p)
        k >>= 1
    return r


def verify_points(z, Q, R, r, s):
    """corelib check using the actual points: (zG ± rQ).x == (sR).x."""
    if s == 0 or r == 0 or r >= 2**251:
        return False
    zG = ec_mul(z % N, G)
    rQ = ec_mul(r, Q)
    sR = ec_mul(s, R)
    plus = ec_add(zG, rQ)
    minus = ec_add(zG, (rQ[0], (-rQ[1]) % P))
    return (plus is not None and plus[0] == sR[0]) or (
        minus is not None and minus[0] == sR[0]
    )


def sign(z, d):
    z %= N
    Q = ec_mul(d, G)
    k = (z ^ d ^ 0xA11CE) % N or 1
    while True:
        R = ec_mul(k, G)
        r = R[0]  # raw x (a valid x-coord, must be < 2^251)
        if r == 0 or r >= 2**251:
            k = (k + 1) % N or 1
            continue
        s = (inv(k, N) * (z + r * d)) % N
        if s == 0:
            k = (k + 1) % N or 1
            continue
        if verify_points(z, Q, R, r, s):
            return Q[0], r, s, Q, R
        k = (k + 1) % N or 1


if __name__ == "__main__":
    m = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    pk, r, s, Q, R = sign(m, D_PRIV)
    assert verify_points(m, Q, R, r, s), "self-verify failed"
    print(f"// authority signature over M = {m}")
    print(f"const PK_A: felt252 = {hex(pk)};")
    print(f"const SIG_R: felt252 = {hex(r)};")
    print(f"const SIG_S: felt252 = {hex(s)};")
