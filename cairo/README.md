# PRIVA-FISC × STRK20 — VAT-on-ciphertext PoC

> **One sentence:** this proves, with a real zero-knowledge proof, that a Tongo-style
> **confidential payment's VAT is additively consistent** (`total = vat_base + vat_amount`) —
> *while the amount stays encrypted* — and binds it to a fiscal receipt + authority signature.

Built on the **real STRK20 cryptography**: the [`she`](https://github.com/fatlabsxyz/she) v0.4.0
library (the Starknet-Homomorphic-Encryption Sigma-protocol toolbox that backs
[Tongo](https://github.com/fatlabsxyz/tongo), Starknet's confidential-ERC-20 SDK). Verified on
**Scarb 2.18.0 / Cairo 2.18.0 / snforge 0.61.0**. Synthetic data only — no real key, no PII.

Background recon: [`../docs/starknet-recon.md`](../docs/starknet-recon.md).

---

## What it proves (the one net claim)

A confidential payment encrypts its amount as an **additively-homomorphic ElGamal ciphertext**
over the Stark curve — exactly as Tongo does:

```
Enc(b ; r) = ( b·G + r·Y ,  r·G )          G = Stark-curve generator, Y = payment key
```

The PoC proves the **VAT identity on the ciphertexts**, without ever decrypting:

```
Enc(total)  =  Enc(vat_base)  ⊕  Enc(vat_amount)      ⇒   total = vat_base + vat_amount
```

via the SHE **`SameEncryption`** Sigma protocol. The verifier:

1. **recomputes** the homomorphic sum `CT_sum = CT_base ⊕ CT_tax` (elliptic-curve point adds) —
   so the prover cannot cheat on the sum;
2. runs `SameEncryption.verify_with_prefix(CT_sum, CT_total)` — a real ZK proof that `CT_sum`
   and `CT_total` encrypt the **same value**, i.e. `total = vat_base + vat_amount`;
3. **binds** that encrypted amount to the fiscal context:
   - **C2** — a Poseidon **commitment** `C` over the (encrypted) amounts + private receipt
     metadata (seller TIN, buyer, rate, salt); the VAT proof's Fiat-Shamir **prefix** is bound
     to `C`, the registry root, and the receipt digest `D`;
   - **C1** — a **Stark-curve ECDSA** authority signature over `M = Poseidon(D, C, R_reg, …)`;
   - **C4** — a Poseidon **Merkle** proof that the seller is in the authority registry.

So the public guarantee is: *"some registered seller's confidential payment was attested by the
authority and is correctly taxed (`total = base + tax`) — without revealing the amount, the
parties, or the line items."*

### What it does **not** prove (honest scope — read this)

- **The multiplicative rate relation** `vat_amount = vat_base · rate / 10000` is **out of scope.**
  It proves only the **additive** identity `total = base + tax` on ciphertext (the task's explicit
  goal). A receipt with the right *sum* but the *wrong rate* would pass. Proving the rate relation
  on ciphertext needs an OR-proof over the statutory rates `{0, 7, 21}%` (compose SHE `Bit`/`Range`)
  or a DLEQ-bound arithmetic proof — see [`../docs/starknet-recon.md`](../docs/starknet-recon.md)
  §C.6. Documented next step, not a hidden gap.
- **Equality is proven *modulo the curve order* (≈2^251), not over the integers.** `SameEncryption`
  certifies the plaintext *scalars* are equal mod the group order; there is **no range proof**, so
  integer-level soundness (no modular wrap; amounts in `[0, 2^k)`) is **not** enforced. The test
  [`documents_modular_equality_limitation`](tests/poc_test.cairo) makes this concrete: a "total" of
  `HONEST_TOTAL + ORDER` is **accepted**. Closing it = pairing the equality proof with a SHE
  `Range`/`Bit` proof (exactly what Tongo does for every amount). This is the most important caveat.
- **Range/solvency proofs** (amounts ≥ 0, sender funded) — Tongo/SHE provide `Range`; not wired here.
- **Authority/registry trust** — `pk_a` and `r_reg` are *trusted public inputs* (SPEC §2). C1/C4 are
  only as strong as an out-of-band binding of `pk_a` to the real authority.
- **The prover is test-grade.** `prove_vat` uses test-seeded Sigma nonces and takes the witness in
  the clear; a real prover needs a CSPRNG (fresh, non-reused nonces) and hardening.
- **Real fiscal signature chain** (RSA-2048 + SHA-256 + MD5 over Montenegro's EFI XML) — that is
  Phase-5; the recon (§D) shows SHA-256 is native and RSA is buildable on `core::circuit`.
- This is a **PoC**, not audited production code. `she` itself is zkSecurity-audited; the
  PRIVA-FISC glue here is not.

---

## Files

| File | What |
|---|---|
| [`src/poc.cairo`](src/poc.cairo) | the PoC: ElGamal `encrypt`/`cipher_add`, `verify_taxed_payment` (the verifier), and the off-chain `prove_vat` prover helper |
| [`tests/poc_test.cairo`](tests/poc_test.cairo) | 1 positive + 5 negative tests (synthetic) |
| [`scripts/sign_attestation.py`](scripts/sign_attestation.py) | dependency-free synthetic Stark-curve ECDSA signer (stands in for the fiscal authority) |
| [`src/lib.cairo`](src/lib.cairo) | the earlier recon skeleton (C1–C5 primitive map + Phase-5 probes) — unchanged |

---

## Run it

```bash
# from cairo/
snforge test                 # all 18 tests (10 recon + 8 PoC)
snforge test poc_test        # just the PoC: 1 positive + 6 negatives + 1 limitation-doc
```

Expected (PoC):

```
[PASS] positive_correctly_taxed_payment_verifies        # correctly-taxed → proof VERIFIES
[PASS] negative_a_wrong_vat_total                        # total ≠ base+tax → VAT_NOT_CONSISTENT
[PASS] negative_b_wrong_signature                        # bad authority sig → C1_BAD_ATTESTATION
[PASS] negative_c_tampered_committed_field               # tampered receipt → C2_COMMIT_MISMATCH
[PASS] negative_d_seller_not_registered                  # unregistered seller → C4_NOT_REGISTERED
[PASS] negative_e_vat_proof_not_bound_to_receipt         # lifted proof → VAT_PROOF_NOT_BOUND
[PASS] negative_f_malformed_ciphertext_rejected          # adversarial ct (∞ sum) → MALFORMED_CIPHERTEXT
[PASS] documents_modular_equality_limitation             # honest: a mod-ORDER-wrapped total IS accepted
```

Every negative is **instruction-level real**: the rejection is a genuine Sigma-verify / ECDSA /
commitment / Merkle / point-validity failure (a Cairo `panic`), not an argument error — verified
by tracing which ordered check fires (and confirmed by gas cost rising with check depth).
`documents_modular_equality_limitation` deliberately **passes** to expose the mod-ORDER caveat above.

### Reproducing the authority signature (optional)

The authority attestation is a real Stark-curve ECDSA signature over the message `M`. To
regenerate it (e.g. after changing the synthetic receipt):

```bash
# 1) emit M from Cairo
snforge test _emit_signing_material --include-ignored        # prints MESSAGE_M=...
# 2) sign it with the synthetic authority key
python3 scripts/sign_attestation.py <MESSAGE_M>              # prints PK_A / SIG_R / SIG_S
# 3) paste PK_A/SIG_R/SIG_S into tests/poc_test.cairo
```

---

## How the pieces map to STRK20 / Tongo

| PoC piece | STRK20 / Tongo reality |
|---|---|
| `Enc(b;r) = (b·G + r·Y, r·G)` | Tongo's confidential-balance ciphertext (exponential ElGamal over the Stark curve) |
| `cipher_add` (homomorphic sum) | Tongo updates encrypted balances homomorphically, no decryption |
| `SameEncryption.verify_with_prefix` | the real `she` Sigma protocol; the prefix binds external context (Tongo binds `chain_id`; we bind the receipt) |
| viewing-key / auditor | STRK20's compliance channel — the tax authority is the "designated auditor"; this PoC is the *proactive* compliance predicate on top |

*PoC — synthetic data only. The fiscal authority, keys, TINs, and amounts are all fake.*
