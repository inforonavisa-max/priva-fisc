# PRIVA-FISC v0-A — Leo / Aleo implementation

> **Variant:** v0-A · **Stack:** Leo 4.2.0 (Aleo) · **Status:** local build + tests pass; **not deployed**
> **Source of truth:** [`../spec/SPEC.md`](../spec/SPEC.md) (the relation) + [`../docs/aleo-recon.md`](../docs/aleo-recon.md) (the Leo native-primitive mapping).

This is an **independent Leo implementation** of the same v0-A relation already built in
Mina/o1js under [`../src/`](../src/). The **spec is shared; the implementations are not** —
the Mina code is untouched. Per SPEC §12, the Poseidon commitment `C` is field-specific, so
this stack's `C`/`M`/root values are its own (Aleo uses the Edwards-BLS12-377 base field, not
Pallas) and are **not** comparable to the Mina fixtures.

## What this is (and is not)

Exactly the **same honesty envelope as Mina v0-A** (SPEC §0). v0-A demonstrates the
selective-disclosure / signature-binding **architecture** on **synthetic** data:

- ✅ Authority attestation = a **ZK-friendly signature** — here Aleo's **native Schnorr**
  (`signature::verify`), with the authority modeled as a **synthetic Aleo test account
  `address`** (the resolved design point: native verify binds to an account address, not an
  arbitrary external key — see [aleo-recon.md](../docs/aleo-recon.md) §C.1 / §7).
- ✅ Privacy/masking = a **Poseidon commitment** (`C`), salt in the preimage.
- ⚠️ The receipt digest **`D` is disclosed and opaque** (two public limbs); it is **not**
  recomputed in-circuit. SHA-256-in-circuit is **Phase-5** (and is **not native in Leo
  either** — Leo has Keccak/SHA3, not SHA-2; see aleo-recon.md §C.3).

**v0-A does NOT** verify Montenegro's real RSA-SHA256/MD5/XML-DSig chain, does not prove any
real receipt was fiscalized, and uses **no real PII or keys** — ever. Same **stated** limits
as Mina v0-A: **`D`-disclosure** (SPEC §1.2) and **no replay nullifier** (SPEC §12) — the same
commitment/proof can be presented more than once. These are documented, not silent.

## Constraint map — Leo code ↔ SPEC C1–C5

All in [`src/main.leo`](src/main.leo), transition `prove`. Native primitives verified in
[aleo-recon.md](../docs/aleo-recon.md).

| SPEC | Leo realization | Native primitive |
|---|---|---|
| **C1** attestation + anti-replay | `m = binding_message(d_hi,d_lo,c,sellers_root,w)`; `assert(signature::verify(sig, authority, m))`. `M = H(DS_ATTEST, D_hi, D_lo, C, R_reg, datetime, invoice)` | **`signature::verify`** (Schnorr, signer = Aleo `address`) |
| **C2** salted commitment | `assert_eq(commit_c(w), c)` over `{seller_tin, buyer_id, items, margin, vat_base, vat_amount, rate_bp, total, salt}` + DS tag | **`Poseidon2::hash_to_field`** (salted hash; no native Poseidon `commit`) |
| **C3** bounded-int VAT | checked `u64`/`u128`: `vat_base..margin ≤ 2^52−1`; `rate_bp ∈ {0,700,2100}`; `vat_amount*10000 + r == vat_base*rate_bp + 5000`, `r<10000`; `total == vat_base+vat_amount` | native **checked integer** arithmetic |
| **C4** anchored Merkle membership | `leaf_of(seller_tin)` then `fold_root(leaf, siblings, path_bits) == sellers_root` (height 8 ⇒ 7 levels); root anchored by C1 (root ∈ M, SPEC §11.3 single-signature) | **`Poseidon2`** hand-rolled fold (no native Merkle gadget) |
| **C5** `D` opaque (LIMIT) | `d_hi`/`d_lo` enter **only** `M`; never recomputed in-circuit | — (documented soundness limit) |

**Public statement** (`prove` public inputs): `authority` (PK_A as address), `sellers_root`
(R_reg), `d_hi`,`d_lo` (D limbs), `c` (commitment). **Private witness:** `w` (seller_tin,
buyer_id, line-items commit, margin, amounts, salt), `sig`, Merkle `siblings` + `path_bits`.
A verifying execution **is** the statement (C realized as a constrained public input, exactly
as in the Mina port — see [circuit.ts](../src/circuit.ts) header).

> `prove` is the proven relation. `prepare` is a **test-only** helper that derives
> `(c, root, m)` from a witness so the harness can publish `c`/`root` and sign `m`; it is **not**
> part of the proven statement and would be removed for production.

## Build & test

Requires **Leo 4.2.0** on `PATH` (`leo --version` → `4.2.0`); see install in
[aleo-recon.md](../docs/aleo-recon.md) §B.

```bash
leo build          # compiles priva_fisc_v0a.aleo to Aleo instructions
./run_tests.sh     # positive + 4 isolated negative (soundness) tests
# or: LEO=/path/to/leo ./run_tests.sh
```

`run_tests.sh` mirrors the Mina fixture discipline — **one valid instance must prove, one
minimally-tampered instance must be rejected per constraint** — driven by `leo run`:

| Test | Tampered input | Rejected by | Isolated? |
|---|---|---|---|
| POSITIVE | — | — (proof passes) | C1–C5 satisfied |
| NEG-A | attacker's signature over the same `M` | **C1** (`signature::verify` → false) | yes |
| NEG-B | `vat_amount`/`total` off by 1 (total stays consistent) | **C3** (round-half-up eq) | yes |
| NEG-C | one Merkle sibling changed | **C4** (root mismatch) | yes |
| NEG-D | `buyer_id` changed, valid `c` kept | **C2** (commit mismatch) | yes — `buyer_id` enters only the commitment |

The synthetic **authority account is generated fresh per run** and kept in shell variables
only — **no private key is written to disk** (and `.gitignore` blocks `*PrivateKey*`/`.env`).

## Not deployed

Deployment to **Testnet Beta** is a separate step (faucet, explorer, `leo deploy --broadcast`
notes in [aleo-recon.md](../docs/aleo-recon.md) §B.3). Nothing here was broadcast to any network.

## Layout

```
leo/
├── program.json        # priva_fisc_v0a.aleo (Apache-2.0)
├── src/main.leo        # the relation: helpers/structs (outside) + prove/prepare (inside)
├── run_tests.sh        # positive + 4 negative soundness tests via `leo run`
└── README.md           # this file
```
