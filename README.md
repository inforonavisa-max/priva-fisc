# PRIVA-FISC — PoC (Mina / o1js)

**PRIVA-FISC** is a minimum-disclosure layer over state-signed fiscal data: a
zero-knowledge protocol proving, in one proof, that the authority's attestation
verifies, the seller is in the authority-anchored registry, and the VAT
predicate holds — **without revealing the private commercial data behind it**
(buyer identity, item-level detail, margins). Verifiers are private parties;
the state is the data source, not the client. This repository is the **v0-A
proof-of-concept** on the Mina protocol using **o1js** (TypeScript).

📄 **Architecture write-up / whitepaper:** [WHITEPAPER.md](WHITEPAPER.md)

> **Status:** the v0-A ZkProgram (constraints C1–C4) is implemented and **live on
> Mina Devnet** — see [Status](#status) for the explorer links. The proven relation
> is specified, language-agnostically, in [`spec/SPEC.md`](spec/SPEC.md) (the single
> source of truth). Read the **honest-scope** note below for exactly what this
> prototype does and does not prove (synthetic data; stand-in authority signature;
> real in-circuit signature/digest verification is Phase-5).

---

## ⚠️ Honest scope — read this first

This v0-A PoC is a **prototype of the signature-binding _architecture_**,
demonstrated on **synthetic data**:

- ❌ **No real in-circuit RSA verification** of Montenegro's actual fiscal
  signature chain. Montenegro e-fiscalization uses **RSA-SHA256 (PKCS#1 v1.5) +
  MD5 + enveloped XML-DSig (Exclusive C14N)**. Verifying that inside a ZK circuit
  (RSA-2048 modexp + SHA-256 + MD5 + XML canonicalization) is heavy and is
  **explicitly deferred to Phase-5 / R&D** (SPEC §8–§10).
- ❌ **Does not prove any real receipt was fiscalized.** v0-A operates on
  synthetic, self-generated inputs.
- ✅ **Demonstrates the selective-disclosure architecture**: a Poseidon
  commitment to sensitive fields, an *anchored* tax-ID membership check, a
  bounded-integer VAT-correctness relation, and a signature-binding shape — on
  synthetic data.

We deliberately do **not** claim this PoC "proves correct fiscalization."

---

## 🔒 Data firewall (D5) — synthetic only, always

**Zero real data.** No real PII, no real taxpayer certificates, no real Tax
Administration keys, ever. Enforced concretely:

- Every emitted fixture carries `"_synthetic": true` and
  `"_warning": "SYNTHETIC TEST DATA — NO REAL PII — NOT FOR PRODUCTION"`.
- **Seller PIBs** come from an obviously-synthetic reserved range: registered
  sellers use prefix `9090…`, deliberately-unregistered sellers `9099…`.
  `TODO(confirm)`: real PIB format/checksum — current values are **synthetic-shape
  only**, no format fidelity claimed.
- Buyers/items are opaque fabricated IDs (`SYNTH-BUYER-0001`, `SYNTH-ITEM-01`),
  never real names.
- The **RSA-2048 keypair** is freshly generated locally into `synthetic-keys/`
  (git-ignored) with a `DO-NOT-USE-NON-PRODUCTION.txt` marker. It is **not** a
  real certificate.
- `fixtures/*.json` and `synthetic-keys/` are git-ignored and never committed.

---

## Stack & toolchain (verified — see [`docs/o1js-notes.md`](docs/o1js-notes.md))

- **o1js `2.15.0`** — Mina ZK framework. **Pinned exactly** (no `^`) in
  `package.json`. (`3.0.0-mesa*` tags on npm are pre-release, not stable.)
- **Node.js** `≥ 18.14.0` (o1js floor); developed on `v25.9.0`.
- **TypeScript** strict, ESM. Scripts compile with `tsc` then run on Node.

## npm scripts

| Script | Action |
|---|---|
| `npm run gen` | `tsc` + generate synthetic fixtures into `fixtures/` |
| `npm run check` | `tsc` + run the generator **self-check** (`scripts/check.ts`) |
| `npm test` | `tsc` + the **36 fast regression guards** (`test/runner.ts`) |
| `npm run test:circuit` | `tsc` + the **ZkProgram suite** (compile + prove + reject; ~40 s) |
| `npm run build` | `tsc` only |

```
npm install
npm run gen          # writes fixtures/valid-*.json, fixtures/invalid-*.json, manifest.json
npm run check        # recomputes every relation (incl. C1 σ) from the witness
npm test             # 36 fast anti-drift guards (T-ORDER/T-LEAK/T-DET/T-CANON/T-RANGE/T-D5/T-PURITY)
npm run test:circuit # compiles the ZkProgram, proves the 5 valid fixtures, asserts all 5 invalids reject

# options:
npm run gen -- --valid=10 --invalid-per-reason=2 --registry=32 --seed=my-seed
```

Generation is **deterministic**: the same `--seed` (default `PRIVA-FISC-v0-A`)
yields byte-identical fixtures. (The synthetic RSA key is the one non-seeded
artifact — Node RSA keygen is not seedable — so it is cached in `synthetic-keys/`
and reused; PKCS#1 v1.5 signatures are themselves deterministic.)

---

## Layout

```
spec/SPEC.md          language-agnostic circuit specification (SINGLE SOURCE OF TRUTH)
docs/o1js-notes.md    verified o1js@2.15.0 APIs + SPEC reconciliations
src/
  encoding.ts         CANONICAL field→Field encoding — SINGLE SOURCE OF TRUTH (circuit-shared)
  schema.ts           EFI record + fixture types (mirrors SPEC §4.1) + VAT rule (SSOT)
  prng.ts             deterministic seeded PRNG (reproducible fixtures)
  canonical.ts        GENERATOR-ONLY byte canonicalize(P) + D = SHA-256 (two limbs)
  rsa.ts              synthetic RSA-2048 keypair, RSA-SHA256 sign/verify, MD5 (IKOF)
  ikof.ts             7-field IKOF input → IICSignature(hex) → IKOF=MD5 → JIKR placeholder
  authority.ts        GENERATOR-ONLY synthetic mock authority key + M + σ_rcpt (C1)
  commitments.ts      Poseidon: itemsCommit, C=SPEC §7-C2, leaf + Provable cores (circuit-shared)
  merkle.ts           registered-sellers tree: root + inclusion paths (o1js MerkleWitness)
  circuit.ts          the v0-A ZkProgram (C1–C4 + C5 limit) — the core deliverable
  synthetic.ts        deterministic record + registry generation (valid + 5 invalid kinds)
  fixtures.ts         assembles {publicInputs, witness, expected, _invalidReason, ikof, efi}
  index.ts            CLI (npm run gen)
  synthetic/index.ts  compatibility re-export of the generator API
scripts/check.ts      generator self-check (npm run check) — NOT the ZK circuit
test/                 36 fast guards (runner.ts) + t-circuit.test.ts (ZkProgram suite)
fixtures/             generated output (git-ignored; .gitkeep tracked)
synthetic-keys/       synthetic RSA keypair + NON-PRODUCTION marker (git-ignored)
```

---

## The v0-A circuit (`src/circuit.ts` — ZkProgram)

A Mina **ZkProgram** proving SPEC §7 over a synthetic receipt, revealing only the
public statement. Scheme: **o1js native `Signature`** (Schnorr over Pallas,
Poseidon-based — SPEC §11.1 left the v0-A scheme open, so we default to the
ZK-native framework signature). The attestation authority is a **synthetic /
NON-PRODUCTION mock** of the Montenegro Tax Administration (`src/authority.ts`),
its key derived deterministically from the generator seed; the **secret key is
never serialized**, only `PK_A` (public).

- **Public inputs:** `PK_A`, `R_reg` (sellersRoot), `D_hi`, `D_lo`, `C`.
  Statutory rate params are in-circuit constants (not public inputs).
- **C1 — attestation binding.** Recompute `M = H(DS_attest, D_hi, D_lo, C, R_reg,
  datetime, invoice_no)` from the public values + witness, assert it equals the
  signed `M` (anti-replay), then `σ_rcpt.verify(PK_A, [M])`. One signature;
  `R_reg` is anchored *inside* `M` (SPEC §11.3 one-signature branch — no σ_reg).
- **C2 — commitment.** `commitCFields(witness) == C` (shared Provable core).
- **C3 — VAT + range.** Round-half-up exactly as `computeVatCents`
  (`vat·10000 + r == base·rateBp + 5000`, `0 ≤ r < 10000`); every monetary
  witness range-checked to **MAXBITS=52**; `rateBp ∈ {0,700,2100}`;
  `total == vat_base + vat_amount`.
- **C4 — registration.** Poseidon-Merkle membership of `leaf = H(DS_leaf,
  seller_tin)` under `R_reg`; `seller_tin` stays private.
- **C5 — limit (documented, no code).** v0-A does **not** recompute
  `D = SHA-256(canonical(P))` in-circuit — `D` is an **opaque public input**, so
  C1 proves *"the authority signed THIS (D,C,R_reg,…)"*, not *"D is the SHA-256 of
  these fields"*. The in-circuit digest is Phase-5 (SPEC §7-C5/§9).

**Negative coverage.** Five invalid-fixture classes each make proving throw on
their constraint: `VAT_MISMATCH`/`OUT_OF_RANGE` (C3), `SELLER_NOT_REGISTERED`
(C4), `COMMITMENT_MISMATCH` (C2), `BAD_SIGNATURE` (C1) — plus a C1 anti-replay
test (tampering a receipt field bound into `M`).

> **Honest scope — `C` role (§6 / decision D2).** SPEC §6 labels `C` the
> *published on-chain output*. v0-A realizes `C` as a **constrained public input**
> (the circuit asserts `commitCFields(witness)==C`) so the COMMITMENT_MISMATCH
> soundness case can be exercised. This is verifier-equivalent (C is part of the
> verified public statement either way) but a deliberate **architectural role
> change**; production / Phase-5 revisits whether `C` is a circuit output or input.
> And, restating the core limit: the authority signature and digest here are
> **synthetic/ZK-native**; real RSA-SHA256 + in-circuit SHA-256(`D`) are Phase-5.

---

## Canonical encoding (the part the circuit must share)

`src/encoding.ts` is the **single source of truth** for how each schema field
becomes `Field` element(s). A generator↔circuit divergence here silently breaks
the C1 binding / C2 commitment, so it lives in exactly one place.

- **Money** → integer **euro cents** (`bigint`) → `Field(cents)` directly.
  Range bound (SPEC §7-C3): `0 ≤ cents ≤ MAX_AMOUNT_CENTS = 2^52 − 1`
  (**MAXBITS = 52**). Derivation: the VAT rule multiplies by up to `2100` basis
  points, and the task requires `base·rateBp < 2^64`; `2^52·2100 ≈ 9.46e18 < 2^64`.
  (SPEC §7-C3's "e.g. 53" example is for the *percent* form with multiplier ≤ 21;
  the basis-point form needs ~12 bits of headroom, so we pin 52. Resolved §11.4.)
- **Strings** (TIN, codes, datetime, buyer id, item names) → one `Field` via the
  **v0-A canonical string encoding**: UTF-8 bytes → big-endian 31-byte chunks →
  `Poseidon([Field(byteLength), ...chunkFields])`. Length-prefixed + chunked ⇒
  deterministic, collision-resistant, always a single Field.
- **VAT rate** → basis points (`Field(rateBp)`).
- **Field-tuple `T`** (SPEC §4.1, 13 elements, fixed order): the 13 payload fields
  with `line_items` represented by its sub-commitment `itemsCommit`. The receipt
  digest is `D = Poseidon([DS.DIGEST, ...T])`.
- **Commitment `C`** = full **SPEC §7-C2** (see "baked-in decisions" below).
- **Domain-separation tags** `DS = {DIGEST:1, COMMIT:2, LEAF:3, ITEMS:4}` (§11.7).

JSON convention: every `Field` and money value is serialized as a **decimal
string** so the self-check reads back the exact values hashed.

---

## Baked-in design decisions (do not refactor without sign-off)

1. **`seller_tin` is PRIVATE** (witness), proven via Merkle membership; only
   `sellersRoot` (`R_reg`) is public. `seller_tin` is **not** a public output.
   (SPEC §5.1.)
2. **Money** is uint64-range integer cents; bounded so `base·rateBp < 2^64`
   (MAXBITS = 52, above).
3. **VAT rule** (default, round-half-up at basis-point precision):
   `vatCents = floor((baseCents·vatRateBp + 5000) / 10000)`;
   `totalCents = baseCents + vatCents`. SSOT: `computeVatCents` in `src/schema.ts`.
4. **`vatRateBp ∈ {2100, 700, 0}`** — `TODO(confirm)`: VAT rate set + rounding
   convention against Montenegro *Tehnička uputstva*. **Not authoritative;
   placeholder.** No other values are invented.
5. **Commitment `C` = full SPEC §7-C2** (`seller_tin, buyer_id, H(line_items),
   margin, vat_base, vat_amount, vat_rate, total, salt`), **not** the prompt's
   reduced 4-field shorthand — so the generator matches the circuit the next task
   builds, and because SPEC §5.1 requires `seller_tin ∈ C`. See
   [`docs/o1js-notes.md`](docs/o1js-notes.md) and `src/commitments.ts`.
6. **Receipt digest `D` = `SHA-256(canonical(P))`** (SPEC §7-C5/§13), two 128-bit
   limbs `{hi,lo}`; an **opaque public input** (the circuit does not recompute it
   — Phase-5). The byte `canonicalize(P)` is a synthetic v0-A convention, NOT the
   real EFI-XML/Exclusive-C14N form (Phase-5 / Tehnička uputstva). The synthetic
   EFI XML is shape/realism only.
7. **Authority signature (C1)** = o1js native `Signature` (Schnorr/Pallas); the
   authority key is a synthetic seed-derived mock; `C` is realized as a constrained
   public input (decision D2, see the circuit section). Real RSA-SHA256 = Phase-5.

### Fixtures

Valid **and** invalid records are emitted. Each invalid record is tagged with
`_invalidReason ∈ {VAT_MISMATCH, SELLER_NOT_REGISTERED, OUT_OF_RANGE,
COMMITMENT_MISMATCH}` and isolates exactly one violated constraint, giving the
next task's circuit tests positive + negative cases. Fixture shape:

```jsonc
{
  "_synthetic": true, "_warning": "SYNTHETIC TEST DATA — …",
  "publicInputs": { "C", "D", "sellersRoot", "PK_ref", "rateParams" },
  "witness":      { …all T fields, "marginCents", "itemsCommit", "salt",
                    "merklePath", "merkleIndexBits", "merkleIndex" },
  "expected":     { "valid": true|false },
  "_invalidReason?": "…",
  "ikof":         { "ikofInput", "iicSignatureHex", "ikof", "jikr", "sellerRsaPublicKeyPem" },
  "efi":          { "record", "xmlSyntheticNonCanonical", "_note" }
}
```

> **`PK_ref` is a placeholder.** The v0-A **authority** ZK-signature
> (Schnorr/EdDSA-native, SPEC §3/§7-C1) and the `σ_rcpt`/`σ_reg` attestations are
> produced by the **circuit task**, not this generator. `expected.valid` therefore
> reflects the generator-checkable subset (SPEC §7 **C2/C3/C4** + structural);
> **C1** (signature binding) is the circuit's. The *seller* RSA key here is only
> for the synthetic IKOF chain.

---

## `TODO(confirm)` register (nothing below is authoritative)

- VAT rate set `{2100,700,0}` + round-half-up convention vs *Tehnička uputstva*.
- Real PIB format/checksum (current PIBs are synthetic-shape only).
- IKOF 7-field set, **order**, and value formatting (date/total formatting,
  separators) vs *Tehnička uputstva*.
- Whether IIC = MD5 over signature **bytes** (as implemented) vs its hex/base64
  text encoding.
- Final domain-separation tag values (`DS_*`) and canonical field ordering (§11.7).

---

## Status

v0-A complete: synthetic generator **+ the ZkProgram** (`src/circuit.ts`, C1–C4 +
C5 limit) with authority attestation. `npm run gen`, `npm run check` (10/10), the
**36 fast guards** (`npm test`), and the **ZkProgram suite** (`npm run
test:circuit`: compile + 5 valid proofs verify + all 5 invalids reject + C1
anti-replay) are all green.

**Live on Mina Devnet.** The `FiscAnchor` zkApp (`src/anchor.ts`) verifies a
FiscProof on-chain and writes only the commitment `C` to contract state. A valid
synthetic proof was verified on Devnet and the on-chain `lastCommitment` matched
`C` (it transitioned `0 → C`). Deploy with `npm run devnet:deploy` from a host
with network access to the Devnet endpoint.
- zkApp account: <https://minascan.io/devnet/account/B62qjhevpDt7BNjvt37JLqr9DVzA7Ewdoye48SbxaaY7vt9QK6X69Q6>
- Deploy tx: <https://minascan.io/devnet/tx/5Jtb4kX3ANjnqdaNsJVSShTb3dtiSe3KivscdaUK6Q5gU28mrpof?type=zk-tx>
- On-chain proof-verification (publish) tx: <https://minascan.io/devnet/tx/5JuG4rMNvzv7xWkodXdd4Q76wbTRWuegzYhkfdJBKW25LtFA3Bw9?type=zk-tx>

This is the v0-A architecture running end-to-end on **synthetic data**, with a
stand-in (ZK-native) authority signature and an opaque public `D` — **not** a proof
that any real receipt was fiscalized. Phase-5 (real RSA-SHA256 + MD5 + XML-DSig
verified in-circuit, in-circuit SHA-256 `D`, real registry oracle + threshold
audit) remains the R&D track (SPEC §8–§10).

---

## License

License: **Apache-2.0** (open-core). See [LICENSE](LICENSE).
