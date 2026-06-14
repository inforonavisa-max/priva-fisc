# PRIVA-FISC — PoC (Mina / o1js)

**PRIVA-FISC** is a zero-knowledge protocol that proves a service transaction was
correctly fiscalized — VAT computed correctly, receipt structurally valid, seller
tax-ID registered — **without revealing the private commercial data behind it**
(buyer identity, item-level detail, margins). This repository is the **v0-A
proof-of-concept** on the Mina protocol using **o1js** (TypeScript).

> **This task = repo skeleton + synthetic EFI generator only.** The ZK circuit /
> ZkProgram is the **next** task and is intentionally **absent**. The relation it
> will prove is specified, language-agnostically, in [`spec/SPEC.md`](spec/SPEC.md)
> — the single source of truth.

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
| `npm run build` | `tsc` only |

```
npm install
npm run gen        # writes fixtures/valid-*.json, fixtures/invalid-*.json, manifest.json
npm run check      # recomputes every relation from the witness; exits non-zero on any failure

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
  rsa.ts              synthetic RSA-2048 keypair, RSA-SHA256 sign/verify, MD5
  ikof.ts             7-field IKOF input → IICSignature(hex) → IKOF=MD5 → JIKR placeholder
  commitments.ts      Poseidon: itemsCommit, D=Poseidon(T), C=SPEC §7-C2, registry leaf
  merkle.ts           registered-sellers tree: root + inclusion paths (o1js MerkleWitness)
  synthetic.ts        deterministic record + registry generation (valid + 4 invalid kinds)
  fixtures.ts         assembles {publicInputs, witness, expected, _invalidReason, ikof, efi}
  index.ts            CLI (npm run gen)
  synthetic/index.ts  compatibility re-export of the generator API
scripts/check.ts      generator self-check (npm run check) — NOT the ZK circuit
fixtures/             generated output (git-ignored; .gitkeep tracked)
synthetic-keys/       synthetic RSA keypair + NON-PRODUCTION marker (git-ignored)
```

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
6. **Receipt digest `D` = `Poseidon(T)`** (ZK-native), not `SHA-256(canonical
   XML)`. Byte-exact Exclusive-C14N is **not** done in v0-A (Phase-5 abstraction,
   SPEC §3/§13); the synthetic EFI XML is shape/realism only.

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

Repo skeleton + synthetic EFI generator complete; `npm run gen` and
`npm run check` are green. **No circuit code yet** — the ZkProgram is the next
task, to be implemented against `spec/SPEC.md` using the shared `src/` modules.

---

## License

**LICENSE: TBD — deferred pending D2 decision. Do not add an OSS license without
sign-off.** (Open-core vs. patent optionality is unresolved; an OSS license now
could foreclose the patent path.) Until then this code is **private / all rights
reserved** — do not redistribute. `package.json` is marked `UNLICENSED`.
