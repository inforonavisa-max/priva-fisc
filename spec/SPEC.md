# PRIVA-FISC — Circuit Specification

> **Variant:** v0-A · **Status:** DRAFT (pending ZK-grant + honesty review)
> **Scope:** language-agnostic. This document defines the *relation* the circuit
> proves — public/private inputs, constraints, trust model — independent of any
> proving framework. No o1js (or Leo/Noir) API appears here by design; the same
> relation is later implemented in each stack.

---

## 0. What v0-A is (and is not)

**v0-A** demonstrates the **selective-disclosure / signature-binding _architecture_**
on **synthetic data**, using ZK-native primitives:

- The authority attestation is a **ZK-friendly signature** (mock stand-in).
- Privacy/masking is a **Poseidon commitment**.
- The receipt digest `D` is **disclosed** (a deliberate, documented limit — §1.2).

**v0-A explicitly does NOT** verify Montenegro's real fiscal signature chain
(RSA-SHA256 / PKCS#1 v1.5 + MD5 + enveloped XML-DSig) in-circuit, and does NOT
prove any *real* receipt was fiscalized. Real in-circuit signature/hash verification
is **Phase-5 / R&D** (§8–§10). We do not claim v0-A "proves correct fiscalization";
it proves the *shape* of that claim under an explicit, stated trust assumption.

---

## 1. Overview

### 1.1 The statement (informal)

> *"There exists a fiscal service receipt, attested by the fiscal authority `A`,
> issued by a **registered** seller, whose VAT is arithmetically correct at a
> statutory rate — and all sensitive commercial fields of that receipt are sealed
> inside the public commitment `C` — without revealing seller identity, buyer
> identity, line items, margins, or amounts."*

### 1.2 Privacy model — and the `D`-disclosure limit

| Class | Values |
|---|---|
| **Disclosed (public)** | `PK_A` (authority key), `R_reg` (registry root), **`D` (receipt digest)**, `C` (commitment) |
| **Hidden (private witness)** | `seller_tin`, `buyer_id`, `line_items`, `margin`, `vat_base`, `vat_amount`, `vat_rate`, `salt`, Merkle path, signatures |
| **Proven (public guarantee)** | registered seller · authority-attested receipt · VAT correct at a statutory rate · sensitive fields committed in `C` |

**The `D` limit (deliberate v0-A compromise).** `D` is the receipt's real-world
digest — in the live system, `D = SHA-256(canonical EFI payload)`, the value the
RSA/MD5 (IKOF) chain signs. v0-A does **not** recompute `D` from the private fields
in-circuit (that requires SHA-256-in-circuit = Phase-5). Therefore `D` is taken as a
**public input** and is bound to the private fields *only* through the authority
attestation (constraint **C1**), not by an in-circuit hash.

Two consequences, stated plainly:

1. **Soundness limit.** v0-A *trusts the attestation* that `D` and `C` describe the
   same real receipt; it does not internally re-derive `D` from the committed fields.
   The cryptographic `D ↔ fields` binding is the Phase-5 deliverable.
2. **Privacy limit.** Because `D` is public, the proof is **linkable** to a specific
   receipt digest, and an adversary holding candidate receipts can confirm them
   offline (`D ?= hash(candidate)`). A full system keeps `D` private and proves its
   relation to `C` in-circuit. v0-A accepts `D`-disclosure as a scoping decision; the
   rationale is solely that real digest computation is deferred to Phase-5.

---

## 2. Entities & trust model

- **Seller (taxpayer).** Holds `seller_tin` (PIB). Issues the receipt.
- **Attestation Authority `A`.** Mock stand-in for the Montenegro Tax Administration.
  Holds keypair `(sk_A, PK_A)`; `PK_A` is a public input. In v0-A, `A` issues a
  ZK-friendly signature. *Real-world caveat:* Montenegro's live protocol returns
  **JIKR/FIC — a confirmation ID, not a third-party-verifiable signature** (§13).
  v0-A therefore models an authority that issues a *verifiable attestation*; that this
  attestation does not yet exist in the live protocol is itself a documented adoption
  dependency (Phase-5 / institutional).
- **Registry.** `A`-maintained set of registered seller TINs, committed as Merkle root
  `R_reg`, **anchored** to `A` (so a prover cannot substitute a self-built registry).
- **Prover.** Seller (or their software) generating the proof.
- **Verifier.** On-chain verifier / consumer of the proof + published `C`.

**Trust assumption (v0-A):** the verifier trusts `PK_A` as the authority key and
trusts `A`'s attestation that `(D, C, R_reg)` belong to one real, accepted receipt.
Removing this trust (re-deriving `D` in-circuit, binding to the real cert chain) is
the Phase-5 goal.

---

## 3. Definitions

- **`H(·)`** — a ZK-friendly hash (Poseidon family), with domain separation per use.
- **`S = (Sign, Verify)`** — a ZK-friendly signature scheme (e.g. Schnorr/EdDSA over
  the proof system's native curve). `Verify(PK, m, σ) ∈ {true,false}`.
- **`Merkle.Verify(root, leaf, path) ∈ {true,false}`** — Poseidon Merkle membership.
- **"Valid / fiscalized" (v0-A definition).** A receipt is *valid* iff its payload
  **carries a signature `σ` such that `Verify(PK_A, M, σ) = true`**, where `M` is the
  binding message (§7, C1) and **`PK_A` is a public input**. (This is point (1) of the
  fixed scope: validity ≡ verifiable authority signature against the public `PK`.)
- **Monetary values** are non-negative integers in **minor units (euro cents)** —
  Montenegro is euroized. All are **range-bounded** (§7, C3) to prevent prime-field
  wrap-around.

---

## 4. Data model — receipt payload `P`

EFI-shaped canonical fields (synthetic in v0-A):

| Field | Meaning | v0-A class |
|---|---|---|
| `seller_tin` | seller PIB (tax ID) | **private** (fixed — §5.1) |
| `datetime` | ISO-8601 issue time | private (binds anti-replay) |
| `invoice_no` | invoice ordinal | private |
| `business_unit` | business-unit code | private |
| `enu_tcr` | ENU/TCR cash-register code | private |
| `software_code` | software code | private |
| `total` | gross total (cents) | private |
| `vat_base` | net base (cents) | private |
| `vat_rate` | applied rate | private (statutory-set constrained — §5.3) |
| `vat_amount` | VAT amount (cents) | private |
| `buyer_id` | buyer identity | **private** (personal data) |
| `line_items` | item-level detail | **private** (representation: open, §11) |
| `margin` | seller margin | **private** |

---

## 5. Fixed design decisions (decided now — do not refactor)

These three are fixed *before* commitment design, to avoid a structural rewrite later.

### 5.1 `seller_tin` is **PRIVATE** (committed witness)
- **Decision:** `seller_tin` is a private witness, included in `C`, and its registry
  membership (C4) is proven **without revealing the leaf value**.
- **Rationale:** (a) maximizes the selective-disclosure thesis — *"some registered
  seller correctly fiscalized this"* — the protocol's whole point; (b) **refactor-safe
  by construction**: a committed-and-hidden field can later be *selectively revealed*
  as an additional public output with no commitment change, whereas a field fixed
  public now would require re-engineering `C` to ever hide it. Reveal-later is additive;
  hide-later is structural. We take the reversible direction.
- **Trade-off (acknowledged):** if the consuming verifier (e.g. tax authority) needs
  attribution, seller identity is recovered via selective reveal or the Phase-5
  threshold-audit path — not by hardcoding it public.

### 5.2 "Valid" ≡ verifiable authority signature; `PK_A` is a **public input**
Per §3. Validity is *defined* by C1, anchored on the public `PK_A`. No notion of
validity in v0-A exists independent of an authority-verifiable signature.

### 5.3 `D` is disclosed (public input); its limit is documented in §1.2
`D` is public in v0-A. The `D ↔ fields` in-circuit binding (SHA-256) is Phase-5.

---

## 6. Circuit interface

**Public inputs (statement):**
- `PK_A` — attestation authority public key
- `R_reg` — authority-anchored registry Merkle root
- `D` — receipt digest (disclosed; §1.2)

**Public output:**
- `C` — Poseidon commitment to the sensitive fields (published on-chain)

**Private witnesses:**
- payload fields per §4 (`seller_tin`, `buyer_id`, `line_items`, `margin`,
  `vat_base`, `vat_amount`, `vat_rate`, `total`, `datetime`, `invoice_no`,
  `business_unit`, `enu_tcr`, `software_code`)
- `salt` — commitment randomness
- `path_reg` — Merkle path of `seller_tin` under `R_reg`
- `σ_rcpt` — authority attestation over the receipt-binding message `M`
- `σ_reg` — authority attestation over `R_reg` (registry anchoring; see §11 for
  single-vs-separate-signature option)

---

## 7. Constraints (the proven relation)

The proof asserts: *there exist private witnesses such that all of the following hold.*

**C1 — Attestation validity (signature binding).**
`Verify(PK_A, M, σ_rcpt) = true`, where the binding message
`M = H( DS_attest, D, C, R_reg, datetime, invoice_no )`.
`M` binds the public `(D, C, R_reg)` together with anti-replay fields so the
attestation cannot be lifted onto a different receipt.
*v0-A:* `S` is ZK-friendly. *Phase-5:* `S` = RSA-SHA256 (PKCS#1 v1.5) + MD5 + enveloped
XML-DSig over the real cert chain, and `D` is recomputed in-circuit.

**C2 — Commitment correctness (masking).**
`C = H( DS_commit, seller_tin, buyer_id, H(line_items), margin, vat_base, vat_amount,
vat_rate, total, salt )`.
Binds every sensitive field; `salt` provides hiding.

**C3 — VAT correctness (bounded integers).**
- Range: every monetary witness `∈ [0, 2^MAXBITS)` (MAXBITS fixed in build, e.g. 53),
  enforced by explicit range checks so `vat_base · vat_rate` cannot wrap the field.
- Arithmetic (rate as integer percent): `vat_amount · 100 == vat_base · vat_rate`
  under the chosen rounding convention (rounding rule = open, §11).
- Consistency: `total == vat_base + vat_amount`.
- Statutory rate: `vat_rate ∈ {0, 7, 21}` enforced by
  `vat_rate · (vat_rate − 7) · (vat_rate − 21) == 0` (proves a lawful rate was applied
  without revealing which; avoids leaking service category).

**C4 — Seller registration (anchored membership).**
`Merkle.Verify(R_reg, leaf, path_reg) = true`, where `leaf = H( DS_leaf, seller_tin )`.
`seller_tin` stays private. **Anchoring:** `R_reg` is covered by the authority
attestation — either folded into `M` (C1) or via a separate `σ_reg` with
`Verify(PK_A, R_reg, σ_reg) = true` — so the registry root is authority-fixed, not
prover-chosen. (Which mechanism = open, §11.)

**C5 — `D`↔fields binding boundary (Phase-5 marker, EXPLICIT LIMIT).**
v0-A does **not** constrain `D = SHA-256(canonical(P))` in-circuit. `D`↔`C`
correspondence is asserted only via C1's attestation. This is the documented
soundness limit (§1.2-1). Phase-5 replaces this with an in-circuit digest
computation, removing the trust placed on the attester for `D`↔fields.

---

## 8. v0-A ↔ real Montenegro / Phase-5 mapping

| Concept | v0-A (this spec) | Real / Phase-5 |
|---|---|---|
| Authority signature `S` | ZK-friendly (Schnorr/EdDSA-native) | RSA-SHA256 PKCS#1 v1.5 **+ MD5** (IKOF) **+ enveloped XML-DSig**, Exclusive C14N |
| `PK_A` | mock authority key | real Tax-Admin cert key, X.509 chain (PKCS12, Posta CG / CoreIT CA) |
| Digest `D` | public input | `SHA-256(canonical EFI XML)`, computed **in-circuit** |
| Authority vouching | verifiable `σ` (assumed) | live protocol returns **JIKR = ID, not a signature** → needs authority-signature integration (§13) |
| Registry `R_reg` | `A`-attested Merkle root | authority registry / oracle attestation |
| Data | synthetic, no PII | (never real PII in this repo; production = separate, gated) |

---

## 9. Maturity ladder

- **v0-A** *(this spec)* — Poseidon commitment + ZK-friendly mock attestation; `D`
  public; no SHA-256/RSA in-circuit. Goal: demonstrate the architecture end-to-end.
- **v0-B** *(optional intermediate)* — SHA-256 of the canonical payload computed
  in-circuit so `D` is privately derived and the C5 limit is closed for the hash layer
  (still ZK-friendly authority signature).
- **Phase-5 / R&D** — full RSA-SHA256 + MD5 + XML-DSig over the real cert chain
  in-circuit; real registry oracle; threshold-audit opening. This is where the heavy
  cryptographic engineering and the principal grant value live.

---

## 10. Feasibility note — why RSA is deferred

Verifying Montenegro's *real* signature in-circuit means, per transaction:
**RSA-2048 modular exponentiation** (non-native big-integer arithmetic — the dominant
cost, heavier than ECDSA) **+ SHA-256 + MD5 + XML Exclusive-C14N normalization**. Each
is individually expensive in a ZK circuit; together they dwarf the v0-A relation
(a handful of Poseidon hashes, one ZK-native signature, one Merkle path, integer range
checks). v0-A is therefore the honest, buildable first rung; a concrete
constraint-count / proving-time estimate for the RSA path is a Phase-5 deliverable and
a strong grant artifact in its own right.

---

## 11. Open decisions (resolved during build — not blocking this spec)

1. **ZK-signature scheme** for the v0-A attestation (Schnorr over the native curve vs
   EdDSA vs a Poseidon-based MAC).
2. **`line_items` representation** (single Poseidon hash of a fixed-arity tuple vs a
   Merkle accumulator vs fixed `N`).
3. **Registry anchoring mechanism** — fold `R_reg` into `M` (one signature) vs a
   separate `σ_reg` (two signatures); and single vs distinct authority keys for
   registry vs receipt.
4. **VAT rounding convention** (exact equality vs half-up to whole cents) and `MAXBITS`
   for monetary range checks.
5. **`vat_rate` exposure** — **default: keep private** + statutory-set constraint
   (§5.3). Exposing the rate leaks the service category (rate ⇒ sector), reducing
   privacy, so the same reversibility principle as `seller_tin` (§5.1) applies —
   private now, selectively revealable later. Direction confirmed **private**; exact
   final form fixed in build.
6. **On-chain published surface** — `C` only vs `C + D` vs add a **nullifier** for
   replay/double-count protection (see §12).
7. **Domain-separation tags** (`DS_*`) concrete values and the canonical field ordering
   inside `H`.

---

## 12. Non-goals / out of scope for v0-A

- **Threshold judicial-audit (K-of-N) opening** — a separate cryptographic layer
  (Shamir / threshold decryption / MPC), explicitly *not* "view keys"; Phase-5.
- **Replay / double-counting nullifier** — **out of scope for v0-A, and this is a
  *stated* limit, not a silent one:** the same proof / commitment can be presented more
  than once. A nullifier (e.g. binding `H(seller_tin, invoice_no)`) closes this in a
  later increment (§11.6). Exactly like the `D` limit (§1.2), the write-up must
  disclose this before a reviewer asks.
- **Real data of any kind** — synthetic only, always (repo data policy).
- **Cross-chain commitment portability** — Poseidon is field-specific; each stack's
  `C` is its own (the spec is shared, the implementations are independent).

---

## 13. References (verified facts this spec relies on)

- **Signature chain is RSA-only.** Montenegro e-fiscalization: **RSA-SHA256
  (PKCS#1 v1.5) + SHA-256 + MD5**; no ECDSA path.
- **IKOF (IIC)** = `uppercase( MD5( RSA-SHA256_sellerKey( "|"-join of 7 fields ) ) )`
  — i.e. an **MD5 hash of an RSA signature**, generated client-side by the seller POS;
  the raw RSA signature is the separate `IICSignature` field.
- **JIKR (FIC)** = the **tax-server confirmation ID** returned after it validates the
  signed XML — **not** a signature or hash. (⇒ the authority does not currently issue a
  third-party-verifiable signature; see §2 trust note.)
- **Message** = custom **EFI XML** (not UBL), enveloped XML-DSig, **Exclusive C14N**,
  SHA-256 digest, X.509 in KeyInfo; PKCS12 RSA cert (~5y) from Posta Crne Gore / CoreIT.
- **Canonicalization caveat:** reference libs differ (one signs raw UTF-8 of the
  concat string, another SHA-256-hashes first then signs the digest) → match the
  canonical EFI form against the official *Tehnička uputstva* before any Phase-5
  in-circuit digest work.
- **v0-A synthetic canonicalization (generator anchor).** The synthetic generator
  fixes **one** convention for internal consistency: `D = SHA-256(canonicalize(P))`;
  synthetic `IICSignature = RSA-SHA256(canonicalize(P))` (locally-generated synthetic
  key); `IKOF = uppercase(MD5(IICSignature))`. This is an *internal v0-A synthetic*
  convention **only** — not a claim about the real canonical form. The generator
  implements a single `canonicalize(P)` used everywhere; matching the official
  *Tehnička uputstva* is Phase-5.
- Endpoints: `mapr.tax.gov.me` (prod), `efitest.tax.gov.me` (test).

---
*v0-A draft. Implementation begins only after this spec is reviewed and approved.*
