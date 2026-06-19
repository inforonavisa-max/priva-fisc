# Starknet / Cairo + STRK20 Reconnaissance — for a v0-A Port Decision

> **Status:** RECON ONLY (2026-06-19). No full port was written; nothing was deployed to
> Starknet; no real data touched; the Mina `src/`, the `spec/`, the Leo `leo/`, and the Noir
> `noir/` were **not** modified. The Cairo toolchain was installed to user dirs
> (`~/.local/bin`, `~/Library/Caches/com.swmansion.scarb`) — outside the repo. One **minimal
> Scarb package** lives in [`../cairo/`](../cairo/) and is the only repo addition besides this
> file. Every external claim is sourced; facts marked **[verified locally]** were actually
> built/run on this machine (macOS 26.5 / arm64) with `scarb build` + `snforge test`.
>
> **Questions this answers:**
> 1. If/when we implement the v0-A relation ([`../spec/SPEC.md`](../spec/SPEC.md)) in Cairo, how
>    cleanly does each constraint map?
> 2. **THE headline (STRK20):** *Can PRIVA-FISC be built as a **fiscalization-compliance proof
>    layer over STRK20's confidential payments** — proving a confidential payment was correctly
>    taxed (VAT correct, receipt authority-signed) in ZK, without revealing the amount or the
>    parties?* **Short answer: YES — and this is the most architecturally natural fit of every
>    stack evaluated (Mina/Aleo/Noir/Cairo), because STRK20's confidential-payment crypto
>    (Tongo/SHE: additively-homomorphic ElGamal + Sigma proofs) and Cairo's native fiscal-proof
>    primitives (Poseidon, Stark-curve ECDSA, SHA-256) live on the *same* Stark curve, and
>    STRK20's viewing-key/auditor model *is* the selective-disclosure channel our spec already
>    calls for.**
> 3. **Phase-5 (real RSA-2048 + SHA-256):** SHA-256 is **native in Cairo's corelib** (unlike
>    Mina/Aleo); RSA-2048 has a **strong native substrate** (the `core::circuit` 384-bit
>    modular-arithmetic builtin) but **no turnkey verifier library** (unlike Noir). Cairo sits
>    **between** Noir (turnkey RSA) and Mina/Aleo (no SHA-256 at all).

---

## 0. Headline

| Question | Answer |
|---|---|
| Native ZK hash in Cairo? | **YES, and it's the *native default* — not a library.** **Poseidon** (`core::poseidon::poseidon_hash_span`, builtin-backed) and **Pedersen** (`core::pedersen::pedersen`, builtin) are in the corelib. **[verified locally]** Contrast Noir, where Poseidon2 is an external lib. |
| Native ZK signature verify? | **YES — Stark-curve ECDSA in corelib** (`core::ecdsa::check_ecdsa_signature`), plus `recover_public_key`. A valid synthetic vector verifies and a tampered message is rejected. **[verified locally]** |
| Native Merkle gadget? | **NO** — no stdlib Merkle helper; hand-roll a Poseidon path-fold (done in the skeleton, `merkle_root`). Same as Noir/Aleo. **[verified locally]** |
| **STRK20 fit — can PRIVA-FISC be a compliance proof layer over confidential payments?** | **YES, and most naturally of all stacks.** STRK20's SDK **Tongo** ([`fatlabsxyz/tongo`](https://github.com/fatlabsxyz/tongo)) encrypts amounts as **additively-homomorphic ElGamal over the Stark curve**, proven with the **SHE** Sigma-protocol library ([`fatlabsxyz/she`](https://github.com/fatlabsxyz/she)), **no trusted setup**. PRIVA-FISC attaches as a **ZK compliance *predicate*** over a Tongo confidential transfer; the VAT identity `total = vat_base + vat_amount` is checkable **directly on the ciphertexts** via the homomorphism (**[verified locally]**); STRK20's **viewing-key/auditor** model is the selective-disclosure channel our SPEC §12/§5.1 already specifies. **Predicate AND viewing-key — layered, not either/or.** |
| **RSA-2048 + SHA-256 in-circuit (Phase-5)?** | **Mixed — better than Mina/Aleo, not as turnkey as Noir.** **SHA-256 is NATIVE** in `core::sha256` (builtin-backed); exact digest verified in-circuit **[verified locally]**. **RSA-2048**: no off-the-shelf PKCS#1 v1.5 verifier library found (checked corelib, Garaga, Alexandria), **but** the substrate is strong — `core::circuit` `AddMod`/`MulMod` do 384-bit modular arithmetic (u384 = 4×u96); a single modmul evaluates **[verified locally]**; RSA-2048 = modexp built on these (the path Garaga already uses for EC). |
| Is SHA-256 native? | **YES — `core::sha256` (corelib), builtin-backed.** This closes the v0-A opaque-`D` limit (C5 → v0-B) in-circuit, exactly as in Noir, and is a strength Mina/Aleo lack entirely. Cost is non-trivial (see §D). **[verified locally]** |
| Does v0-A map cleanly? | **Yes — and Cairo is the only stack where the *commitment/hash/signature* primitives are all corelib-native AND the privacy substrate (STRK20) is a same-curve, no-trusted-setup, compliance-first framework.** Merkle is hand-rolled (as everywhere); `C` is Stark-field-specific (as everywhere). |
| Execution model | **Cairo has no "gates."** v0-A is a **Cairo program** whose execution is **STARK-proven** by Starknet's native prover (Stwo/SHARP). **No per-application trusted setup, no external verifier** — the proof verifies on Starknet directly. This is a structural advantage for an *on-chain* compliance layer over STRK20. |

---

## TASK A — Toolchain & versions (verified)

### A.1 Versions (June 2026)

| Component | Version | Source |
|---|---|---|
| **Scarb** (build tool) | **`2.18.0`** (`e6144df0f`, 2026-04-21) | `scarb --version` — **[verified locally]** |
| **Cairo** (compiler) | **`2.18.0`** | bundled in Scarb 2.18.0 — **[verified locally]** |
| **Sierra** | **`1.8.0`** | bundled in Scarb 2.18.0 — **[verified locally]** |
| **Starknet Foundry** (`snforge` test runner) | **`0.61.0`** | `snforge --version` — **[verified locally]** |
| **`sncast`** (deploy/interact CLI) | **`0.61.0`** | `sncast --version` — **[verified locally]** |
| **universal-sierra-compiler** | **`2.8.0`** | resolved by `snfoundryup` — **[verified locally]** |
| `snforge_std` / `assert_macros` (deps) | **`0.61.0` / `2.18.0`** | `scarb new --test-runner starknet-foundry` lockfile — **[verified locally]** |

**Install run [verified locally]** (official non-interactive scripts, to `~/.local/bin`):
```
$ curl --proto '=https' --tlsv1.2 -sSf https://docs.swmansion.com/scarb/install.sh | sh   # Scarb
$ curl -sSL .../starknet-foundry/master/scripts/install.sh | sh && snfoundryup           # snforge
$ scarb --version
scarb 2.18.0 (e6144df0f 2026-04-21)
cairo: 2.18.0 ; sierra: 1.8.0 ; arch: aarch64-apple-darwin
$ snforge --version
snforge 0.61.0
```

> The recommended all-in-one is **`starkup`**, which installs the latest stable Scarb + Starknet
> Foundry via an `asdf`-style manager. We used the two individual official scripts (equivalent,
> fully non-interactive). Pin versions in `Scarb.toml` for reproducibility.

### A.2 Execution model — why "circuit" is the wrong mental model

Cairo is **not** a circuit DSL like Noir/o1js/Leo. You write an ordinary Cairo program; the
Starknet prover produces a **STARK** attesting that the program executed correctly on its inputs.
Consequences that matter for a port decision:

- **No per-application trusted setup, no external verifier.** A Halo2/Groth16 circuit needs a
  proving/verifying key (and Groth16 a ceremony); a Cairo program is proven by the **shared,
  STARK-based** Starknet prover and verified **on Starknet natively**. For an *on-chain* fiscal
  compliance layer over STRK20, this removes a whole class of deployment friction (no Solidity
  verifier, no ceremony).
- **Cost is measured in Cairo steps + builtin cells (≈ L2 gas), not gates.** The gate counts that
  dominate the Noir recon have no analogue here. The skeleton reports `snforge` **sierra-gas**
  estimates (§F) as the closest available cost signal.
- **The STRK20/Tongo "circuit" is the same idea:** client-side proof, sequencer-side verification,
  all in Cairo — *"a single unified codebase for both the client-side proof and the on-chain
  contract."* ([Starknet blog](https://www.starknet.io/blog/make-all-erc-20-tokens-private-with-strk20/))

---

## TASK B — Native / library primitive inventory (compile-verified)

Cairo's **corelib is crypto-rich** (the opposite of Noir's shrinking stdlib): the hashes and the
signature scheme v0-A needs are all `core::*`, builtin-backed. Verified by reading the resolved
corelib source (`…/registry/std/v2.18.0/core/src/*`) **and** by compiling/running probes in
[`../cairo/`](../cairo/).

| Primitive | Where (Cairo 2.18 corelib) | API | Local probe |
|---|---|---|---|
| **Poseidon** | `core::poseidon` | `poseidon_hash_span(Span<felt252>) -> felt252` (+ `hades_permutation`) | C2 commitment + C4 fold **[verified locally]** |
| **Pedersen** | `core::pedersen` | `pedersen(a: felt252, b: felt252) -> felt252` (builtin) | available (corelib) |
| **Stark-curve ECDSA** | `core::ecdsa` | `check_ecdsa_signature(msg_hash, pub_key, r, s) -> bool`; `recover_public_key(...)` | valid vector ✓, tamper ✗ **[verified locally]** |
| **SHA-256** | `core::sha256` | `compute_sha256_byte_array`, `compute_sha256_u32_array(Array<u32>, last_word, last_bytes) -> [u32;8]` | exact digest match **[verified locally]** |
| **Keccak-256** | `core::keccak` | (builtin-backed) | available (corelib) |
| **EC over Stark curve** | `core::ec` | `EcPointTrait::new/new_nz/mul/coordinates`, `EcPoint + EcPoint`, `stark_curve::{ALPHA,BETA,ORDER,GEN_X,GEN_Y}` | ElGamal homomorphism **[verified locally]** |
| **384-bit modular arithmetic** | `core::circuit` | `AddMod`/`MulMod` builtins, `u384` (4×`u96`), `circuit_add/sub/mul/inverse`, `CircuitModulus` | one modmul evaluates **[verified locally]** |
| Merkle membership | **no corelib helper** | hand-rolled Poseidon fold | `merkle_root` (C4) **[verified locally]** |

**The STARK curve** (`core::ec::stark_curve`): `y² ≡ x³ + α·x + β (mod p)` with `α = 1`,
`β = 0x6f21…e89`, group **`ORDER = 0x800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f`**,
generator `(GEN_X, GEN_Y)`. **This is the single most important fact for STRK20 fit:** it is the
curve Cairo's **native ECDSA** signs over *and* the curve **Tongo/SHE** build their ElGamal +
Sigma proofs over. The fiscal-attestation primitive and the confidential-payment primitive share
a curve — no cross-curve embedding (contrast Noir's BN254-circuit/Grumpkin-signature split, or
Mina's Pallas).

**Findings worth carrying forward:**

- **Poseidon, Pedersen, SHA-256, Keccak, Stark-ECDSA are all corelib-native** — no external git-tag
  libraries to pin (the Noir recon's main fragility). This is Cairo's biggest ergonomic win.
- **No stdlib Merkle gadget** — fold a fixed-depth Poseidon path by hand (done; identical idiom to
  the Aleo/Noir skeletons). Root **anchored by C1** so the prover can't substitute a self-built tree.
- **`core::circuit`** is the emulated-modular-arithmetic builtin (StarkWare-made) that **Garaga**
  uses for all its EC/pairing work; it is the substrate any RSA-2048 verifier would be built on (§D).

---

## TASK C — STRK20 / Tongo / SHE fit (THE critical question)

### C.1 NET ANSWER: **YES — a fiscalization-compliance proof layer over STRK20 confidential payments is feasible, and architecturally the cleanest of any stack we've evaluated.**

PRIVA-FISC is **not** a competitor to STRK20; it is a **compliance predicate that composes with
it**. STRK20 hides *how much* and *between whom*; PRIVA-FISC proves *that the hidden amount was
correctly taxed and authority-attested*. They share a curve, a language (Cairo), a prover
(Starknet's), and — crucially — a **compliance philosophy** (selective disclosure to authorities),
which is exactly the gap the rest of this section maps.

### C.2 What STRK20 / Tongo / SHE actually are (sourced)

- **STRK20** — Starknet's privacy framework for ERC-20, **announced 2026-03-10**. Shielded
  balances + private transfers for *any* ERC-20, with **built-in compliance** (selective
  disclosure to regulators/auditors, an audit trail). *"Every private transaction is backed by a
  zero-knowledge proof generated client-side and verified at the sequencer level … all logic is
  written in Cairo."* First shipped in **strkBTC** (shielded BTC on Starknet, earlier in 2026).
  ([Starknet blog](https://www.starknet.io/blog/make-all-erc-20-tokens-private-with-strk20/),
  [crypto.news](https://crypto.news/starknet-privacy-tech-erc20-compliance-2026/))
- **Tongo** ([`fatlabsxyz/tongo`](https://github.com/fatlabsxyz/tongo), by Fat Labs / Fat
  Solutions) — *"a prototype for a confidential payment system based on the Starknet blockchain."*
  Wraps any ERC-20 with **ElGamal encryption over the Stark curve**; **additively homomorphic**
  (on-chain balance updates **without decryption**); **no trusted ceremony** (security rests on
  the **discrete-log assumption over the Stark curve**); reported **~120K Cairo steps per
  transfer**; **audited by zkSecurity**. ([docs.tongo.cash](https://docs.tongo.cash/))
- **SHE — "Starknet Homomorphic Encryption"** ([`fatlabsxyz/she`](https://github.com/fatlabsxyz/she))
  — the low-level library Tongo proves with: *"low-level cryptographic primitives for proving and
  verification of **Sigma protocols over the Stark elliptic curve**, including ZK proof of ElGamal
  encryption."* TypeScript (prover-side) **+ Cairo (on-chain verifier)**. Audited by zkSecurity.
- **KAGE** ([`keep-starknet-strange/kage`](https://github.com/keep-starknet-strange/kage)) — a
  React-Native wallet using the Tongo SDK (the `keep-starknet-strange` org is StarkWare's
  exploration arm — a signal of first-party backing).

### C.3 The SHE Sigma-protocol toolbox (the building blocks PRIVA-FISC would use)

SHE exposes these Sigma protocols, each with `verify(statement, commitment, challenge, response)`
and a Fiat-Shamir `verify_with_prefix` (`c = Hash(prefix, A)`, which **binds external data** into
the challenge — directly useful for binding a fiscal commitment into a payment proof):

| SHE protocol | Statement proven | PRIVA-FISC use |
|---|---|---|
| **POE** | knowledge of a discrete-log exponent (Schnorr-like) | prove control of a key / opening |
| **POE2 / POEN** | equality of 2 / N exponents (DLEQ) | **bind** the receipt-committed amount to the Tongo ciphertext (same value under two encodings) |
| **Bit** | a committed value ∈ {0,1} | build OR-proofs (e.g. statutory-rate disjunction) |
| **Range** | a committed value ∈ [0, 2ⁿ) | **C3 range checks** on encrypted monetary fields |
| **ElGamal** | a ciphertext is a correct ElGamal encryption | well-formedness of the payment amount |
| **SameEncryption** | two ElGamal ciphertexts encrypt the **same** value | **C3 consistency** `Enc(total) = Enc(vat_base) ⊕ Enc(vat_amount)` |

### C.4 How PRIVA-FISC sits on top — the architecture

```
   Tongo confidential transfer (STRK20)                 PRIVA-FISC compliance predicate
   ────────────────────────────────────                ───────────────────────────────────
   amount  →  ElGamal ct = (r·G, m·G + r·H)   ──bind──►  C2: receipt commitment C (Poseidon)
   over the Stark curve, additively homom.    (POE2/     C3: VAT correct on the SAME amount
   SHE proves: well-formed, sender solvent     Same-          - total = vat_base + vat_amount
   (Range), balances update homomorphically    Encryption)      checked ON the ciphertexts
                                                              - lawful statutory rate
   viewing key registered on-chain  ──────────────────►  C1: authority attestation (Stark ECDSA)
   auditor can decrypt one user's key & trace            C4: seller ∈ registry (Poseidon Merkle)
   (STRK20 native selective disclosure)                  C5: D (Phase-5: SHA-256 in-circuit)
```

Three load-bearing facts make this clean:

1. **VAT arithmetic runs on the ciphertexts (homomorphism).** Because ElGamal here is
   **additively homomorphic**, `Enc(vat_base) ⊕ Enc(vat_amount)` *is* an encryption of
   `vat_base + vat_amount`. Proving `total = vat_base + vat_amount` reduces to a **SHE
   SameEncryption** proof between that homomorphic sum and `Enc(total)` — no decryption, no
   amount revealed. **[verified locally]** that the homomorphism holds over the Stark curve
   (`test_strk20_elgamal_additive_homomorphism`). Range bounds (C3) come from **SHE Range**.
2. **Same curve ⇒ the fiscal attestation composes natively.** C1's authority signature is
   **Stark-curve ECDSA** (corelib) — the same curve SHE works over — so the attestation, the
   commitment (Poseidon), and the payment proof live in one algebraic world. No embedded-curve
   gymnastics.
3. **The disclosure channel already exists.** STRK20 registers an **encrypted viewing key**
   on-chain; a **designated auditor** can decrypt a specific user's key and trace their history.
   That is *precisely* SPEC §12's threshold-audit / §5.1's selective-reveal requirement. **The tax
   authority = STRK20's designated auditor.**

### C.5 Viewing-key model **or** separate ZK predicate? → **BOTH, layered**

The task asks which. The honest answer is that they are **complementary, not alternatives**:

- **STRK20 viewing keys = the *reactive* disclosure channel.** *After the fact*, on a lawful
  request, the authority decrypts a user's key and sees amounts/parties. This is identity/amount
  *recovery* — it answers "who, how much" on demand. It does **not** prove correctness.
- **PRIVA-FISC predicate = the *proactive* correctness guarantee.** *At issue time*, a Cairo proof
  asserts the (still-hidden) amount was taxed correctly, by a registered seller, under an authority
  attestation — **without any disclosure**. It answers "was this taxed correctly" **always**.

A real deployment wants both: the predicate gives continuous, privacy-preserving compliance; the
viewing key gives the auditor a break-glass path for investigations. PRIVA-FISC therefore **reuses**
STRK20's viewing-key layer (no need to reinvent threshold disclosure) and **adds** the fiscal
predicate STRK20 does not have.

### C.6 The rate-privacy design fork (the one real subtlety)

v0-A keeps `vat_rate` **private** (statutory-set; SPEC §5.3/§11.5). On encrypted values this
splits into two cases:

- **If the rate is public** (e.g. revealed per receipt): `vat_amount = vat_base·rate/10000` is a
  **linear** relation with a public coefficient → provable by homomorphic scalar-multiplication +
  **SameEncryption**. **Trivial.**
- **If the rate stays private** (v0-A default): `vat_base·rate` is a product of two secrets →
  prove an **OR over {0%, 7%, 21%}** (compose SHE **Bit**/**Range** into a 3-branch disjunction,
  each branch a linear relation), **or** drop the multiplicative check into a small **Cairo
  arithmetic proof** over the witnessed values and bind them to the ciphertext with a **POE2/DLEQ**.
  **Feasible, more engineering.** This is the principal design decision for the STRK20 variant.

### C.7 Honest boundary / caveats

- **Tongo/SHE are research-grade ("prototype")** as of recon, though **zkSecurity-audited** and
  KAGE-integrated. STRK20's *wallet API + SDK* were announced as open-sourcing **"in the next
  phase"** — confirm the public surface, license, and production-readiness before building on it.
- **The homomorphic-VAT design is sketched, not built.** The local probe proves the *homomorphism*
  and the *curve ops*; wiring SHE's `SameEncryption`/`Range`/`POE2` into a VAT predicate is the
  actual port work.
- **Amount domain.** ElGamal-over-EC encodes `m` as `m·G`; recovering `m` needs a bounded
  discrete-log (baby-step/giant-step), so monetary values must stay within a **bounded range** —
  already required by C3, and aligned with how Tongo bounds transfer amounts.

---

## TASK D — Phase-5 status in Cairo (RSA-2048 + SHA-256)

### D.1 SHA-256 — **NATIVE, verified, but not cheap**

`core::sha256` is in the corelib and builtin-backed. The probe computes `SHA-256("hello")`
in-program and matches the known digest exactly **[verified locally]**. **This closes the v0-A
opaque-`D` limit (C5 → v0-B) in-circuit** — Cairo can recompute `D = SHA-256(canonical(P))` from
the private fields, exactly the capability Mina/Aleo lack. Cost signal: a **5-byte** message cost
**≈ 869,915** `snforge` sierra-gas in the skeleton — i.e. SHA-256 is *available* but is the heaviest
single primitive measured; a real (longer) EFI payload scales up. Budget for it in Phase-5.

### D.2 RSA-2048 — **substrate present, verifier library absent**

- **No off-the-shelf Cairo RSA-PKCS#1 v1.5 verifier library** surfaced in recon (checked the
  corelib, **Garaga**, and **Alexandria**). This is the one place Noir is ahead: Noir has the
  production `zkpassport/noir_rsa`; Cairo (as of recon) does not have an equivalent.
- **But the substrate is strong and proven.** `core::circuit`'s `AddMod`/`MulMod` builtins do
  384-bit modular arithmetic (`u384` = 4×`u96`); a single `a·b mod n` **evaluates [verified
  locally]** (`test_phase5_modmul_builtin`, ≈31,788 sierra-gas). **RSA-2048 verify = modexp =
  square-and-multiply over a 2048-bit modulus assembled from limbs** — built on exactly these
  builtins, which is the same machinery **Garaga** uses for its EC/pairing circuits at production
  scale. So RSA-2048 in Cairo is **build/port work on a de-risked native primitive**, not blocked
  R&D.
- **MD5 (IKOF)** — not ZK-friendly, no Cairo library — the same Phase-5 protocol boundary as every
  other stack (SPEC §13).

### D.3 Cross-stack Phase-5 verdict

| Stack | SHA-256 in-circuit | RSA-2048 verify | Net Phase-5 position |
|---|---|---|---|
| **Mina (o1js)** | ✗ not available | ✗ | hardest — both primitives are R&D |
| **Aleo (Leo)** | ✗ (has Keccak/SHA-3, not SHA-2) | ✗ | hardest — no SHA-256 |
| **Noir** | ✅ `sha256` lib | ✅ **turnkey** (`zkpassport/noir_rsa`, benchmarked) | **easiest — solved + benchmarked** |
| **Cairo** | ✅ **native corelib** | ⚠️ **substrate native** (`core::circuit`), **no library yet** | **middle — SHA-256 done, RSA buildable** |

> **Net:** for *Phase-5 crypto feasibility*, Cairo is second only to Noir, and well ahead of
> Mina/Aleo. The unique Cairo trade-off: you give up Noir's turnkey RSA library, but you gain a
> **native prover with no trusted setup and on-chain verification** — and, via STRK20, a
> **same-curve confidential-payment substrate** that the others don't have at all.

---

## TASK E — v0-A constraint map (C1–C5 → Cairo)

From [`../spec/SPEC.md`](../spec/SPEC.md) §7, mirroring [`../src/circuit.ts`](../src/circuit.ts),
[`../leo/src/main.leo`](../leo/src/main.leo), and [`../noir/v0a_skeleton`](../noir/v0a_skeleton/).
All compile-verified in [`../cairo/`](../cairo/) (10/10 `snforge` tests pass). Verdicts use the
Aleo/Noir recon vocabulary: **KOLAY** (easy/native) · **ZOR** (hard) · **FARKLI** (different).

| SPEC | Cairo realization | Primitive | Verdict |
|---|---|---|---|
| **C1** attestation + anti-replay | `m = poseidon_hash_span([DS_ATTEST, d_hi, d_lo, c, root, datetime, invoice])`; `check_ecdsa_signature(m, pk_a, r, s)` | **Stark-curve ECDSA** (`core::ecdsa`, **native**) | **KOLAY** — *FARKLI/aligned signer model:* `PK_A` is a **felt252 Stark-curve pubkey x-coord** — and it is the **same curve STRK20/Tongo/SHE sign over**, so the attestation composes with the confidential-payment proof. Valid sig ✓ / tamper ✗ **[verified locally]**. **Phase-5 swap:** ECDSA → RSA-2048+SHA-256 built on `core::circuit` + `core::sha256` (§D). |
| **C2** salted commitment | `c = poseidon_hash_span([DS_COMMIT, seller_tin, buyer_id, items_hash, margin, vat_base, vat_amount, rate_bp, total, salt])` | **Poseidon** (`core::poseidon`, **native default**) | **KOLAY** — Poseidon is Cairo's *native* hash (no library to pin, unlike Noir). `C` is **Stark-field-specific** (SPEC §12) — *FARKLI field*, as everywhere. **[verified locally]** |
| **C3** bounded-int VAT | native `u64`→`u128` promote: `vat_amount == vat_base·rate_bp/10000` (one rounding rule), `rate_bp ∈ {0,700,2100}`, `total == vat_base + vat_amount`, range `< 2^52` | native **`u64`/`u128`** | **KOLAY** — overflow-checked integers; `2^52·2100 < 2^64` ⇒ no wrap. **STRK20 bonus:** the *same* relation is expressible **on Tongo ciphertexts** via SHE homomorphism + SameEncryption (§C). Valid ✓ / wrong-amount ✗ / illegal-rate ✗ **[verified locally]**. |
| **C4** anchored Merkle membership | `leaf = poseidon_hash_span([DS_LEAF, seller_tin])`; `merkle_root(leaf, siblings, path_bits) == r_reg` | hand-rolled **Poseidon fold** | **FARKLI** — no corelib Merkle gadget; fixed-depth fold (same idiom as Aleo/Noir). Root **anchored by C1** (`root ∈ m`). `seller_tin` stays private (§5.1). Deterministic + leaf-sensitive **[verified locally]**. |
| **C5** opaque `D` (Phase-5 marker) | `d_hi, d_lo` are public felt limbs entering **only** `m`; not recomputed in-circuit (skeleton) | (public `felt252` limbs) | **KOLAY now — and CLOSABLE.** Like Noir (and unlike Mina/Aleo), Cairo's **native `core::sha256`** can later recompute `D = SHA-256(canonical(P))` in-circuit (v0-B), removing the attester-trust on `D↔fields`. In-circuit SHA-256 already exercised **[verified locally]** (§D). |

---

## TASK F — Minimal skeleton (verified locally)

One Scarb package, [`../cairo/`](../cairo/), compiling on Scarb 2.18.0 and passing **10/10**
`snforge` tests. Synthetic data only (no real key/PII).

| File | What |
|---|---|
| [`cairo/src/lib.cairo`](../cairo/src/lib.cairo) | the v0-A relation **C1–C5** (`verify_v0a`) + Phase-5 probes (`sha256_probe`, `modmul_u384`) + the **STRK20 substrate probe** (`elgamal_enc`/`elgamal_add`/`ec_eq`) |
| [`cairo/tests/recon_test.cairo`](../cairo/tests/recon_test.cairo) | 10 `snforge` tests exercising every primitive |

**`snforge test` result [verified locally] — 10 passed, 0 failed:**

| Test | Proves | `l2_gas` (sierra-gas) |
|---|---|---|
| `test_c1_ecdsa_valid_signature_verifies` | C1: Stark-ECDSA valid ✓ / tampered ✗ | ~72,490 |
| `test_c2_commitment_runs_and_is_deterministic` | C2: Poseidon commitment | ~61,632 |
| `test_c3_vat_ok` | C3: valid VAT accepted | ~19,150 |
| `test_c3_vat_rejects_wrong_amount` | C3: off-by-one cent rejected | ~19,050 |
| `test_c3_vat_rejects_nonstatutory_rate` | C3: 10% rate rejected | ~13,840 |
| `test_c4_merkle_fold_roundtrip` | C4: Poseidon fold deterministic + leaf-sensitive | ~108,126 |
| `test_v0a_relation_wires_and_runs` | C1–C4 wired end-to-end (relation executes) | ~183,451 |
| `test_phase5_sha256_native` | Phase-5: in-circuit SHA-256 = exact digest | ~869,915 |
| `test_phase5_modmul_builtin` | Phase-5: `core::circuit` modmul (RSA substrate) | ~31,788 |
| `test_strk20_elgamal_additive_homomorphism` | **STRK20: ElGamal additive homomorphism over Stark curve** | ~136,690 |

> **Honesty boundary (mirrors the Noir recon).** `test_v0a_relation_wires_and_runs` asserts the
> relation *executes* and that C2/C3/C4 hold; C1 returns `false` because the synthetic signature is
> over the corelib test vector's message, **not** over our Poseidon `m`. A *green C1 over `m`*
> needs an off-chain Stark-curve signer (a trivial port task), so we assert the wiring rather than
> forge a signature. The standalone `test_c1_ecdsa_valid_signature_verifies` proves the ECDSA
> primitive itself runs green on a valid vector. The STRK20 and Phase-5 probes are **fully green**.

---

## Open questions / caveats (verify before acting)

1. **Corelib-native, version-pinned.** Unlike Noir, the primitives are corelib (`core::*`) — no
   external git-tag libraries for hash/sig/SHA-256 (a real ergonomic win). Still pin Scarb/Cairo
   versions; `core::circuit` and `core::sha256` APIs have evolved across Cairo releases.
2. **STRK20/Tongo/SHE are prototype-grade but audited.** `fatlabsxyz/{tongo,she}` are public and
   zkSecurity-audited; the STRK20 *wallet API/SDK* were announced as open-sourcing "next phase."
   Re-verify the public surface, license, and maturity before depending on them.
3. **The homomorphic-VAT predicate is designed, not built.** Local probes prove the homomorphism
   and the curve/modular/hash primitives; wiring SHE `SameEncryption`/`Range`/`POE2` into a VAT
   predicate over a Tongo ciphertext is the port deliverable. The **rate-privacy fork (§C.6)** is
   the key design decision.
4. **RSA-2048 has no Cairo verifier library yet.** Plan to build/port one on `core::circuit`
   (or extend Garaga). SHA-256 is native but **heavy** (§D.1) — budget Phase-5 cost accordingly.
5. **Cost numbers are `snforge` sierra-gas estimates**, not proving times, and are arg/version
   dependent. Magnitudes (SHA-256 ≫ Merkle > ECDSA ≈ Poseidon > modmul) are the signal; re-measure
   on the real prover before committing to a design.
6. **MD5/IKOF and canonical-EFI byte construction remain the real Phase-5 work** (SPEC §13) — the
   same protocol-fidelity boundary as every stack; not a Cairo-specific blocker.

## Primary sources

- **Toolchain:** [Scarb](https://docs.swmansion.com/scarb/) · [Starknet Foundry](https://foundry-rs.github.io/starknet-foundry/) · [Cairo Book — Installation](https://www.starknet.io/cairo-book/ch01-01-installation.html) · [`starkup`](https://github.com/software-mansion/starkup)
- **Primitives:** [Cairo Corelib docs](https://docs.cairo-lang.org/core/) · [Starknet Corelib intro](https://docs.starknet.io/build/corelib/intro) · [`core::ecdsa`/ECDSA-by-example](https://starknet-by-example.voyager.online/advanced-concepts/signature_verification/) · [Arithmetic Circuits (`core::circuit`)](https://www.starknet.io/cairo-book/ch12-10-arithmetic-circuits.html) · [`starkware-libs/cairo` corelib source](https://github.com/starkware-libs/cairo/tree/main/corelib/src)
- **STRK20 / confidential payments:** [Starknet blog — STRK20](https://www.starknet.io/blog/make-all-erc-20-tokens-private-with-strk20/) · [crypto.news — STRK20 compliance](https://crypto.news/starknet-privacy-tech-erc20-compliance-2026/) · [The Block — STRK20](https://www.theblock.co/post/392974/starknet-to-deploy-strk20-framework-enabling-privacy-focused-stablecoins-and-other-assets) · [The Defiant — STRK20](https://thedefiant.io/news/blockchains/starknet-strk20-privacy-layer-shielded-erc20-balances-transfers)
- **Tongo / SHE (the SDK + crypto):** [`fatlabsxyz/tongo`](https://github.com/fatlabsxyz/tongo) · [`fatlabsxyz/she`](https://github.com/fatlabsxyz/she) · [docs.tongo.cash](https://docs.tongo.cash/) · [Fat Solutions](https://fatsolutions.xyz/) · [`keep-starknet-strange/kage` (wallet)](https://github.com/keep-starknet-strange/kage)
- **Phase-5 substrate:** [`keep-starknet-strange/garaga`](https://github.com/keep-starknet-strange/garaga) · [`keep-starknet-strange/alexandria`](https://github.com/keep-starknet-strange/alexandria) · [`core::sha256` source](https://github.com/starkware-libs/cairo/blob/main/corelib/src/sha256.cairo)

---
*Recon only. No full port written, nothing deployed; repo additions limited to
[`../cairo/`](../cairo/) (one Scarb package, 10 green `snforge` tests) and this file. Next step (if
approved): a scoped v0-A→Cairo implementation plan, with the **STRK20/Tongo compliance-predicate**
as the differentiator — VAT-on-ciphertext via SHE, the tax authority as STRK20's designated
auditor, and Phase-5 SHA-256 already de-risked (native) with RSA-2048 as the remaining build.*
