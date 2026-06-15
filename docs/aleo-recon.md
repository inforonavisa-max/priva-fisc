# Aleo / Leo Reconnaissance — for a v0-A Port Decision

> **Status:** RECON ONLY (2026-06-15). No Leo program was written (beyond a trivial
> compile test), nothing was deployed to Aleo, no real data touched, and the Mina/o1js
> `src/` was not modified. Toolchain installed to a scratch dir (`/tmp/aleo-leo-recon`),
> repo left clean. Every external claim is sourced; toolchain facts marked **[verified
> locally]** were run on this machine.
>
> **Question this answers:** if/when we port the v0-A relation (`spec/SPEC.md`,
> `src/circuit.ts`) from Mina/o1js to Aleo/Leo, how cleanly does each circuit primitive
> map — and specifically, does Leo give us **native Poseidon** and **native signature
> verification**? (Short answer: **yes to both.**)

---

## 0. Headline

| Question | Answer |
|---|---|
| Native Poseidon hash in Leo? | **YES** — `Poseidon2/4/8::hash_to_field/group/scalar/...`, compiles to AVM `hash.psd2/4/8`. |
| Native signature verify in Leo? | **YES** — `signature::verify(sig, addr, msg)` → `bool` (Schnorr over Edwards-BLS12-377), AVM `sign.verify`. **Caveat:** the signer is an Aleo **`address`**, not an arbitrary external public key. |
| Native Merkle gadget? | **NO** — hand-rolled Poseidon path-fold (official examples: zPass, Sealance). |
| Native Poseidon **commitment**? | **NO** — Poseidon is hash-only. Native `commit.*` exists only for **BHP/Pedersen**. v0-A's commitment is already a *Poseidon hash with `salt` in the preimage*, which maps natively as a hash. |
| Does v0-A map cleanly? | **Mostly yes.** The two pillars (Poseidon, Schnorr verify) are native. Frictions: signer = Aleo address (not arbitrary `PK_A`); Merkle is hand-rolled; `C` is stack-specific (different field/params); SHA-256 (Phase-5) is still not native. |

---

## TASK A — Grant Reconnaissance

### A.1 Program & administrator

- The current, active program is the **Aleo Network Foundation (ANF) Developer Grants
  Program**, at **https://aleo.org/grants/**. ANF is an independent non-profit (501(c)(4),
  Wyoming), announced 2023-12-20, operating independently from the commercial Aleo entity.
  [aleo.org/grants](https://aleo.org/grants/) · [ANF announcement](https://aleo.org/post/announcing-aleo-network-foundation/)
- Headline terms: **up to $100K per project**, **milestone-based** payout, **open-source
  required**, open to **teams and solo devs**. Advertised totals: **"$1M+ deployed", "50+
  projects funded"**. Use-case focus areas: **Payments, Identity, Gaming, DeFi**.
- Two earlier/specialized tracks exist as context (not the main funnel today): the
  **Tooling & Infrastructure Grants Program** ($1M, 2023-05-22) and a **Community Grants
  Program**. The canonical "apply here" entry point today is `aleo.org/grants/`.

### A.2 What the application actually asks

The four-step flow: **Submit Application → Review & Decision (initial feedback within ~1
week) → Build with Support (milestone funding + mentorship) → Launch & Scale (mainnet).**

The live submission is an **Asana form** linked from every "Apply for Funding" / "Apply
now" button:
`https://form.asana.com/?k=sCm0WT9M-V_fHl8AA48czQ&d=1199198487809755`
(off the allowed-host list / gated, so the raw input widgets could not be inspected
directly). The official pages document the **required components** rather than a verbatim
field schema:

| Required component (quoted/paraphrased from aleo.org) | Notes |
|---|---|
| **Project overview** | "project details" — what it is, the problem it solves |
| **Team background** | "information on your team background" / bios |
| **Grant proposal** | written from the **"Launch Grants Proposal Template"** (a Google Doc) |
| → **Development roadmap / timeline** | applicant-defined |
| → **Milestones** | payout is per-milestone |
| → **Amount of funding required** | applicant self-determines (≤ $100K) |
| **Open-source confirmation** | project "must contain open-source elements built on Aleo" |
| **Scope-area selection** | Payments / Identity / Gaming / DeFi |

> Source: [aleo.org/grants](https://aleo.org/grants/). Exact field labels live behind the
> Asana form; the above is the authoritative requirement set from the public pages.

### A.3 RFPs / Blueprints — and our fit

- **There is no discrete numbered RFP/Blueprint catalogue.** Aleo funds against the four
  **scope areas**, not a posted RFP list.
- The only explicitly named blueprint-RFP is the **"Proof of Useful Work Blueprint Grant"**
  (a Leo computational-bounty program) — **not** payments/compliance themed.
  [source](https://aleo.org/post/aleo-grants-solve-meaningful-world-problems-with-zero-knowledge/)
- "Blueprints" otherwise = ANF **in-house reference products** for the community, starting
  with **zPass** (privacy-preserving identity / selective attribute disclosure).
  [ANF announcement](https://aleo.org/post/announcing-aleo-network-foundation/) · [zPass](https://aleo.org/post/introducing-zpass-aleos-pioneering-step-toward-privacy-preserving-digital/)

**Does a payment/compliance/identity RFP fit PRIVA-FISC?** There is no tax/VAT/fiscal-titled
RFP, but the **theme fit is strong at the scope-area level**:

| Track / artifact | Why it fits a privacy-preserving fiscal-receipt ZK proof |
|---|---|
| **Payments** scope | Explicitly framed as "privacy **and** compliance… safeguards user data while meeting regulations" — the closest standing track for VAT/authority-attestation. |
| **DeFi** scope | "private-by-default… while ensuring user privacy and regulatory compliance." |
| **Identity** scope + **zPass** | Selective-disclosure / credential-membership — maps onto registered-seller membership (C4) and authority attestation (C1). |
| **ViewKey + ARC-0100** (ANF US-Treasury RFC response) | "selective disclosure tools for compliance" + "Compliance Best Practices" — directly the disclosure/attestation primitive. [Treasury RFC response](https://aleo.org/post/aleo-response-treasury-rfc-illicit-activity-digital-assets/) |

→ **Recommendation:** submit under **Payments** (primary) with the **selective-disclosure /
compliance** framing; cite zPass/ViewKey as the precedent. There is no dedicated fiscal RFP
to apply against.

### A.4 OSS requirement + funding tiers (exact text)

**OSS — differs by program:**

- **Developer Grants (the program we'd use):** *"Projects for all developer grants must
  contain open-source elements that are built on the Aleo network."* — **No specific license
  named, no Apache-2.0 mandate, and the public page does not state the repo must be public on
  GitHub.** [aleo.org/grants](https://aleo.org/grants/)
- **Tooling & Infrastructure program (stricter):** a post-acceptance step is *"Set up a
  GitHub repo and ensure it's open-source and uses the **Apache 2** license."* — this is the
  **only** Aleo program where Apache-2.0 is explicitly required, and it mandates the
  grantee's **own** GitHub repo (not a ProvableHQ/AleoNet org repo).
  [Tooling & Infra announcement](https://aleo.org/post/announcing-the-aleo-tooling-and-infrastructure-grants-program/)
- **No** accessible official source requires the code to live in a ProvableHQ/AleoNet org repo.

> **Practical read:** our existing **Apache-2.0 + public GitHub** posture (this repo)
> already satisfies the strictest Aleo requirement. For Developer Grants it more than
> suffices; for Tooling & Infra it is exactly the mandated form.

**Funding tiers:**

- Officially, the only stated numbers are **"up to $100K" per grant**, **applicant-defined
  amount/milestones**, **milestone-based payout**, **$1M+ deployed / 50+ funded**.
- ⚠️ The frequently-cited **micro $1K–$5K / small $5K–$25K / medium $25K–$100K / large
  $100K+** tier table appears **only in third-party Medium articles, NOT on any official
  Aleo source** — treat as **unverified**. Official sources state only the self-determined
  amount and the $100K ceiling.

---

## TASK B — Leo / Aleo Toolchain (verified)

### B.1 Versions (June 2026)

| Component | Version | Source |
|---|---|---|
| **Leo CLI** | **`leo-lang-v4.2.0`** (2026-06-04) | [releases](https://github.com/ProvableHQ/leo/releases/latest) — **[verified locally]** |
| **snarkVM** (bundled) | **`4.7.3`** (consensus V15) | Leo 4.2.0 release notes |
| **Aleo SDK** `@provablehq/sdk` | **`v0.11.1`** (2026-06-10) | [sdk releases](https://github.com/ProvableHQ/sdk/releases/latest) |
| **snarkOS** (node) | **`v4.7.4`** (~2026-06-03) | [snarkOS releases](https://github.com/ProvableHQ/snarkOS/releases) |

**Install (official):** `cargo install leo-lang leo-fmt leo-lsp` (needs Rust), or
`cargo binstall …`, or **prebuilt ZIP** from GitHub Releases; verify with `leo --version`.
[installation docs](https://docs.leo-lang.org/getting_started/installation)

### B.2 Local verification — toolchain works **[verified locally]**

Rust/cargo was **not** present; rather than a long source build, the **prebuilt arm64
binary** was used (`leo-lang-v4.2.0-aarch64-apple-darwin.zip`) on macOS 26.5 / arm64:

```
$ leo --version
leo 4.2.0 (ff8a86e HEAD) features=[noconfig]

$ leo new hello   →   $ leo build
   Leo ✅ Compiled 'hello.aleo' into Aleo instructions.

$ leo run main 1u32 2u32
   ➡️  Output
    • 3u32
```

Notes worth carrying forward:
- v4.2.0's default template uses **`fn main(public a: u32, b: u32)`** (the `transition`
  keyword is the older spelling) and ships an upgradability **`constructor()` with
  `@noupgrade`**.
- `leo build`/`run` default to **network `testnet`**, endpoint
  **`https://api.explorer.provable.com/v1`**.
- CLI surface present: `account · new · run · execute · test · deploy · devnet · query ·
  build · add/remove · synthesize · update · upgrade`.

### B.3 Testnet deploy notes (NOTE-ONLY — nothing deployed)

| Item | Value | Source |
|---|---|---|
| Mainnet | **Live** since 2024-09-18 (network id **0**) | [mainnet announce](https://aleo.org/post/announcing-aleo-mainnet/) |
| Current testnet | **"Testnet Beta"** (network id **1**, name `testnet`) | [environments](https://aleo.org/post/devnet-mainnet-aleos-testing-environments/) |
| Bleeding-edge net | **CanaryNet** (network id **2**, `canary`) | [devnet docs](https://docs.leo-lang.org/testing/devnet) |
| Faucet | **https://faucet.aleo.org/** (enter Aleo address; Leo Wallet → switch to "Aleo Testnet" first) | [faucet](https://faucet.aleo.org/) |
| Explorers | **testnet.aleoscan.io**, **testnet.aleo123.io**, **testnet.explorer.provable.com** | [aleoscan](https://testnet.aleoscan.io/) |
| Deploy flow | `leo deploy --broadcast` with a `.env` (`NETWORK=testnet`, `PRIVATE_KEY=APrivateKey1z…`, `ENDPOINT=https://api.explorer.provable.com/v1`); `--network`/`--endpoint` override | [deploy guide](https://docs.leo-lang.org/guides/deploy) |
| Sample deploy cost | **2.67705 credits** (storage 0.879 + synthesis 0.748 + **namespace 1.000 fixed** + constructor 0.05) | [deploy guide](https://docs.leo-lang.org/guides/deploy) |
| Low-level alt | `snarkos developer deploy <prog>.aleo --private-key … --query … --broadcast …/<network>/transaction/broadcast --priority-fee <microcredits>` | [snarkOS](https://github.com/ProvableHQ/snarkOS) |

> Analogy to the Mina path we already ran: faucet + explorer + a one-command deploy exist
> exactly like Devnet; the equivalent of our `devnet-deploy.ts` would be `leo deploy
> --broadcast` against Testnet Beta. **Deferred — not done here.**

---

## TASK C — Circuit Primitive Mapping (the critical part)

### C.0 v0-A primitive inventory (from our source, not memory)

| v0-A primitive | o1js realization (verified in repo) |
|---|---|
| Poseidon hash | `Poseidon.hash([Field,…])` over **Pallas** — string-encoding, `itemsCommit`, `C`, `leaf`, `M`; DS-tagged ([commitments.ts](../src/commitments.ts), [encoding.ts](../src/encoding.ts)) |
| Signature verify (C1) | o1js native `Signature` (Schnorr/Pallas, Poseidon): `sig.verify(PK_A, [M]).assertTrue()`; **`PK_A` = arbitrary `PublicKey`** ([circuit.ts:105](../src/circuit.ts)) |
| Merkle membership (C4) | o1js `MerkleWitness(8)` `.calculateRoot(leaf)` (Poseidon tree) ([merkle.ts](../src/merkle.ts)) |
| Field arith + range (C3) | `Field` over Pallas; `assertLessThanOrEqual(2^52-1)`; VAT via field mul/add + remainder `r` ([circuit.ts:129-154](../src/circuit.ts)) |
| Public/private model | ZkProgram `publicInput = {PK_A, R_reg, D_hi, D_lo, C}`; private `FiscWitness + SellersWitness + Signature`; **C a constrained public input**, **D opaque** ([circuit.ts:46-105](../src/circuit.ts)) |

### C.1 Mapping table — KOLAY / ZOR / FARKLI

| Primitive | Verdict | Leo realization & note |
|---|---|---|
| **Poseidon hash** | **KOLAY** (native) — *FARKLI field* | `Poseidon2/4/8::hash_to_field(...)` → AVM `hash.psd2/4/8`; accepts any type incl. `struct`/array; DS-tag-prepend pattern works unchanged. **Different curve/field** (Edwards-BLS12-377 base field ≈ 2²⁵³ vs Pallas ≈ 2²⁵⁴) ⇒ hash values differ ⇒ `C` is **stack-specific** (already stated in SPEC §12). |
| **Poseidon *commitment* (C2)** | **FARKLI** | There is **no native Poseidon `commit`** — Poseidon is hash-only. But v0-A's `C` is *already a Poseidon **hash** with `salt` in the preimage*, so it maps directly to `Poseidon2::hash_to_field(preimage_incl_salt)`. If a formal hiding+binding **commit opcode** is preferred, `BHP*::commit_to_field` / `Pedersen*::commit_to_*` are native (take a **`scalar`** randomness). |
| **Signature verify (C1)** | **KOLAY** (native) — *FARKLI signer model* | `signature::verify(sig, addr, msg) -> bool` (Schnorr/Edwards-BLS12-377) → AVM `sign.verify`. v0-A signs a **single field** `M` ⇒ message shape maps cleanly. **Key delta:** the signer is an Aleo **`address`** (account-derived key), **not an arbitrary `PK_A`**. The authority must therefore hold an **Aleo account** (or `PK_A` be modeled as one). Resolves SPEC §11.1 (scheme) → **Schnorr, account-based.** |
| **Merkle membership (C4)** | **FARKLI** (no native gadget; standard pattern) | No stdlib Merkle. Reconstruct the root by folding the leaf with a **fixed-depth array of sibling fields via Poseidon**, then `assert_eq(root, public_root)`. Official precedents: **zPass** (Poseidon2, depth-8) and **Sealance** (Poseidon4, 16-sibling `MerkleProof` struct). More manual than o1js's `MerkleWitness` helper, but a well-trodden idiom; our height-8 tree maps directly. |
| **Field arith + int/range types (C3)** | **KOLAY / daha kolay** — *FARKLI (better)* | Leo has native **`u8…u128` / `i8…i128`** with **checked arithmetic by default** (halts on overflow) plus `_wrapped` variants; `field` supports `<,<=`. v0-A's manual `assertLessThanOrEqual(2^52-1)` becomes either an **integer type** (overflow auto-checked — VAT `base*rateBp` fits `u128`) or an explicit `lt`. Net: **easier/safer** than hand-rolled Field range checks. (Different field modulus, as above.) |
| **Public inputs + private state (C1–C4 wiring)** | **KOLAY** | `fn main(public PK…, public R_reg, public D_hi, public D_lo, public C, /*private:*/ witness…, sig)` — `public` inputs become the verified statement (≈ o1js `publicInput`), everything else is private by default. All of C1–C4 run in the **transition body**. Direct analogue of the ZkProgram. |
| **Opaque `D` public input (C5 limit)** | **KOLAY** | Pass `D` as **`public` field limb(s)**, never recomputed in-circuit — identical to v0-A's `D_hi/D_lo`. (A 256-bit SHA-256 digest still needs **two field limbs** in Aleo's ~253-bit field, same as Pallas.) |
| **Commitment `C` as constrained public input** | **KOLAY** | `public C: field` + `assert_eq(Poseidon2::hash_to_field(preimage), C)` — exact analogue of `commitCFields(w).assertEquals(pub.C)`. **Bonus:** publishing `C` on-chain is *more first-class* in Aleo — write it to a **`mapping`** inside a `final { }` block (public on-chain state), which o1js has no direct equivalent for. |

### C.2 Records vs mappings — the Aleo state model (and how C1–C4 fit)

- **Records** = private, owner-encrypted, off-chain state (must contain `owner: address`;
  fields default `private`). **Mappings** = public on-chain key→value state
  (`mapping name: key => value;`), mutated **only** inside a `final { }` block / `final fn`
  that validators run **after** the proof verifies.
  [private_state](https://docs.leo-lang.org/language/programs_in_practice/private_state) · [public_state](https://docs.leo-lang.org/language/programs_in_practice/public_state)
- For PRIVA-FISC we **don't need records** (no owned UTXO-style asset). The relation is a
  **pure proving statement**: one `transition` with `public` statement inputs
  (`PK_A`/authority address, `R_reg`, `D`, `C`) + `private` witnesses (seller id, amounts,
  `salt`, signature, Merkle path), all checked in the body. **Optionally**, publish `C`
  (and/or a future nullifier) into a **mapping** via `final { }` so the commitment lands as
  verifiable on-chain state — a clean home for SPEC §11.6 / §12's nullifier idea.

### C.3 What stays HARD in Leo too (Phase-5 honesty)

- **SHA-256 (the real `D`, v0-B/§7-C5):** Leo's native hashes are BHP, Pedersen, Poseidon,
  **Keccak**, and **SHA3** — **not SHA-2/SHA-256**. So in-circuit SHA-256 is **as
  non-native in Leo as in o1js**; it needs a gadget. (Keccak256/SHA3-256 are native, but
  those are different functions from Montenegro's SHA-256.)
- **RSA-2048 + MD5 + XML-C14N (Phase-5):** non-native big-integer / byte work — equally
  heavy in Leo. The SPEC §10 feasibility caveat carries over unchanged.

→ The **maturity ladder is identical**: v0-A maps cleanly; the hard cryptographic
engineering (SHA-256, RSA, MD5, canonicalization) remains the Phase-5 prize on either stack.

---

## Open questions / caveats (verify before acting)

1. **Authority key = Aleo address.** Native `sign.verify` binds to an Aleo `address`. If the
   "authority" must use an externally-defined key, that's a design change (model the
   authority as an Aleo account, or build a non-native verify). **Highest-impact delta.**
2. **Funding tiers** beyond "up to $100K" are unverified (only third-party blogs). The
   official terms (exact license clause, payout currency USD vs credits/tokens) live in the
   **signed grant letter / Asana form**, which were not accessible.
3. **`final` vs `async` syntax.** Current docs (v4.2.0) use `final { }` / `Final`; older
   material uses `async`/`Future`. Same semantics — confirm against the exact compiler.
4. **Constraint cost** of `hash.psd2/4/8` and the hand-rolled Merkle fold is not in the
   operator docs; benchmark before committing to a tree depth / rate.
5. Several `developer.aleo.org/*` pages now **301-redirect to `docs.aleo.org`** (off our
   allow-list) and the AleoNet/welcome opcode source repo was **archived 2026-05-26** —
   re-confirm the canonical opcode reference location when needed.

## Primary sources

- Grants: [aleo.org/grants](https://aleo.org/grants/) · [ANF](https://aleo.org/post/announcing-aleo-network-foundation/) · [Tooling & Infra](https://aleo.org/post/announcing-the-aleo-tooling-and-infrastructure-grants-program/) · [Treasury RFC](https://aleo.org/post/aleo-response-treasury-rfc-illicit-activity-digital-assets/)
- Toolchain: [Leo releases](https://github.com/ProvableHQ/leo/releases/latest) · [install](https://docs.leo-lang.org/getting_started/installation) · [deploy](https://docs.leo-lang.org/guides/deploy) · [faucet](https://faucet.aleo.org/) · [aleoscan](https://testnet.aleoscan.io/)
- Primitives: [Leo cryptographic operators](https://docs.leo-lang.org/language/operators/cryptographic_operators) · [data types](https://docs.leo-lang.org/language/data_types) · [standard operators](https://docs.leo-lang.org/language/operators/standard_operators) · [cheatsheet](https://docs.leo-lang.org/language/cheatsheet) · [public_state](https://docs.leo-lang.org/language/programs_in_practice/public_state) · [AVM opcodes](https://github.com/AleoNet/welcome/blob/master/documentation/guides/aleo/04_opcodes.md) · Merkle precedents: [zPass](https://zpass.docs.aleo.org/zpass-programs/zpass-merkle-tree-size-8-program), [Sealance](https://developer.aleo.org/sdk/api-specification/sealance_merkle_tree/)

---
*Recon only. No Leo port written, nothing deployed. Next step (if approved): a scoped v0-A→Leo
port plan, starting from C1 (signer-model decision) and the Poseidon-hash `C`.*
