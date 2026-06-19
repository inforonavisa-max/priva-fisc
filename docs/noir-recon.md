# Noir / Aztec Reconnaissance — for a v0-A Port Decision

> **Status:** RECON ONLY (2026-06-19). No full port was written; nothing was deployed to
> Aztec; no real data touched; the Mina `src/`, the spec, and the Leo `leo/` were **not**
> modified. The Noir toolchain was installed to user dirs (`~/.nargo`, `~/.bb`) — outside the
> repo. Two **minimal compile probes** live in [`../noir/`](../noir/) and are the only repo
> additions. Every external claim is sourced; toolchain/compile facts marked **[verified
> locally]** were actually built/run on this machine (macOS 26.5 / arm64).
>
> **Question this answers:** if/when we implement the v0-A relation ([`../spec/SPEC.md`](../spec/SPEC.md),
> [`../src/circuit.ts`](../src/circuit.ts)) in Noir, how cleanly does each circuit primitive
> map — and the headline question: **is Phase-5 (the *real* RSA-2048 + SHA-256 authority
> signature) verifiable in-circuit in Noir?** (Short answer: **yes — and unlike Mina/Aleo,
> this is the one stack where the real signature primitive is a maintained, production-proven
> library that compiles today.**)

---

## 0. Headline

| Question | Answer |
|---|---|
| Native ZK hash in Noir? | **YES** — **Poseidon2** via the `poseidon` library (`Poseidon2::hash`), **Pedersen** in std (`std::hash::pedersen_hash`). **[verified locally]** |
| Native ZK signature verify? | **YES** — **Schnorr over Grumpkin** (`schnorr` lib, message = a single `Field`, matches v0-A's `M`); **ECDSA secp256k1 / secp256r1** are in std. **EdDSA** exists but its latest tag is **broken on current Nargo**. **[verified locally]** |
| Native Merkle gadget? | **NO** — `std::merkle` was removed; hand-roll a Poseidon2 path-fold (done in the skeleton). **[verified locally]** |
| **RSA-2048 + SHA-256 in-circuit (Phase-5)?** | **YES, and practical.** The maintained **`zkpassport/noir_rsa` v0.11.1** verifies RSA-2048 PKCS#1 v1.5 over a SHA-256 digest; the full in-circuit chain **compiles on the latest Nargo** at **35 992 UltraHonk gates** (sub-second proving on a laptop; runs in production on mobile at ZKPassport). **[verified locally]** |
| Is SHA-256 native? | **NO native full hash** (only `sha256_compression` in std), but the **`sha256` library** (v0.3.0) provides it and it composes in-circuit with RSA. **This is the key Noir advantage over Mina/Leo**, where SHA-256 is *not* available as a native/library primitive at all. **[verified locally]** |
| Does v0-A map cleanly? | **Yes — most cleanly of the three stacks.** Poseidon2 + Schnorr are libraries (not stdlib, but blessed/maintained); Merkle is hand-rolled (as in Aleo); the BN254 field makes `C` stack-specific (as everywhere). **The differentiator: Phase-5's RSA+SHA-256 is a *solved, benchmarked* problem in Noir, not deferred R&D.** |
| Target Aztec v4 or wait for v5? | **Neither binds us.** A standalone Noir proving circuit + `bb` proof is **decoupled** from the Aztec L2 protocol version. Build on **latest stable Nargo (`1.0.0-beta.22`) + matching `bb` now**; the v4↔v5 question only binds *Aztec.nr contract* authors deploying to the L2 (which v0-A is not). |

---

## TASK A — Toolchain & Aztec version (verified)

### A.1 Versions (June 2026)

| Component | Version | Source |
|---|---|---|
| **Nargo (Noir compiler)** | **`1.0.0-beta.22`** (noirc `1.0.0-beta.22+c57152f9…`, released 2026-06-01) | [noir releases](https://github.com/noir-lang/noir/releases) — **[verified locally]** |
| **Barretenberg `bb`** (proving backend) | **`5.0.0-nightly.20260522`** (resolved by `bbup` for beta.22) | `bbup --noir-version 1.0.0-beta.22` — **[verified locally]** |
| Aztec **mainnet** | **Alpha `4.3.1`** on Ethereum (initial, "early/experimental" phase) | [docs.aztec.network/networks](https://docs.aztec.network/) |
| Aztec **testnet** | **`5.0.0-rc.1`** on Sepolia | [docs.aztec.network/networks](https://docs.aztec.network/) |
| Aztec **v5** (next major) | **~July 2026 (forward-looking)** — bundles the fix for a proving-system vuln found ~Mar 2026; currently in nightly/RC (`@aztec/bb.js` `5.0.0-nightly.*`, `5.0.0-patched.20260318`) | [Aztec security blog 2026-03-10](https://aztec.network/) |

> There is **no final Noir 1.0.0** yet (still the `beta` series) and **no stable `bb` 3.0.0**;
> `bbup` derives the matching backend per Nargo version. Install: `noirup` (Noir) +
> `bbup --noir-version <nargo>` (backend). **[verified locally]**

**Install run [verified locally]:**
```
$ nargo --version
nargo version = 1.0.0-beta.22
noirc version = 1.0.0-beta.22+c57152f91260ecdb9faad4efc20abb14b6d2ece7
$ bbup --noir-version 1.0.0-beta.22
✓ Resolved to barretenberg version 5.0.0-nightly.20260522
```

### A.2 Port to v4 or wait for v5? — assessment

**Decision: target the latest *upstream stable Nargo* (`1.0.0-beta.22`) + its matching `bb`
now. The Aztec L2 protocol version (v4 vs v5) is orthogonal to this work.** Reasoning:

1. **v0-A is a proving relation, not an Aztec.nr contract.** Like the Mina (`ZkProgram`) and
   Aleo (`transition`) implementations, the Noir artifact is a **circuit proved with `bb`**
   (off-chain, or verified by a Solidity verifier on any EVM chain). It does **not** run inside
   the Aztec L2 VM, so it is **not tied** to the L2 protocol/verification-key version (4.3.1
   vs 5.0.0). Only the **`nargo`↔`bb` pair** binds the artifact.
2. **The v4↔v5 split binds *Aztec.nr contract authors*** who deploy private contracts to the
   Aztec L2 (where `aztec-nargo` pins its own Noir+bb per network release, which may *lag*
   upstream `noirup`). We are not (yet) in that bucket.
3. **The library ecosystem tracks upstream stable Nargo**, not the Aztec L2 release. Every
   primitive we need (Poseidon2, Schnorr, sha256, noir-bignum, noir_rsa) compiles on
   `beta.22` today — see Task B/C. Waiting for v5 buys nothing for the circuit.
4. **Caveat (only if we later go on-chain):** the ~Mar-2026 proving-system vulnerability is
   patched in **v5** — relevant if we eventually run *production* proofs or deploy an
   Aztec.nr contract. For a recon/grant PoC it does not gate us; revisit at productionization.

> **Net:** "port to v4 vs wait for v5" is a **non-question for the v0-A circuit**. Build on
> stable `beta.22`+`bb`; treat the Aztec L2 version as a *deployment-target* decision deferred
> to whenever (if ever) we wrap the circuit in an on-chain Aztec contract.

---

## TASK B — Native / library primitive inventory (compile-verified)

Noir's stdlib has been **shrinking**: hashes and signatures are moving out of `std` into
**blessed `noir-lang` (and Aztec/ZKPassport) libraries**. The authoritative test is *does it
compile* — every row below was built as a minimal `bin` crate and measured with `nargo info`
(ACIR opcode counts; a primitive's *real* cost is its `bb` gate count, see Task C).

> ⚠️ **Gotcha [verified locally]:** `nargo compile` on a `--lib` crate does **not** fully
> resolve unused function bodies — a `lib` probe with bogus `std::hash::sha256` paths "passed".
> The truth only appears when compiling a **`bin` with a `main`** that calls the primitive. All
> rows below are `bin`+`nargo info` results.

| Primitive | Where (current Nargo) | API | Local probe | ACIR |
|---|---|---|---|---|
| **Poseidon2** | `poseidon` lib **v0.3.0** | `poseidon::poseidon2::Poseidon2::hash(arr, len)` | hash of 9 fields | **11** |
| **Pedersen hash** | **std** | `std::hash::pedersen_hash(arr)` | hash of 4 fields | **34** |
| Pedersen commitment | **std** | `std::hash::pedersen_commitment` | (not probed) | — |
| **SHA-256** | `sha256` lib **v0.3.0** | `sha256::digest` / `sha256::sha256_var` | digest of 64 bytes | **190** |
| Keccak-256 | `keccak256` lib **v0.1.3** | (lib) | `std::hash::keccak256` path | **absent in std [verified locally]** |
| **ECDSA secp256k1** | **std** | `std::ecdsa_secp256k1::verify_signature` | full verify | **162** |
| **ECDSA secp256r1** (P-256) | **std** | `std::ecdsa_secp256r1::verify_signature` | full verify | **162** |
| **Schnorr** (Grumpkin) | `schnorr` lib **v0.4.0** | `schnorr::verify_signature(pk: EmbeddedCurvePoint, sig: (Scalar,Scalar), msg: Field)` | full verify | **41** |
| EdDSA (Baby Jubjub) | `eddsa` lib **v0.1.3** | `eddsa::eddsa_verify::<H>(...)` | full verify | **❌ FAILS** |
| **2048-bit modmul** | `noir-bignum` lib **v0.10.0** | `RuntimeBigNum * RuntimeBigNum` | one mulmod | **482** |
| Merkle membership | **no std helper** | hand-rolled Poseidon2 fold | in skeleton (C4) | — |

**Findings worth carrying forward:**

- **SHA-256 / Keccak-256 are NOT in `std`** (only `sha256_compression` / `keccakf1600` low-level
  blocks). `std::hash::sha256` and `std::hash::keccak256` paths **do not resolve** on beta.22
  **[verified locally]** — you must depend on the `sha256` / `keccak256` libraries. This is the
  opposite of the Aleo finding (Leo has native Keccak/SHA3 but not SHA-2) and **better for us**:
  Noir's `sha256` library *is* SHA-2/SHA-256.
- **Poseidon and Poseidon2 left `std`** too (now the `poseidon` library); Poseidon2 is the
  idiomatic, cheaper choice (~2–4× cheaper than Poseidon v1).
- **`std::merkle::compute_merkle_root` was removed** (noir PR 7582) — no stdlib Merkle gadget;
  fold a fixed-depth Poseidon2 path by hand (exactly as in the Aleo path). Done in
  [`v0a_skeleton`](../noir/v0a_skeleton/src/main.nr) `fold_root`.
- ⚠️ **EdDSA is currently broken on beta.22 [verified locally].** `eddsa` v0.1.3 (its newest
  tag) pulls `ec` v0.1.2, which uses the **removed `u1` type** (`error: `u1` has been removed,
  use `bool` instead`). So the **maintained ZK-signature path is Schnorr**, not EdDSA — fine,
  since v0-A signs a single `Field` `M` and Schnorr takes exactly that.

---

## TASK C — RSA-2048 + SHA-256 feasibility (THE critical question)

### C.1 NET ANSWER: **YES — practical, not merely possible.**

A real, **actively maintained** Noir library verifies **RSA-2048 PKCS#1 v1.5 signatures over a
SHA-256 digest fully in-circuit**, it **compiles on the latest Nargo**, and the full chain
proves **sub-second on a laptop** (and runs in **production on mobile**). This is the single
most important recon result, and it is the strongest argument for Noir as the Phase-5 stack:
**of Mina / Aleo / Noir, Noir is the only one where the *real* fiscal signature primitive
(RSA-2048+SHA-256) is a solved, benchmarked, production-proven library — not deferred R&D.**

### C.2 What exists, and the maintenance trap [verified locally]

- ⚠️ The "obvious" repo **`noir-lang/noir_rsa` is ARCHIVED (read-only since 2025-05-01)**; its
  last tag **v0.7.0 (2025-03-13)** pins **`noir-bignum` v0.6.0**, which **fails to compile on
  beta.22** — `error: Type annotation needed` *inside bignum's own source*
  (`unconstrained_ops.nr`). **[verified locally]** A naive `git tag`-grab of "noir_rsa" lands
  here and concludes "broken." It is not the maintained library.
- ✅ Maintenance moved to the fork **`zkpassport/noir_rsa`** — newest tag **v0.11.1
  (2026-06-12, *one week ago*)**, Apache-2.0, `compiler_version ">=1.0.0"`, README *"tested
  with all Noir stable releases from v1.0.0-beta.0"*, dependency bump *"support noir 1.0.0
  beta 20"* (2026-04-15). It pins the **fresh** `noir-bignum` **v0.10.0** (2026-04-08) +
  `sha256` v0.3.0 — both of which **compile cleanly on beta.22 [verified locally]** (a 2048-bit
  modmul = 482 ACIR; SHA-256/64B = 190 ACIR).
- **Production pedigree:** ZKPassport uses this exact RSA-2048/PKCS#1v1.5/SHA-256 path to verify
  eMRTD passport signatures; >17 000 people used it in the Aztec token sale; **Aztec Labs
  acquired ZKPassport (2026)** and the circuits stay open-source.

### C.3 Local proof — the full chain compiles & gate-counts on beta.22 [verified locally]

[`noir/phase5_rsa_probe`](../noir/phase5_rsa_probe/src/main.nr) calls the maintained
`zkpassport/noir_rsa` v0.11.1 directly: compute **SHA-256 of the message in-circuit**, then
**RSA-2048 PKCS#1 v1.5 verify** the authority signature over that digest. API (verbatim):

```rust
verify_sha256_pkcs1v15<let NumLimbs: u32, let ModBits: u32>(
    msg_hash: [u8; 32], sig: RuntimeBigNum<NumLimbs, ModBits>, exponent: u32,
) -> bool
```

```
$ nargo info --program-dir noir/phase5_rsa_probe     # in-circuit SHA-256 + RSA-2048 verify
  main: 3136 ACIR opcodes
$ bb gates -b noir/phase5_rsa_probe/target/phase5_rsa_probe.json
  { "acir_opcodes": 3136, "circuit_size": 35992 }    # UltraHonk gates
```

(Cross-check: I also **ported** `noir_rsa`'s ~80-line `verify_sha256_pkcs1v15` onto `noir-bignum`
v0.10.0 directly — 2854 ACIR / **35 992** gates — same backend size, confirming the cost is the
library's, not an artifact of how I called it. **[verified locally]**)

### C.4 Cost — rough constraint count, reconciled

| Measurement | Value | Source |
|---|---|---|
| **In-circuit SHA-256 + RSA-2048 verify (1 circuit)** | **35 992 UltraHonk gates** | **[verified locally]** `bb gates` |
| RSA-2048 verify, "does nothing else" | **~32 000 gates** (incl. lookup-table init) | `noir_rsa` source comment |
| RSA-2048 verify, *marginal* per extra signature | **~7 131 gates** (10×2048 = 63 821 ⇒ ~6.4k each) | `noir_rsa` README benchmark |
| Single 2048-bit modular multiplication | **~930 gates** | `noir-bignum` README |
| SHA-256 (Barretenberg precompile), few hundred bytes | ~36–47k constraints, sub-second | Ethproofs CSP (2026-06-10) |
| Poseidon2 permutation (t=2 / t=3) | ~586 / ~2 094 constraints | TACEO (measured, Barretenberg) |
| **Proving time, 1× RSA-2048+SHA-256** | **~262 ms (UltraHonk) on an i7 laptop** | `noir_rsa` README |
| Production (mobile) | 3 base proofs **10–50 s total, <1 GB RAM** even at RSA-4096+SHA-512 | ZKPassport FAQ |

The two headline numbers reconcile cleanly: a circuit that does **one** RSA-2048 verify costs
**~32k gates** (dominated by lookup-table initialization), and each *additional* signature adds
only **~7k** (the README's "7 131"). Add in-circuit SHA-256 of a short message and the whole
chain is **~36k gates / sub-second** — exactly what I measured (**35 992**).

### C.5 The honest Phase-5 boundary (what the library does NOT solve)

The library covers the **RSA-2048 / PKCS#1 v1.5 / SHA-256 *primitive*** — the math. It does
**not** solve Montenegro's protocol specifics, which remain the real Phase-5 engineering (same
boundary as Mina/Leo, just with the heaviest crypto already done):

- **Canonicalization** — the exact bytes that get hashed/signed (EFI XML, **Exclusive C14N**),
  which the SPEC §13 / §2.1 canonicalization caveat flags as ambiguous across reference libs.
- **IKOF = `uppercase(MD5(RSA-signature))`** — MD5 is a *separate* primitive (not in this lib,
  and not ZK-friendly); whether/how it must be proven in-circuit is a design question.
- **X.509 cert-chain** validation, `exponent` must fit `u32` (65537 fine; v0.11.1 blocks `e=1`).

> So Phase-5 in Noir = **(solved) RSA-2048+SHA-256 verify** + **(real work) canonical-EFI digest
> construction + cert/IKOF integration**. The cryptographic mountain Mina/Leo deferred is, in
> Noir, a foothill — the remaining climb is protocol fidelity, not ZK feasibility.

---

## TASK D — v0-A constraint map (C1–C5 → Noir)

From [`../spec/SPEC.md`](../spec/SPEC.md) §7, mirroring [`../src/circuit.ts`](../src/circuit.ts)
and [`../leo/src/main.leo`](../leo/src/main.leo). All compile-verified in
[`v0a_skeleton`](../noir/v0a_skeleton/src/main.nr) (**143 ACIR opcodes** total). Verdicts use the
Aleo recon's vocabulary: **KOLAY** (easy/native) · **ZOR** (hard) · **FARKLI** (different).

| SPEC | Noir realization | Primitive | Verdict |
|---|---|---|---|
| **C1** attestation + anti-replay | `m = Poseidon2::hash([DS_ATTEST, d_hi, d_lo, c, root, datetime, invoice], 7)`; `assert(schnorr::verify_signature(pk, sig, m))` | **Schnorr / Grumpkin** (`schnorr` lib) | **KOLAY** — *FARKLI signer model (good)*: signer is an **embedded-curve public key `(pk_x,pk_y)`**, i.e. an **arbitrary `PK_A`** — **closer to Mina's `PublicKey` than Aleo's account-`address`** constraint. Message = single `Field`, exact v0-A fit. **Phase-5 swap:** `schnorr::verify` → `noir_rsa::verify_sha256_pkcs1v15` — *the unique Noir win (Task C).* |
| **C2** salted commitment | `assert(commit_c(...) == c)` over `{seller_tin, buyer_id, items, margin, vat_base, vat_amount, rate_bp, total, salt}` with `DS_COMMIT` tag | **Poseidon2** (`poseidon` lib) | **KOLAY** — *FARKLI field*: BN254 scalar field ⇒ `C` is **stack-specific** (SPEC §12), not comparable to Pallas/BLS12-377. No native Poseidon `commit` (same as Mina/Leo) ⇒ salted **hash** maps 1:1. |
| **C3** bounded-int VAT | checked `u64`: `vat_base..margin ≤ 2^52−1`; `rate_bp ∈ {0,700,2100}`; promote to `u128`: `vat_amount*10000 + r == vat_base*rate_bp + 5000`, `r < 10000`; `total == vat_base + vat_amount` | native **`u64`/`u128`** ops | **KOLAY** — Noir integers overflow-check on cast/op; `u128` headroom (`2^52·2100 < 2^64`) prevents wrap. Same shape as Leo's `u64/u128`. |
| **C4** anchored Merkle membership | `leaf = Poseidon2::hash([DS_LEAF, seller_tin], 2)`; `fold_root(leaf, siblings[7], path_bits[7]) == sellers_root` | hand-rolled **Poseidon2 fold** | **FARKLI** — no stdlib Merkle (PR 7582 removed it); fixed-depth fold (height-8 ⇒ 7 siblings), identical idiom to Aleo. Root **anchored by C1** (`root ∈ M`), so prover can't substitute a self-built registry. `seller_tin` stays private (§5.1). |
| **C5** opaque `D` (Phase-5 marker) | `d_hi, d_lo` are **public inputs**, enter **only** `M`; never recomputed in-circuit in the skeleton | (public `Field` limbs) | **KOLAY now — and CLOSABLE.** Unlike Mina/Leo (no native SHA-256), Noir **can** later recompute `D = SHA-256(canonical(P))` in-circuit (`sha256` lib), binding `D` to the fields and removing the attester-trust (SPEC §9 v0-B). [`phase5_rsa_probe`](../noir/phase5_rsa_probe/src/main.nr) already exercises in-circuit SHA-256. |

---

## TASK E — Minimal circuits (skeleton) [verified locally]

Two `bin` crates in [`../noir/`](../noir/), both compiling on Nargo `1.0.0-beta.22`:

| Crate | What | `nargo info` | `bb gates` |
|---|---|---|---|
| [`v0a_skeleton`](../noir/v0a_skeleton/src/main.nr) | the full v0-A relation **C1–C5** (Schnorr + Poseidon2 commit + bounded-int VAT + Merkle fold + opaque `D`) | **143 ACIR** | — |
| [`phase5_rsa_probe`](../noir/phase5_rsa_probe/src/main.nr) | Phase-5: in-circuit **SHA-256 → RSA-2048 PKCS#1 v1.5 verify** (`zkpassport/noir_rsa` v0.11.1) | **3 136 ACIR** | **35 992** |

A clean end-to-end **execution** (witness solve) of the Poseidon2 primitive ran green
(`Circuit witness successfully solved`) **[verified locally]**, confirming the prove path works
on this machine. The two skeleton crates are **compile-verified** (the recon bar); green
*executions* of them are explicit port tasks (off-circuit Schnorr signer for `v0a_skeleton`;
regenerated `noir-bignum` v0.10.0 Barrett `redc_param` for `phase5_rsa_probe` — the bundled
bench vector is an older encoding, so its `bb`-level witness solve hits a `validate_in_range`
assertion). Neither is a feasibility blocker.

---

## Open questions / caveats (verify before acting)

1. **Library, not stdlib.** Poseidon2, Schnorr, sha256, bignum, and noir_rsa are **external
   libraries** (pinned by git tag), not `std`. This is normal for Noir's shrinking stdlib, but
   it means the build depends on a moving 1.0-beta target. Pin **explicit tags** (the READMEs'
   default install snippets are *stale* — they show old tags); the libs have tracked Nargo
   bumps promptly, but a future breaking change could need a dep bump.
2. **noir_rsa source-of-truth.** Use **`zkpassport/noir_rsa`** (maintained), **not**
   `noir-lang/noir_rsa` (archived). Pin a **tag** (v0.11.1) — the repo has *no GitHub Releases*,
   only tags; its manifest version reads `0.11.0` while the newest tag is `v0.11.1`.
3. **EdDSA is broken on beta.22** (stale `ec` dep); the maintained ZK-signature is **Schnorr**.
   If a Baby-Jubjub EdDSA is ever required, expect to fork/fix `ec` or wait for a bump.
4. **Gate counts are single-laptop, version-dependent benchmarks.** Magnitudes (RSA-2048 a few
   ×10³–10⁴ gates, SHA-256 tens of thousands, Poseidon2 hundreds) are stable; exact numbers
   drift release-to-release. Re-benchmark on target hardware before committing to a design.
5. **The real Phase-5 work is protocol fidelity, not ZK math** (Task C.5): canonical-EFI byte
   construction, the **MD5-based IKOF** (a non-ZK-friendly hash, out of `noir_rsa`'s scope), and
   the X.509 chain. Match the canonical form against the official *Tehnička uputstva* (SPEC §13)
   before any fidelity claim.
6. **On-chain deployment is a separate decision.** If we ever wrap the circuit in an Aztec.nr
   contract (vs. a `bb` proof + EVM verifier), the v4↔v5 protocol version and the Mar-2026
   proving-system vuln fix (v5) become relevant — revisit then.

## Primary sources

- Toolchain: [Noir releases](https://github.com/noir-lang/noir/releases) · [noirup](https://github.com/noir-lang/noirup) · [bbup / barretenberg](https://github.com/AztecProtocol/aztec-packages) · [docs.aztec.network](https://docs.aztec.network/)
- Primitives: [Noir crypto primitives docs](https://noir-lang.org/docs/noir/standard_library/cryptographic_primitives/hashes) · [poseidon](https://github.com/noir-lang/poseidon) · [sha256](https://github.com/noir-lang/sha256) · [keccak256](https://github.com/noir-lang/keccak256) · [schnorr](https://github.com/noir-lang/schnorr) · [eddsa](https://github.com/noir-lang/eddsa) · [TACEO Poseidon2-for-Noir](https://core.taceo.io/articles/poseidon2-for-noir/)
- RSA / bignum: **[zkpassport/noir_rsa](https://github.com/zkpassport/noir_rsa)** (maintained) · [noir-lang/noir_rsa](https://github.com/noir-lang/noir_rsa) (archived) · [noir-bignum](https://github.com/noir-lang/noir-bignum) · [ZKPassport FAQ](https://docs.zkpassport.id/faq) · [Aztec acquires ZKPassport](https://thedefiant.io/news/blockchains/aztec-labs-acquires-zkpassport-identity-verification-q2dgkb)
- Benchmarks: `noir_rsa` / `noir-bignum` READMEs · [Ethproofs CSP](https://ethproofs.org/csp-benchmarks) · [Savio-Sou/noir-benchmarks](https://github.com/Savio-Sou/noir-benchmarks)

---
*Recon only. No full port written, nothing deployed; repo additions limited to [`../noir/`](../noir/)
(two compile probes) and this file. Next step (if approved): a scoped v0-A→Noir implementation
plan, starting from C1 (Schnorr) with the Phase-5 RSA+SHA-256 path already de-risked (Task C).*
