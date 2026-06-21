# Arbitrum Reconnaissance — for a v0-A On-Chain Verification Decision

> **Status:** RECON ONLY (2026-06-21). No full PoC was written; nothing was deployed to Arbitrum;
> no real data, keys, or PII touched (synthetic only). The Mina `src/`, the `spec/`, the `leo/`,
> the `noir/`, and the `cairo/` trees were **not** modified. The only repo additions are this file
> and a minimal [`../arbitrum/`](../arbitrum/) skeleton (a Solidity verifier-gate + a reference
> financial-dApp + an illustrative Stylus sketch). A Solidity compiler (`solc 0.8.35`) was installed
> to a **temp dir outside the repo** (`/tmp/arb-recon-build`, like the Noir recon's `~/.nargo`) so the
> Solidity skeleton could be genuinely built; **no** Foundry and **no** Rust/Stylus toolchain were
> installed. Facts marked **[verified locally]** were actually compiled on this machine
> (macOS / arm64). Every external claim is **[sourced]** with a URL; gas figures are benchmark/
> version-dependent and flagged as such.
>
> **Question this answers:** PRIVA-FISC already produces ZK proofs (Mina/Kimchi, **Noir/UltraHonk**,
> Cairo/STARK, Aleo/Varuna). **How do we verify one of those proofs *on-chain* on Arbitrum, and which
> of our existing PoCs bridges most cleanly?** Short answer: **the Noir/UltraHonk PoC bridges with
> zero circuit changes via a Barretenberg-generated Solidity verifier, in Solidity (not Stylus),
> because the cost is a BN254 pairing the EVM does natively.**

---

## 0. Headline

| Question | Answer |
|---|---|
| Does Arbitrum support on-chain pairing verification (the gating fact)? | **YES.** Arbitrum Nitro is a go-ethereum fork; the BN254/alt-bn128 precompiles a SNARK verifier needs — **0x06 ecAdd, 0x07 ecMul, 0x08 ecPairing**, plus **0x05 modexp** — are all registered at the standard addresses. If 0x08 were absent, Solidity pairing verifiers would be impossible; it is present. **[sourced]** |
| **Solidity (EVM) or Stylus (Rust/WASM) for the verifier?** | **SOLIDITY.** Our proof is a **BN254 pairing-based SNARK**; verification cost is dominated by `ecPairing` (0x08), which is **NEUTRAL** between Solidity and Stylus (a Stylus verifier just calls the same precompile — proven by the live `zk-sunade` Stylus Groth16 verifier). Stylus wins only on **hash/loop-heavy in-WASM compute** (Poseidon ~18× cheaper), i.e. a future **STARK/FRI** path — not a pairing check. Solidity tooling is turnkey; Stylus ZK tooling is experimental in mid-2026. **[sourced]** |
| **How is a PRIVA-FISC proof verified on Arbitrum?** | Reuse the **existing Noir circuit unchanged**; regenerate its proof+VK in the **keccak flavor** (`bb …--oracle_hash keccak`); emit a Solidity verifier (`bb write_solidity_verifier --scheme ultra_honk`); deploy it behind [`FiscComplianceGate`](../arbitrum/solidity/src/FiscComplianceGate.sol), the EVM analogue of our Mina `FiscAnchor`. **[sourced + skeleton verified locally]** |
| **Which of our PoCs bridges easiest?** | **Noir** (`noir/v0a_skeleton`) — it is already **UltraHonk over BN254**, so `bb` emits an EVM verifier from the *same* circuit with **no `.nr` changes and no trusted setup**. Mina (Pasta/Kimchi), Aleo (Varuna/BLS12-377) and Cairo (STARK) would each need an expensive **re-prove/wrap** to reach the EVM. **[sourced]** |
| Rough gas cost? | **UltraHonk Solidity verifier ≈ 2.4M gas** (L2 execution) + an **L1 data-posting fee on the ~16 KB proof** (the Arbitrum swing cost). A **Groth16 re-prove** alternative is **≈ 200–250k gas** + a constant **256-byte** proof — ~10× cheaper on-chain, but costs a **per-circuit trusted-setup ceremony** and a second circuit to maintain. **[sourced]** |
| New proof needed, or bridge an existing one? | **Bridge the existing Noir proof** — no new proof system required for the recommended route. A Groth16 re-prove (in Circom/gnark) is an *optional gas optimization*, not a prerequisite. **[sourced]** |
| Is STARK (our Cairo PoC) verifiable on Arbitrum? | **Not practically.** On-chain STARK/FRI verification is multi-MB / multi-tx / ~millions of gas, and the Starknet-native verifiers (Integrity/SHARP/Stwo) target **Starknet/Ethereum-L1, not Arbitrum**. **Garaga** generates **Cairo (Starknet) verifiers, not Solidity** — so it is *not* an Arbitrum path (it is the cross-link to our Starknet recon). **[sourced]** |

---

## TASK A — Toolchain: Solidity (EVM) vs Stylus (Rust/WASM)

### A.1 Versions (June 2026)

| Component | Version / fact | Source |
|---|---|---|
| **Arbitrum One** | chain ID **42161**, RPC `https://arb1.arbitrum.io/rpc` | [docs.arbitrum.io/…/chain-info](https://docs.arbitrum.io/for-devs/dev-tools-and-resources/chain-info) — **[sourced]** |
| **Arbitrum Sepolia** (testnet) | chain ID **421614**, RPC `https://sepolia-rollup.arbitrum.io/rpc` | same — **[sourced]** |
| **Foundry** (forge/cast/anvil) | stable **v1.0+** (since 2025-02-13) | [paradigm.xyz announcing-foundry-v1-0](https://www.paradigm.xyz/2025/02/announcing-foundry-v1-0) — **[sourced]** |
| **solc** | **0.8.35** (2026-04-29) is the latest patch | [solidity releases](https://github.com/ethereum/solidity/releases) — **[verified locally]** (0.8.35 installed + compiled the skeleton) |
| **cargo-stylus** + **stylus-sdk** | co-versioned **0.10.7** (2026-05-19), monorepo `OffchainLabs/stylus-sdk-rs` (old standalone `cargo-stylus` repo **archived 2025-10**); needs **Rust ≥ 1.91** + `wasm32-unknown-unknown` | [stylus-sdk-rs releases](https://github.com/OffchainLabs/stylus-sdk-rs/releases) · [crates.io](https://crates.io/crates/stylus-sdk/versions) — **[sourced]** |
| **Stylus availability** | GA on **Arbitrum One + Nova** since **2024-09-03** (ArbOS 32 "Bianca"); live on Arbitrum Sepolia | [blog.arbitrum.io/arbitrum-stylus-mainnet](https://blog.arbitrum.io/arbitrum-stylus-mainnet/) — **[sourced]** |
| **snarkjs** (Groth16/PLONK toolkit) | **v0.7.6** (2026-01-26) | [iden3/snarkjs](https://github.com/iden3/snarkjs) — **[sourced]** |
| **Barretenberg `bb`** | nightly aztec-packages (e.g. `v4.2.0-nightly.20260325`); UltraHonk vuln patched ≥ **0.82.2** — pin recent | [barretenberg readme](https://github.com/AztecProtocol/aztec-packages/blob/master/barretenberg/cpp/src/barretenberg/bb/readme.md) — **[sourced]** |

> **solc evmVersion caveat:** solc's *default* EVM target moved `cancun → prague` (0.8.30) → `osaka`
> (0.8.31). Arbitrum can lag Ethereum hardforks, so **set `evmVersion` explicitly** (the skeleton
> compiles with `cancun`) rather than trusting solc's newest default. **[sourced]**

### A.2 The gating fact — EVM precompiles on Arbitrum

A Groth16/PLONK/Honk Solidity verifier is just elliptic-curve math that bottoms out in four
precompiles. **All four are present on Arbitrum Nitro** (verified in the OffchainLabs go-ethereum
fork's `core/vm/contracts.go` precompile tables, addresses `0x01–0x09`):

| Addr | Precompile | Used by verifier for | EIP-1108 gas |
|---|---|---|---|
| `0x05` | modexp | RSA/bignum, some encodings | input-dependent |
| `0x06` | bn256Add (ecAdd) | public-input linear combination | **150** |
| `0x07` | bn256ScalarMul (ecMul) | per-public-input scalar mul | **6,000** |
| `0x08` | bn256Pairing (ecPairing) | the final pairing-product check | **34,000·k + 45,000** |

Source: [OffchainLabs/go-ethereum `contracts.go`](https://github.com/OffchainLabs/go-ethereum/blob/master/core/vm/contracts.go) · [EIP-1108](https://eips.ethereum.org/EIPS/eip-1108) · [Arbitrum precompiles overview](https://docs.arbitrum.io/build-decentralized-apps/precompiles/overview). **[sourced]**
This is **the** enabling fact: standard Groth16/Honk Solidity verifiers run on Arbitrum **unmodified**.

### A.3 Arbitrum's two-dimensional gas model (why proof *size* matters)

Arbitrum charges **L2 execution gas PLUS an L1 data-posting fee**. The L1 fee ≈
`(Brotli-compressed calldata bytes) × 16 × L1_basefee`, expressed back in L2 gas. **[sourced]**
([l1-gas-pricing](https://docs.arbitrum.io/how-arbitrum-works/l1-gas-pricing)). Consequence for us:

- A **Groth16** proof is a constant **256 bytes** → negligible L1 fee.
- An **UltraHonk** proof is **~508 field elements ≈ 16 KB** → the L1 posting fee becomes a *material*
  part of total cost, on top of the ~2.4M L2 verification gas.
- ⚠️ `anvil --fork-url` simulates L2 execution but **does not** reproduce the L1 data fee, so local
  gas estimates **understate** real Arbitrum cost for a large Honk proof. Measure on Sepolia.

### A.4 Solidity vs Stylus — the recommendation (NET)

| Dimension | Solidity (EVM) | Stylus (Rust/WASM) |
|---|---|---|
| Pairing check (our cost driver) | calls `ecPairing` 0x08 | **calls the same `ecPairing` 0x08** via `RawCall::new_static()` — **no advantage** |
| Tooling for *our* proof | `bb write_solidity_verifier` + `snarkjs … solidityverifier` — **turnkey** | hand-written PoCs only (`zk-sunade`, testnet, SDK 0.4.1; `noir-stylus-verifier` alpha) — **experimental** |
| Contract-size limit | EIP-170 **24 KB** (Honk verifier ~33 KB → needs library split) | Brotli-compressed WASM **≤ 24 KB** (a pairing verifier is tight; `zk-sunade` = 22.7 KB) |
| Where it genuinely wins | mature, audited, native precompiles | **hash/loop-heavy WASM**: Poseidon **220k → 12k gas (~18×)**; FRI/STARK, in-WASM modexp |
| Entry overhead | none | **128–2048 gas** per WASM call |

Evidence the pairing is a wash: the deployed **`zk-sunade`** Stylus Groth16 verifier implements its
BN254 ops by calling `0x06/0x07/0x08` directly (runtime verify ≈ **256k gas**, precompile-bound, not
in-WASM) — [supernovahs/zk-sunade](https://github.com/supernovahs/zk-sunade). Arbitrum's own docs warn
"the fee reduction may be smaller for highly optimized Solidity that makes heavy use of native
precompiles vs. an unoptimized Stylus equivalent." **[sourced]**
Where Stylus *does* win: OpenZeppelin measured **Poseidon (BN256, t=3): Solidity 220,244 gas → Rust/
Stylus 11,887 gas (~18×)** — [openzeppelin.com/news/poseidon-…-stylus](https://www.openzeppelin.com/news/poseidon-go-brr-with-stylus-cryptographic-functions-are-18x-more-gas-efficient-via-rust-on-arbitrum). **[sourced]**

> **Recommendation:** **Build the verifier in Solidity (M1).** For a BN254 pairing SNARK, Stylus buys
> nothing and costs maturity. **Keep Stylus explicitly in reserve** for two specific futures: (a) if we
> ever verify our **Cairo STARK** path on Arbitrum (FRI/Poseidon-heavy → Stylus' 18× compute discount
> is decisive), or (b) to shave the Honk verifier's keccak/field work or fuse it with heavy dApp logic.
> The alpha `wakeuplabs-io/noir-stylus-verifier` is the watch-this-space artifact for (b).

---

## TASK B — Proof-on-chain verification (THE critical question)

### B.1 NET answer

> **A PRIVA-FISC proof is verified on Arbitrum by deploying a Barretenberg-generated Solidity
> UltraHonk verifier, with our existing Noir PoC ([`noir/v0a_skeleton`](../noir/v0a_skeleton/src/main.nr))
> as the source — reused unchanged.** No new proof system is required for this route. The proof is
> produced off-chain (`bb prove`), the verifier is generated from the circuit's VK, and a thin gate
> contract anchors the public statement and records only the commitment `C` on-chain.

The end-to-end command path (mid-2026 `bb` syntax — `--scheme` replaces the old `bb contract`):

```bash
# 0) the SAME circuit we already have — no .nr change
nargo compile                         # -> target/v0a_skeleton.json (ACIR)

# 1) regenerate VK + proof in the KECCAK (EVM) flavor, not the default Poseidon2/Grumpkin one
bb write_vk -b ./target/v0a_skeleton.json --oracle_hash keccak -o ./target/vk
bb prove    -b ./target/v0a_skeleton.json -w ./target/witness.gz --oracle_hash keccak -o ./target/proof

# 2) emit the Solidity verifier from the VK
bb write_solidity_verifier --scheme ultra_honk -k ./target/vk -o ./target/Verifier.sol

# 3) deploy Verifier.sol + FiscComplianceGate on Arbitrum (Foundry)
forge create --rpc-url https://sepolia-rollup.arbitrum.io/rpc ... HonkVerifier
```

Why keccak flavor: the default `ultra_honk` uses Poseidon2/Grumpkin (for off-chain/recursive
verification) and is **far** more expensive on the EVM; `--oracle_hash keccak` (`ultra_keccak_honk`)
uses the EVM's native `keccak256` and is the on-chain flavor. Source:
[barretenberg how-to-solidity-verifier](https://barretenberg.aztec.network/docs/how_to_guides/how-to-solidity-verifier/) · [noir-lang how-to-solidity-verifier](https://noir-lang.org/docs/dev/how_to/how-to-solidity-verifier). **[sourced]**

### B.2 Which proof systems are practical on Arbitrum

| System | Curve / field | On-chain verify cost | Trusted setup | Verdict for Arbitrum |
|---|---|---|---|---|
| **Groth16** | BN254 | **~200–250k gas**, 256 B proof | **per-circuit** phase-2 ceremony | **Cheapest**, but a ceremony per circuit revision |
| **PLONK** (snarkjs) | BN254 | ~290k gas | universal SRS only | viable; pricier than Groth16 |
| **fflonk** | BN254 | ~200k + 0.9k·ℓ gas | universal SRS only | cheap verify, heavy proving/large proof |
| **UltraHonk** (bb / Noir) | BN254 | **~2.4M gas**, ~16 KB proof | **none** (universal) | **viable + reuses our Noir circuit** |
| **STARK** (Cairo) | M31/felt252 | ~millions of gas, multi-MB, **multi-tx** | none | **impractical on EVM** (see B.6) |

Gas sources: Groth16 formula ≈ `207,700 + 7,160·ℓ` and `ECPAIRING = 34,000·k+45,000`
([Orbiter benchmark](https://hackmd.io/@Orbiter-Research/S1nat__m0), [EIP-1108](https://eips.ethereum.org/EIPS/eip-1108)); UltraHonk **2,396,575 gas** ([blog.base.dev benchmark](https://blog.base.dev/benchmarking-zkp-systems)) corroborated at **2.45–2.51M** ([Aztec forum PoC](https://forum.aztec.network/t/noir-rlwe-gadgets-verifiable-bfv-encryption-rlwe-in-noir-with-an-on-chain-ultrahonk-verifier/8591)). **[sourced]** All are circuit-size/version dependent — treat as order-of-magnitude bands.

### B.3 Which of OUR PoCs bridges easiest (cross-stack)

| Our PoC | Proof system | Native EVM verify? | Bridge to Arbitrum | Effort |
|---|---|---|---|---|
| **Noir** [`noir/v0a_skeleton`](../noir/v0a_skeleton/src/main.nr) | **UltraHonk / BN254** | **YES** via `bb write_solidity_verifier` | **reuse circuit unchanged**, regenerate keccak proof, deploy `Verifier.sol` | **LOWEST** ✅ |
| *(re-prove)* Circom/gnark | Groth16 / BN254 | YES (`snarkjs … solidityverifier`) | **new** circuit + **trusted-setup ceremony** | MEDIUM (but ~10× cheaper gas) |
| **Mina** [`src/`](../src/circuit.ts) | Kimchi/Pickles | NO | recursive wrap **Pasta→BN254** (expensive) | HIGH |
| **Aleo** [`leo/`](../leo/src/main.leo) | Varuna (Marlin) / BLS12-377 | NO | wrap / re-prove | HIGH |
| **Cairo** [`cairo/`](../cairo/src/lib.cairo) | STARK (Stwo/SHARP) | NO (Starknet-native) | re-prove via stwo→gnark→Groth16, or verify on **Starknet not Arbitrum** | HIGH |

**There is no format conversion** from a Mina/Aleo/Cairo proof to an EVM Groth16 proof — you must
**re-prove/wrap** (encode the source verifier as a BN254 circuit). Precedents: RISC Zero (STARK→Circom
Groth16, ~256 B receipt), Herodotus `stwo-gnark-verifier` (Cairo/Stwo STARK→gnark). **[sourced]**
([aligned mina-bridge](https://blog.alignedlayer.com/mina-to-ethereum-bridge/), [stwo-gnark-verifier](https://github.com/HerodotusDev/stwo-gnark-verifier)). **Noir is the only PoC that needs none of this** — it is *already* BN254/UltraHonk.

### B.4 Two routes — and the recommendation

- **Route A — Noir/UltraHonk Solidity verifier (RECOMMENDED for M1).** Reuse the de-risked Noir
  circuit; no trusted-setup ceremony; one extra build step (keccak proof) + one generated contract.
  Cost: **~2.4M gas + ~16 KB calldata**.
- **Route B — re-prove in Circom/gnark → Groth16 (gas-optimization path).** ~10× cheaper on-chain
  (~200–250k gas, 256 B), but requires (i) a **second circuit** implementing the same C1–C5 relation,
  (ii) a **per-circuit trusted-setup ceremony** re-run on *every* circuit change (e.g. a VAT-rule
  update), and (iii) ongoing two-circuit maintenance.

> **Recommendation:** ship **Route A** first — it minimizes new code and trust assumptions and turns
> our existing Noir work directly into an Arbitrum deployment. Treat **Route B** as a deferred
> optimization, taken only if the ~2.4M-gas + calldata cost becomes the binding constraint at volume.
> (If Route B is ever needed, the Stylus Poseidon discount and `noir-stylus-verifier` are the further
> levers.) For a *tax-compliance* deployment, Route A's **no-ceremony** property is also a governance
> win: a circuit revision does not force a new ceremony + a redeployed, re-audited verifier.

### B.5 Rough cost estimate (per proof, Arbitrum)

| Route | L2 verify gas | Proof calldata | L1 data fee | Net character |
|---|---|---|---|---|
| **A — UltraHonk** | **~2.4M** | **~16 KB** | **material** (Brotli × 16 × L1 basefee) | cheap L2, calldata-sensitive |
| **B — Groth16** | **~200–250k** | **256 B** | negligible | cheapest overall |

Arbitrum L2 execution gas is inexpensive in fiat terms, so even Route A's 2.4M gas is modest; the
**L1 calldata posting on the 16 KB proof is the swing cost** and tracks Ethereum L1 basefee. Re-measure
on Arbitrum Sepolia (not a local `anvil` fork, which omits the L1 fee). **[sourced]**

### B.6 STARK / Garaga — the honest correction

Two things a naive plan gets wrong, corrected here:

1. **Direct STARK-on-EVM is impractical.** FRI proofs are large and need many Merkle/hash openings;
   a *toy* Fibonacci proof is ~166 KB, and SHARP splits each proof into Merkle/FRI/Memory-Page/Main
   components across **separate transactions**; on-chain STARK verification is on the order of
   **~5M gas**. The Starknet-native verifiers (**Integrity** in Cairo on Starknet; **SHARP/Stwo** on
   Starknet/Ethereum-L1) **do not target Arbitrum**. ([zksecurity stark-evm-adapter](https://blog.zksecurity.xyz/posts/stark-evm-adapter/), [HerodotusDev/integrity](https://github.com/HerodotusDev/integrity)). **[sourced]**
2. **Garaga is NOT an Arbitrum path.** Garaga (`keep-starknet-strange/garaga`, latest tagged **v1.1.0**,
   the newest release as of mid-2026) generates **Cairo / Starknet** verifier contracts (Groth16,
   UltraHonk flavors, SP1, RISC Zero) — **not Solidity**. Its `calldata` output is Starknet-formatted.
   So Garaga is the bridge for our **Cairo/Starknet** recon, *not* for Arbitrum; the EVM/Arbitrum
   bridge for a Noir proof is **Barretenberg's own `bb write_solidity_verifier`**.
   ([garaga noir generator](https://garaga.gitbook.io/garaga/smart-contract-generators/noir)). **[sourced]**

---

## TASK C — Reference financial-dApp integration (architecture)

PRIVA-FISC as a **"tax-compliance verifier module"** bolted onto an Arbitrum payment / stablecoin flow:
a transfer settles **only if** accompanied by a valid fiscalization-compliance proof. The dApp learns
the proven commitment `C` (an audit handle) and **nothing** about buyer / line items / margin / seller
TIN / amounts.

### C.1 Components (all in [`../arbitrum/solidity/src/`](../arbitrum/solidity/src/))

| Layer | Artifact | Role |
|---|---|---|
| Generated verifier | `HonkVerifier` (from `bb`) ⇒ [`IHonkVerifier`](../arbitrum/solidity/src/IHonkVerifier.sol) | the cryptographic check (pairing/sumcheck) — auto-generated, not hand-written |
| Compliance gate | [`FiscComplianceGate`](../arbitrum/solidity/src/FiscComplianceGate.sol) | anchors the public statement (authority key + registry root), verifies, records `C` — the EVM analogue of the Mina `FiscAnchor` zkApp |
| Reference dApp | [`CompliantPaymentFlow`](../arbitrum/solidity/src/CompliantPaymentFlow.sol) | a stablecoin transfer gated on a fresh proof |

### C.2 Architecture sketch

```
  OFF-CHAIN (prover: the compliant business)            ON-CHAIN (Arbitrum One / Sepolia)
  ┌──────────────────────────────────────┐
  │ synthetic EFI receipt  ──►  Noir      │              ┌─────────────────────────────────┐
  │  (buyer, items, margin,    v0a circuit│   proof +    │  CompliantPaymentFlow            │
  │   amounts, seller TIN,     C1..C5     │   public     │   .settle(payee, amount,         │
  │   salt, σ_attest)          (UltraHonk)│   inputs     │            proof, publicInputs)   │
  │            │                   │      │  ──────────► │        │                          │
  │            │            bb prove      │  (calldata)  │        ▼                          │
  │            ▼          --oracle_hash   │              │  FiscComplianceGate.submitProof  │
  │   PUBLIC statement:      keccak       │              │   1. require pk == pinned PK_A    │
  │   [pk_x, pk_y,                        │              │   2. require root == pinned root  │
  │    sellers_root,                      │              │   3. HonkVerifier.verify(...) ◄───┼── ecPairing 0x08
  │    d_hi, d_lo, c]                     │              │   4. record/emit commitment C     │
  └──────────────────────────────────────┘              │        │                          │
                                                          │        ▼  on success only         │
                                                          │  ERC-20 stablecoin.transferFrom   │
                                                          │  emit Settled(C, payer, payee, …) │
                                                          └─────────────────────────────────┘
       Hidden forever: buyer, line items, margin, seller TIN, base/VAT/total, rate
       On-chain (public): commitment C, digest limbs, registry root, authority pubkey
```

### C.3 Design notes (faithful to the SPEC / WHITEPAPER)

- **Anchored statement.** The gate pins the **authority public key `PK_A`** and the **registered-
  taxpayer registry root** at deploy time and rejects any proof whose public inputs differ — the
  on-chain equivalent of SPEC **C1**'s "registry root is anchored by the authority signature," so a
  prover cannot substitute their own key or a self-built registry.
- **Public-input layout** (from [`noir/v0a_skeleton/src/main.nr`](../noir/v0a_skeleton/src/main.nr)):
  `[0]=pk_x [1]=pk_y [2]=sellers_root [3]=d_hi [4]=d_lo [5]=c`. The gate decodes `C = publicInputs[5]`.
- **Selective disclosure preserved.** Only `C`, the digest limbs, the root and `PK_A` ever appear
  on-chain — exactly the disclosure set of the Mina deployment.
- **Scope honesty (matches WHITEPAPER).** v0-A's attestation signature is a **ZK-native stand-in**
  (no real-world security); the gate is proof-system-agnostic, so the **Phase-5** swap (real RSA-2048
  + SHA-256, already de-risked in the Noir recon) changes the *circuit*, not the gate. **No nullifier**
  yet — the same proof can be re-submitted (anti-double-submission is a later addition).
- **Auditor channel.** `C` is the handle an authorized auditor can later force-open (threshold/
  judicial opening is future work, not in this skeleton).

---

## TASK D — Minimal skeleton (verified locally)

[`../arbitrum/`](../arbitrum/) — Solidity skeleton **compiles clean**; Stylus sketch is illustrative.

| File | What | Build |
|---|---|---|
| [`solidity/src/IHonkVerifier.sol`](../arbitrum/solidity/src/IHonkVerifier.sol) | ABI of the `bb`/Garaga-generated verifier (`verify(bytes,bytes32[])→bool`) | **[verified locally]** |
| [`solidity/src/MockHonkVerifier.sol`](../arbitrum/solidity/src/MockHonkVerifier.sol) | non-crypto stand-in so the gate wires end-to-end pre-VK | **[verified locally]** |
| [`solidity/src/FiscComplianceGate.sol`](../arbitrum/solidity/src/FiscComplianceGate.sol) | anchors statement, verifies, records `C` (the EVM `FiscAnchor`) | **[verified locally]** |
| [`solidity/src/CompliantPaymentFlow.sol`](../arbitrum/solidity/src/CompliantPaymentFlow.sol) | reference financial-dApp (proof-gated stablecoin settle) | **[verified locally]** |
| [`stylus/src/lib.rs`](../arbitrum/stylus/src/lib.rs) + [`Cargo.toml`](../arbitrum/stylus/Cargo.toml) | illustrative Stylus gate (strategy A: delegate to the EVM verifier) | **NOT compiled** (no Rust toolchain) |

**Compile result [verified locally]** — `solc 0.8.35`, optimizer (200 runs), `evmVersion=cancun`:

```
errors: 0 | warnings: 0
FiscComplianceGate.sol:FiscComplianceGate     1558 bytes
CompliantPaymentFlow.sol:CompliantPaymentFlow 1338 bytes
MockHonkVerifier.sol:MockHonkVerifier          371 bytes
IHonkVerifier.sol:IHonkVerifier   (interface)    0 bytes
```

(The compiler was installed to `/tmp/arb-recon-build`, **outside the repo**; the repo holds only the
`.sol` sources. The real `HonkVerifier.sol` is generated from the circuit VK and replaces the mock 1:1.)

---

## TASK E — Milestone plan (draft)

| Milestone | Concrete deliverable | Rough effort |
|---|---|---|
| **M1 — Verifier contract** | (1) Regenerate the **keccak-flavor** UltraHonk proof+VK from the *existing* `noir/v0a_skeleton` circuit; (2) `bb write_solidity_verifier` → `HonkVerifier.sol`; (3) the **library-split** workaround for the ~33 KB > 24 KB limit; (4) deploy `HonkVerifier` + [`FiscComplianceGate`](../arbitrum/solidity/src/FiscComplianceGate.sol) on **Arbitrum Sepolia**; (5) a Foundry test that a valid synthetic proof **verifies on-chain** and a tampered one **reverts**; (6) **measured** L2 gas + L1 data fee on Sepolia (not a local fork). | **~1–1.5 wk** (circuit reused; work is keccak re-gen + size-split + deploy/measure) |
| **M2 — Reference dApp integration** | [`CompliantPaymentFlow`](../arbitrum/solidity/src/CompliantPaymentFlow.sol) wired to a testnet ERC-20 stablecoin: a transfer **settles only against a passing proof**; emits `Settled(C, …)`; end-to-end Foundry/JS test (off-chain `bb prove` → on-chain `settle`). Optional: a minimal web demo. | **~1–2 wk** |
| **M3 — Documentation / demo** | Deployment addresses + verified contracts on Arbiscan; a runbook (prove → generate calldata → settle); a short demo (script or screencast) of a private, compliance-gated payment; cost table (A vs B, measured); explicit scope/honesty statement (stand-in signature, no nullifier, synthetic data). | **~3–5 days** |

> **Optional M1.5 (only if gas/calldata is the constraint):** a **Groth16 re-prove** of the C1–C5
> relation (Circom/gnark) + ceremony + `snarkjs` Solidity verifier behind the *same* `IHonkVerifier`
> ABI → ~10× cheaper on-chain. Deferred by default (adds a second circuit + a trusted-setup ceremony).

---

## Open questions / caveats (verify before acting)

1. **Gas figures are benchmark/version-dependent.** UltraHonk ~2.4M and Groth16 ~200k are *bands*
   from specific circuits/`bb`/`snarkjs` versions; **re-measure** on the real v0-A circuit and target
   network. Arbitrum's **L1 data fee is omitted by local `anvil` forks** — measure on Sepolia.
2. **Honk verifier > 24 KB.** The generated `HonkVerifier` (~33 KB) exceeds Arbitrum One's EIP-170
   24 KB limit; plan the **optimized/library split** (only custom Orbit chains can raise to 96 KB).
3. **Pin `bb`.** UltraHonk had a security patch (≥ 0.82.2); the `--scheme` flag and keccak flavor are
   current-syntax but version-sensitive — pin `bb`/aztec-packages and re-confirm flags before M1.
4. **Stylus is a deliberate reserve, not the default.** It is neutral for a pairing check and its ZK
   tooling is experimental in mid-2026 (`zk-sunade` testnet; `noir-stylus-verifier` alpha). Revisit
   **only** for a STARK/FRI path or to optimize the Honk verifier's hash work.
5. **Garaga ≠ EVM.** Garaga emits **Cairo/Starknet** verifiers; do not plan it as the Arbitrum bridge.
   It is the cross-link to our Starknet recon, where it *is* the right tool.
6. **Phase-5 is orthogonal to this recon.** The gate is proof-system-agnostic; swapping the v0-A
   stand-in signature for the real RSA-2048+SHA-256 (de-risked in [`noir-recon.md`](noir-recon.md))
   changes the **circuit**, not the on-chain verification architecture.
7. **Synthetic only.** No real keys/PII anywhere; the deployment story assumes the same hard rule as
   every prior stack.

## Primary sources

- **Toolchain / chains:** [Arbitrum chain-info](https://docs.arbitrum.io/for-devs/dev-tools-and-resources/chain-info) · [Stylus mainnet launch](https://blog.arbitrum.io/arbitrum-stylus-mainnet/) · [stylus-sdk-rs releases](https://github.com/OffchainLabs/stylus-sdk-rs/releases) · [crates.io stylus-sdk](https://crates.io/crates/stylus-sdk/versions) · [Foundry v1.0](https://www.paradigm.xyz/2025/02/announcing-foundry-v1-0) · [solidity releases](https://github.com/ethereum/solidity/releases)
- **Precompiles / gas:** [OffchainLabs go-ethereum `contracts.go`](https://github.com/OffchainLabs/go-ethereum/blob/master/core/vm/contracts.go) · [Arbitrum precompiles](https://docs.arbitrum.io/build-decentralized-apps/precompiles/overview) · [EIP-1108](https://eips.ethereum.org/EIPS/eip-1108) · [L1 gas pricing](https://docs.arbitrum.io/how-arbitrum-works/l1-gas-pricing) · [Stylus gas metering](https://docs.arbitrum.io/stylus/concepts/gas-metering)
- **Noir / bb → Solidity verifier:** [barretenberg how-to-solidity-verifier](https://barretenberg.aztec.network/docs/how_to_guides/how-to-solidity-verifier/) · [noir-lang how-to-solidity-verifier](https://noir-lang.org/docs/dev/how_to/how-to-solidity-verifier) · [bb readme](https://github.com/AztecProtocol/aztec-packages/blob/master/barretenberg/cpp/src/barretenberg/bb/readme.md) · [base.dev ZKP benchmark](https://blog.base.dev/benchmarking-zkp-systems) · [Aztec forum on-chain UltraHonk PoC](https://forum.aztec.network/t/noir-rlwe-gadgets-verifiable-bfv-encryption-rlwe-in-noir-with-an-on-chain-ultrahonk-verifier/8591)
- **Groth16/PLONK:** [snarkjs](https://github.com/iden3/snarkjs) · [circom proving-circuits](https://docs.circom.io/getting-started/proving-circuits/) · [Orbiter verifier-gas benchmark](https://hackmd.io/@Orbiter-Research/S1nat__m0)
- **STARK-on-EVM / Garaga / wrapping:** [zksecurity stark-evm-adapter](https://blog.zksecurity.xyz/posts/stark-evm-adapter/) · [HerodotusDev/integrity](https://github.com/HerodotusDev/integrity) · [stwo-gnark-verifier](https://github.com/HerodotusDev/stwo-gnark-verifier) · [garaga](https://garaga.gitbook.io/garaga) · [aligned mina-bridge](https://blog.alignedlayer.com/mina-to-ethereum-bridge/)
- **Stylus ZK:** [supernovahs/zk-sunade](https://github.com/supernovahs/zk-sunade) · [OpenZeppelin Poseidon-on-Stylus](https://www.openzeppelin.com/news/poseidon-go-brr-with-stylus-cryptographic-functions-are-18x-more-gas-efficient-via-rust-on-arbitrum) · [wakeuplabs-io/noir-stylus-verifier](https://github.com/wakeuplabs-io/noir-stylus-verifier) · [Stylus call docs](https://docs.rs/stylus-sdk/latest/stylus_sdk/call/)

---
*Recon only. No full PoC written, nothing deployed; repo additions limited to [`../arbitrum/`](../arbitrum/)
(a compile-verified Solidity skeleton + an illustrative Stylus sketch) and this file. Next step (if
approved): **M1** — turn the existing Noir/UltraHonk circuit into an Arbitrum-deployed Solidity verifier
behind `FiscComplianceGate`, measured on Arbitrum Sepolia, with the Groth16 re-prove held in reserve as
a gas optimization.*
