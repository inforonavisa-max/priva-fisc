# `arbitrum/` — recon skeleton (NOT a full PoC)

Minimal artifacts supporting [`../docs/arbitrum-recon.md`](../docs/arbitrum-recon.md). **Synthetic
data only; no real keys/PII; nothing deployed.**

```
arbitrum/
├── solidity/src/
│   ├── IHonkVerifier.sol        # ABI of the bb-generated proof verifier (verify(bytes,bytes32[])→bool)
│   ├── MockHonkVerifier.sol     # non-crypto stand-in so the gate wires end-to-end (NO security)
│   ├── FiscComplianceGate.sol   # EVM analogue of the Mina FiscAnchor: verify + record commitment C
│   └── CompliantPaymentFlow.sol # reference financial-dApp: a stablecoin transfer gated on a proof
└── stylus/                      # illustrative Stylus (Rust/WASM) sketch — NOT compiled (no Rust toolchain)
    ├── Cargo.toml
    └── src/lib.rs
```

**Solidity = [verified locally]** (`solc 0.8.35`, optimizer, `evmVersion=cancun`, **0 errors / 0
warnings**). The compiler was installed to a temp dir **outside the repo**; only the `.sol` sources
live here. The real `HonkVerifier.sol` is generated from the Noir circuit's VK
(`bb write_solidity_verifier --scheme ultra_honk`) and replaces `MockHonkVerifier` 1:1.

**Stylus = illustrative only**, uncompiled — for a BN254 pairing verifier Stylus is *neutral* vs
Solidity (both call the `ecPairing` precompile). See the recon's Task A.4 / Task F for why Solidity is
the recommended path and Stylus is the reserve (STARK/FRI or hash-heavy futures).

Reuses, unchanged, the existing Noir circuit at
[`../noir/v0a_skeleton/src/main.nr`](../noir/v0a_skeleton/src/main.nr) — public-input layout
`[pk_x, pk_y, sellers_root, d_hi, d_lo, c]`.
