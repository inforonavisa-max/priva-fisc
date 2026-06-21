# PRIVA-FISC on Arbitrum — working PoC (Noir proof verified on-chain by an EVM contract)

**What this proves (the single net claim):** the **existing** PRIVA-FISC Noir circuit's
zero-knowledge proof is verified **on-chain by an EVM contract** — the Arbitrum bridge the
[recon](../../docs/arbitrum-recon.md) recommended (Route A: Noir/UltraHonk → bb Solidity
verifier), demonstrated end-to-end on a local EVM, with the real bb artifacts committed.

> **SYNTHETIC DATA ONLY.** No real keys, PII, or fiscal data. The proven relation is the
> v0-A stand-in (Schnorr attestation), exactly as in every other PRIVA-FISC stack.

## What runs green

`forge test` (local EVM), 4/4 passing — the real bb-generated proof + verifier:

| Test | Asserts | Gas |
|---|---|---|
| `test_Positive_RawVerifierAcceptsValidProof` | the bb `HonkVerifier` **accepts the valid proof on-chain** | `verify` = **2,808,474** |
| `test_Positive_GateAcceptsAndRecordsCommitment` | `FiscComplianceGate.submitProof` verifies + **returns commitment `C`** (end-to-end) | 3,115,252 |
| `test_Negative_TamperedPublicInputRejected` | flip one bit of `C` → proof **rejected** | — |
| `test_Negative_GateRejectsWrongAuthorityKey` | gate pinned to a wrong `PK_A` → **reverts** before verifying | — |

The measured **2.81M gas** for `HonkVerifier.verify` confirms the recon's ~2.4M estimate
(the ZK/keccak flavor + 6 public inputs land it slightly higher).

## The circuit is UNMODIFIED

`circuit/` is a **verbatim copy** of [`noir/v0a_skeleton`](../../noir/v0a_skeleton) — byte-identical:

```
$ shasum -a256 noir/v0a_skeleton/src/main.nr arbitrum/poc/circuit/src/main.nr
bbc25e3e… …/noir/v0a_skeleton/src/main.nr
bbc25e3e… …/arbitrum/poc/circuit/src/main.nr   # same hash
```

The copy keeps `noir/` strictly read-only and all writes under `arbitrum/`. Nothing in the
proven relation changed; we only built a **valid witness** and the EVM verifier around it.

## Layout

```
arbitrum/poc/
├── circuit/            # verbatim copy of noir/v0a_skeleton (UNMODIFIED) + generated Prover.toml
├── helper/             # Noir helper: recomputes Poseidon2/Grumpkin values for the witness
├── scripts/
│   ├── gen_inputs.py   # builds a VALID witness (finishes the Schnorr signature off-circuit)
│   └── deploy_sepolia.sh   # DELEGATED: deploy + on-chain verify tx (needs a funded key)
├── artifacts/          # committed evidence: HonkVerifier.sol, vk, proof, public_inputs, calldata.json
└── foundry/            # forge test: positive + negative, reads the real proof from artifacts/
```

## How the witness is built (the recon's open "port deliverable", now closed)

The recon flagged that C1 needs a real off-circuit **Grumpkin Schnorr signature** over the
binding message `M`. `schnorr v0.4.0` is Poseidon2-based:

```
e = Poseidon2([DST, R.x, P.x, P.y, M], 5),   verify: s·G + e·P == R  and  e' == e
```

So we sign with secret `sk` (`P = sk·G`), nonce `k` (`R = k·G`), and `s = (k − e·sk) mod n`
(`n` = Grumpkin group order = BN254 base field). All Poseidon2/Grumpkin values (`P`, `R.x`,
`C`, registry root, `M`, `e`) are computed by the **Noir helper** (same libraries ⇒ exact
match); `scripts/gen_inputs.py` finishes `s` and writes `circuit/Prover.toml`. The unmodified
circuit then accepts it (`nargo execute` → `Circuit witness successfully solved`).

## Reproduce (local)

Prereqs: `nargo 1.0.0-beta.22`, `bb 5.0.0-nightly.20260522` (`~/.nargo/bin`, `~/.bb`),
`forge 1.7+`.

```bash
cd arbitrum/poc

# 1) valid synthetic witness for the UNMODIFIED circuit (runs the Noir helper, finishes Schnorr)
python3 scripts/gen_inputs.py
( cd circuit && nargo execute )                      # -> circuit/target/witness.gz

# 2) EVM/keccak-flavor VK + proof from the SAME circuit  (bb: -t evm == keccak + ZK)
cd circuit
bb write_vk -b target/priva_fisc_v0a.json            -t evm -o ../artifacts/vk
bb prove    -b target/priva_fisc_v0a.json -w target/witness.gz -k ../artifacts/vk/vk -t evm -o ../artifacts/proof
bb verify   -k ../artifacts/vk/vk -p ../artifacts/proof/proof -i ../artifacts/proof/public_inputs -t evm   # native: ok

# 3) Solidity verifier from the VK
bb write_solidity_verifier -k ../artifacts/vk/vk -t evm -o ../artifacts/HonkVerifier.sol
cd ..

# 4) on-chain verification (local EVM): positive + negative
cd foundry && forge test -vv
```

## Honest notes / findings

- **bb flag drift (vs the recon doc).** The recon documented `bb write_solidity_verifier
  --scheme ultra_honk` + `--oracle_hash keccak` (an older bb). The **installed** bb
  `5.0.0-nightly.20260522` replaced these with **`-t evm`** (`evm` = keccak + ZK). Same
  result, current syntax. (The recon flagged "exact flag set is version-dependent" — confirmed.)
- **Public inputs:** the circuit declares **6** (`pk_x, pk_y, sellers_root, d_hi, d_lo, c`);
  the verifier reports `NUMBER_OF_PUBLIC_INPUTS = 14` (6 + an 8-element pairing-point object
  carried inside the proof). `verify(proof, publicInputs)` expects **exactly the 6** — which
  is what `artifacts/proof/public_inputs` (192 bytes) contains, in gate-expected order.
- **Verifier size:** runtime bytecode is **17,952 bytes < 24,576 (EIP-170)** → deploys on
  Arbitrum Sepolia/One **as-is**. (The recon's ~33 KB caveat was for a larger circuit; our
  small v0-A circuit's verifier fits without `--optimized`.)
- **Proof size:** 7,616-byte proof (238 field elements) — on a real L2 this is the calldata
  the recon flagged as the L1 data-fee swing cost.

## Bonus: Arbitrum Sepolia deploy (DELEGATED — faucet is a human gate)

`scripts/deploy_sepolia.sh` deploys `HonkVerifier` + `FiscComplianceGate` and sends one
`submitProof` tx (on-chain verification, like the Mina FiscAnchor evidence). It needs a
**funded** Arbitrum Sepolia key; obtaining test-ETH requires a faucet captcha/login (a human
gate this PoC does not bypass). To complete it:

```bash
# fund a fresh key via a standard Arbitrum Sepolia faucet (Alchemy / QuickNode / Chainlink), then:
PRIVATE_KEY=0x<funded-key> ./scripts/deploy_sepolia.sh
# prints HonkVerifier addr, gate addr, and the verification tx hash + sepolia.arbiscan.io links
```

Local EVM verification (above) is the DoD; the Sepolia tx is optional persistent evidence.
