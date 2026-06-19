# PRIVA-FISC — Noir / Aztec reconnaissance artifacts

> **Variant:** v0-A · **Stack:** Noir / Nargo `1.0.0-beta.22` (Barretenberg `bb` backend) · **Status:** RECON — both crates **compile locally**; **nothing deployed**, no full port.
> **Source of truth:** [`../spec/SPEC.md`](../spec/SPEC.md) (the relation) + [`../docs/noir-recon.md`](../docs/noir-recon.md) (the Noir native-primitive mapping + RSA feasibility).

This directory holds the **minimal compile probes** that back [`../docs/noir-recon.md`](../docs/noir-recon.md).
It is **not** a port. The Mina/o1js [`../src/`](../src/) and Leo [`../leo/`](../leo/) implementations are
untouched. Per SPEC §12, the Poseidon commitment is field-specific (Noir uses the **BN254**
scalar field), so this stack's `C`/`M`/root values would be its own — not comparable to the
Mina (Pallas) or Aleo (Edwards-BLS12-377) values.

## What is here

| Crate | Purpose | Verified |
|---|---|---|
| [`v0a_skeleton/`](v0a_skeleton/src/main.nr) | The v0-A relation (SPEC §7 **C1–C5**) skeleton — Schnorr + Poseidon2 commitment + bounded-int VAT + Merkle fold + opaque `D`. Mirrors [`../leo/src/main.leo`](../leo/src/main.leo) and [`../src/circuit.ts`](../src/circuit.ts). | `nargo info` → **143 ACIR opcodes** |
| [`phase5_rsa_probe/`](phase5_rsa_probe/src/main.nr) | The **Phase-5 feasibility** artifact: in-circuit **SHA-256 → RSA-2048 PKCS#1 v1.5 verify** via the maintained **`zkpassport/noir_rsa` v0.11.1** (+ `noir-bignum` v0.10.0, `sha256` v0.3.0). | `nargo info` → **3 136 ACIR**; `bb gates` → **35 992 UltraHonk gates** |

## Honesty envelope (same as Mina/Leo v0-A)

- ✅ Authority attestation = a **ZK-friendly signature** — here Noir's **Schnorr over Grumpkin** (`schnorr::verify_signature`), message = a single `Field` `M` (matches v0-A exactly). The signer is an embedded-curve public key (`pk_x,pk_y`) — **more like Mina's arbitrary `PublicKey` than Aleo's account-`address`** constraint.
- ✅ Privacy/masking = a **Poseidon2 commitment** `C`, salt in the preimage (no native Poseidon `commit` — same as Mina/Leo).
- ⚠️ The receipt digest **`D` is disclosed and opaque** (two public limbs); **not** recomputed in-circuit in `v0a_skeleton`. SHA-256-in-circuit is **Phase-5** — and unlike Mina/Leo (where SHA-256 is *not* native), in Noir it is an available, benchmarked library primitive (`phase5_rsa_probe` demonstrates the full chain).

**These crates use NO real PII or keys** — only synthetic test vectors (the RSA modulus/signature
are lifted verbatim from `noir_rsa`'s own `bench.nr`, "Hello World! This is Noir-RSA"). Same
**stated** limits as Mina/Leo v0-A: `D`-disclosure (SPEC §1.2) and no replay nullifier (SPEC §12).

**Not a full port:** a green witness **execution** of `v0a_skeleton` needs an off-circuit
Schnorr signer keyed to the in-circuit `M`; a green execution of `phase5_rsa_probe` needs the
Barrett `redc_param` regenerated for `noir-bignum` v0.10.0 (the bundled bench vector is an
older encoding). Both are witness-generation tasks for the port, not feasibility blockers —
**compilation + gate-count is the recon bar**, and both clear it.

## Reproduce

```bash
# toolchain (installs to ~/.nargo, ~/.bb — outside this repo)
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash && noirup
bbup --noir-version "$(nargo --version | sed -n 's/nargo version = //p')"

nargo info  --program-dir noir/v0a_skeleton        # 143 ACIR
nargo info  --program-dir noir/phase5_rsa_probe     # 3 136 ACIR
nargo compile --program-dir noir/phase5_rsa_probe
bb gates -b noir/phase5_rsa_probe/target/phase5_rsa_probe.json   # 35 992 gates
```
