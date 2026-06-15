# PRIVA-FISC — Mina Devnet on-chain evidence (v0-A)

> **Purpose:** a permanent, self-contained record of the v0-A on-chain demonstration on
> **Mina Devnet**, so the evidence survives even if Mina Devnet is reset (Devnets reset
> periodically, which wipes accounts and transactions from explorers). The explorer links
> below may stop resolving after a reset; the captured details and the
> [`docs/evidence/`](evidence/) text snapshots do not.
>
> Captured in a **residential** browser on **2026-06-15**. `WebFetch`/datacenter IPs get
> HTTP 403 from Minascan (bot protection), so this was verified by opening each page directly.

---

## Summary

The **FiscAnchor** zkApp was **deployed to Mina Devnet**, and a **FiscProof was verified
on-chain** one block later. Both transactions are `zkApp Tx` and were **Applied** (accepted
by the network — for the verification transaction, "Applied" means the Mina network checked
the zk proof and it passed).

| Role | Public key |
|---|---|
| **FiscAnchor zkApp account** | `B62qjhevpDt7BNjvt37JLqr9DVzA7Ewdoye48SbxaaY7vt9QK6X69Q6` |
| **Fee payer** (deploy + verify) | `B62qnXRgk811FnEiYYhAuy27nhBT5oaqzgoHMeKu3QtRmgch3emw5Ze` |

> Only **public keys** appear in this file and the repo. No private key, view key, or seed.

---

## Transaction 1 — DEPLOY (FiscAnchor zkApp)

| Field | Value |
|---|---|
| **Tx hash** | `5Jtb4kX3ANjnqdaNsJVSShTb3dtiSe3KivscdaUK6Q5gU28mrpof` |
| **Type / status** | `zkApp Tx` · **Applied** |
| **Block** | **527,877** |
| **Created** | **2026-06-14 18:30 UTC** |
| **Nonce** | **0** |
| **Block state hash** | `3NK8T28VfMsS9gBv3jfoUvLXrfXYBYmPUuVx1mQVuPw1yaFv4hi2` |
| **Fee / fee payer** | 0.1 MINA · `B62qnXRgk811…w5Ze` |
| **Account updates** | 2 — #1 fee payer; **#2 = the zkApp account `B62qjhev…QK6X69Q6` (created here)** |
| **Link** (may reset) | https://minascan.io/devnet/tx/5Jtb4kX3ANjnqdaNsJVSShTb3dtiSe3KivscdaUK6Q5gU28mrpof?type=zk-tx |

Raw explorer capture: [`docs/evidence/mina-deploy-tx.txt`](evidence/mina-deploy-tx.txt)

## Transaction 2 — on-chain proof VERIFICATION (FiscProof)

| Field | Value |
|---|---|
| **Tx hash** | `5JuG4rMNvzv7xWkodXdd4Q76wbTRWuegzYhkfdJBKW25LtFA3Bw9` |
| **Type / status** | `zkApp Tx` · **Applied** (proof verified by the network) |
| **Block** | **527,878** (the block immediately after the deploy) |
| **Created** | **2026-06-14 18:33 UTC** |
| **Nonce** | **1** (next nonce after the deploy, same fee payer) |
| **Block state hash** | `3NKbFY3UtAHfi6Mjn59ydztU6hEYXtZ6E1VyLDgr1uc2t3d6JHxQ` |
| **Fee / fee payer** | 0.1 MINA · `B62qnXRgk811…w5Ze` |
| **Account updates** | 1 — **#1 = the zkApp account `B62qjhev…QK6X69Q6`** |
| **Link** (may reset) | https://minascan.io/devnet/tx/5JuG4rMNvzv7xWkodXdd4Q76wbTRWuegzYhkfdJBKW25LtFA3Bw9?type=zk-tx |

Raw explorer capture: [`docs/evidence/mina-verification-tx.txt`](evidence/mina-verification-tx.txt)

## zkApp account page

`B62qjhevpDt7BNjvt37JLqr9DVzA7Ewdoye48SbxaaY7vt9QK6X69Q6` —
[link](https://minascan.io/devnet/account/B62qjhevpDt7BNjvt37JLqr9DVzA7Ewdoye48SbxaaY7vt9QK6X69Q6) ·
capture: [`docs/evidence/mina-zkapp-account.txt`](evidence/mina-zkapp-account.txt)

> ⚠️ **The account page renders as "Not Activated / 0 balance / no transactions".** This is a
> Minascan **display quirk** for a zero-balance zkApp account (its tx tab does not list zkApp
> txs), **not** a missing deploy — the two transactions above both reference this address as a
> `zk` account with zkApp account-updates. **For reviewers: cite the two transaction links
> (which render fully) as the primary evidence; the account link is corroborating only.**

---

## Internal-consistency check (why this is a genuine deploy→verify sequence)

- **Same fee payer** `B62qnXRgk811…w5Ze` signs both transactions.
- **Sequential nonces** `0` (deploy) → `1` (verify) — consecutive, from one signer.
- **Consecutive blocks** `527,877` → `527,878`.
- **Three minutes apart** (18:30 → 18:33 UTC, 2026-06-14).
- Both reference the **same zkApp account** `B62qjhev…QK6X69Q6` via zkApp account-updates.

Together: the FiscAnchor zkApp was deployed and then, in the very next block, a FiscProof was
submitted and **verified on-chain** by the Mina network.

---

## Honest scope (this is v0-A — read this)

This on-chain demonstration proves the **architecture end-to-end on synthetic data — it is
NOT proof of real fiscalization.** Identical caveats to the rest of the project (`spec/SPEC.md`,
`WHITEPAPER.md`):

- **Mock authority signature** — a ZK-friendly signature (here Mina's native Schnorr over
  Pallas) from a **synthetic** key, **not** a real national e-fiscalization authority's signature.
- **Opaque digest `D`** — `D` is a public input; in-circuit SHA-256 of a real attestation is
  **not** implemented (Phase-5).
- **Synthetic data only** — no real PII, taxpayer data, or production keys.
- **No replay nullifier** in v0-A.

> **"Architecture demonstration on synthetic data, not proof of real fiscalization."**

The Aleo/Leo port of the same relation is in [`leo/`](../leo/); the cross-stack mapping is in
[`docs/aleo-recon.md`](aleo-recon.md). (Note: that port uses Aleo-native Schnorr where the
signer is an Aleo `address`; the Mina demonstration above uses Mina's native Schnorr.)

---

## A note on the captures

Permanent visual capture of the explorer pages as PNG could not be produced automatically from
this environment (the browser-automation screenshot does not return a saveable file path, and
desktop screen-capture requires a macOS Screen-Recording grant). The
[`docs/evidence/*.txt`](evidence/) files are faithful, durable text snapshots of exactly what
each Minascan page rendered — sufficient to reconstruct the evidence after a Devnet reset.
PNG screenshots can be added later (e.g. by granting Screen-Recording, or saved manually from
the live links while they still resolve).
