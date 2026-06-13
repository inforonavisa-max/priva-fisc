# PRIVA-FISC — PoC (Mina / o1js)

**PRIVA-FISC** is a zero-knowledge protocol that proves a service transaction was
correctly fiscalized — VAT computed correctly, receipt structurally valid, seller
tax-ID registered — **without revealing the private commercial data behind it**
(buyer identity, item-level detail, margins). This repository is the **v0
proof-of-concept** on the Mina protocol using **o1js** (TypeScript).

---

## ⚠️ Honest scope — read this first

This v0 PoC is a **prototype of the signature-binding _architecture_**, demonstrated
on **synthetic data**. To be explicit about what it does and does **not** do:

- ❌ **It does NOT perform real in-circuit RSA verification** of Montenegro's actual
  fiscal signature chain. Montenegro e-fiscalization uses **RSA-SHA256 (PKCS#1 v1.5) +
  MD5 + enveloped XML-DSig (Exclusive C14N)**. Verifying that real signature inside a
  ZK circuit (RSA-2048 modexp + SHA-256 + MD5 + XML canonicalization) is heavy and is
  **explicitly deferred to Phase 5 / R&D**.
- ❌ **It does NOT prove that any real receipt was fiscalized** or accepted by the Tax
  Administration. v0 operates on synthetic, self-generated inputs.
- ✅ **It DOES demonstrate the selective-disclosure architecture** end-to-end: binding
  a masked commitment to a (synthetic-format) signature, an *anchored* tax-ID
  membership check, a bounded-integer VAT-correctness constraint, and on-chain proof
  verification — so the *shape* of the full protocol is shown.

We deliberately do **not** claim this PoC "proves correct fiscalization." It shows the
architecture that a fully-funded build would extend to real signatures. Overstating
what a demo proves is itself a misrepresentation we refuse to make.

---

## 🔒 Data policy — synthetic only

**Zero real data.** No real personal data (PII), no real taxpayer certificates, no
real Tax Administration keys, and no real third-party customer or fiscal data ever
enter this repository or any demo. All inputs are **synthetic**, schema-shaped test
fixtures generated locally. Secrets/keys/certs are git-ignored and never committed.

---

## Layout

```
src/             circuit + helpers          (placeholder until SPEC.md is approved)
src/synthetic/   synthetic EFI receipt +
                 certificate generator      (placeholder)
spec/SPEC.md     language-agnostic circuit
                 specification              (placeholder — next step)
test/            tests                      (placeholder)
```

## Stack

- **o1js** `2.15.0` — Mina protocol ZK framework (TypeScript)
- **TypeScript** (strict, ESM) · **Node.js** ≥ `18.14.0`

## Status

Scaffold only. **No circuit code yet** — implementation begins after `spec/SPEC.md`
is drafted and approved. **Next step: draft `spec/SPEC.md`.**

## License

Not yet licensed. The open-source vs. proprietary decision is pending. Until then this
code is **private / all rights reserved** — do not redistribute.
