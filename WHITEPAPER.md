# Zero-Knowledge Proofs of Fiscalization Compliance — PRIVA-FISC (v0-A)

*Working title. A v0-A architecture demonstration built on Mina / o1js. This document deliberately separates what the current prototype does from what remains to be built, and does not claim the prototype proves more than it does.*

---

## Summary

PRIVA-FISC is a minimum-disclosure layer over state-signed fiscal data. A business whose transactions are already fiscalized — reported to and attested by the tax authority — has no way today to let a third party (an insurer, a lender, a landlord) independently verify a fact about that data without handing over the underlying records wholesale. The state is the data source, not the client: the fiscal record already exists and already carries the authority's attestation; what is missing is a way to prove facts about it while disclosing nothing else. This design depends explicitly on the tax administration's signing infrastructure: PRIVA-FISC is designed to anchor to authority-issued signatures, and where such signatures do not exist it has nothing to anchor to.

PRIVA-FISC is a zero-knowledge protocol that proves the compliance-relevant facts of a fiscalized receipt — the VAT is computed correctly, the receipt carries a valid authority attestation, and the seller is a registered taxpayer — while keeping the sensitive commercial data (buyer identity, line-item detail, margin) hidden.

**v0-A** is a working proof-of-concept of this architecture on **synthetic data**, built on Mina/o1js. It demonstrates the end-to-end shape of the protocol and is adversarially soundness-tested. It deliberately **mocks** the cryptographic verification of the authority's real signature: verifying Montenegro's actual RSA-SHA256 + MD5 + XML-DSig signature chain inside a circuit is the heavy engineering reserved for the next phase. We are explicit about this boundary throughout.

---

## The problem: compliance vs. confidentiality

Live national fiscalization regimes — Montenegro, Croatia, Italy, Serbia, and others — require each transaction to be reported to the tax authority and made verifiable. By design, they *maximize* disclosure.

For a compliant business this creates a real dilemma whenever a private party needs assurance. Today the options are binary: expose the full records to obtain assurance, or offer no independent verification at all. Consent-based paths to share the data exist; what does not exist is a way to share *only the answer*. The design target is one proof carrying three claims at once: the state's signature verifies, the set is complete, and the predicate holds. Two of those three work today over a disclosed set — signature verification and predicate checks. Set-completeness — proving that a disclosed set is *all* of the relevant records, not a curated subset — is deliberately marked open: it is unsolved here, and it is the core research question of the project's next phase, pursued with the project's scientific advisor.

## The idea: selective disclosure

A zero-knowledge proof lets a provider prove only the properties that matter, while hiding everything else. Concretely, the prover convinces a private-party verifier (an insurer, a lender, a landlord, an auditor) that:

- the declared VAT equals the correct tax on the taxable base at the declared statutory rate;
- the receipt carries a valid attestation binding it to the tax authority;
- the seller's tax ID is a member of the registered-taxpayer set;

…without revealing the buyer, the line items, or the margin. The verifier learns that compliance holds — and nothing more.

## What is new here, and what is not

Zero-knowledge for regulatory compliance is **not new**, and we say so plainly. The space is active: a16z's 2022 work set out how zero-knowledge proofs enable *selective disclosure* for regulatory compliance, focused on AML / illicit-finance [1]; the academic *zkTax* system applies the same idea to tax records — a trusted tax service issues signed documents that users can redact and prove over — focused on US tax returns [2]; and more recent academic work applies ZK to other tax-compliance settings, such as location-based vehicle taxation [3]. The narrow, defensible novelty of PRIVA-FISC is the *combination*: ZK selective-disclosure applied to **state-signed, transaction-level fiscal data**. The live fiscalization regimes (Croatia, Montenegro, Serbia, Italy, and others) produce exactly such data; to our knowledge none has a minimum-disclosure layer on top, and the large commercial e-invoicing / VAT-compliance vendors automate submission rather than minimize disclosure.

We also name the real adoption dependency openly, because hiding it would be dishonest. In Montenegro the tax server returns a confirmation identifier (JIKR) after it validates a signed receipt — this is *not* a third-party-verifiable signature; the only verifiable signature in the chain is the seller's own. A fully trustless version of this protocol therefore depends on either (a) the authority issuing attestable, signed fiscal records, or (b) a trusted intermediary attesting them. This is the same structural dependency that zkTax relies on — its design assumes a trusted tax service that issues digitally signed documents [2] — and it is the principal real-world blocker. v0-A models the attestation with a stand-in key precisely so this dependency is visible rather than papered over.

## v0-A: what the prototype demonstrates

v0-A implements the protocol's relation as a Mina `ZkProgram` over **synthetic data** that mirrors the real Montenegrin EFI receipt schema in shape, with **zero real personal or fiscal data** (a hard rule: no real PII, no real taxpayer certificates, no real authority keys ever touch the prototype).

The circuit enforces four constraints:

- **C1 — Attestation binding.** The masked commitment and the receipt digest are bound, via an authority signature over a binding message, to a single attested receipt. The binding message also includes anti-replay fields, so an attestation cannot be lifted onto a different receipt. *(In v0-A the signature is a ZK-native scheme used as a stand-in — see scope below.)*
- **C2 — Commitment correctness.** A salted Poseidon commitment to the sensitive fields — the **seller's tax ID**, the buyer, the line-item sub-commitment, the margin, the amounts (taxable base, VAT, total) and the VAT rate — is published; the circuit proves the committed values are exactly those used in the rest of the proof. Binding the seller's tax ID here is what lets the seller stay hidden while still being committed.
- **C3 — VAT correctness.** The declared VAT equals the correct tax on the base at the declared rate, computed in **bounded integers with explicit range-checks** (so that field arithmetic cannot "wrap" to forge a false equality), with the rounding rule made explicit.
- **C4 — Anchored seller-membership.** The seller's tax ID is proven to be a member of the registered-taxpayer set (a Merkle tree), while the tax ID itself stays private. Crucially, the set's root is itself bound into the authority-signed binding message — so membership is *anchored* to the authority, not to a root the prover could fabricate. Without this anchoring, proving membership in a tree the prover built themselves would be vacuous.

A valid proof reveals only the commitment, the receipt digest, the registry root, and the authority public key. The sensitive fields never appear:

| Disclosed (public) | Hidden (private) | Proven |
|---|---|---|
| commitment `C`, receipt digest `D`, registry root, authority public key | buyer, line items, margin, seller's tax ID, amounts (base / VAT / total), VAT rate | VAT is correct · seller is registered · receipt is authority-attested and bound to `C` and `D` |

## What v0-A does **not** do (scope and honesty)

This is the most important section. v0-A is an architecture demonstration, not a finished compliance product.

- **It does not verify the real authority signature.** Montenegro's fiscalization uses RSA-SHA256 (PKCS#1 v1.5) + MD5 + enveloped XML-DSig. Verifying that chain *inside a circuit* — RSA-2048 modular exponentiation, SHA-256, MD5, and XML canonicalization — is heavy, and is **deferred to the next phase**. In v0-A the authority attestation is a ZK-native signature used as a stand-in; it provides **no real-world security** and is clearly labelled as such.
- **It does not recompute the receipt digest in-circuit.** The digest is taken as an *opaque public input*. The binding between the digest and the receipt's fields is asserted only through the attestation, not by recomputing the hash inside the circuit. Removing this trust assumption (recomputing the digest in-circuit) is part of the next phase.
- **It runs on synthetic data.** It does not prove that any real receipt was fiscalized. It proves that a receipt *of the right shape* satisfying the relation exists, on data we generated ourselves.
- **A linkability caveat.** v0-A takes the receipt digest as an *opaque public input* — it does not recompute the digest from the receipt's fields inside the circuit, so the digest is revealed. Because fiscalization regimes often expose public receipt-verification portals keyed by such identifiers, a revealed digest could in principle be linked back to the underlying receipt. The next phase closes this by recomputing the digest *in-circuit*, so the digest itself can stay private while its relationship to the commitment is still proven. (Note: v0-A's stand-in signature *is* verified inside the circuit — it is the **digest**, not the signature check, that is currently exposed.)
- **No double-submission / double-counting protection.** The anti-replay binding (C1) prevents an attestation from being *lifted onto a different receipt*, but it does **not** prevent the *same* proof or commitment from being submitted more than once. A nullifier scheme to prevent replay / double-counting of the same receipt is a later addition.

**On auditability.** Hiding commercial data from counterparties does not blind the tax authority: in this model the authority already holds the underlying receipt. For third parties, the committed fields (for example the seller's tax ID) can be *selectively opened* to an authorized auditor when required; a threshold / judicial-opening mechanism for richer, controlled audit is future work, not part of v0-A.

We deliberately do **not** describe v0-A as "proving correct fiscalization." It demonstrates the *binding architecture* for such a proof; the real signature verification is the funded next step.

## Soundness: adversarially tested

The prototype is not just exercised on the happy path. Every class of malformed receipt is **rejected** — proving cannot produce a valid proof for: an incorrect VAT figure, an unregistered seller, an out-of-range amount, a commitment that does not match the witnessed fields, or an invalid attestation. The anti-replay property is tested by tampering with a public value and confirming the proof fails.

The VAT constraint received specific attention. Euclidean-division constraints (quotient and remainder) are a classic soundness pitfall: both the quotient and the remainder must be range-bounded, or a malicious prover can satisfy the same equation with a different split. We constructed adversarial alternative witnesses — including ones using a *stronger-than-real* attacker who can forge and re-sign the commitment — and confirmed the circuit rejects every alternative VAT split, caught by both the commitment binding and the remainder range-check.

Beyond the proofs themselves, the prototype is built with anti-drift discipline: a single language-independent specification is the source of truth; the field-encoding order and the circuit-purity invariants are protected by fast regression guards; signing and commitment are deterministic and tested for determinism; and the VAT soundness is probed adversarially as above. The intent is disciplined engineering that can later be audited — not a throwaway demo.

## The hard part ahead: in-circuit signature verification

The genuinely novel and difficult engineering — and where the principal value lies — is verifying the **real** Montenegrin signature chain inside the circuit. An honest feasibility sketch (constraint counts are order-of-magnitude and must be measured, not assumed):

- **XML Exclusive-C14N stays out of circuit.** Byte-exact XML canonicalization in-circuit is impractical; the sound approach is to canonicalize off-circuit, commit to the canonical byte string, and prove the hash and signature over those committed bytes.
- **SHA-256 in-circuit** over the committed canonical bytes — well-trodden, on the order of tens of thousands of constraints per block.
- **RSA-2048 verification in-circuit** is the dominant cost: a 2048-bit modular exponentiation (helped substantially by the standard public exponent 65537, which is only ~17 bits), followed by checking the result against the PKCS#1 v1.5 encoded structure. Plausibly tens to low-hundreds of thousands of constraints depending on the proof system and limb strategy.
- **MD5 may be removable from the critical path.** The Montenegrin IKOF is an MD5 of the RSA signature — a human-verifiable display code, not an independent trust anchor. If the RSA signature itself is verified in-circuit, MD5 likely need not be proven in-circuit at all, which meaningfully reduces scope (no standard ZK gadget for MD5 exists).
- **Recursion** (a native strength of Mina/o1js) can split the SHA-256 and RSA work across composed proofs if a single circuit is too large.

This is the phase that turns the architecture into something that proves *real* fiscalization, and it is where the next phase of engineering and a security audit are focused.

## Team, and why this combination can reach real-world adoption

The defensible advantage is not "ZK for tax" in the abstract — that, as noted, is not novel. It is the combination of three things: direct cross-border fiscalization-law expertise, deep integration with one specific live regime (Montenegro's IKOF / JIKR / certificate chain — the anchor jurisdiction of this prototype), and a live multilingual service marketplace (Glatko — 42 verified providers across 8 cities, 99 registered users) as a distribution surface. That is an execution-and-distribution path, not only a research result.

The team reflects this. The founders, Rohat Kahraman and Nazlıcan Hilaloğulları, are cross-border tax and fiscalization lawyers and the founders of the legal practice behind the project — the source of its regulatory grounding and of the Montenegro integration. The engineering is led by Cemal Özçelik, a software engineer working with the team (not a founder), with a background spanning full-stack development, embedded systems, and computer vision / deep-learning applications, currently completing an MSc in Artificial Intelligence at Gebze Technical University; he is deepening into applied zero-knowledge and SNARK engineering — the area he will lead in the next phase, where the heavier in-circuit cryptographic work lives. Prof. Oğuz Yayla (METU) advises the project as scientific advisor on the cryptography, in weekly working sessions. The v0-A prototype was built by the founders with substantial AI assistance — an architecture demonstration rather than a finished system.

We are direct about the implication: the heaviest cryptographic engineering — verifying the real signature chain in-circuit — is work the team is taking on for the next phase, not work it has already shipped. We therefore treat an independent, third-party security audit (i.e. specialist cryptographic review) as an explicit milestone of that phase, not an afterthought. What v0-A already establishes is execution velocity: a small team, working with AI assistance, produced an end-to-end, adversarially-tested prototype with disciplined, regression-guarded engineering.

## Status

- **Off-chain proof-of-concept: working.** The circuit compiles; valid synthetic receipts produce proofs that verify; every malformed class is rejected; the foundation is locked against regression.
- **Testnet deployment: live on Mina Devnet.** A `FiscAnchor` zkApp wraps the circuit: it verifies a PRIVA-FISC proof *on-chain* and records only the resulting commitment in on-chain state. A valid synthetic proof was verified on-chain and its commitment anchored (the on-chain value matches the proof's commitment `C`).
  - zkApp account: https://minascan.io/devnet/account/B62qjhevpDt7BNjvt37JLqr9DVzA7Ewdoye48SbxaaY7vt9QK6X69Q6
  - Deploy transaction: https://minascan.io/devnet/tx/5Jtb4kX3ANjnqdaNsJVSShTb3dtiSe3KivscdaUK6Q5gU28mrpof?type=zk-tx
  - On-chain proof-verification transaction: https://minascan.io/devnet/tx/5JuG4rMNvzv7xWkodXdd4Q76wbTRWuegzYhkfdJBKW25LtFA3Bw9?type=zk-tx
- **Source: open-core, licensed under Apache-2.0.** The Montenegro-integration depth and the heavier cryptographic engineering are the team's defensible know-how, rather than the protocol itself.

---

*Honest-scope statement: v0-A demonstrates a signature-binding selective-disclosure architecture on synthetic data. In-circuit verification of the real RSA-SHA256 / MD5 / XML-DSig authority signature, in-circuit recomputation of the receipt digest, and a real registry anchor are the next phase. Nothing in this prototype should be read as a claim that real fiscalization has been cryptographically proven.*

---

## References

[1] J. Burleson, M. Korver, D. Boneh. *Privacy-Protecting Regulatory Solutions Using Zero-Knowledge Proofs.* a16z crypto, Nov. 2022. https://a16zcrypto.com/posts/article/privacy-protecting-regulatory-solutions-using-zero-knowledge-proofs-full-paper/

[2] A. Berke, T. South, R. Mahari, K. Larson, A. Pentland. *zkTax: A Pragmatic Way to Support Zero-Knowledge Tax Disclosures.* MIT Media Lab & Harvard Law School. Poster, Proc. ACM CCS 2024 (4 pp.). arXiv:2311.13008. https://arxiv.org/abs/2311.13008

[3] D. Bogdanov, E. Brito, A. Jaakson, P. Laud, R-M. Rebane. *Zero-Knowledge Proof-of-Location Protocols for Vehicle Subsidies and Taxation Compliance.* Cybernetica AS & University of Tartu, 2025. arXiv:2506.16812. https://arxiv.org/abs/2506.16812
