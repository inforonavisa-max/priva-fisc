# PRIVA-FISC — Circuit Specification (v0)

> **Status:** PLACEHOLDER — pending draft (this is the next step).

This document will hold the **language-agnostic circuit specification**:

- **Public / private input–output** definitions.
- **Constraint list:**
  - in-circuit signature verification (full or **hybrid** stand-in),
  - masked-commitment binding to the verified signature,
  - **anchored** tax-ID (PIB) Merkle membership — the root must be anchored to an
    authority signature/attestation, not a self-built tree,
  - **bounded-integer** VAT-correctness check (avoid prime-field wrap-around).
- **Feasibility note:** RSA-in-circuit (RSA-2048 modexp + SHA-256 + MD5 + XML
  Exclusive C14N) constraint-count / proving-time estimate.

**Scope discipline:** v0 demonstrates the signature-binding architecture on
**synthetic** data. Real in-circuit RSA-SHA256 verification over the actual
Montenegro certificate chain is explicitly **deferred to Phase 5 / R&D**.
