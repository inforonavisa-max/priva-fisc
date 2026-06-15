// PRIVA-FISC v0-A — Leo port of the FiscProof relation (SPEC §7 C1–C5).
// ============================================================================
// Source of truth: ../../spec/SPEC.md (the relation) + ../../docs/aleo-recon.md
// (the Leo native-primitive mapping). Leo 4.2.0. SYNTHETIC DATA ONLY.
// See ./README.md for scope, honesty limits, and the C1–C5 ↔ SPEC table.
//
// Layout (Leo 4.2.0): helper fns + structs live OUTSIDE `program {}`; the two
// entry transitions live INSIDE. Native primitives (verified in recon):
//   Poseidon2::hash_to_field(struct)  — C1/C2/C4 hashing (Edwards-BLS12-377 base field)
//   signature::verify(sig, addr, msg) — C1 Schnorr verify; signer = an Aleo `address`

// ── Private witness (SPEC §6 private set; PRE-ENCODED synthetic fields) ──────
// Comment marks WHICH constraint each field feeds — used to isolate negatives.
struct Witness {
    seller_tin: field,    // §4 private (also C4 leaf)        — C2 + C4
    buyer_id: field,      // §4 private (personal data)       — C2 only
    enc_datetime: field,  // anti-replay binding              — C1 only
    enc_invoice: field,   // anti-replay binding              — C1 only
    items: field,         // H(line_items) sub-commitment     — C2 only
    margin: u64,          // §4 private                       — C2 only
    vat_base: u64,        // net base (cents)                 — C2 + C3
    vat_amount: u64,      // VAT (cents)                      — C2 + C3
    rate_bp: u64,         // statutory rate (basis points)    — C2 + C3
    total: u64,           // gross (cents)                    — C2 + C3
    r: u64,               // VAT round-half-up remainder      — C3 only
    salt: field,          // commitment hiding randomness     — C2 only
}

// Poseidon preimages (struct-typed; domain-separated by a leading DS tag).
// DS tags mirror Mina src/encoding.ts: COMMIT=2, LEAF=3, ATTEST=5.
struct CommitPre {
    ds: field, seller_tin: field, buyer_id: field, items: field, margin: field,
    vat_base: field, vat_amount: field, rate_bp: field, total: field, salt: field,
}
struct MPre {
    ds: field, d_hi: field, d_lo: field, c: field, root: field, datetime: field, invoice: field,
}
struct LeafPre { ds: field, tin: field }
struct NodePre { left: field, right: field }

// C2 — Poseidon commitment over all sensitive fields, salt IN the preimage
// (salted hash; recon confirmed Leo has no native Poseidon `commit`, so the
// v0-A salted-hash commitment maps to a native Poseidon hash 1:1).
fn commit_c(w: Witness) -> field {
    return Poseidon2::hash_to_field(CommitPre {
        ds: 2field,
        seller_tin: w.seller_tin,
        buyer_id: w.buyer_id,
        items: w.items,
        margin: w.margin as field,
        vat_base: w.vat_base as field,
        vat_amount: w.vat_amount as field,
        rate_bp: w.rate_bp as field,
        total: w.total as field,
        salt: w.salt,
    });
}

// C4 — registry leaf = H(DS_LEAF, seller_tin); seller_tin stays private (§5.1).
fn leaf_of(seller_tin: field) -> field {
    return Poseidon2::hash_to_field(LeafPre { ds: 3field, tin: seller_tin });
}

// C4 — fold a fixed-depth Merkle path (height 8 ⇒ 7 siblings) up to the root.
fn fold_root(leaf: field, siblings: [field; 7], path_bits: [bool; 7]) -> field {
    let node: field = leaf;
    for i: u8 in 0u8..7u8 {
        // path_bits[i] == true ⇒ `node` is the RIGHT child at level i.
        node = path_bits[i]
            ? Poseidon2::hash_to_field(NodePre { left: siblings[i], right: node })
            : Poseidon2::hash_to_field(NodePre { left: node, right: siblings[i] });
    }
    return node;
}

// C1 — attestation binding message
//   M = H(DS_ATTEST, D_hi, D_lo, C, R_reg, datetime, invoice_no).
// Binds the public (D,C,R_reg) with private anti-replay fields so the
// attestation cannot be lifted onto a different receipt.
fn binding_message(d_hi: field, d_lo: field, c: field, root: field, w: Witness) -> field {
    return Poseidon2::hash_to_field(MPre {
        ds: 5field, d_hi: d_hi, d_lo: d_lo, c: c, root: root,
        datetime: w.enc_datetime, invoice: w.enc_invoice,
    });
}

program priva_fisc_v0a.aleo {
    @noupgrade
    constructor() {}

    // ── prove: the v0-A relation (SPEC §7 C1–C5). A verifying execution IS the statement. ──
    // PUBLIC statement: authority (PK_A modeled as an Aleo address), sellers_root (R_reg),
    //   D as two opaque limbs (d_hi,d_lo), commitment c.
    // PRIVATE witness: w, sig (σ_rcpt over M), Merkle siblings + path_bits.
    fn prove(
        public authority: address,
        public sellers_root: field,
        public d_hi: field,
        public d_lo: field,
        public c: field,
        w: Witness,
        sig: signature,
        siblings: [field; 7],
        path_bits: [bool; 7],
    ) {
        // ── C1 — attestation validity + anti-replay (SPEC §7-C1) ──
        // Recompute M from public (d_hi,d_lo,c,sellers_root) + private (datetime,invoice),
        // then verify σ over M. Signer is an Aleo `address` (native Schnorr binds to an
        // account address — the resolved authority-key design, see aleo-recon.md).
        let m: field = binding_message(d_hi, d_lo, c, sellers_root, w);
        assert(signature::verify(sig, authority, m));
        // ── C5 — D opaque (SPEC §7-C5 LIMIT): d_hi/d_lo enter ONLY M; never recomputed
        //         in-circuit (no SHA-256). Same documented soundness limit as Mina v0-A. ──

        // ── C2 — commitment correctness (SPEC §7-C2): published c == H(sensitive…, salt). ──
        assert_eq(commit_c(w), c);

        // ── C3 — VAT correctness, bounded integers (SPEC §7-C3). ──
        let max_cents: u64 = 4503599627370495u64; // 2^52 - 1 (MAXBITS=52, src/encoding.ts)
        assert(w.vat_base <= max_cents);
        assert(w.vat_amount <= max_cents);
        assert(w.total <= max_cents);
        assert(w.margin <= max_cents);
        // statutory rate ∈ {0, 700, 2100} bp (§5.3 statutory-set; OR ≡ Mina's product-of-roots).
        assert(w.rate_bp == 0u64 || w.rate_bp == 700u64 || w.rate_bp == 2100u64);
        // round-half-up: vat_amount = floor((vat_base*rate_bp + 5000)/10000)
        //   ⇔ vat_amount*10000 + r == vat_base*rate_bp + 5000,  0 <= r < 10000.
        // u128 headroom: 2^52 * 2100 ≈ 9.46e18 < 2^64, so no overflow.
        assert(w.r < 10000u64);
        let lhs: u128 = (w.vat_amount as u128) * 10000u128 + (w.r as u128);
        let rhs: u128 = (w.vat_base as u128) * (w.rate_bp as u128) + 5000u128;
        assert_eq(lhs, rhs);
        // consistency: total == vat_base + vat_amount (checked u64 add).
        assert_eq(w.total, w.vat_base + w.vat_amount);

        // ── C4 — anchored Merkle membership (SPEC §7-C4). ──
        // leaf recomputes to sellers_root; the root is anchored by C1 (root ∈ M ⇒
        // authority-fixed, SPEC §11.3 single-signature option). seller_tin stays private (§5.1).
        let leaf: field = leaf_of(w.seller_tin);
        assert_eq(fold_root(leaf, siblings, path_bits), sellers_root);
    }

    // ── prepare: TEST-ONLY witness→public derivation (NOT part of the proven statement). ──
    // Returns (c, root, m) so the test harness can publish c/root and sign m with the
    // synthetic authority key. Production/Phase-5 would remove this; it exists only so
    // run_tests.sh can build self-consistent Aleo-Poseidon public inputs for a witness.
    fn prepare(
        d_hi: field,
        d_lo: field,
        w: Witness,
        siblings: [field; 7],
        path_bits: [bool; 7],
    ) -> (field, field, field) {
        let c: field = commit_c(w);
        let root: field = fold_root(leaf_of(w.seller_tin), siblings, path_bits);
        let m: field = binding_message(d_hi, d_lo, c, root, w);
        return (c, root, m);
    }
}
