//! PRIVA-FISC v0-A — Noir skeleton of the FiscProof relation (SPEC §7 C1–C5).
//! RECON SKELETON: compiles on nargo 1.0.0-beta.22; SYNTHETIC DATA ONLY.
//! Mirrors leo/src/main.leo and src/circuit.ts. Native primitives verified in
//! docs/noir-recon.md: Poseidon2 (poseidon v0.3.0) for C1/C2/C4 hashing;
//! Schnorr over Grumpkin (schnorr v0.4.0) for C1 — message = single Field M,
//! matching v0-A exactly. NOT a full port: a green witness EXECUTION needs an
//! off-circuit Schnorr signer keyed to the in-circuit M (the port deliverable).
use poseidon::poseidon2::Poseidon2;
use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar};

// Domain-separation tags (mirror src/encoding.ts / leo: COMMIT=2, LEAF=3, ATTEST=5).
global DS_COMMIT: Field = 2;
global DS_LEAF: Field = 3;
global DS_ATTEST: Field = 5;

global MAX_CENTS: u64 = 4503599627370495; // 2^52 - 1 (MAXBITS=52, src/encoding.ts)
global DENOM: u64 = 10000;
global BIAS: u64 = 5000;

// C2 — Poseidon2 commitment over all sensitive fields; salt IN the preimage
// (salted hash == native commitment; recon: Noir has no native Poseidon `commit`).
fn commit_c(
    seller_tin: Field, buyer_id: Field, items: Field, margin: u64, vat_base: u64,
    vat_amount: u64, rate_bp: u64, total: u64, salt: Field,
) -> Field {
    Poseidon2::hash(
        [
            DS_COMMIT, seller_tin, buyer_id, items, margin as Field, vat_base as Field,
            vat_amount as Field, rate_bp as Field, total as Field, salt,
        ],
        10,
    )
}

// C4 — registry leaf = H(DS_LEAF, seller_tin); seller_tin stays private (§5.1).
fn leaf_of(seller_tin: Field) -> Field {
    Poseidon2::hash([DS_LEAF, seller_tin], 2)
}

// C4 — fold a fixed-depth Merkle path (height 8 => 7 siblings) up to the root.
fn fold_root(leaf: Field, siblings: [Field; 7], path_bits: [bool; 7]) -> Field {
    let mut node = leaf;
    for i in 0..7 {
        // path_bits[i] == true => `node` is the RIGHT child at level i.
        node = if path_bits[i] {
            Poseidon2::hash([siblings[i], node], 2)
        } else {
            Poseidon2::hash([node, siblings[i]], 2)
        };
    }
    node
}

// C1 — attestation binding message M = H(DS_ATTEST, D_hi, D_lo, C, R_reg, datetime, invoice).
fn binding_message(
    d_hi: Field, d_lo: Field, c: Field, root: Field, datetime: Field, invoice: Field,
) -> Field {
    Poseidon2::hash([DS_ATTEST, d_hi, d_lo, c, root, datetime, invoice], 7)
}

fn main(
    // ── PUBLIC statement (SPEC §6): authority pubkey, registry root, opaque D, commitment ──
    pk_x: pub Field,
    pk_y: pub Field,
    sellers_root: pub Field,
    d_hi: pub Field,
    d_lo: pub Field,
    c: pub Field,
    // ── PRIVATE witness (all PRE-ENCODED Fields; amounts as bounded u64) ──
    enc_seller_tin: Field,
    enc_buyer_id: Field,
    enc_datetime: Field,
    enc_invoice: Field,
    items: Field,
    margin: u64,
    vat_base: u64,
    vat_amount: u64,
    rate_bp: u64,
    total: u64,
    r: u64,
    salt: Field,
    // Schnorr signature σ_rcpt over M (Grumpkin scalars lo/hi limbs).
    sig_s_lo: Field, sig_s_hi: Field, sig_e_lo: Field, sig_e_hi: Field,
    // Merkle path.
    siblings: [Field; 7],
    path_bits: [bool; 7],
) {
    // ── C1 — attestation validity + anti-replay (SPEC §7-C1) ──
    let m = binding_message(d_hi, d_lo, c, sellers_root, enc_datetime, enc_invoice);
    let pk = EmbeddedCurvePoint::new(pk_x, pk_y);
    let sig = (EmbeddedCurveScalar::new(sig_s_lo, sig_s_hi), EmbeddedCurveScalar::new(sig_e_lo, sig_e_hi));
    assert(schnorr::verify_signature(pk, sig, m));
    // ── C5 — D opaque (SPEC §7-C5 LIMIT): d_hi/d_lo enter ONLY M; never recomputed
    //         in-circuit (no SHA-256 here). Phase-5 adds in-circuit SHA-256 (see
    //         noir/phase5_rsa_probe) to bind D to the fields. ──

    // ── C2 — commitment correctness (SPEC §7-C2) ──
    assert(commit_c(enc_seller_tin, enc_buyer_id, items, margin, vat_base, vat_amount, rate_bp, total, salt) == c);

    // ── C3 — VAT correctness, bounded integers (SPEC §7-C3) ──
    assert(vat_base <= MAX_CENTS);
    assert(vat_amount <= MAX_CENTS);
    assert(total <= MAX_CENTS);
    assert(margin <= MAX_CENTS);
    // statutory rate ∈ {0, 700, 2100} bp (§5.3).
    assert((rate_bp == 0) | (rate_bp == 700) | (rate_bp == 2100));
    // round-half-up: vat_amount*DENOM + r == vat_base*rate_bp + BIAS, 0 <= r < DENOM.
    // u128 headroom: 2^52 * 2100 < 2^64, promote to u128 to be safe.
    assert(r < DENOM);
    let lhs: u128 = (vat_amount as u128) * (DENOM as u128) + (r as u128);
    let rhs: u128 = (vat_base as u128) * (rate_bp as u128) + (BIAS as u128);
    assert(lhs == rhs);
    // consistency: total == vat_base + vat_amount.
    assert(total == vat_base + vat_amount);

    // ── C4 — anchored Merkle membership (SPEC §7-C4) ──
    // root is anchored by C1 (root ∈ M => authority-fixed). seller_tin stays private.
    let leaf = leaf_of(enc_seller_tin);
    assert(fold_root(leaf, siblings, path_bits) == sellers_root);
}
