//! PRIVA-FISC — Starknet / Cairo v0-A RECON skeleton (NOT a port).
//!
//! Purpose: prove (by *compiling and running on snforge*) that each v0-A circuit
//! primitive — C1 signature, C2 commitment, C3 VAT arithmetic, C4 Merkle, C5 opaque D —
//! maps onto a Cairo-native primitive, and that the Phase-5 substrate (in-circuit
//! SHA-256, big-modular-arithmetic for RSA) and the STRK20/Tongo substrate
//! (additively-homomorphic ElGamal over the Stark curve) are reachable from corelib.
//!
//! This is recon, not a finished implementation. Every value here is SYNTHETIC — no
//! real key, no PII. See ../../docs/starknet-recon.md for the full write-up.
//!
//! Verified on: Scarb 2.18.0 / Cairo 2.18.0 / Sierra 1.8.0 / snforge 0.61.0 (macOS arm64).

use core::circuit::{
    AddInputResultTrait, CircuitElement, CircuitInput, CircuitInputs, CircuitModulus,
    CircuitOutputsTrait, EvalCircuitTrait, circuit_mul, u384, u96,
};
use core::ec::{EcPoint, EcPointTrait, NonZeroEcPoint, stark_curve};
use core::ecdsa::check_ecdsa_signature;
use core::poseidon::poseidon_hash_span;
use core::sha256::compute_sha256_u32_array;

// ---------------------------------------------------------------------------
// Domain-separation tags (synthetic short-string felts).
// ---------------------------------------------------------------------------
pub const DS_ATTEST: felt252 = 'PFISC_ATTEST_v0A';
pub const DS_COMMIT: felt252 = 'PFISC_COMMIT_v0A';
pub const DS_LEAF: felt252 = 'PFISC_LEAF_v0A';

// VAT statutory rates in basis points: 0%, 7%, 21%.
pub const RATE_0: u64 = 0;
pub const RATE_7: u64 = 700;
pub const RATE_21: u64 = 2100;

// MAXBITS range bound for monetary fields (2^52) — keeps vat_base*rate_bp from
// approaching the u128 ceiling (2^52 * 2100 < 2^64).
pub const MAX_MONEY: u64 = 0x10000000000000; // 2^52

/// v0-A synthetic receipt witness (§4 of spec).
#[derive(Drop, Copy)]
pub struct Receipt {
    pub seller_tin: felt252,
    pub buyer_id: felt252,
    pub line_items_hash: felt252,
    pub margin: u64,
    pub vat_base: u64,
    pub vat_amount: u64,
    pub rate_bp: u64,
    pub total: u64,
    pub datetime: felt252,
    pub invoice_no: felt252,
    pub salt: felt252,
}

// ===========================================================================
// C2 — salted Poseidon commitment (masking).
//   C = H(DS_COMMIT, seller_tin, buyer_id, H(items), margin, vat_base,
//         vat_amount, rate_bp, total, salt)
//   Primitive: core::poseidon::poseidon_hash_span  (native, STARK-friendly).
// ===========================================================================
pub fn commit_c(r: @Receipt) -> felt252 {
    poseidon_hash_span(
        array![
            DS_COMMIT,
            *r.seller_tin,
            *r.buyer_id,
            *r.line_items_hash,
            (*r.margin).into(),
            (*r.vat_base).into(),
            (*r.vat_amount).into(),
            (*r.rate_bp).into(),
            (*r.total).into(),
            *r.salt,
        ]
            .span(),
    )
}

// ===========================================================================
// C1 — attestation binding message + verification.
//   M = H(DS_ATTEST, d_hi, d_lo, C, R_reg, datetime, invoice_no)
//   Verify(PK_A, M, sig) via Stark-curve ECDSA (native: core::ecdsa).
//   Signer model: PK_A is a single felt252 (Stark-curve pubkey x-coord) — the
//   SAME curve Tongo/SHE sign Sigma proofs over. FARKLI-but-aligned.
// ===========================================================================
pub fn binding_message(
    d_hi: felt252, d_lo: felt252, c: felt252, root: felt252, datetime: felt252, invoice_no: felt252,
) -> felt252 {
    poseidon_hash_span(array![DS_ATTEST, d_hi, d_lo, c, root, datetime, invoice_no].span())
}

pub fn verify_attestation(pk_a: felt252, m: felt252, sig_r: felt252, sig_s: felt252) -> bool {
    check_ecdsa_signature(m, pk_a, sig_r, sig_s)
}

// ===========================================================================
// C3 — bounded-int VAT correctness.
//   rate_bp ∈ {0, 700, 2100}; vat_amount == floor(vat_base * rate_bp / 10000)
//   (one fixed rounding convention for recon); total == vat_base + vat_amount.
//   Range checks via native u64 + u128 promotion to prevent field wrap.
//   Primitive: native integer types (no external lib).
// ===========================================================================
pub fn rate_is_statutory(rate_bp: u64) -> bool {
    rate_bp == RATE_0 || rate_bp == RATE_7 || rate_bp == RATE_21
}

pub fn check_vat(r: @Receipt) -> bool {
    let rr = *r; // Receipt is Copy — deref once for unambiguous u64 fields.
    // Range bounds (mirror spec C3; native u64 already caps at 2^64).
    if rr.vat_base >= MAX_MONEY || rr.vat_amount >= MAX_MONEY || rr.margin >= MAX_MONEY {
        return false;
    }
    if !rate_is_statutory(rr.rate_bp) {
        return false;
    }
    // Promote to u128 so vat_base*rate_bp (< 2^52*2100 < 2^64) cannot wrap.
    let base_u128: u128 = rr.vat_base.into();
    let rate_u128: u128 = rr.rate_bp.into();
    let amt_u128: u128 = rr.vat_amount.into();
    let expected: u128 = (base_u128 * rate_u128) / 10000_u128;
    if amt_u128 != expected {
        return false;
    }
    rr.total == rr.vat_base + rr.vat_amount
}

// ===========================================================================
// C4 — anchored Merkle membership (Poseidon fold).
//   leaf = H(DS_LEAF, seller_tin); fold path → root; compare to R_reg.
//   No stdlib Merkle gadget in Cairo → hand-rolled Poseidon fold (same idiom
//   as the Aleo / Noir skeletons).  R_reg anchored by C1 (root ∈ M).
// ===========================================================================
pub fn leaf_of(seller_tin: felt252) -> felt252 {
    poseidon_hash_span(array![DS_LEAF, seller_tin].span())
}

pub fn merkle_root(leaf: felt252, siblings: Span<felt252>, path_bits: Span<bool>) -> felt252 {
    let mut cur = leaf;
    let mut i: usize = 0;
    while i < siblings.len() {
        let sib = *siblings.at(i);
        let go_right = *path_bits.at(i);
        cur =
            if go_right {
                poseidon_hash_span(array![sib, cur].span())
            } else {
                poseidon_hash_span(array![cur, sib].span())
            };
        i += 1;
    }
    cur
}

// ===========================================================================
// Full v0-A relation (C1..C5 wired). Returns the public commitment C; asserts
// the rest. C5: d_hi/d_lo are public felt limbs, entering ONLY the message M
// (opaque-D limit — not recomputed in-circuit; that is Phase-5 / v0-B).
// ===========================================================================
#[derive(Drop, Copy)]
pub struct V0AStatement {
    pub pk_a: felt252,
    pub r_reg: felt252,
    pub d_hi: felt252,
    pub d_lo: felt252,
}

#[derive(Drop)]
pub struct V0AWitness {
    pub receipt: Receipt,
    pub sig_r: felt252,
    pub sig_s: felt252,
    pub siblings: Span<felt252>,
    pub path_bits: Span<bool>,
}

/// Returns (ok, C). `ok` is the conjunction C1 ∧ C3 ∧ C4 (C2 is the returned C).
pub fn verify_v0a(stmt: @V0AStatement, w: @V0AWitness) -> (bool, felt252) {
    let r = w.receipt;
    let c = commit_c(r); // C2: C is the published commitment.
    // C3: VAT correctness.
    if !check_vat(r) {
        return (false, c);
    }
    // C4: anchored membership.
    let leaf = leaf_of(*r.seller_tin);
    let root = merkle_root(leaf, *w.siblings, *w.path_bits);
    if root != *stmt.r_reg {
        return (false, c);
    }
    // C1: attestation over M binding (D, C, R_reg, datetime, invoice).
    let m = binding_message(*stmt.d_hi, *stmt.d_lo, c, *stmt.r_reg, *r.datetime, *r.invoice_no);
    let ok = verify_attestation(*stmt.pk_a, m, *w.sig_r, *w.sig_s);
    (ok, c)
}

// ===========================================================================
// PHASE-5 PROBE #1 — in-circuit SHA-256 (native in Cairo corelib).
//   Unlike Mina/Aleo, Cairo ships SHA-256 in core::sha256 (builtin-backed).
//   This is the "compute D = SHA-256(canonical(P)) in-circuit" substrate that
//   closes the v0-A opaque-D limit (C5 → v0-B).
// ===========================================================================
pub fn sha256_probe(words: Array<u32>, last_word: u32, last_bytes: u32) -> [u32; 8] {
    compute_sha256_u32_array(words, last_word, last_bytes)
}

// ===========================================================================
// PHASE-5 PROBE #2 — big modular multiplication (RSA-2048 substrate).
//   core::circuit AddMod/MulMod builtins do 384-bit modular arithmetic
//   (4×u96 limbs). RSA-2048 verify = modexp = a loop of these over a
//   2048-bit modulus assembled from limbs (the path Garaga uses for EC).
//   Here we run ONE modmul to prove the modular-arithmetic builtin compiles
//   and evaluates; full RSA-2048 PKCS#1 v1.5 is NOT implemented (see doc §C).
// ===========================================================================
pub fn modmul_u384(a: [u96; 4], b: [u96; 4], modulus: [u96; 4]) -> u384 {
    let x = CircuitElement::<CircuitInput<0>> {};
    let y = CircuitElement::<CircuitInput<1>> {};
    let prod = circuit_mul(x, y);
    let m = TryInto::<[u96; 4], CircuitModulus>::try_into(modulus).unwrap();
    let outputs = (prod,).new_inputs().next(a).next(b).done().eval(m).unwrap();
    outputs.get_output(prod)
}

// ===========================================================================
// STRK20 / TONGO SUBSTRATE PROBE — additively-homomorphic ElGamal over the
//   Stark curve. Tongo encrypts amounts as ElGamal ciphertexts (c1, c2) over
//   exactly this curve and proves Sigma statements (SHE library). The VAT
//   relation total = vat_base + vat_amount is checkable ON ciphertexts via the
//   homomorphism: Enc(a) ⊕ Enc(b) = Enc(a+b). This probe proves the curve ops
//   needed (scalar-mul + point-add) are corelib-native and the homomorphism
//   holds — i.e. PRIVA-FISC's VAT predicate can bind to a Tongo ciphertext.
// ===========================================================================
fn generator() -> EcPoint {
    EcPointTrait::new(stark_curve::GEN_X, stark_curve::GEN_Y).unwrap()
}

/// ElGamal: Enc(m; rnd) = (rnd·G, m·G + rnd·H), H = recipient public key point.
pub fn elgamal_enc(m: felt252, rnd: felt252, h: EcPoint) -> (EcPoint, EcPoint) {
    let g = generator();
    let c1 = g.mul(rnd);
    let c2 = g.mul(m) + h.mul(rnd);
    (c1, c2)
}

/// Homomorphic add of two ciphertexts: Enc(a) ⊕ Enc(b).
pub fn elgamal_add(a: (EcPoint, EcPoint), b: (EcPoint, EcPoint)) -> (EcPoint, EcPoint) {
    let (a1, a2) = a;
    let (b1, b2) = b;
    (a1 + b1, a2 + b2)
}

/// Point equality (p == q  iff  p - q is the point at infinity).
pub fn ec_eq(p: EcPoint, q: EcPoint) -> bool {
    let diff = p - q;
    let nz: Option<NonZeroEcPoint> = diff.try_into();
    nz.is_none()
}
