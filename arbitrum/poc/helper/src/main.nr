//! PoC witness helper — recomputes the v0a_skeleton public values + Schnorr challenge so a
//! valid signature can be finished off-circuit. NOT part of the proven relation; the circuit
//! at arbitrum/poc/circuit (verbatim copy of noir/v0a_skeleton) is unchanged. SYNTHETIC ONLY.
//!
//! Mirrors, byte-for-byte, the hashing in noir/v0a_skeleton/src/main.nr and the challenge in
//! schnorr v0.4.0 (`e = Poseidon2([DST, R.x, P.x, P.y, M], 5)`).
use poseidon::poseidon2::Poseidon2;
use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, multi_scalar_mul};

global DS_COMMIT: Field = 2;
global DS_LEAF: Field = 3;
global DS_ATTEST: Field = 5;
// schnorr v0.4.0 SCHNORR_CHALLENGE_DST (pinned constant from the library source).
global SCHNORR_CHALLENGE_DST: Field =
    0x024c76938ed06b8ec1d9094b1013d190baa4011372f0604643bda812a63b832e;

fn main(
    sk_lo: Field,
    sk_hi: Field, // signer secret key (scalar limbs)
    k_lo: Field,
    k_hi: Field, // nonce (scalar limbs)
    enc_seller_tin: Field,
    enc_buyer_id: Field,
    enc_datetime: Field,
    enc_invoice: Field,
    items: Field,
    margin: Field,
    vat_base: Field,
    vat_amount: Field,
    rate_bp: Field,
    total: Field,
    salt: Field,
    digest_hi: Field,
    digest_lo: Field,
    siblings: [Field; 7],
    path_bits: [bool; 7],
) {
    let g = EmbeddedCurvePoint::generator();
    let sk = EmbeddedCurveScalar::new(sk_lo, sk_hi);
    let k = EmbeddedCurveScalar::new(k_lo, k_hi);
    let p = multi_scalar_mul([g], [sk]); // public key P = sk*G
    let r = multi_scalar_mul([g], [k]); // nonce point  R = k*G

    let c = Poseidon2::hash(
        [
            DS_COMMIT, enc_seller_tin, enc_buyer_id, items, margin, vat_base, vat_amount, rate_bp,
            total, salt,
        ],
        10,
    );

    let leaf = Poseidon2::hash([DS_LEAF, enc_seller_tin], 2);
    let mut node = leaf;
    for i in 0..7 {
        node = if path_bits[i] {
            Poseidon2::hash([siblings[i], node], 2)
        } else {
            Poseidon2::hash([node, siblings[i]], 2)
        };
    }
    let root = node;

    let m = Poseidon2::hash([DS_ATTEST, digest_hi, digest_lo, c, root, enc_datetime, enc_invoice], 7);
    let e = Poseidon2::hash([SCHNORR_CHALLENGE_DST, r.x, p.x, p.y, m], 5);

    let pk_x: Field = p.x;
    let pk_y: Field = p.y;
    let r_x: Field = r.x;
    println(f"PK_X={pk_x}");
    println(f"PK_Y={pk_y}");
    println(f"R_X={r_x}");
    println(f"C={c}");
    println(f"ROOT={root}");
    println(f"M={m}");
    println(f"E={e}");
}
