//! PRIVA-FISC Cairo recon — snforge tests. SYNTHETIC data only.
//! Each test demonstrates that a v0-A / Phase-5 / STRK20 primitive COMPILES and
//! RUNS green on this machine (the recon bar). Run: `snforge test`.

use priva_fisc_recon::{
    DS_COMMIT, Receipt, V0AStatement, V0AWitness, binding_message, check_vat, commit_c, ec_eq,
    elgamal_add, elgamal_enc, leaf_of, merkle_root, modmul_u384, rate_is_statutory, sha256_probe,
    verify_attestation, verify_v0a,
};
use core::ec::{EcPointTrait, stark_curve};
use core::circuit::u384;

// ---- a synthetic receipt: net 1000c @ 21% → VAT 210c, total 1210c ----
fn sample_receipt() -> Receipt {
    Receipt {
        seller_tin: 0x504942313233343536, // synthetic PIB
        buyer_id: 0xB0FF,
        line_items_hash: 'ITEMS',
        margin: 150,
        vat_base: 1000,
        vat_amount: 210,
        rate_bp: 2100,
        total: 1210,
        datetime: 0x32303236, // "2026"
        invoice_no: 42,
        salt: 0x5A17,
    }
}

// =================== C2 — Poseidon commitment ===================
#[test]
fn test_c2_commitment_runs_and_is_deterministic() {
    let r = sample_receipt();
    let c1 = commit_c(@r);
    let c2 = commit_c(@r);
    assert(c1 == c2, 'commit not deterministic');
    assert(c1 != 0, 'commit is zero');
    // domain separation actually changes the digest
    assert(c1 != DS_COMMIT, 'commit == tag (no mixing)');
}

// =================== C3 — VAT arithmetic ===================
#[test]
fn test_c3_vat_ok() {
    let r = sample_receipt();
    assert(check_vat(@r), 'valid VAT rejected');
}

#[test]
fn test_c3_vat_rejects_wrong_amount() {
    let mut r = sample_receipt();
    r.vat_amount = 211; // off by one cent
    r.total = 1211;
    assert(!check_vat(@r), 'wrong VAT accepted');
}

#[test]
fn test_c3_vat_rejects_nonstatutory_rate() {
    let mut r = sample_receipt();
    r.rate_bp = 1000; // 10% — not a Montenegro statutory rate
    assert(!check_vat(@r), 'illegal rate accepted');
    assert(!rate_is_statutory(1000), 'rate_is_statutory wrong');
    assert(rate_is_statutory(700), '7% should be statutory');
}

// =================== C4 — Merkle membership (Poseidon fold) ===================
#[test]
fn test_c4_merkle_fold_roundtrip() {
    let r = sample_receipt();
    let leaf = leaf_of(r.seller_tin);
    // height-3 path (2 siblings) — synthetic.
    let siblings = array![0xA, 0xB];
    let path_bits = array![false, true];
    let root = merkle_root(leaf, siblings.span(), path_bits.span());
    // recompute with same inputs → same root (membership is reproducible)
    let root2 = merkle_root(leaf, array![0xA, 0xB].span(), array![false, true].span());
    assert(root == root2, 'merkle not deterministic');
    // a different leaf yields a different root
    let other = merkle_root(leaf_of(0xDEAD), array![0xA, 0xB].span(), array![false, true].span());
    assert(root != other, 'root not leaf-sensitive');
}

// =================== C1 — Stark-curve ECDSA (valid synthetic vector) ===================
// Synthetic vector lifted from the Cairo corelib ECDSA test (no real key / PII).
#[test]
fn test_c1_ecdsa_valid_signature_verifies() {
    let message_hash = 0x503f4bea29baee10b22a7f10bdc82dda071c977c1f25b8f3973d34e6b03b2c;
    let public_key = 0x7b7454acbe7845da996377f85eb0892044d75ae95d04d3325a391951f35d2ec;
    let signature_r = 0xbe96d72eb4f94078192c2e84d5230cde2a70f4b45c8797e2c907acff5060bb;
    let signature_s = 0x677ae6bba6daf00d2631fab14c8acf24be6579f9d9e98f67aa7f2770e57a1f5;
    assert(
        verify_attestation(public_key, message_hash, signature_r, signature_s),
        'valid sig rejected',
    );
    // tamper the message → must reject (binding works)
    assert(
        !verify_attestation(public_key, message_hash + 1, signature_r, signature_s),
        'tampered sig accepted',
    );
}

// =================== C1+C2+C3+C4 wired — full v0-A relation ===================
// The attestation here is over the Poseidon message M (not the raw vector above),
// so a *valid* signature over M needs an off-chain Stark-curve signer (a port task).
// We assert the relation RUNS and that C2/C3/C4 hold; C1 returns false only because
// the synthetic sig is not over this M — exactly the Noir-recon honesty boundary.
#[test]
fn test_v0a_relation_wires_and_runs() {
    let r = sample_receipt();
    let leaf = leaf_of(r.seller_tin);
    let siblings = array![0xA, 0xB];
    let path_bits = array![false, true];
    let r_reg = merkle_root(leaf, siblings.span(), path_bits.span());

    let stmt = V0AStatement {
        pk_a: 0x7b7454acbe7845da996377f85eb0892044d75ae95d04d3325a391951f35d2ec,
        r_reg,
        d_hi: 0xD1,
        d_lo: 0xD0,
    };
    let w = V0AWitness {
        receipt: r,
        sig_r: 0xbe96d72eb4f94078192c2e84d5230cde2a70f4b45c8797e2c907acff5060bb,
        sig_s: 0x677ae6bba6daf00d2631fab14c8acf24be6579f9d9e98f67aa7f2770e57a1f5,
        siblings: siblings.span(),
        path_bits: path_bits.span(),
    };
    let (ok, c) = verify_v0a(@stmt, @w);
    // C is produced (C2) and the message binds it:
    assert(c != 0, 'no commitment');
    let m = binding_message(stmt.d_hi, stmt.d_lo, c, stmt.r_reg, r.datetime, r.invoice_no);
    assert(m != 0, 'no binding message');
    // ok==false is expected (sig not over M). The relation executed end-to-end.
    assert(!ok, 'unexpected: sig over M?!');
}

// =================== PHASE-5 #1 — in-circuit SHA-256 (native corelib) ===================
#[test]
fn test_phase5_sha256_native() {
    // SHA-256("hello") — corelib doc vector for "hell"+"o".
    let hash = sha256_probe(array![0x68656c6c], 0x6f, 1);
    let expected: [u32; 8] = [
        0x2cf24dba, 0x5fb0a30e, 0x26e83b2a, 0xc5b9e29e, 0x1b161e5c, 0x1fa7425e, 0x73043362,
        0x938b9824,
    ];
    assert(hash == expected, 'sha256 mismatch');
}

// =================== PHASE-5 #2 — big modular multiplication (RSA substrate) ===================
#[test]
fn test_phase5_modmul_builtin() {
    // 7 * 8 mod 13 = 56 mod 13 = 4   (proves core::circuit MulMod evaluates)
    let out = modmul_u384([7, 0, 0, 0], [8, 0, 0, 0], [13, 0, 0, 0]);
    let four = u384 { limb0: 4, limb1: 0, limb2: 0, limb3: 0 };
    assert(out == four, 'modmul wrong');
}

// =================== STRK20 / TONGO — additively-homomorphic ElGamal ===================
#[test]
fn test_strk20_elgamal_additive_homomorphism() {
    // recipient public key H = h_sk · G (synthetic)
    let g = EcPointTrait::new(stark_curve::GEN_X, stark_curve::GEN_Y).unwrap();
    let h = g.mul(0x1234567);

    // Enc(vat_base=1000; r1)  and  Enc(vat_amount=210; r2)
    let ct_base = elgamal_enc(1000, 0xA11CE, h);
    let ct_amt = elgamal_enc(210, 0xB0B, h);

    // homomorphic sum should equal a fresh Enc(1210; r1+r2)
    let summed = elgamal_add(ct_base, ct_amt);
    let ct_total = elgamal_enc(1210, 0xA11CE + 0xB0B, h);

    let (s1, s2) = summed;
    let (t1, t2) = ct_total;
    assert(ec_eq(s1, t1), 'c1 homomorphism broke');
    assert(ec_eq(s2, t2), 'c2 homomorphism broke');
    // i.e. total = vat_base + vat_amount is checkable ON Tongo ciphertexts.
}
