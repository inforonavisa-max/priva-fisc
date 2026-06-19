//! PRIVA-FISC × STRK20 — VAT-on-ciphertext PoC tests. SYNTHETIC data only.
//!
//! POSITIVE: a correctly-taxed confidential payment → proof VERIFIES.
//! NEGATIVE (instruction-level real — every rejection is an assertion/Sigma failure,
//! not an argument error):
//!   (a) total ≠ vat_base + vat_amount        → VAT_NOT_CONSISTENT
//!   (b) wrong authority signature            → C1_BAD_ATTESTATION
//!   (c) tampered committed field             → C2_COMMIT_MISMATCH
//!   (d) seller not in registry               → C4_NOT_REGISTERED
//!   (e) VAT proof lifted from another receipt→ VAT_PROOF_NOT_BOUND

use core::ec::{EcPointTrait, NonZeroEcPoint};
use core::ec::stark_curve::{GEN_X, GEN_Y, ORDER};
use priva_fisc_recon::leaf_of;
use priva_fisc_recon::merkle_root;
use priva_fisc_recon::poc::{
    Cipher, FiscStatement, FiscWitness, add_mod_order, assert_taxed_payment, binding_message,
    commit_fisc, encrypt, prove_vat, vat_binding_prefix,
};
use she::protocols::SameEncryption::SameEncryptionProofWithPrefix;
use she::utils::generate_random_for_testing;

// ---- synthetic fixed scenario ----------------------------------------------
const SEED: felt252 = 777;
const X_PAY: felt252 = 0x50415F6B6579; // payment secret (derives Y) — synthetic
const VAT_BASE: felt252 = 1000;
const VAT_AMT: felt252 = 210; // 21% of 1000
const HONEST_TOTAL: felt252 = 1210;
const RATE_BP: felt252 = 2100;
const SELLER_TIN: felt252 = 0x504942313233343536;
const BUYER_ID: felt252 = 0xB0FF;
const ITEMS_HASH: felt252 = 'ITEMS';
const MARGIN: felt252 = 150;
const SALT: felt252 = 0x5A17;
const D_HI: felt252 = 0xD1;
const D_LO: felt252 = 0xD0;
const DATETIME: felt252 = 0x32303236;
const INVOICE: felt252 = 42;

fn pk_point(x: felt252) -> NonZeroEcPoint {
    let g = EcPointTrait::new(GEN_X, GEN_Y).unwrap();
    g.mul(x).try_into().unwrap()
}

fn registry_path() -> (Array<felt252>, Array<bool>) {
    (array![0xA, 0xB], array![false, true])
}

/// Builds a full PoC scenario. `claimed_total` is the value the receipt claims (and the
/// value CT_total encrypts and the VAT proof commits to). Honest ⇔ claimed_total == base+tax.
/// Returns (statement, witness, vat_proof). pk_a/siblings handled by caller.
fn scenario(claimed_total: felt252, pk_a: felt252) -> (FiscStatement, FiscWitness, SameEncryptionProofWithPrefix) {
    let y = pk_point(X_PAY);

    let r_base = generate_random_for_testing(SEED, 1);
    let r_tax = generate_random_for_testing(SEED, 2);
    let r_total = generate_random_for_testing(SEED, 3);

    let ct_base: Cipher = encrypt(VAT_BASE, r_base, y);
    let ct_tax: Cipher = encrypt(VAT_AMT, r_tax, y);
    let ct_total: Cipher = encrypt(claimed_total, r_total, y);

    let witness = FiscWitness {
        seller_tin: SELLER_TIN,
        buyer_id: BUYER_ID,
        items_hash: ITEMS_HASH,
        margin: MARGIN,
        rate_bp: RATE_BP,
        salt: SALT,
    };

    // registry root from the seller's Merkle path
    let (siblings, bits) = registry_path();
    let r_reg = merkle_root(leaf_of(SELLER_TIN), siblings.span(), bits.span());

    // commitment is computed from witness + ciphertexts; build statement around it
    let mut st = FiscStatement {
        y, ct_base, ct_tax, ct_total, commitment: 0, r_reg, d_hi: D_HI, d_lo: D_LO,
        datetime: DATETIME, invoice_no: INVOICE, pk_a,
    };
    let c = commit_fisc(@witness, @st);
    st.commitment = c;

    // off-chain prover: SameEncryption proof that CT_sum and CT_total encrypt same value.
    // b committed = claimed_total; r1 = r_base+r_tax (CT_sum randomness); r2 = r_total.
    let prefix = vat_binding_prefix(@st);
    let r1 = add_mod_order(r_base, r_tax);
    let kb = generate_random_for_testing(SEED, 11);
    let kr1 = generate_random_for_testing(SEED, 12);
    let kr2 = generate_random_for_testing(SEED, 13);
    let vat_proof = prove_vat(claimed_total, r1, r_total, y, prefix, kb, kr1, kr2);

    (st, witness, vat_proof)
}

// Authority signature over M for the HONEST scenario (M is pk_a-independent), produced
// off-chain by scripts/sign_attestation.py (synthetic authority key) over the M emitted by
// _emit_signing_material. Stark-curve ECDSA, verified by core::ecdsa::check_ecdsa_signature.
// Generated for M = 686765739543614203559255429176489996827193953767580348622006092240395225874
// (if the scenario/binding_message inputs change, re-run _emit_signing_material + the signer).
const PK_A: felt252 = 0x300c7f890ab6493c19342d03e8071fa36aa473e31acc862bc426228e7cd236d;
const SIG_R: felt252 = 0x577ec47ce9573ed917b6cf16d52e7e42acf10a0278672023e69f872d3516482;
const SIG_S: felt252 = 0x32418e955ee78efb1aa960073c301a30c7d493f723df650a71dab353aa5be66;

// Helper test: prints M (and C) so the synthetic authority can sign it off-chain.
#[test]
#[ignore]
fn _emit_signing_material() {
    let (st, _w, _p) = scenario(HONEST_TOTAL, 0);
    let m = binding_message(@st);
    println!("COMMITMENT_C={}", st.commitment);
    println!("MESSAGE_M={}", m);
}

#[test]
fn positive_correctly_taxed_payment_verifies() {
    let (st, w, proof) = scenario(HONEST_TOTAL, PK_A);
    let (siblings, bits) = registry_path();
    assert_taxed_payment(@st, @w, proof, SIG_R, SIG_S, siblings.span(), bits.span());
}

#[test]
#[should_panic(expected: 'VAT_NOT_CONSISTENT')]
fn negative_a_wrong_vat_total() {
    // receipt claims total = 1300 while base+tax = 1210
    let (st, w, proof) = scenario(1300, PK_A);
    let (siblings, bits) = registry_path();
    assert_taxed_payment(@st, @w, proof, SIG_R, SIG_S, siblings.span(), bits.span());
}

#[test]
#[should_panic(expected: 'C1_BAD_ATTESTATION')]
fn negative_b_wrong_signature() {
    let (st, w, proof) = scenario(HONEST_TOTAL, PK_A);
    let (siblings, bits) = registry_path();
    assert_taxed_payment(@st, @w, proof, SIG_R, SIG_S + 1, siblings.span(), bits.span());
}

#[test]
#[should_panic(expected: 'C2_COMMIT_MISMATCH')]
fn negative_c_tampered_committed_field() {
    let (st, mut w, proof) = scenario(HONEST_TOTAL, PK_A);
    w.buyer_id = 0xDEAD; // tamper a field that C2 binds
    let (siblings, bits) = registry_path();
    assert_taxed_payment(@st, @w, proof, SIG_R, SIG_S, siblings.span(), bits.span());
}

#[test]
#[should_panic(expected: 'C4_NOT_REGISTERED')]
fn negative_d_seller_not_registered() {
    let (st, w, proof) = scenario(HONEST_TOTAL, PK_A);
    // wrong Merkle path → recomputed root ≠ r_reg
    let siblings = array![0xA, 0xC];
    let bits = array![false, true];
    assert_taxed_payment(@st, @w, proof, SIG_R, SIG_S, siblings.span(), bits.span());
}

// DOCUMENTED LIMITATION (passes on purpose): SameEncryption proves plaintext equality of the
// scalars MOD THE CURVE ORDER, not over the integers. A "total" of HONEST_TOTAL + ORDER encrypts
// to the SAME ciphertext as HONEST_TOTAL (scalar mul is mod ORDER), so the proof VERIFIES even
// though 1210 + ORDER ≠ 1210 as an integer. This is exactly why a production system must pair the
// equality proof with a range proof (she `Range`/`Bit`) bounding amounts to [0, 2^k). See the
// module SCOPE note in src/poc.cairo. This test asserts the (honest-about-it) ACCEPTANCE.
#[test]
fn documents_modular_equality_limitation() {
    let (st, w, proof) = scenario(HONEST_TOTAL + ORDER, PK_A);
    let (siblings, bits) = registry_path();
    assert_taxed_payment(@st, @w, proof, SIG_R, SIG_S, siblings.span(), bits.span());
}

#[test]
#[should_panic(expected: 'VAT_PROOF_NOT_BOUND')]
fn negative_e_vat_proof_not_bound_to_receipt() {
    // A proof whose prefix is not this receipt's binding prefix (e.g. lifted from another
    // receipt) must be rejected — it isn't cryptographically tied to (C, registry, D).
    let (st, w, mut proof) = scenario(HONEST_TOTAL, PK_A);
    proof.prefix = proof.prefix + 1; // no longer == vat_binding_prefix(st)
    let (siblings, bits) = registry_path();
    assert_taxed_payment(@st, @w, proof, SIG_R, SIG_S, siblings.span(), bits.span());
}

#[test]
#[should_panic(expected: 'MALFORMED_CIPHERTEXT')]
fn negative_f_malformed_ciphertext_rejected() {
    // Adversarial PUBLIC ciphertext: ct_tax.L = -(ct_base.L) ⇒ the homomorphic sum CT_sum.L is
    // the point at infinity. The verifier must REJECT cleanly (not panic on an unwrap).
    let y = pk_point(X_PAY);
    let r_base = generate_random_for_testing(SEED, 1);
    let r_tax = generate_random_for_testing(SEED, 2);
    let r_total = generate_random_for_testing(SEED, 3);
    let ct_base: Cipher = encrypt(VAT_BASE, r_base, y);
    // L = -(ct_base.L): same x, negated y (still on curve). Reuse a valid R component.
    let (bx, by) = ct_base.L.coordinates();
    let neg_l: NonZeroEcPoint = EcPointTrait::new_nz(bx, -by).unwrap();
    let ct_tax = Cipher { L: neg_l, R: encrypt(VAT_AMT, r_tax, y).R };
    let ct_total: Cipher = encrypt(HONEST_TOTAL, r_total, y);
    let w = FiscWitness {
        seller_tin: SELLER_TIN, buyer_id: BUYER_ID, items_hash: ITEMS_HASH, margin: MARGIN,
        rate_bp: RATE_BP, salt: SALT,
    };
    let (siblings, bits) = registry_path();
    let r_reg = merkle_root(leaf_of(SELLER_TIN), siblings.span(), bits.span());
    let mut st = FiscStatement {
        y, ct_base, ct_tax, ct_total, commitment: 0, r_reg, d_hi: D_HI, d_lo: D_LO,
        datetime: DATETIME, invoice_no: INVOICE, pk_a: PK_A,
    };
    st.commitment = commit_fisc(@w, @st); // C2 passes (commits the malformed ct)
    // proof with the correct prefix so we actually reach cipher_add (the malformed-ct check)
    let prefix = vat_binding_prefix(@st);
    let kb = generate_random_for_testing(SEED, 11);
    let proof = prove_vat(HONEST_TOTAL, add_mod_order(r_base, r_tax), r_total, y, prefix, kb, kb, kb);
    assert_taxed_payment(@st, @w, proof, SIG_R, SIG_S, siblings.span(), bits.span());
}
