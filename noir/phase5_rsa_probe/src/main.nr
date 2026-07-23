// DEFINITIVE Phase-5 C1 probe: the actively-maintained zkpassport/noir_rsa v0.11.1
// (2026-06-12) called DIRECTLY on the latest upstream nargo 1.0.0-beta.22.
// In-circuit SHA-256 digest -> RSA-2048 PKCS#1 v1.5 verify. Synthetic test vector
// (modulus/redc/signature) lifted from noir_rsa's own bench.nr.
use noir_rsa::rsa::verify_sha256_pkcs1v15;
use bignum::{params::BigNumParams, RuntimeBigNum};

fn main(msg: [u8; 29], signature: [u128; 18]) {
    let sha256_hash: [u8; 32] = sha256::digest(msg); // in-circuit digest
    let params: BigNumParams<18, 2048> = BigNumParams::new(
        false,
        [
            0x8d5e7d9daedd6cfd1c9bdf0227e05b, 0xbfb937fc4d3cf02cc0af780f3cab44,
            0xd20637ef7adcf5d238ee87bccc9bca, 0xb9db4f2663108e2f8b673f7612ae8b,
            0x85f894ef669b36bfd3d86b0a28873, 0xdcc70e1884e38b8229cce3b884121d,
            0x35488d1138e0b03e1676f7f5d8a5b3, 0xe1a97820e7dcbb4eab35c9b71bb273,
            0x97d19eb3c63249ddbfcff915863f54, 0x3a78c7af6da0f6af0d67b1ca4b6065,
            0xd7a3c433c020f624821e5e678c7d69, 0x52d5b53240feae82ffea3d2a3d9b09,
            0xb8aad5e19e2163f68997c6fdd71906, 0x5db432d06e8b0bf59511100c7894e2,
            0xadc0bbc4c54da10d1cc88438ea3127, 0xece1cf6a1501109cd2734d5893c8d9,
            0x7196b90acdf06c31b1288064fd0c27, 0xc8,
        ],
        [
            0x6c77b33d36f7a14b0d2975a42283c, 0xf2796f6ac8bc08fef32961a4af33d4,
            0x7d950e5a1588f914e5bfd55d470efe, 0xadab4b17e38eab0574332eae05afe8,
            0x728ba38c12090f05b1c22a00c2ac34, 0xc01e6ffac7e947954056045cf28671,
            0xfe357dafa9217f7309c58c9fda6ad0, 0xdad66760562505ad6d7c0de61ae667,
            0xd584b8d293fca7c28669e08d44bd60, 0xa22da25e4a6d530ec9a97ea81f003d,
            0x2d59d7e84eadd113c7c11f4fac6ef8, 0xae82b1843be7c99eacc3f896ec7211,
            0x8e1ad23b80c5a3573a8fb2e772407d, 0xb3c6807df6e913814325d850bec7da,
            0x5e98ed72dfbf1834d40a51abb18f3e, 0x4b307572ac4287a788e634a6e78fbe,
            0x18d73c9719b9daeea00d37d18813ec, 0x51bd,
        ],
    );
    let sig: RuntimeBigNum<18, 2048> = RuntimeBigNum { params, limbs: signature };
    assert(verify_sha256_pkcs1v15(sha256_hash, sig, 65537));
}
