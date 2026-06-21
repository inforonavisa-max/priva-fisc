//! PRIVA-FISC v0-A — Arbitrum **Stylus** (Rust/WASM) skeleton of the compliance gate.
//!
//! ┌──────────────────────────────────────────────────────────────────────────┐
//! │ RECON SKELETON — **NOT COMPILED LOCALLY** (no Rust/cargo-stylus toolchain  │
//! │ on this machine). Illustrative API only; the stylus-sdk surface drifts     │
//! │ across releases — verify against the current SDK before building.          │
//! └──────────────────────────────────────────────────────────────────────────┘
//!
//! WHY THIS EXISTS: to make the Solidity-vs-Stylus comparison concrete. For the
//! PRIVA-FISC proof (a BN254 pairing-based UltraHonk/Groth16 check) Stylus has **no
//! cost advantage** over Solidity, because the dominant cost is the `ecPairing`
//! precompile (0x08), which Stylus would call the same way Solidity does. Stylus only
//! wins when verification is *hash/loop-heavy WASM compute* (e.g. an in-WASM STARK/FRI
//! or Poseidon-heavy verifier) — see docs/arbitrum-recon.md §Task F. Hence the
//! recommended path is Solidity (arbitrum/solidity/), and this is the reserve option.
//!
//! The two host strategies a Stylus gate could take:
//!   (A) call the *same* generated EVM verifier contract (a cross-contract staticcall)
//!       — identical security, Rust only for the surrounding business logic; or
//!   (B) verify in-WASM via arkworks (bn254) — only worth it for non-pairing systems.
//! This sketch shows strategy (A): the Rust gate delegates the cryptographic check.

#![cfg_attr(not(feature = "export-abi"), no_main)]
extern crate alloc;

use stylus_sdk::{
    alloy_primitives::{Address, FixedBytes, U256},
    prelude::*,
};

sol_storage! {
    #[entrypoint]
    pub struct FiscComplianceGate {
        address verifier;      // generated EVM Honk verifier (strategy A)
        uint256 auth_pk_x;     // pinned authority public key X
        uint256 auth_pk_y;     // pinned authority public key Y
        bytes32 sellers_root;  // pinned registered-taxpayer registry root
    }
}

// Public-input layout of the v0-A Noir circuit (noir/v0a_skeleton/src/main.nr):
// [0]=pk_x [1]=pk_y [2]=sellers_root [3]=d_hi [4]=d_lo [5]=c
const PI_LEN: usize = 6;

#[public]
impl FiscComplianceGate {
    /// Verify a PRIVA-FISC proof and, on success, return the proven commitment `C`.
    /// Anchors the statement to the pinned authority key + registry root first, then
    /// delegates the ZK check to the generated verifier (strategy A).
    pub fn submit_proof(
        &mut self,
        proof: alloc::vec::Vec<u8>,
        public_inputs: alloc::vec::Vec<FixedBytes<32>>,
    ) -> Result<FixedBytes<32>, alloc::vec::Vec<u8>> {
        if public_inputs.len() != PI_LEN {
            return Err(b"BadPublicInputLength".to_vec());
        }
        if U256::from_be_bytes(public_inputs[0].0) != self.auth_pk_x.get()
            || U256::from_be_bytes(public_inputs[1].0) != self.auth_pk_y.get()
        {
            return Err(b"UnexpectedAuthorityKey".to_vec());
        }
        if public_inputs[2] != self.sellers_root.get() {
            return Err(b"UnexpectedRegistryRoot".to_vec());
        }

        // Strategy (A): staticcall the generated EVM verifier `verify(bytes,bytes32[])`.
        // (Pseudocode — wire via a `sol_interface!` binding + RawCall against the SDK.)
        let ok = self.call_verifier(&proof, &public_inputs);
        if !ok {
            return Err(b"InvalidProof".to_vec());
        }

        // Reveal only the commitment (public_inputs[5]); no nullifier yet (see WHITEPAPER).
        Ok(public_inputs[5])
    }

    fn verifier_address(&self) -> Address {
        self.verifier.get()
    }
}

impl FiscComplianceGate {
    /// Placeholder for the cross-contract verify call (strategy A). In a real build this
    /// is a `sol_interface!{ interface IHonkVerifier { function verify(bytes,bytes32[])
    /// external view returns (bool); } }` binding invoked against `self.verifier`.
    fn call_verifier(&self, _proof: &[u8], _public_inputs: &[FixedBytes<32>]) -> bool {
        // NOT IMPLEMENTED in the skeleton (uncompiled). See docs/arbitrum-recon.md.
        true
    }
}
