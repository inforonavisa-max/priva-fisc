// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IHonkVerifier} from "./IHonkVerifier.sol";

/// @title FiscComplianceGate — on-chain verifier of a PRIVA-FISC v0-A tax-compliance proof.
/// @notice RECON SKELETON (synthetic data only). The EVM/Arbitrum analogue of the Mina
///         `FiscAnchor` zkApp: it verifies a ZK proof on-chain and records ONLY the
///         resulting commitment + digest. Buyer, line items, margin, seller TIN and the
///         monetary amounts never appear on-chain.
/// @dev    The proof is produced off-chain by the existing Noir circuit
///         (noir/v0a_skeleton/src/main.nr) and proven with Barretenberg in its
///         keccak-flavored UltraHonk form, so the generated Solidity verifier is cheap
///         on the EVM. This contract is proof-system-agnostic: any verifier exposing
///         {IHonkVerifier} (Honk, or a Groth16 verifier wrapped to the same ABI) plugs in.
contract FiscComplianceGate {
    /// The generated proof verifier (bb `write_solidity_verifier` or Garaga).
    IHonkVerifier public immutable verifier;

    /// Trusted anchors pinned at deploy time: the authority public key (PK_A) and the
    /// registered-taxpayer registry root. Pinning them here means a prover cannot
    /// substitute their own authority key or a self-built registry — the on-chain
    /// equivalent of SPEC C1's "registry root is anchored by the authority signature".
    uint256 public immutable authPkX;
    uint256 public immutable authPkY;
    bytes32 public immutable sellersRoot;

    /// Public-input layout of the v0-A circuit, in declaration order:
    /// [0]=pk_x [1]=pk_y [2]=sellers_root [3]=d_hi [4]=d_lo [5]=c
    uint256 internal constant PI_LEN = 6;
    uint256 internal constant PI_PK_X = 0;
    uint256 internal constant PI_PK_Y = 1;
    uint256 internal constant PI_ROOT = 2;
    uint256 internal constant PI_D_HI = 3;
    uint256 internal constant PI_D_LO = 4;
    uint256 internal constant PI_C = 5;

    event ComplianceProven(
        bytes32 indexed commitment,
        bytes32 digestHi,
        bytes32 digestLo,
        address indexed submitter
    );

    error BadPublicInputLength();
    error UnexpectedAuthorityKey();
    error UnexpectedRegistryRoot();
    error InvalidProof();

    constructor(
        IHonkVerifier _verifier,
        uint256 _authPkX,
        uint256 _authPkY,
        bytes32 _sellersRoot
    ) {
        verifier = _verifier;
        authPkX = _authPkX;
        authPkY = _authPkY;
        sellersRoot = _sellersRoot;
    }

    /// @notice Verify a PRIVA-FISC proof; on success record the commitment + digest.
    /// @return commitment the salted Poseidon commitment `C` the proof binds to.
    function submitProof(bytes calldata proof, bytes32[] calldata publicInputs)
        external
        returns (bytes32 commitment)
    {
        if (publicInputs.length != PI_LEN) revert BadPublicInputLength();

        // Anchor the public statement to the pinned authority key + registry root.
        if (
            uint256(publicInputs[PI_PK_X]) != authPkX ||
            uint256(publicInputs[PI_PK_Y]) != authPkY
        ) revert UnexpectedAuthorityKey();
        if (publicInputs[PI_ROOT] != sellersRoot) revert UnexpectedRegistryRoot();

        // The cryptographic check: pairing/sumcheck verification of the ZK proof.
        if (!verifier.verify(proof, publicInputs)) revert InvalidProof();

        commitment = publicInputs[PI_C];

        // SCOPE NOTE (matches WHITEPAPER): no nullifier yet — the SAME proof/commitment
        // can be submitted more than once. Anti-double-submission is a later addition.
        emit ComplianceProven(
            commitment,
            publicInputs[PI_D_HI],
            publicInputs[PI_D_LO],
            msg.sender
        );
    }
}
