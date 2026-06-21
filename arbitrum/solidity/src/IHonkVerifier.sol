// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title IHonkVerifier — interface of the auto-generated PRIVA-FISC proof verifier.
/// @notice This is the ABI that Barretenberg's `bb write_solidity_verifier` (UltraHonk,
///         keccak flavor) and Garaga's `garaga gen --system ultra_keccak_honk` both emit.
///         The concrete verifier is generated from the Noir circuit's verification key —
///         it is NOT hand-written. PRIVA-FISC only writes the gate that *calls* it.
/// @dev    `publicInputs` are the circuit's public statement, one bytes32 (BN254 field
///         element, big-endian) per public input, in declaration order. For the v0-A
///         circuit (noir/v0a_skeleton/src/main.nr) that order is:
///           [0]=pk_x  [1]=pk_y  [2]=sellers_root  [3]=d_hi  [4]=d_lo  [5]=c
interface IHonkVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs)
        external
        view
        returns (bool);
}
