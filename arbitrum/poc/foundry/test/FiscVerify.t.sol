// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {HonkVerifier} from "verifier/HonkVerifier.sol";
import {FiscComplianceGate} from "fisc/FiscComplianceGate.sol";
import {IHonkVerifier} from "fisc/IHonkVerifier.sol";

/// Minimal cheatcode surface (avoids a forge-std git dependency).
interface Vm {
    function readFileBinary(string calldata path) external view returns (bytes memory);
    function expectRevert(bytes4 selector) external;
}

/// PoC test: the EXISTING Noir v0a_skeleton proof (UltraHonk, keccak/EVM flavor) is
/// verified ON-CHAIN by the bb-generated Solidity verifier, both directly and behind
/// FiscComplianceGate. The proof + public inputs are the real bb artifacts in ../build.
contract FiscVerifyTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    HonkVerifier verifier;
    bytes proof;
    bytes32[] publicInputs;

    event log_named_uint(string key, uint256 val);

    function setUp() public {
        verifier = new HonkVerifier();
        proof = vm.readFileBinary("../artifacts/proof/proof");
        bytes memory pi = vm.readFileBinary("../artifacts/proof/public_inputs");
        uint256 n = pi.length / 32;
        publicInputs = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            bytes32 word;
            // load the i-th 32-byte big-endian field element
            assembly {
                word := mload(add(add(pi, 0x20), mul(i, 0x20)))
            }
            publicInputs[i] = word;
        }
        require(n == 6, "expected 6 public inputs [pk_x,pk_y,sellers_root,d_hi,d_lo,c]");
    }

    // ── POSITIVE: the raw verifier accepts the valid proof, and report gas ──
    function test_Positive_RawVerifierAcceptsValidProof() public {
        uint256 g0 = gasleft();
        bool ok = verifier.verify(proof, publicInputs);
        uint256 used = g0 - gasleft();
        emit log_named_uint("HonkVerifier.verify gas", used);
        require(ok, "valid proof MUST verify on-chain");
    }

    // ── POSITIVE (end-to-end): the gate verifies + records only the commitment C ──
    function test_Positive_GateAcceptsAndRecordsCommitment() public {
        FiscComplianceGate gate = new FiscComplianceGate(
            IHonkVerifier(address(verifier)),
            uint256(publicInputs[0]), // pin authority pk_x
            uint256(publicInputs[1]), // pin authority pk_y
            publicInputs[2] // pin registry root
        );
        bytes32 c = gate.submitProof(proof, publicInputs);
        require(c == publicInputs[5], "gate must return the proven commitment C");
    }

    // ── NEGATIVE 1: tamper a public input (commitment C) → MUST NOT verify ──
    function test_Negative_TamperedPublicInputRejected() public {
        bytes32[] memory t = new bytes32[](publicInputs.length);
        for (uint256 i = 0; i < publicInputs.length; i++) {
            t[i] = publicInputs[i];
        }
        t[5] = bytes32(uint256(t[5]) ^ 1); // flip one bit of C
        try verifier.verify(proof, t) returns (bool ok) {
            require(!ok, "tampered public input MUST be rejected");
        } catch {
            // a revert (failed sumcheck/transcript) is an acceptable rejection
        }
    }

    // ── NEGATIVE 2: gate pinned to a WRONG authority key → reverts before verifying ──
    function test_Negative_GateRejectsWrongAuthorityKey() public {
        FiscComplianceGate gate = new FiscComplianceGate(
            IHonkVerifier(address(verifier)),
            uint256(publicInputs[0]) ^ 1, // WRONG pinned pk_x
            uint256(publicInputs[1]),
            publicInputs[2]
        );
        vm.expectRevert(FiscComplianceGate.UnexpectedAuthorityKey.selector);
        gate.submitProof(proof, publicInputs);
    }
}
