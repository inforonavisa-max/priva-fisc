// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IHonkVerifier} from "./IHonkVerifier.sol";

/// @title MockHonkVerifier — non-cryptographic stand-in for the generated verifier.
/// @notice RECON SKELETON ONLY. Lets `FiscComplianceGate` and `CompliantPaymentFlow`
///         compile, deploy and wire end-to-end before the real verifier exists. It
///         performs NO verification and provides NO security. In production this is
///         replaced 1:1 by the `bb`/Garaga-generated `HonkVerifier` (same interface).
contract MockHonkVerifier is IHonkVerifier {
    function verify(bytes calldata, bytes32[] calldata)
        external
        pure
        returns (bool)
    {
        return true;
    }
}
