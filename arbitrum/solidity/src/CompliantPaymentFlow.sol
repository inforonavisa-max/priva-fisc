// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @dev Minimal ERC-20 surface (a stablecoin like USDC/USDT on Arbitrum).
interface IERC20Minimal {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @dev The gate's settlement-facing surface (see FiscComplianceGate).
interface IFiscComplianceGate {
    function submitProof(bytes calldata proof, bytes32[] calldata publicInputs)
        external
        returns (bytes32 commitment);
}

/// @title CompliantPaymentFlow — reference financial-dApp integration.
/// @notice RECON SKELETON (synthetic only). Shows PRIVA-FISC as a "tax-compliance
///         verifier module" bolted onto a payment/stablecoin flow on Arbitrum: a
///         transfer settles ONLY if it is accompanied by a valid fiscalization-
///         compliance proof. The dApp learns the proven commitment `C` (an audit
///         handle) and nothing about the underlying receipt.
contract CompliantPaymentFlow {
    IFiscComplianceGate public immutable gate;
    IERC20Minimal public immutable token;

    event Settled(bytes32 indexed commitment, address indexed payer, address indexed payee, uint256 amount);

    constructor(IFiscComplianceGate _gate, IERC20Minimal _token) {
        gate = _gate;
        token = _token;
    }

    /// @notice Settle a stablecoin payment gated on a fresh compliance proof.
    /// @dev The proof is verified first (reverts on failure); only then does value move.
    ///      `commitment` ties the settled payment to the proven (hidden) receipt.
    function settle(
        address payee,
        uint256 amount,
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external returns (bytes32 commitment) {
        commitment = gate.submitProof(proof, publicInputs);
        require(token.transferFrom(msg.sender, payee, amount), "transfer failed");
        emit Settled(commitment, msg.sender, payee, amount);
    }
}
