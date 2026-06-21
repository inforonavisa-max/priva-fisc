#!/usr/bin/env bash
# Deploy the PRIVA-FISC verifier + gate to Arbitrum Sepolia and submit ONE on-chain
# verification transaction (analogous to the Mina FiscAnchor evidence).
#
# DELEGATED STEP — requires a FUNDED Arbitrum Sepolia key. Obtaining test ETH is a human
# gate (faucet captcha / wallet connect / login); this script does NOT bypass it. Fund a
# key via a standard Arbitrum Sepolia faucet, then:
#
#     PRIVATE_KEY=0x<funded-key> ./scripts/deploy_sepolia.sh
#
# SYNTHETIC DATA ONLY — never use a real/production key here.
set -euo pipefail

RPC="${RPC:-https://sepolia-rollup.arbitrum.io/rpc}"
EXPLORER="https://sepolia.arbiscan.io"
POC="$(cd "$(dirname "$0")/.." && pwd)"      # arbitrum/poc
FOUNDRY="$POC/foundry"
CD="$POC/artifacts/calldata.json"

: "${PRIVATE_KEY:?set PRIVATE_KEY to a FUNDED Arbitrum Sepolia key (faucet = human gate)}"
command -v forge >/dev/null || { echo "need foundry (forge/cast) on PATH"; exit 1; }
command -v jq    >/dev/null || { echo "need jq on PATH"; exit 1; }

PKX=$(jq -r .gateConstructorArgs.authPkX   "$CD")
PKY=$(jq -r .gateConstructorArgs.authPkY   "$CD")
ROOT=$(jq -r .gateConstructorArgs.sellersRoot "$CD")
PROOF=$(jq -r .submitProof.proof "$CD")
PI=$(jq -r '.submitProof.publicInputs | join(",")' "$CD")

cd "$FOUNDRY"

echo "1/3  deploy HonkVerifier (bb-generated UltraHonk/keccak verifier)…"
VER=$(forge create verifier/HonkVerifier.sol:HonkVerifier \
        --rpc-url "$RPC" --private-key "$PRIVATE_KEY" --broadcast --json | jq -r .deployedTo)
echo "     HonkVerifier      = $VER"
echo "     $EXPLORER/address/$VER"

echo "2/3  deploy FiscComplianceGate (pins authority key + registry root)…"
GATE=$(forge create fisc/FiscComplianceGate.sol:FiscComplianceGate \
        --rpc-url "$RPC" --private-key "$PRIVATE_KEY" --broadcast --json \
        --constructor-args "$VER" "$PKX" "$PKY" "$ROOT" | jq -r .deployedTo)
echo "     FiscComplianceGate = $GATE"
echo "     $EXPLORER/address/$GATE"

echo "3/3  submitProof — ON-CHAIN verification of the Noir proof…"
TX=$(cast send "$GATE" "submitProof(bytes,bytes32[])" "$PROOF" "[$PI]" \
        --rpc-url "$RPC" --private-key "$PRIVATE_KEY" --json | jq -r .transactionHash)
echo "     verification tx   = $TX"
echo "     $EXPLORER/tx/$TX"

echo
echo "DONE — the PRIVA-FISC Noir proof was verified ON-CHAIN on Arbitrum Sepolia."
echo "Record the gate address + tx hash as persistent evidence (as we did for Mina Devnet)."
