/**
 * PRIVA-FISC v0-A — on-chain anchor (Mina zkApp SmartContract)
 * ============================================================================
 * Thin on-chain wrapper around the off-chain v0-A relation. It does NOT change
 * the circuit (src/circuit.ts) — it RE-VERIFIES a FiscProof on-chain and records
 * only the published commitment `C` in contract state. The sensitive receipt
 * fields never appear on-chain (they are inside the proof's hidden witness).
 *
 * Scheme verified against installed o1js@2.15.0 (SmartContract / State / @state /
 * @method / ZkProgram.Proof). Decorators require tsconfig
 * experimentalDecorators + useDefineForClassFields:false (already set).
 *
 * On-chain published surface (SPEC §6 / §11.6): `C` only. (D / R_reg / PK_A are
 * carried by the proof's public input and checked in-circuit; this minimal anchor
 * persists just the commitment. A richer surface — D, a nullifier — is later work.)
 * ----------------------------------------------------------------------------
 */

import { Field, SmartContract, State, state, method } from 'o1js';
import { FiscProofClass } from './circuit.js';

export class FiscAnchor extends SmartContract {
  /** Last published commitment C (Poseidon commitment to the sealed fields). */
  @state(Field) lastCommitment = State<Field>();

  init() {
    super.init();
    this.lastCommitment.set(Field(0));
  }

  /**
   * Publish a fiscalization proof on-chain: verify the FiscProof (C1–C4) in the
   * circuit, then record its public commitment `C`. A transaction only succeeds
   * if the proof verifies — so only authority-attested, VAT-correct, registered
   * receipts can ever update the anchor.
   */
  @method async publish(proof: FiscProofClass) {
    proof.verify();
    this.lastCommitment.set(proof.publicInput.C);
  }
}
