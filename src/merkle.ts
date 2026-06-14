/**
 * PRIVA-FISC v0-A — Registered-sellers Merkle tree (SPEC §6 `R_reg`, §7-C4)
 * ============================================================================
 * Poseidon Merkle tree over registry leaves `Poseidon([DS.LEAF, enc(seller_tin)])`.
 * Exposes the root (`sellersRoot` = `R_reg`) and per-seller inclusion paths.
 * `seller_tin` itself stays private (SPEC §5.1); only leaves/root are derived.
 *
 * o1js primitives (verified o1js@2.15.0 — see ../docs/o1js-notes.md):
 *   • `new MerkleTree(height)` → 2^(height-1) leaves; `setLeaf(i, Field)`,
 *     `getRoot()`, `getWitness(i)` (array of {isLeft, sibling}, length height-1).
 *   • `class W extends MerkleWitness(height) {}`; `new W(path).calculateRoot(leaf)`,
 *     `.calculateIndex()`.
 *   • Index↔path: index bit k (LSB-first) = isLeft[k] ? 0 : 1.
 * ----------------------------------------------------------------------------
 */

import { Field, MerkleTree, MerkleWitness } from 'o1js';
import { sellerLeaf } from './commitments.js';

/** Tree height. 8 ⇒ 128 registry slots; witness/path length = 7. */
export const MERKLE_HEIGHT = 8;
export const MERKLE_LEAVES = 1 << (MERKLE_HEIGHT - 1); // 128

/** Concrete witness class for MERKLE_HEIGHT (path length = height - 1). */
export class SellersWitness extends MerkleWitness(MERKLE_HEIGHT) {}

export interface PathElement {
  sibling: Field;
  isLeft: boolean;
}

export interface SerializablePathElement {
  sibling: string; // Field decimal
  isLeft: boolean;
}

export interface InclusionPath {
  merklePath: SerializablePathElement[];
  /** LSB-first index bits (bit k = isLeft[k] ? 0 : 1). Length = height - 1. */
  merkleIndexBits: number[];
  merkleIndex: number;
}

export interface SellersTree {
  tree: MerkleTree;
  root: Field;
  /** Registry slot index assigned to each registered TIN. */
  indexByTin: Map<string, number>;
}

/**
 * Build the registry tree from an ordered list of registered seller TINs.
 * TIN i is placed at leaf i; unused slots default to Field(0).
 */
export function buildSellersTree(registeredTins: string[]): SellersTree {
  if (registeredTins.length > MERKLE_LEAVES) {
    throw new Error(
      `buildSellersTree: ${registeredTins.length} TINs exceed ${MERKLE_LEAVES} slots`,
    );
  }
  const tree = new MerkleTree(MERKLE_HEIGHT);
  const indexByTin = new Map<string, number>();
  registeredTins.forEach((tin, i) => {
    tree.setLeaf(BigInt(i), sellerLeaf(tin));
    indexByTin.set(tin, i);
  });
  return { tree, root: tree.getRoot(), indexByTin };
}

/** Extract the inclusion path for a leaf index, in serializable form. */
export function inclusionPath(tree: MerkleTree, index: number): InclusionPath {
  const witness = tree.getWitness(BigInt(index)) as PathElement[];
  const merklePath = witness.map((e) => ({
    sibling: e.sibling.toString(),
    isLeft: e.isLeft,
  }));
  const merkleIndexBits = witness.map((e) => (e.isLeft ? 0 : 1));
  return { merklePath, merkleIndexBits, merkleIndex: index };
}

/** Rebuild an o1js witness object array from serialized path elements. */
export function deserializePath(
  merklePath: SerializablePathElement[],
): PathElement[] {
  return merklePath.map((e) => ({
    sibling: Field(BigInt(e.sibling)),
    isLeft: e.isLeft,
  }));
}

/**
 * Recompute the Merkle root from a leaf + serialized path, using the SAME o1js
 * MerkleWitness API the circuit will use (SPEC §7-C4 `Merkle.Verify`). Returns
 * the recomputed root; the self-check compares it to the published sellersRoot.
 */
export function recomputeRoot(
  leaf: Field,
  merklePath: SerializablePathElement[],
): Field {
  const witness = new SellersWitness(deserializePath(merklePath));
  return witness.calculateRoot(leaf);
}

/** Recompute the leaf index from a serialized path (cross-checks index bits). */
export function recomputeIndex(merklePath: SerializablePathElement[]): bigint {
  const witness = new SellersWitness(deserializePath(merklePath));
  return witness.calculateIndex().toBigInt();
}
