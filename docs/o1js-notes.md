# o1js notes — verified primitive APIs (v0-A generator)

> Purpose: record the **actual** o1js API used by this repo, verified against the
> installed package (not from memory), per the task's STEP-0 requirement. The ZK
> circuit (next task) must use the SAME primitives/encoding from `src/`.

## Toolchain (verified)

| Item | Value | How verified |
|---|---|---|
| Node | `v25.9.0` (≥ o1js floor `>=18.14.0`) | `node --version`; `npm view o1js engines` |
| npm | `11.12.1` | `npm --version` |
| o1js (latest stable) | **`2.15.0`** | `npm view o1js version` (the `3.0.0-mesa*` tags are pre-release, not stable) |
| o1js (installed + pinned) | `2.15.0` (exact, no `^`) | `node_modules/o1js/package.json`; `package.json` `dependencies.o1js: "2.15.0"` |

Module system: ESM (`"type":"module"`), TypeScript strict, `module/moduleResolution:
nodenext` → intra-repo imports use explicit `.js` specifiers. Scripts run via
`tsc && node build/...` (no extra runtime dep).

## Primitives confirmed by runtime probe

Probed directly against `o1js@2.15.0`:

### `Field`
- `Field(bigint | number | string)` constructs; `.toString()` → decimal string;
  `.toBigInt()` → bigint; `.add(Field)` → Field.
- `Field.ORDER = 28948022309329048855892746252171976963363056481941560715954676764349967630337`
  (Pallas base field). Bit length **255**.
- ⇒ **31 bytes (248 bits) pack losslessly into one Field** (`2^248 - 1 < ORDER`).
  This underpins `encodeStringToField` in `src/encoding.ts` (31-byte BE chunks).

### `Poseidon`
- `Poseidon.hash(fields: Field[]): Field` — variable-length input array. Used for
  all commitments/digests (`D`, `C`, `itemsCommit`, registry leaf).

### `MerkleTree`
- `new MerkleTree(height: number)` — a height-`h` tree has **`2^(h-1)` leaves**
  (probe: `new MerkleTree(8).leafCount === 128`).
- `tree.setLeaf(index: bigint, value: Field): void`
- `tree.getRoot(): Field`
- `tree.getWitness(index: bigint)` → array of `{ isLeft: boolean, sibling: Field }`,
  **length `h-1`** (probe: length 7 for height 8).

### `MerkleWitness(height)`
- `class W extends MerkleWitness(height) {}` — factory returns a class; construct
  with the `getWitness(...)` array (or an equivalent `{isLeft, sibling}[]`).
- `new W(path).calculateRoot(leaf: Field): Field` — recomputes the root.
- `new W(path).calculateIndex(): Field` — recomputes the leaf index.

### Index ↔ path bit convention (verified)
For each path element (level 0 = leaf level, ascending):

> **`isLeft = true`** ⇔ the current node is the **left** child of its parent
> ⇔ **index bit at that level = 0**. `isLeft = false` ⇔ index bit = 1.

Probe (height 4, 8 leaves), LSB-first `isLeft` arrays vs `calculateIndex()`:

| index | isLeft(level0..top) | bits (isLeft?0:1) |
|---|---|---|
| 0 | `[T,T,T]` | `000` = 0 |
| 1 | `[F,T,T]` | `100`→1 |
| 2 | `[T,F,T]` | `010`→2 |
| 5 | `[F,T,F]` | `101`→5 |
| 7 | `[F,F,F]` | `111`→7 |

⇒ `merkleIndexBits[k] = isLeft[k] ? 0 : 1` (LSB-first). This is exactly how
`src/merkle.ts` serializes `merkleIndexBits`, and the self-check cross-validates
`Σ bit_k·2^k == calculateIndex()`.

## API differences from initial expectation

- **No surprises** in the primitives themselves — `Field`, `Poseidon.hash`,
  `MerkleTree`, `MerkleWitness` match the names/signatures expected. The only
  detail worth pinning is the **`isLeft` semantics** (left-child ⇒ bit 0), which
  is easy to get backwards and is therefore probe-verified above.
- `MerkleTree(h)` leaf capacity is `2^(h-1)`, **not** `2^h` — height 8 ⇒ 128
  slots. `src/merkle.ts` uses `MERKLE_HEIGHT = 8`, `MERKLE_LEAVES = 128`.

## SPEC-vs-task reconciliations baked into `src/`

Places where the build resolved an ambiguity; the **SPEC is the single source of
truth** and the choices below were made so the generator matches the circuit:

1. **Commitment `C` scope.** The task prompt's shorthand was
   `C = Poseidon(buyerId, itemsCommit, margin, salt)`. We instead implement the
   **full SPEC §7-C2** commitment
   `C = H(DS_commit, seller_tin, buyer_id, H(line_items), margin, vat_base,
   vat_amount, vat_rate, total, salt)`. Reasons: SPEC is authoritative; SPEC §5.1
   *requires* `seller_tin ∈ C`; and the circuit will enforce C2, so the reduced
   form would guarantee the generator↔circuit mismatch the prompt warns against.
   The prompt's 4 fields are a strict subset of C2. See `src/commitments.ts`.

2. **Receipt digest `D` = `SHA-256(canonical(P))`** (SPEC §7-C5/§13), carried as
   two 128-bit Field limbs `{hi, lo}` + hex. (An earlier `D = Poseidon(T)`
   construction was a stale prompt artifact, corrected in commit `c8b5649` to
   match the spec.) `D` is an **opaque public input** in v0-A; the circuit does
   NOT recompute it (the in-circuit SHA-256 is the Phase-5/§9 v0-B step). The byte
   `canonicalize(P)` lives in the generator-only `src/canonical.ts`. The synthetic
   IKOF chain (RSA-SHA256 + MD5) is separate, over the 7-field pipe-join (§13).

3. **`C` realization (circuit, §6 / D2).** §6 labels `C` the published **output**;
   the v0-A ZkProgram realizes it as a **constrained public input** (asserts
   `commitCFields(witness)==C`) so the COMMITMENT_MISMATCH case is exercisable.
   Verifier-equivalent but an architectural role change; Phase-5 revisits it.

## Domain-separation tags (v0-A choice)

`DS = { COMMIT:2, LEAF:3, ITEMS:4, ATTEST:5 }` (distinct Field constants), per
SPEC §11.7. There is no DS tag for `D` (it is a byte SHA-256, not Poseidon).
`TODO(confirm)`: final DS values pinned in build.

## Circuit-phase APIs (verified against installed o1js@2.15.0)

Probed before use (the `node --eval` path mangles o1js stack traces — run probes
from a file, e.g. a gitignored `build/*.mjs`):

| API | Verified behaviour |
|---|---|
| `Signature.create(sk, Field[])` / `sig.verify(pk, Field[]) → Bool` | in-circuit `sig.verify(PK,[M]).assertTrue()`; **deterministic** for same `(sk, msg)` |
| `PrivateKey.fromBigInt(scalar)` | accepts a 248-bit seed-derived scalar → deterministic authority key |
| `Signature.toBase58/fromBase58`, `PublicKey.toBase58/fromBase58` | round-trip ✓ (fixture serialization) |
| `ZkProgram({ name, publicInput: Struct, methods:{ m:{ privateInputs, async method(pub,…) } } })` | omit `publicOutput` ⇒ void; `await P.compile()` (~6 s); `await P.m(pub,…) → {proof, auxiliaryOutput}`; `await P.verify(proof) → boolean` |
| `class P extends ZkProgram.Proof(prog) {}` | proof class factory |
| `Field.assertLessThanOrEqual(Field)` / `assertLessThan` | canonical-integer comparison in `[0,p)`; used for the MAXBITS=52 range bound + remainder `r < denom` |
| `UInt64.from(...)` | **does NOT type-accept `Field`** (only string/number/bigint/UInt64/UInt32); use `Field.assertLessThanOrEqual` or `UInt64.Unsafe.fromField` instead |
| `Gadgets.rangeCheckN(length, x)` | exists; `length` must be a **multiple of 16** (so not usable for a bare 52-bit check) |
| `MerkleWitness(h).calculateRoot(leaf)` | runs in-circuit (C4) |

Proving times (this machine): compile ~6 s; each valid prove+verify ~4.4 s;
invalid fixtures reject at witness-generation (~0 s, before proving).
