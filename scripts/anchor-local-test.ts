/**
 * PRIVA-FISC v0-A — on-chain anchor local proof (OFFLINE; `npm run anchor:test`)
 * ============================================================================
 * Deploys FiscAnchor to an in-memory Mina.LocalBlockchain (no network), proves a
 * VALID synthetic receipt, publishes it on-chain, and asserts the contract state
 * == C. Then confirms an INVALID receipt is rejected at the proof boundary (it
 * can never produce a publishable proof). NO real data, NO broadcast.
 *
 * Verified against o1js@2.15.0: Mina.LocalBlockchain is async; testAccounts[i] is
 * a TestPublicKey (PublicKey + `.key`); Mina.transaction(sender, async cb).
 * ----------------------------------------------------------------------------
 */

import { AccountUpdate, Mina, PrivateKey } from 'o1js';
import { FiscProof, circuitInputsFromFixture } from '../src/circuit.js';
import { FiscAnchor } from '../src/anchor.js';
import { buildDataset } from '../src/fixtures.js';
import { DEFAULT_CONFIG } from '../src/synthetic.js';

const results: [string, boolean][] = [];
function check(name: string, cond: boolean): void {
  results.push([name, cond]);
  console.log(`${cond ? '[PASS]' : '[FAIL]'} ${name}`);
}
const secs = (t: number): string => `${((Date.now() - t) / 1000).toFixed(1)}s`;

const { fixtures } = buildDataset(DEFAULT_CONFIG);
const validFx = fixtures.find((f) => f.expected.valid)!;
const invalidFx = fixtures.find((f) => f._invalidReason === 'VAT_MISMATCH')!;

const Local = await Mina.LocalBlockchain({ proofsEnabled: true });
Mina.setActiveInstance(Local);
const deployer = Local.testAccounts[0]!; // funded TestPublicKey (offline)

let t = Date.now();
console.log('compiling FiscProof (ZkProgram)...');
await FiscProof.compile();
console.log(`  done ${secs(t)}`);
t = Date.now();
console.log('compiling FiscAnchor (SmartContract)...');
await FiscAnchor.compile();
console.log(`  done ${secs(t)}`);

// Deploy the anchor to a fresh zkApp account.
const zkAppPrivate = PrivateKey.random();
const zkAppAddress = zkAppPrivate.toPublicKey();
const zkApp = new FiscAnchor(zkAppAddress);

t = Date.now();
const deployTx = await Mina.transaction(deployer, async () => {
  AccountUpdate.fundNewAccount(deployer);
  await zkApp.deploy();
});
await deployTx.prove();
await deployTx.sign([deployer.key, zkAppPrivate]).send();
console.log(`deployed FiscAnchor ${secs(t)}; initial lastCommitment = ${zkApp.lastCommitment.get().toString()}`);
check('deploy: initial lastCommitment == 0', zkApp.lastCommitment.get().toString() === '0');

// ── VALID receipt → prove → publish on-chain → state == C ──
const v = circuitInputsFromFixture(validFx);
t = Date.now();
console.log(`proving valid receipt (${validFx.id})...`);
const { proof } = await FiscProof.prove(v.publicInput, v.witness, v.merkleWitness, v.sig);
console.log(`  proof ${secs(t)}`);
t = Date.now();
const publishTx = await Mina.transaction(deployer, async () => {
  await zkApp.publish(proof);
});
await publishTx.prove();
await publishTx.sign([deployer.key]).send();
console.log(`  published ${secs(t)}`);
const onChainC = zkApp.lastCommitment.get().toString();
check(`valid proof published; on-chain lastCommitment == C (${onChainC.slice(0, 14)}…)`,
  onChainC === v.publicInput.C.toString());

// ── INVALID receipt → cannot produce a proof → can never reach publish ──
const inv = circuitInputsFromFixture(invalidFx);
let invThrew = false;
try {
  await FiscProof.prove(inv.publicInput, inv.witness, inv.merkleWitness, inv.sig);
} catch {
  invThrew = true;
}
check(`invalid receipt (${invalidFx._invalidReason}) rejected at proof boundary (publish unreachable)`, invThrew);

const passed = results.filter(([, c]) => c).length;
console.log(`\nPRIVA-FISC v0-A anchor local test: ${passed}/${results.length} PASS`);
if (passed !== results.length) {
  console.error('✗ anchor local test FAILED');
  process.exit(1);
}
console.log('✓ on-chain publish accepts valid receipts and rejects invalid ones (offline).');
