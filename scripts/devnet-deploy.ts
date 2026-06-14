/**
 * PRIVA-FISC v0-A — LIVE Devnet deploy + on-chain publish (`npm run devnet:deploy`)
 * ============================================================================
 * ⚠️  RUN THIS FROM A MACHINE WITH NETWORK ACCESS TO THE DEVNET ENDPOINT.
 *     It was NOT executed in the build/CI sandbox (that environment cannot reach
 *     api.minascan.io — Cloudflare holds the connection, http=000). On a normal
 *     residential network it works.
 *
 * Talks ONLY to the Mina Devnet GraphQL endpoint below. Uses the EXISTING keys in
 * keys/devnet.json (never regenerated, never printed). Synthetic proof only.
 *
 * Step 0 reachability + balance precheck → Step 1 deploy FiscAnchor → Step 2
 * publish a valid synthetic proof on-chain → Step 3 verify lastCommitment == C.
 * Prints tx hashes + minascan explorer links.
 *
 * Network note: the classic "Devnet" (this endpoint) is what o1js 2.15.0 targets.
 * The Mesa hard fork is a SEPARATE network (the faucet lists DEVNET vs MESA vs
 * TRAILBLAZER(MESA) distinctly). If this endpoint is ever migrated to Mesa, the
 * deploy needs o1js 3.0.0-mesa.* — do that as a deliberate upgrade, not forced.
 * ----------------------------------------------------------------------------
 */

import { AccountUpdate, Mina, PrivateKey, fetchAccount } from 'o1js';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { FiscProof, circuitInputsFromFixture } from '../src/circuit.js';
import { FiscAnchor } from '../src/anchor.js';
import { buildDataset } from '../src/fixtures.js';
import { DEFAULT_CONFIG } from '../src/synthetic.js';

const ENDPOINT = 'https://api.minascan.io/node/devnet/v1/graphql';
const FEE = 1e8; // 0.1 MINA
const txLink = (h: string): string => `https://minascan.io/devnet/tx/${h}?type=zk-tx`;
const acctLink = (a: string): string => `https://minascan.io/devnet/account/${a}`;

interface KeyFile {
  feePayer: { publicKey: string; privateKey: string };
  zkApp: { publicKey: string; privateKey: string };
}
const keys = JSON.parse(
  readFileSync(join(process.cwd(), 'keys', 'devnet.json'), 'utf8'),
) as KeyFile;
const feePayerKey = PrivateKey.fromBase58(keys.feePayer.privateKey);
const feePayer = feePayerKey.toPublicKey();
const zkAppKey = PrivateKey.fromBase58(keys.zkApp.privateKey);
const zkAppAddress = zkAppKey.toPublicKey();

Mina.setActiveInstance(Mina.Network(ENDPOINT));

// ── Step 0 — reachability + balance precheck (spend nothing if not ready) ──
console.log('Step 0: fetching fee-payer from Devnet…', feePayer.toBase58());
const acct = await fetchAccount({ publicKey: feePayer });
if (acct.error) {
  console.error('  ✗ Devnet unreachable / fetchAccount error:', JSON.stringify(acct.error).slice(0, 200));
  console.error('    (Confirm network access to the Devnet endpoint, then retry.)');
  process.exit(1);
}
const balNano = acct.account?.balance.toBigInt() ?? 0n;
const balMina = Number(balNano) / 1e9;
console.log(`  balance: ${balMina} tMINA`);
if (balNano < 1_100_000_000n) {
  console.error('  ✗ balance < 1.1 tMINA — fund the fee-payer via the faucet first:');
  console.error(`    https://faucet.minaprotocol.com/?address=${feePayer.toBase58()}  (network: DEVNET)`);
  process.exit(1);
}

console.log('compiling FiscProof + FiscAnchor…');
await FiscProof.compile();
await FiscAnchor.compile();

// ── Step 1 — deploy FiscAnchor ──
const zkApp = new FiscAnchor(zkAppAddress);
console.log('Step 1: deploying FiscAnchor →', zkAppAddress.toBase58());
const deployTx = await Mina.transaction({ sender: feePayer, fee: FEE }, async () => {
  AccountUpdate.fundNewAccount(feePayer);
  await zkApp.deploy();
});
await deployTx.prove();
const deployPending = await deployTx.sign([feePayerKey, zkAppKey]).send();
console.log('  deploy tx hash:', deployPending.hash);
console.log('  explorer      :', txLink(deployPending.hash));
console.log('  waiting for inclusion (~minutes)…');
await deployPending.wait();
console.log('  ✓ deploy included.');

// ── Step 2 — publish a valid synthetic proof on-chain ──
const { fixtures } = buildDataset(DEFAULT_CONFIG);
const validFx = fixtures.find((f) => f.expected.valid)!;
const v = circuitInputsFromFixture(validFx);
console.log(`Step 2: proving valid receipt (${validFx.id}) and publishing…`);
const { proof } = await FiscProof.prove(v.publicInput, v.witness, v.merkleWitness, v.sig);
await fetchAccount({ publicKey: zkAppAddress });
const pubTx = await Mina.transaction({ sender: feePayer, fee: FEE }, async () => {
  await zkApp.publish(proof);
});
await pubTx.prove();
const pubPending = await pubTx.sign([feePayerKey]).send();
console.log('  publish tx hash:', pubPending.hash);
console.log('  explorer       :', txLink(pubPending.hash));
console.log('  waiting for inclusion (~minutes)…');
await pubPending.wait();
console.log('  ✓ publish included.');

// ── Step 3 — verify on-chain state ──
await fetchAccount({ publicKey: zkAppAddress });
const onChainC = zkApp.lastCommitment.get().toString();
const expectedC = v.publicInput.C.toString();
console.log('\n=== RESULT ===');
console.log('deploy tx :', txLink(deployPending.hash));
console.log('publish tx:', txLink(pubPending.hash));
console.log('zkApp acct:', acctLink(zkAppAddress.toBase58()));
console.log('on-chain lastCommitment:', onChainC);
console.log('expected C (valid-000) :', expectedC);
console.log(onChainC === expectedC ? '✓ MATCH — on-chain anchor == C' : '✗ MISMATCH');
if (onChainC !== expectedC) process.exit(1);
