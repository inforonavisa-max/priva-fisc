/**
 * PRIVA-FISC v0-A — Devnet keypair generator (OFFLINE; `npm run devnet:keys`)
 * ============================================================================
 * Generates a fee-payer + a zkApp keypair for a LATER Devnet deploy, writes them
 * to keys/devnet.json (GIT-IGNORED — never staged/committed), prints the public
 * addresses + the Devnet faucet URL, then STOPS. NO live broadcast here.
 *
 * SYNTHETIC / NON-PRODUCTION test keys. Never use on Mainnet.
 * ----------------------------------------------------------------------------
 */

import { PrivateKey } from 'o1js';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const KEYS_DIR = join(process.cwd(), 'keys');
const OUT = join(KEYS_DIR, 'devnet.json');

interface KeyFile {
  feePayer: { publicKey: string; privateKey: string };
  zkApp: { publicKey: string; privateKey: string };
}

let data: KeyFile;
if (existsSync(OUT)) {
  // Do NOT clobber keys that may already be funded — reuse and report.
  data = JSON.parse(readFileSync(OUT, 'utf8')) as KeyFile;
  console.log('keys/devnet.json already exists — reusing (not overwriting).');
} else {
  const feePayer = PrivateKey.random();
  const zkApp = PrivateKey.random();
  data = {
    feePayer: { publicKey: feePayer.toPublicKey().toBase58(), privateKey: feePayer.toBase58() },
    zkApp: { publicKey: zkApp.toPublicKey().toBase58(), privateKey: zkApp.toBase58() },
  };
  mkdirSync(KEYS_DIR, { recursive: true });
  const onDisk = {
    _warning: 'SYNTHETIC / NON-PRODUCTION DEVNET TEST KEYS — DO NOT COMMIT, NEVER USE ON MAINNET',
    network: 'devnet',
    ...data,
  };
  writeFileSync(OUT, `${JSON.stringify(onDisk, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  console.log('Generated Devnet keypairs → keys/devnet.json (git-ignored; DO NOT COMMIT).');
}

const faucet = `https://faucet.minaprotocol.com/?address=${data.feePayer.publicKey}`;

console.log('');
console.log('  Fee-payer public address :', data.feePayer.publicKey);
console.log('  zkApp public address     :', data.zkApp.publicKey);
console.log('');
console.log('  Faucet (network: Devnet) :', faucet);
console.log('');
console.log('  NEXT (manual — NOT this step):');
console.log('   1. Open the faucet URL, select **Devnet**, request tMINA for the fee-payer.');
console.log('   2. Wait ~3-5 minutes for the funds to arrive.');
console.log('   3. Run the live-deploy step (a SEPARATE task) to broadcast FiscAnchor.');
console.log('');
console.log('  STOP — this step performs NO live broadcast. (Before the live deploy, confirm');
console.log('  the current Devnet protocol vs o1js: if Devnet has activated the Mesa hard fork,');
console.log('  the deploy needs o1js 3.0.0-mesa.*; 2.15.0 targets the current stable Devnet.)');
