#!/usr/bin/env node
/**
 * PBA-L4-001 tripwire against the BUILT artifact, not the source tree.
 *
 * Packs the package exactly as `npm publish` would (`npm pack`), unpacks the
 * tarball, loads its `dist/index.js`, and drives the public
 * `CitrateClient.deployModel` with a capturing transport:
 *   1. thresholdShares > 0 without holder keys must be refused before any send;
 *   2. with holder keys, no subset of the captured deploy calldata may
 *      reconstruct the model key (scripts/keyshare-leak-tripwire.js);
 *   3. the holders must still be able to rebuild the key from their envelopes
 *      (so the check is not passing because sharing silently broke).
 *
 * Usage: node scripts/check-keyshare-pack.mjs [path/to/package.tgz]
 * Without an argument it runs `npm pack` itself (requires a prior build).
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const { revealsKey } = require('./keyshare-leak-tripwire.js');

function fail(msg) {
  console.error(`PBA-L4-001 pack tripwire FAILED: ${msg}`);
  process.exit(1);
}

let tarball = process.argv[2];
const tmp = mkdtempSync(path.join(repo, '.pack-check-'));
try {
  if (!tarball) {
    const out = execFileSync('npm', ['pack', '--silent', '--pack-destination', tmp], { cwd: repo, encoding: 'utf8' });
    tarball = path.join(tmp, out.trim().split('\n').pop());
  }
  if (!existsSync(tarball)) fail(`tarball not found: ${tarball}`);
  const unpack = path.join(tmp, 'unpacked');
  mkdirSync(unpack);
  execFileSync('tar', ['-xzf', tarball, '-C', unpack]);
  // Unpacked under the repo so `ethers` etc. resolve from the repo's node_modules.
  const sdk = require(path.join(unpack, 'package', 'dist', 'index.js'));
  const { CitrateClient, KeyManager } = sdk;
  const pkg = require(path.join(unpack, 'package', 'package.json'));

  const OWNER = '0x' + '11'.repeat(32);
  const HOLDERS = ['0x' + '22'.repeat(32), '0x' + '33'.repeat(32), '0x' + '44'.repeat(32)];
  const MODEL = new TextEncoder().encode('proprietary-model-weights');
  const DEPLOYED_TOPIC = require('ethers').ethers.id('ModelDeployed(bytes32,address)');

  const client = new CitrateClient({ rpcUrl: 'http://127.0.0.1:8545', privateKey: OWNER });
  const captured = [];
  client.wallet.sendTransaction = async (tx) => {
    captured.push(tx.data);
    return {
      hash: '0x' + 'ab'.repeat(32),
      wait: async () => ({ logs: [{ topics: [DEPLOYED_TOPIC], data: '0x' + 'ab'.repeat(64) }], gasUsed: 21000n }),
    };
  };
  const base = {
    name: 'm', modelType: sdk.ModelType.ONNX, accessType: sdk.AccessType.PUBLIC, accessPrice: 0n, encrypted: true,
    encryptionConfig: { algorithm: 'AES-256-GCM', keyDerivation: 'HKDF-SHA256', accessControl: true, thresholdShares: 2, totalShares: 3 },
  };

  // 1. refusal without holders
  let refused = false;
  try {
    await client.deployModel(MODEL, base);
  } catch (e) {
    refused = /shareHolderPublicKeys/.test(String(e && e.message));
  }
  if (!refused) fail('thresholdShares > 0 without shareHolderPublicKeys was not refused');
  if (captured.length !== 0) fail('a transaction was sent for the refused deploy');

  // 2. holder-wrapped deploy: calldata must not reveal the key
  const holderPubs = HOLDERS.map((k) => new KeyManager(k).getPublicKey());
  const dep = await client.deployModel(MODEL, {
    ...base,
    encryptionConfig: { ...base.encryptionConfig, shareHolderPublicKeys: holderPubs },
  });
  if (captured.length !== 1) fail(`expected 1 captured tx, got ${captured.length}`);
  const payload = JSON.parse(Buffer.from(captured[0].slice(2), 'hex').toString('utf8'));
  const key = await new KeyManager(OWNER).decryptKeyFromOwner(payload.metadata.encryption.encryptedKey);
  const verdict = revealsKey(captured[0], key);
  if (verdict.reveals) fail(`deploy calldata reveals the model key (${verdict.how})`);

  // 3. holders can still rebuild it off-chain
  const ownerPub = new KeyManager(OWNER).getPublicKey();
  const envs = dep.keyShareEnvelopes || [];
  if (envs.length !== 3) fail(`expected 3 key-share envelopes, got ${envs.length}`);
  const s0 = await new KeyManager(HOLDERS[0]).unwrapKeyShare(envs[0], ownerPub);
  const s1 = await new KeyManager(HOLDERS[1]).unwrapKeyShare(envs[1], ownerPub);
  const rebuilt = new KeyManager(HOLDERS[0]).reconstructKeyFromShares([s0, s1], 2);
  if (Buffer.compare(Buffer.from(rebuilt), Buffer.from(key)) !== 0) fail('holders could not rebuild the key');

  console.log(`PBA-L4-001 pack tripwire PASSED for ${pkg.name}@${pkg.version} (${path.basename(tarball)})`);
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
