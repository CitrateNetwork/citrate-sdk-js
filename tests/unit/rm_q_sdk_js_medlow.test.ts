/**
 * RM-Q — regression tripwires for the med/low findings in the 2026-09-02
 * federation graded audit (citrate-sdk-js leg SJS-B-* + Leg-A C-02).
 *
 * Each block fails RED against the pre-fix behavior and GREEN after the fix.
 */
import * as fs from 'fs';
import * as path from 'path';
import { ethers } from 'ethers';
import { CitrateClient } from '../../src/client/CitrateClient';
import { KeyManager } from '../../src/crypto/KeyManager';
import { GF256 } from '../../src/crypto/FiniteField';
import {
  enforceTransportSecurity,
  InsecureTransportError,
} from '../../src/utils/transport';
import { signUserOpWithPasskey } from '../../src/aa/webauthn';

const SENDER_KEY =
  '0x0123456789012345678901234567890123456789012345678901234567890123';
const RECIPIENT_KEY =
  '0x0223456789012345678901234567890123456789012345678901234567890123';

// ── SJS-B-003 — keccak receipt topics (deploy/inference no longer always throw)
describe('SJS-B-003 — receipt topics matched by keccak, not an impossible ASCII literal', () => {
  test('the old literal can never equal a real keccak topic', () => {
    // The pre-fix matcher: startsWith('0x' + 'ModelDeployed'.slice(0,8)).
    expect('0x' + 'ModelDeployed'.slice(0, 8)).toBe('0xModelDep');
    expect(ethers.id('ModelDeployed(bytes32,address)').startsWith('0xModelDep')).toBe(false);
  });

  test('deployModel resolves the modelId from a realistic keccak-topic receipt', async () => {
    const c = new CitrateClient({ rpcUrl: 'http://127.0.0.1:8545', privateKey: SENDER_KEY });
    const modelId = '0x' + '11'.repeat(32);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (c as any).wallet.sendTransaction = async () => ({
      hash: '0x' + 'ab'.repeat(32),
      wait: async () => ({
        hash: '0x' + 'ab'.repeat(32),
        gasUsed: 21000n,
        logs: [{ topics: [ethers.id('ModelDeployed(bytes32,address)'), modelId], data: '0x' }],
      }),
    });
    const dep = await c.deployModel(new Uint8Array([1, 2, 3]), {
      name: 'm', modelType: 'onnx', accessType: 'public', accessPrice: 0n,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any);
    expect(dep.modelId).toBe(modelId);
  });

  test('unmatched receipt throws with the tx hash so the caller can recover (no blind retry)', () => {
    const c = new CitrateClient({ rpcUrl: 'http://127.0.0.1:8545' });
    const receipt = { hash: '0xdead', logs: [{ topics: ['0xdeadbeef'], data: '0x' }] };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => (c as any).extractModelIdFromReceipt(receipt)).toThrow(/0xdead/);
  });
});

// ── SJS-B-004 — decryptData fails closed on legacy/forged envelopes; sender pinning
describe('SJS-B-004 — decryptData refuses cleartext-key + V1 envelopes, pins the sender', () => {
  test('refuses an attacker-supplied cleartext-key envelope', async () => {
    const victim = new KeyManager(SENDER_KEY);
    const cm = victim['cryptoManager'];
    const key = cm.generateRandomBytes(32);
    const enc = await cm.encryptAES(cm.stringToBytes('ATTACKER CONTROLLED PLAINTEXT'), key);
    const forged = JSON.stringify({
      scheme: 'ecdh-secp256k1-aesgcm-v2',
      ciphertext: cm.bytesToHex(enc.ciphertext),
      nonce: cm.bytesToHex(enc.nonce),
      authTag: cm.bytesToHex(enc.authTag),
      key: cm.bytesToHex(key), // hostile
    });
    await expect(victim.decryptData(forged)).rejects.toThrow(/cleartext-key/);
  });

  test('refuses a V1 envelope on the read path', async () => {
    const victim = new KeyManager(SENDER_KEY);
    await expect(
      victim.decryptData(JSON.stringify({ scheme: 'ecdh-secp256k1-aesgcm-v1', wrappedKey: 'ab' })),
    ).rejects.toThrow(/unsupported envelope scheme/);
  });

  test('round-trips V2, and sender pinning accepts the real sender / rejects a mismatch', async () => {
    const sender = new KeyManager(SENDER_KEY);
    const recipient = new KeyManager(RECIPIENT_KEY);
    const attacker = new KeyManager('0x' + '33'.repeat(32));
    const env = await sender.encryptData(JSON.stringify({ x: 1 }), recipient.getPublicKey());
    // correct sender pin passes
    await expect(recipient.decryptData(env, sender.getPublicKey())).resolves.toBe('{"x":1}');
    // wrong sender pin fails BEFORE trusting the plaintext
    await expect(recipient.decryptData(env, attacker.getPublicKey())).rejects.toThrow(/does not match/);
  });
});

// ── SJS-B-005 — uploadToIPFS fails closed
describe('SJS-B-005 — uploadToIPFS fails closed when a configured endpoint fails', () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  test('throws (does not return a sha256 pseudo-pointer) on a transport error', async () => {
    globalThis.fetch = (async () => {
      throw new Error('ECONNREFUSED');
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    }) as any;
    const c = new CitrateClient({ rpcUrl: 'https://rpc.citrate.ai', ipfsApiUrl: 'https://ipfs.example' });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await expect((c as any).uploadToIPFS(new Uint8Array([1, 2, 3]))).rejects.toThrow(/Refusing to record/);
  });

  test('throws on a non-2xx response', async () => {
    globalThis.fetch = (async () => ({ ok: false, status: 500 })) as unknown as typeof fetch;
    const c = new CitrateClient({ rpcUrl: 'https://rpc.citrate.ai', ipfsApiUrl: 'https://ipfs.example' });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await expect((c as any).uploadToIPFS(new Uint8Array([1]))).rejects.toThrow(/HTTP 500/);
  });

  test('still returns a content hash when NO endpoint is configured (documented opt-out)', async () => {
    const c = new CitrateClient({ rpcUrl: 'https://rpc.citrate.ai' });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await expect((c as any).uploadToIPFS(new Uint8Array([1]))).resolves.toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});

// ── SJS-B-008 — multi-RPC failover actually exists
describe('SJS-B-008 — rpcCall fails over to the next endpoint on a transport error', () => {
  test('a request that fails on the primary succeeds on the backup', async () => {
    const c = new CitrateClient({
      rpcUrl: ['https://primary.example', 'https://backup.example'],
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const pool = (c as any).axiosPool as Array<{ post: unknown }>;
    expect(pool).toHaveLength(2);
    pool[0]!.post = async () => {
      throw new Error('ETIMEDOUT'); // transport failure, not a JSON-RPC error body
    };
    pool[1]!.post = async () => ({ data: { result: 'from-backup' } });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const out = await (c as any).rpcCall('citrate_ping', []);
    expect(out).toBe('from-backup');
  });
});

// ── SJS-B-009 — ECDH derives the same KEK on both sides (full x-coordinate + HKDF)
describe('SJS-B-009 — deriveSharedKey KAT: sender and recipient agree', () => {
  test('both endpoints derive the identical 32-byte KEK', async () => {
    const sender = new KeyManager(SENDER_KEY);
    const recipient = new KeyManager(RECIPIENT_KEY);
    const salt = new Uint8Array(32).fill(7);
    const info = new TextEncoder().encode('kat');
    const a = await sender.deriveSharedKey(recipient.getPublicKey(), { salt, info });
    const b = await recipient.deriveSharedKey(sender.getPublicKey(), { salt, info });
    expect(a).toHaveLength(32);
    expect(Buffer.from(a).toString('hex')).toBe(Buffer.from(b).toString('hex'));
  });

  test('accepts a compressed / 0x-prefixed peer key without mangling it', async () => {
    const sender = new KeyManager(SENDER_KEY);
    const recipient = new KeyManager(RECIPIENT_KEY);
    const salt = new Uint8Array(32).fill(9);
    const info = new TextEncoder().encode('kat2');
    const uncompressed = recipient.getPublicKey(); // 04.. (no 0x)
    const compressed = ethers.SigningKey.computePublicKey('0x' + uncompressed, true); // 0x02/03..
    const fromUncompressed = await sender.deriveSharedKey(uncompressed, { salt, info });
    const fromCompressed = await sender.deriveSharedKey(compressed, { salt, info });
    expect(Buffer.from(fromUncompressed).toString('hex')).toBe(
      Buffer.from(fromCompressed).toString('hex'),
    );
  });
});

// ── SJS-B-010 — WebAuthn signing defaults to userVerification:'required'
describe("SJS-B-010 — passkey signing defaults userVerification to 'required'", () => {
  test('the default request options carry required user verification', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let captured: any;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (globalThis as any).navigator = {
      credentials: {
        get: async (opts: unknown) => {
          captured = opts;
          return null; // triggers "no credential returned" after we've captured
        },
      },
    };
    try {
      await signUserOpWithPasskey(('0x' + '00'.repeat(32)) as `0x${string}`);
    } catch {
      /* expected: no credential returned */
    } finally {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      delete (globalThis as any).navigator;
    }
    expect(captured.publicKey.userVerification).toBe('required');
  });
});

// ── SJS-B-011 — getPublicKey is cached (no throwaway Wallet on a hot path)
describe('SJS-B-011 — getPublicKey does not reconstruct a Wallet, source has no key-in-template', () => {
  test('getPublicKey is stable and does not build a new ethers.Wallet after construction', () => {
    const km = new KeyManager(SENDER_KEY); // build BEFORE spying (ctor legitimately uses Wallet)
    const spy = jest.spyOn(ethers, 'Wallet');
    const a = km.getPublicKey();
    const b = km.getPublicKey();
    expect(a).toBe(b);
    expect(spy).not.toHaveBeenCalled(); // pre-fix built a throwaway Wallet on every call
    spy.mockRestore();
  });

  test('KeyManager source no longer embeds the private key in a template literal', () => {
    const src = fs.readFileSync(path.join(__dirname, '../../src/crypto/KeyManager.ts'), 'utf8');
    expect(src).not.toMatch(/\$\{[^}]*privateKey[^}]*\}/);
  });
});

// ── Leg-A C-02 — constant-time GF(2^8): correctness + no secret-indexed tables
describe('Leg-A C-02 — GF(2^8) is table-free and still correct', () => {
  test('multiply matches known GF(2^8) vectors (AES field, 0x11b)', () => {
    // Standard test vectors for the AES field.
    expect(GF256.multiply(0x57, 0x13)).toBe(0xfe);
    expect(GF256.multiply(0x02, 0x87)).toBe(0x15);
    expect(GF256.multiply(0, 0x99)).toBe(0);
    expect(GF256.multiply(1, 0x99)).toBe(0x99);
  });

  test('inverse · a == 1 for every non-zero element', () => {
    for (let a = 1; a < 256; a++) {
      expect(GF256.multiply(a, GF256.inverse(a))).toBe(1);
    }
    expect(() => GF256.inverse(0)).toThrow();
  });

  test('the implementation uses no secret-indexed log/exp tables', () => {
    const src = fs.readFileSync(path.join(__dirname, '../../src/crypto/FiniteField.ts'), 'utf8');
    // No table declarations and no secret-indexed lookups remain.
    expect(src).not.toMatch(/static\s+(log|exp)Table/);
    expect(src).not.toMatch(/(log|exp)Table\s*\[/);
  });
});

// ── SJS-B / SPY-B-009 mirror — transport security guard
describe('transport security — remote plaintext is refused, localhost/https pass', () => {
  test('remote http/ws throws by default', () => {
    expect(() => enforceTransportSecurity('http://gateway.example.com')).toThrow(InsecureTransportError);
    expect(() => enforceTransportSecurity('ws://node.example.com:8546')).toThrow(InsecureTransportError);
  });

  test('loopback http and https/wss pass silently', () => {
    expect(enforceTransportSecurity('http://localhost:8545')).toMatch(/^http:/);
    expect(enforceTransportSecurity('http://127.0.0.1:5001')).toMatch(/^http:/);
    expect(enforceTransportSecurity('https://rpc.citrate.ai')).toMatch(/^https:/);
    expect(enforceTransportSecurity('wss://rpc.citrate.ai/ws')).toMatch(/^wss:/);
  });

  test('allowInsecureHttp opts in to a remote plaintext endpoint', () => {
    expect(enforceTransportSecurity('http://lab.internal:8545', { allowInsecureHttp: true })).toMatch(/^http:/);
  });

  test('CitrateClient refuses a remote http RPC by default but accepts it with the opt-in', () => {
    expect(() => new CitrateClient({ rpcUrl: 'http://gateway.example.com' })).toThrow(InsecureTransportError);
    expect(
      () => new CitrateClient({ rpcUrl: 'http://gateway.example.com', allowInsecureHttp: true }),
    ).not.toThrow();
  });
});
