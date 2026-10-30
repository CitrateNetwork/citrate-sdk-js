/**
 * Call-site pins for client and crypto guards that existing tests did not
 * observe: each test below fails when the named guard is reverted.
 *
 *  - Shamir coefficients come from Web Crypto, not Math.random.
 *  - ECDH KEK = HKDF-SHA256 over the full 32-byte shared x-coordinate
 *    (known-answer test computed independently with node:crypto).
 *  - Key-derived temporaries are wiped after use; the public key is cached.
 *  - Several RPC URLs build a FallbackProvider; a JSON-RPC error body from a
 *    reachable node is surfaced, not retried against the next endpoint.
 *  - The HTTP User-Agent tracks the SDK version.
 *
 * Keys are fixed throwaway test scalars. No socket is opened: RPC URLs are
 * loopback and the HTTP clients are stubbed.
 */
import { createECDH, hkdfSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ethers } from 'ethers';
import { ShamirSecretSharing, splitSecretBytes } from '../../src/crypto/FiniteField';
import { KeyManager } from '../../src/crypto/KeyManager';
import { CitrateClient } from '../../src/client/CitrateClient';
import { CitrateError } from '../../src/errors/CitrateError';
import { SDK_VERSION } from '../../src/utils/constants';

const SENDER_KEY = '0x0123456789012345678901234567890123456789012345678901234567890123';
const RECIPIENT_KEY = '0x0223456789012345678901234567890123456789012345678901234567890123';

afterEach(() => {
  jest.restoreAllMocks();
});

describe('Shamir coefficients are drawn from Web Crypto', () => {
  test('a constant Math.random does not make two splits of one secret identical', () => {
    jest.spyOn(Math, 'random').mockReturnValue(0.42);
    const sss = new ShamirSecretSharing(3, 5);
    const secret = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const a = sss.splitSecret(secret).flatMap((s) => Array.from(s.y));
    const b = sss.splitSecret(secret).flatMap((s) => Array.from(s.y));
    expect(a).not.toEqual(b);
  });

  test('splitSecretBytes (the KeyManager share path) calls getRandomValues', () => {
    const spy = jest.spyOn(globalThis.crypto, 'getRandomValues');
    const mathSpy = jest.spyOn(Math, 'random');
    splitSecretBytes(new Uint8Array(32).fill(0xab), 2, 3);
    expect(spy).toHaveBeenCalled();
    expect(mathSpy).not.toHaveBeenCalled();
  });

  test('when getRandomValues yields a fixed stream, the shares follow it', () => {
    // Control for the test above: the coefficients really come from this source.
    jest
      .spyOn(globalThis.crypto, 'getRandomValues')
      .mockImplementation(<T extends ArrayBufferView | null>(arr: T): T => {
        if (arr) new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength).fill(0x11);
        return arr;
      });
    const sss = new ShamirSecretSharing(2, 3);
    const a = sss.splitSecret(new Uint8Array([9, 9]));
    const b = sss.splitSecret(new Uint8Array([9, 9]));
    expect(a.map((s) => Array.from(s.y))).toEqual(b.map((s) => Array.from(s.y)));
  });
});

describe('ECDH KEK known-answer test', () => {
  function expectedKek(priv: string, peerUncompressedHex: string, salt: Uint8Array, info: Uint8Array) {
    const ecdh = createECDH('secp256k1');
    ecdh.setPrivateKey(Buffer.from(priv.slice(2), 'hex'));
    const x = ecdh.computeSecret(Buffer.from(peerUncompressedHex, 'hex')); // 32-byte x
    expect(x).toHaveLength(32);
    return Buffer.from(hkdfSync('sha256', x, salt, info, 32)).toString('hex');
  }

  test('deriveSharedKey equals HKDF-SHA256(full x, salt, info)', async () => {
    const sender = new KeyManager(SENDER_KEY);
    const recipient = new KeyManager(RECIPIENT_KEY);
    const salt = new Uint8Array(32).fill(3);
    const info = new TextEncoder().encode('citrate-kat');
    const got = await sender.deriveSharedKey(recipient.getPublicKey(), { salt, info });
    expect(Buffer.from(got).toString('hex')).toBe(
      expectedKek(SENDER_KEY, recipient.getPublicKey(), salt, info),
    );
  });
});

describe('key-derived temporaries are wiped', () => {
  test('the shared x-coordinate handed to HKDF is zeroed afterwards', async () => {
    const sender = new KeyManager(SENDER_KEY);
    const recipient = new KeyManager(RECIPIENT_KEY);
    const cm = (sender as any).cryptoManager;
    const seen: Uint8Array[] = [];
    const real = cm.hkdfSha256.bind(cm);
    jest.spyOn(cm, 'hkdfSha256').mockImplementation(async (...args: any[]) => {
      seen.push(args[0]);
      return real(...args);
    });
    await sender.deriveSharedKey(recipient.getPublicKey(), {
      salt: new Uint8Array(32),
      info: new Uint8Array([1]),
    });
    expect(seen).toHaveLength(1);
    expect(seen[0]!.some((b) => b !== 0)).toBe(false);
  });

  test('the owner-wrap PBKDF2 password is zeroed after deriving', async () => {
    const km = new KeyManager(SENDER_KEY);
    const cm = (km as any).cryptoManager;
    const passwords: Uint8Array[] = [];
    const real = cm.deriveKeyBytes.bind(cm);
    jest.spyOn(cm, 'deriveKeyBytes').mockImplementation(async (...args: any[]) => {
      passwords.push(args[0]);
      return real(...args);
    });
    await km.encryptModel(new Uint8Array([1, 2, 3]));
    expect(passwords.length).toBeGreaterThan(0);
    for (const p of passwords) {
      expect(p.length).toBeGreaterThan(32);
      expect(p.some((b) => b !== 0)).toBe(false);
    }
  });

  test('the private-key bytes copied into the wrap password are zeroed', async () => {
    const km = new KeyManager(SENDER_KEY);
    const cm = (km as any).cryptoManager;
    const privHex = SENDER_KEY.slice(2);
    const copies: Uint8Array[] = [];
    const real = cm.hexToBytes.bind(cm);
    jest.spyOn(cm, 'hexToBytes').mockImplementation((hex: unknown) => {
      const out = real(hex);
      if (typeof hex === 'string' && hex.toLowerCase() === privHex) copies.push(out);
      return out;
    });
    await km.encryptModel(new Uint8Array([4, 5, 6]));
    expect(copies.length).toBeGreaterThan(0);
    for (const c of copies) expect(c.some((b) => b !== 0)).toBe(false);
  });

  test('getPublicKey is computed once and then served from the cache', () => {
    const km = new KeyManager(SENDER_KEY);
    const wallet = (km as any).wallet;
    const proto = Object.getPrototypeOf(wallet);
    let holder = proto;
    while (holder && !Object.getOwnPropertyDescriptor(holder, 'signingKey')) {
      holder = Object.getPrototypeOf(holder);
    }
    expect(holder).toBeTruthy();
    const getter = jest.spyOn(holder, 'signingKey', 'get');
    const first = km.getPublicKey();
    const second = km.getPublicKey();
    const third = km.getPublicKey();
    expect(second).toBe(first);
    expect(third).toBe(first);
    expect(getter).toHaveBeenCalledTimes(1);
  });
});

describe('RPC failover', () => {
  const URLS = ['http://127.0.0.1:1', 'http://127.0.0.1:2'];

  test('several RPC URLs build an ethers FallbackProvider; one URL builds a JsonRpcProvider', () => {
    const multi = new CitrateClient({ rpcUrl: URLS });
    const single = new CitrateClient({ rpcUrl: URLS[0]! });
    expect((multi as any).provider).toBeInstanceOf(ethers.FallbackProvider);
    expect((single as any).provider).toBeInstanceOf(ethers.JsonRpcProvider);
    expect((single as any).provider).not.toBeInstanceOf(ethers.FallbackProvider);
  });

  test('a JSON-RPC error body from the primary is surfaced, not retried on the backup', async () => {
    const c = new CitrateClient({ rpcUrl: URLS });
    const pool = (c as any).axiosPool as Array<{ post: unknown }>;
    pool[0]!.post = async () => ({ data: { error: { code: 3, message: 'execution reverted' } } });
    const backup = jest.fn(async () => ({ data: { result: 'from-backup' } }));
    pool[1]!.post = backup;
    const p = (c as any).rpcCall('eth_call', []);
    await expect(p).rejects.toBeInstanceOf(CitrateError);
    await expect((c as any).rpcCall('eth_call', [])).rejects.toThrow(/execution reverted/);
    expect(backup).not.toHaveBeenCalled();
  });
});

describe('User-Agent', () => {
  test('carries the SDK version, which matches package.json', () => {
    const c = new CitrateClient({ rpcUrl: 'http://127.0.0.1:1' });
    const pkg = JSON.parse(readFileSync(join(__dirname, '..', '..', 'package.json'), 'utf8'));
    const ua = (c as any).axiosPool[0].defaults.headers['User-Agent'];
    expect(SDK_VERSION).toBe(pkg.version);
    expect(ua).toBe(`citrate-js-sdk/${pkg.version}`);
  });
});
