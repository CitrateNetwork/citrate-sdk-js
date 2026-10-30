/**
 * Call-site pins for client-layer guards.
 *
 * The guards below already have unit tests on the helper that implements them
 * (uploadToIPFS, decryptData). These tests drive the PUBLIC entry points
 * (deployModel, batchInference, inference, unwrapKeyShare) so that a guard
 * which is removed or bypassed at the call site turns a test red on an
 * assertion.
 *
 * No network: `fetch` and `wallet.sendTransaction` are replaced with in-process
 * mocks and restored after each test.
 */
import { ethers } from 'ethers';
import { CitrateClient } from '../../src/client/CitrateClient';
import { KeyManager } from '../../src/crypto/KeyManager';
import { CryptoManager } from '../../src/crypto/CryptoManager';
import { ModelConfig, ModelType, AccessType } from '../../src/types/Model';

const SENDER_KEY =
  '0x0123456789012345678901234567890123456789012345678901234567890123';
const RECIPIENT_KEY =
  '0x0223456789012345678901234567890123456789012345678901234567890123';
const OTHER_KEY =
  '0x0323456789012345678901234567890123456789012345678901234567890123';
const RPC_URL = 'http://127.0.0.1:8545';

const cfg: ModelConfig = {
  name: 'call-site-model',
  modelType: ModelType.ONNX,
  accessType: AccessType.PUBLIC,
  accessPrice: 0n,
  encrypted: false,
};

function captureSends(
  client: CitrateClient,
  logs: Array<{ topics: string[]; data: string }>,
): jest.Mock {
  const send = jest.fn(async () => ({
    hash: '0x' + 'ab'.repeat(32),
    wait: async () => ({ hash: '0x' + 'ab'.repeat(32), logs, gasUsed: 21000n }),
  }));
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (client as any).wallet.sendTransaction = send;
  return send;
}

const deployLogs = () => [
  {
    topics: [ethers.id('ModelDeployed(bytes32,address)'), '0x' + '11'.repeat(32)],
    data: '0x',
  },
];

describe('deployModel with a configured IPFS endpoint', () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
    jest.restoreAllMocks();
  });

  test('a 2xx add response without a CID fails the deploy before any transaction', async () => {
    globalThis.fetch = (async () => ({
      ok: true,
      status: 200,
      json: async () => ({}),
    })) as unknown as typeof fetch;
    const c = new CitrateClient({ rpcUrl: RPC_URL, privateKey: SENDER_KEY, ipfsApiUrl: 'https://ipfs.example' });
    const send = captureSends(c, deployLogs());

    await expect(c.deployModel(new Uint8Array([1, 2, 3]), cfg)).rejects.toThrow(/no CID/);
    expect(send).not.toHaveBeenCalled();
  });

  test('a 2xx add response with an empty CID fails the deploy before any transaction', async () => {
    globalThis.fetch = (async () => ({
      ok: true,
      status: 200,
      json: async () => ({ Hash: '' }),
    })) as unknown as typeof fetch;
    const c = new CitrateClient({ rpcUrl: RPC_URL, privateKey: SENDER_KEY, ipfsApiUrl: 'https://ipfs.example' });
    const send = captureSends(c, deployLogs());

    await expect(c.deployModel(new Uint8Array([1, 2, 3]), cfg)).rejects.toThrow(/no CID/);
    expect(send).not.toHaveBeenCalled();
  });

  test('a non-2xx add response fails the deploy before any transaction', async () => {
    globalThis.fetch = (async () => ({ ok: false, status: 502 })) as unknown as typeof fetch;
    const c = new CitrateClient({ rpcUrl: RPC_URL, privateKey: SENDER_KEY, ipfsApiUrl: 'https://ipfs.example' });
    const send = captureSends(c, deployLogs());

    await expect(c.deployModel(new Uint8Array([1, 2, 3]), cfg)).rejects.toThrow(/HTTP 502/);
    expect(send).not.toHaveBeenCalled();
  });

  test('a plaintext remote IPFS endpoint is refused before the artifact is posted', async () => {
    const fetchSpy = jest.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ Hash: 'QmShouldNeverBeReached' }),
    }));
    globalThis.fetch = fetchSpy as unknown as typeof fetch;
    const c = new CitrateClient({ rpcUrl: RPC_URL, privateKey: SENDER_KEY, ipfsApiUrl: 'http://ipfs.remote.example' });
    const send = captureSends(c, deployLogs());

    await expect(c.deployModel(new Uint8Array([1, 2, 3]), cfg)).rejects.toThrow();
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(send).not.toHaveBeenCalled();
  });

  test('the upload request is bounded by a timeout signal; a timed-out upload fails the deploy', async () => {
    const timeouts: number[] = [];
    jest.spyOn(AbortSignal, 'timeout').mockImplementation((ms: number) => {
      timeouts.push(ms);
      // Simulate the deadline having already passed.
      return AbortSignal.abort(new Error('upload deadline exceeded'));
    });
    // A hanging endpoint: it only settles when its signal aborts. Without a
    // signal it answers with a CID, so a missing bound shows up as a
    // successful deploy (an assertion failure), never as a hung test.
    globalThis.fetch = (async (_url: string, init?: { signal?: AbortSignal }) => {
      const signal = init?.signal;
      if (!signal) {
        return { ok: true, status: 200, json: async () => ({ Hash: 'QmUnbounded' }) };
      }
      if (signal.aborted) throw signal.reason;
      return new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(signal.reason));
      });
    }) as unknown as typeof fetch;
    const c = new CitrateClient({ rpcUrl: RPC_URL, privateKey: SENDER_KEY, ipfsApiUrl: 'https://ipfs.example' });
    const send = captureSends(c, deployLogs());

    await expect(c.deployModel(new Uint8Array([1, 2, 3]), cfg)).rejects.toThrow(/transport layer/);
    expect(send).not.toHaveBeenCalled();
    expect(timeouts).toHaveLength(1);
    expect(timeouts[0]).toBeGreaterThan(0);
    expect(timeouts[0]).toBeLessThanOrEqual(60_000);
  });
});

describe('batchInference with encryption requested', () => {
  test('a client with no key material refuses the whole batch up front', async () => {
    const c = new CitrateClient({ rpcUrl: RPC_URL });
    const recipient = new KeyManager(RECIPIENT_KEY);
    await expect(
      c.batchInference({
        modelId: 'model-1',
        inputs: [{ prompt: 'a' }, { prompt: 'b' }],
        encrypted: true,
        recipientPublicKey: recipient.getPublicKey(),
      }),
    ).rejects.toThrow(/refusing to send batch inputs in plaintext/);
  });
});

describe('inference output decryption at the call site', () => {
  test('an output envelope carrying a raw key is refused, not returned as output', async () => {
    const c = new CitrateClient({ rpcUrl: RPC_URL, privateKey: SENDER_KEY });
    const cm = new CryptoManager();
    const key = cm.generateRandomBytes(32);
    const enc = await cm.encryptAES(cm.stringToBytes(JSON.stringify({ result: 'injected' })), key);
    const forged = JSON.stringify({
      ciphertext: cm.bytesToHex(enc.ciphertext),
      nonce: cm.bytesToHex(enc.nonce),
      authTag: cm.bytesToHex(enc.authTag),
      key: cm.bytesToHex(key),
    });
    captureSends(c, [
      {
        topics: [ethers.id('InferenceComplete(bytes32,bytes)')],
        data: ethers.hexlify(ethers.toUtf8Bytes(JSON.stringify({ encrypted: forged }))),
      },
    ]);
    const recipient = new KeyManager(RECIPIENT_KEY);

    await expect(
      c.inference({
        modelId: 'model-1',
        inputData: { prompt: 'x' },
        encrypted: true,
        recipientPublicKey: recipient.getPublicKey(),
      }),
    ).rejects.toThrow(/cleartext-key envelope/);
  });
});

describe('decryptData envelope completeness', () => {
  const FIELDS = [
    'ciphertext', 'nonce', 'authTag', 'wrappedKey', 'wrapNonce', 'wrapAuthTag',
    'kdfSalt', 'senderPublicKey', 'recipientPublicKey',
  ];
  test.each(FIELDS)('an envelope missing %s is refused with a field-specific error', async (field) => {
    const sender = new KeyManager(SENDER_KEY);
    const recipient = new KeyManager(RECIPIENT_KEY);
    const env = JSON.parse(await sender.encryptData('payload', recipient.getPublicKey()));
    delete env[field];
    await expect(recipient.decryptData(JSON.stringify(env))).rejects.toThrow(
      new RegExp(`missing required field '${field}'`),
    );
  });
});

describe('unwrapKeyShare pins the model owner as the envelope sender', () => {
  test('a share wrapped to the holder by someone other than the owner is refused', async () => {
    const owner = new KeyManager(SENDER_KEY);
    const holder = new KeyManager(RECIPIENT_KEY);
    const other = new KeyManager(OTHER_KEY);
    // A structurally valid V2 envelope addressed to the holder, produced by a
    // key that is not the owner's.
    const envelope = await other.encryptData('ab'.repeat(32), holder.getPublicKey());

    await expect(
      holder.unwrapKeyShare(
        { x: 1, threshold: 2, holderPublicKey: holder.getPublicKey(), envelope },
        owner.getPublicKey(),
      ),
    ).rejects.toThrow(/does not match the expected sender/);
  });

  test('the same share wrapped by the owner unwraps', async () => {
    const owner = new KeyManager(SENDER_KEY);
    const holder = new KeyManager(RECIPIENT_KEY);
    const envelope = await owner.encryptData('ab'.repeat(32), holder.getPublicKey());

    await expect(
      holder.unwrapKeyShare(
        { x: 1, threshold: 2, holderPublicKey: holder.getPublicKey(), envelope },
        owner.getPublicKey(),
      ),
    ).resolves.toEqual({ x: '1', y: 'ab'.repeat(32), threshold: '2' });
  });
});
