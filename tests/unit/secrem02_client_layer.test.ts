/**
 * SECREM-02 5.4 — client-layer remediation tripwires.
 *
 * Covers, red-test-first:
 *  - FUA-SDK-JS-01 (MED): `batchInference` silently dropped encryption —
 *    with encryption configured, every batched input went out as plaintext
 *    on public calldata. Batch must encrypt exactly like single calls and
 *    fail closed when encryption is configured but cannot be applied.
 *  - CITRATE_SDK_JS-2026-05-31-003 (HIGH): the exported validation layer
 *    was dead code — no public mutating method ever invoked it.
 *  - CITRATE_SDK_JS-2026-05-31-004 (HIGH): `purchaseModelAccess` sent buyer
 *    `value` to 0x..0104 = INFERENCE_VERIFY (node `addresses::PROOF_VERIFY`);
 *    the canonical dispatch table has no access-purchase precompile at all,
 *    and the client hardcoded address literals instead of using
 *    `PRECOMPILE_ADDRESSES`.
 *
 * The transport is mocked at `wallet.sendTransaction` — nothing leaves the
 * process; assertions inspect exactly what would have hit public calldata.
 */
import * as fs from 'fs';
import * as path from 'path';
import { ethers } from 'ethers';
import { CitrateClient } from '../../src/client/CitrateClient';
import { KeyManager } from '../../src/crypto/KeyManager';
import { PRECOMPILE_ADDRESSES } from '../../src/utils/constants';
import { ModelConfig, ModelType, AccessType } from '../../src/types/Model';
import { CitrateError, ValidationError } from '../../src/errors/CitrateError';

const SENDER_KEY =
  '0x0123456789012345678901234567890123456789012345678901234567890123';
const RECIPIENT_KEY =
  '0x0223456789012345678901234567890123456789012345678901234567890123';
const RPC_URL = 'http://127.0.0.1:8545';

interface CapturedTx {
  to: string;
  data: string;
  value?: bigint | undefined;
}

/**
 * Replace the wallet's sendTransaction with a capture mock so we can assert
 * on the exact calldata/address/value the SDK would broadcast.
 */
function mockTransport(
  client: CitrateClient,
  receiptLogs: Array<{ topics: string[]; data: string }>
): { captured: CapturedTx[]; sendTransaction: jest.Mock } {
  const captured: CapturedTx[] = [];
  const sendTransaction = jest.fn(async (tx: CapturedTx) => {
    captured.push({ to: tx.to, data: tx.data, value: tx.value });
    return {
      hash: '0x' + 'ab'.repeat(32),
      wait: async () => ({ logs: receiptLogs, gasUsed: 21000n })
    };
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (client as any).wallet.sendTransaction = sendTransaction;
  return { captured, sendTransaction };
}

function inferenceReceiptLogs(): Array<{ topics: string[]; data: string }> {
  return [
    {
      topics: ['0xInferenceComplete'],
      data: ethers.hexlify(ethers.toUtf8Bytes(JSON.stringify({ result: 'ok' })))
    }
  ];
}

function deployReceiptLogs(): Array<{ topics: string[]; data: string }> {
  return [{ topics: ['0xModelDeployed'], data: '0x' + 'ab'.repeat(64) }];
}

function newClient(): CitrateClient {
  return new CitrateClient({ rpcUrl: RPC_URL, privateKey: SENDER_KEY });
}

const validModelConfig: ModelConfig = {
  name: 'test-model',
  modelType: ModelType.ONNX,
  accessType: AccessType.PUBLIC,
  accessPrice: 0n,
  encrypted: false
};

describe('FUA-SDK-JS-01 — batchInference must encrypt exactly like single calls', () => {
  it('never puts plaintext batch inputs on calldata when encryption is configured', async () => {
    const client = newClient();
    const { captured } = mockTransport(client, inferenceReceiptLogs());
    const recipient = new KeyManager(RECIPIENT_KEY);

    const result = await client.batchInference({
      modelId: 'model-1',
      inputs: [{ prompt: 'TOP-SECRET-INPUT' }],
      encrypted: true,
      recipientPublicKey: recipient.getPublicKey()
    });

    expect(result.successCount).toBe(1);
    expect(captured).toHaveLength(1);
    const payload = JSON.parse(ethers.toUtf8String(captured[0]!.data));
    // The calldata must never contain the plaintext input.
    expect(JSON.stringify(payload)).not.toContain('TOP-SECRET-INPUT');
    expect(payload.encrypted).toBe(true);
    // And the envelope must be the real ECDH wrap: the intended recipient
    // can decrypt it back to the original input.
    const envelope = JSON.parse(payload.inputData);
    expect(envelope.wrappedKey).toBeDefined();
    await expect(recipient.decryptData(payload.inputData)).resolves.toBe(
      JSON.stringify({ prompt: 'TOP-SECRET-INPUT' })
    );
  });

  it('fails closed before any tx when encrypted is set without a recipient key', async () => {
    const client = newClient();
    const { sendTransaction } = mockTransport(client, inferenceReceiptLogs());

    await expect(
      client.batchInference({
        modelId: 'model-1',
        inputs: [{ prompt: 'TOP-SECRET-INPUT' }],
        encrypted: true
      })
    ).rejects.toThrow(/recipientPublicKey/);
    expect(sendTransaction).not.toHaveBeenCalled();
  });

  it('single-call inference fails closed (no plaintext downgrade) when no KeyManager is available', async () => {
    const client = newClient();
    const { sendTransaction } = mockTransport(client, inferenceReceiptLogs());
    const recipient = new KeyManager(RECIPIENT_KEY);
    // Simulate the encryption capability being unavailable.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (client as any).keyManager = undefined;

    await expect(
      client.inference({
        modelId: 'model-1',
        inputData: { prompt: 'TOP-SECRET-INPUT' },
        encrypted: true,
        recipientPublicKey: recipient.getPublicKey()
      })
    ).rejects.toThrow(CitrateError);
    expect(sendTransaction).not.toHaveBeenCalled();
  });

  it('deployModel fails closed (no plaintext upload) when encryption is requested but unavailable', async () => {
    const client = newClient();
    const { sendTransaction } = mockTransport(client, deployReceiptLogs());
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (client as any).keyManager = undefined;

    await expect(
      client.deployModel(new Uint8Array([1, 2, 3]), {
        ...validModelConfig,
        encrypted: true
      })
    ).rejects.toThrow(CitrateError);
    expect(sendTransaction).not.toHaveBeenCalled();
  });
});

describe('CITRATE_SDK_JS-2026-05-31-003 — validation layer must be wired, not dead code', () => {
  it('constructor rejects a non-http(s)/ws(s) RPC URL with ValidationError', () => {
    expect(
      () => new CitrateClient({ rpcUrl: 'ftp://rpc.citrate.ai' })
    ).toThrow(ValidationError);
  });

  it('constructor rejects a malformed private key with ValidationError', () => {
    expect(
      () => new CitrateClient({ rpcUrl: RPC_URL, privateKey: '0x12345' })
    ).toThrow(ValidationError);
  });

  it('deployModel rejects invalid config before any wallet activity', async () => {
    const client = newClient();
    const { sendTransaction } = mockTransport(client, deployReceiptLogs());

    await expect(
      client.deployModel(new Uint8Array([1, 2, 3]), {
        ...validModelConfig,
        name: ''
      })
    ).rejects.toThrow(ValidationError);
    expect(sendTransaction).not.toHaveBeenCalled();
  });

  it('deployModel rejects empty model data before any wallet activity', async () => {
    const client = newClient();
    const { sendTransaction } = mockTransport(client, deployReceiptLogs());

    await expect(
      client.deployModel(new Uint8Array([]), validModelConfig)
    ).rejects.toThrow(ValidationError);
    expect(sendTransaction).not.toHaveBeenCalled();
  });

  it('inference rejects a malformed modelId before any wallet activity', async () => {
    const client = newClient();
    const { sendTransaction } = mockTransport(client, inferenceReceiptLogs());

    await expect(
      client.inference({ modelId: '../../etc', inputData: { a: 1 } })
    ).rejects.toThrow(ValidationError);
    expect(sendTransaction).not.toHaveBeenCalled();
  });

  it('batchInference validates inputs up front — invalid batch throws, no tx leaves', async () => {
    const client = newClient();
    const { sendTransaction } = mockTransport(client, inferenceReceiptLogs());

    await expect(
      client.batchInference({
        modelId: 'bad model id!',
        inputs: [{ a: 1 }, { b: 2 }]
      })
    ).rejects.toThrow(ValidationError);
    expect(sendTransaction).not.toHaveBeenCalled();
  });
});

describe('CITRATE_SDK_JS-2026-05-31-004 — no payment to INFERENCE_VERIFY, no hardcoded precompiles', () => {
  it('purchaseModelAccess fails closed instead of routing value to the verify precompile', async () => {
    const client = newClient();
    const { sendTransaction } = mockTransport(client, []);

    await expect(
      client.purchaseModelAccess('model-1', 1_000_000_000_000_000_000n)
    ).rejects.toThrow(/access-purchase/);
    // Buyer funds must never leave toward 0x..0104 (INFERENCE_VERIFY).
    expect(sendTransaction).not.toHaveBeenCalled();
  });

  it('deployModel routes to the canonical INFERENCE_DEPLOY precompile from constants', async () => {
    const client = newClient();
    const { captured } = mockTransport(client, deployReceiptLogs());

    await client.deployModel(new Uint8Array([1, 2, 3]), validModelConfig);
    expect(captured).toHaveLength(1);
    expect(captured[0]!.to).toBe(PRECOMPILE_ADDRESSES.INFERENCE_DEPLOY);
  });

  it('inference routes to the canonical INFERENCE_RUN precompile from constants', async () => {
    const client = newClient();
    const { captured } = mockTransport(client, inferenceReceiptLogs());

    await client.inference({ modelId: 'model-1', inputData: { a: 1 } });
    expect(captured).toHaveLength(1);
    expect(captured[0]!.to).toBe(PRECOMPILE_ADDRESSES.INFERENCE_RUN);
  });

  it('tripwire: the client has no hardcoded precompile address literals', () => {
    const clientSrc = fs.readFileSync(
      path.join(__dirname, '../../src/client/CitrateClient.ts'),
      'utf8'
    );
    // Pre-fix the client sent txs to literal '0x0100...01xx' strings that
    // match no node dispatch address; all routing must come from
    // PRECOMPILE_ADDRESSES (constants.ts, mirrored from the node table).
    expect(clientSrc).not.toMatch(/to:\s*'0x01/);
    expect(clientSrc).toMatch(/PRECOMPILE_ADDRESSES/);
  });
});
