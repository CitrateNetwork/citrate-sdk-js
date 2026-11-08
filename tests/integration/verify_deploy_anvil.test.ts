/**
 * deployAndVerify through CitrateClient's real signer path on a local anvil.
 *
 * Skipped unless CITRATE_VERIFY_ANVIL_RPC and CITRATE_VERIFY_ANVIL_KEY are set (start
 * `anvil --chain-id 40204` and pass one of its funded dev keys; no key is stored here).
 * The chain is real; the explorer is a test-only recorder, since this checks what the SDK
 * sends: the creation transaction on chain must be exactly the build-info's creation code
 * plus the encoded constructor arguments, and the explorer submission must name that
 * transaction and those arguments.
 */
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ethers } from 'ethers';
import { CitrateClient, deployAndVerify, type BuildInfo } from '../../src';

const RPC = process.env.CITRATE_VERIFY_ANVIL_RPC;
const KEY = process.env.CITRATE_VERIFY_ANVIL_KEY;
const maybe = RPC && KEY ? describe : describe.skip;

maybe('deployAndVerify on anvil', () => {
  it('deploys from forge build-info and submits the creation tx to the explorer', async () => {
    const bodies: string[] = [];
    const answers = [
      JSON.stringify({ status: '1', message: 'OK', result: 'guid-anvil' }),
      JSON.stringify({ status: '1', message: 'OK', result: 'Pass - Verified' }),
    ];
    const server = createServer((req, res) => {
      let b = '';
      req.on('data', (c: Buffer) => (b += c.toString('utf8')));
      req.on('end', () => {
        bodies.push(b);
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(answers.shift() ?? answers[0]);
      });
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const explorerUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api`;

    const buildInfo = JSON.parse(
      readFileSync(join(__dirname, '..', 'fixtures', 'verify', 'forge', 'build-info', '970692f6b0ae96cc.json'), 'utf8'),
    ) as BuildInfo;
    const client = new CitrateClient({ rpcUrl: RPC as string, privateKey: KEY as string, expectedGenesisHash: null });
    try {
      const r = await deployAndVerify({
        client,
        chainId: 40204,
        buildInfo,
        contract: 'src/Greeter.sol:Greeter',
        args: [7n, 'hello'],
        explorerUrl,
        pollIntervalMs: 10,
      });

      const provider = new ethers.JsonRpcProvider(RPC);
      const tx = await provider.getTransaction(r.txHash);
      const greeter = buildInfo.output?.contracts?.['src/Greeter.sol']?.['Greeter'];
      const encoded = new ethers.Interface(greeter?.abi as ethers.InterfaceAbi).encodeDeploy([7n, 'hello']).slice(2);
      expect(tx?.data).toBe(`0x${greeter?.evm?.bytecode?.object}${encoded}`);
      expect((await provider.getCode(r.address)).length).toBeGreaterThan(2);
      provider.destroy();

      const submitted = Object.fromEntries(new URLSearchParams(bodies[0]));
      expect(submitted.contractaddress).toBe(r.address);
      expect(submitted.creationtxhash).toBe(r.txHash);
      expect(submitted.constructorArguements).toBe(encoded);
      expect(r.verification.status).toBe('verified');
    } finally {
      await new Promise<void>((res) => server.close(() => res()));
    }
  });
});
