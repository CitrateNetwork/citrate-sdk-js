/**
 * PBA-L8-016 (SDK part): `CHAIN_IDS.MAINNET = 1` advertised Ethereum mainnet's
 * chain id as Citrate's. Citrate runs on 40204 only (chainId is permanent);
 * an integrator who picked `CHAIN_IDS.MAINNET` signed for chain 1, where
 * EIP-155 replay protection no longer separates the two networks.
 */
import * as fs from 'fs';
import * as path from 'path';
import { CHAIN_IDS } from '../../src/utils/constants';
import { FEDERATION_CONTRACT } from '../../src/generated/contract';

describe('PBA-L8-016: CHAIN_IDS names only Citrate chains', () => {
  it('has no MAINNET = 1 entry', () => {
    expect(Object.keys(CHAIN_IDS)).not.toContain('MAINNET');
    expect(Object.values(CHAIN_IDS)).not.toContain(1);
  });

  it('every CHAIN_IDS value is the federation chain id', () => {
    for (const v of Object.values(CHAIN_IDS)) expect(v).toBe(FEDERATION_CONTRACT.chain.chainId);
  });

  it('README does not document a mainnet chain id', () => {
    const readme = fs.readFileSync(path.join(__dirname, '../../README.md'), 'utf8');
    expect(readme).not.toMatch(/CHAIN_IDS\.MAINNET/);
  });
});
