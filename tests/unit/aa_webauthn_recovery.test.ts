/**
 * EW-S1 WP-7 — WebAuthn signature encoding + guardian-recovery builder.
 *
 * The WebAuthn blob layout is pinned to `WebAuthnP256Validator.sol`
 * (abi.encode(bytes,string,uint256,uint256,uint256,uint256)) and the
 * vendored Daimo `WebAuthn.sol` semantics (challengeLocation /
 * responseTypeLocation are byte indexes of the exact substrings).
 * Recovery digests/blobs are pinned to `GuardianRecoveryModule.sol`
 * (`keccak256(userOpHash ++ account)`, threshold × 65-byte sigs).
 */

import { AbiCoder, Wallet, getBytes, keccak256, solidityPacked } from 'ethers';

import {
  base64UrlEncode,
  encodeWebauthnValidatorSignature,
  normalizeP256S,
  parseDerEcdsaSignature,
  P256_N,
  P256_N_DIV_2,
  WebAuthnSigningError,
} from '../../src/aa/webauthn';
import {
  buildRotateSignerCall,
  guardianRecoveryDigest,
  packGuardianSignatures,
  RecoveryError,
} from '../../src/aa/recovery';
import { signUserOpWithEoa } from '../../src/aa/eoa';
import { validatorNonceKey, EXECUTE_SELECTOR } from '../../src/aa/kernel';

const coder = AbiCoder.defaultAbiCoder();

const USER_OP_HASH =
  '0x5369c256d308e61a1fe8b15aaaa7709fee6b8edd46b5c452a9bc5ec8965629fd' as const;

function makeClientDataJSON(challenge: Uint8Array): string {
  return (
    '{"type":"webauthn.get","challenge":"' +
    base64UrlEncode(challenge) +
    '","origin":"https://auth.citrate.ai","crossOrigin":false}'
  );
}

describe('WebAuthn validator signature encoding', () => {
  const challenge = getBytes(USER_OP_HASH);
  const authenticatorData = new Uint8Array(37).fill(1); // ≥37 bytes; flags at [32]

  it('encodes the 6-tuple the validator abi.decodes, with correct locations', () => {
    const clientDataJSON = makeClientDataJSON(challenge);
    const r = 123n;
    const s = 456n;
    const blob = encodeWebauthnValidatorSignature(
      { authenticatorData, clientDataJSON, r, s },
      challenge,
    );

    const [authData, cdj, challengeLoc, typeLoc, rOut, sOut] = coder.decode(
      ['bytes', 'string', 'uint256', 'uint256', 'uint256', 'uint256'],
      blob,
    );
    expect(cdj).toBe(clientDataJSON);
    expect(authData).toBe(
      '0x' + Buffer.from(authenticatorData).toString('hex'),
    );
    // The Daimo verifier `contains()`-checks these exact substrings at
    // the given byte offsets.
    const challengeProperty = `"challenge":"${base64UrlEncode(challenge)}"`;
    expect(cdj.slice(Number(challengeLoc), Number(challengeLoc) + challengeProperty.length)).toBe(
      challengeProperty,
    );
    expect(cdj.slice(Number(typeLoc), Number(typeLoc) + '"type":"webauthn.get"'.length)).toBe(
      '"type":"webauthn.get"',
    );
    expect(rOut).toBe(r);
    expect(sOut).toBe(s);
  });

  it('normalizes a high-s into the lower half order (Daimo rejects high-s)', () => {
    const highS = P256_N_DIV_2 + 5n;
    const blob = encodeWebauthnValidatorSignature(
      {
        authenticatorData,
        clientDataJSON: makeClientDataJSON(challenge),
        r: 1n,
        s: highS,
      },
      challenge,
    );
    const [, , , , , sOut] = coder.decode(
      ['bytes', 'string', 'uint256', 'uint256', 'uint256', 'uint256'],
      blob,
    );
    expect(sOut).toBe(P256_N - highS);
    expect(sOut <= P256_N_DIV_2).toBe(true);
  });

  it('rejects a clientDataJSON that does not carry the challenge', () => {
    expect(() =>
      encodeWebauthnValidatorSignature(
        {
          authenticatorData,
          clientDataJSON: makeClientDataJSON(new Uint8Array(32).fill(9)),
          r: 1n,
          s: 1n,
        },
        challenge,
      ),
    ).toThrow(WebAuthnSigningError);
  });

  it('parses DER ECDSA signatures and round-trips through normalization', () => {
    // Minimal DER: SEQUENCE { INTEGER 0x05, INTEGER 0x07 }
    const der = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07]);
    const { r, s } = parseDerEcdsaSignature(der);
    expect(r).toBe(5n);
    expect(s).toBe(7n);
    expect(normalizeP256S(s)).toBe(7n);
    expect(() => parseDerEcdsaSignature(new Uint8Array([1, 2, 3]))).toThrow(
      WebAuthnSigningError,
    );
  });
});

describe('guardian recovery', () => {
  const account = '0x5cE327300221659b66323dC344C2275A7DA756fF' as const;

  it('digest = keccak256(userOpHash ++ account), matching the module', () => {
    expect(guardianRecoveryDigest(USER_OP_HASH, account)).toBe(
      keccak256(solidityPacked(['bytes32', 'address'], [USER_OP_HASH, account])),
    );
  });

  it('packs exactly N 65-byte signatures and rejects malformed ones', async () => {
    // Real ECDSA over the recovery digest, EIP-191 shape (the module's
    // second recovery branch). Wallets are throwaway test keys.
    const g1 = new Wallet(
      '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
    );
    const g2 = new Wallet(
      '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a',
    );
    const digest = guardianRecoveryDigest(USER_OP_HASH, account);
    const s1 = (await g1.signMessage(getBytes(digest))) as `0x${string}`;
    const s2 = (await g2.signMessage(getBytes(digest))) as `0x${string}`;

    const blob = packGuardianSignatures([s1, s2]);
    expect(blob.length).toBe(2 + 130 * 2);
    expect(blob).toBe(s1 + s2.slice(2));

    expect(() => packGuardianSignatures([])).toThrow(RecoveryError);
    expect(() => packGuardianSignatures(['0x1234'])).toThrow(RecoveryError);
  });

  it('buildRotateSignerCall self-calls changeRootValidator under the recovery nonce key', () => {
    const guardianModule = '0x42F3d7842d382D47199533a6BFcceAF483C6C857' as const;
    const webauthnValidator = '0x97FF6d1C4d2f4337EC09F2a1c01808016f728dEf' as const;
    const { callData, nonceKey } = buildRotateSignerCall(
      {
        account,
        webauthnValidator,
        newPasskey: {
          credentialIdHash: ('0x' + 'cd'.repeat(32)) as `0x${string}`,
          x: ('0x' + 'aa'.repeat(32)) as `0x${string}`,
          y: ('0x' + 'bb'.repeat(32)) as `0x${string}`,
          requireUserVerification: true,
        },
      },
      guardianModule,
    );

    expect(nonceKey).toBe(validatorNonceKey(guardianModule));
    expect(callData.startsWith(EXECUTE_SELECTOR)).toBe(true);

    // The single-call execution targets the account itself (self-call),
    // value 0 — the packed form is target ++ value ++ data.
    const [, exec] = coder.decode(['bytes32', 'bytes'], '0x' + callData.slice(10));
    expect(exec.slice(0, 42).toLowerCase()).toBe(account.toLowerCase());
    const value = BigInt('0x' + exec.slice(42, 42 + 64));
    expect(value).toBe(0n);
    // The inner data is changeRootValidator(bytes21,address,bytes,bytes).
    const inner = '0x' + exec.slice(42 + 64);
    expect(inner.slice(0, 10)).toBe('0x52141cd9');
  });
});

describe('signUserOpWithEoa', () => {
  it('produces a 65-byte EIP-191 signature the ECDSA validator accepts', async () => {
    const wallet = new Wallet(
      '0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba',
    );
    const sig = await signUserOpWithEoa(wallet, USER_OP_HASH);
    expect(sig.length).toBe(2 + 65 * 2);
    // ethers verifyMessage recovers the signer for the EIP-191 shape —
    // the same recovery branch CitrateECDSAValidator falls back to.
    const { verifyMessage } = await import('ethers');
    expect(verifyMessage(getBytes(USER_OP_HASH), sig)).toBe(wallet.address);
  });
});
