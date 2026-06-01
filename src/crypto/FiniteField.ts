/**
 * Galois Field GF(2^8) implementation for Shamir's Secret Sharing
 * Uses irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11b)
 */

/**
 * Cryptographically secure random bytes via Web Crypto `getRandomValues`.
 *
 * FAIL-CLOSED: throws if no CSPRNG is available rather than silently degrading
 * to a predictable source. Shamir's information-theoretic secrecy depends on the
 * non-constant polynomial coefficients being drawn from a CSPRNG; `Math.random`
 * (V8 xorshift128+) is predictable and recoverable, which would let an attacker
 * reconstruct the secret from fewer than `threshold` shares.
 * Audit: CITRATE_SDK_JS-2026-05-31-001 (CRITICAL).
 */
function secureRandomBytes(length: number): Uint8Array {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c || typeof c.getRandomValues !== 'function') {
    throw new Error(
      'Shamir secret sharing requires a cryptographically secure RNG ' +
        '(Web Crypto getRandomValues), which is unavailable in this runtime. ' +
        'Refusing to generate share coefficients with a non-cryptographic source.',
    );
  }
  const out = new Uint8Array(length);
  c.getRandomValues(out);
  return out;
}

export class GF256 {
  private static expTable: number[] = [];
  private static logTable: number[] = [];
  private static initialized = false;

  /**
   * Initialize exponential and logarithm tables
   */
  private static initializeTables(): void {
    if (this.initialized) return;

    this.expTable = new Array(512);
    this.logTable = new Array(256);

    // Generate exponential table
    let x = 1;
    for (let i = 0; i < 255; i++) {
      this.expTable[i] = x;
      this.logTable[x] = i;
      x = this.multiplyRaw(x, 3); // 3 is a primitive element
    }

    // Handle overflow
    for (let i = 255; i < 512; i++) {
      this.expTable[i] = this.expTable[i - 255] ?? 0;
    }

    this.logTable[0] = 0; // Special case
    this.initialized = true;
  }

  /**
   * Raw multiplication without table lookup
   */
  private static multiplyRaw(a: number, b: number): number {
    let result = 0;
    while (b) {
      if (b & 1) {
        result ^= a;
      }
      a <<= 1;
      if (a & 0x100) {
        a ^= 0x11b; // Irreducible polynomial
      }
      b >>= 1;
    }
    return result & 0xff;
  }

  /**
   * Addition in GF(2^8) (XOR)
   */
  static add(a: number, b: number): number {
    return a ^ b;
  }

  /**
   * Subtraction in GF(2^8) (same as addition)
   */
  static subtract(a: number, b: number): number {
    return a ^ b;
  }

  /**
   * Multiplication in GF(2^8)
   */
  static multiply(a: number, b: number): number {
    this.initializeTables();

    if (a === 0 || b === 0) {
      return 0;
    }

    return this.expTable[(this.logTable[a] ?? 0) + (this.logTable[b] ?? 0)] ?? 0;
  }

  /**
   * Division in GF(2^8)
   */
  static divide(a: number, b: number): number {
    if (b === 0) {
      throw new Error('Division by zero in GF(2^8)');
    }

    if (a === 0) {
      return 0;
    }

    this.initializeTables();
    return this.expTable[(this.logTable[a] ?? 0) - (this.logTable[b] ?? 0) + 255] ?? 0;
  }

  /**
   * Exponentiation in GF(2^8)
   */
  static power(a: number, exp: number): number {
    if (exp === 0) {
      return 1;
    }
    if (a === 0) {
      return 0;
    }

    this.initializeTables();
    return this.expTable[((this.logTable[a] ?? 0) * exp) % 255] ?? 0;
  }

  /**
   * Multiplicative inverse in GF(2^8)
   */
  static inverse(a: number): number {
    if (a === 0) {
      throw new Error('Zero has no inverse in GF(2^8)');
    }

    this.initializeTables();
    return this.expTable[255 - (this.logTable[a] ?? 0)] ?? 0;
  }
}

/**
 * Shamir's Secret Sharing implementation using finite field arithmetic
 */
export class ShamirSecretSharing {
  constructor(private threshold: number, private totalShares: number) {
    if (threshold <= 0) {
      throw new Error('Threshold must be positive');
    }
    if (threshold > totalShares) {
      throw new Error('Threshold cannot exceed total shares');
    }
    if (totalShares > 255) {
      throw new Error('Total shares cannot exceed 255');
    }
  }

  /**
   * Split secret into shares
   */
  splitSecret(secret: Uint8Array): Array<{ x: number; y: Uint8Array }> {
    // Build ONE random polynomial per secret byte, coefficients drawn from a
    // CSPRNG. The coefficients are fixed once and reused across every share:
    // all shares MUST lie on the same polynomial or reconstruction is
    // impossible. (Audit CITRATE_SDK_JS-2026-05-31-001 — CSPRNG coefficients —
    // and the coupled reconstruct-correctness fix: the prior code regenerated
    // fresh coefficients per share, putting each share on a different
    // polynomial, so reconstruction never recovered the secret.)
    const degree = Math.max(0, this.threshold - 1);
    const polynomials: number[][] = [];
    for (const secretByte of secret) {
      const coefficients: number[] = [secretByte];
      const randomCoeffs = secureRandomBytes(degree);
      for (let i = 0; i < randomCoeffs.length; i++) {
        coefficients.push(randomCoeffs[i]!);
      }
      polynomials.push(coefficients);
    }

    const shares: Array<{ x: number; y: Uint8Array }> = [];
    for (let x = 1; x <= this.totalShares; x++) {
      const shareBytes = new Uint8Array(polynomials.length);
      for (let b = 0; b < polynomials.length; b++) {
        shareBytes[b] = ShamirSecretSharing.evaluatePolynomial(polynomials[b]!, x);
      }
      shares.push({ x, y: shareBytes });
    }

    return shares;
  }

  /**
   * Reconstruct secret from shares
   */
  reconstructSecret(shares: Array<{ x: number; y: Uint8Array }>): Uint8Array {
    if (shares.length < this.threshold) {
      throw new Error(`Need at least ${this.threshold} shares, got ${shares.length}`);
    }

    // Use first threshold shares
    const activeShares = shares.slice(0, this.threshold);

    // Ensure all shares have same length
    const firstShare = activeShares[0];
    if (!firstShare) {
      throw new Error('No shares provided');
    }
    const shareLength = firstShare.y.length;
    if (!activeShares.every(share => share.y.length === shareLength)) {
      throw new Error('All shares must have the same length');
    }

    // Reconstruct each byte position
    const secretBytes: number[] = [];
    for (let bytePos = 0; bytePos < shareLength; bytePos++) {
      // Extract byte values for this position
      const points = activeShares.map(share => ({ x: share.x, y: share.y[bytePos] ?? 0 }));

      // Use Lagrange interpolation to find f(0)
      const reconstructedByte = this.lagrangeInterpolation(points, 0);
      secretBytes.push(reconstructedByte);
    }

    return new Uint8Array(secretBytes);
  }

  /**
   * Evaluate a GF(2^8) polynomial (coefficients given low-order first, i.e.
   * `[a0, a1, a2, ...]` for `a0 + a1·x + a2·x² + …`) at point `x` via Horner-
   * style accumulation. Pure: no randomness, so a polynomial evaluates
   * identically at every share point.
   */
  private static evaluatePolynomial(coefficients: number[], x: number): number {
    let result = 0;
    let xPower = 1;
    for (const coeff of coefficients) {
      result = GF256.add(result, GF256.multiply(coeff, xPower));
      xPower = GF256.multiply(xPower, x);
    }
    return result;
  }

  /**
   * Lagrange interpolation to find f(x) given points
   */
  private lagrangeInterpolation(points: Array<{ x: number; y: number }>, x: number): number {
    let result = 0;

    for (let i = 0; i < points.length; i++) {
      const point = points[i];
      if (!point) continue;
      const { x: xi, y: yi } = point;

      // Calculate Lagrange basis polynomial L_i(x)
      let numerator = 1;
      let denominator = 1;

      for (let j = 0; j < points.length; j++) {
        if (i !== j) {
          const otherPoint = points[j];
          if (!otherPoint) continue;
          const xj = otherPoint.x;
          // For x=0, numerator becomes (0 - x_j) = -x_j = x_j (in GF(2^8))
          numerator = GF256.multiply(numerator, xj);
          denominator = GF256.multiply(denominator, GF256.subtract(xi, xj));
        }
      }

      // L_i(x) = numerator / denominator
      if (denominator === 0) {
        throw new Error('Denominator is zero in Lagrange interpolation');
      }

      const lagrangeCoeff = GF256.divide(numerator, denominator);

      // Add y_i * L_i(x) to result
      result = GF256.add(result, GF256.multiply(yi, lagrangeCoeff));
    }

    return result;
  }

  /**
   * Verify that shares are consistent
   */
  verifyShares(shares: Array<{ x: number; y: Uint8Array }>): boolean {
    if (shares.length < this.threshold) {
      return false;
    }

    try {
      // Try to reconstruct with different combinations
      for (let i = 0; i <= shares.length - this.threshold; i++) {
        const testShares = shares.slice(i, i + this.threshold);
        this.reconstructSecret(testShares);
      }
      return true;
    } catch {
      return false;
    }
  }
}

/**
 * Convenience function to split secret bytes
 */
export function splitSecretBytes(
  secret: Uint8Array,
  threshold: number,
  totalShares: number
): Array<{ x: number; y: Uint8Array }> {
  const sss = new ShamirSecretSharing(threshold, totalShares);
  return sss.splitSecret(secret);
}

/**
 * Convenience function to reconstruct secret bytes
 */
export function reconstructSecretBytes(
  shares: Array<{ x: number; y: Uint8Array }>,
  threshold: number
): Uint8Array {
  // Infer total_shares from the shares provided
  const totalShares = Math.max(shares.length, threshold);
  const sss = new ShamirSecretSharing(threshold, totalShares);
  return sss.reconstructSecret(shares);
}