/**
 * Transport-security guard — the JS twin of SPY-B-009 (citrate-sdk-python).
 *
 * The asset being protected is signed transactions, private model inputs, and
 * bearer credentials (gateway `cgk_` keys, OIDC id/access/refresh tokens). For
 * that asset class the control FAILS CLOSED: a *remote* `http://`/`ws://`
 * endpoint throws `InsecureTransportError` unless the caller explicitly passes
 * `allowInsecureHttp: true`. Traffic to loopback/localhost passes silently — a
 * developer running a node or gateway locally is not shipping secrets over a
 * network — and the scheme is never rewritten implicitly (an automatic
 * http→https upgrade to a host that does not serve TLS would fail confusingly).
 */

export class InsecureTransportError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InsecureTransportError';
  }
}

// Hostnames that are always local to the calling machine — plaintext to these
// never leaves the box, so it is not a transport-confidentiality concern.
const LOCAL_HOSTNAMES = new Set(['localhost', 'ip6-localhost', 'ip6-loopback']);

function isLocalHost(host: string): boolean {
  if (!host) return false;
  const h = host.toLowerCase();
  if (LOCAL_HOSTNAMES.has(h)) return true;
  // Bracketed IPv6 loopback, e.g. [::1]
  const bare = h.startsWith('[') && h.endsWith(']') ? h.slice(1, -1) : h;
  if (bare === '::1') return true;
  // IPv4 loopback range 127.0.0.0/8
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(bare)) return true;
  return false;
}

/**
 * Throw unless `url` is safe to send secrets over.
 *
 * - `https://` / `wss://` pass silently.
 * - `http://` / `ws://` to a loopback/localhost host pass silently.
 * - `http://` / `ws://` to a *remote* host RAISE unless `allowInsecureHttp`.
 *
 * Returns the URL unchanged so it can be used inline.
 */
export function enforceTransportSecurity(
  url: string,
  opts: { allowInsecureHttp?: boolean } = {},
): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    // Not our job to validate URL shape here (validateRpcUrl does that); an
    // unparseable string is simply not a plaintext-remote transport.
    return url;
  }
  const scheme = parsed.protocol;
  if (scheme === 'https:' || scheme === 'wss:') return url;
  if (scheme === 'http:' || scheme === 'ws:') {
    if (isLocalHost(parsed.hostname)) return url;
    if (opts.allowInsecureHttp) return url;
    throw new InsecureTransportError(
      `refusing to use a remote plaintext endpoint (${scheme}//${parsed.host}). ` +
        'Signed transactions, private inputs, and bearer credentials would go out ' +
        'in cleartext. Use https/wss, or pass allowInsecureHttp:true to opt in ' +
        '(e.g. an internal lab network without TLS).',
    );
  }
  return url;
}
