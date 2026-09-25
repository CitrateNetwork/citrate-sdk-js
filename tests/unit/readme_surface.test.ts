/**
 * The README is an interface contract: humans and AI agents copy its imports
 * verbatim. The previous README documented `import { GatewayClient } from
 * '@citratelabs/sdk'`, which does not exist (it lives under the `gateway`
 * namespace), so the documented code failed at runtime.
 *
 * These tests read README.md and fail if any symbol it uses is not actually
 * exported where it says, or if the version constants drift from package.json.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import * as sdk from '../../src';
import { SDK_VERSION } from '../../src/utils/constants';

const exported = sdk as unknown as Record<string, unknown>;

const root = join(__dirname, '..', '..');
const readme = readFileSync(join(root, 'README.md'), 'utf8');
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const hooksSource = readFileSync(join(root, 'src', 'react', 'hooks.ts'), 'utf8');

const NAMESPACES = ['gateway', 'identity', 'aa', 'entitlements', 'memory'] as const;

function importedNames(from: string): string[] {
  const re = new RegExp(`import\\s*\\{([^}]+)\\}\\s*from\\s*'${from.replace(/[/.]/g, '\\$&')}'`, 'g');
  const names: string[] = [];
  for (const m of readme.matchAll(re)) {
    for (const part of (m[1] as string).split(',')) {
      const name = part.trim().split(/\s+as\s+/)[0]?.trim();
      if (name) names.push(name);
    }
  }
  return names;
}

describe('README documents only symbols the package exports', () => {
  test('top-level imports from @citratelabs/sdk exist', () => {
    const names = importedNames('@citratelabs/sdk');
    expect(names.length).toBeGreaterThan(0);
    const missing = names.filter((n) => exported[n] === undefined);
    expect(missing).toEqual([]);
  });

  test('namespace members (gateway.X, identity.X, aa.X, entitlements.X, memory.X) exist', () => {
    const missing: string[] = [];
    let seen = 0;
    for (const ns of NAMESPACES) {
      const mod = exported[ns] as Record<string, unknown> | undefined;
      expect(mod).toBeDefined();
      for (const m of readme.matchAll(new RegExp(`(?<![\\w./-])${ns}\\.([A-Za-z_][A-Za-z0-9_]*)`, 'g'))) {
        seen++;
        const member = m[1] as string;
        if (mod?.[member] === undefined) missing.push(`${ns}.${member}`);
      }
    }
    expect(seen).toBeGreaterThan(0);
    expect(missing).toEqual([]);
  });

  test('React hooks imported from @citratelabs/sdk/react/hooks exist', () => {
    const names = importedNames('@citratelabs/sdk/react/hooks');
    expect(names.length).toBeGreaterThan(0);
    const missing = names.filter((n) => !new RegExp(`export function ${n}\\b`).test(hooksSource));
    expect(missing).toEqual([]);
  });
});

describe('version constants match package.json', () => {
  test('VERSION === package.json version', () => {
    expect(sdk.VERSION).toBe(pkg.version);
  });
  test('SDK_VERSION === package.json version', () => {
    expect(SDK_VERSION).toBe(pkg.version);
  });
});
