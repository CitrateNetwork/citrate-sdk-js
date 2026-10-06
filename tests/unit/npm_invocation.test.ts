interface NpmInvocation {
  command: string;
  args: string[];
}

interface ResolveOptions {
  platform: NodeJS.Platform;
  nodeExecutable: string;
  npmExecPath?: string;
  fileExists: (candidate: string) => boolean;
}

interface NpmInvocationModule {
  resolveNpmInvocation(options: ResolveOptions): NpmInvocation;
}

const { resolveNpmInvocation } = require('../../scripts/npm-invocation.cjs') as NpmInvocationModule;

describe('shell-free npm invocation', () => {
  test('runs npm_execpath through the current Node executable when available', () => {
    const npmCli = 'C:\\npm-cache\\npm-cli.js';
    expect(
      resolveNpmInvocation({
        platform: 'win32',
        nodeExecutable: 'C:\\Program Files\\nodejs\\node.exe',
        npmExecPath: npmCli,
        fileExists: (candidate) => candidate === npmCli,
      }),
    ).toEqual({
      command: 'C:\\Program Files\\nodejs\\node.exe',
      args: [npmCli],
    });
  });

  test('finds the npm CLI beside a standard Windows Node installation', () => {
    const npmCli = 'C:\\Program Files\\nodejs\\node_modules\\npm\\bin\\npm-cli.js';
    expect(
      resolveNpmInvocation({
        platform: 'win32',
        nodeExecutable: 'C:\\Program Files\\nodejs\\node.exe',
        fileExists: (candidate) => candidate === npmCli,
      }),
    ).toEqual({
      command: 'C:\\Program Files\\nodejs\\node.exe',
      args: [npmCli],
    });
  });

  test('uses the npm executable directly on POSIX without a shell', () => {
    expect(
      resolveNpmInvocation({
        platform: 'linux',
        nodeExecutable: '/usr/bin/node',
        fileExists: () => false,
      }),
    ).toEqual({ command: 'npm', args: [] });
  });

  test('fails explicitly when a Windows npm CLI cannot be located', () => {
    expect(() =>
      resolveNpmInvocation({
        platform: 'win32',
        nodeExecutable: 'C:\\portable-node\\node.exe',
        fileExists: () => false,
      }),
    ).toThrow('unable to locate npm-cli.js');
  });
});
