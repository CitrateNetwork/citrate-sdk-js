'use strict';

const { existsSync } = require('node:fs');
const path = require('node:path');

function resolveNpmInvocation({
  platform = process.platform,
  nodeExecutable = process.execPath,
  npmExecPath = process.env.npm_execpath,
  fileExists = existsSync,
} = {}) {
  if (npmExecPath && fileExists(npmExecPath)) {
    return { command: nodeExecutable, args: [npmExecPath] };
  }

  if (platform === 'win32') {
    const npmCli = path.win32.join(
      path.win32.dirname(nodeExecutable),
      'node_modules',
      'npm',
      'bin',
      'npm-cli.js',
    );
    if (!fileExists(npmCli)) {
      throw new Error(
        `unable to locate npm-cli.js beside the Node executable: ${nodeExecutable}`,
      );
    }
    return { command: nodeExecutable, args: [npmCli] };
  }

  return { command: 'npm', args: [] };
}

module.exports = { resolveNpmInvocation };
