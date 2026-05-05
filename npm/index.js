/**
 * @the-17/agentsecrets
 * Zero-knowledge secrets infrastructure built for AI agents.
 */

const { spawn } = require('child_process');
const path = require('path');
const { getBinaryPath } = require('./bin/agentsecrets');

/**
 * Executes the agentsecrets CLI binary with the given arguments.
 * @param {string[]} args 
 * @returns {Promise<number>}
 */
async function run(args = []) {
  const binaryPath = await getBinaryPath();
  return new Promise((resolve, reject) => {
    const proc = spawn(binaryPath, args, { stdio: 'inherit' });
    proc.on('close', (code) => resolve(code));
    proc.on('error', (err) => reject(err));
  });
}

module.exports = {
  run,
  getBinaryPath
};
