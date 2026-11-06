'use strict';
const vscode = require('vscode');
const { execFile } = require('child_process');
const { taintDiagnostics, breachMessages } = require('./diagnostics');

let collection;

function xray(args, cwd) {
  const command = vscode.workspace.getConfiguration('xray').get('path') || 'xray';
  return new Promise((resolve, reject) => {
    // execFile, not a shell: arguments are passed as they are.
    execFile(command, args, { cwd, maxBuffer: 64 * 1024 * 1024, timeout: 120000 }, (error, stdout, stderr) => {
      if (error && error.code === 'ENOENT') {
        reject(new Error(`xray not found (${command}); install xray-trust or set xray.path`));
        return;
      }
      // xray exits 1 to signal findings; the JSON on stdout is still the answer.
      if (!stdout && error) reject(new Error(stderr || error.message));
      else resolve(stdout);
    });
  });
}

async function taint(document) {
  if (!['shellscript', 'python'].includes(document.languageId) || document.uri.scheme !== 'file') return;
  const file = document.uri.fsPath;
  try {
    const report = JSON.parse(await xray(['taint', file, '--json']));
    const showLow = vscode.workspace.getConfiguration('xray').get('showLow');
    const items = taintDiagnostics(report, report.root || file, showLow);
    collection.set(document.uri, items.map((item) => {
      const line = document.lineAt(Math.min(item.line, document.lineCount - 1));
      const diagnostic = new vscode.Diagnostic(line.range, item.message, vscode.DiagnosticSeverity[item.severity]);
      diagnostic.source = item.source;
      diagnostic.code = item.code;
      return diagnostic;
    }));
  } catch (error) {
    vscode.window.showWarningMessage(`XRAY: ${error.message}`);
  }
}

async function inspect() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) return;
  try {
    const html = await xray(['inspect', editor.document.uri.fsPath, '--html']);
    const panel = vscode.window.createWebviewPanel('xrayGraph', 'XRAY evidence graph', vscode.ViewColumn.Beside,
      { enableScripts: true, localResourceRoots: [] });
    panel.webview.html = html;
  } catch (error) {
    vscode.window.showErrorMessage(`XRAY: ${error.message}`);
  }
}

async function contractCheck() {
  const picked = await vscode.window.showOpenDialog({ filters: { 'XRAY contract': ['contract'] }, canSelectMany: false });
  if (!picked || !picked.length) return;
  try {
    const result = JSON.parse(await xray(['contract', 'check', picked[0].fsPath, '--json']));
    const breaches = breachMessages(result);
    if (!breaches.length) vscode.window.showInformationMessage(`XRAY: ${result.program} stays within its contract.`);
    else vscode.window.showWarningMessage(`XRAY: ${breaches.length} breach(es) — ${breaches.slice(0, 3).join(' | ')}`);
  } catch (error) {
    vscode.window.showErrorMessage(`XRAY: ${error.message}`);
  }
}

function activate(context) {
  collection = vscode.languages.createDiagnosticCollection('xray');
  context.subscriptions.push(
    collection,
    vscode.commands.registerCommand('xray.taint', () => vscode.window.activeTextEditor && taint(vscode.window.activeTextEditor.document)),
    vscode.commands.registerCommand('xray.inspect', inspect),
    vscode.commands.registerCommand('xray.contractCheck', contractCheck),
    vscode.workspace.onDidSaveTextDocument((document) => {
      if (vscode.workspace.getConfiguration('xray').get('taintOnSave')) taint(document);
    }),
  );
}

function deactivate() {}

module.exports = { activate, deactivate };
