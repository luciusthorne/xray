// Pure helpers, kept free of the vscode module so they can be tested with plain Node.
'use strict';

const SEVERITY = { high: 'Error', medium: 'Warning', low: 'Information', info: 'Hint' };

/** Turn `xray taint --json` output into diagnostics for one file. */
function taintDiagnostics(report, file, showLow) {
  const out = [];
  for (const item of report.findings || []) {
    if (item.file !== file || !item.line) continue;
    if (!showLow && (item.severity === 'low' || item.severity === 'info')) continue;
    const chain = (item.chain || []).map((step) => `via ${step.file}:${step.line} ${step.detail}`).join('; ');
    out.push({
      line: item.line - 1,
      severity: SEVERITY[item.severity] || 'Warning',
      message: `${item.detail} (from ${item.sources.join(', ')}; ${item.basis})${chain ? ' — ' + chain : ''}`,
      source: 'xray taint',
      code: item.sink,
    });
  }
  // Findings in other files reached from this one are reported on the line that passes the input on.
  for (const item of report.findings || []) {
    if (item.file === file || !(item.chain || []).length) continue;
    const first = item.chain[0];
    if (first.file !== file || !first.line) continue;
    if (!showLow && (item.severity === 'low' || item.severity === 'info')) continue;
    out.push({
      line: first.line - 1,
      severity: SEVERITY[item.severity] || 'Warning',
      message: `input reaches ${item.sink} in ${item.file}:${item.line || '?'}: ${item.detail}`,
      source: 'xray taint',
      code: item.sink,
    });
  }
  return out;
}

/** Turn `xray contract check --json` output into one message per breach. */
function breachMessages(result) {
  return (result.breaches || []).map((item) => `${item.section} ${item.value}: ${item.detail}`);
}

module.exports = { taintDiagnostics, breachMessages, SEVERITY };
