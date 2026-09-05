// detectionEngine.mjs

function collectArtifactNames(report) {
  const names = [];
  for (const p of report.processes ?? []) names.push(p.name, p.path);
  for (const p of report.prefetch ?? []) names.push(p.fileName);
  for (const b of report.bam ?? []) names.push(b.path);
  for (const e of report.eventLog ?? []) names.push(e.summary, e.taskName);
  for (const s of report.shimCache ?? []) names.push(s.path);
  for (const a of report.amcache ?? []) names.push(a.path);
  for (const r of report.rpf ?? []) names.push(r.path);
  for (const m of report.modules ?? []) names.push(m.moduleName, m.path, m.ownerProcess);
  for (const r of report.memoryRegions ?? []) if (r.strings_found) names.push(r.strings_found);
  for (const k of report.runKeys ?? []) names.push(k.name, k.command, k.hive);
  for (const d of report.deletedFiles ?? []) names.push(d.originalPath ?? d.path);
  for (const n of report.networkConnections ?? []) names.push(n.remoteAddress, n.processName);
  for (const d of report.dnsCache ?? []) names.push(d.entryName);
  for (const f of report.suspiciousFiles ?? []) names.push(f);
  for (const b of report.browserHits ?? []) names.push(b);
  return names.filter(Boolean).map((n) => n.toLowerCase());
}

function collectArtifactHashes(report) {
  const hashes = [];
  for (const a of report.amcache ?? []) if (a.sha1) hashes.push(a.sha1);
  for (const m of report.modules ?? []) if (m.sha1) hashes.push(m.sha1);
  return hashes.filter(Boolean).map((h) => h.toLowerCase());
}

function compileRegex(pattern) {
  try { return new RegExp(pattern, "i"); } catch { return null; }
}

function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Levenshtein distance for fuzzy matching
function levenshtein(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  const matrix = Array.from(new Array(a.length + 1), () => new Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) matrix[i][0] = i;
  for (let j = 0; j <= b.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(matrix[i - 1][j] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j - 1] + cost);
    }
  }
  return matrix[a.length][b.length];
}

function getBasename(path) {
  return path.split(/[\\/]/).pop();
}

export function runDetections(report, rules) {
  const detections = [];
  const names = collectArtifactNames(report);
  const hashes = collectArtifactHashes(report);
  const warningCodes = new Set((report.warnings ?? []).map((w) => w.code));

  for (const rule of rules) {
    if (!rule.enabled) continue;

    if (rule.type === "filename") {
      const needle = rule.match.toLowerCase();
      // Improved filename logic to reduce false positives
      // Check if it matches the exact basename, or is a distinct word in the path
      const regex = new RegExp(`(^|[\\\\/\\s_-])${escapeRegExp(needle)}([\\\\/\\s_\\.-]|$)`, "i");
      
      const hit = names.find((n) => {
        const base = getBasename(n);
        if (base === needle || base === needle + '.exe' || base === needle + '.dll') return true;
        return regex.test(n);
      });
      
      if (hit) {
        detections.push({ ruleId: rule.id, name: rule.name, severity: rule.severity, evidence: hit, note: rule.note });
      }
    }

    if (rule.type === "regex") {
      const re = compileRegex(rule.match);
      const hit = re ? names.find((n) => re.test(n)) : null;
      if (hit) {
        detections.push({ ruleId: rule.id, name: rule.name, severity: rule.severity, evidence: hit, note: rule.note });
      }
    }

    if (rule.type === "fuzzy") {
      const needle = rule.match.toLowerCase();
      const threshold = rule.match.length > 5 ? 2 : 1; // 1 or 2 typos allowed
      const hit = names.find((n) => {
         const base = getBasename(n).replace(/\.(exe|dll|sys|bin)$/, '');
         return Math.abs(base.length - needle.length) <= threshold && levenshtein(base, needle) <= threshold;
      });
      if (hit) {
        detections.push({ ruleId: rule.id, name: rule.name, severity: rule.severity, evidence: hit, note: rule.note });
      }
    }

    if (rule.type === "hash") {
      const needle = rule.match.toLowerCase().trim();
      if (hashes.includes(needle)) {
        detections.push({ ruleId: rule.id, name: rule.name, severity: rule.severity, evidence: needle, note: rule.note });
      }
    }

    if (rule.type === "warning" && warningCodes.has(rule.match)) {
      detections.push({ ruleId: rule.id, name: rule.name, severity: rule.severity, evidence: rule.match, note: rule.note });
    }
  }

  return detections;
}

export function summarize(detections) {
  if (detections.length === 0) return "clean";
  if (detections.some((d) => d.severity === "high")) return "cheating";
  return "suspicious";
}
