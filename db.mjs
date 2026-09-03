// db.mjs
//
// Minimal file-backed datastore. This is intentionally simple (a JSON file
// guarded by an in-process write queue) so the project runs with zero
// external services. Swap this module out for Postgres/SQLite/etc. once you
// need multi-instance deployment or serious concurrency.

import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(__dirname, "data");
const SCANS_FILE = path.join(DATA_DIR, "scans.json");
const RULES_FILE = path.join(DATA_DIR, "rules.json");
const AUDIT_FILE = path.join(DATA_DIR, "audit.json");
const SESSIONS_FILE = path.join(DATA_DIR, "sessions.json");
const SETTINGS_FILE = path.join(DATA_DIR, "settings.json");
const KEYS_FILE = path.join(DATA_DIR, "keys.json");
const AUTH_SESSIONS_FILE = path.join(DATA_DIR, "auth_sessions.json");

async function ensureFile(file, fallback) {
  try {
    await fs.access(file);
  } catch {
    await fs.writeFile(file, JSON.stringify(fallback, null, 2));
  }
}

async function init() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  await ensureFile(SCANS_FILE, {});
  const defaultRules = [
    { id: crypto.randomUUID(), type: 'filename', match: 'cheat', severity: 'high', name: 'Genel Hile Kelimesi', note: 'Dosya adında cheat geçiyor', enabled: true, system: true, createdAt: new Date().toISOString() },
    { id: crypto.randomUUID(), type: 'filename', match: 'hack', severity: 'high', name: 'Genel Hile Kelimesi', note: 'Dosya adında hack geçiyor', enabled: true, system: true, createdAt: new Date().toISOString() },
    { id: crypto.randomUUID(), type: 'filename', match: 'injector', severity: 'high', name: 'Injector', note: 'Injector programı tespit edildi', enabled: true, system: true, createdAt: new Date().toISOString() },
    { id: crypto.randomUUID(), type: 'filename', match: 'skript', severity: 'medium', name: 'Script/Makro', note: 'Script veya makro programı', enabled: true, system: true, createdAt: new Date().toISOString() },
    { id: crypto.randomUUID(), type: 'filename', match: 'bypass', severity: 'high', name: 'Anti-Cheat Bypass', note: 'Bypass aracı tespit edildi', enabled: true, system: true, createdAt: new Date().toISOString() },
    { id: crypto.randomUUID(), type: 'filename', match: 'dumper', severity: 'high', name: 'Dumper', note: 'Oyun hafızasını okuyan dumper aracı', enabled: true, system: true, createdAt: new Date().toISOString() },
    { id: crypto.randomUUID(), type: 'filename', match: 'aimbot', severity: 'high', name: 'Aimbot', note: 'Aimbot yazılımı', enabled: true, system: true, createdAt: new Date().toISOString() },
    { id: crypto.randomUUID(), type: 'filename', match: 'wallhack', severity: 'high', name: 'Wallhack', note: 'Wallhack yazılımı', enabled: true, system: true, createdAt: new Date().toISOString() },
    { id: crypto.randomUUID(), type: 'filename', match: 'esp', severity: 'medium', name: 'ESP', note: 'ESP/Wallhack yazılımı', enabled: true, system: true, createdAt: new Date().toISOString() },
    { id: crypto.randomUUID(), type: 'filename', match: 'mod menu', severity: 'high', name: 'Mod Menü', note: 'Oyun içi mod menü tespit edildi', enabled: true, system: true, createdAt: new Date().toISOString() },
    { id: crypto.randomUUID(), type: 'filename', match: 'eulen', severity: 'high', name: 'Eulen (FiveM)', note: 'Popüler FiveM Hilesi: Eulen', enabled: true, system: true, createdAt: new Date().toISOString() },
    { id: crypto.randomUUID(), type: 'filename', match: 'hx', severity: 'high', name: 'HX (FiveM)', note: 'Popüler FiveM Hilesi: HX', enabled: true, system: true, createdAt: new Date().toISOString() },
    { id: crypto.randomUUID(), type: 'filename', match: 'redengine', severity: 'high', name: 'RedEngine (FiveM)', note: 'Popüler FiveM Hilesi: RedEngine', enabled: true, system: true, createdAt: new Date().toISOString() },
    { id: crypto.randomUUID(), type: 'filename', match: 'lunia', severity: 'high', name: 'Lunia (FiveM)', note: 'Popüler FiveM Hilesi: Lunia', enabled: true, system: true, createdAt: new Date().toISOString() },
    { id: crypto.randomUUID(), type: 'filename', match: 'crown', severity: 'high', name: 'Crown (FiveM)', note: 'Popüler FiveM Hilesi: Crown', enabled: true, system: true, createdAt: new Date().toISOString() },
    { id: crypto.randomUUID(), type: 'filename', match: 'nexus', severity: 'high', name: 'Nexus (FiveM)', note: 'Popüler FiveM Hilesi: Nexus', enabled: true, system: true, createdAt: new Date().toISOString() },
    { id: crypto.randomUUID(), type: 'filename', match: 'tz', severity: 'high', name: 'TZ Project (FiveM)', note: 'Popüler FiveM Hilesi: TZ Project', enabled: true, system: true, createdAt: new Date().toISOString() },
    { id: crypto.randomUUID(), type: 'filename', match: '.rpf', severity: 'medium', name: 'Modifiye RPF', note: 'Modlanmış RPF dosyası tespiti (.rpf)', enabled: true, system: true, createdAt: new Date().toISOString() },
    { id: crypto.randomUUID(), type: 'regex', match: '\\.rpf$', severity: 'medium', name: 'RPF Dosyası Uzantısı', note: 'RPF (RAGE Package Format) dosyası uzantısı taraması', enabled: true, system: true, createdAt: new Date().toISOString() }
  ];
  await ensureFile(RULES_FILE, defaultRules);   // Render'da data/ klasörü olmadığı için burada oluştur ve kuralları ekle
  await ensureFile(AUDIT_FILE, []);
  await ensureFile(SESSIONS_FILE, {});
  await ensureFile(SETTINGS_FILE, {});
  await ensureFile(KEYS_FILE, {});
  await ensureFile(AUTH_SESSIONS_FILE, {});
}

// --- tiny write queue so concurrent requests don't clobber the file ---
let queue = Promise.resolve();
function serialize(fn) {
  const run = queue.then(fn, fn);
  queue = run.catch(() => {});
  return run;
}

async function readJson(file) {
  const raw = await fs.readFile(file, "utf-8");
  return JSON.parse(raw);
}

async function writeJson(file, data) {
  await fs.writeFile(file, JSON.stringify(data, null, 2));
}

export async function getRules() {
  return readJson(RULES_FILE);
}

export async function addRule(rule) {
  return serialize(async () => {
    const rules = await readJson(RULES_FILE);
    rules.push(rule);
    await writeJson(RULES_FILE, rules);
    return rule;
  });
}

// Bulk variant for file-based rule import
export async function addRules(newRules) {
  return serialize(async () => {
    const rules = await readJson(RULES_FILE);
    rules.push(...newRules);
    await writeJson(RULES_FILE, rules);
    return newRules;
  });
}

export async function updateRule(id, patch) {
  return serialize(async () => {
    const rules = await readJson(RULES_FILE);
    const idx = rules.findIndex((r) => r.id === id);
    if (idx === -1) return null;
    rules[idx] = { ...rules[idx], ...patch };
    await writeJson(RULES_FILE, rules);
    return rules[idx];
  });
}

export async function deleteRule(id) {
  return serialize(async () => {
    const rules = await readJson(RULES_FILE);
    const idx = rules.findIndex((r) => r.id === id);
    if (idx === -1) return false;
    rules.splice(idx, 1);
    await writeJson(RULES_FILE, rules);
    return true;
  });
}

export async function saveScan(pin, report) {
  return serialize(async () => {
    const scans = await readJson(SCANS_FILE);
    scans[pin] = report;
    await writeJson(SCANS_FILE, scans);
    return report;
  });
}

export async function getScan(pin) {
  const scans = await readJson(SCANS_FILE);
  return scans[pin] ?? null;
}

export async function listScans() {
  const scans = await readJson(SCANS_FILE);
  return Object.values(scans).sort(
    (a, b) => new Date(b.createdAt) - new Date(a.createdAt)
  );
}

export async function appendAudit(entry) {
  return serialize(async () => {
    const audit = await readJson(AUDIT_FILE);
    audit.push({ ...entry, at: new Date().toISOString() });
    await writeJson(AUDIT_FILE, audit);
  });
}

export async function getAudit() {
  return readJson(AUDIT_FILE);
}

// ---- scan sessions (staff-generated codes the client must be given) ----

export async function createSession(session) {
  return serialize(async () => {
    const sessions = await readJson(SESSIONS_FILE);
    sessions[session.code] = session;
    await writeJson(SESSIONS_FILE, sessions);
    return session;
  });
}

export async function getSession(code) {
  const sessions = await readJson(SESSIONS_FILE);
  return sessions[code] ?? null;
}

export async function markSessionUsed(code) {
  return serialize(async () => {
    const sessions = await readJson(SESSIONS_FILE);
    if (!sessions[code]) return null;
    sessions[code].usedAt = new Date().toISOString();
    await writeJson(SESSIONS_FILE, sessions);
    return sessions[code];
  });
}

export async function updateSession(code, patch) {
  return serialize(async () => {
    const sessions = await readJson(SESSIONS_FILE);
    if (!sessions[code]) return null;
    sessions[code] = { ...sessions[code], ...patch };
    await writeJson(SESSIONS_FILE, sessions);
    return sessions[code];
  });
}

export async function deleteSession(code) {
  return serialize(async () => {
    const sessions = await readJson(SESSIONS_FILE);
    if (!sessions[code]) return false;
    delete sessions[code];
    await writeJson(SESSIONS_FILE, sessions);
    return true;
  });
}

export async function listSessions() {
  const sessions = await readJson(SESSIONS_FILE);
  return Object.values(sessions).sort(
    (a, b) => new Date(b.createdAt) - new Date(a.createdAt)
  );
}

// ---- dashboard-configurable appearance settings ----

const getUserSettingsFile = (discordId) => path.join(DATA_DIR, `settings_${discordId}.json`);

export async function getSettings(discordId) {
  try {
    if (!discordId) return await readJson(SETTINGS_FILE);
    return await readJson(getUserSettingsFile(discordId));
  } catch (err) {
    if (err.code === 'ENOENT') return {};
    throw err;
  }
}

export async function updateSettings(discordId, patch) {
  return serialize(async () => {
    const file = discordId ? getUserSettingsFile(discordId) : SETTINGS_FILE;
    let settings = {};
    try {
      settings = await readJson(file);
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
    }
    const next = { ...settings, ...patch };
    await writeJson(file, next);
    return next;
  });
}

// ---- License Keys ----

export async function createLicenseKey(key) {
  return serialize(async () => {
    const keys = await readJson(KEYS_FILE);
    keys[key.code] = key;
    await writeJson(KEYS_FILE, keys);
    return key;
  });
}

export async function getLicenseKey(code) {
  const keys = await readJson(KEYS_FILE);
  return keys[code] ?? null;
}

export async function listLicenseKeys() {
  const keys = await readJson(KEYS_FILE);
  return Object.values(keys).sort(
    (a, b) => new Date(b.createdAt) - new Date(a.createdAt)
  );
}

export async function updateLicenseKey(code, patch) {
  return serialize(async () => {
    const keys = await readJson(KEYS_FILE);
    if (!keys[code]) return null;
    keys[code] = { ...keys[code], ...patch };
    await writeJson(KEYS_FILE, keys);
    return keys[code];
  });
}

export async function deleteLicenseKey(code) {
  return serialize(async () => {
    const keys = await readJson(KEYS_FILE);
    if (!keys[code]) return false;
    delete keys[code];
    await writeJson(KEYS_FILE, keys);
    return true;
  });
}

// ---- Auth Sessions ----

export async function createAuthSession(session) {
  return serialize(async () => {
    const sessions = await readJson(AUTH_SESSIONS_FILE);
    sessions[session.token] = session;
    await writeJson(AUTH_SESSIONS_FILE, sessions);
    return session;
  });
}

export async function getAuthSession(token) {
  const sessions = await readJson(AUTH_SESSIONS_FILE);
  return sessions[token] ?? null;
}

export async function deleteAuthSession(token) {
  return serialize(async () => {
    const sessions = await readJson(AUTH_SESSIONS_FILE);
    if (!sessions[token]) return false;
    delete sessions[token];
    await writeJson(AUTH_SESSIONS_FILE, sessions);
    return true;
  });
}

await init();
