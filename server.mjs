// server.mjs
// Mist AC backend with Discord OAuth + License Key system

import express from "express";
import cors from "cors";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  saveScan, getScan, listScans, getRules, addRule, addRules, updateRule, deleteRule,
  appendAudit, getAudit, createSession, getSession, markSessionUsed, updateSession,
  deleteSession, listSessions, getSettings, updateSettings,
  createLicenseKey, getLicenseKey, listLicenseKeys, updateLicenseKey, deleteLicenseKey,
  createAuthSession, getAuthSession, deleteAuthSession,
} from "./db.mjs";
import { runDetections, summarize } from "./detectionEngine.mjs";
import { parseRuleImport } from "./ruleImport.mjs";
import dotenv from "dotenv";

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PORT = process.env.PORT || 8787;
const CLIENT_SECRET = process.env.CLIENT_SECRET || "changeme-client-secret";
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || "";
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || "";
const OWNER_DISCORD_ID = process.env.OWNER_DISCORD_ID || "1097761624200314951";
const BACKEND_URL = process.env.BACKEND_URL || "http://localhost:8787";
// Eğer .env içinde DASHBOARD_URL yoksa, artık backend'in kendisi dashboard'u sunacak:
const DASHBOARD_URL = process.env.DASHBOARD_URL || "http://localhost:8787/index.html";

const app = express();
app.use(cors({
  origin: (origin, cb) => cb(null, true),
  credentials: true,
}));
app.use(express.json({ limit: "2mb" }));

// Dashboard klasörünü backend üzerinden yayınla
app.use(express.static(path.join(__dirname, '../dashboard')));

// Rate limiting (simple memory-based)
function makeRateLimiter(windowMs, maxReq) {
  const hits = new Map();
  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    let record = hits.get(ip);
    if (!record || now > record.resetAt) {
      record = { count: 0, resetAt: now + windowMs };
    }
    record.count++;
    hits.set(ip, record);
    if (record.count > maxReq) {
      return res.status(429).json({ error: "too many requests" });
    }
    next();
  };
}
const scanLimiter = makeRateLimiter(60 * 1000, 10);
const apiLimiter = makeRateLimiter(60 * 1000, 100);

const SESSION_TTL_MS = 15 * 60 * 1000;

function generatePin() {
  return String(crypto.randomInt(100000, 999999));
}

function isSessionUsable(session) {
  if (!session) return false;
  if (session.usedAt) return false;
  if (new Date(session.expiresAt).getTime() < Date.now()) return false;
  return true;
}

function generateKeyCode() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let part1 = '', part2 = '';
  for (let i = 0; i < 4; i++) part1 += chars[crypto.randomInt(0, chars.length)];
  for (let i = 0; i < 4; i++) part2 += chars[crypto.randomInt(0, chars.length)];
  return `${part1}-${part2}`;
}

function calcExpiry(durationType) {
  const now = Date.now();
  if (durationType === '1d') return new Date(now + 24 * 60 * 60 * 1000).toISOString();
  if (durationType === '1w') return new Date(now + 7 * 24 * 60 * 60 * 1000).toISOString();
  if (durationType === '1y') return new Date(now + 365 * 24 * 60 * 60 * 1000).toISOString();
  return null;
}

async function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'not authenticated' });
  const session = await getAuthSession(token);
  if (!session) return res.status(401).json({ error: 'invalid or expired session' });
  if (new Date(session.expiresAt) < new Date()) {
    await deleteAuthSession(token);
    return res.status(401).json({ error: 'session expired' });
  }
  req.user = session;
  next();
}

function requireOwner(req, res, next) {
  if (req.user?.discordId !== OWNER_DISCORD_ID) {
    return res.status(403).json({ error: 'forbidden: owner only' });
  }
  next();
}

async function requireActiveKey(req, res, next) {
  if (req.user?.discordId === OWNER_DISCORD_ID) return next();
  const keys = await listLicenseKeys();
  const now = new Date();
  const activeKey = keys.find(k =>
    k.activatedBy === req.user.discordId &&
    k.status === 'active' &&
    new Date(k.expiresAt) > now
  );
  if (!activeKey) {
    return res.status(403).json({ error: 'no active license key' });
  }
  req.licenseKey = activeKey;
  next();
}

function requireClientSecret(req, res, next) {
  const secret = req.header('x-client-secret');
  if (secret !== CLIENT_SECRET) return res.status(401).json({ error: 'unauthorized' });
  next();
}

// ---- Discord OAuth -------------------------------------------------------

app.get('/auth/discord', (req, res) => {
  if (!DISCORD_CLIENT_ID) {
    return res.status(500).json({ error: 'Discord OAuth not configured' });
  }
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: `${BACKEND_URL}/auth/callback`,
    response_type: 'code',
    scope: 'identify',
  });
  res.redirect(`https://discord.com/oauth2/authorize?${params}`);
});

app.get('/auth/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.redirect(`${DASHBOARD_URL}?auth_error=no_code`);
  try {
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: `${BACKEND_URL}/auth/callback`,
      }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) {
      return res.redirect(`${DASHBOARD_URL}?auth_error=token_failed`);
    }
    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const user = await userRes.json();
    if (!user.id) return res.redirect(`${DASHBOARD_URL}?auth_error=user_failed`);
    const sessionToken = crypto.randomBytes(32).toString('hex');
    await createAuthSession({
      token: sessionToken,
      discordId: user.id,
      discordUsername: user.username,
      discordGlobalName: user.global_name || user.username,
      discordAvatar: user.avatar,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
    });
    await appendAudit({ action: 'discord_login', discordId: user.id, username: user.username });
    res.redirect(`${DASHBOARD_URL}?auth_token=${sessionToken}`);
  } catch (err) {
    console.error('OAuth callback error:', err);
    res.redirect(`${DASHBOARD_URL}?auth_error=server_error`);
  }
});

app.get('/auth/me', requireAuth, (req, res) => {
  res.json({
    discordId: req.user.discordId,
    discordUsername: req.user.discordUsername,
    discordGlobalName: req.user.discordGlobalName,
    discordAvatar: req.user.discordAvatar,
    isOwner: req.user.discordId === OWNER_DISCORD_ID,
  });
});

app.post('/auth/logout', requireAuth, async (req, res) => {
  const token = req.headers['authorization']?.slice(7);
  await deleteAuthSession(token);
  res.json({ ok: true });
});

// ---- Owner: License Key Management -------------------------------------

app.get('/api/owner/keys', requireAuth, requireOwner, async (_req, res) => {
  const keys = await listLicenseKeys();
  res.json(keys);
});

app.post('/api/owner/keys', requireAuth, requireOwner, async (req, res) => {
  const { label, targetDiscordId, description, durationType } = req.body ?? {};
  if (!label || !targetDiscordId || !durationType) {
    return res.status(400).json({ error: 'missing required fields' });
  }
  if (!['1d', '1w', '1y'].includes(durationType)) {
    return res.status(400).json({ error: 'durationType must be 1d, 1w, or 1y' });
  }
  let code = generateKeyCode();
  while (await getLicenseKey(code)) code = generateKeyCode();
  const key = {
    code,
    label: String(label).slice(0, 100),
    targetDiscordId: String(targetDiscordId),
    description: description ? String(description).slice(0, 500) : '',
    durationType,
    status: 'unused',
    createdAt: new Date().toISOString(),
    activatedAt: null,
    activatedBy: null,
    activatedByUsername: null,
    expiresAt: null,
  };
  await createLicenseKey(key);
  await appendAudit({ action: 'license_key_created', code, label, targetDiscordId, durationType, by: req.user.discordId });
  res.status(201).json(key);
});

app.delete('/api/owner/keys/:code', requireAuth, requireOwner, async (req, res) => {
  const ok = await deleteLicenseKey(req.params.code);
  if (!ok) return res.status(404).json({ error: 'key not found' });
  await appendAudit({ action: 'license_key_deleted', code: req.params.code, by: req.user.discordId });
  res.status(204).end();
});

app.post('/api/owner/keys/:code/revoke', requireAuth, requireOwner, async (req, res) => {
  const key = await getLicenseKey(req.params.code);
  if (!key) return res.status(404).json({ error: 'key not found' });
  const updated = await updateLicenseKey(req.params.code, { status: 'revoked' });
  await appendAudit({ action: 'license_key_revoked', code: req.params.code, by: req.user.discordId });
  res.json(updated);
});

// ---- User: Key Activation -----------------------------------------------

app.post('/api/keys/activate', requireAuth, async (req, res) => {
  const { code } = req.body ?? {};
  if (!code) return res.status(400).json({ error: 'missing key code' });
  const key = await getLicenseKey(code.toUpperCase());
  if (!key) return res.status(404).json({ error: 'key not found' });
  if (key.status === 'revoked') return res.status(403).json({ error: 'key has been revoked' });
  if (key.status === 'active') {
    if (new Date(key.expiresAt) < new Date()) {
      await updateLicenseKey(code, { status: 'expired' });
      return res.status(403).json({ error: 'key has expired' });
    }
    if (key.activatedBy === req.user.discordId) {
      return res.json({ ok: true, key, alreadyActive: true });
    }
    return res.status(409).json({ error: 'key already in use by another account' });
  }
  if (key.status === 'expired') return res.status(403).json({ error: 'key has expired' });
  if (key.status !== 'unused') return res.status(400).json({ error: 'key is not available' });
  if (key.targetDiscordId !== req.user.discordId) {
    return res.status(403).json({ error: 'this key is not assigned to your Discord account' });
  }
  const activatedAt = new Date().toISOString();
  const expiresAt = calcExpiry(key.durationType);
  const updated = await updateLicenseKey(code.toUpperCase(), {
    status: 'active',
    activatedAt,
    activatedBy: req.user.discordId,
    activatedByUsername: req.user.discordUsername,
    expiresAt,
  });
  await appendAudit({
    action: 'license_key_activated',
    code: code.toUpperCase(),
    by: req.user.discordId,
    username: req.user.discordUsername,
    expiresAt,
  });
  res.json({ ok: true, key: updated });
});

app.get('/api/keys/my', requireAuth, async (req, res) => {
  if (req.user.discordId === OWNER_DISCORD_ID) {
    return res.json({ isOwner: true, key: null });
  }
  const keys = await listLicenseKeys();
  const myKey = keys.find(k => k.activatedBy === req.user.discordId && k.status === 'active');
  if (myKey && new Date(myKey.expiresAt) < new Date()) {
    await updateLicenseKey(myKey.code, { status: 'expired' });
    return res.json({ key: null });
  }
  res.json({ key: myKey ?? null });
});

// ---- Client API (Scanner) ------------------------------------------------

app.post('/api/scan', scanLimiter, requireClientSecret, async (req, res) => {
  // C# ScanReport gönderir: sessionCode, machineId, game, processes, prefetch... hepsi düz (flat) alanda
  const body = req.body ?? {};
  const { sessionCode, machineId } = body;

  if (!machineId) return res.status(400).json({ error: 'missing machineId' });
  if (!sessionCode) return res.status(400).json({ error: 'missing sessionCode' });

  const session = await getSession(sessionCode);
  if (!isSessionUsable(session)) return res.status(403).json({ error: 'invalid or expired session code' });

  try {
    const rules = await getRules();
    const detections = runDetections(body, rules.filter(r => r.enabled));
    const verdict = summarize(detections); // string: 'clean', 'suspicious', 'cheating'
    const finalPin = sessionCode;
    const finalReport = {
      pin: finalPin,
      machineId,
      game: session.game || body.game || 'unknown',
      createdAt: new Date().toISOString(),
      scanDurationMs: body.scanDurationMs || 0,
      submittedBy: session.createdBy || body.submittedBy || 'client',
      ...body,
      detections,   // Detection nesneleri dizisi
      verdict,      // 'clean' | 'suspicious' | 'cheating'
    };
    await saveScan(finalPin, finalReport);
    await markSessionUsed(sessionCode);
    
    // Discord Webhook integration
    if (verdict !== 'clean') {
      const settings = await getSettings();
      if (settings.discordWebhookUrl) {
        const color = verdict === 'cheating' ? 15158332 : 15105570; // red : yellow
        const embed = {
          title: `Yeni Şüpheli Tarama Sonucu: ${verdict.toUpperCase()}`,
          color: color,
          fields: [
            { name: 'Kod (Pin)', value: finalPin, inline: true },
            { name: 'Makine ID', value: machineId, inline: true },
            { name: 'Oyun', value: finalReport.game, inline: true },
            { name: 'Tespit Sayısı', value: detections.length.toString(), inline: false }
          ],
          timestamp: new Date().toISOString()
        };
        
        // Add top 5 detections to the embed
        if (detections.length > 0) {
           const detText = detections.slice(0, 5).map(d => `**${d.name}** (${d.severity})`).join('\n');
           embed.fields.push({ name: 'İlk Tespitler', value: detText, inline: false });
        }
        
        fetch(settings.discordWebhookUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ embeds: [embed] })
        }).catch(e => console.error('Webhook gönderme hatası:', e.message));
      }
    }

    res.status(201).json({ ok: true, pin: finalPin, verdict });
  } catch (err) {
    console.error('Scan submit error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ---- Staff API -----------------------------------------------------------

app.post('/api/sessions', apiLimiter, requireAuth, requireActiveKey, async (req, res) => {
  const code = generatePin();
  const creatorDiscordId = req.user.discordId;
  const creatorSettings = await getSettings(creatorDiscordId);

  const session = {
    code,
    game: req.body.game?.slice(0, 50) || '',
    createdBy: req.user.discordUsername,
    creatorDiscordId,
    creatorSettings,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
    usedAt: null,
    startedAt: null,
    status: 'pending',
    progress: null,
  };
  await createSession(session);
  await appendAudit({ action: 'session_created', pin: code, game: session.game, by: req.user.discordUsername });
  res.status(201).json(session);
});

app.get('/api/sessions', apiLimiter, requireAuth, requireActiveKey, async (req, res) => {
  res.json(await listSessions());
});

app.delete('/api/sessions/:code', apiLimiter, requireAuth, requireActiveKey, async (req, res) => {
  const ok = await deleteSession(req.params.code);
  if (!ok) return res.status(404).json({ error: 'not found' });
  await appendAudit({ action: 'session_deleted', pin: req.params.code, by: req.user.discordUsername });
  res.status(204).end();
});

app.get('/api/sessions/:code', apiLimiter, requireClientSecret, async (req, res) => {
  const session = await getSession(req.params.code);
  if (!isSessionUsable(session)) return res.status(404).json({ valid: false, error: 'invalid or expired code' });
  if (!session.startedAt) {
    await updateSession(req.params.code, { startedAt: new Date().toISOString(), status: 'scanning' });
  }
  // 'valid: true' is required by ApiClient.cs (C# client reads this field)
  res.json({ valid: true, ok: true, game: session.game });
});

app.get('/api/download/:code', async (req, res) => {
  const code = req.params.code;
  const session = await getSession(code);
  
  if (!isSessionUsable(session)) {
    return res.status(403).send(`
      <!DOCTYPE html>
      <html lang="tr">
      <head>
        <meta charset="utf-8">
        <title>Bağlantı Geçersiz</title>
        <style>
          body { background: #0b0d10; color: #e7ebee; font-family: sans-serif; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; margin: 0; }
          .card { background: #14181c; border: 1px solid #262c32; padding: 30px; border-radius: 8px; text-align: center; max-width: 400px; }
          h2 { color: #e5484d; margin-top: 0; }
          p { color: #8b96a1; line-height: 1.5; }
        </style>
      </head>
      <body>
        <div class="card">
          <h2>İndirme Süresi Doldu</h2>
          <p>Bu indirme bağlantısının süresi dolmuş veya tarama zaten tamamlanmış. Eğer henüz taranmadıysanız yetkiliden yeni bir bağlantı isteyin.</p>
        </div>
      </body>
      </html>
    `);
  }
  
  // If EXE_DOWNLOAD_URL is set (e.g. a GitHub Releases link), redirect there.
  // This is the recommended approach when hosting on Render/Railway since
  // the exe is too large (161MB) to include in the git repo.
  const exeUrl = process.env.EXE_DOWNLOAD_URL;
  if (exeUrl) {
    return res.redirect(302, exeUrl);
  }

  // Fallback: serve from local bin/ directory (only works when running locally)
  const exePath = path.join(__dirname, 'bin', 'MistAC.exe');
  res.download(exePath, `MistScanner-${code}.exe`, (err) => {
    if (err) {
      if (!res.headersSent) {
        res.status(500).send('EXE_DOWNLOAD_URL env değişkeni tanımlanmamış ve yerel dosya bulunamadı. Lütfen Render ortam değişkenlerini kontrol edin.');
      }
    }
  });
});

app.post('/api/sessions/:code/progress', apiLimiter, requireClientSecret, async (req, res) => {
  const { headline, detail, percent } = req.body ?? {};
  const ok = await updateSession(req.params.code, {
    progress: { headline, detail, percent: Number(percent) || 0 }
  });
  if (!ok) return res.status(404).json({ error: 'session not found' });
  res.status(204).end();
});

app.get('/api/pin/:pin', apiLimiter, requireAuth, requireActiveKey, async (req, res) => {
  const rep = await getScan(req.params.pin);
  if (!rep) return res.status(404).json({ error: 'scan not found' });
  res.json(rep);
});

app.post('/api/pin/:pin/decision', apiLimiter, requireAuth, requireActiveKey, async (req, res) => {
  const { decision, reason } = req.body;
  if (!['cleared', 'warned', 'banned'].includes(decision)) return res.status(400).json({ error: 'invalid decision' });
  const rep = await getScan(req.params.pin);
  if (!rep) return res.status(404).json({ error: 'scan not found' });
  rep.staffDecision = { decision, reason: String(reason || ''), by: req.user.discordUsername, at: new Date().toISOString() };
  await saveScan(req.params.pin, rep);
  await appendAudit({ action: 'decision_' + decision, pin: req.params.pin, by: req.user.discordUsername });
  res.json(rep);
});

app.get('/api/scans', apiLimiter, requireAuth, requireActiveKey, async (req, res) => {
  const all = await listScans();
  const sum = all.map(s => ({
    pin: s.pin,
    game: s.game,
    machineId: s.machineId,
    createdAt: s.createdAt,
    detectionCount: s.detections?.length || 0,
    verdict: s.verdict,
    staffDecision: s.staffDecision,
    submittedBy: s.submittedBy,
  }));
  res.json(sum);
});

app.get('/api/rules', apiLimiter, requireAuth, requireActiveKey, async (req, res) => {
  res.json(await getRules());
});

app.post('/api/rules', apiLimiter, requireAuth, requireActiveKey, async (req, res) => {
  const { type, match, severity, name, note } = req.body;
  if (!type || !match || !severity || !name) return res.status(400).json({ error: 'missing fields' });
  const rule = await addRule({
    id: crypto.randomUUID(), type, match, severity, name, note: note || '', enabled: true,
  });
  await appendAudit({ action: 'rule_added', by: req.user.discordUsername });
  res.status(201).json(rule);
});

app.post('/api/rules/import', apiLimiter, requireAuth, requireActiveKey, async (req, res) => {
  const { text, sourceFileName } = req.body;
  if (!text) return res.status(400).json({ error: 'missing text payload' });
  
  const existing = await getRules();
  const parsed = parseRuleImport(text, sourceFileName, existing);
  if (parsed.created.length > 0) await addRules(parsed.created);
  if (parsed.created.length > 0) {
    await appendAudit({ action: 'rule_imported', by: req.user.discordUsername });
  }
  res.status(201).json(parsed);
});

app.patch('/api/rules/:id', apiLimiter, requireAuth, requireActiveKey, async (req, res) => {
  const r = await updateRule(req.params.id, req.body);
  if (!r) return res.status(404).json({ error: 'rule not found' });
  await appendAudit({ action: 'rule_updated', by: req.user.discordUsername });
  res.json(r);
});

app.delete('/api/rules/:id', apiLimiter, requireAuth, requireActiveKey, async (req, res) => {
  const ok = await deleteRule(req.params.id);
  if (!ok) return res.status(404).json({ error: 'rule not found' });
  await appendAudit({ action: 'rule_deleted', by: req.user.discordUsername });
  res.status(204).end();
});

app.get('/api/audit', apiLimiter, requireAuth, requireOwner, async (req, res) => {
  res.json(await getAudit());
});

app.get('/api/settings', apiLimiter, requireAuth, requireActiveKey, async (req, res) => {
  res.json(await getSettings(req.user.discordId));
});

app.patch('/api/settings', apiLimiter, requireAuth, requireActiveKey, async (req, res) => {
  const r = await updateSettings(req.user.discordId, req.body);
  await appendAudit({ action: 'settings_updated', by: req.user.discordUsername });
  res.json(r);
});

app.get('/api/client-settings', apiLimiter, requireClientSecret, async (req, res) => {
  res.json(await getSettings()); // fallback to global
});

app.get('/api/client-settings/:code', apiLimiter, requireClientSecret, async (req, res) => {
  const code = req.params.code;
  const session = await getSession(code);
  if (session && session.creatorSettings) {
    return res.json(session.creatorSettings);
  }
  res.json(await getSettings());
});

app.get('/api/health', (req, res) => res.json({ ok: true, version: '1.0.0' }));

app.listen(PORT, () => {
  console.log(`Mist AC backend listening on http://localhost:${PORT}`);
  console.log(`Owner Discord ID: ${OWNER_DISCORD_ID}`);
  console.log(`Dashboard URL: ${DASHBOARD_URL}`);
  console.log(`Backend URL: ${BACKEND_URL}`);
  if (!DISCORD_CLIENT_ID) console.warn('⚠ DISCORD_CLIENT_ID not set - OAuth disabled. Set it in .env!');

  // Render ücretsiz planda 15 dakika sonra uyku moduna girer.
  // Her 14 dakikada bir kendine ping atarak servisi canlı tutuyoruz.
  if (BACKEND_URL && !BACKEND_URL.includes('localhost')) {
    setInterval(() => {
      fetch(`${BACKEND_URL}/api/health`)
        .then(() => console.log('[keep-alive] ping OK'))
        .catch((e) => console.warn('[keep-alive] ping failed:', e.message));
    }, 14 * 60 * 1000); // 14 dakika
    console.log('[keep-alive] Self-ping aktif — Render uyku moduna girmeyecek.');
  }
});

