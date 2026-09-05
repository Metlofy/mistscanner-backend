// server.mjs
// Mist AC backend with Discord OAuth + License Key system

import express from "express";
import cors from "cors";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { readFile, writeFile, mkdir } from "node:fs/promises";
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
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

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
  // Check if user has a revoked key first
  const revokedKey = keys.find(k =>
    k.activatedBy === req.user.discordId && k.status === 'revoked'
  );
  if (revokedKey) {
    return res.status(403).json({ error: 'key_revoked', code: 'KEY_REVOKED' });
  }
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
      headers: { 
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'MistScanner (https://github.com/Metlofy, 1.0)'
      },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: `${BACKEND_URL}/auth/callback`,
      }),
    });
    if (!tokenRes.ok && tokenRes.status === 403) {
      throw new Error("Discord Cloudflare tarafindan Render IP'niz engellendi. Lutfen Discord API User-Agent ayarlarini kontrol edin: " + await tokenRes.text());
    }
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) {
      return res.redirect(`${DASHBOARD_URL}?auth_error=token_failed`);
    }
    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { 
        Authorization: `Bearer ${tokenData.access_token}`,
        'User-Agent': 'MistScanner (https://github.com/Metlofy, 1.0)'
      },
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
  const updated = await updateLicenseKey(req.params.code, { status: 'revoked', revokedAt: new Date().toISOString(), revokedBy: req.user.discordId });
  await appendAudit({ 
    action: 'license_key_revoked', 
    code: req.params.code, 
    label: key.label, 
    targetDiscordId: key.targetDiscordId, 
    activatedBy: key.activatedByUsername,
    by: req.user.discordUsername 
  });
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
  const myKey = keys.find(k => k.activatedBy === req.user.discordId && (k.status === 'active' || k.status === 'revoked'));
  if (myKey?.status === 'revoked') {
    return res.json({ key: myKey, revoked: true });
  }
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
      creatorDiscordId: session.creatorDiscordId,
      ...body,
      detections,   // Detection nesneleri dizisi
      verdict,      // 'clean' | 'suspicious' | 'cheating'
    };
    await saveScan(finalPin, finalReport);
    await markSessionUsed(sessionCode);
    
    // Always fetch settings from the creator of the session
    const creatorSettings = session.creatorSettings || await getSettings(session.creatorDiscordId);
    if (creatorSettings && creatorSettings.discordWebhookUrl) {
      // --- Rich Webhook ---
      const color = verdict === 'cheating' ? 15158332 : (verdict === 'suspicious' ? 15105570 : 3066993);
      const verdictEmoji = verdict === 'cheating' ? '🚫' : verdict === 'suspicious' ? '⚠️' : '✅';
      const verdictTr = verdict === 'cheating' ? 'HİLE TESPİT EDİLDİ' : verdict === 'suspicious' ? 'ŞÜPHELİ / UYARI' : 'TEMİZ';

      const embed = {
        title: `${verdictEmoji} Tarama Sonucu: ${verdictTr}`,
        color,
        description: [
          `**📌 PIN:** \`${finalPin}\``,
          `**🖥️ Makine ID:** \`${machineId}\``,
          `**🎮 Oyun:** ${finalReport.game}`,
          `**⏱️ Süre:** ${body.scanDurationMs || 0}ms`,
          `**👤 Gönderen:** ${session.createdBy || 'bilinmiyor'}`,
          `**🕒 Tarih:** ${new Date().toLocaleString('tr-TR')}`,
        ].join('\n'),
        fields: [],
        footer: { text: 'Mist Scanner • Adli İnceleme Sistemi' },
        timestamp: new Date().toISOString()
      };

      // Detections
      if (detections.length > 0) {
        const det = detections.slice(0, 12).map(d =>
          `\`${d.severity.toUpperCase()}\` **${d.name}** — ${d.type}${d.evidence ? `\n  ↳ \`${String(d.evidence).substring(0,80)}\`` : ''}`
        ).join('\n');
        embed.fields.push({ name: `🔍 Tespitler (${detections.length})`, value: det.substring(0, 1024), inline: false });
      } else {
        embed.fields.push({ name: '✅ Tespitler', value: 'Herhangi bir hile/şüpheli aktivite bulunamadı.', inline: false });
      }

      // Warnings
      if (body.warnings && body.warnings.length > 0) {
        const warn = body.warnings.slice(0, 8).map(w => `⚠️ \`${w.code || w.name || w}\``).join('\n');
        embed.fields.push({ name: `⚠️ Uyarılar (${body.warnings.length})`, value: warn.substring(0, 1024), inline: false });
      }

      // Processes (suspicious only)
      if (body.processes && body.processes.length > 0) {
        const procs = body.processes.slice(0, 15).map(p => `\`${(p.name || p).substring(0, 40)}\``).join(', ');
        embed.fields.push({ name: `⚙️ Çalışan Süreçler (${body.processes.length})`, value: procs.substring(0, 1024), inline: false });
      }

      // Prefetch
      if (body.prefetchFiles && body.prefetchFiles.length > 0) {
        const pf = body.prefetchFiles.slice(0, 10).map(f => `\`${(typeof f === 'string' ? f : f.name || '').substring(0, 50)}\``).join('\n');
        embed.fields.push({ name: `📂 Prefetch Dosyaları (${body.prefetchFiles.length})`, value: pf.substring(0, 1024), inline: false });
      }

      // USB History
      if (body.usbHistory && body.usbHistory.length > 0) {
        const usb = body.usbHistory.slice(0, 8).map(u => `🔌 ${u.deviceName || u.FriendlyName || 'USB Aygıt'}${u.lastConnected ? ` — ${u.lastConnected}` : ''}`).join('\n');
        embed.fields.push({ name: `🔌 USB Geçmişi (${body.usbHistory.length})`, value: usb.substring(0, 1024), inline: false });
      }

      // Browser History (suspicious)
      if (body.browserHistory && body.browserHistory.length > 0) {
        const bh = body.browserHistory.slice(0, 6).map(h => `🌐 ${(h.url || h).substring(0, 70)}`).join('\n');
        embed.fields.push({ name: `🌐 Şüpheli Tarayıcı Geçmişi (${body.browserHistory.length})`, value: bh.substring(0, 1024), inline: false });
      }

      // Lua hits
      if (body.luaHits && body.luaHits.length > 0) {
        const lua = body.luaHits.slice(0, 6).map(l => `Satır ${l.lineNumber}: **${l.match}** \`${(l.path||'').substring(0,40)}\``).join('\n');
        embed.fields.push({ name: `📜 Şüpheli Lua Kodları (${body.luaHits.length})`, value: lua.substring(0, 1024), inline: false });
      }

      // Clipboard
      if (body.clipboardText && body.clipboardText.trim()) {
        const clip = body.clipboardText.substring(0, 400).replace(/`/g, "'");
        embed.fields.push({ name: '📋 Pano İçeriği', value: `\`\`\`${clip}\`\`\``, inline: false });
      }

      // Amcache / Deleted files
      if (body.amcache && body.amcache.length > 0) {
        const am = body.amcache.slice(0, 8).map(a => `\`${(a.name || a).substring(0,50)}\``).join('\n');
        embed.fields.push({ name: `🗂️ Amcache Kayıtları (${body.amcache.length})`, value: am.substring(0, 1024), inline: false });
      }
      if (body.deletedFiles && body.deletedFiles.length > 0) {
        const del = body.deletedFiles.slice(0, 8).map(d => `\`${(d.name || d).substring(0,50)}\``).join('\n');
        embed.fields.push({ name: `🗑️ Silinmiş Dosyalar (${body.deletedFiles.length})`, value: del.substring(0, 1024), inline: false });
      }

      // Loaded Modules (suspicious)
      if (body.modules && body.modules.length > 0) {
        const mods = body.modules.filter(m => m.suspicious).slice(0, 8).map(m => `\`${(m.name||m).substring(0,50)}\``).join('\n');
        if (mods) embed.fields.push({ name: `💉 Şüpheli Yüklü Modüller`, value: mods.substring(0, 1024), inline: false });
      }

      fetch(creatorSettings.discordWebhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ embeds: [embed] })
      }).catch(e => console.error('Webhook gönderme hatası:', e.message));
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
  const all = await listSessions();
  const filtered = all.filter(s => s.creatorDiscordId === req.user.discordId);
  res.json(filtered);
});

app.delete('/api/sessions/:code', apiLimiter, requireAuth, requireActiveKey, async (req, res) => {
  const session = await getSession(req.params.code);
  if (session && session.creatorDiscordId !== req.user.discordId) {
    return res.status(403).json({ error: 'forbidden' });
  }
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

    // Send "Scan Started" webhook
    const creatorSettings = session.creatorSettings || await getSettings(session.creatorDiscordId);
    if (creatorSettings && creatorSettings.discordWebhookUrl) {
      const startEmbed = {
        title: 'Tarama Başladı',
        color: 3447003, // blue
        fields: [
          { name: 'Kod (Pin)', value: req.params.code, inline: true },
          { name: 'Oyun', value: session.game || 'Bilinmiyor', inline: true }
        ],
        timestamp: new Date().toISOString()
      };
      fetch(creatorSettings.discordWebhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ embeds: [startEmbed] })
      }).catch(() => {});
    }
  }
  // 'valid: true' is required by ApiClient.cs (C# client reads this field)
  res.json({ valid: true, ok: true, game: session.game });
});

// Returns the latest version info for the Auto-Updater
app.get('/api/version', (req, res) => {
  res.json({
    version: '1.0.1', // Bump this when pushing a mandatory update
    exeUrl: process.env.EXE_DOWNLOAD_URL || ''
  });
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
    try {
      const resp = await fetch(exeUrl);
      if (!resp.ok) {
        return res.status(500).send('Exe dosyası indirilemedi (GitHub Releases hatası).');
      }
      res.setHeader('Content-Disposition', `attachment; filename="MistScanner-${code}.exe"`);
      res.setHeader('Content-Type', 'application/vnd.microsoft.portable-executable');
      if (resp.headers.has('content-length')) {
        res.setHeader('Content-Length', resp.headers.get('content-length'));
      }
      // Node 18+ Web Streams to Express response
      const reader = resp.body.getReader();
      return (async function pump() {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          res.write(value);
        }
        res.end();
      })();
    } catch (err) {
      console.error('Exe download proxy error:', err);
      return res.status(500).send('Exe indirme proxy hatası.');
    }
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
  if (rep.creatorDiscordId && rep.creatorDiscordId !== req.user.discordId) {
    return res.status(403).json({ error: 'forbidden' });
  }
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
  const sum = all
    .filter(s => s.creatorDiscordId === req.user.discordId)
    .map(s => ({
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

app.get('/api/stats/global', async (req, res) => {
  try {
    const files = await fs.readdir(SCANS_DIR);
    let total = 0, banned = 0, clean = 0, warned = 0, pending = 0;
    
    for (const f of files) {
      if (!f.endsWith('.json')) continue;
      total++;
      try {
        const data = JSON.parse(await fs.readFile(path.join(SCANS_DIR, f), 'utf-8'));
        const v = data.staffDecision ? data.staffDecision.decision : data.verdict;
        if (v === 'banned' || v === 'cheating') banned++;
        else if (v === 'cleared' || v === 'clean') clean++;
        else if (v === 'warned' || v === 'suspicious') warned++;
        else pending++;
      } catch (e) {}
    }
    res.json({ total, banned, clean, warned, pending });
  } catch (err) {
    res.status(500).json({ error: 'Failed to compute stats' });
  }
});

app.get('/api/rules', apiLimiter, requireAuth, requireActiveKey, async (req, res) => {
  const all = await getRules();
  // Only show rules this user created (hide built-in system rules from dashboard)
  const filtered = all.filter(r => r.creatorDiscordId === req.user.discordId);
  res.json(filtered);
});

app.post('/api/rules', apiLimiter, requireAuth, requireActiveKey, async (req, res) => {
  const { type, match, severity, name, note } = req.body;
  if (!type || !match || !severity || !name) return res.status(400).json({ error: 'missing fields' });
  const rule = await addRule({
    id: crypto.randomUUID(), type, match, severity, name, note: note || '', enabled: true,
    creatorDiscordId: req.user.discordId,
    createdAt: new Date().toISOString(),
  });
  await appendAudit({ action: 'rule_added', by: req.user.discordUsername });
  res.status(201).json(rule);
});

app.post('/api/rules/import', apiLimiter, requireAuth, requireActiveKey, async (req, res) => {
  const { text, sourceFileName } = req.body;
  if (!text) return res.status(400).json({ error: 'missing text payload' });
  
  const existing = await getRules();
  const parsed = parseRuleImport(text, sourceFileName, existing);
  // Tag imported rules with this user's ID
  parsed.created = parsed.created.map(r => ({ ...r, creatorDiscordId: req.user.discordId }));
  if (parsed.created.length > 0) await addRules(parsed.created);
  if (parsed.created.length > 0) {
    await appendAudit({ action: 'rule_imported', by: req.user.discordUsername });
  }
  res.status(201).json(parsed);
});

app.patch('/api/rules/:id', apiLimiter, requireAuth, requireActiveKey, async (req, res) => {
  const all = await getRules();
  const rule = all.find(r => r.id === req.params.id);
  // Only allow editing own rules (system rules cannot be modified)
  if (!rule) return res.status(404).json({ error: 'rule not found' });
  if (rule.system && !req.user.isOwner) return res.status(403).json({ error: 'cannot modify system rule' });
  if (!rule.system && rule.creatorDiscordId !== req.user.discordId) return res.status(403).json({ error: 'forbidden' });
  const r = await updateRule(req.params.id, req.body);
  if (!r) return res.status(404).json({ error: 'rule not found' });
  await appendAudit({ action: 'rule_updated', by: req.user.discordUsername });
  res.json(r);
});

app.delete('/api/rules/:id', apiLimiter, requireAuth, requireActiveKey, async (req, res) => {
  const all = await getRules();
  const rule = all.find(r => r.id === req.params.id);
  if (!rule) return res.status(404).json({ error: 'rule not found' });
  if (rule.system) return res.status(403).json({ error: 'cannot delete system rule' });
  if (rule.creatorDiscordId !== req.user.discordId) return res.status(403).json({ error: 'forbidden' });
  const ok = await deleteRule(req.params.id);
  if (!ok) return res.status(404).json({ error: 'rule not found' });
  await appendAudit({ action: 'rule_deleted', by: req.user.discordUsername });
  res.status(204).end();
});

// Leaderboard - tüm kullanıcıların tarama performansını döndürür (sadece auth gerekli, Free dahil)
app.get('/api/leaderboard', apiLimiter, requireAuth, async (req, res) => {
  try {
    const [all, authSessions] = await Promise.all([
      listScans(),
      // Build a lookup: discordId -> {username, avatar}
      (async () => {
        const { promises: fs } = await import('node:fs');
        try {
          const raw = await fs.readFile(path.join(__dirname, 'data', 'auth_sessions.json'), 'utf-8');
          const sessions = Object.values(JSON.parse(raw));
          const map = {};
          for (const s of sessions) {
            if (s.discordId && !map[s.discordId]) {
              map[s.discordId] = { name: s.discordGlobalName || s.discordUsername, avatar: s.discordAvatar };
            }
          }
          return map;
        } catch { return {}; }
      })()
    ]);

    const leaderScans = all.map(s => {
      const userInfo = authSessions[s.creatorDiscordId] || {};
      return {
        createdAt: s.createdAt,
        creatorDiscordId: s.creatorDiscordId || null,
        creatorDiscordUsername: userInfo.name || s.submittedBy || null,
        creatorDiscordAvatar: userInfo.avatar || null,
        detectionCount: s.detections?.length || 0,
        staffDecision: s.staffDecision ? { decision: s.staffDecision.decision } : null,
      };
    });
    res.json({ scans: leaderScans });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
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

// ---- Maintenance Mode ----------------------------------------------------
// Stored as a global flag in data/maintenance.json
const MAINTENANCE_FILE = path.join(path.dirname(fileURLToPath(import.meta.url)), 'data', 'maintenance.json');

async function getMaintenanceMode() {
  try {
    const raw = await readFile(MAINTENANCE_FILE, 'utf8');
    return JSON.parse(raw);
  } catch { return { enabled: false }; }
}
async function setMaintenanceMode(val) {
  try { await mkdir(path.dirname(MAINTENANCE_FILE), { recursive: true }); } catch {}
  await writeFile(MAINTENANCE_FILE, JSON.stringify(val, null, 2));
}

// Anyone can check maintenance status (used before login to show maintenance page)
app.get('/api/maintenance', async (_req, res) => {
  res.json(await getMaintenanceMode());
});

// Only owner can toggle maintenance mode
app.post('/api/maintenance', requireAuth, requireOwner, async (req, res) => {
  const { enabled } = req.body ?? {};
  await setMaintenanceMode({ enabled: !!enabled, updatedAt: new Date().toISOString() });
  await appendAudit({ action: enabled ? 'maintenance_enabled' : 'maintenance_disabled', by: req.user.discordId });
  res.json({ ok: true, enabled: !!enabled });
});

// ---- Screenshot/Video Upload -----------------------------------------------
// C# client sends: { pin, clientSecret, frames: ["base64...", ...] }
// We store them under data/videos/<pin>.json as raw base64 array.
// The dashboard hits GET /api/video/:pin to retrieve and build a timelapse.

const VIDEOS_DIR = path.join(__dirname, 'data', 'videos');
mkdir(VIDEOS_DIR, { recursive: true }).catch(() => {});

app.post('/api/scan/:pin/frames', requireClientSecret, async (req, res) => {
  const { pin } = req.params;
  const { frames } = req.body; // string[]  base64 PNG images
  if (!Array.isArray(frames) || frames.length === 0) {
    return res.status(400).json({ error: 'frames array required' });
  }
  try {
    const file = path.join(VIDEOS_DIR, `${pin}.json`);
    await writeFile(file, JSON.stringify({ pin, frames, createdAt: new Date().toISOString() }), 'utf-8');
    res.json({ ok: true, count: frames.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/video/:pin', requireAuth, requireActiveKey, async (req, res) => {
  try {
    const file = path.join(VIDEOS_DIR, `${req.params.pin}.json`);
    const data = JSON.parse(await readFile(file, 'utf-8'));
    // Verify the requester owns this scan
    const scan = await getScan(req.params.pin);
    if (scan && scan.creatorDiscordId && scan.creatorDiscordId !== req.user.discordId) {
      return res.status(403).json({ error: 'forbidden' });
    }
    res.json(data);
  } catch {
    res.status(404).json({ error: 'no video for this pin' });
  }
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

