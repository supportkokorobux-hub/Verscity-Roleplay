const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const crypto = require('node:crypto');

loadEnvFile(path.join(__dirname, '.env'));

const PORT = Number(process.env.PORT || 3000);
const HTML_FILE = path.join(__dirname, 'verscity-fixed__21_ (6).html');
const TICKET_STORE_FILE = path.join(__dirname, 'discord-tickets.json');
const DISCORD_API = 'https://discord.com/api/v10';
const DISCORD_OAUTH_AUTHORIZE = 'https://discord.com/oauth2/authorize';
const DISCORD_OAUTH_TOKEN = 'https://discord.com/api/oauth2/token';
const DISCORD_PERMS = {
  VIEW_CHANNEL: 1 << 10,
  SEND_MESSAGES: 1 << 11,
  READ_MESSAGE_HISTORY: 1 << 16
};
const TICKET_LIMIT_WINDOW_MS = 60_000;
const TICKET_LIMIT_MAX = Number(process.env.DISCORD_TICKET_RATE_LIMIT || 5);
const ticketHits = new Map();
const oauthStates = new Map();
const sessions = new Map();
let tickets = loadTickets();

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    if (req.method === 'OPTIONS' && url.pathname.startsWith('/api/')) {
      setCorsHeaders(req, res);
      res.writeHead(204);
      res.end();
      return;
    }

    if (req.method === 'GET' && url.pathname === '/auth/discord/start') {
      await handleDiscordAuthStart(req, res, url);
      return;
    }

    if (req.method === 'GET' && url.pathname === '/auth/discord/callback') {
      await handleDiscordAuthCallback(req, res, url);
      return;
    }

    if (req.method === 'GET' && url.pathname === '/api/discord-me') {
      setCorsHeaders(req, res);
      await handleDiscordMe(req, res);
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/discord-ticket') {
      setCorsHeaders(req, res);
      await handleDiscordTicket(req, res);
      return;
    }

    if (req.method === 'GET' && url.pathname === '/api/discord-ticket-status') {
      setCorsHeaders(req, res);
      await handleDiscordTicketStatus(req, res, url);
      return;
    }

    if (req.method === 'GET' && url.pathname === '/api/discord-ticket-approve') {
      await handleDiscordTicketApprove(req, res, url);
      return;
    }

    if (req.method === 'GET' && (url.pathname === '/' || decodeURIComponent(url.pathname.slice(1)) === path.basename(HTML_FILE))) {
      const html = fs.readFileSync(HTML_FILE, 'utf8');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
      return;
    }

    if (req.method === 'GET' && url.pathname === '/qris-image') {
      if (!serveQrisImage(res)) {
        sendJson(req, res, 404, { message: 'QRIS image not found' });
      }
      return;
    }

    if (req.method === 'GET' && serveStaticFile(url, res)) {
      return;
    }

    sendJson(req, res, 404, { message: 'Not found' });
  } catch (err) {
    console.error(err);
    sendJson(req, res, 500, { message: 'Server error' });
  }
});

server.listen(PORT, () => {
  console.log(`VersCity web server running at http://localhost:${PORT}`);
});

async function handleDiscordAuthStart(req, res, url) {
  const clientId = process.env.DISCORD_CLIENT_ID;
  const clientSecret = process.env.DISCORD_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    sendHtml(res, 500, approvalPage('Login Discord belum dikonfigurasi.', 'Isi DISCORD_CLIENT_ID dan DISCORD_CLIENT_SECRET di file .env.'));
    return;
  }

  const state = makeSecretToken();
  const returnTo = normalizeReturnTo(url.searchParams.get('returnTo'), req);
  oauthStates.set(state, {
    returnTo,
    createdAt: Date.now()
  });

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    scope: 'identify guilds.join',
    state,
    redirect_uri: getDiscordRedirectUri(req),
    prompt: 'consent'
  });

  res.writeHead(302, { Location: `${DISCORD_OAUTH_AUTHORIZE}?${params}` });
  res.end();
}

async function handleDiscordAuthCallback(req, res, url) {
  const state = url.searchParams.get('state') || '';
  const code = url.searchParams.get('code') || '';
  const savedState = oauthStates.get(state);
  oauthStates.delete(state);

  if (!code || !savedState || Date.now() - savedState.createdAt > 10 * 60 * 1000) {
    sendHtml(res, 400, approvalPage('Login Discord gagal.', 'State OAuth tidak valid atau sudah kedaluwarsa. Coba login ulang.'));
    return;
  }

  try {
    const tokenData = await exchangeDiscordCode(code, req);
    const user = await getDiscordUser(tokenData.access_token);
    const sessionId = makeSecretToken();
    sessions.set(sessionId, {
      user,
      accessToken: tokenData.access_token,
      expiresAt: Date.now() + Number(tokenData.expires_in || 604800) * 1000,
      createdAt: Date.now()
    });

    setSessionCookie(req, res, sessionId);
    res.writeHead(302, { Location: savedState.returnTo || '/' });
    res.end();
  } catch (err) {
    console.error('Discord OAuth error:', err);
    sendHtml(res, 502, approvalPage('Login Discord gagal.', err.message || 'Discord OAuth gagal.'));
  }
}

async function handleDiscordMe(req, res) {
  const session = getSession(req);
  if (!session) {
    sendJson(req, res, 200, { loggedIn: false });
    return;
  }

  sendJson(req, res, 200, {
    loggedIn: true,
    user: publicDiscordUser(session.user)
  });
}

async function handleDiscordTicket(req, res) {
  if (!checkRateLimit(req)) {
    sendJson(req, res, 429, { message: 'Terlalu banyak membuat channel. Coba lagi sebentar.' });
    return;
  }

  const token = process.env.DISCORD_BOT_TOKEN;
  const guildId = process.env.DISCORD_GUILD_ID;
  const adminChannelId = process.env.DISCORD_ADMIN_CHANNEL_ID;
  const clientId = process.env.DISCORD_CLIENT_ID;
  const clientSecret = process.env.DISCORD_CLIENT_SECRET;
  if (!token || !guildId || !adminChannelId || !clientId || !clientSecret) {
    sendJson(req, res, 500, {
      message: 'Backend Discord belum dikonfigurasi. Isi DISCORD_BOT_TOKEN, DISCORD_GUILD_ID, DISCORD_ADMIN_CHANNEL_ID, DISCORD_CLIENT_ID, dan DISCORD_CLIENT_SECRET di file .env.'
    });
    return;
  }

  const body = await readJson(req);
  const session = getSession(req);
  if (!session) {
    sendJson(req, res, 401, {
      message: 'Login Discord dulu sebelum membuat ticket.',
      authUrl: buildDiscordAuthUrl(req, body.returnTo)
    });
    return;
  }

  const customer = session.user;
  const item = cleanText(body.item, 'Donasi');
  const price = cleanText(body.price, '-');
  const ticketId = makePublicId();
  const approvalToken = makeSecretToken();
  const approvalUrl = `${getPublicBaseUrl(req)}/api/discord-ticket-approve?id=${encodeURIComponent(ticketId)}&token=${encodeURIComponent(approvalToken)}`;
  const channelName = buildChannelName(customer, item);

  await ensureGuildMember(guildId, customer.id, session.accessToken, token);

  const channelPayload = {
    name: channelName,
    type: 0,
    topic: `Ticket pending approval | ID: ${ticketId} | Customer: ${customer.id} | Item: ${item} | Harga: ${price}`,
    rate_limit_per_user: Number(process.env.DISCORD_CHANNEL_SLOWMODE || 2)
  };

  if (process.env.DISCORD_CATEGORY_ID) {
    channelPayload.parent_id = process.env.DISCORD_CATEGORY_ID;
  }

  channelPayload.permission_overwrites = [
    {
      id: guildId,
      type: 0,
      allow: '0',
      deny: String(DISCORD_PERMS.VIEW_CHANNEL | DISCORD_PERMS.SEND_MESSAGES)
    },
    {
      id: customer.id,
      type: 1,
      allow: String(DISCORD_PERMS.VIEW_CHANNEL | DISCORD_PERMS.READ_MESSAGE_HISTORY),
      deny: String(DISCORD_PERMS.SEND_MESSAGES)
    }
  ];

  if (process.env.DISCORD_ADMIN_ROLE_ID) {
    channelPayload.permission_overwrites.push({
      id: process.env.DISCORD_ADMIN_ROLE_ID,
      type: 0,
      allow: String(DISCORD_PERMS.VIEW_CHANNEL | DISCORD_PERMS.SEND_MESSAGES),
      deny: '0'
    });
  }

  try {
    const channel = await discordRequest(`/guilds/${guildId}/channels`, {
      method: 'POST',
      token,
      reason: 'VersCity website donation ticket',
      body: channelPayload
    });

    const channelUrl = `https://discord.com/channels/${guildId}/${channel.id}`;
    tickets[ticketId] = {
      id: ticketId,
      approvalToken,
      status: 'pending',
      item,
      price,
      customer: publicDiscordUser(customer),
      channelId: channel.id,
      channelUrl,
      inviteUrl: null,
      redirectUrl: channelUrl,
      createdAt: new Date().toISOString(),
      approvedAt: null
    };
    saveTickets();

    await sendCustomerTicketIntro(channel.id, token, item, price, customer);
    await sendAdminApprovalRequest(adminChannelId, token, item, price, approvalUrl, ticketId, channelUrl, customer);

    sendJson(req, res, 200, {
      ticketId,
      status: 'pending',
      channelId: channel.id,
      channelUrl,
      inviteUrl: null,
      redirectUrl: channelUrl,
      message: 'Channel ticket sudah dibuat. Customer bisa masuk, tapi chat dikunci sampai admin menerima ticket.'
    });
  } catch (err) {
    console.error('Discord ticket error:', err);
    sendJson(req, res, 502, {
      message: `Discord gagal membuat channel: ${err.message || 'Unknown error'}`
    });
  }
}

async function handleDiscordTicketStatus(req, res, url) {
  const ticketId = cleanText(url.searchParams.get('id'), '');
  const ticket = tickets[ticketId];
  if (!ticket) {
    sendJson(req, res, 404, { message: 'Ticket tidak ditemukan.' });
    return;
  }

  sendJson(req, res, 200, {
    ticketId: ticket.id,
    status: ticket.status,
    channelId: ticket.channelId,
    redirectUrl: ticket.status === 'approved' ? ticket.redirectUrl : null,
    message: ticket.status === 'approved'
      ? 'Ticket sudah diterima admin. Mengalihkan ke Discord...'
      : 'Menunggu admin menerima ticket.'
  });
}

async function handleDiscordTicketApprove(req, res, url) {
  const token = process.env.DISCORD_BOT_TOKEN;
  const guildId = process.env.DISCORD_GUILD_ID;
  const ticketId = cleanText(url.searchParams.get('id'), '');
  const approvalToken = cleanText(url.searchParams.get('token'), '');
  const ticket = tickets[ticketId];

  if (!token || !guildId) {
    sendHtml(res, 500, approvalPage('Backend Discord belum dikonfigurasi.', 'Isi DISCORD_BOT_TOKEN dan DISCORD_GUILD_ID di file .env.'));
    return;
  }

  if (!ticket || !approvalToken || ticket.approvalToken !== approvalToken) {
    sendHtml(res, 403, approvalPage('Link approval tidak valid.', 'Ticket tidak ditemukan atau token approval salah.'));
    return;
  }

  if (ticket.status === 'approved') {
    sendHtml(res, 200, approvalPage('Ticket sudah diterima.', `Customer sudah bisa chat di channel: ${ticket.channelUrl}`));
    return;
  }

  try {
    await unlockTicketChannel(ticket.channelId, ticket.customer.id, token);
    ticket.status = 'approved';
    ticket.approvedAt = new Date().toISOString();
    saveTickets();

    await sendApprovalMessage(ticket.channelId, token, ticket);

    sendHtml(res, 200, approvalPage('Ticket diterima.', 'Customer sekarang sudah bisa chat di channel Discord.'));
  } catch (err) {
    console.error('Discord approval error:', err);
    sendHtml(res, 502, approvalPage('Ticket gagal diterima.', err.message || 'Discord gagal membuat invite.'));
  }
}

async function sendCustomerTicketIntro(channelId, token, item, price, customer) {
  const content = [
    'Ticket donasi berhasil dibuat.',
    '',
    `Customer: <@${customer.id}>`,
    `Item: **${escapeMentions(item)}**`,
    `Harga: **${escapeMentions(price)}**`,
    '',
    'Channel ini sudah bisa dilihat customer, tapi chat masih dikunci.',
    'Tunggu admin menerima ticket sebelum mengirim nama karakter dan bukti transfer.'
  ].join('\n');

  try {
    await discordRequest(`/channels/${channelId}/messages`, {
      method: 'POST',
      token,
      body: {
        content,
        allowed_mentions: { users: [customer.id] }
      }
    });
  } catch (err) {
    console.warn('Channel created, but customer intro message failed:', err.message);
  }
}

async function sendAdminApprovalRequest(adminChannelId, token, item, price, approvalUrl, ticketId, channelUrl, customer) {
  const adminRoleId = process.env.DISCORD_ADMIN_ROLE_ID;
  const adminMention = adminRoleId ? `<@&${adminRoleId}> ` : '';
  const content = [
    `${adminMention}Ticket donasi baru dari website menunggu approval admin.`,
    '',
    `Ticket ID: \`${ticketId}\``,
    `Customer: <@${customer.id}> (${escapeMentions(customer.username)})`,
    `Item: **${escapeMentions(item)}**`,
    `Harga: **${escapeMentions(price)}**`,
    `Channel: ${channelUrl}`,
    '',
    'Customer sudah diarahkan ke channel ini, tapi belum bisa chat.',
    'Klik link berikut untuk menerima ticket dan membuka izin chat:',
    approvalUrl
  ].join('\n');

  try {
    await discordRequest(`/channels/${adminChannelId}/messages`, {
      method: 'POST',
      token,
      body: {
        content,
        allowed_mentions: adminRoleId ? { roles: [adminRoleId] } : { parse: [] }
      }
    });
  } catch (err) {
    throw new Error(`Pesan approval gagal dikirim ke channel admin: ${err.message}`);
  }
}

async function createChannelInvite(channelId, token) {
  try {
    const maxAge = clampNumber(process.env.DISCORD_INVITE_MAX_AGE, 0, 604800, 86400);
    const maxUses = clampNumber(process.env.DISCORD_INVITE_MAX_USES, 0, 100, 1);
    const invite = await discordRequest(`/channels/${channelId}/invites`, {
      method: 'POST',
      token,
      reason: 'VersCity website donation ticket invite',
      body: {
        max_age: maxAge,
        max_uses: maxUses,
        temporary: false,
        unique: true
      }
    });

    return invite && invite.code ? `https://discord.gg/${invite.code}` : null;
  } catch (err) {
    console.warn('Channel created, but invite failed:', err.message);
    return null;
  }
}

async function unlockTicketChannel(channelId, customerUserId, token) {
  await discordRequest(`/channels/${channelId}/permissions/${customerUserId}`, {
    method: 'PUT',
    token,
    reason: 'VersCity ticket approved by admin',
    body: {
      type: 1,
      allow: String(DISCORD_PERMS.VIEW_CHANNEL | DISCORD_PERMS.SEND_MESSAGES | DISCORD_PERMS.READ_MESSAGE_HISTORY),
      deny: '0'
    }
  });
}

async function sendApprovalMessage(channelId, token, ticket) {
  try {
    await discordRequest(`/channels/${channelId}/messages`, {
      method: 'POST',
      token,
      body: {
        content: [
          'Ticket sudah diterima admin.',
          'Customer sekarang sudah bisa chat di channel ini.'
        ].join('\n'),
        allowed_mentions: { parse: [] }
      }
    });
  } catch (err) {
    console.warn('Ticket approved, but approval message failed:', err.message);
  }
}

async function discordRequest(route, options) {
  const headers = {
    Authorization: `Bot ${options.token}`,
    'Content-Type': 'application/json'
  };

  if (options.reason) {
    headers['X-Audit-Log-Reason'] = encodeURIComponent(options.reason);
  }

  const response = await fetch(`${DISCORD_API}${route}`, {
    method: options.method,
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined
  });

  const text = await response.text();
  const data = text ? safeJsonParse(text) : null;
  if (!response.ok) {
    const message = (data && data.message) || text || `HTTP ${response.status}`;
    const err = new Error(message);
    err.status = response.status;
    err.discord = data;
    throw err;
  }

  return data;
}

function buildDiscordAuthUrl(req, returnTo) {
  const state = makeSecretToken();
  oauthStates.set(state, {
    returnTo: normalizeReturnTo(returnTo, req),
    createdAt: Date.now()
  });

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: process.env.DISCORD_CLIENT_ID,
    scope: 'identify guilds.join',
    state,
    redirect_uri: getDiscordRedirectUri(req),
    prompt: 'consent'
  });

  return `${DISCORD_OAUTH_AUTHORIZE}?${params}`;
}

async function exchangeDiscordCode(code, req) {
  const params = new URLSearchParams({
    client_id: process.env.DISCORD_CLIENT_ID,
    client_secret: process.env.DISCORD_CLIENT_SECRET,
    grant_type: 'authorization_code',
    code,
    redirect_uri: getDiscordRedirectUri(req)
  });

  const response = await fetch(DISCORD_OAUTH_TOKEN, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error_description || data.error || 'Token OAuth Discord gagal dibuat.');
  return data;
}

async function getDiscordUser(accessToken) {
  const response = await fetch(`${DISCORD_API}/users/@me`, {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.message || 'Data user Discord gagal diambil.');
  return data;
}

async function ensureGuildMember(guildId, userId, accessToken, botToken) {
  if (!accessToken) throw new Error('Session Discord tidak punya access token. Login ulang Discord.');

  const response = await fetch(`${DISCORD_API}/guilds/${guildId}/members/${userId}`, {
    method: 'PUT',
    headers: {
      Authorization: `Bot ${botToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ access_token: accessToken })
  });

  if (response.status === 201 || response.status === 204) return;

  const data = await response.json().catch(() => ({}));
  throw new Error(data.message || 'Customer gagal dimasukkan ke server Discord.');
}

function getDiscordRedirectUri(req) {
  const configured = (process.env.DISCORD_REDIRECT_URI || '').trim();
  if (configured) return configured;
  return `${getPublicBaseUrl(req)}/auth/discord/callback`;
}

function getSession(req) {
  const cookies = parseCookies(req.headers.cookie || '');
  const sid = cookies.vrc_discord_session;
  if (!sid) return null;
  const session = sessions.get(sid);
  if (!session) return null;
  if (Date.now() - session.createdAt > 7 * 24 * 60 * 60 * 1000 || Date.now() > session.expiresAt) {
    sessions.delete(sid);
    return null;
  }
  return session;
}

function setSessionCookie(req, res, sessionId) {
  const secure = getPublicBaseUrl(req).startsWith('https://');
  const attrs = [
    `vrc_discord_session=${sessionId}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=604800'
  ];
  if (secure) attrs.push('Secure');
  res.setHeader('Set-Cookie', attrs.join('; '));
}

function parseCookies(cookieHeader) {
  const cookies = {};
  cookieHeader.split(';').forEach(part => {
    const eq = part.indexOf('=');
    if (eq === -1) return;
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (key) cookies[key] = value;
  });
  return cookies;
}

function publicDiscordUser(user) {
  return {
    id: user.id,
    username: user.global_name || user.username,
    avatar: user.avatar || null
  };
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    let tooLarge = false;

    req.on('data', chunk => {
      raw += chunk;
      if (raw.length > 16_384) {
        tooLarge = true;
        req.destroy();
      }
    });

    req.on('end', () => {
      if (tooLarge) {
        reject(new Error('Request terlalu besar.'));
        return;
      }
      if (!raw.trim()) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new Error('JSON request tidak valid.'));
      }
    });

    req.on('error', reject);
  });
}

function sendJson(req, res, status, payload) {
  setCorsHeaders(req, res);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
}

function serveStaticFile(url, res) {
  const safeName = path.basename(decodeURIComponent(url.pathname));
  const ext = path.extname(safeName).toLowerCase();
  const mime = {
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.webp': 'image/webp',
    '.gif': 'image/gif'
  }[ext];

  if (!mime || safeName !== decodeURIComponent(url.pathname).replace(/^\/+/, '')) return false;

  const filePath = path.join(__dirname, safeName);
  if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) return false;

  res.writeHead(200, { 'Content-Type': mime, 'Cache-Control': 'no-cache' });
  fs.createReadStream(filePath).pipe(res);
  return true;
}

function serveQrisImage(res) {
  const candidates = ['qris.png', 'qris.jpg', 'qris.jpeg', 'qris.webp'];
  for (const name of candidates) {
    const filePath = path.join(__dirname, name);
    if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) continue;

    const ext = path.extname(name).toLowerCase();
    const mime = {
      '.png': 'image/png',
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.webp': 'image/webp'
    }[ext] || 'application/octet-stream';

    res.writeHead(200, { 'Content-Type': mime, 'Cache-Control': 'no-cache' });
    fs.createReadStream(filePath).pipe(res);
    return true;
  }

  return false;
}

function sendHtml(res, status, html) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}

function approvalPage(title, message) {
  return `<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <style>
    body { margin:0; min-height:100vh; display:grid; place-items:center; background:#080a0e; color:#d4cfc8; font-family:Arial,sans-serif; }
    main { max-width:560px; padding:32px; border:1px solid rgba(201,168,76,.25); background:#0d1117; text-align:center; }
    h1 { margin:0 0 12px; color:#c9a84c; letter-spacing:1px; }
    p { margin:0; line-height:1.6; }
  </style>
</head>
<body>
  <main>
    <h1>${escapeHtml(title)}</h1>
    <p>${escapeHtml(message)}</p>
  </main>
</body>
</html>`;
}

function setCorsHeaders(req, res) {
  const origin = req.headers.origin;
  const allowedOrigin = process.env.DISCORD_ALLOWED_ORIGIN || '';
  const allowLocal = !allowedOrigin && (origin === 'null' || /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin || ''));

  if (allowedOrigin === '*' || (allowedOrigin && origin === allowedOrigin) || allowLocal) {
    res.setHeader('Access-Control-Allow-Origin', allowedOrigin === '*' ? '*' : origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
}

function checkRateLimit(req) {
  const ip = req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const bucket = ticketHits.get(ip) || [];
  const fresh = bucket.filter(time => now - time < TICKET_LIMIT_WINDOW_MS);
  if (fresh.length >= TICKET_LIMIT_MAX) return false;
  fresh.push(now);
  ticketHits.set(ip, fresh);
  return true;
}

function buildChannelName(customer, item) {
  const customerName = slugifyDiscordName(customer.global_name || customer.username || 'customer', 24);
  const itemName = slugifyOrderName(item, 48);
  const orderNumber = getNextOrderNumber(customer.id, itemName);
  return `ticket-${customerName}-${itemName}-${orderNumber}`.slice(0, 100).replace(/-+$/g, '');
}

function getNextOrderNumber(customerId, itemSlug) {
  let count = 0;
  Object.values(tickets).forEach(ticket => {
    if (!ticket || !ticket.customer) return;
    if (ticket.customer.id !== customerId) return;
    if (slugifyOrderName(ticket.item, 48) !== itemSlug) return;
    count += 1;
  });
  return count + 1;
}

function slugifyDiscordName(value, maxLength) {
  return slugify(value, maxLength) || 'customer';
}

function slugifyOrderName(value, maxLength) {
  let text = String(value || 'orderan');
  const parts = text.split(/\s+[—–-]\s+/);
  if (parts.length > 1) text = parts.pop();
  return (slugify(text, maxLength) || 'orderan')
    .replace(/([a-z])-(\d)/g, '$1$2')
    .replace(/(\d)-([a-z])/g, '$1$2');
}

function slugify(value, maxLength) {
  return String(value || '')
    .normalize('NFKD')
    .replace(/[^\x00-\x7F]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, maxLength)
    .replace(/-+$/g, '');
}

function makePublicId() {
  return `tkt_${crypto.randomBytes(8).toString('hex')}`;
}

function makeSecretToken() {
  return crypto.randomBytes(24).toString('hex');
}

function getPublicBaseUrl(req) {
  const configured = (process.env.PUBLIC_BASE_URL || '').trim().replace(/\/+$/g, '');
  if (configured) return configured;

  const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  const forwardedHost = String(req.headers['x-forwarded-host'] || '').split(',')[0].trim();
  const proto = forwardedProto || 'http';
  const host = forwardedHost || req.headers.host || `localhost:${PORT}`;
  return `${proto}://${host}`;
}

function normalizeReturnTo(value, req) {
  const fallback = `${getPublicBaseUrl(req)}/#checkout`;
  if (!value) return fallback;

  try {
    const target = new URL(value, getPublicBaseUrl(req));
    if (target.protocol === 'file:') return target.href;
    if (target.origin === getPublicBaseUrl(req)) return target.href;
    if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?/i.test(target.origin)) return target.href;

    const allowedOrigin = (process.env.DISCORD_ALLOWED_ORIGIN || '').trim();
    if (allowedOrigin && target.origin === allowedOrigin.replace(/\/+$/g, '')) return target.href;
  } catch {}

  return fallback;
}

function loadTickets() {
  if (!fs.existsSync(TICKET_STORE_FILE)) return {};
  try {
    const raw = fs.readFileSync(TICKET_STORE_FILE, 'utf8');
    return raw.trim() ? JSON.parse(raw) : {};
  } catch (err) {
    console.warn('Failed to load ticket store:', err.message);
    return {};
  }
}

function saveTickets() {
  try {
    fs.writeFileSync(TICKET_STORE_FILE, JSON.stringify(tickets, null, 2));
  } catch (err) {
    console.warn('Failed to save ticket store:', err.message);
  }
}

function cleanText(value, fallback) {
  const text = String(value || fallback || '')
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return text.slice(0, 120) || fallback;
}

function escapeMentions(value) {
  return String(value).replace(/@/g, '@\u200b');
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function clampNumber(value, min, max, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function safeJsonParse(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) return;
  const lines = fs.readFileSync(filePath, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim().replace(/^['"]|['"]$/g, '');
    if (key && process.env[key] === undefined) process.env[key] = value;
  }
}
