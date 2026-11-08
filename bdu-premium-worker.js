// BDU PREMIUM — authentication helpers (Phase 1)
// Uses only Web Crypto, which is built into Cloudflare Workers.

const PBKDF2_ITERATIONS = 100000; // Cloudflare Workers caps PBKDF2 at 100k iterations
const SESSION_DAYS = 30;

const enc = new TextEncoder();

function toHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

async function pbkdf2(password, saltBytes, iterations) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: saltBytes, iterations, hash: 'SHA-256' },
    key,
    256
  );
  return toHex(bits);
}

// Stored format: pbkdf2$<iterations>$<saltHex>$<hashHex>
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
  return `pbkdf2$${PBKDF2_ITERATIONS}$${toHex(salt)}$${hash}`;
}

async function verifyPassword(password, stored) {
  const [scheme, iter, saltHex, expected] = stored.split('$');
  if (scheme !== 'pbkdf2') return false;
  const hash = await pbkdf2(password, fromHex(saltHex), Number(iter));
  // constant-time-ish comparison
  if (hash.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < hash.length; i++) diff |= hash.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

// Session tokens: the client gets a random token; the database stores only its SHA-256 hash.
async function createSession(db, userId) {
  const token = toHex(crypto.getRandomValues(new Uint8Array(32)));
  const tokenHash = await sha256Hex(token);
  const expires = new Date(Date.now() + SESSION_DAYS * 86400 * 1000).toISOString();
  await db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
    .bind(tokenHash, userId, expires).run();
  return token;
}

async function getUserFromRequest(db, request) {
  const auth = request.headers.get('Authorization') || '';
  const match = auth.match(/^Bearer\s+([a-f0-9]{64})$/i);
  if (!match) return null;
  const tokenHash = await sha256Hex(match[1]);
  const row = await db.prepare(
    `SELECT u.id, u.full_name, u.university, u.campus, u.phone, u.is_suspended, s.expires_at
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?`
  ).bind(tokenHash).first();
  if (!row) return null;
  if (new Date(row.expires_at) < new Date()) return null;
  if (row.is_suspended) return null;
  return { id: row.id, full_name: row.full_name, university: row.university, campus: row.campus, phone: row.phone };
}

  }
  if (!file || typeof file === 'string') return json({ ok: false, error: 'Attach a receipt image.' }, 400, cors);
  if (file.size === 0 || file.size > MAX_RECEIPT_BYTES) {
    return json({ ok: false, error: 'Receipt must be an image under 1 MB. Try a smaller screenshot.' }, 400, cors);
  }

  const bytes = new Uint8Array(await file.arrayBuffer());
  const type = detectImageType(bytes);
  if (!type) return json({ ok: false, error: 'Receipt must be a JPG, PNG or WEBP image.' }, 400, cors);

  const id = crypto.randomUUID();

  // Save the payment and its receipt together. If either fails, neither is saved.
  // The UNIQUE(method, reference) constraint blocks a transaction being used twice.
  try {
    await env.DB.batch([
      env.DB.prepare(
        'INSERT INTO payments (id, user_id, method, reference, receipt_key) VALUES (?, ?, ?, ?, ?)'
      ).bind(id, user.id, method, reference, `db:${id}`),
      env.DB.prepare(
        'INSERT INTO receipts (payment_id, mime, data_base64) VALUES (?, ?, ?)'
      ).bind(id, type.mime, bytesToBase64(bytes)),
    ]);
  } catch {
    return json({ ok: false, error: 'This transaction reference was already submitted.' }, 409, cors);
  }

  const payment = await env.DB.prepare('SELECT id, method, reference, created_at FROM payments WHERE id = ?')
    .bind(id).first();
  const student = await env.DB.prepare('SELECT full_name, university, campus, phone FROM users WHERE id = ?')
    .bind(user.id).first();

  // Tell admins. If Telegram is down, the payment is still saved and can be seen later.
  try {
    await sendPaymentReview(env, payment, student, new Blob([bytes], { type: type.mime }));
  } catch (err) {
    console.error('Telegram notify failed', err && err.message);
  }

  return json({ ok: true, payment: { id, status: 'pending' } }, 201, cors);
}

// GET /api/payment/status  — the app polls this to learn the decision
async function paymentStatus(env, cors, user) {
  if (!user) return json({ ok: false, error: 'Please log in first.' }, 401, cors);
  const row = await env.DB.prepare(
    'SELECT id, status, created_at, decided_at FROM payments WHERE user_id = ? ORDER BY created_at DESC LIMIT 1'
  ).bind(user.id).first();
  return json({ ok: true, payment: row ?? null }, 200, cors);
}

// POST /api/telegram/webhook  — Telegram calls this when an admin presses a button
async function telegramWebhook(request, env) {
  // Only requests carrying our secret header are accepted.
  if (request.headers.get('X-Telegram-Bot-Api-Secret-Token') !== env.TELEGRAM_WEBHOOK_SECRET) {
    return new Response('Forbidden', { status: 403 });
  }
  const update = await request.json().catch(() => null);
  const cb = update?.callback_query;
  if (!cb) return new Response('ok');

  if (!isAdmin(env, cb.from.id)) {
  return headers;
}

function json(data, status, cors) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...cors },
  });
}

// Never leak internal details to the client; log them server-side without personal data.
function fail(status, message, cors) {
  return json({ ok: false, error: message }, status, cors);
}

function clientIp(request) {
  return request.headers.get('CF-Connecting-IP') || 'unknown';
}

async function readJson(request) {
  try { return await request.json(); } catch { return null; }
}

// ---------- Auth ----------

async function signup(request, env, cors) {
  if (!await allowRequest(env.DB, `signup:${clientIp(request)}`, 5, 3600)) {
    return fail(429, 'Too many sign-up attempts. Try again later.', cors);
  }
  const body = await readJson(request);
  if (!body) return fail(400, 'Invalid request body.', cors);

  const fullName = String(body.full_name || '').trim();
  const university = String(body.university || '').trim();
  const campus = String(body.campus || '').trim();
  const phone = normalizePhone(body.phone);
  const password = String(body.password || '');
  const confirm = String(body.confirm_password || '');

  if (fullName.length < 3) return fail(400, 'Please enter your full name.', cors);
  if (!university || !campus) return fail(400, 'University and campus are required.', cors);
  if (!phone) return fail(400, 'Enter a valid Ethiopian phone number (e.g. 09XXXXXXXX).', cors);
  if (password.length < 8) return fail(400, 'Password must be at least 8 characters.', cors);
  if (password !== confirm) return fail(400, 'Passwords do not match.', cors);

  const existing = await env.DB.prepare('SELECT id FROM users WHERE phone = ?').bind(phone).first();
  if (existing) return fail(409, 'This phone number is already registered.', cors);

  const id = crypto.randomUUID();
  const passwordHash = await hashPassword(password);
  await env.DB.prepare(
    'INSERT INTO users (id, full_name, university, campus, phone, password_hash) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(id, fullName, university, campus, phone, passwordHash).run();
  await env.DB.prepare('INSERT INTO entitlements (user_id, premium) VALUES (?, 0)').bind(id).run();

  const token = await createSession(env.DB, id);
  return json({ ok: true, token, user: { id, full_name: fullName, phone } }, 201, cors);
}

async function login(request, env, cors) {
  if (!await allowRequest(env.DB, `login:${clientIp(request)}`, 10, 900)) {
    return fail(429, 'Too many login attempts. Try again in 15 minutes.', cors);
  }
    'SELECT id, full_name, password_hash, is_suspended FROM users WHERE phone = ?'
  ).bind(phone).first();
  // Same message whether the phone exists or not, to avoid account enumeration.
  if (!user || !(await verifyPassword(password, user.password_hash))) {
    return fail(401, 'Incorrect phone number or password.', cors);
  }
  if (user.is_suspended) return fail(403, 'This account is suspended. Contact support.', cors);

  const token = await createSession(env.DB, user.id);
  return json({ ok: true, token, user: { id: user.id, full_name: user.full_name, phone } }, 200, cors);
}

async function logout(request, env, cors) {
  await deleteSession(env.DB, request);
  return json({ ok: true }, 200, cors);
}

// ---------- Content (public reads, premium enforced server-side) ----------

async function getVersion(env, cors) {
  const row = await env.DB.prepare(
    'SELECT version, published_at FROM content_versions WHERE is_current = 1 ORDER BY id DESC LIMIT 1'
  ).first();
  return json({ ok: true, version: row?.version ?? '0', published_at: row?.published_at ?? null }, 200, cors);
}

async function getPrograms(env, cors) {
  const { results } = await env.DB.prepare('SELECT id, name FROM programs ORDER BY sort_order').all();
  return json({ ok: true, programs: results }, 200, cors);
}

async function getCourses(url, env, cors) {
  const semesterId = url.searchParams.get('semester');
  if (!semesterId) return fail(400, 'Missing semester parameter.', cors);
  const { results } = await env.DB.prepare(
    'SELECT id, name FROM courses WHERE semester_id = ? ORDER BY sort_order'
  ).bind(semesterId).all();
  return json({ ok: true, courses: results }, 200, cors);
}

async function getChapters(url, env, cors, user) {
  const courseId = url.searchParams.get('course');
  if (!courseId) return fail(400, 'Missing course parameter.', cors);
  const premium = user ? await hasPremium(env.DB, user.id) : false;
  const { results } = await env.DB.prepare(
    'SELECT id, number, title, is_free FROM chapters WHERE course_id = ? ORDER BY sort_order, number'
  ).bind(courseId).all();
  // Locked chapters are flagged; their content is never sent to non-premium users.
  const chapters = results.map((c) => ({
    ...c,
    locked: !c.is_free && !premium,
  }));
  return json({ ok: true, chapters }, 200, cors);
}

async function getNotes(url, env, cors, user) {
  const chapterId = url.searchParams.get('chapter');
  if (!chapterId) return fail(400, 'Missing chapter parameter.', cors);
  const chapter = await env.DB.prepare('SELECT id, is_free FROM chapters WHERE id = ?')
    .bind(chapterId).first();
  if (!chapter) return fail(404, 'Chapter not found.', cors);

  // The real gate: a locked chapter returns 402 without its content, regardless of what the UI shows.
  if (!chapter.is_free) {
    if (!user) return fail(401, 'Please log in to read this note.', cors);
    if (!(await hasPremium(env.DB, user.id))) {
      return fail(402, 'This chapter requires premium access.', cors);
    }
  }
  const note = await env.DB.prepare('SELECT body_html, updated_at FROM notes WHERE chapter_id = ?')
    .bind(chapterId).first();
  return json({ ok: true, note: note ?? { body_html: '', updated_at: null } }, 200, cors);
}

// ---------- Premium ----------

async function hasPremium(db, userId) {
  const row = await db.prepare('SELECT premium FROM entitlements WHERE user_id = ?').bind(userId).first();
  return row?.premium === 1;
}

async function premiumStatus(env, cors, user) {
  if (!user) return json({ ok: true, authenticated: false, premium: false }, 200, cors);
  return json({ ok: true, authenticated: true, premium: await hasPremium(env.DB, user.id) }, 200, cors);
}

// ---------- Router ----------

export default {
  async fetch(request, env) {
    const cors = corsHeaders(request, env);
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

    try {
      const path = url.pathname;
      const isGet = request.method === 'GET';
      const isPost = request.method === 'POST';

      // Auth
      // NOTE: every handler is "await"-ed so that errors reach the catch block below.
      if (isPost && path === '/api/auth/signup') return await signup(request, env, cors);
      if (isPost && path === '/api/auth/login') return await login(request, env, cors);
      if (isPost && path === '/api/auth/logout') return await logout(request, env, cors);

      // Public content
      if (isGet && path === '/api/version') return await getVersion(env, cors);
      if (isGet && path === '/api/programs') return await getPrograms(env, cors);

      // Telegram calls this directly. It is protected by its own secret header, not a login token.
      if (isPost && path === '/api/telegram/webhook') return await telegramWebhook(request, env);

      // Routes below use the logged-in user if a valid token is sent (optional for reads).
      const user = await getUserFromRequest(env.DB, request);

      // Payments (login required)
      if (isPost && path === '/api/receipt') return await submitReceipt(request, env, cors, user);
      if (isGet && path === '/api/payment/status') return await paymentStatus(env, cors, user);

      if (isGet && path === '/api/courses') return await getCourses(url, env, cors);
      if (isGet && path === '/api/chapters') return await getChapters(url, env, cors, user);
      if (isGet && path === '/api/notes') return await getNotes(url, env, cors, user);
      if (isGet && path === '/api/premium/status') return await premiumStatus(env, cors, user);

      return fail(404, 'Not found.', cors);
    } catch (err) {
      // Log the error for the developer; send the student a generic message.
      console.error('Unhandled error', err && err.message);
      return fail(500, 'Something went wrong. Please try again.', cors);
    }
  },
};
