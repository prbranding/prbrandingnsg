import { getDatabase } from "@netlify/database";
import {
  randomBytes, randomUUID, createHash, scryptSync, timingSafeEqual
} from "node:crypto";

const WORKSPACE = "nsg-pr-branding-main";
const COOKIE = "__Host-nsg_session";
const SESSION_DAYS = 14;
const db = () => getDatabase();

function response(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...extraHeaders
    }
  });
}
function fail(message, status = 400) { return response({ ok: false, error: message }, status); }
async function bodyOf(req) {
  try { return await req.json(); } catch { return {}; }
}
function cookieValue(req, name) {
  const raw = req.headers.get("cookie") || "";
  const part = raw.split(";").map(x => x.trim()).find(x => x.startsWith(name + "="));
  return part ? decodeURIComponent(part.slice(name.length + 1)) : "";
}
function hashToken(token) {
  return createHash("sha256").update(token).digest("hex");
}
function passwordHash(password, salt) {
  return scryptSync(password, salt, 64).toString("hex");
}
function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ""));
  const bb = Buffer.from(String(b || ""));
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}
function cookie(token, maxAge = SESSION_DAYS * 86400) {
  return `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}
function clearCookie() {
  return `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}
function sameOrigin(req) {
  const origin = req.headers.get("origin");
  if (!origin) return true;
  try { return new URL(origin).origin === new URL(req.url).origin; } catch { return false; }
}
async function currentUser(req) {
  const token = cookieValue(req, COOKIE);
  if (!token) return null;
  const rows = await db().sql`
    SELECT u.id, u.email, u.role, u.profile, u.active
    FROM nsg_sessions s
    JOIN nsg_users u ON u.id = s.user_id
    WHERE s.token_hash = ${hashToken(token)}
      AND s.expires_at > NOW()
      AND u.active = TRUE
    LIMIT 1
  `;
  return rows[0] || null;
}
function publicUser(u) {
  return { id: u.id, email: u.email, role: u.role, profile: u.profile || {} };
}
async function requireUser(req) {
  const user = await currentUser(req);
  if (!user) throw Object.assign(new Error("Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại."), { status: 401 });
  return user;
}
async function requireAdmin(req) {
  const user = await requireUser(req);
  if (user.role !== "admin") throw Object.assign(new Error("Bạn không có quyền thực hiện thao tác này."), { status: 403 });
  return user;
}
async function setupAdmin(req) {
  const input = await bodyOf(req);
  const expected = process.env.NSG_SETUP_KEY || "";
  if (!expected) return fail("Chưa thiết lập biến NSG_SETUP_KEY trong Netlify Environment Variables.", 503);
  if (!safeEqual(input.setupKey, expected)) return fail("Mã khởi tạo không chính xác.", 403);
  const email = String(input.email || "").trim().toLowerCase();
  const password = String(input.password || "");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail("Email không hợp lệ.");
  if (password.length < 10) return fail("Mật khẩu phải có ít nhất 10 ký tự.");
  const count = await db().sql`SELECT COUNT(*)::int AS count FROM nsg_users`;
  if (Number(count[0]?.count || 0) > 0) return fail("Quản trị viên đầu tiên đã được tạo. Không thể khởi tạo lại.", 409);
  const id = randomUUID();
  const salt = randomBytes(16).toString("hex");
  await db().sql`
    INSERT INTO nsg_users (id,email,password_hash,password_salt,role,profile)
    VALUES (${id},${email},${passwordHash(password,salt)},${salt},'admin','{}'::jsonb)
  `;
  return response({ ok: true, message: "Đã tạo quản trị viên." });
}
async function login(req) {
  const input = await bodyOf(req);
  const email = String(input.email || "").trim().toLowerCase();
  const password = String(input.password || "");
  const rows = await db().sql`SELECT * FROM nsg_users WHERE email=${email} AND active=TRUE LIMIT 1`;
  const user = rows[0];
  if (!user || !safeEqual(passwordHash(password, user.password_salt), user.password_hash)) {
    return fail("Email hoặc mật khẩu không chính xác.", 401);
  }
  const token = randomBytes(32).toString("base64url");
  await db().sql`
    INSERT INTO nsg_sessions (token_hash,user_id,expires_at)
    VALUES (${hashToken(token)},${user.id},NOW() + (${SESSION_DAYS} * INTERVAL '1 day'))
  `;
  return response({ ok: true, user: publicUser(user) }, 200, { "Set-Cookie": cookie(token) });
}
async function logout(req) {
  const token = cookieValue(req, COOKIE);
  if (token) await db().sql`DELETE FROM nsg_sessions WHERE token_hash=${hashToken(token)}`;
  return response({ ok: true }, 200, { "Set-Cookie": clearCookie() });
}
async function snapshot(user) {
  const [records, metaRows, historyRows] = await Promise.all([
    db().sql`SELECT module,record_id,payload,version FROM nsg_records WHERE workspace=${WORKSPACE} ORDER BY module,record_id`,
    db().sql`SELECT payload FROM nsg_meta WHERE workspace=${WORKSPACE} AND meta_key='global' LIMIT 1`,
    db().sql`SELECT id,payload,created_at FROM nsg_audit WHERE workspace=${WORKSPACE} ORDER BY created_at DESC LIMIT 500`
  ]);
  const data = {}, versions = {};
  for (const row of records) {
    data[row.module] ||= [];
    versions[row.module] ||= {};
    data[row.module].push(row.payload);
    versions[row.module][row.record_id] = Number(row.version);
  }
  return response({
    ok: true, data, versions,
    meta: metaRows[0]?.payload || { logo: "", logs: [], shares: [] },
    history: historyRows.map(r => ({ ...r.payload, id: r.id })).reverse(),
    profile: user.profile || {},
    user: publicUser(user)
  });
}
async function sync(req, user) {
  const input = await bodyOf(req);
  const changes = Array.isArray(input.changes) ? input.changes : [];
  const deletes = Array.isArray(input.deletes) ? input.deletes : [];
  const history = Array.isArray(input.history) ? input.history : [];
  if (changes.length > 300 || deletes.length > 300 || history.length > 500) {
    return fail("Gói đồng bộ quá lớn. Vui lòng chia nhỏ dữ liệu.", 413);
  }
  const versions = {};
  for (const item of changes) {
    const module = String(item.module || "");
    const id = String(item.id || "");
    if (!/^[a-zA-Z0-9_-]{1,80}$/.test(module) || !id || id.length > 180 || !item.payload || typeof item.payload !== "object") {
      return fail("Bản ghi đồng bộ không hợp lệ.");
    }
    const payload = JSON.stringify(item.payload);
    let rows;
    if (item.expectedVersion == null) {
      rows = await db().sql`
        INSERT INTO nsg_records (workspace,module,record_id,payload,version,updated_by)
        VALUES (${WORKSPACE},${module},${id},${payload}::jsonb,1,${user.id})
        ON CONFLICT (workspace,module,record_id) DO NOTHING
        RETURNING version
      `;
    } else {
      rows = await db().sql`
        UPDATE nsg_records
        SET payload=${payload}::jsonb, version=version+1, updated_by=${user.id}, updated_at=NOW()
        WHERE workspace=${WORKSPACE} AND module=${module} AND record_id=${id} AND version=${Number(item.expectedVersion)}
        RETURNING version
      `;
    }
    if (!rows.length) return fail(`Bản ghi "${id}" vừa được cập nhật ở thiết bị khác. Hãy tải lại dữ liệu trước khi sửa tiếp.`, 409);
    versions[`${module}:${id}`] = Number(rows[0].version);
  }
  for (const item of deletes) {
    const module = String(item.module || ""), id = String(item.id || "");
    if (!module || !id || item.expectedVersion == null) continue;
    const rows = await db().sql`
      DELETE FROM nsg_records
      WHERE workspace=${WORKSPACE} AND module=${module} AND record_id=${id} AND version=${Number(item.expectedVersion)}
      RETURNING record_id
    `;
    if (!rows.length) return fail(`Bản ghi "${id}" đã thay đổi trên thiết bị khác; thao tác xóa chưa được áp dụng.`, 409);
  }
  if (input.meta && typeof input.meta === "object") {
    const meta = JSON.stringify(input.meta);
    await db().sql`
      INSERT INTO nsg_meta (workspace,meta_key,payload,updated_by)
      VALUES (${WORKSPACE},'global',${meta}::jsonb,${user.id})
      ON CONFLICT (workspace,meta_key)
      DO UPDATE SET payload=EXCLUDED.payload,updated_by=EXCLUDED.updated_by,updated_at=NOW()
    `;
  }
  if (input.profile && typeof input.profile === "object") {
    await db().sql`
      UPDATE nsg_users SET profile=${JSON.stringify(input.profile)}::jsonb,updated_at=NOW()
      WHERE id=${user.id}
    `;
  }
  for (const item of history) {
    const id = String(item.id || randomUUID());
    const payload = JSON.stringify({ ...item, id });
    await db().sql`
      INSERT INTO nsg_audit (id,workspace,actor_id,actor_email,payload)
      VALUES (${id},${WORKSPACE},${user.id},${user.email},${payload}::jsonb)
      ON CONFLICT (id) DO UPDATE SET payload=EXCLUDED.payload, actor_id=EXCLUDED.actor_id, actor_email=EXCLUDED.actor_email
    `;
  }
  return response({ ok: true, versions, savedAt: new Date().toISOString() });
}
async function createUser(req, admin) {
  const input = await bodyOf(req);
  const email = String(input.email || "").trim().toLowerCase();
  const password = String(input.password || "");
  const role = input.role === "admin" ? "admin" : "member";
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail("Email không hợp lệ.");
  if (password.length < 10) return fail("Mật khẩu phải có ít nhất 10 ký tự.");
  const id = randomUUID(), salt = randomBytes(16).toString("hex");
  try {
    await db().sql`
      INSERT INTO nsg_users (id,email,password_hash,password_salt,role)
      VALUES (${id},${email},${passwordHash(password,salt)},${salt},${role})
    `;
    return response({ ok: true, user: { id, email, role } });
  } catch (e) {
    if (String(e.message || "").toLowerCase().includes("unique")) return fail("Email này đã có tài khoản.", 409);
    throw e;
  }
}
async function listUsers(req) {
  const admin = await requireAdmin(req);
  const users = await db().sql`SELECT id,email,role,profile,active,created_at FROM nsg_users ORDER BY created_at`;
  return response({ ok: true, users });
}

export default async (request) => {
  try {
    const url = new URL(request.url);
    const action = url.searchParams.get("action") || "";
    if (!sameOrigin(request)) return fail("Yêu cầu không cùng nguồn.", 403);
    if (request.method === "OPTIONS") return new Response(null, { status: 204 });
    if (action === "setup" && request.method === "POST") return await setupAdmin(request);
    if (action === "login" && request.method === "POST") return await login(request);
    if (action === "logout" && request.method === "POST") return await logout(request);

    const user = await requireUser(request);
    if (action === "me" && request.method === "GET") return response({ ok: true, user: publicUser(user) });
    if (action === "snapshot" && request.method === "GET") return await snapshot(user);
    if (action === "sync" && request.method === "POST") return await sync(request, user);
    if (action === "create-user" && request.method === "POST") return await createUser(request, await requireAdmin(request));
    if (action === "users" && request.method === "GET") return await listUsers(request);
    return fail("Không tìm thấy API.", 404);
  } catch (error) {
    console.error("PR-Branding API error:", error);
    return fail(error.message || "Lỗi máy chủ.", error.status || 500);
  }
};
