
import { neon } from "@neondatabase/serverless";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const sql = neon(process.env.DATABASE_URL || "");

function send(res, status, data) {
  res.status(status).json(data);
}

function bodyOf(req) {
  if (typeof req.body === "string") {
    try { return JSON.parse(req.body); } catch { return {}; }
  }
  return req.body || {};
}

function getToken(req) {
  const header = req.headers.authorization || "";
  return header.startsWith("Bearer ") ? header.slice(7) : "";
}

function verifyUser(req) {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.length < 32) throw new Error("تنظیم JWT_SECRET در Vercel درست نیست.");
  const token = getToken(req);
  if (!token) throw new Error("ابتدا وارد حساب شوید.");
  try {
    return jwt.verify(token, secret);
  } catch {
    throw new Error("نشست شما پایان یافته است؛ دوباره وارد شوید.");
  }
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export default async function handler(req, res) {
  const origin = req.headers.origin;
  const allowed = process.env.ALLOWED_ORIGIN;

  if (origin && (!allowed || origin === allowed)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }

  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");

  if (req.method === "OPTIONS") return res.status(204).end();

  if (!process.env.DATABASE_URL) {
    return send(res, 500, { error: "DATABASE_URL تنظیم نشده است." });
  }

  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
    return send(res, 500, { error: "JWT_SECRET باید حداقل ۳۲ حرف باشد." });
  }
const routePath = Array.isArray(req.query?.path)
  ? req.query.path.join("/")
  : String(req.query?.path || "");

const path = routePath
  ? (routePath.startsWith("/api/") ? routePath : "/api/" + routePath).replace(/\/+$/, "")
  : (req.url || "/").split("?")[0].replace(/\/+$/, "");
  const body = bodyOf(req);

  try {
    // بررسی اتصال API و دیتابیس
    if (path === "/api/health" && req.method === "GET") {
      await sql`SELECT 1`;
      return send(res, 200, {
        ok: true,
        app: "Afghan App Store",
        database: "connected"
      });
    }

    // ساخت اولین مدیر فروشگاه
    if (path === "/api/setup-admin" && req.method === "POST") {
      if (!process.env.ADMIN_SETUP_SECRET) {
        return send(res, 503, { error: "ADMIN_SETUP_SECRET تنظیم نشده است." });
      }

      if (body.secret !== process.env.ADMIN_SETUP_SECRET) {
        return send(res, 403, { error: "رمز راه‌اندازی مدیر اشتباه است." });
      }

      const name = String(body.name || "").trim();
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");

      if (!name || !validEmail(email) || password.length < 10) {
        return send(res, 400, {
          error: "نام، ایمیل معتبر و رمز حداقل ۱۰ حرفی لازم است."
        });
      }

      const existing = await sql`
        SELECT id FROM users WHERE role = 'admin' LIMIT 1
      `;

      if (existing.length) {
        return send(res, 409, { error: "مدیر قبلاً ساخته شده است." });
      }

      const hash = await bcrypt.hash(password, 12);

      await sql`
        INSERT INTO users (name, email, password_hash, role)
        VALUES (${name}, ${email}, ${hash}, 'admin')
      `;

      return send(res, 201, { ok: true, message: "حساب مدیر ساخته شد." });
    }

    // ثبت‌نام کاربر
    if (path === "/api/register" && req.method === "POST") {
      const name = String(body.name || "").trim();
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");

      if (!name || name.length > 80 || !validEmail(email) || password.length < 8) {
        return send(res, 400, {
          error: "نام، ایمیل معتبر و رمز حداقل ۸ حرفی وارد کنید."
        });
      }

      const hash = await bcrypt.hash(password, 12);

      const rows = await sql`
        INSERT INTO users (name, email, password_hash)
        VALUES (${name}, ${email}, ${hash})
        ON CONFLICT (email) DO NOTHING
        RETURNING id, name, email, role
      `;

      if (!rows.length) {
        return send(res, 409, { error: "این ایمیل قبلاً ثبت شده است." });
      }

      const user = rows[0];
      const token = jwt.sign(
        { id: user.id, role: user.role, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: "30d" }
      );

      return send(res, 201, { ok: true, token, user });
    }

    // ورود کاربر
    if (path === "/api/login" && req.method === "POST") {
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");

      const rows = await sql`
        SELECT id, name, email, password_hash, role
        FROM users WHERE email = ${email} LIMIT 1
      `;

      if (!rows.length || !(await bcrypt.compare(password, rows[0].password_hash))) {
        return send(res, 401, { error: "ایمیل یا رمز عبور اشتباه است." });
      }

      const user = rows[0];
      const token = jwt.sign(
        { id: user.id, role: user.role, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: "30d" }
      );

      return send(res, 200, {
        ok: true,
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role
        }
      });
    }

    // اطلاعات حساب فعلی
    if (path === "/api/me" && req.method === "GET") {
      const auth = verifyUser(req);
      const rows = await sql`
        SELECT id, name, email, role, created_at
        FROM users WHERE id = ${auth.id} LIMIT 1
      `;

      if (!rows.length) return send(res, 404, { error: "کاربر پیدا نشد." });
      return send(res, 200, { user: rows[0] });
    }

    // فهرست برنامه‌های تأییدشده
    if (path === "/api/apps" && req.method === "GET") {
      const q = String(req.query?.q || "").trim().slice(0, 100);
      const category = String(req.query?.category || "").trim().slice(0, 50);
      const search = `%${q}%`;

      let apps;

      if (q && category) {
        apps = await sql`
          SELECT id, name, package_name, category, version,
                 description, icon_url, price, currency, downloads
          FROM apps
          WHERE status = 'approved'
            AND category ILIKE ${category}
            AND (name ILIKE ${search} OR description ILIKE ${search})
          ORDER BY created_at DESC LIMIT 100
        `;
      } else if (q) {
        apps = await sql`
          SELECT id, name, package_name, category, version,
                 description, icon_url, price, currency, downloads
          FROM apps
          WHERE status = 'approved'
            AND (name ILIKE ${search} OR description ILIKE ${search})
          ORDER BY created_at DESC LIMIT 100
        `;
      } else if (category) {
        apps = await sql`
          SELECT id, name, package_name, category, version,
                 description, icon_url, price, currency, downloads
          FROM apps
          WHERE status = 'approved' AND category ILIKE ${category}
          ORDER BY created_at DESC LIMIT 100
        `;
      } else {
        apps = await sql`
          SELECT id, name, package_name, category, version,
                 description, icon_url, price, currency, downloads
          FROM apps
          WHERE status = 'approved'
          ORDER BY created_at DESC LIMIT 100
        `;
      }

      return send(res, 200, { apps });
    }

    // جزئیات یک برنامه
    const detailMatch = path.match(/^\/api\/apps\/(\d+)$/);
    if (detailMatch && req.method === "GET") {
      const id = Number(detailMatch[1]);
      const rows = await sql`
        SELECT id, name, package_name, category, version,
               description, icon_url, price, currency, downloads
        FROM apps WHERE id = ${id} AND status = 'approved'
        LIMIT 1
      `;

      if (!rows.length) return send(res, 404, { error: "برنامه پیدا نشد." });
      return send(res, 200, { app: rows[0] });
    }

    // ارسال برنامه توسط توسعه‌دهنده
    if (path === "/api/developer/app" && req.method === "POST") {
      const user = verifyUser(req);

      const name = String(body.name || "").trim();
      const packageName = String(body.package_name || "").trim();
      const category = String(body.category || "").trim();
      const version = String(body.version || "").trim();
      const description = String(body.description || "").trim();
      const iconUrl = String(body.icon_url || "").trim() || null;
      const fileUrl = String(body.file_url || "").trim();
      const price = Number(body.price || 0);

      const packagePattern = /^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$/;

      let file;
      try { file = new URL(fileUrl); } catch {}

      if (!name || name.length > 100 ||
          !packagePattern.test(packageName) ||
          !category || category.length > 50 ||
          !version || version.length > 40 ||
          !description || !file || file.protocol !== "https:" ||
          !Number.isFinite(price) || price < 0) {
        return send(res, 400, { error: "اطلاعات برنامه درست نیست. لینک دانلود باید HTTPS باشد." });
      }

      if (iconUrl) {
        try {
          if (new URL(iconUrl).protocol !== "https:") throw new Error();
        } catch {
          return send(res, 400, { error: "لینک آیکون باید HTTPS باشد." });
        }
      }

      const rows = await sql`
        INSERT INTO apps
          (developer_id, name, package_name, category, version,
           description, icon_url, file_url, price, currency)
        VALUES
          (${user.id}, ${name}, ${packageName}, ${category}, ${version},
           ${description}, ${iconUrl}, ${fileUrl}, ${price}, 'USD')
        RETURNING id, name, status
      `;

      return send(res, 201, {
        ok: true,
        message: "برنامه برای بررسی ارسال شد.",
        app: rows[0]
      });
    }

    // برنامه‌های توسعه‌دهنده
    if (path === "/api/developer/apps" && req.method === "GET") {
      const user = verifyUser(req);
      const apps = await sql`
        SELECT id, name, version, category, status, review_note,
               price, currency, downloads, created_at
        FROM apps
        WHERE developer_id = ${user.id}
        ORDER BY created_at DESC LIMIT 100
      `;
      return send(res, 200, { apps });
    }

    // فهرست برنامه‌های در انتظار تأیید مدیر
    if (path === "/api/admin/pending" && req.method === "GET") {
      const user = verifyUser(req);
      if (user.role !== "admin") return send(res, 403, { error: "دسترسی مدیر لازم است." });

      const apps = await sql`
        SELECT apps.*, users.name AS developer_name, users.email AS developer_email
        FROM apps
        JOIN users ON users.id = apps.developer_id
        WHERE apps.status = 'pending'
        ORDER BY apps.created_at ASC LIMIT 100
      `;

      return send(res, 200, { apps });
    }

    // تأیید یا رد برنامه
    if (path === "/api/admin/review" && req.method === "POST") {
      const user = verifyUser(req);
      if (user.role !== "admin") return send(res, 403, { error: "دسترسی مدیر لازم است." });

      const appId = Number(body.app_id);
      const status = String(body.status || "");
      const note = String(body.review_note || "").slice(0, 1000);

      if (!Number.isInteger(appId) || appId < 1 ||
          !["approved", "rejected"].includes(status)) {
        return send(res, 400, { error: "اطلاعات بررسی درست نیست." });
      }

      const rows = await sql`
        UPDATE apps
        SET status = ${status},
            review_note = ${note},
            updated_at = NOW()
        WHERE id = ${appId} AND status = 'pending'
        RETURNING id, name, status
      `;

      if (!rows.length) return send(res, 404, { error: "برنامه در انتظار بررسی پیدا نشد." });
      return send(res, 200, { ok: true, app: rows[0] });
    }

    // دانلود برنامه رایگان
    const downloadMatch = path.match(/^\/api\/apps\/(\d+)\/download$/);
    if (downloadMatch && req.method === "POST") {
      const user = verifyUser(req);
      const appId = Number(downloadMatch[1]);

      const rows = await sql`
        SELECT id, name, file_url, price
        FROM apps
        WHERE id = ${appId} AND status = 'approved'
        LIMIT 1
      `;

      if (!rows.length) return send(res, 404, { error: "برنامه پیدا نشد." });

      const app = rows[0];

      if (Number(app.price) > 0) {
        return send(res, 402, {
          error: "این برنامه پولی است. پرداخت آنلاین هنوز فعال نشده است."
        });
      }

      await sql`
        INSERT INTO downloads (user_id, app_id)
        VALUES (${user.id}, ${appId})
      `;

      await sql`
        UPDATE apps SET downloads = downloads + 1
        WHERE id = ${appId}
      `;

      return send(res, 200, {
        ok: true,
        download_url: app.file_url
      });
    }

    return send(res, 404, { error: "Endpoint not found" });

  } catch (error) {
    console.error("Afghan App Store API error:", error);

    const message = error.message || "خطای سرور";
    const status = message.includes("ابتدا وارد") ||
                   message.includes("نشست شما") ? 401 : 500;

    return send(res, status, { error: message });
  }
}
