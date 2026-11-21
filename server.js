require("dotenv").config();
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const mysql = require("mysql2/promise");
const { authenticator } = require("otplib");
const QRCode = require("qrcode");

const required = ["HOST", "PORT", "TAX_RATE", "SESSION_SECRET", "DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME", "LOG_URL", "LOG_TOKEN"];
for (const key of required) {
  if (!process.env[key]) {
    console.error("Missing " + key);
    process.exit(1);
  }
}

authenticator.options = { window: 1 };
const taxRate = Number(process.env.TAX_RATE);
if (!Number.isFinite(taxRate) || taxRate < 0) {
  console.error("TAX_RATE is invalid");
  process.exit(1);
}

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
});

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "32kb" }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { httpOnly: true, sameSite: "lax", secure: false },
}));

function audit(req, access, action) {
  const who = req.session.userId ? String(req.session.userId) : "guest";
  const url = process.env.LOG_URL.replace(/\/$/, "") + "/logs";
  fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Log-Token": process.env.LOG_TOKEN },
    body: JSON.stringify({ who, access, action, time: new Date().toISOString() }),
  }).catch((err) => {
    console.error("audit failed", err.message);
  });
}

function cartOf(req) {
  if (!Array.isArray(req.session.cart)) req.session.cart = [];
  return req.session.cart;
}

function requireUser(req, res) {
  if (!req.session.userId) {
    res.status(401).json({ success: false, message: "Sign in required." });
    return false;
  }
  return true;
}

function isEmail(value) {
  return typeof value === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) && value.length <= 255;
}

function publicUser(row) {
  return {
    name: row.name,
    email: row.email,
    street: row.street || "",
    apartment: row.apartment || "",
    city: row.city || "",
    state: row.state || "",
    zip: row.zip || "",
    phone: row.phone || "",
  };
}

async function findUser(id) {
  const [rows] = await pool.query(
    "SELECT id, name, email, password_hash, street, apartment, city, state, zip, phone, mfa_secret, mfa_enabled FROM users WHERE id = ?",
    [id]
  );
  return rows[0] || null;
}

async function setupPayload(user) {
  const otpauth = authenticator.keyuri(user.email, "Critter Kingdom", user.mfa_secret);
  const qrCode = await QRCode.toDataURL(otpauth);
  return { qrCode, secret: user.mfa_secret };
}

function cardBrand(digits) {
  if (digits.startsWith("4")) return "Visa";
  if (digits.startsWith("5")) return "Mastercard";
  if (digits.startsWith("34") || digits.startsWith("37")) return "Amex";
  if (digits.startsWith("6")) return "Discover";
  return "Card";
}

async function loadCart(req) {
  const cart = cartOf(req).filter((item) => Number.isInteger(item.id) && item.quantity >= 1 && item.quantity <= 20);
  req.session.cart = cart;
  if (!cart.length) {
    return { items: [], totals: { subtotal: 0, tax: 0, total: 0 }, count: 0 };
  }
  const ids = cart.map((item) => item.id);
  const [rows] = await pool.query(
    "SELECT id, name, description, price, image_path FROM products WHERE id IN (?)",
    [ids]
  );
  const byId = new Map(rows.map((row) => [row.id, row]));
  const items = [];
  let subtotal = 0;
  let count = 0;
  for (const item of cart) {
    const product = byId.get(item.id);
    if (!product) continue;
    const price = Number(product.price);
    items.push({
      quantity: item.quantity,
      product: {
        id: product.id,
        B_name: product.name,
        B_desc: product.description,
        B_price: price,
        B_img: product.image_path,
      },
    });
    subtotal += price * item.quantity;
    count += item.quantity;
  }
  const tax = Math.round(subtotal * taxRate * 100) / 100;
  const total = Math.round((subtotal + tax) * 100) / 100;
  return { items, totals: { subtotal, tax, total }, count };
}

app.post("/B_register", async (req, res) => {
  audit(req, "write", "B_register");
  const name = typeof req.body.name === "string" ? req.body.name.trim() : "";
  const email = typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = typeof req.body.password === "string" ? req.body.password : "";
  if (!name || name.length > 100 || !isEmail(email) || password.length < 6 || password.length > 200) {
    res.json({ success: false, message: "Check your name, email, and password." });
    return;
  }
  try {
    const secret = authenticator.generateSecret();
    const hash = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      "INSERT INTO users (name, email, password_hash, mfa_secret, mfa_enabled) VALUES (?, ?, ?, ?, 0)",
      [name, email, hash, secret]
    );
    req.session.userId = null;
    req.session.pendingUserId = result.insertId;
    req.session.pendingPurpose = "setup";
    const user = await findUser(result.insertId);
    const setup = await setupPayload(user);
    res.json({ success: true, qrCode: setup.qrCode, secret: setup.secret });
  } catch (err) {
    if (err && err.code === "ER_DUP_ENTRY") {
      res.json({ success: false, message: "An account with that email already exists." });
      return;
    }
    console.error(err);
    res.status(500).json({ success: false, message: "Could not create the account." });
  }
});

app.post("/B_mfa_setup", async (req, res) => {
  audit(req, "write", "B_mfa_setup");
  const code = typeof req.body.code === "string" ? req.body.code.trim() : "";
  if (!/^\d{6}$/.test(code) || req.session.pendingPurpose !== "setup" || !req.session.pendingUserId) {
    res.json({ success: false, message: "Enter the 6-digit code from your authenticator app." });
    return;
  }
  const user = await findUser(req.session.pendingUserId);
  if (!user || !authenticator.check(code, user.mfa_secret)) {
    res.json({ success: false, message: "That code was not accepted." });
    return;
  }
  await pool.query("UPDATE users SET mfa_enabled = 1 WHERE id = ?", [user.id]);
  req.session.userId = user.id;
  req.session.pendingUserId = null;
  req.session.pendingPurpose = null;
  res.json({ success: true, user: publicUser(user) });
});

app.post("/B_login", async (req, res) => {
  audit(req, "write", "B_login");
  const email = typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = typeof req.body.password === "string" ? req.body.password : "";
  const [rows] = await pool.query(
    "SELECT id, name, email, password_hash, street, apartment, city, state, zip, phone, mfa_secret, mfa_enabled FROM users WHERE email = ?",
    [email]
  );
  const user = rows[0];
  const matches = user ? await bcrypt.compare(password, user.password_hash) : false;
  if (!user || !matches) {
    res.json({ success: false, message: "Invalid email or password." });
    return;
  }
  req.session.userId = null;
  req.session.pendingUserId = user.id;
  if (!user.mfa_enabled) {
    req.session.pendingPurpose = "setup";
    const setup = await setupPayload(user);
    res.json({ success: true, mfaSetup: true, qrCode: setup.qrCode, secret: setup.secret });
    return;
  }
  req.session.pendingPurpose = "login";
  res.json({ success: true, mfaRequired: true });
});

app.post("/B_mfa_verify", async (req, res) => {
  audit(req, "write", "B_mfa_verify");
  const code = typeof req.body.code === "string" ? req.body.code.trim() : "";
  if (!/^\d{6}$/.test(code) || req.session.pendingPurpose !== "login" || !req.session.pendingUserId) {
    res.json({ success: false, message: "Enter the 6-digit code from your authenticator app." });
    return;
  }
  const user = await findUser(req.session.pendingUserId);
  if (!user || !user.mfa_enabled || !authenticator.check(code, user.mfa_secret)) {
    res.json({ success: false, message: "That code was not accepted." });
    return;
  }
  req.session.userId = user.id;
  req.session.pendingUserId = null;
  req.session.pendingPurpose = null;
  res.json({ success: true, user: publicUser(user) });
});

app.get("/B_session", async (req, res) => {
  audit(req, "read", "B_session");
  if (!req.session.userId) {
    res.json({ user: null });
    return;
  }
  const user = await findUser(req.session.userId);
  res.json({ user: user ? publicUser(user) : null });
});

app.post("/B_logout", (req, res) => {
  audit(req, "write", "B_logout");
  const cart = cartOf(req);
  req.session.userId = null;
  req.session.pendingUserId = null;
  req.session.pendingPurpose = null;
  req.session.pendingSecret = null;
  req.session.cart = cart;
  res.json({ success: true });
});

app.get("/B_account", async (req, res) => {
  audit(req, "read", "B_account");
  if (!requireUser(req, res)) return;
  const user = await findUser(req.session.userId);
  if (!user) {
    res.status(401).json({ success: false, message: "Sign in required." });
    return;
  }
  res.json({ user: publicUser(user) });
});

app.put("/B_account", async (req, res) => {
  audit(req, "write", "B_account");
  if (!requireUser(req, res)) return;
  const user = await findUser(req.session.userId);
  if (!user) {
    res.status(401).json({ success: false, message: "Sign in required." });
    return;
  }
  const body = req.body || {};
  const changingSecret = body.email !== undefined || body.password !== undefined;
  if (changingSecret) {
    const current = typeof body.currentPassword === "string" ? body.currentPassword : "";
    if (!await bcrypt.compare(current, user.password_hash)) {
      res.json({ success: false, message: "Current password is incorrect." });
      return;
    }
  }
  if (body.email !== undefined) {
    const email = String(body.email).trim().toLowerCase();
    if (!isEmail(email)) {
      res.json({ success: false, message: "Enter a valid email." });
      return;
    }
    try {
      await pool.query("UPDATE users SET email = ? WHERE id = ?", [email, user.id]);
    } catch (err) {
      if (err && err.code === "ER_DUP_ENTRY") {
        res.json({ success: false, message: "An account with that email already exists." });
        return;
      }
      throw err;
    }
  }
  if (body.password !== undefined) {
    const password = String(body.password);
    if (password.length < 6 || password.length > 200) {
      res.json({ success: false, message: "Password must be at least 6 characters." });
      return;
    }
    const hash = await bcrypt.hash(password, 10);
    await pool.query("UPDATE users SET password_hash = ? WHERE id = ?", [hash, user.id]);
  }
  const fields = ["street", "apartment", "city", "state", "zip", "phone"];
  const updates = [];
  const values = [];
  for (const field of fields) {
    if (body[field] !== undefined) {
      updates.push(field + " = ?");
      values.push(String(body[field]).slice(0, 255));
    }
  }
  if (updates.length) {
    values.push(user.id);
    await pool.query("UPDATE users SET " + updates.join(", ") + " WHERE id = ?", values);
  }
  const fresh = await findUser(user.id);
  res.json({ success: true, user: publicUser(fresh) });
});

app.post("/B_mfa_reset", async (req, res) => {
  audit(req, "write", "B_mfa_reset");
  if (!requireUser(req, res)) return;
  const user = await findUser(req.session.userId);
  const secret = authenticator.generateSecret();
  req.session.pendingSecret = secret;
  const otpauth = authenticator.keyuri(user.email, "Critter Kingdom", secret);
  const qrCode = await QRCode.toDataURL(otpauth);
  res.json({ success: true, qrCode, secret });
});

app.post("/B_mfa_reset_confirm", async (req, res) => {
  audit(req, "write", "B_mfa_reset_confirm");
  if (!requireUser(req, res)) return;
  const code = typeof req.body.code === "string" ? req.body.code.trim() : "";
  const currentCode = typeof req.body.currentCode === "string" ? req.body.currentCode.trim() : "";
  const user = await findUser(req.session.userId);
  if (!req.session.pendingSecret || !/^\d{6}$/.test(code) || !/^\d{6}$/.test(currentCode)) {
    res.json({ success: false, message: "Enter both 6-digit codes." });
    return;
  }
  if (!authenticator.check(currentCode, user.mfa_secret) || !authenticator.check(code, req.session.pendingSecret)) {
    res.json({ success: false, message: "Those codes were not accepted." });
    return;
  }
  await pool.query("UPDATE users SET mfa_secret = ?, mfa_enabled = 1 WHERE id = ?", [req.session.pendingSecret, user.id]);
  req.session.pendingSecret = null;
  res.json({ success: true });
});

app.get("/B_getproducts", async (req, res) => {
  audit(req, "read", "B_getproducts");
  const name = typeof req.query.name === "string" ? req.query.name.trim().slice(0, 40) : "";
  let rows;
  if (name) {
    const like = "%" + name.replace(/[\\%_]/g, (ch) => "\\" + ch) + "%";
    [rows] = await pool.query(
      "SELECT id, name, description, price, image_path FROM products WHERE name LIKE ? ESCAPE '\\\\' ORDER BY name",
      [like]
    );
  } else {
    [rows] = await pool.query("SELECT id, name, description, price, image_path FROM products ORDER BY name");
  }
  res.json({
    products: rows.map((row) => ({
      id: row.id,
      B_name: row.name,
      B_desc: row.description,
      B_price: Number(row.price),
      B_img: row.image_path,
    })),
  });
});

app.get("/B_getcartcount", async (req, res) => {
  audit(req, "read", "B_getcartcount");
  const cart = await loadCart(req);
  res.json({ count: cart.count });
});

app.get("/B_getcartitems", async (req, res) => {
  audit(req, "read", "B_getcartitems");
  const cart = await loadCart(req);
  res.json({ items: cart.items, totals: cart.totals });
});

app.post("/B_addtocart", async (req, res) => {
  audit(req, "write", "B_addtocart");
  const id = Number(req.body && req.body.id);
  const quantity = Number(req.body && req.body.quantity);
  if (!Number.isInteger(id) || !Number.isInteger(quantity) || quantity < 1 || quantity > 20) {
    res.status(400).json({ success: false, message: "Choose a quantity from 1 to 20." });
    return;
  }
  const [rows] = await pool.query("SELECT id FROM products WHERE id = ?", [id]);
  if (!rows.length) {
    res.status(404).json({ success: false, message: "That animal is not available." });
    return;
  }
  const cart = cartOf(req);
  const existing = cart.find((item) => item.id === id);
  if (existing) existing.quantity = Math.min(20, existing.quantity + quantity);
  else cart.push({ id, quantity: Math.min(20, quantity) });
  res.json({ success: true });
});

app.put("/B_updateQuantity", (req, res) => {
  audit(req, "write", "B_updateQuantity");
  const id = Number(req.body && req.body.id);
  const quantity = Number(req.body && req.body.quantity);
  if (!Number.isInteger(id) || !Number.isInteger(quantity) || quantity < 1 || quantity > 20) {
    res.status(400).json({ success: false, message: "Choose a quantity from 1 to 20." });
    return;
  }
  const item = cartOf(req).find((entry) => entry.id === id);
  if (item) item.quantity = quantity;
  res.json({ success: true });
});

app.delete("/B_removefromcart", (req, res) => {
  audit(req, "write", "B_removefromcart");
  const id = Number(req.body && req.body.id);
  req.session.cart = cartOf(req).filter((item) => item.id !== id);
  res.json({ success: true });
});

app.get("/B_getcards", async (req, res) => {
  audit(req, "read", "B_getcards");
  if (!requireUser(req, res)) return;
  const [rows] = await pool.query(
    "SELECT id, brand, last4, expiry FROM saved_cards WHERE user_id = ? ORDER BY id DESC",
    [req.session.userId]
  );
  res.json({ cards: rows });
});

app.delete("/B_removecard", async (req, res) => {
  audit(req, "write", "B_removecard");
  if (!requireUser(req, res)) return;
  const id = Number(req.body && req.body.id);
  await pool.query("DELETE FROM saved_cards WHERE id = ? AND user_id = ?", [id, req.session.userId]);
  res.json({ success: true });
});

app.get("/B_getorders", async (req, res) => {
  audit(req, "read", "B_getorders");
  if (!requireUser(req, res)) return;
  const params = [req.session.userId];
  let sql = "SELECT id, email, total, payment_method, card_brand, card_last4, created_at FROM orders WHERE user_id = ?";
  if (req.query.id !== undefined) {
    sql += " AND id = ?";
    params.push(Number(req.query.id));
  }
  sql += " ORDER BY created_at DESC, id DESC";
  const [orders] = await pool.query(sql, params);
  const result = [];
  for (const order of orders) {
    const [items] = await pool.query(
      "SELECT product_name AS name, quantity FROM order_items WHERE order_id = ?",
      [order.id]
    );
    result.push({
      id: order.id,
      email: order.email,
      total: Number(order.total),
      createdAt: new Date(order.created_at).toISOString(),
      items,
      payment: {
        method: order.payment_method,
        last4: order.card_last4 || "",
      },
    });
  }
  res.json({ orders: result });
});

app.post("/B_checkout", async (req, res) => {
  audit(req, "write", "B_checkout");
  if (!requireUser(req, res)) return;
  const info = req.body && req.body.customerInfo;
  if (!info || typeof info !== "object") {
    res.status(400).json({ success: false, message: "Missing checkout details." });
    return;
  }
  const cart = await loadCart(req);
  if (!cart.items.length) {
    res.status(400).json({ success: false, message: "Your cart is empty." });
    return;
  }
  const email = typeof info.email === "string" ? info.email.trim() : "";
  if (!isEmail(email)) {
    res.status(400).json({ success: false, message: "Enter a valid email." });
    return;
  }
  let cardBrandName = null;
  let last4 = null;
  const method = info.paymentMethod === "paypal" ? "paypal" : "card";
  if (method === "card") {
    if (info.savedCardId !== undefined) {
      const [cards] = await pool.query(
        "SELECT brand, last4 FROM saved_cards WHERE id = ? AND user_id = ?",
        [Number(info.savedCardId), req.session.userId]
      );
      if (!cards.length) {
        res.status(400).json({ success: false, message: "That saved card is not on your account." });
        return;
      }
      cardBrandName = cards[0].brand;
      last4 = cards[0].last4;
    } else {
      const digits = String(info.cardNumber || "").replace(/\D/g, "");
      const expiry = String(info.expiry || "").replace(/\s/g, "");
      const cvv = String(info.cvv || "");
      if (digits.length < 13 || digits.length > 19 || !/^\d{2}\/\d{2}$/.test(expiry) || !/^\d{3,4}$/.test(cvv)) {
        res.status(400).json({ success: false, message: "Enter a valid card number, expiration, and security code." });
        return;
      }
      cardBrandName = cardBrand(digits);
      last4 = digits.slice(-4);
      if (info.saveCard === true) {
        await pool.query(
          "INSERT INTO saved_cards (user_id, brand, last4, expiry) VALUES (?, ?, ?, ?)",
          [req.session.userId, cardBrandName, last4, expiry.replace("/", " / ")]
        );
      }
    }
  }
  const [orderResult] = await pool.query(
    "INSERT INTO orders (user_id, email, total, payment_method, card_brand, card_last4) VALUES (?, ?, ?, ?, ?, ?)",
    [req.session.userId, email, cart.totals.total, method, cardBrandName, last4]
  );
  for (const item of cart.items) {
    await pool.query(
      "INSERT INTO order_items (order_id, product_name, quantity, price) VALUES (?, ?, ?, ?)",
      [orderResult.insertId, item.product.B_name, item.quantity, item.product.B_price]
    );
  }
  req.session.cart = [];
  res.json({ order: { id: orderResult.insertId } });
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ success: false, message: "Something went wrong." });
});

app.listen(Number(process.env.PORT), process.env.HOST, () => {
  console.log("API listening on " + process.env.HOST + ":" + process.env.PORT);
});
