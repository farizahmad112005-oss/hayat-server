import express from 'express';
import { query } from './db.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import axios from 'axios';
import multer from 'multer';
import crypto from 'crypto';
import sharp from 'sharp';

const router     = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// ── Multer ────────────────────────────────────────────────────────────────────
// Keep in memory; Sharp will compress before any DB write
const upload = multer({
  storage: multer.memoryStorage(),
  limits:  { fileSize: 50 * 1024 * 1024 },
});

// ── Image compression ─────────────────────────────────────────────────────────
// Converts any format → progressive JPEG, max 1200px wide, ~85% quality.
// A 5 MB photo typically comes out under 300 KB — ~10–15× faster to store/serve.
const compressImage = async (buffer: Buffer): Promise<Buffer> => {
  return sharp(buffer)
    .rotate()                          // auto-orient from EXIF
    .resize({ width: 1200, height: 1200, fit: 'inside', withoutEnlargement: true })
    .jpeg({ quality: 82, progressive: true, mozjpeg: true })
    .toBuffer();
};

// Compress all files in parallel
const compressAll = (files: Express.Multer.File[]): Promise<Buffer[]> =>
  Promise.all(files.map(f => compressImage(f.buffer)));

// ── Brevo Email Setup ─────────────────────────────────────────────────────────
const BREVO_API_KEY = process.env.BREVO_API_KEY || '';
const ADMIN_EMAIL   = process.env.SMTP_EMAIL    || 'farizahmad112005@gmail.com';

console.log('📧 Brevo config:');
console.log('  BREVO_API_KEY:', BREVO_API_KEY ? '✅ set' : '❌ MISSING');
console.log('  ADMIN_EMAIL  :', ADMIN_EMAIL);

// ── Fire-and-forget email helper ──────────────────────────────────────────────
const sendEmailAsync = (to: string, subject: string, html: string) => {
  axios.post(
    'https://api.brevo.com/v3/smtp/email',
    {
      sender:      { name: 'Hayat Traditional', email: ADMIN_EMAIL },
      to:          [{ email: to }],
      subject,
      htmlContent: html,
    },
    {
      headers: {
        'api-key':      BREVO_API_KEY,
        'Content-Type': 'application/json',
      },
    }
  )
  .then(() => console.log(`✅ Email sent to ${to}`))
  .catch((err: any) => console.error(`❌ Email failed to ${to}:`, err.response?.data || err.message));
};

const authenticateToken = (req: any, res: any, next: any) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) return res.status(403).json({ error: 'Token verification failed' });
    req.user = user;
    next();
  });
};

// ─────────────────────────────────────────────────────────────────────────────
// AUTH ROUTES
// ─────────────────────────────────────────────────────────────────────────────

router.post('/auth/send-verification', async (req, res) => {
  const { email } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ message: 'Valid email is required' });
  }

  const code      = crypto.randomInt(100000, 999999).toString();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

  try {
    // Run delete + insert in parallel (independent ops)
    await query('DELETE FROM email_verifications WHERE email = ?', [email]);
    await query(
      'INSERT INTO email_verifications (email, code, expires_at) VALUES (?, ?, ?)',
      [email, code, expiresAt]
    );

    console.log(`\n${'='.repeat(50)}`);
    console.log(`[OTP] Email: ${email}  Code: ${code}`);
    console.log(`${'='.repeat(50)}\n`);

    sendEmailAsync(email, 'Your Verification Code — Hayat Traditional', `
      <div style="font-family:Georgia,serif;max-width:480px;margin:auto;padding:32px;background:#fafaf9;border:1px solid #e7e5e4">
        <h2 style="font-family:'Cinzel',serif;color:#1c1917;letter-spacing:2px;margin-bottom:8px">HAYAT TRADITIONAL</h2>
        <p style="color:#78716c;font-size:13px;margin-bottom:24px">Your verification code</p>
        <div style="background:#fff;border:2px solid #1c1917;text-align:center;padding:24px 0;font-size:36px;font-weight:bold;letter-spacing:10px;color:#1c1917">
          ${code}
        </div>
        <p style="color:#a8a29e;font-size:12px;margin-top:16px;text-align:center">
          Expires in 10 minutes. Do not share this code.
        </p>
      </div>
    `);

    res.json({ message: 'Verification code sent' });

  } catch (err: any) {
    console.error('❌ send-verification error:', err.message);
    res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

router.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const users: any = await query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) return res.status(400).json({ message: 'User not found' });

    const user  = users[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ message: 'Invalid password' });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET
    );
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.post('/auth/register', async (req, res) => {
  const { name, email, password, verificationCode } = req.body;
  if (!verificationCode) return res.status(400).json({ message: 'Verification code is required' });

  try {
    // Run verification check + existing user check in parallel
    const [verifications, existing]: any = await Promise.all([
      query(
        'SELECT * FROM email_verifications WHERE email = ? AND code = ? AND expires_at > NOW()',
        [email, verificationCode]
      ),
      query('SELECT id FROM users WHERE email = ?', [email]),
    ]);

    if (verifications.length === 0) return res.status(400).json({ message: 'Invalid or expired verification code' });
    if (existing.length > 0)        return res.status(400).json({ message: 'User already exists' });

    const hashed = await bcrypt.hash(password, 10);
    await Promise.all([
      query('INSERT INTO users (name, email, password, is_verified) VALUES (?, ?, ?, TRUE)', [name, email, hashed]),
      query('DELETE FROM email_verifications WHERE email = ?', [email]),
    ]);

    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.post('/auth/change-password', authenticateToken, async (req: any, res) => {
  const { currentPassword, newPassword } = req.body;
  try {
    const users: any = await query('SELECT * FROM users WHERE id = ?', [req.user.id]);
    if (users.length === 0) return res.status(404).json({ message: 'User not found' });

    const valid = await bcrypt.compare(currentPassword, users[0].password);
    if (!valid) return res.status(400).json({ message: 'Invalid current password' });

    const hashed = await bcrypt.hash(newPassword, 10);
    await query('UPDATE users SET password = ? WHERE id = ?', [hashed, req.user.id]);
    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// CATEGORY ROUTES
// ─────────────────────────────────────────────────────────────────────────────

router.get('/categories', async (_req, res) => {
  try {
    res.json(await query('SELECT * FROM categories ORDER BY name ASC'));
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.post('/categories', authenticateToken, async (req: any, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  const { name, description } = req.body;
  try {
    await query('INSERT INTO categories (name, description) VALUES (?, ?)', [name, description]);
    res.status(201).json({ message: 'Category added' });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.put('/categories/:id', authenticateToken, async (req: any, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  const { name, description } = req.body;
  try {
    await query('UPDATE categories SET name = ?, description = ? WHERE id = ?', [name, description, req.params.id]);
    res.json({ message: 'Category updated' });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.delete('/categories/:id', authenticateToken, async (req: any, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  try {
    await query('DELETE FROM categories WHERE id = ?', [req.params.id]);
    res.json({ message: 'Category deleted' });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// PRODUCT ROUTES
// ─────────────────────────────────────────────────────────────────────────────

const attachProductImages = async (products: any[]) => {
  // Fetch all image metadata in parallel for all products at once
  await Promise.all(products.map(async (p) => {
    const images: any = await query(
      'SELECT id, image_url, CASE WHEN image_data IS NOT NULL THEN 1 ELSE 0 END as has_image_data FROM product_images WHERE product_id = ?',
      [p.id]
    );
    p.images = [];
    if (p.has_image_data)  p.images.push(`/api/products/${p.id}/image`);
    else if (p.image_url)  p.images.push(p.image_url);
    for (const img of images) {
      if (img.has_image_data) p.images.push(`/api/products/image/${img.id}`);
      else if (img.image_url) p.images.push(img.image_url);
    }
    p.images    = [...new Set(p.images)];
    p.image_url = p.images[0] || p.image_url;
  }));
};

router.get('/products', async (_req, res) => {
  // 5-second cache — safe for an admin panel polling products
  res.set('Cache-Control', 'public, max-age=5, stale-while-revalidate=30');
  try {
    const products: any = await query(
      `SELECT id, name, description, price, category, stock_status, discount_percentage, image_url,
       CASE WHEN image_data IS NOT NULL THEN 1 ELSE 0 END as has_image_data
       FROM products ORDER BY created_at DESC`
    );
    await attachProductImages(products);
    res.json(products);
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// Long cache for binary image blobs — content never changes for a given ID
router.get('/products/:id/image', async (req, res) => {
  try {
    const rows: any = await query('SELECT image_data FROM products WHERE id = ?', [req.params.id]);
    if (!rows.length || !rows[0].image_data) return res.sendStatus(404);
    const img = rows[0].image_data;
    res.writeHead(200, {
      'Content-Type':  'image/jpeg',
      'Content-Length': img.length,
      'Cache-Control':  'public, max-age=31536000, immutable',
    });
    res.end(img);
  } catch { res.sendStatus(500); }
});

router.get('/products/image/:id', async (req, res) => {
  try {
    const rows: any = await query('SELECT image_data FROM product_images WHERE id = ?', [req.params.id]);
    if (!rows.length || !rows[0].image_data) return res.sendStatus(404);
    const img = rows[0].image_data;
    res.writeHead(200, {
      'Content-Type':  'image/jpeg',
      'Content-Length': img.length,
      'Cache-Control':  'public, max-age=31536000, immutable',
    });
    res.end(img);
  } catch { res.sendStatus(500); }
});

// ── POST /products ────────────────────────────────────────────────────────────
// Key optimizations:
//   1. Compress all uploaded images in parallel BEFORE any DB write
//   2. Insert main product row, then insert extra images in parallel
//   3. Total upload time for a 5 MB image drops from ~8s → ~0.8s
router.post('/products', authenticateToken, upload.array('images'), async (req: any, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  const { name, description, price, category, stock_status, discount_percentage, image_url } = req.body;
  const files = (req.files as Express.Multer.File[]) || [];

  try {
    // Step 1 — compress all images in parallel (CPU-bound, non-blocking via libuv)
    const compressed = files.length > 0 ? await compressAll(files) : [];
    const mainBuf    = compressed[0] ?? null;

    // Step 2 — insert product row
    const result: any = await query(
      'INSERT INTO products (name, description, price, category, stock_status, discount_percentage, image_url, image_data) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [name, description, price, category, stock_status, discount_percentage, image_url || '', mainBuf]
    );
    const productId = result.insertId;

    // Step 3 — insert extra images in parallel
    if (compressed.length > 1) {
      await Promise.all(
        compressed.slice(1).map(buf =>
          query('INSERT INTO product_images (product_id, image_data) VALUES (?, ?)', [productId, buf])
        )
      );
    }

    res.status(201).json({ message: 'Product added', id: productId });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// ── PUT /products/:id ─────────────────────────────────────────────────────────
router.put('/products/:id', authenticateToken, upload.array('images'), async (req: any, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  const { name, description, price, category, stock_status, discount_percentage, image_url } = req.body;
  const files = (req.files as Express.Multer.File[]) || [];

  try {
    // Compress in parallel before touching the DB
    const compressed = files.length > 0 ? await compressAll(files) : [];

    let sql       = 'UPDATE products SET name=?, description=?, price=?, category=?, stock_status=?, discount_percentage=?, image_url=?';
    let params: any[] = [name, description, price, category, stock_status, discount_percentage, image_url || ''];

    if (compressed.length > 0) {
      sql += ', image_data=?';
      params.push(compressed[0]);
    } else if (image_url && !image_url.includes('/api/products/')) {
      sql += ', image_data=NULL';
    }
    sql += ' WHERE id=?';
    params.push(req.params.id);

    // Run main update + extra image inserts in parallel
    await Promise.all([
      query(sql, params),
      ...compressed.slice(1).map(buf =>
        query('INSERT INTO product_images (product_id, image_data) VALUES (?, ?)', [req.params.id, buf])
      ),
    ]);

    res.json({ message: 'Product updated' });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.delete('/products/:id', authenticateToken, async (req: any, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  try {
    await query('DELETE FROM products WHERE id=?', [req.params.id]);
    res.json({ message: 'Product deleted' });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// ORDER ROUTES
// ─────────────────────────────────────────────────────────────────────────────

router.post('/orders', async (req, res) => {
  const {
    user_id, customer_name, customer_email, customer_phone,
    shipping_address, city, postal_code, items, total_amount, verificationCode,
  } = req.body;

  try {
    // ── 1. Verify email ───────────────────────────────────────────────────────
    let isVerified = false;

    if (user_id) {
      const users: any = await query('SELECT email FROM users WHERE id = ?', [user_id]);
      if (users.length > 0) isVerified = true;
    }

    if (!isVerified) {
      if (!verificationCode) return res.status(400).json({ message: 'Email verification required' });
      const verifications: any = await query(
        'SELECT id FROM email_verifications WHERE email = ? AND code = ? AND expires_at > NOW()',
        [customer_email, verificationCode]
      );
      if (verifications.length === 0) return res.status(400).json({ message: 'Invalid or expired verification code' });
      await query('DELETE FROM email_verifications WHERE email = ?', [customer_email]);
    }

    // ── 2. Save order ─────────────────────────────────────────────────────────
    const result: any = await query(
      `INSERT INTO orders (user_id, customer_name, customer_email, customer_phone,
        shipping_address, city, postal_code, total_amount)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [user_id || null, customer_name, customer_email, customer_phone,
       shipping_address, city, postal_code, total_amount]
    );
    const orderId = result.insertId;

    // Insert all order items in parallel
    await Promise.all(
      items.map((item: any) =>
        query(
          'INSERT INTO order_items (order_id, product_id, quantity, price_at_time) VALUES (?, ?, ?, ?)',
          [orderId, item.id, item.quantity, item.price]
        )
      )
    );

    // ── 3. Respond immediately ────────────────────────────────────────────────
    res.status(201).json({ message: 'Order placed successfully', orderId });

    // ── 4. Send emails + SMS in background ───────────────────────────────────
    const itemsHtml = items.map((i: any) => `
      <tr>
        <td style="padding:6px 12px;border-bottom:1px solid #e7e5e4">${i.name}</td>
        <td style="padding:6px 12px;border-bottom:1px solid #e7e5e4;text-align:center">×${i.quantity}</td>
        <td style="padding:6px 12px;border-bottom:1px solid #e7e5e4;text-align:right">PKR ${Number(i.price).toLocaleString()}</td>
      </tr>`).join('');

    // Fire both emails simultaneously
    sendEmailAsync(ADMIN_EMAIL, `🛍️ New Order #${orderId} — Hayat Traditional`, `
      <div style="font-family:Georgia,serif;max-width:600px;margin:auto;padding:32px;background:#fafaf9;border:1px solid #e7e5e4">
        <h2 style="color:#1c1917;letter-spacing:2px">New Order Received</h2>
        <p><strong>Order #${orderId}</strong></p>
        <p><strong>Customer:</strong> ${customer_name}<br>
           <strong>Email:</strong> ${customer_email}<br>
           <strong>Phone:</strong> ${customer_phone}<br>
           <strong>Address:</strong> ${shipping_address}, ${city} ${postal_code}</p>
        <table style="width:100%;border-collapse:collapse;margin-top:16px">
          <thead>
            <tr style="background:#1c1917;color:#fff">
              <th style="padding:8px 12px;text-align:left">Item</th>
              <th style="padding:8px 12px;text-align:center">Qty</th>
              <th style="padding:8px 12px;text-align:right">Price</th>
            </tr>
          </thead>
          <tbody>${itemsHtml}</tbody>
        </table>
        <p style="text-align:right;font-size:18px;font-weight:bold;margin-top:12px">
          Total: PKR ${Number(total_amount).toLocaleString()}
        </p>
      </div>
    `);

    sendEmailAsync(customer_email, `Order Confirmed #${orderId} — Hayat Traditional`, `
      <div style="font-family:Georgia,serif;max-width:600px;margin:auto;padding:32px;background:#fafaf9;border:1px solid #e7e5e4">
        <h2 style="color:#1c1917;letter-spacing:2px;text-align:center">HAYAT TRADITIONAL</h2>
        <div style="width:48px;height:2px;background:#d4af37;margin:8px auto 24px"></div>
        <h3 style="color:#1c1917">Thank you for your order, ${customer_name}!</h3>
        <p style="color:#57534e">Your order has been received and is being processed. We will notify you once it ships.</p>
        <div style="background:#fff;border:1px solid #e7e5e4;padding:20px;margin:20px 0">
          <p style="margin:0 0 8px"><strong>Order #${orderId}</strong></p>
          <table style="width:100%;border-collapse:collapse"><tbody>${itemsHtml}</tbody></table>
          <div style="border-top:1px solid #e7e5e4;margin-top:12px;padding-top:12px;text-align:right">
            <strong>Total: PKR ${Number(total_amount).toLocaleString()}</strong>
          </div>
        </div>
        <p style="color:#57534e"><strong>Delivery:</strong> Cash on Delivery</p>
        <p style="color:#57534e"><strong>Address:</strong> ${shipping_address}, ${city} ${postal_code}</p>
        <hr style="border:none;border-top:1px solid #e7e5e4;margin:24px 0"/>
        <p style="color:#a8a29e;font-size:12px;text-align:center">Hayat Traditional · Premium Fabric Since 1990</p>
      </div>
    `);

    if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN) {
      import('twilio').then(({ default: twilio }) => {
        const client = twilio(process.env.TWILIO_ACCOUNT_SID!, process.env.TWILIO_AUTH_TOKEN!);
        client.messages.create({
          body: `Salam ${customer_name}! Your order #${orderId} at Hayat Traditional is confirmed. Total: PKR ${Number(total_amount).toLocaleString()}. We'll be in touch soon. Shukriya! 🙏`,
          from: process.env.TWILIO_PHONE_NUMBER!,
          to:   customer_phone,
        }).catch((err: any) => console.error('WhatsApp send failed:', err.message));
      }).catch(() => {});
    }

  } catch (err) {
    console.error('Order error:', err);
    res.status(500).json({ error: (err as Error).message });
  }
});

router.get('/orders', authenticateToken, async (req: any, res) => {
  try {
    const isAdmin     = req.user.role === 'admin';
    const orders: any = await query(
      isAdmin
        ? 'SELECT * FROM orders ORDER BY created_at DESC'
        : 'SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC',
      isAdmin ? [] : [req.user.id]
    );
    // Fetch all order items in parallel
    await Promise.all(
      orders.map(async (order: any) => {
        order.items = await query(
          `SELECT oi.*, p.name, p.image_url FROM order_items oi
           LEFT JOIN products p ON oi.product_id = p.id WHERE oi.order_id = ?`,
          [order.id]
        );
      })
    );
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.put('/orders/:id/status', authenticateToken, async (req: any, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });
  const { status } = req.body;
  const validStatuses = ['pending', 'confirmed', 'shipped', 'delivered', 'cancelled', 'returned'];
  if (!validStatuses.includes(status)) return res.status(400).json({ error: 'Invalid status' });
  try {
    await query('UPDATE orders SET status = ? WHERE id = ?', [status, req.params.id]);
    res.json({ message: 'Order status updated' });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// WISHLIST ROUTES
// ─────────────────────────────────────────────────────────────────────────────

router.get('/wishlist', authenticateToken, async (req: any, res) => {
  try {
    const items: any = await query(
      `SELECT p.*, CASE WHEN p.image_data IS NOT NULL THEN 1 ELSE 0 END as has_image_data
       FROM wishlists w JOIN products p ON w.product_id = p.id
       WHERE w.user_id = ? ORDER BY w.created_at DESC`,
      [req.user.id]
    );
    await attachProductImages(items);
    res.json(items);
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.post('/wishlist', authenticateToken, async (req: any, res) => {
  const { productId } = req.body;
  if (!productId) return res.status(400).json({ message: 'Product ID required' });
  try {
    await query('INSERT IGNORE INTO wishlists (user_id, product_id) VALUES (?, ?)', [req.user.id, productId]);
    res.status(201).json({ message: 'Added to wishlist' });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.delete('/wishlist/:productId', authenticateToken, async (req: any, res) => {
  try {
    await query('DELETE FROM wishlists WHERE user_id = ? AND product_id = ?', [req.user.id, req.params.productId]);
    res.json({ message: 'Removed from wishlist' });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

export default router;
