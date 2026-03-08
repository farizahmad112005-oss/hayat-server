import express from 'express';
import cors from 'cors';
import { initDB, query } from './db.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import multer from 'multer';
import crypto from 'crypto';
import dns from 'dns';
import util from 'util';

const resolveMx = util.promisify(dns.resolveMx);

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Configure Multer for memory storage (buffer)
const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB limit
});

// Middleware to verify token
const authenticateToken = (req: any, res: any, next: any) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    console.log('Auth failed: No token provided');
    return res.sendStatus(401);
  }

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) {
      console.log('Auth failed: Token verification error:', err.message);
      return res.status(403).json({ error: 'Token verification failed', details: err.message });
    }
    req.user = user;
    console.log('Auth success: User:', user);
    next();
  });
};

// Helper to verify email domain
const verifyEmailDomain = async (email: string): Promise<boolean> => {
  try {
    const domain = email.split('@')[1];
    if (!domain) return false;
    const addresses = await resolveMx(domain);
    return addresses && addresses.length > 0;
  } catch (error) {
    console.error('MX Record check failed:', error);
    return false;
  }
};

// Helper to send verification code
const sendVerificationCode = async (email: string, code: string) => {
  // Always log the code to console for development/preview purposes
  console.log(`\n==================================================`);
  console.log(`[VERIFICATION CODE] To: ${email}`);
  console.log(`CODE: ${code}`);
  console.log(`==================================================\n`);

  const smtpPassword = 'nyazgaiserqiuwog';
  if (smtpPassword) {
    console.log(`[DEBUG] Using hardcoded App Password. Length: ${smtpPassword.length}`);
  } else {
    console.log('[DEBUG] SMTP_PASSWORD is NOT set.');
  }

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'farizahmad112005@gmail.com',
      pass: smtpPassword.replace(/\s+/g, '')
    }
  });

  const mailOptions = {
    from: 'farizahmad112005@gmail.com',
    to: email,
    subject: 'Your Verification Code - Luxe Aurum',
    text: `Your verification code is: ${code}. It expires in 10 minutes.`
  };

  if (smtpPassword) {
    try {
      await transporter.sendMail(mailOptions);
      console.log(`✅ Verification email sent to ${email}`);
    } catch (error: any) {
      console.error('❌ Failed to send verification email:', error.message);
      
      if (error.response && error.response.includes('534-5.7.9')) {
        console.error(`
        ***********************************************************
        GMAIL AUTHENTICATION ERROR: App Password Required
        ***********************************************************
        You are trying to use a regular Gmail password, but 2-Step Verification is enabled.
        
        SOLUTION:
        1. Go to your Google Account settings (https://myaccount.google.com/security).
        2. Enable 2-Step Verification if not already enabled.
        3. Search for "App Passwords" in the search bar.
        4. Create a new App Password for "Mail" / "Other".
        5. Use that 16-character App Password as your SMTP_PASSWORD environment variable.
        ***********************************************************
        `);
      }
    }
  } else {
    console.log('⚠️ SMTP_PASSWORD not set. Email sending skipped.');
  }
};

// Auth Routes
router.post('/auth/send-verification', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: 'Email is required' });

  // 1. Check if email domain exists (MX records)
  const isValidDomain = await verifyEmailDomain(email);
  if (!isValidDomain) {
    return res.status(400).json({ message: 'Invalid email domain. Please provide a valid email address.' });
  }

  // 2. Generate Code
  const code = crypto.randomInt(100000, 999999).toString();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

  try {
    // 3. Store Code
    await query('DELETE FROM email_verifications WHERE email = ?', [email]); // Clean up old codes
    await query('INSERT INTO email_verifications (email, code, expires_at) VALUES (?, ?, ?)', [email, code, expiresAt]);

    // 4. Send Code
    await sendVerificationCode(email, code);

    res.json({ message: 'Verification code sent' });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const users: any = await query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) return res.status(400).json({ message: 'User not found' });

    const user = users[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ message: 'Invalid password' });

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET);
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.post('/auth/register', async (req, res) => {
  const { name, email, password, verificationCode } = req.body;
  
  if (!verificationCode) {
    return res.status(400).json({ message: 'Verification code is required' });
  }

  try {
    // Verify Code
    const verifications: any = await query(
      'SELECT * FROM email_verifications WHERE email = ? AND code = ? AND expires_at > NOW()', 
      [email, verificationCode]
    );

    if (verifications.length === 0) {
      return res.status(400).json({ message: 'Invalid or expired verification code' });
    }

    // Check if user exists
    const existing: any = await query('SELECT * FROM users WHERE email = ?', [email]);
    if (existing.length > 0) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await query('INSERT INTO users (name, email, password, is_verified) VALUES (?, ?, ?, TRUE)', [name, email, hashedPassword]);
    
    // Clean up verification code
    await query('DELETE FROM email_verifications WHERE email = ?', [email]);

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

    const user = users[0];
    const validPassword = await bcrypt.compare(currentPassword, user.password);
    if (!validPassword) return res.status(400).json({ message: 'Invalid current password' });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, req.user.id]);
    
    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// Category Routes
router.get('/categories', async (req, res) => {
  try {
    const categories = await query('SELECT * FROM categories ORDER BY name ASC');
    res.json(categories);
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

// Product Routes
router.get('/products', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  try {
    const products: any = await query('SELECT id, name, description, price, category, stock_status, discount_percentage, image_url, CASE WHEN image_data IS NOT NULL THEN 1 ELSE 0 END as has_image_data FROM products ORDER BY created_at DESC');
    
    // Fetch additional images for each product
    for (const product of products) {
      const images: any = await query('SELECT id, image_url, CASE WHEN image_data IS NOT NULL THEN 1 ELSE 0 END as has_image_data FROM product_images WHERE product_id = ?', [product.id]);
      
      product.images = [];
      
      // Add main image first if exists
      if (product.has_image_data) {
        product.images.push(`/api/products/${product.id}/image`);
      } else if (product.image_url) {
        product.images.push(product.image_url);
      }

      // Add additional images
      for (const img of images) {
        if (img.has_image_data) {
          product.images.push(`/api/products/image/${img.id}`);
        } else if (img.image_url) {
          product.images.push(img.image_url);
        }
      }
      
      // Ensure unique images
      product.images = [...new Set(product.images)];
      
      // Set main image_url for backward compatibility
      if (product.images.length > 0) {
        product.image_url = product.images[0];
      }
    }

    res.json(products);
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.get('/products/:id/image', async (req, res) => {
  try {
    const products: any = await query('SELECT image_data FROM products WHERE id = ?', [req.params.id]);
    if (products.length === 0 || !products[0].image_data) return res.sendStatus(404);
    
    const img = products[0].image_data;
    res.writeHead(200, {
      'Content-Type': 'image/jpeg',
      'Content-Length': img.length,
      'Cache-Control': 'public, max-age=86400'
    });
    res.end(img);
  } catch (err) {
    console.error(err);
    res.sendStatus(500);
  }
});

router.get('/products/image/:id', async (req, res) => {
  try {
    const images: any = await query('SELECT image_data FROM product_images WHERE id = ?', [req.params.id]);
    if (images.length === 0 || !images[0].image_data) return res.sendStatus(404);
    
    const img = images[0].image_data;
    res.writeHead(200, {
      'Content-Type': 'image/jpeg',
      'Content-Length': img.length,
      'Cache-Control': 'public, max-age=86400'
    });
    res.end(img);
  } catch (err) {
    console.error(err);
    res.sendStatus(500);
  }
});

router.post('/products', authenticateToken, upload.array('images'), async (req: any, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  
  console.log('Received product creation request:', req.body);
  const { name, description, price, category, stock_status, discount_percentage, image_url } = req.body;
  const files = req.files as Express.Multer.File[];
  
  try {
    // Insert main product (using first image as main if available, for backward compatibility)
    const mainImageBuffer = files && files.length > 0 ? files[0].buffer : null;
    
    const result: any = await query(
      'INSERT INTO products (name, description, price, category, stock_status, discount_percentage, image_url, image_data) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [name, description, price, category, stock_status, discount_percentage, image_url || '', mainImageBuffer]
    );
    
    const productId = result.insertId;
    console.log('Product inserted successfully, ID:', productId);

    // Insert additional images (skip first one if it was used as main)
    if (files && files.length > 1) {
      for (let i = 1; i < files.length; i++) {
        await query(
          'INSERT INTO product_images (product_id, image_data) VALUES (?, ?)',
          [productId, files[i].buffer]
        );
      }
    }

    res.status(201).json({ message: 'Product added', id: productId });
  } catch (err) {
    console.error('Error inserting product:', err);
    res.status(500).json({ error: (err as Error).message });
  }
});

router.put('/products/:id', authenticateToken, upload.array('images'), async (req: any, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  
  const { name, description, price, category, stock_status, discount_percentage, image_url } = req.body;
  const files = req.files as Express.Multer.File[];

  try {
    let sql = 'UPDATE products SET name=?, description=?, price=?, category=?, stock_status=?, discount_percentage=?, image_url=?';
    let params: any[] = [name, description, price, category, stock_status, discount_percentage, image_url || ''];

    // If new files are uploaded, update main image with first one
    if (files && files.length > 0) {
      sql += ', image_data=?';
      params.push(files[0].buffer);
    } else if (image_url && !image_url.includes('/api/products/')) {
      // If a new external URL is provided (and no new file), clear the old image data
      sql += ', image_data=NULL';
    }

    sql += ' WHERE id=?';
    params.push(req.params.id);

    await query(sql, params);

    // Insert additional images
    if (files && files.length > 1) {
      // Optional: Clear old additional images? Or append? 
      // For simplicity, let's append. Admin can delete specific images later if we implement that.
      // But user asked for "Option to add Multiple photos", usually implies replacing or adding.
      // Let's append for now.
      for (let i = 1; i < files.length; i++) {
        await query(
          'INSERT INTO product_images (product_id, image_data) VALUES (?, ?)',
          [req.params.id, files[i].buffer]
        );
      }
    }

    res.json({ message: 'Product updated' });
  } catch (err) {
    console.error(err);
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

// Order Routes
router.post('/orders', async (req, res) => {
  const { user_id, customer_name, customer_email, customer_phone, shipping_address, city, postal_code, items, total_amount, verificationCode } = req.body;
  
  try {
    // Email Verification Logic
    let isVerified = false;

    if (user_id) {
      const users: any = await query('SELECT * FROM users WHERE id = ?', [user_id]);
      if (users.length > 0 && users[0].email === customer_email) {
        isVerified = true;
      }
    }

    if (!isVerified) {
      if (!verificationCode) {
        return res.status(400).json({ message: 'Email verification required for guest checkout or new email' });
      }
      
      const verifications: any = await query(
        'SELECT * FROM email_verifications WHERE email = ? AND code = ? AND expires_at > NOW()', 
        [customer_email, verificationCode]
      );

      if (verifications.length === 0) {
        return res.status(400).json({ message: 'Invalid or expired verification code' });
      }
      
      // Clean up verification code
      await query('DELETE FROM email_verifications WHERE email = ?', [customer_email]);
    }

    const result: any = await query(
      'INSERT INTO orders (user_id, customer_name, customer_email, customer_phone, shipping_address, city, postal_code, total_amount) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [user_id || null, customer_name, customer_email, customer_phone, shipping_address, city, postal_code, total_amount]
    );
    
    const orderId = result.insertId;

    for (const item of items) {
      await query(
        'INSERT INTO order_items (order_id, product_id, quantity, price_at_time) VALUES (?, ?, ?, ?)',
        [orderId, item.id, item.quantity, item.price]
      );
    }

    // Send Email to Admin
    const smtpPassword = 'nyazgaiserqiuwog';
    
    // Debug log to check if password is loaded (do not log the actual password)
    if (smtpPassword) {
      console.log(`[DEBUG] Using hardcoded App Password. Length: ${smtpPassword.length}`);
    } else {
      console.log('[DEBUG] SMTP_PASSWORD is NOT set.');
    }

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'farizahmad112005@gmail.com',
        pass: smtpPassword.replace(/\s+/g, '') // Remove spaces just in case
      }
    });

    const adminMailOptions = {
      from: 'farizahmad112005@gmail.com',
      to: 'farizahmad112005@gmail.com',
      subject: `New Order #${orderId} Received - Luxe Aurum`,
      html: `
        <h1>New Order Received</h1>
        <p><strong>Order ID:</strong> #${orderId}</p>
        <p><strong>Customer:</strong> ${customer_name}</p>
        <p><strong>Email:</strong> ${customer_email}</p>
        <p><strong>Phone:</strong> ${customer_phone}</p>
        <p><strong>Total Amount:</strong> $${total_amount}</p>
        <p><strong>Address:</strong> ${shipping_address}, ${city}, ${postal_code}</p>
        <hr/>
        <h3>Items:</h3>
        <ul>
          ${items.map((item: any) => `<li>${item.name} (x${item.quantity}) - $${item.price}</li>`).join('')}
        </ul>
      `
    };

    const customerMailOptions = {
      from: 'farizahmad112005@gmail.com',
      to: customer_email,
      subject: `Order Confirmation #${orderId} - Luxe Aurum`,
      html: `
        <h1>Thank you for your order!</h1>
        <p>Dear ${customer_name},</p>
        <p>We have received your order and it is currently being processed.</p>
        <p><strong>Order ID:</strong> #${orderId}</p>
        <p><strong>Total Amount:</strong> $${total_amount}</p>
        <p>We will notify you once your order has been shipped.</p>
        <br/>
        <p>Best Regards,</p>
        <p>Luxe Aurum Team</p>
      `
    };

    // Attempt to send emails
    if (smtpPassword) {
      try {
        await transporter.sendMail(adminMailOptions);
        console.log(`✅ Admin email sent to farizahmad112005@gmail.com`);
        await transporter.sendMail(customerMailOptions);
        console.log(`✅ Customer confirmation email sent to ${customer_email}`);
      } catch (emailError: any) {
        console.error('❌ Failed to send emails:', emailError.message);
        
        if (emailError.response && emailError.response.includes('534-5.7.9')) {
          console.error(`
          ***********************************************************
          GMAIL AUTHENTICATION ERROR: App Password Required
          ***********************************************************
          You are trying to use a regular Gmail password, but 2-Step Verification is enabled.
          
          SOLUTION:
          1. Go to your Google Account settings (https://myaccount.google.com/security).
          2. Enable 2-Step Verification if not already enabled.
          3. Search for "App Passwords" in the search bar.
          4. Create a new App Password for "Mail" / "Other".
          5. Use that 16-character App Password as your SMTP_PASSWORD environment variable.
          ***********************************************************
          `);
        }
      }
    } else {
      console.log('⚠️ SMTP_PASSWORD not set. Skipping email sending.');
      console.log('--- Mock Admin Email ---');
      console.log(adminMailOptions.html);
      console.log('------------------------');
    }

    // Send WhatsApp Message (Twilio)
    if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_PHONE_NUMBER) {
      try {
        const client = require('twilio')(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
        await client.messages.create({
          body: `Hello ${customer_name}, your order #${orderId} at Luxe Aurum has been confirmed! Total: $${total_amount}. Thank you for shopping with us.`,
          from: process.env.TWILIO_PHONE_NUMBER,
          to: customer_phone
        });
        console.log(`✅ WhatsApp message sent to ${customer_phone}`);
      } catch (waError) {
        console.error('❌ Failed to send WhatsApp message:', waError);
      }
    } else {
      console.log('⚠️ Twilio credentials not set. Skipping WhatsApp sending.');
      console.log(`--- Mock WhatsApp Message to ${customer_phone} ---`);
      console.log(`Hello ${customer_name}, your order #${orderId} at Luxe Aurum has been confirmed! Total: $${total_amount}.`);
      console.log('--------------------------------------------------');
    }

    res.status(201).json({ message: 'Order placed successfully', orderId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: (err as Error).message });
  }
});

router.get('/orders', authenticateToken, async (req: any, res) => {
  try {
    let sql = 'SELECT * FROM orders ORDER BY created_at DESC';
    let params: any[] = [];
    
    if (req.user.role !== 'admin') {
      sql = 'SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC';
      params = [req.user.id];
    }
    
    const orders: any = await query(sql, params);
    
    // Fetch items for each order
    for (const order of orders) {
      order.items = await query(
        `SELECT oi.*, p.name, p.image_url 
         FROM order_items oi 
         LEFT JOIN products p ON oi.product_id = p.id 
         WHERE oi.order_id = ?`,
        [order.id]
      );
    }
    
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.put('/orders/:id/status', authenticateToken, async (req: any, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    const { status } = req.body;
    const { id } = req.params;

    if (!['pending', 'confirmed', 'shipped', 'delivered', 'cancelled', 'returned'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    await query('UPDATE orders SET status = ? WHERE id = ?', [status, id]);
    res.json({ message: 'Order status updated successfully' });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// Wishlist Routes
router.get('/wishlist', authenticateToken, async (req: any, res) => {
  try {
    const wishlistItems: any = await query(
      `SELECT p.*, 
       CASE WHEN p.image_data IS NOT NULL THEN 1 ELSE 0 END as has_image_data 
       FROM wishlists w 
       JOIN products p ON w.product_id = p.id 
       WHERE w.user_id = ? 
       ORDER BY w.created_at DESC`,
      [req.user.id]
    );
    
    // Fetch additional images for each product
    for (const product of wishlistItems) {
      const images: any = await query('SELECT id, image_url, CASE WHEN image_data IS NOT NULL THEN 1 ELSE 0 END as has_image_data FROM product_images WHERE product_id = ?', [product.id]);
      
      product.images = [];
      
      // Add main image first if exists
      if (product.has_image_data) {
        product.images.push(`/api/products/${product.id}/image`);
      } else if (product.image_url) {
        product.images.push(product.image_url);
      }

      // Add additional images
      for (const img of images) {
        if (img.has_image_data) {
          product.images.push(`/api/products/image/${img.id}`);
        } else if (img.image_url) {
          product.images.push(img.image_url);
        }
      }
      
      // Ensure unique images
      product.images = [...new Set(product.images)];
      
      // Set main image_url for backward compatibility
      if (product.images.length > 0) {
        product.image_url = product.images[0];
      }
    }

    res.json(wishlistItems);
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.post('/wishlist', authenticateToken, async (req: any, res) => {
  const { productId } = req.body;
  if (!productId) return res.status(400).json({ message: 'Product ID is required' });

  try {
    await query(
      'INSERT IGNORE INTO wishlists (user_id, product_id) VALUES (?, ?)',
      [req.user.id, productId]
    );
    res.status(201).json({ message: 'Product added to wishlist' });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.delete('/wishlist/:productId', authenticateToken, async (req: any, res) => {
  try {
    await query(
      'DELETE FROM wishlists WHERE user_id = ? AND product_id = ?',
      [req.user.id, req.params.productId]
    );
    res.json({ message: 'Product removed from wishlist' });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

export default router;
