import mysql from 'mysql2/promise';

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'crossover.proxy.rlwy.net',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'QmPuDwlRcYXBDFSwgmEtlveSrssNqaMq',
  database: process.env.DB_NAME || 'hayat_traditional',
  port: parseInt(process.env.DB_PORT || '37055'),
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

export async function query(sql: string, params?: any[]) {
  const [results] = await pool.execute(sql, params);
  return results;
}

export async function initDB() {
  try {
    const connection = await pool.getConnection();
    console.log('✅ MySQL Connection Successful');
    
    // Create Users Table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        role ENUM('admin', 'customer') DEFAULT 'customer',
        is_verified BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Add is_verified column if it doesn't exist
    try {
      await connection.query(`ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT FALSE`);
    } catch (e: any) {
      if (e.code !== 'ER_DUP_FIELDNAME') {
        console.log('Column is_verified might already exist or error:', e.message);
      }
    }

    // Create Email Verifications Table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS email_verifications (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        code VARCHAR(6) NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX (email)
      )
    `);

    // Create Categories Table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS categories (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL UNIQUE,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Seed Initial Categories if empty
    const [categories]: any = await connection.query('SELECT * FROM categories');
    if (categories.length === 0) {
      await connection.query('INSERT INTO categories (name) VALUES (?), (?), (?), (?)', ['Cotton', 'Wash & Wear', 'Latha', 'Karandi']);
      console.log('Initial categories seeded');
    }

    // Create Products Table
    // Modified to include image_data for BLOB storage
    // Note: In a real migration, we would ALTER TABLE. Here we rely on IF NOT EXISTS.
    // If the table exists with image_url, we might need to add image_data.
    // For this environment, we'll try to add the column if it doesn't exist.
    
    await connection.query(`
      CREATE TABLE IF NOT EXISTS products (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        price DECIMAL(10, 2) NOT NULL,
        image_url TEXT,
        image_data LONGBLOB,
        category VARCHAR(100),
        stock_status ENUM('in_stock', 'out_of_stock') DEFAULT 'in_stock',
        discount_percentage INT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Attempt to add image_data column if it doesn't exist (for existing tables)
    try {
      await connection.query(`ALTER TABLE products ADD COLUMN image_data LONGBLOB`);
    } catch (e: any) {
      // Ignore error if column already exists
      if (e.code !== 'ER_DUP_FIELDNAME') {
        console.log('Column image_data might already exist or error:', e.message);
      }
    }

    // Create Product Images Table for multiple images
    await connection.query(`
      CREATE TABLE IF NOT EXISTS product_images (
        id INT AUTO_INCREMENT PRIMARY KEY,
        product_id INT NOT NULL,
        image_data LONGBLOB,
        image_url TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
      )
    `);

    // Create Orders Table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        customer_name VARCHAR(255) NOT NULL,
        customer_email VARCHAR(255) NOT NULL,
        customer_phone VARCHAR(50) NOT NULL,
        shipping_address TEXT NOT NULL,
        city VARCHAR(100) NOT NULL,
        postal_code VARCHAR(20) NOT NULL,
        total_amount DECIMAL(10, 2) NOT NULL,
        status ENUM('pending', 'confirmed', 'shipped', 'delivered', 'cancelled', 'returned') DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
      )
    `);

    // Attempt to update status enum if it doesn't include 'returned'
    try {
      await connection.query(`ALTER TABLE orders MODIFY COLUMN status ENUM('pending', 'confirmed', 'shipped', 'delivered', 'cancelled', 'returned') DEFAULT 'pending'`);
    } catch (e: any) {
      // Ignore error if column already exists or other issues
      console.log('Column status might already be updated or error:', e.message);
    }

    // Create Order Items Table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS order_items (
        id INT AUTO_INCREMENT PRIMARY KEY,
        order_id INT NOT NULL,
        product_id INT,
        quantity INT NOT NULL,
        price_at_time DECIMAL(10, 2) NOT NULL,
        FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE SET NULL
      )
    `);

    // Create Wishlists Table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS wishlists (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        product_id INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
        UNIQUE KEY unique_wishlist (user_id, product_id)
      )
    `);

    // Seed Admin User if not exists
    const [users]: any = await connection.query('SELECT * FROM users WHERE email = ?', ['farizahmad112005@gmail.com']);
    if (users.length === 0) {
      // In a real app, hash the password. For simplicity here, storing plain text or simple hash.
      // I'll use bcryptjs for security.
      const bcrypt = await import('bcryptjs');
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await connection.query('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)', 
        ['Admin', 'farizahmad112005@gmail.com', hashedPassword, 'admin']);
      console.log('Admin user created');
    }

    connection.release();
  } catch (err) {
    console.error('❌ MySQL connection error:', err);
  }
}
