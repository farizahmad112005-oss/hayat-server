import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { initDB } from './db.js';
import apiRoutes from './routes.js';

process.on('unhandledRejection', (reason, p) => {
  console.error('Unhandled Rejection at:', p, 'reason:', reason);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000; // ✅ convert to number

  app.use(cors());
  app.use(express.json());

  // Health check
  app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  console.log('Starting server initialization...');

  // Initialize DB
  initDB()
    .then(() => console.log('Database initialized'))
    .catch((err: any) => console.error('Database initialization failed:', err));

  // API routes
  app.use('/api', apiRoutes);

  // Start server
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
  });
}

startServer();