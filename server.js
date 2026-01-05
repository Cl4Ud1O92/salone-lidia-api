const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');  // ✅ AGGIUNTO PER RENDER

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'salone-lidia-2026-supersecret';
const DB_PATH = path.join(__dirname, 'data/salone.db');

app.use(cors());
app.use(express.json());

// ✅ FIX RENDER: Crea data/ se manca
if (!fs.existsSync('data')) {
  fs.mkdirSync('data', { recursive: true });
  console.log('📁 Cartella data/ creata automaticamente');
}

// Init DB + ADMIN FORZATO ✅
const db = new Database(DB_PATH);
console.log('🗄️ DB:', DB_PATH);

// Crea tabella
db.exec(`
  CREATE TABLE IF NOT EXISTS customers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    phone TEXT UNIQUE NOT NULL,
    email TEXT,
    points INTEGER DEFAULT 0,
    username TEXT UNIQUE,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

// ✅ HASH VERO PER "admin123"
const adminHash = bcrypt.hashSync('admin123', 10);
console.log('🔐 Admin hash:', adminHash);

// FORZA inserimento admin
try {
  db.prepare("DELETE FROM customers WHERE username = 'admin'").run();
  db.prepare("INSERT INTO customers (first_name, last_name, phone, username, password) VALUES (?, ?, ?, ?, ?)")
    .run('Lidia', 'Zucaro', '+393331234567', 'admin', adminHash);
  console.log('✅ Admin creato: admin/admin123');
} catch (err) {
  console.log('ℹ️ Admin già esistente');
}

// Middleware JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token mancante' });
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token invalido' });
    req.user = user;
    next();
  });
};

// Routes
app.get('/api/ping', (req, res) => res.json({ status: 'OK', timestamp: new Date() }));

app.post('/api/auth/login', (req, res) => {
  console.log('🔑 Login:', req.body);
  const { username, password } = req.body;
  try {
    const user = db.prepare("SELECT * FROM customers WHERE username = ?").get(username);
    if (!user || !bcrypt.compareSync(password, user.password)) {
      console.log('❌ Login fallito:', username);
      return res.status(401).json({ error: 'Credenziali errate' });
    }
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    console.log('✅ Login OK:', username);
    res.json({ 
      success: true, 
      token, 
      user: { 
        id: user.id, 
        username: user.username, 
        first_name: user.first_name,
        points: user.points 
      } 
    });
  } catch (err) {
    res.status(500).json({ error: 'Errore server' });
  }
});

// ✅ STATS DASHBOARD
app.get('/api/admin/stats', authenticateToken, (req, res) => {
  try {
    const row = db.prepare("SELECT COUNT(*) as total, SUM(points) as total_points FROM customers").get();
    res.json({ total: row.total, total_points: Number(row.total_points) || 0 });
  } catch (err) {
    res.status(500).json({ error: 'Errore stats' });
  }
});

// ✅ LISTA CLIENTI
app.get('/api/admin/customers', authenticateToken, (req, res) => {
  try {
    const rows = db.prepare("SELECT id, first_name, last_name, phone, email, points FROM customers ORDER BY created_at DESC").all();
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Errore lista' });
  }
});

// ✅ AGGIUNGI CLIENTE
app.post('/api/admin/customers', authenticateToken, (req, res) => {
  console.log('➕ Nuovo cliente:', req.body);
  const { first_name, last_name, phone, email, username, password } = req.body;
  
  if (!phone || !username || !password) {
    return res.status(400).json({ error: 'Phone, username e password obbligatori' });
  }
  
  try {
    const hashed = bcrypt.hashSync(password, 10);
    const result = db.prepare(`
      INSERT INTO customers (first_name, last_name, phone, email, username, password) 
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(first_name, last_name, phone, email || null, username, hashed);
    console.log('✅ Cliente aggiunto ID:', result.lastInsertRowid);
    res.json({ id: result.lastInsertRowid, message: 'Cliente aggiunto!' });
  } catch (err) {
    console.error('❌ Errore cliente:', err);
    res.status(400).json({ error: err.message });
  }
});

const listener = app.listen(PORT, () => {
  console.log(`🚀 API live su http://localhost:${PORT}`);
  console.log(`DB: ${DB_PATH}`);
  console.log('🔐 Login: admin/admin123');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM ricevuto, chiusura...');
  listener.close(() => {
    db.close();
    console.log('DB chiuso');
  });
});
