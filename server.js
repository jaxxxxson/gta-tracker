const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        expires_at TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS access_keys (
        id SERIAL PRIMARY KEY,
        key_code VARCHAR(50) UNIQUE NOT NULL,
        duration_days INT NOT NULL,
        is_used BOOLEAN DEFAULT FALSE,
        used_by INT REFERENCES users(id)
      );
    `);
    console.log("Таблицы успешно инициализированы.");
  } catch (err) {
    console.error("Ошибка инициализации БД:", err);
  }
}
initDB();

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username',
      [username, hashedPassword]
    );
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    res.status(400).json({ success: false, message: 'Пользователь уже существует или ошибка данных.' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) return res.status(400).json({ success: false, message: 'Неверный логин или пароль.' });

    const user = result.rows[0];
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(400).json({ success: false, message: 'Неверный логин или пароль.' });

    const now = new Date();
    const hasAccess = user.expires_at && new Date(user.expires_at) > now;

    res.json({ success: true, userId: user.id, username: user.username, hasAccess, expiresAt: user.expires_at });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Ошибка сервера.' });
  }
});

app.post('/api/activate-key', async (req, res) => {
  const { userId, keyCode } = req.body;
  try {
    const keyRes = await pool.query('SELECT * FROM access_keys WHERE key_code = $1 AND is_used = FALSE', [keyCode]);
    if (keyRes.rows.length === 0) return res.status(400).json({ success: false, message: 'Неверный или уже использованный ключ.' });

    const keyData = keyRes.rows[0];
    const userRes = await pool.query('SELECT expires_at FROM users WHERE id = $1', [userId]);
    let baseDate = new Date();
    const currentExp = userRes.rows[0].expires_at;
    if (currentExp && new Date(currentExp) > baseDate) {
      baseDate = new Date(currentExp);
    }
    
    baseDate.setDate(baseDate.getDate() + keyData.duration_days);

    await pool.query('UPDATE users SET expires_at = $1 WHERE id = $2', [baseDate, userId]);
    await pool.query('UPDATE access_keys SET is_used = TRUE, used_by = $1 WHERE id = $2', [userId, keyData.id]);

    res.json({ success: true, expiresAt: baseDate });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Ошибка при активации ключа.' });
  }
});

app.post('/api/admin/create-key', async (req, res) => {
  const { secret, days, keyCode } = req.body;
  if (secret !== 'my_super_secret_admin_pass') return res.status(403).json({ message: 'Доступ запрещен' });
  
  try {
    await pool.query('INSERT INTO access_keys (key_code, duration_days) VALUES ($1, $2)', [keyCode, days]);
    res.json({ success: true, message: `Ключ ${keyCode} на ${days} дней создан!` });
  } catch (err) {
    res.status(400).json({ success: false, message: 'Ключ уже существует.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Сервер запущен на порту ${PORT}`));
