const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();
const port = process.env.PORT || 3001;
const multer = require('multer');
const fs = require('fs');

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';

// Auth middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
};

// Database connection - Neon
const pool = new Pool({
  user: 'gen_user',
  host: 'c98956375b5e3a754597fbcd.twc1.net',
  database: 'map',
  password: 'Y7_TvHl,5gd8eE',
  port: 5432,
  ssl: {
    rejectUnauthorized: false
  },
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
  maxUses: 10000,
});

// Добавьте обработчики событий пула
pool.on('error', (err, client) => {
  console.error('Unexpected error on idle client', err);
});

pool.on('connect', () => {
  console.log('Database connection established');
});

pool.on('remove', () => {
  console.log('Database connection removed');
});

pool.connect((err, client, release) => {
  if (err) {
    console.error('Error connecting to database:', err.stack);
  } else {
    console.log('Connected to Timeweb database successfully');
    release();
  }
});

process.on('unhandledRejection', (err) => {
  console.error('Unhandled Promise Rejection:', err);
  // Не завершайте процесс в development
  if (process.env.NODE_ENV === 'production') {
    process.exit(1);
  }
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  if (process.env.NODE_ENV === 'production') {
    process.exit(1);
  }
});

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = path.join(__dirname, 'uploads/avatars');
    // Создаем директорию если не существует
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'avatar-' + uniqueSuffix + path.extname(file.originalname));
  }
});

// Обслуживаем статические файлы из папки сервера
app.use('/uploads', express.static(path.join(__dirname, '/uploads')));

const createDirectories = () => {
  const directories = [
    path.join(__dirname, 'uploads/avatars'),
    path.join(__dirname, 'public/img')
  ];
  
  directories.forEach(dir => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
      console.log('Created directory:', dir);
    }
  });
};

createDirectories();

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  },
  fileFilter: function (req, file, cb) {
    // Проверяем что файл является изображением
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

// Маршрут для удаления аватара
app.delete('/api/auth/me/avatar', authenticate, async (req, res) => {
  try {
    // Получаем текущий аватар
    const { rows: [profile] } = await pool.query(
      'SELECT avatar_url FROM profiles WHERE user_id = $1',
      [req.user.id]
    );

    if (profile && profile.avatar_url && profile.avatar_url !== '/img/default-avatar.png') {
      // Удаляем файл аватара
      const avatarPath = path.join(__dirname, 'uploads/avatars', path.basename(profile.avatar_url));
      if (fs.existsSync(avatarPath)) {
        fs.unlinkSync(avatarPath);
      }
    }

    // Устанавливаем аватар по умолчанию
    await pool.query(
      'UPDATE profiles SET avatar_url = $1 WHERE user_id = $2',
      ['/img/default-avatar.png', req.user.id]
    );

    res.json({ 
      success: true, 
      message: 'Аватар удален',
      avatarUrl: '/img/default-avatar.png'
    });

  } catch (err) {
    console.error('Error removing avatar:', err);
    res.status(500).json({ error: 'Ошибка удаления аватара' });
  }
});

function getSearchTypeLabel(type) {
  const types = {
    'audience': 'Аудитория',
    'group': 'Группа', 
    'teacher': 'Преподаватель'
  };
  return types[type] || type;
}

function formatTime(dateString) {
  const date = new Date(dateString);
  return date.toLocaleTimeString('ru-RU', { 
    hour: '2-digit', 
    minute: '2-digit' 
  });
}

const formatDate = (date) => new Date(date).toISOString();

// API Routes

// ==================== Auth Routes ====================
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password, group } = req.body;
  
  try {
    // Check if user exists
    const userExists = await pool.query(
      'SELECT * FROM users WHERE username = $1 OR email = $2', 
      [username, email]
    );
    
    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    
    const { rows: [user] } = await pool.query(
      `INSERT INTO users (username, email, password_hash, role) 
       VALUES ($1, $2, $3, 'user') RETURNING *`,
      [username, email, hashedPassword]
    );

    await pool.query(
      `INSERT INTO profiles (user_id, group_name, bio, settings, last_login, login_count) 
       VALUES ($1, $2, '', '{}', NOW(), 1)`,
      [user.id, group]
    );

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role }, 
      JWT_SECRET, 
      { expiresIn: '1d' }
    );

    res.json({ 
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        group
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Пример для Express.js
app.get('/api/buffet-menu', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM buffet_menu 
      WHERE is_available = true 
      ORDER BY category, name
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching buffet menu:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  
  try {
    // Find user
    const { rows: [user] } = await pool.query(
      'SELECT * FROM users WHERE username = $1', 
      [username]
    );
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const { rows: [profile] } = await pool.query(
      'SELECT * FROM profiles WHERE user_id = $1', 
      [user.id]
    );

    await pool.query(
      'UPDATE profiles SET last_login = NOW(), login_count = COALESCE(login_count, 0) + 1 WHERE user_id = $1',
      [user.id]
    );

    // Generate token
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role }, 
      JWT_SECRET, 
      { expiresIn: '1d' }
    );

    res.json({ 
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        avatar: profile?.avatar_url,
        group: profile?.group_name
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// ==================== Admin Routes ====================

// -------------------- Users CRUD --------------------
app.get('/api/admin/users', authenticate, isAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, username, email, role, created_at, updated_at FROM users'
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.put('/api/admin/users/:id/role', authenticate, isAdmin, async (req, res) => {
  const { id } = req.params;
  const { role } = req.body;

  try {
    if (!['admin', 'user'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    const { rows } = await pool.query(
      `UPDATE users 
       SET role = $1, updated_at = NOW() 
       WHERE id = $2 
       RETURNING id, username, email, role, created_at, updated_at`,
      [role, id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.delete('/api/admin/users/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const { rowCount } = await pool.query(
      'DELETE FROM users WHERE id = $1',
      [req.params.id]
    );
    
    if (rowCount === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// -------------------- Teachers CRUD --------------------
app.get('/api/admin/teachers', authenticate, isAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM teachers');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/admin/teachers', authenticate, isAdmin, async (req, res) => {
  const { name, surname, patronymic, post } = req.body;
  try {
    const { rows } = await pool.query(
      'INSERT INTO teachers (name, surname, patronymic, post) VALUES ($1, $2, $3, $4) RETURNING *',
      [name, surname, patronymic, post]
    );
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/admin/teachers/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM teachers WHERE id = $1', [req.params.id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Teacher not found' });
    }
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.put('/api/admin/teachers/:id', authenticate, isAdmin, async (req, res) => {
  const { name, surname, patronymic, post } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE teachers 
       SET name = $1, surname = $2, patronymic = $3, post = $4 
       WHERE id = $5 RETURNING *`,
      [name, surname, patronymic, post, req.params.id]
    );
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.delete('/api/admin/teachers/:id', authenticate, isAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM teachers WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// -------------------- Groups CRUD --------------------
app.get('/api/admin/groups', authenticate, isAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM groups');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/admin/groups', authenticate, isAdmin, async (req, res) => {
  const { name_group } = req.body;
  try {
    const { rows } = await pool.query(
      'INSERT INTO groups (name_group) VALUES ($1) RETURNING *',
      [name_group]
    );
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/admin/groups/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM groups WHERE id = $1', [req.params.id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Group not found' });
    }
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.put('/api/admin/groups/:id', authenticate, isAdmin, async (req, res) => {
  const { name_group } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE groups SET name_group = $1 WHERE id = $2 RETURNING *`,
      [name_group, req.params.id]
    );
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.delete('/api/admin/groups/:id', authenticate, isAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM groups WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// -------------------- Audiences CRUD --------------------
app.get('/api/admin/audiences', authenticate, isAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM audiences');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/admin/audiences', authenticate, isAdmin, async (req, res) => {
  const { num_audiences, corpus, image1, image2, image3, floor, x, y, width, height, description, audience_type } = req.body;
  
  try {
    // Проверяем, существует ли уже аудитория с таким номером в этом корпусе
    const existing = await pool.query(
      'SELECT * FROM audiences WHERE num_audiences = $1 AND corpus = $2',
      [num_audiences, corpus]
    );
    
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Аудитория с таким номером уже существует в этом корпусе' });
    }

    const { rows } = await pool.query(
      `INSERT INTO audiences (num_audiences, corpus, image1, image2, image3, floor, x, y, width, height, description, audience_type) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *`,
      [num_audiences, corpus, image1, image2, image3, floor, x, y, width, height, description, audience_type]
    );
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});


app.get('/api/admin/audiences/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM audiences WHERE id = $1', [req.params.id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Audience not found' });
    }
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// В PUT /api/admin/audiences/:id
app.put('/api/admin/audiences/:id', authenticate, isAdmin, async (req, res) => {
  const { num_audiences, corpus, image1, image2, image3, floor, x, y, width, height, description, audience_type } = req.body;
  
  try {
    // Проверка на существование дубликата
    const existing = await pool.query(
      'SELECT * FROM audiences WHERE num_audiences = $1 AND corpus = $2 AND id != $3',
      [num_audiences, corpus, req.params.id]
    );
    
    if (existing.rows.length > 0) {
      return res.status(400).json({ 
        error: 'Аудитория с таким номером уже существует в этом корпусе',
        details: existing.rows[0]
      });
    }

    const { rows } = await pool.query(
      `UPDATE audiences 
       SET num_audiences = $1, corpus = $2, image1 = $3, image2 = $4, image3 = $5, 
           floor = $6, x = $7, y = $8, width = $9, height = $10, 
           description = $11, audience_type = $12
       WHERE id = $13 RETURNING *`,
      [num_audiences, corpus, image1, image2, image3, floor, x, y, width, height, 
       description, audience_type, req.params.id]
    );
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Аудитория не найдена' });
    }
    
    res.json(rows[0]);
  } catch (err) {
    console.error('Ошибка при обновлении аудитории:', err);
    res.status(500).json({ 
      error: 'Ошибка базы данных',
      details: err.message,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
  }
});

app.delete('/api/admin/audiences/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const { rowCount } = await pool.query(
      'DELETE FROM audiences WHERE id = $1',
      [req.params.id]
    );
    
    if (rowCount === 0) {
      return res.status(404).json({ error: 'Audience not found' });
    }
    
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// -------------------- Lessons CRUD --------------------
app.get('/api/admin/lessons', authenticate, isAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM lessons');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/admin/lessons', authenticate, isAdmin, async (req, res) => {
  const { name_lesson } = req.body;
  try {
    const { rows } = await pool.query(
      'INSERT INTO lessons (name_lesson) VALUES ($1) RETURNING *',
      [name_lesson]
    );
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/admin/lessons/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM lessons WHERE id = $1', [req.params.id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Lesson not found' });
    }
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.put('/api/admin/lessons/:id', authenticate, isAdmin, async (req, res) => {
  const { name_lesson } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE lessons SET name_lesson = $1 WHERE id = $2 RETURNING *`,
      [name_lesson, req.params.id]
    );
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.delete('/api/admin/lessons/:id', authenticate, isAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM lessons WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// -------------------- Schedule CRUD --------------------
app.get('/api/admin/schedule', authenticate, isAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT s.*, l.name_lesson, t.name, t.surname, g.name_group, a.num_audiences
      FROM schedule s
      LEFT JOIN lessons l ON s.lesson_id = l.id
      LEFT JOIN teachers t ON s.teacher_id = t.id
      LEFT JOIN groups g ON s.group_id = g.id
      LEFT JOIN audiences a ON s.audience_id = a.id
    `);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/admin/schedule', authenticate, isAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT s.*, 
             l.name_lesson, 
             t.name, 
             t.surname, 
             g.name_group, 
             a.num_audiences,
             TO_CHAR(s.time_start, 'HH24:MI') as time_start,
             TO_CHAR(s.time_over, 'HH24:MI') as time_over
      FROM schedule s
      LEFT JOIN lessons l ON s.lesson_id = l.id
      LEFT JOIN teachers t ON s.teacher_id = t.id
      LEFT JOIN groups g ON s.group_id = g.id
      LEFT JOIN audiences a ON s.audience_id = a.id
    `);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/admin/schedule/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT s.*, 
             l.name_lesson, 
             t.name, 
             t.surname, 
             g.name_group, 
             a.num_audiences,
             TO_CHAR(s.time_start, 'HH24:MI') as time_start,
             TO_CHAR(s.time_over, 'HH24:MI') as time_over
      FROM schedule s
      LEFT JOIN lessons l ON s.lesson_id = l.id
      LEFT JOIN teachers t ON s.teacher_id = t.id
      LEFT JOIN groups g ON s.group_id = g.id
      LEFT JOIN audiences a ON s.audience_id = a.id
      WHERE s.id = $1
    `, [req.params.id]);
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Schedule not found' });
    }
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.put('/api/admin/schedule/:id', authenticate, isAdmin, async (req, res) => {
  const { lesson_id, teacher_id, group_id, audience_id, time_start, time_over, day_week } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE schedule 
       SET lesson_id = $1, teacher_id = $2, group_id = $3, audience_id = $4, 
           time_start = $5, time_over = $6, day_week = $7
       WHERE id = $8 RETURNING *`,
      [lesson_id, teacher_id, group_id, audience_id, time_start, time_over, day_week, req.params.id]
    );
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.delete('/api/admin/schedule/:id', authenticate, isAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM schedule WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// ==================== Public Routes ====================
// Получение списка групп (публичный)
app.get('/api/groups', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM groups');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Получение списка преподавателей (публичный)
app.get('/api/teachers', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM teachers');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Получение аудиторий (публичный)
app.get('/api/audiences', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM audiences');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Получение предметов (публичный)
app.get('/api/lessons', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM lessons');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Получение расписания для аудитории (публичный)
app.get('/api/schedule/:audienceId', async (req, res) => {
  const { audienceId } = req.params;
  try {
    const { rows } = await pool.query(`
      SELECT s.*, 
             l.name_lesson, 
             t.name, 
             t.surname, 
             t.patronymic, 
             g.name_group,
             TO_CHAR(s.time_start, 'HH24:MI') as time_start,
             TO_CHAR(s.time_over, 'HH24:MI') as time_over
      FROM schedule s
      JOIN lessons l ON s.lesson_id = l.id
      JOIN teachers t ON s.teacher_id = t.id
      JOIN groups g ON s.group_id = g.id
      WHERE s.audience_id = $1
    `, [audienceId]);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/audiences', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM audiences');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/schedule/group/:groupName', async (req, res) => {
  const { groupName } = req.params;
  try {
    const { rows } = await pool.query(`
      SELECT DISTINCT s.audience_id
      FROM schedule s
      JOIN groups g ON s.group_id = g.id
      WHERE g.name_group ILIKE $1
    `, [`%${groupName}%`]);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/schedule/teacher/:teacherName', async (req, res) => {
  const { teacherName } = req.params;
  try {
    const { rows } = await pool.query(`
      SELECT DISTINCT s.audience_id
      FROM schedule s
      JOIN teachers t ON s.teacher_id = t.id
      WHERE CONCAT(t.surname, ' ', t.name, ' ', t.patronymic) ILIKE $1
    `, [`%${teacherName}%`]);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// ==================== Territory Routes ====================

// Получение всех зданий
app.get('/api/territory/buildings', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM buildings ORDER BY name');
    res.json(rows);
  } catch (err) {
    console.error('Ошибка загрузки зданий:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Получение всех памятников
app.get('/api/territory/landmarks', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM landmarks ORDER BY name');
    res.json(rows);
  } catch (err) {
    console.error('Ошибка загрузки памятников:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Получение расписания спортивного объекта
app.get('/api/sport-schedule/:buildingId', async (req, res) => {
  try {
    const { buildingId } = req.params;
    const { rows } = await pool.query(
      'SELECT * FROM sport_schedule WHERE building_id = $1 ORDER BY day_week, time_start',
      [buildingId]
    );
    res.json(rows);
  } catch (err) {
    console.error('Ошибка загрузки расписания:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Поиск зданий
app.get('/api/territory/buildings/search', async (req, res) => {
  try {
    const { query } = req.query;
    const { rows } = await pool.query(
      `SELECT * FROM buildings 
       WHERE name ILIKE $1 OR description ILIKE $1 
       ORDER BY name`,
      [`%${query}%`]
    );
    res.json(rows);
  } catch (err) {
    console.error('Ошибка поиска зданий:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Поиск памятников
app.get('/api/territory/landmarks/search', async (req, res) => {
  try {
    const { query } = req.query;
    const { rows } = await pool.query(
      `SELECT * FROM landmarks 
       WHERE name ILIKE $1 OR description ILIKE $1 
       ORDER BY name`,
      [`%${query}%`]
    );
    res.json(rows);
  } catch (err) {
    console.error('Ошибка поиска памятников:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// ==================== Admin Routes for Territory ====================

// CRUD для зданий
app.get('/api/admin/buildings', authenticate, isAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM buildings ORDER BY name');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/admin/buildings', authenticate, isAdmin, async (req, res) => {
  const { name, type, corpus, x, y, width, height, description, images } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO buildings (name, type, corpus, x, y, width, height, description, images) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [name, type, corpus, x, y, width, height, description, images]
    );
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.put('/api/admin/buildings/:id', authenticate, isAdmin, async (req, res) => {
  const { name, type, corpus, x, y, width, height, description, images } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE buildings 
       SET name = $1, type = $2, corpus = $3, x = $4, y = $5, width = $6, height = $7, 
           description = $8, images = $9, updated_at = NOW()
       WHERE id = $10 RETURNING *`,
      [name, type, corpus, x, y, width, height, description, images, req.params.id]
    );
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.delete('/api/admin/buildings/:id', authenticate, isAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM buildings WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// CRUD для памятников
app.get('/api/admin/landmarks', authenticate, isAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM landmarks ORDER BY name');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/admin/landmarks', authenticate, isAdmin, async (req, res) => {
  const { name, type, x, y, radius, description, year, images } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO landmarks (name, type, x, y, radius, description, year, images) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [name, type, x, y, radius, description, year, images]
    );
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.put('/api/admin/landmarks/:id', authenticate, isAdmin, async (req, res) => {
  const { name, type, x, y, radius, description, year, images } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE landmarks 
       SET name = $1, type = $2, x = $3, y = $4, radius = $5, 
           description = $6, year = $7, images = $8, updated_at = NOW()
       WHERE id = $9 RETURNING *`,
      [name, type, x, y, radius, description, year, images, req.params.id]
    );
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.delete('/api/admin/landmarks/:id', authenticate, isAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM landmarks WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// CRUD для спортивного расписания
app.get('/api/admin/sport-schedule', authenticate, isAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT ss.*, b.name as building_name 
      FROM sport_schedule ss
      LEFT JOIN buildings b ON ss.building_id = b.id
      ORDER BY ss.day_week, ss.time_start
    `);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/admin/sport-schedule', authenticate, isAdmin, async (req, res) => {
  const { building_id, sport_type, coach, group_name, day_week, time_start, time_over } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO sport_schedule (building_id, sport_type, coach, group_name, day_week, time_start, time_over) 
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [building_id, sport_type, coach, group_name, day_week, time_start, time_over]
    );
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.put('/api/admin/sport-schedule/:id', authenticate, isAdmin, async (req, res) => {
  const { building_id, sport_type, coach, group_name, day_week, time_start, time_over } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE sport_schedule 
       SET building_id = $1, sport_type = $2, coach = $3, group_name = $4, 
           day_week = $5, time_start = $6, time_over = $7, updated_at = NOW()
       WHERE id = $8 RETURNING *`,
      [building_id, sport_type, coach, group_name, day_week, time_start, time_over, req.params.id]
    );
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.delete('/api/admin/sport-schedule/:id', authenticate, isAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM sport_schedule WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// ==================== 3D Coordinates CRUD ====================

app.get('/api/admin/audiences-3d', authenticate, isAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT ac.*, a.num_audiences, a.corpus as audience_corpus, a.floor as audience_floor
      FROM audience_3d_coordinates ac
      JOIN audiences a ON ac.audience_id = a.id
      ORDER BY a.corpus, a.floor, a.num_audiences
    `);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/admin/audiences-3d', authenticate, isAdmin, async (req, res) => {
  const {
    audience_id, corpus, floor, position_x, position_y, position_z,
    rotation_x, rotation_y, rotation_z, scale_x, scale_y, scale_z, model_type
  } = req.body;
  
  try {
    const { rows } = await pool.query(`
      INSERT INTO audience_3d_coordinates 
      (audience_id, corpus, floor, position_x, position_y, position_z,
       rotation_x, rotation_y, rotation_z, scale_x, scale_y, scale_z, model_type)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      RETURNING *
    `, [
      audience_id, corpus, floor, position_x, position_y, position_z,
      rotation_x || 0, rotation_y || 0, rotation_z || 0,
      scale_x || 1, scale_y || 1, scale_z || 1, model_type || 'box'
    ]);
    
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.put('/api/admin/audiences-3d/:id', authenticate, isAdmin, async (req, res) => {
  const { id } = req.params;
  const {
    position_x, position_y, position_z,
    rotation_x, rotation_y, rotation_z,
    scale_x, scale_y, scale_z, model_type
  } = req.body;
  
  try {
    const { rows } = await pool.query(`
      UPDATE audience_3d_coordinates 
      SET position_x = $1, position_y = $2, position_z = $3,
          rotation_x = $4, rotation_y = $5, rotation_z = $6,
          scale_x = $7, scale_y = $8, scale_z = $9,
          model_type = $10, updated_at = CURRENT_TIMESTAMP
      WHERE id = $11
      RETURNING *
    `, [
      position_x, position_y, position_z,
      rotation_x, rotation_y, rotation_z,
      scale_x, scale_y, scale_z, model_type, id
    ]);
    
    if (rows.length === 0) {
      return res.status(404).json({ error: '3D coordinates not found' });
    }
    
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.delete('/api/admin/audiences-3d/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const { rowCount } = await pool.query(
      'DELETE FROM audience_3d_coordinates WHERE id = $1',
      [req.params.id]
    );
    
    if (rowCount === 0) {
      return res.status(404).json({ error: '3D coordinates not found' });
    }
    
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Получение 3D координат аудиторий для конкретного корпуса и этажа
app.get('/api/audiences-3d/:corpus/:floor', async (req, res) => {
  const { corpus, floor } = req.params;
  
  try {
    const { rows } = await pool.query(`
      SELECT ac.*, a.num_audiences, a.audience_type, a.description
      FROM audience_3d_coordinates ac
      JOIN audiences a ON ac.audience_id = a.id
      WHERE ac.corpus = $1 AND ac.floor = $2
      ORDER BY a.num_audiences
    `, [corpus, floor]);
    
    res.json(rows);
  } catch (err) {
    console.error('Ошибка загрузки 3D координат:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/auth/me', authenticate, async (req, res) => {
  try {
    const { rows: [user] } = await pool.query(
      'SELECT id, username, email, role FROM users WHERE id = $1', 
      [req.user.id]
    );
    
    const { rows: [profile] } = await pool.query(
      'SELECT * FROM profiles WHERE user_id = $1', 
      [req.user.id]
    );

    res.json({
      ...user,
      avatar: profile?.avatar_url,
      group: profile?.group_name
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch user data' });
  }
});

app.put('/api/auth/me', authenticate, async (req, res) => {
  const { username, email, group, bio } = req.body;
  
  try {
    // Проверяем уникальность username и email
    if (username !== req.user.username) {
      const existingUser = await pool.query(
        'SELECT id FROM users WHERE username = $1 AND id != $2',
        [username, req.user.id]
      );
      if (existingUser.rows.length > 0) {
        return res.status(400).json({ error: 'Username already taken' });
      }
    }

    if (email !== req.user.email) {
      const existingEmail = await pool.query(
        'SELECT id FROM users WHERE email = $1 AND id != $2',
        [email, req.user.id]
      );
      if (existingEmail.rows.length > 0) {
        return res.status(400).json({ error: 'Email already registered' });
      }
    }

    // Обновляем пользователя
    const { rows: [updatedUser] } = await pool.query(
      `UPDATE users 
       SET username = $1, email = $2, updated_at = NOW() 
       WHERE id = $3 
       RETURNING id, username, email, role, created_at, updated_at`,
      [username, email, req.user.id]
    );

    // Обновляем профиль
    await pool.query(
      `UPDATE profiles 
       SET group_name = $1, bio = $2, updated_at = NOW()
       WHERE user_id = $3`,
      [group, bio, req.user.id]
    );

    // Получаем обновленные данные профиля
    const { rows: [profile] } = await pool.query(
      'SELECT * FROM profiles WHERE user_id = $1',
      [req.user.id]
    );

    res.json({
      ...updatedUser,
      avatar: profile?.avatar_url,
      group: profile?.group_name,
      bio: profile?.bio
    });
  } catch (err) {
    console.error('Error updating profile:', err);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Обновление пароля
app.put('/api/auth/me/password', authenticate, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  
  try {
    const { rows: [user] } = await pool.query(
      'SELECT * FROM users WHERE id = $1', 
      [req.user.id]
    );
    
    const validPassword = await bcrypt.compare(currentPassword, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Неверный текущий пароль' });
    }
    
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query(
      'UPDATE users SET password_hash = $1 WHERE id = $2',
      [hashedPassword, req.user.id]
    );
    
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка обновления пароля' });
  }
});

app.put('/api/auth/me', authenticate, async (req, res) => {
  const { username, email, group, bio } = req.body;
  
  try {
    // Проверяем уникальность username и email
    if (username !== req.user.username) {
      const existingUser = await pool.query(
        'SELECT id FROM users WHERE username = $1 AND id != $2',
        [username, req.user.id]
      );
      if (existingUser.rows.length > 0) {
        return res.status(400).json({ error: 'Username already taken' });
      }
    }

    if (email !== req.user.email) {
      const existingEmail = await pool.query(
        'SELECT id FROM users WHERE email = $1 AND id != $2',
        [email, req.user.id]
      );
      if (existingEmail.rows.length > 0) {
        return res.status(400).json({ error: 'Email already registered' });
      }
    }

    // Обновляем пользователя
    const { rows: [updatedUser] } = await pool.query(
      `UPDATE users 
       SET username = $1, email = $2, updated_at = NOW() 
       WHERE id = $3 
       RETURNING id, username, email, role, created_at, updated_at`,
      [username, email, req.user.id]
    );

    // Обновляем профиль
    await pool.query(
      `UPDATE profiles 
       SET group_name = $1, bio = $2, updated_at = NOW()
       WHERE user_id = $3`,
      [group, bio, req.user.id]
    );

    // Получаем обновленные данные профиля
    const { rows: [profile] } = await pool.query(
      'SELECT * FROM profiles WHERE user_id = $1',
      [req.user.id]
    );

    res.json({
      ...updatedUser,
      avatar: profile?.avatar_url,
      group: profile?.group_name,
      bio: profile?.bio
    });
  } catch (err) {
    console.error('Error updating profile:', err);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Обновление настроек
app.put('/api/auth/me/settings', authenticate, async (req, res) => {
  const settings = req.body;
  
  try {
    await pool.query(
      'UPDATE profiles SET settings = $1 WHERE user_id = $2',
      [JSON.stringify(settings), req.user.id]
    );
    
    res.json({ success: true });
  } catch (err) {
    console.error('Error saving settings:', err);
    res.status(500).json({ error: 'Failed to save settings' });
  }
});

app.get('/api/auth/me/full', authenticate, async (req, res) => {
  try {
    const { rows: [user] } = await pool.query(
      `SELECT u.id, u.username, u.email, u.role, u.created_at, u.updated_at,
              p.avatar_url, p.group_name, p.bio, p.settings, p.last_login, p.login_count
       FROM users u
       LEFT JOIN profiles p ON u.id = p.user_id
       WHERE u.id = $1`,
      [req.user.id]
    );
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    console.log('Sending user data to client:', {
      id: user.id,
      username: user.username,
      avatar_url: user.avatar_url
    });
    
    res.json(user);
  } catch (err) {
    console.error('Error fetching full profile:', err);
    res.status(500).json({ error: 'Failed to fetch profile data' });
  }
});

// Удаление аккаунта
app.delete('/api/auth/me', authenticate, async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [req.user.id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка удаления аккаунта' });
  }
});

app.post('/api/auth/me/avatar', authenticate, upload.single('avatar'), async (req, res) => {
  try {
    console.log('Avatar upload started...');
    
    if (!req.file) {
      console.log('No file received');
      return res.status(400).json({ error: 'Файл не загружен' });
    }

    console.log('File received:', req.file);

    // Проверяем тип файла
    if (!req.file.mimetype.startsWith('image/')) {
      // Удаляем загруженный файл
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: 'Можно загружать только изображения' });
    }

    // Генерируем относительный URL для аватара
    const avatarUrl = `/uploads/avatars/${req.file.filename}`;
    console.log('Generated avatar URL:', avatarUrl);

    // Получаем старый аватар перед обновлением
    const { rows: [oldProfile] } = await pool.query(
      'SELECT avatar_url FROM profiles WHERE user_id = $1',
      [req.user.id]
    );

    // Обновляем аватар в базе данных
    const updateResult = await pool.query(
      'UPDATE profiles SET avatar_url = $1 WHERE user_id = $2 RETURNING avatar_url',
      [avatarUrl, req.user.id]
    );

    console.log('Database updated:', updateResult.rows[0]);

    // Удаляем старый аватар, если он не дефолтный
    if (oldProfile && oldProfile.avatar_url && 
        oldProfile.avatar_url !== '/img/default-avatar.png' &&
        oldProfile.avatar_url !== avatarUrl) {
      try {
        const oldAvatarPath = path.join(__dirname, 'uploads/avatars', path.basename(oldProfile.avatar_url));
        if (fs.existsSync(oldAvatarPath)) {
          fs.unlinkSync(oldAvatarPath);
          console.log('Old avatar deleted:', oldAvatarPath);
        }
      } catch (deleteErr) {
        console.error('Error deleting old avatar:', deleteErr);
        // Продолжаем выполнение даже если удаление старого аватара не удалось
      }
    }

    res.json({ 
      success: true, 
      avatarUrl: avatarUrl,
      message: 'Аватар успешно обновлен' 
    });

  } catch (err) {
    console.error('Error in avatar upload:', err);
    
    // Удаляем загруженный файл в случае ошибки
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    
    res.status(500).json({ 
      error: 'Ошибка загрузки аватара',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});


// Маршрут для удаления аватара
app.delete('/api/auth/me/avatar', authenticate, async (req, res) => {
  try {
    const { rows: [profile] } = await pool.query(
      'SELECT avatar_url FROM profiles WHERE user_id = $1',
      [req.user.id]
    );

    // Удаляем файл аватара если он не дефолтный
    if (profile.avatar_url && profile.avatar_url !== '/img/default-avatar.png') {
      const avatarPath = path.join(__dirname, 'uploads/avatars', path.basename(profile.avatar_url));
      if (fs.existsSync(avatarPath)) {
        fs.unlinkSync(avatarPath);
      }
    }

    // Устанавливаем дефолтный аватар
    await pool.query(
      'UPDATE profiles SET avatar_url = $1 WHERE user_id = $2',
      ['/img/default-avatar.png', req.user.id]
    );

    res.json({ 
      success: true, 
      message: 'Avatar removed successfully',
      avatarUrl: '/img/default-avatar.png'
    });
  } catch (err) {
    console.error('Error removing avatar:', err);
    res.status(500).json({ error: 'Failed to remove avatar' });
  }
});

// Health check endpoint
// Улучшенный health check
app.get('/api/health', async (req, res) => {
  try {
    const client = await pool.connect();
    try {
      await client.query('SELECT 1');
      res.json({ 
        status: 'OK', 
        database: 'Connected',
        timestamp: new Date().toISOString()
      });
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('Health check failed:', err);
    res.status(500).json({ 
      status: 'Error', 
      database: 'Disconnected',
      error: err.message 
    });
  }
});

if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, 'client/build')));
  
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'client/build', 'index.html'));
  });
}

app.get('/api/audiences-3d/:corpus/:floor', async (req, res) => {
  const { corpus, floor } = req.params;
  
  try {
    const tableExists = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'audience_3d_coordinates'
      )
    `);
    
    if (!tableExists.rows[0].exists) {
      return res.status(200).json([]);
    }

    const { rows } = await pool.query(`
      SELECT ac.*, a.num_audiences, a.audience_type, a.description
      FROM audience_3d_coordinates ac
      JOIN audiences a ON ac.audience_id = a.id
      WHERE ac.corpus = $1 AND ac.floor = $2
      ORDER BY a.num_audiences
    `, [corpus, floor]);
    
    res.json(rows);
  } catch (err) {
    console.error('Ошибка загрузки 3D координат:', err);
    res.status(200).json([]);
  }
});


// Получение статистики пользователя
app.get('/api/profile/stats', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Получаем общее количество поисков
    const searchCount = await pool.query(
      'SELECT COUNT(*) FROM search_history WHERE user_id = $1',
      [userId]
    );
    
    // Получаем количество поисков за неделю
    const weekSearchCount = await pool.query(
      'SELECT COUNT(*) FROM search_history WHERE user_id = $1 AND created_at >= NOW() - INTERVAL \'7 days\'',
      [userId]
    );
    
    // Получаем количество избранных аудиторий
    const favoriteCount = await pool.query(
      'SELECT COUNT(*) FROM favorite_audiences WHERE user_id = $1',
      [userId]
    );
    
    res.json({
      totalSearches: parseInt(searchCount.rows[0].count),
      thisWeekSearches: parseInt(weekSearchCount.rows[0].count),
      favoriteAudiences: parseInt(favoriteCount.rows[0].count)
    });
  } catch (err) {
    console.error('Error fetching profile stats:', err);
    res.status(500).json({ error: 'Failed to fetch profile statistics' });
  }
});

// Получение последней активности
app.get('/api/profile/activity', authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, activity_type, description, metadata, created_at 
       FROM user_activity 
       WHERE user_id = $1 
       ORDER BY created_at DESC 
       LIMIT 10`,
      [req.user.id]
    );
    
    // Форматируем активность для фронтенда
    const formattedActivity = rows.map(activity => {
      let icon = 'fas fa-info-circle';
      let description = activity.description;
      
      switch (activity.activity_type) {
        case 'search':
          icon = 'fas fa-search';
          break;
        case 'favorite':
          icon = 'fas fa-star';
          break;
        case 'navigation':
          icon = 'fas fa-map-marker-alt';
          break;
        case 'profile_update':
          icon = 'fas fa-user-edit';
          break;
      }
      
      return {
        id: activity.id,
        icon: icon,
        description: description,
        time: formatRelativeTime(activity.created_at)
      };
    });
    
    res.json(formattedActivity);
  } catch (err) {
    console.error('Error fetching user activity:', err);
    res.status(500).json({ error: 'Failed to fetch user activity' });
  }
});

function formatRelativeTime(dateString) {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now - date;
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);
  
  if (diffMins < 1) return 'только что';
  if (diffMins < 60) return `${diffMins} минут назад`;
  if (diffHours < 24) return `${diffHours} часов назад`;
  if (diffDays === 1) return 'вчера';
  if (diffDays < 7) return `${diffDays} дней назад`;
  
  return date.toLocaleDateString('ru-RU');
}

// Добавление активности
app.post('/api/profile/activity', authenticate, async (req, res) => {
  const { activity_type, description, metadata } = req.body;
  
  try {
    await pool.query(
      'INSERT INTO user_activity (user_id, activity_type, description, metadata) VALUES ($1, $2, $3, $4)',
      [req.user.id, activity_type, description, metadata]
    );
    
    res.json({ success: true });
  } catch (err) {
    console.error('Error logging activity:', err);
    // Не отправляем ошибку клиенту, так как это не критично
    res.json({ success: false });
  }
});

// Избранные аудитории
app.get('/api/profile/favorites', authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT fa.*, a.num_audiences, a.corpus, a.floor, a.description as audience_description
       FROM favorite_audiences fa
       JOIN audiences a ON fa.audience_id = a.id
       WHERE fa.user_id = $1
       ORDER BY fa.created_at DESC`,
      [req.user.id]
    );
    
    res.json(rows);
  } catch (err) {
    console.error('Error fetching favorites:', err);
    res.status(500).json({ error: 'Failed to fetch favorites' });
  }
});

app.post('/api/profile/favorites', authenticate, async (req, res) => {
  const { audience_id } = req.body;
  
  try {
    const { rows } = await pool.query(
      `INSERT INTO favorite_audiences (user_id, audience_id) 
       VALUES ($1, $2) 
       ON CONFLICT (user_id, audience_id) DO NOTHING
       RETURNING *`,
      [req.user.id, audience_id]
    );
    
    res.json({ success: true, favorite: rows[0] });
  } catch (err) {
    console.error('Error adding favorite:', err);
    res.status(500).json({ error: 'Failed to add favorite' });
  }
});

app.delete('/api/profile/favorites/:audience_id', authenticate, async (req, res) => {
  const { audience_id } = req.params;
  
  try {
    await pool.query(
      'DELETE FROM favorite_audiences WHERE user_id = $1 AND audience_id = $2',
      [req.user.id, audience_id]
    );
    
    res.json({ success: true });
  } catch (err) {
    console.error('Error removing favorite:', err);
    res.status(500).json({ error: 'Failed to remove favorite' });
  }
});

app.get('/api/profile/search-history', authenticate, async (req, res) => {
  try {
    console.log('Fetching search history for user:', req.user.id);
    
    const { rows } = await pool.query(
      `SELECT id, search_type, query, results_count, corpus, floor, created_at 
       FROM search_history 
       WHERE user_id = $1 
       ORDER BY created_at DESC 
       LIMIT 20`,
      [req.user.id]
    );
    
    console.log('Found search history items:', rows.length);
    res.json(rows);
  } catch (err) {
    console.error('Error fetching search history:', err);
    res.status(500).json({ error: 'Failed to fetch search history' });
  }
});

// Сохранение истории поиска
app.post('/api/profile/search-history', authenticate, async (req, res) => {
  const { search_type, query, results_count, corpus, floor } = req.body;
  
  console.log('Saving search history:', { 
    user_id: req.user.id, 
    search_type, 
    query, 
    results_count, 
    corpus, 
    floor 
  });
  
  try {
    const result = await pool.query(
      `INSERT INTO search_history (user_id, search_type, query, results_count, corpus, floor) 
       VALUES ($1, $2, $3, $4, $5, $6) 
       RETURNING *`,
      [req.user.id, search_type, query, results_count || 0, corpus, floor]
    );
    
    console.log('Saved search history:', result.rows[0]);
    res.json({ success: true, savedItem: result.rows[0] });
  } catch (err) {
    console.error('Error saving search history:', err);
    res.status(500).json({ error: 'Failed to save search history' });
  }
});

// Удаление всей истории поиска пользователя
app.delete('/api/profile/search-history', authenticate, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM search_history WHERE user_id = $1',
      [req.user.id]
    );
    
    res.json({ success: true });
  } catch (err) {
    console.error('Error clearing search history:', err);
    res.status(500).json({ error: 'Failed to clear search history' });
  }
});

// Удаление конкретной записи истории поиска
app.delete('/api/profile/search-history/:id', authenticate, async (req, res) => {
  try {
    const { rowCount } = await pool.query(
      'DELETE FROM search_history WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );
    
    if (rowCount === 0) {
      return res.status(404).json({ error: 'Search history item not found' });
    }
    
    res.json({ success: true });
  } catch (err) {
    console.error('Error deleting search history item:', err);
    res.status(500).json({ error: 'Failed to delete search history item' });
  }
});

app.get('/api/search/popular', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT query, search_type, COUNT(*) as search_count
       FROM search_history 
       WHERE created_at >= NOW() - INTERVAL '30 days'
       GROUP BY query, search_type
       ORDER BY search_count DESC
       LIMIT 10`
    );
    
    res.json(rows);
  } catch (err) {
    console.error('Error fetching popular searches:', err);
    res.status(500).json({ error: 'Failed to fetch popular searches' });
  }
});

// Обновление последнего входа
app.post('/api/profile/update-last-login', authenticate, async (req, res) => {
  try {
    await pool.query(
      `UPDATE profiles 
       SET last_login = NOW(), login_count = COALESCE(login_count, 0) + 1 
       WHERE user_id = $1`,
      [req.user.id]
    );
    
    res.json({ success: true });
  } catch (err) {
    console.error('Error updating last login:', err);
    // Не отправляем ошибку клиенту
    res.json({ success: false });
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});