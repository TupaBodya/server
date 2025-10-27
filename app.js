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
app.use('/uploads', express.static('public/uploads'));

// Конфигурация пула подключений к БД
const dbConfig = {
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
  connectionTimeoutMillis: 10000, // Увеличиваем таймаут подключения
  retryDelay: 2000, // Задержка между попытками в миллисекундах
  maxRetries: 3 // Максимальное количество попыток
};

// Функция для создания пула с повторными попытками
const createPoolWithRetry = (config, retries = config.maxRetries) => {
  const pool = new Pool(config);
  
  // Обработчик ошибок подключения
  pool.on('error', (err, client) => {
    console.error('Unexpected error on idle client', err);
  });
  
  return pool;
};

const pool = createPoolWithRetry(dbConfig);

// Функция для проверки подключения с повторными попытками
const connectWithRetry = async (retries = dbConfig.maxRetries, delay = dbConfig.retryDelay) => {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const client = await pool.connect();
      console.log(`✅ Database connection successful (attempt ${attempt}/${retries})`);
      client.release();
      return true;
    } catch (err) {
      console.error(`❌ Database connection failed (attempt ${attempt}/${retries}):`, err.message);
      
      if (attempt < retries) {
        console.log(`🔄 Retrying connection in ${delay/1000} seconds...`);
        await new Promise(resolve => setTimeout(resolve, delay));
        // Увеличиваем задержку для следующей попытки (экспоненциальная backoff)
        delay *= 1.5;
      } else {
        console.error('💥 All connection attempts failed');
        return false;
      }
    }
  }
};

// Функция для выполнения запросов с автоматическими повторными попытками
const queryWithRetry = async (text, params, retries = 3) => {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const result = await pool.query(text, params);
      return result;
    } catch (err) {
      console.error(`Query failed (attempt ${attempt}/${retries}):`, err.message);
      
      // Проверяем, стоит ли повторять запрос (только для определенных ошибок)
      const shouldRetry = [
        'connection', 'connect', 'timeout', 'closed', 'end'
      ].some(keyword => err.message.toLowerCase().includes(keyword));
      
      if (attempt < retries && shouldRetry) {
        const delay = Math.min(1000 * Math.pow(2, attempt - 1), 10000); // Экспоненциальная backoff, максимум 10 секунд
        console.log(`Retrying query in ${delay}ms...`);
        await new Promise(resolve => setTimeout(resolve, delay));
        continue;
      }
      
      throw err; // Если не стоит повторять или попытки закончились
    }
  }
};

// Инициализация подключения к БД при запуске сервера
const initializeDatabase = async () => {
  console.log('🔄 Initializing database connection...');
  
  const isConnected = await connectWithRetry();
  
  if (!isConnected) {
    console.warn('⚠️  Server starting without database connection. Some features may not work.');
    // Сервер продолжает работу, но некоторые функции могут быть недоступны
  }
  
  return isConnected;
};

// Периодическая проверка подключения (каждые 5 минут)
setInterval(async () => {
  try {
    await pool.query('SELECT 1');
    console.log('✅ Database health check: OK');
  } catch (err) {
    console.error('❌ Database health check failed:', err.message);
    // Попытка переподключения
    await connectWithRetry(1, 5000); // Одна быстрая попытка
  }
}, 5 * 60 * 1000); // 5 минут

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = 'public/uploads/avatars';
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

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 5MB limit
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

// Middleware для обработки ошибок БД
const handleDbError = (res, err, operation = 'operation') => {
  console.error(`Database error during ${operation}:`, err);
  
  if (err.message && err.message.includes('connection')) {
    return res.status(503).json({ 
      error: 'Service temporarily unavailable. Please try again later.' 
    });
  }
  
  res.status(500).json({ 
    error: 'Database error',
    details: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
};

// API Routes

// ==================== Auth Routes ====================
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password, group } = req.body;
  
  try {
    // Check if user exists
    const userExists = await queryWithRetry(
      'SELECT * FROM users WHERE username = $1 OR email = $2', 
      [username, email]
    );
    
    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    
    const { rows: [user] } = await queryWithRetry(
      `INSERT INTO users (username, email, password_hash, role) 
       VALUES ($1, $2, $3, 'user') RETURNING *`,
      [username, email, hashedPassword]
    );

    await queryWithRetry(
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
    handleDbError(res, err, 'registration');
  }
});

// Пример для Express.js
app.get('/api/buffet-menu', async (req, res) => {
  try {
    const result = await queryWithRetry(`
      SELECT * FROM buffet_menu 
      WHERE is_available = true 
      ORDER BY category, name
    `);
    res.json(result.rows);
  } catch (error) {
    handleDbError(res, error, 'fetching buffet menu');
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  
  try {
    // Find user
    const { rows: [user] } = await queryWithRetry(
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

    const { rows: [profile] } = await queryWithRetry(
      'SELECT * FROM profiles WHERE user_id = $1', 
      [user.id]
    );

    await queryWithRetry(
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
    handleDbError(res, err, 'login');
  }
});

// ==================== Admin Routes ====================

// -------------------- Users CRUD --------------------
app.get('/api/admin/users', authenticate, isAdmin, async (req, res) => {
  try {
    const { rows } = await queryWithRetry(
      'SELECT id, username, email, role, created_at, updated_at FROM users'
    );
    res.json(rows);
  } catch (err) {
    handleDbError(res, err, 'fetching users');
  }
});

app.put('/api/admin/users/:id/role', authenticate, isAdmin, async (req, res) => {
  const { id } = req.params;
  const { role } = req.body;

  try {
    if (!['admin', 'user'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    const { rows } = await queryWithRetry(
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
    handleDbError(res, err, 'updating user role');
  }
});

app.delete('/api/admin/users/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const { rowCount } = await queryWithRetry(
      'DELETE FROM users WHERE id = $1',
      [req.params.id]
    );
    
    if (rowCount === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ success: true });
  } catch (err) {
    handleDbError(res, err, 'deleting user');
  }
});

// Остальные маршруты аналогично заменяем pool.query на queryWithRetry
// Для краткости покажу только несколько примеров, остальные нужно модифицировать аналогично

app.get('/api/admin/teachers', authenticate, isAdmin, async (req, res) => {
  try {
    const { rows } = await queryWithRetry('SELECT * FROM teachers');
    res.json(rows);
  } catch (err) {
    handleDbError(res, err, 'fetching teachers');
  }
});

app.post('/api/admin/teachers', authenticate, isAdmin, async (req, res) => {
  const { name, surname, patronymic, post } = req.body;
  try {
    const { rows } = await queryWithRetry(
      'INSERT INTO teachers (name, surname, patronymic, post) VALUES ($1, $2, $3, $4) RETURNING *',
      [name, surname, patronymic, post]
    );
    res.json(rows[0]);
  } catch (err) {
    handleDbError(res, err, 'creating teacher');
  }
});

// ... остальные маршруты аналогично модифицируем

// ==================== Public Routes ====================
app.get('/api/groups', async (req, res) => {
  try {
    const { rows } = await queryWithRetry('SELECT * FROM groups');
    res.json(rows);
  } catch (err) {
    handleDbError(res, err, 'fetching groups');
  }
});

app.get('/api/teachers', async (req, res) => {
  try {
    const { rows } = await queryWithRetry('SELECT * FROM teachers');
    res.json(rows);
  } catch (err) {
    handleDbError(res, err, 'fetching teachers');
  }
});

app.get('/api/audiences', async (req, res) => {
  try {
    const { rows } = await queryWithRetry('SELECT * FROM audiences');
    res.json(rows);
  } catch (err) {
    handleDbError(res, err, 'fetching audiences');
  }
});

// Health check endpoint с проверкой БД
app.get('/api/health', async (req, res) => {
  try {
    await queryWithRetry('SELECT 1');
    res.json({ 
      status: 'OK', 
      database: 'Connected',
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(503).json({ 
      status: 'Error', 
      database: 'Disconnected',
      error: 'Database connection failed',
      timestamp: new Date().toISOString()
    });
  }
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('🛑 Shutting down server gracefully...');
  try {
    await pool.end();
    console.log('✅ Database pool closed');
    process.exit(0);
  } catch (err) {
    console.error('❌ Error during shutdown:', err);
    process.exit(1);
  }
});

process.on('SIGTERM', async () => {
  console.log('🛑 Received SIGTERM, shutting down gracefully...');
  try {
    await pool.end();
    console.log('✅ Database pool closed');
    process.exit(0);
  } catch (err) {
    console.error('❌ Error during shutdown:', err);
    process.exit(1);
  }
});

// Замените все остальные вызовы pool.query на queryWithRetry в оставшихся маршрутах
// Например:
app.get('/api/territory/buildings', async (req, res) => {
  try {
    const { rows } = await queryWithRetry('SELECT * FROM buildings ORDER BY name');
    res.json(rows);
  } catch (err) {
    handleDbError(res, err, 'loading buildings');
  }
});

// ... и так для всех остальных маршрутов

if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, 'client/build')));
  
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'client/build', 'index.html'));
  });
}

// Start server с инициализацией БД
const startServer = async () => {
  try {
    // Инициализируем подключение к БД
    await initializeDatabase();
    
    // Запускаем сервер
    app.listen(port, () => {
      console.log(`🚀 Server running on port ${port}`);
      console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`⏰ Started at: ${new Date().toISOString()}`);
    });
  } catch (err) {
    console.error('💥 Failed to start server:', err);
    process.exit(1);
  }
};

startServer();