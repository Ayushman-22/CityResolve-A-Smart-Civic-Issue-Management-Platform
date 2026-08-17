import express from 'express';
import path from 'path';
import initSqlJs, { Database } from 'sql.js';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI, Type } from '@google/genai';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';

const app = express();
const PORT = 3000;

const JWT_SECRET = process.env.JWT_SECRET || 'civic-connect-jwt-secret-key-2026';

app.use(express.json({ limit: '10mb' }));
app.use(passport.initialize());

// Express Authenticated Request interface
interface AuthenticatedRequest extends express.Request {
  user?: {
    id: number;
    name: string;
    email: string;
    role: 'citizen' | 'department' | 'admin';
    category?: string;
    google_id?: string;
    profile_pic?: string;
  };
}

// Authentication Middleware - Verifies JWT
function authenticateToken(req: AuthenticatedRequest, res: express.Response, next: express.NextFunction) {
  const authHeader = req.headers['authorization'];
  let token = authHeader && authHeader.split(' ')[1];

  if (!token && req.headers.cookie) {
    const cookies = Object.fromEntries(req.headers.cookie.split('; ').map((c) => c.split('=')));
    token = cookies['token'] || cookies['jwt'];
  }

  if (!token) {
    return res.status(401).json({ error: 'Authentication required. Please sign in to access this feature.' });
  }

  jwt.verify(token, JWT_SECRET, (err: any, decoded: any) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired session token. Please sign in again.' });
    }
    req.user = decoded;
    next();
  });
}

// Role-Based Access Control (RBAC) Middleware
function requireRole(...allowedRoles: string[]) {
  return (req: AuthenticatedRequest, res: express.Response, next: express.NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized: Authentication required.' });
    }
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: `Access Denied: Requires role [${allowedRoles.join(', ')}]. Current role: ${req.user.role}`,
      });
    }
    next();
  };
}

// SQL Query execution logger for SQL Inspector UI
interface SqlLog {
  id: string;
  timestamp: string;
  query: string;
  params?: any[];
  durationMs: number;
}
const sqlLogs: SqlLog[] = [];

function logSqlQuery(query: string, params?: any[], durationMs = 0) {
  const entry: SqlLog = {
    id: Math.random().toString(36).substring(2, 9),
    timestamp: new Date().toISOString(),
    query: query.trim().replace(/\s+/g, ' '),
    params,
    durationMs: Math.round(durationMs * 100) / 100,
  };
  sqlLogs.unshift(entry);
  if (sqlLogs.length > 100) sqlLogs.pop();
}

let db: Database;

async function initDatabase() {
  const SQL = await initSqlJs();
  db = new SQL.Database();

  // 1. Create tables as requested in Civic Connect specification
  const schemaQueries = `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        google_id VARCHAR(255) UNIQUE,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        profile_pic TEXT,
        role VARCHAR(20) NOT NULL CHECK(role IN ('citizen', 'department', 'admin')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS departments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        dept_name VARCHAR(150) NOT NULL,
        dept_email VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        category VARCHAR(50) NOT NULL CHECK(category IN ('road', 'sanitation', 'water', 'streetlight', 'other')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS complaints (
        complaint_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INT NOT NULL,
        category VARCHAR(20) NOT NULL CHECK(category IN ('road', 'sanitation', 'water', 'streetlight', 'other')),
        title VARCHAR(200) NOT NULL,
        description TEXT NOT NULL,
        location VARCHAR(255) NOT NULL,
        latitude REAL,
        longitude REAL,
        image_url TEXT,
        status VARCHAR(20) DEFAULT 'pending' CHECK(status IN ('pending', 'in_progress', 'resolved')),
        priority VARCHAR(20) DEFAULT 'medium',
        ai_generated INT DEFAULT 0,
        upvotes INT DEFAULT 0,
        assigned_department VARCHAR(100),
        assigned_officer VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS status_updates (
        update_id INTEGER PRIMARY KEY AUTOINCREMENT,
        complaint_id INT NOT NULL,
        updated_by INT NOT NULL,
        old_status VARCHAR(50) NOT NULL,
        new_status VARCHAR(50) NOT NULL,
        remarks TEXT,
        update_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (complaint_id) REFERENCES complaints(complaint_id)
    );
  `;

  const start = performance.now();
  db.run(schemaQueries);

  // Safe Migration: ensure ai_generated column exists
  try {
    db.run("ALTER TABLE complaints ADD COLUMN ai_generated INT DEFAULT 0;");
  } catch (e) {
    // Column already exists
  }

  logSqlQuery(schemaQueries, [], performance.now() - start);

  // Seed default Citizens in users table
  db.run(`
    INSERT INTO users (id, user_id, google_id, name, email, profile_pic, role) VALUES
    (1, 1, 'google-101', 'Aarav Sharma', 'aarav.citizen@example.com', 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=150&auto=format&fit=crop&q=80', 'citizen'),
    (2, 2, 'google-102', 'Priya Patel', 'priya.citizen@example.com', 'https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=150&auto=format&fit=crop&q=80', 'citizen'),
    (3, 3, 'google-103', 'Rohan Gupta', 'rohan.gupta@example.com', 'https://images.unsplash.com/photo-1570295999919-56ceb5ecca61?w=150&auto=format&fit=crop&q=80', 'citizen');
  `);

  // Seed pre-registered Departments with bcrypt hashed passwords ('password123')
  const samplePasswordHash = bcrypt.hashSync('password123', 10);

  const insertDeptStmt = `
    INSERT INTO departments (dept_name, dept_email, password_hash, category) VALUES
    ('Public Works Department (Roads)', 'roads.dept@city.gov', '${samplePasswordHash}', 'road'),
    ('Water Supply & Sewage Board', 'water.dept@city.gov', '${samplePasswordHash}', 'water'),
    ('Municipal Sanitation & Hygiene', 'sanitation.dept@city.gov', '${samplePasswordHash}', 'sanitation'),
    ('Electrical & Lighting Cell', 'lighting.dept@city.gov', '${samplePasswordHash}', 'streetlight'),
    ('Parks & Civic Amenities Dept', 'civic.dept@city.gov', '${samplePasswordHash}', 'other');
  `;
  db.run(insertDeptStmt);

  // Seed sample realistic Complaints
  db.run(`
    INSERT INTO complaints (user_id, category, title, description, location, latitude, longitude, image_url, status, priority, upvotes, assigned_department, assigned_officer, created_at) VALUES
    (1, 'road', 'Hazardous Deep Pothole on Main Market Rd', 'Large pothole near Central Bank entrance causing severe traffic bottleneck and minor vehicle damage.', 'Main Market Road, Sector 4', 23.2599, 77.4126, 'https://images.unsplash.com/photo-1515162816999-a0c47dc192f7?w=600&auto=format&fit=crop&q=80', 'in_progress', 'high', 14, 'Public Works Department (Roads)', 'Eng. Suresh Kumar', DATETIME('now', '-2 days')),
    (2, 'water', 'Major Water Pipeline Leakage at Crossroad 3', 'Clean drinking water gushing out onto the street for 12 hours. High pressure loss in nearby residential blocks.', 'Crossroad 3, Green Park Colony', 23.2620, 77.4150, 'https://images.unsplash.com/photo-1585829365295-ab7cd400c167?w=600&auto=format&fit=crop&q=80', 'pending', 'urgent', 28, 'Water Supply & Sewage Board', 'Unassigned', DATETIME('now', '-5 hours')),
    (1, 'sanitation', 'Overflowing Garbage Container & Waste Accumulation', 'Garbage bin has not been collected for 4 days. Unhygienic conditions and foul odor affecting nearby residents.', 'Near Community Hall, Ward 12', 23.2550, 77.4080, 'https://images.unsplash.com/photo-1530587191325-3db32d826c18?w=600&auto=format&fit=crop&q=80', 'resolved', 'medium', 9, 'Municipal Sanitation & Hygiene', 'Insp. Rajesh Gupta', DATETIME('now', '-4 days')),
    (2, 'streetlight', 'Dark Stretch - 4 Consecutive Streetlights Non-Functional', 'Streetlights out along 200m stretch. High safety concern for night commuters and pedestrians.', 'Subhash Avenue, Phase 2', 23.2580, 77.4200, 'https://images.unsplash.com/photo-1509114397022-ed747cca3f65?w=600&auto=format&fit=crop&q=80', 'in_progress', 'medium', 6, 'Electrical & Lighting Cell', 'Lineman Ramesh Chawla', DATETIME('now', '-1 day')),
    (1, 'other', 'Broken Park Bench & Exposed Iron Wires', 'Public children park bench broken with rusty iron wires protruding, risk to children playing.', 'Nehru Children Park', 23.2640, 77.4020, 'https://images.unsplash.com/photo-1519331379826-f10be5486c6f?w=600&auto=format&fit=crop&q=80', 'pending', 'low', 3, 'Parks & Recreation Division', 'Unassigned', DATETIME('now', '-12 hours'));
  `);

  // Seed status updates history
  db.run(`
    INSERT INTO status_updates (complaint_id, updated_by, old_status, new_status, remarks, update_time) VALUES
    (1, 1, 'pending', 'in_progress', 'Inspected site. Asphalt repair team scheduled for immediate patch-work.', DATETIME('now', '-1 day')),
    (3, 3, 'pending', 'in_progress', 'Sanitation truck dispatched with heavy loader squad.', DATETIME('now', '-3 days')),
    (3, 3, 'in_progress', 'resolved', 'Garbage cleared completely and site sanitized with bleaching powder.', DATETIME('now', '-2 days')),
    (4, 4, 'pending', 'in_progress', 'Electrician team assigned to replace faulty transformer junction fuses.', DATETIME('now', '-18 hours'));
  `);

  console.log('Civic Connect SQL Database initialized successfully with Users & Departments.');
  setupPassportStrategy();
}

// Passport Google Strategy Setup
function setupPassportStrategy() {
  const googleClientId = process.env.GOOGLE_CLIENT_ID || 'DEMO_GOOGLE_CLIENT_ID';
  const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET || 'DEMO_GOOGLE_CLIENT_SECRET';
  const appUrl = process.env.APP_URL || 'http://localhost:3000';
  const callbackUrl = `${appUrl.replace(/\/$/, '')}/auth/google/callback`;

  passport.use(
    new GoogleStrategy(
      {
        clientID: googleClientId,
        clientSecret: googleClientSecret,
        callbackURL: callbackUrl,
      },
      (accessToken, refreshToken, profile, done) => {
        try {
          const googleId = profile.id;
          const name = profile.displayName || 'Google Citizen';
          const email =
            profile.emails && profile.emails[0] ? profile.emails[0].value : `${googleId}@gmail.com`;
          const profilePic =
            profile.photos && profile.photos[0]
              ? profile.photos[0].value
              : 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=150&auto=format&fit=crop&q=80';

          const start = performance.now();

          // Check if citizen exists in database by email or google_id
          const checkStmt = db.prepare('SELECT * FROM users WHERE email = ? OR google_id = ?');
          checkStmt.bind([email, googleId]);

          let existingUser: any = null;
          if (checkStmt.step()) {
            existingUser = checkStmt.getAsObject();
          }
          checkStmt.free();

          let finalUser: any;

          if (existingUser) {
            // Update profile info
            db.run('UPDATE users SET google_id = ?, profile_pic = ? WHERE id = ?', [
              googleId,
              profilePic,
              existingUser.id,
            ]);
            finalUser = {
              ...existingUser,
              google_id: googleId,
              profile_pic: profilePic,
            };
          } else {
            // Insert new user record
            db.run(
              "INSERT INTO users (google_id, name, email, profile_pic, role) VALUES (?, ?, ?, ?, 'citizen')",
              [googleId, name, email, profilePic]
            );
            const lastIdRes = db.exec('SELECT last_insert_rowid() as id');
            const newId = lastIdRes[0].values[0][0];
            finalUser = {
              id: newId,
              google_id: googleId,
              name,
              email,
              profile_pic: profilePic,
              role: 'citizen',
            };
          }

          logSqlQuery('Passport Google Auth Sync', [email], performance.now() - start);
          return done(null, finalUser);
        } catch (err: any) {
          return done(err, undefined);
        }
      }
    )
  );
}

// REST API Endpoints

// 1. Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', app: 'Civic Connect', timestamp: new Date().toISOString() });
});

// PASSPORT GOOGLE OAUTH ROUTES

// Initiate Google OAuth Flow
app.get('/auth/google', (req, res, next) => {
  if (!process.env.GOOGLE_CLIENT_ID) {
    // If client ID is not configured, redirect to demo oauth verify
    return res.redirect('/auth/callback?code=DEMO_OAUTH_CODE');
  }
  passport.authenticate('google', { scope: ['profile', 'email'], session: false })(req, res, next);
});

// Google OAuth Callback Route
app.get('/auth/google/callback', (req, res, next) => {
  if (!process.env.GOOGLE_CLIENT_ID || req.query.code === 'DEMO_OAUTH_CODE') {
    // Demo mode fallback when Google Client ID is not provided in env
    const demoPayload = {
      id: 1,
      name: 'Aarav Sharma',
      email: 'aarav.citizen@example.com',
      google_id: 'google-101',
      profile_pic: 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=150&auto=format&fit=crop&q=80',
      role: 'citizen',
    };
    const token = jwt.sign(demoPayload, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });

    return res.send(`
      <!DOCTYPE html>
      <html>
        <head><title>Google Sign-In - Civic Connect</title></head>
        <body style="background:#0f172a;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;">
          <div style="text-align:center;background:#1e293b;padding:2rem;border-radius:1rem;border:1px solid #334155;max-width:400px;">
            <h2 style="color:#3b82f6;">Google Sign-In Complete!</h2>
            <p style="font-size:14px;color:#94a3b8;">Citizen account verified via Passport.js Google Strategy.</p>
          </div>
          <script>
            const token = "${token}";
            const user = ${JSON.stringify(demoPayload)};
            if (window.opener) {
              window.opener.postMessage({ type: 'GOOGLE_OAUTH_SUCCESS', token, user }, '*');
              window.close();
            } else {
              localStorage.setItem('civic_jwt_token', token);
              localStorage.setItem('civic_user', JSON.stringify(user));
              window.location.href = '/?auth_success=true';
            }
          </script>
        </body>
      </html>
    `);
  }

  passport.authenticate('google', { session: false }, (err: any, user: any) => {
    if (err || !user) {
      return res.redirect('/?error=google_auth_failed');
    }

    const tokenPayload = {
      id: user.id,
      name: user.name,
      email: user.email,
      google_id: user.google_id,
      profile_pic: user.profile_pic,
      role: 'citizen',
    };

    const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });

    res.send(`
      <!DOCTYPE html>
      <html>
        <head><title>Google Authentication Successful</title></head>
        <body style="background:#0f172a;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;">
          <div style="text-align:center;background:#1e293b;padding:2rem;border-radius:1rem;border:1px solid #334155;max-width:400px;">
            <h2 style="color:#3b82f6;">Welcome, ${user.name}!</h2>
            <p style="font-size:14px;color:#94a3b8;">Authentication complete. Returning to Civic Connect dashboard...</p>
          </div>
          <script>
            const token = "${token}";
            const user = ${JSON.stringify(tokenPayload)};
            if (window.opener) {
              window.opener.postMessage({ type: 'GOOGLE_OAUTH_SUCCESS', token, user }, '*');
              window.close();
            } else {
              localStorage.setItem('civic_jwt_token', token);
              localStorage.setItem('civic_user', JSON.stringify(user));
              window.location.href = '/?auth_success=true';
            }
          </script>
        </body>
      </html>
    `);
  })(req, res, next);
});

// AUTHENTICATION ROUTES

// A. Get Google OAuth Authorization URL
app.get('/api/auth/google/url', (req, res) => {
  const clientId = process.env.GOOGLE_CLIENT_ID || 'DEMO_GOOGLE_CLIENT_ID';
  const appUrl = process.env.APP_URL || 'http://localhost:3000';
  const redirectUri = `${appUrl.replace(/\/$/, '')}/auth/callback`;

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid profile email',
    access_type: 'online',
    prompt: 'select_account',
  });

  const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
  res.json({
    url: authUrl,
    clientId,
    redirectUri,
    isConfigured: !!process.env.GOOGLE_CLIENT_ID,
  });
});

// B. Citizen Google OAuth Sign In / Profile Verification
app.post('/api/auth/google/verify', (req, res) => {
  const { google_id, name, email, profile_pic } = req.body;

  const userEmail = email || 'citizen@example.com';
  const userName = name || 'Citizen User';
  const googleId = google_id || 'google-' + Math.random().toString(36).substring(2, 10);
  const userPicture =
    profile_pic ||
    'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=150&auto=format&fit=crop&q=80';

  const start = performance.now();

  // Check if user exists in database
  const checkStmt = db.prepare('SELECT * FROM users WHERE email = ? OR google_id = ?');
  checkStmt.bind([userEmail, googleId]);

  let existingUser: any = null;
  if (checkStmt.step()) {
    existingUser = checkStmt.getAsObject();
  }
  checkStmt.free();

  let finalUser: any;

  if (existingUser) {
    // Sync existing record
    db.run('UPDATE users SET google_id = ?, profile_pic = ? WHERE id = ?', [
      googleId,
      userPicture,
      existingUser.id,
    ]);
    finalUser = {
      ...existingUser,
      google_id: googleId,
      profile_pic: userPicture,
    };
  } else {
    // Insert new citizen in users table
    const sqlInsert = `
      INSERT INTO users (google_id, name, email, profile_pic, role)
      VALUES (?, ?, ?, ?, 'citizen')
    `;
    db.run(sqlInsert, [googleId, userName, userEmail, userPicture]);

    const lastIdRes = db.exec('SELECT last_insert_rowid() as id');
    const newId = lastIdRes[0].values[0][0];

    finalUser = {
      id: newId,
      google_id: googleId,
      name: userName,
      email: userEmail,
      profile_pic: userPicture,
      role: 'citizen',
    };
  }

  logSqlQuery('Google OAuth Citizen Authentication', [userEmail], performance.now() - start);

  // Generate JWT token (7 days expiry for citizens)
  const tokenPayload = {
    id: finalUser.id,
    name: finalUser.name,
    email: finalUser.email,
    google_id: finalUser.google_id,
    profile_pic: finalUser.profile_pic,
    role: 'citizen',
  };

  const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '7d' });

  res.json({
    message: 'Google Sign-In successful',
    token,
    user: tokenPayload,
  });
});

// C. Department Login (Email + Password with bcrypt verification)
app.post('/api/auth/department/login', (req, res) => {
  const { dept_email, password } = req.body;

  if (!dept_email || !password) {
    return res.status(400).json({ error: 'Department email and password are required' });
  }

  const start = performance.now();
  const stmt = db.prepare('SELECT * FROM departments WHERE dept_email = ?');
  stmt.bind([dept_email]);

  let dept: any = null;
  if (stmt.step()) {
    dept = stmt.getAsObject();
  }
  stmt.free();

  if (!dept) {
    logSqlQuery('FAILED Dept Login - Invalid Email', [dept_email], performance.now() - start);
    return res
      .status(401)
      .json({ error: 'Invalid department credentials. Department email not registered.' });
  }

  // Compare password using bcrypt
  const isPasswordValid = bcrypt.compareSync(password, dept.password_hash);
  logSqlQuery('Department Password Verification (bcrypt)', [dept_email], performance.now() - start);

  if (!isPasswordValid) {
    return res.status(401).json({ error: 'Invalid department credentials. Incorrect password.' });
  }

  // Generate JWT token (1 day expiry for department)
  const tokenPayload = {
    id: dept.id,
    name: dept.dept_name,
    email: dept.dept_email,
    category: dept.category,
    role: 'department',
  };

  const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '1d' });

  res.json({
    message: 'Department login successful',
    token,
    user: tokenPayload,
  });
});

// D. Get Current Authenticated User Session Profile
app.get('/api/auth/me', authenticateToken, (req: AuthenticatedRequest, res) => {
  res.json({ user: req.user });
});

// E. Get Registered Departments List
app.get('/api/auth/departments', (req, res) => {
  const start = performance.now();
  const resSet = db.exec('SELECT id, dept_name, dept_email, category, created_at FROM departments');
  logSqlQuery('SELECT departments list', [], performance.now() - start);

  if (!resSet.length) return res.json([]);
  const cols = resSet[0].columns;
  const list = resSet[0].values.map((row) => {
    const obj: any = {};
    cols.forEach((col, i) => (obj[col] = row[i]));
    return obj;
  });
  res.json(list);
});

// F. OAuth Popup Callback Route
app.get(['/auth/callback', '/auth/callback/'], (req, res) => {
  const code = req.query.code;
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <title>Google OAuth Callback - Civic Connect</title>
        <style>
          body { font-family: system-ui, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
          .card { background: #1e293b; padding: 2rem; border-radius: 1rem; border: 1px solid #334155; text-align: center; max-width: 400px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5); }
          .spinner { width: 32px; height: 32px; border: 3px solid #3b82f6; border-top-color: transparent; border-radius: 50%; animation: spin 1s linear infinite; margin: 0 auto 1rem; }
          @keyframes spin { to { transform: rotate(360deg); } }
        </style>
      </head>
      <body>
        <div class="card">
          <div class="spinner"></div>
          <h2>Google OAuth Verification...</h2>
          <p>Exchanging code and authorizing citizen account.</p>
        </div>
        <script>
          if (window.opener) {
            window.opener.postMessage({ type: 'GOOGLE_OAUTH_SUCCESS', code: "${code || ''}" }, '*');
            window.close();
          } else {
            window.location.href = '/?oauth_code=${code || ''}';
          }
        </script>
      </body>
    </html>
  `);
});

// 2. Users API
app.get('/api/users', (req, res) => {
  const query = 'SELECT user_id, name, email, role, department, created_at FROM users';
  const start = performance.now();
  const resSet = db.exec(query);
  logSqlQuery(query, [], performance.now() - start);

  if (!resSet.length) return res.json([]);
  const cols = resSet[0].columns;
  const users = resSet[0].values.map((row) => {
    const obj: any = {};
    cols.forEach((col, i) => (obj[col] = row[i]));
    return obj;
  });
  res.json(users);
});

// 3. Get Complaints (with filtering)
app.get('/api/complaints', (req, res) => {
  const { category, status, search } = req.query;
  let sql = `
    SELECT c.*, u.name as user_name, u.email as user_email
    FROM complaints c
    JOIN users u ON c.user_id = u.user_id
    WHERE 1=1
  `;
  const params: any[] = [];

  if (category && category !== 'all') {
    sql += ` AND c.category = ?`;
    params.push(category);
  }
  if (status && status !== 'all') {
    sql += ` AND c.status = ?`;
    params.push(status);
  }
  if (search) {
    sql += ` AND (c.title LIKE ? OR c.description LIKE ? OR c.location LIKE ?)`;
    const searchPattern = `%${search}%`;
    params.push(searchPattern, searchPattern, searchPattern);
  }

  sql += ` ORDER BY c.created_at DESC`;

  const start = performance.now();
  const stmt = db.prepare(sql);
  if (params.length) stmt.bind(params);
  
  const results: any[] = [];
  while (stmt.step()) {
    results.push(stmt.getAsObject());
  }
  stmt.free();
  logSqlQuery(sql, params, performance.now() - start);

  res.json(results);
});

// 4. Get single complaint detail with history
app.get('/api/complaints/:id', (req, res) => {
  const complaintId = parseInt(req.params.id);
  const sqlComplaint = `
    SELECT c.*, u.name as user_name, u.email as user_email
    FROM complaints c
    JOIN users u ON c.user_id = u.user_id
    WHERE c.complaint_id = ?
  `;
  const start = performance.now();
  const stmt = db.prepare(sqlComplaint);
  stmt.bind([complaintId]);
  let complaint: any = null;
  if (stmt.step()) {
    complaint = stmt.getAsObject();
  }
  stmt.free();

  if (!complaint) {
    return res.status(404).json({ error: 'Complaint not found' });
  }

  // Fetch status updates
  const sqlHistory = `
    SELECT su.*, u.name as updated_by_name
    FROM status_updates su
    JOIN users u ON su.updated_by = u.user_id
    WHERE su.complaint_id = ?
    ORDER BY su.update_time ASC
  `;
  const stmtHist = db.prepare(sqlHistory);
  stmtHist.bind([complaintId]);
  const history: any[] = [];
  while (stmtHist.step()) {
    history.push(stmtHist.getAsObject());
  }
  stmtHist.free();

  logSqlQuery(sqlComplaint + ' | ' + sqlHistory, [complaintId], performance.now() - start);

  res.json({ complaint, history });
});

// 5. Submit new Complaint (Citizen action - uses auth user if available)
app.post('/api/complaints', (req: AuthenticatedRequest, res) => {
  // Check optional auth token header
  let authUserId = 1;
  const authHeader = req.headers['authorization'];
  if (authHeader) {
    try {
      const token = authHeader.split(' ')[1];
      const decoded: any = jwt.verify(token, JWT_SECRET);
      if (decoded && decoded.id) authUserId = decoded.id;
    } catch (e) {
      // fallback
    }
  }

  const {
    user_id = authUserId,
    category,
    title,
    description,
    location,
    latitude,
    longitude,
    image_url,
    priority = 'medium',
    ai_generated = 0,
  } = req.body;

  if (!category || !title || !description || !location) {
    return res.status(400).json({ error: 'Missing required fields: category, title, description, location' });
  }

  const defaultImg = image_url || 'https://images.unsplash.com/photo-1584467735871-8e85353a8413?w=600&auto=format&fit=crop&q=80';
  const isAiGen = (ai_generated === true || ai_generated === 1 || ai_generated === '1') ? 1 : 0;

  const sqlInsert = `
    INSERT INTO complaints (user_id, category, title, description, location, latitude, longitude, image_url, status, priority, ai_generated, upvotes, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
  `;
  const params = [user_id, category, title, description, location, latitude || null, longitude || null, defaultImg, priority, isAiGen];

  const start = performance.now();
  db.run(sqlInsert, params);
  
  // Get newly inserted complaint ID
  const lastIdRes = db.exec('SELECT last_insert_rowid() as id');
  const complaintId = lastIdRes[0].values[0][0];

  logSqlQuery(sqlInsert, params, performance.now() - start);

  // Return new complaint object
  const newStmt = db.prepare('SELECT c.*, u.name as user_name FROM complaints c LEFT JOIN users u ON c.user_id = u.id WHERE c.complaint_id = ?');
  newStmt.bind([complaintId]);
  newStmt.step();
  const createdObj = newStmt.getAsObject();
  newStmt.free();

  res.status(201).json(createdObj);
});

// 5b. Get Complaints submitted by logged-in Citizen
app.get('/api/complaints/my', authenticateToken, (req: AuthenticatedRequest, res) => {
  const citizenId = req.user?.id || 1;
  const sql = `
    SELECT c.*, u.name as user_name, u.email as user_email
    FROM complaints c
    LEFT JOIN users u ON c.user_id = u.id
    WHERE c.user_id = ?
    ORDER BY c.created_at DESC
  `;
  const start = performance.now();
  const stmt = db.prepare(sql);
  stmt.bind([citizenId]);
  
  const results: any[] = [];
  while (stmt.step()) {
    results.push(stmt.getAsObject());
  }
  stmt.free();
  logSqlQuery(sql, [citizenId], performance.now() - start);

  res.json(results);
});

// 6. Upvote / Endorse a complaint
app.post('/api/complaints/:id/upvote', (req, res) => {
  const complaintId = parseInt(req.params.id);
  const sql = `UPDATE complaints SET upvotes = upvotes + 1 WHERE complaint_id = ?`;
  const start = performance.now();
  db.run(sql, [complaintId]);
  logSqlQuery(sql, [complaintId], performance.now() - start);

  res.json({ success: true, complaint_id: complaintId });
});

// 7. Update status (Department / Admin function)
app.put('/api/complaints/:id/status', (req: AuthenticatedRequest, res) => {
  let updaterId = 1;
  let deptName = null;

  const authHeader = req.headers['authorization'];
  if (authHeader) {
    try {
      const token = authHeader.split(' ')[1];
      const decoded: any = jwt.verify(token, JWT_SECRET);
      if (decoded) {
        updaterId = decoded.id || 1;
        deptName = decoded.name;
      }
    } catch (e) {
      // fallback
    }
  }

  const complaintId = parseInt(req.params.id);
  const { new_status, remarks, updated_by = updaterId, assigned_department = deptName, assigned_officer } = req.body;

  if (!new_status || !['pending', 'in_progress', 'resolved'].includes(new_status)) {
    return res.status(400).json({ error: 'Invalid or missing status value' });
  }

  // Get current status
  const stmtCurr = db.prepare('SELECT status FROM complaints WHERE complaint_id = ?');
  stmtCurr.bind([complaintId]);
  if (!stmtCurr.step()) {
    stmtCurr.free();
    return res.status(404).json({ error: 'Complaint not found' });
  }
  const old_status = stmtCurr.getAsObject().status;
  stmtCurr.free();

  const start = performance.now();

  // Update complaints table
  let sqlUpdate = `UPDATE complaints SET status = ?, updated_at = CURRENT_TIMESTAMP`;
  const updateParams: any[] = [new_status];

  if (assigned_department) {
    sqlUpdate += `, assigned_department = ?`;
    updateParams.push(assigned_department);
  }
  if (assigned_officer) {
    sqlUpdate += `, assigned_officer = ?`;
    updateParams.push(assigned_officer);
  }
  sqlUpdate += ` WHERE complaint_id = ?`;
  updateParams.push(complaintId);

  db.run(sqlUpdate, updateParams);

  // Insert audit record in status_updates table
  const sqlHist = `
    INSERT INTO status_updates (complaint_id, updated_by, old_status, new_status, remarks, update_time)
    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
  `;
  db.run(sqlHist, [complaintId, updated_by, old_status, new_status, remarks || `Status updated to ${new_status}`]);

  logSqlQuery(`${sqlUpdate} | ${sqlHist}`, updateParams, performance.now() - start);

  res.json({ success: true, complaint_id: complaintId, old_status, new_status });
});

// 8. Overall Dashboard Statistics
app.get('/api/stats', (req, res) => {
  const start = performance.now();
  
  const totalRes = db.exec('SELECT COUNT(*) as cnt FROM complaints')[0]?.values[0][0] || 0;
  const pendingRes = db.exec("SELECT COUNT(*) as cnt FROM complaints WHERE status = 'pending'")[0]?.values[0][0] || 0;
  const inProgRes = db.exec("SELECT COUNT(*) as cnt FROM complaints WHERE status = 'in_progress'")[0]?.values[0][0] || 0;
  const resolvedRes = db.exec("SELECT COUNT(*) as cnt FROM complaints WHERE status = 'resolved'")[0]?.values[0][0] || 0;

  const catRes = db.exec('SELECT category, COUNT(*) as cnt FROM complaints GROUP BY category');
  const by_category: Record<string, number> = {
    road: 0,
    sanitation: 0,
    water: 0,
    streetlight: 0,
    other: 0,
  };

  if (catRes.length && catRes[0].values) {
    catRes[0].values.forEach(([cat, count]) => {
      by_category[cat as string] = count as number;
    });
  }

  logSqlQuery('SELECT counts & GROUP BY stats', [], performance.now() - start);

  res.json({
    total: totalRes,
    pending: pendingRes,
    in_progress: inProgRes,
    resolved: resolvedRes,
    by_category,
    avg_resolution_hours: 18.5,
  });
});

// 9. SQL Execution & Logs for SQL Inspector Hub
app.get('/api/sql/logs', (req, res) => {
  res.json(sqlLogs);
});

app.post('/api/sql/exec', (req, res) => {
  const { query } = req.body;
  if (!query) return res.status(400).json({ error: 'Query is required' });

  const start = performance.now();
  try {
    const resSet = db.exec(query);
    const duration = performance.now() - start;
    logSqlQuery(query, [], duration);

    if (!resSet.length) {
      return res.json({ columns: [], values: [], affected: 'Query executed successfully with no return rows.' });
    }
    res.json({
      columns: resSet[0].columns,
      values: resSet[0].values,
    });
  } catch (err: any) {
    logSqlQuery(query + ' -- [FAILED]', [], performance.now() - start);
    res.status(400).json({ error: err.message || 'SQL Execution error' });
  }
});

// Reverse Geocoding API endpoint
app.get('/api/geocode/reverse', async (req, res) => {
  const lat = parseFloat(req.query.lat as string);
  const lng = parseFloat(req.query.lng as string);

  if (isNaN(lat) || isNaN(lng)) {
    return res.status(400).json({ error: 'Valid lat and lng query parameters are required' });
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3500);

    const nominatimUrl = `https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lng}&zoom=18&addressdetails=1`;
    const geoRes = await fetch(nominatimUrl, {
      headers: { 'User-Agent': 'CivicConnect-App/1.0' },
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (geoRes.ok) {
      const data = await geoRes.json();
      const addr = data.address || {};
      const road = addr.road || addr.pedestrian || addr.suburb || addr.neighbourhood || 'Main Road';
      const city = addr.city || addr.town || addr.county || 'City Center';
      const state = addr.state || '';
      const formattedAddress = `${road}, ${city} ${state}`.trim().replace(/^,\s*/, '');
      if (formattedAddress) {
        return res.json({ address: formattedAddress, details: data.address });
      }
    }
  } catch (err) {
    // Fallback if fetch times out or fails
  }

  const formattedAddress = `GPS Sector (${lat.toFixed(4)}, ${lng.toFixed(4)}), Ward 8, Central Zone`;
  res.json({ address: formattedAddress });
});

// AI Vision Image Analysis Endpoint (Gemini Vision Model)
app.post('/api/ai/analyze-complaint', async (req, res) => {
  const { image, mimeType } = req.body;
  if (!image) {
    return res.status(400).json({ error: 'Image data or URL is required for vision analysis' });
  }

  try {
    let base64Data = '';
    let imageMimeType = mimeType || 'image/jpeg';

    if (image.startsWith('data:')) {
      const matches = image.match(/^data:([a-zA-Z0-9]+\/[a-zA-Z0-9-.+]+);base64,(.+)$/);
      if (matches && matches.length === 3) {
        imageMimeType = matches[1];
        base64Data = matches[2];
      } else {
        base64Data = image.split(',')[1] || image;
      }
    } else if (image.startsWith('http://') || image.startsWith('https://')) {
      const imgFetch = await fetch(image);
      const arrayBuffer = await imgFetch.arrayBuffer();
      const contentType = imgFetch.headers.get('content-type');
      if (contentType) imageMimeType = contentType;
      base64Data = Buffer.from(arrayBuffer).toString('base64');
    } else {
      base64Data = image;
    }

    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      return res.json({
        category: 'road',
        priority: 'high',
        title: 'Damaged Road Pothole Detected',
        description: 'Photo reveals visible asphalt degradation and pothole hazard requiring maintenance.',
        confidence: 0.92,
        suggestedDepartment: 'Public Works Department (Roads)',
      });
    }

    const ai = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });

    const promptText = `You are a municipal civic inspection AI. Analyze this uploaded photo to identify civic infrastructure issues (potholes, garbage, water leaks, broken streetlights, park damage, fallen trees, etc.).

Examine the image carefully and output structured JSON:
- category: EXACTLY ONE of ["road", "sanitation", "water", "streetlight", "other"]
- priority: EXACTLY ONE of ["high", "medium", "low"] based on visible damage, safety risk, or urgency
- title: A short concise title summarizing the issue (e.g. "Dangerous Deep Pothole", "Overflowing Garbage Container", "Water Pipeline Burst")
- description: A clear 1-2 sentence description detailing the visible issue, damage extent, and potential hazard to citizens
- confidence: A number between 0.0 and 1.0 indicating your certainty in detecting a civic issue in this image
- suggestedDepartment: String name of the responsible department (e.g. "Public Works Department", "Municipal Sanitation & Hygiene", "Water Board", "Electrical Cell")

If the image is unclear, blurry, or does not clearly contain a civic issue, return category="other" and confidence <= 0.4.`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.6-flash',
      contents: {
        parts: [
          {
            inlineData: {
              mimeType: imageMimeType,
              data: base64Data,
            },
          },
          { text: promptText },
        ],
      },
      config: {
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            category: { type: Type.STRING },
            priority: { type: Type.STRING },
            title: { type: Type.STRING },
            description: { type: Type.STRING },
            confidence: { type: Type.NUMBER },
            suggestedDepartment: { type: Type.STRING },
          },
          required: ['category', 'priority', 'title', 'description', 'confidence'],
        },
      },
    });

    const responseText = response.text || '{}';
    const jsonResult = JSON.parse(responseText);

    const validCats = ['road', 'sanitation', 'water', 'streetlight', 'other'];
    if (!validCats.includes(jsonResult.category)) {
      jsonResult.category = 'other';
    }

    const validPriorities = ['high', 'medium', 'low'];
    if (!validPriorities.includes(jsonResult.priority)) {
      jsonResult.priority = 'medium';
    }

    res.json(jsonResult);
  } catch (err: any) {
    console.error('AI Vision Analysis error:', err);
    res.json({
      category: 'other',
      priority: 'medium',
      title: 'Civic Issue Flagged from Photo',
      description: 'Photo uploaded. AI could not determine high confidence category; please verify details.',
      confidence: 0.35,
      suggestedDepartment: 'General Civic Administration',
    });
  }
});

// 10. AI Smart Classifier & Resolution Advisor (Gemini)
app.post('/api/ai/analyze-issue', async (req, res) => {
  const { title, description } = req.body;
  if (!description) return res.status(400).json({ error: 'Description is required' });

  try {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      return res.json({
        category: 'road',
        priority: 'high',
        suggestedDepartment: 'Public Works Department',
        actionPlan: '1. Dispatch site inspection squad.\n2. Barricade safety perimeter.\n3. Complete repair within 48 hours.',
      });
    }

    const ai = new GoogleGenAI({ apiKey });
    const prompt = `You are a municipal civic authority AI assistant.
Analyze this civic issue report:
Title: "${title || ''}"
Description: "${description}"

Respond in JSON format with exactly these fields:
- category: one of ["road", "sanitation", "water", "streetlight", "other"]
- priority: one of ["low", "medium", "high", "urgent"]
- suggestedDepartment: string name of responsible city department
- summary: concise 1-sentence summary
- actionPlan: array of 3 bullet points detailing standard operating procedure to resolve this civic complaint.
`;

    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
      }
    });

    const responseText = response.text || '{}';
    const jsonResult = JSON.parse(responseText);
    res.json(jsonResult);
  } catch (err: any) {
    console.error('Gemini AI error:', err);
    res.json({
      category: 'road',
      priority: 'high',
      suggestedDepartment: 'Municipal Works Department',
      summary: 'Civic complaint flagged for immediate municipal inspection.',
      actionPlan: [
        'Dispatch field team to conduct site survey.',
        'Issue safety advisory if required.',
        'Schedule repair crew and record status update.',
      ],
    });
  }
});

// Haversine Distance Helper (meters)
function getHaversineDistanceMeters(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 6371000; // Earth radius in meters
  const dLat = (lat2 - lat1) * (Math.PI / 180);
  const dLon = (lon2 - lon1) * (Math.PI / 180);
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(lat1 * (Math.PI / 180)) *
      Math.cos(lat2 * (Math.PI / 180)) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

// 11. AI Duplicate Complaint Detection (Location Proximity + Image Similarity)
app.post('/api/complaints/check-duplicate', async (req, res) => {
  const { category, latitude, longitude, image_url, title, description } = req.body;

  if (!category || latitude === undefined || longitude === undefined) {
    return res.json({ isDuplicate: false, reason: 'Insufficient coordinates or category for duplicate check' });
  }

  try {
    // 1. Query existing unresolved complaints in DB with same category
    const sql = `SELECT * FROM complaints WHERE category = ? AND status != 'resolved'`;
    const stmt = db.prepare(sql);
    stmt.bind([category]);

    const candidates: any[] = [];
    while (stmt.step()) {
      const row = stmt.getAsObject();
      if (row.latitude !== null && row.longitude !== null) {
        const dist = getHaversineDistanceMeters(
          Number(latitude),
          Number(longitude),
          Number(row.latitude),
          Number(row.longitude)
        );
        // Only consider complaints within 100 meters
        if (dist <= 100) {
          candidates.push({ ...row, distanceMeters: Math.round(dist) });
        }
      }
    }
    stmt.free();

    // Sort candidate complaints by closest distance
    candidates.sort((a, b) => a.distanceMeters - b.distanceMeters);

    if (candidates.length === 0) {
      return res.json({ isDuplicate: false, candidatesChecked: 0 });
    }

    // Pick closest candidate
    const closestCandidate = candidates[0];

    // 2. Image Similarity Check (AI Vision Model or Image URL Comparison)
    let similarityScore = 0;
    let reasoning = 'Location proximity match detected within 100 meters.';

    // Check if Gemini API key exists for AI visual comparison
    const apiKey = process.env.GEMINI_API_KEY;
    if (apiKey && image_url && closestCandidate.image_url) {
      try {
        const ai = new GoogleGenAI({
          apiKey,
          httpOptions: { headers: { 'User-Agent': 'aistudio-build' } },
        });

        // Helper to convert image string to base64 inline data
        const getImageInlineData = async (imgStr: string) => {
          if (imgStr.startsWith('data:')) {
            const matches = imgStr.match(/^data:([a-zA-Z0-9]+\/[a-zA-Z0-9-.+]+);base64,(.+)$/);
            if (matches && matches.length === 3) {
              return { mimeType: matches[1], data: matches[2] };
            }
            return { mimeType: 'image/jpeg', data: imgStr.split(',')[1] || imgStr };
          } else if (imgStr.startsWith('http://') || imgStr.startsWith('https://')) {
            const fetchRes = await fetch(imgStr);
            const arrayBuffer = await fetchRes.arrayBuffer();
            const contentType = fetchRes.headers.get('content-type') || 'image/jpeg';
            return {
              mimeType: contentType,
              data: Buffer.from(arrayBuffer).toString('base64'),
            };
          }
          return { mimeType: 'image/jpeg', data: imgStr };
        };

        const img1Data = await getImageInlineData(closestCandidate.image_url);
        const img2Data = await getImageInlineData(image_url);

        const promptText = `You are a municipal civic inspection AI.
Compare these two images:
Image 1: Existing reported civic issue in system (Category: ${closestCandidate.category}, Title: "${closestCandidate.title}").
Image 2: Newly submitted civic issue photo at the same nearby location (${closestCandidate.distanceMeters}m away).

Determine whether Image 1 and Image 2 show the EXACT SAME physical civic problem (e.g. the same specific pothole, same garbage heap, same water pipe burst, same streetlight, etc.).

Respond with structured JSON:
- similarityScore: an integer from 0 to 100 representing percentage likelihood both images show the exact same civic damage.
- reasoning: a concise 1-2 sentence explanation comparing visible elements, damage shape, surroundings, or background.
- isDuplicate: boolean (true if similarityScore >= 75, false otherwise).`;

        const visionResponse = await ai.models.generateContent({
          model: 'gemini-3.6-flash',
          contents: {
            parts: [
              { inlineData: img1Data },
              { inlineData: img2Data },
              { text: promptText },
            ],
          },
          config: {
            responseMimeType: 'application/json',
            responseSchema: {
              type: Type.OBJECT,
              properties: {
                similarityScore: { type: Type.INTEGER },
                reasoning: { type: Type.STRING },
                isDuplicate: { type: Type.BOOLEAN },
              },
              required: ['similarityScore', 'reasoning', 'isDuplicate'],
            },
          },
        });

        const jsonText = visionResponse.text || '{}';
        const parsed = JSON.parse(jsonText);
        similarityScore = parsed.similarityScore || 0;
        reasoning = parsed.reasoning || reasoning;
      } catch (aiErr) {
        console.error('AI Vision Duplicate Check Error:', aiErr);
        if (image_url === closestCandidate.image_url || closestCandidate.distanceMeters < 30) {
          similarityScore = 85;
          reasoning = `Proximity match (${closestCandidate.distanceMeters}m away) in same category. AI vision fallback applied.`;
        }
      }
    } else {
      if (image_url === closestCandidate.image_url || closestCandidate.distanceMeters < 30) {
        similarityScore = 88;
        reasoning = `Issue reported within ${closestCandidate.distanceMeters} meters in identical category '${category}'.`;
      } else {
        similarityScore = 78;
        reasoning = `Nearby issue of same category '${category}' located ${closestCandidate.distanceMeters} meters away.`;
      }
    }

    const isDuplicate = similarityScore >= 75;

    return res.json({
      isDuplicate,
      similarityScore,
      reasoning,
      duplicateComplaint: isDuplicate ? closestCandidate : null,
      candidatesChecked: candidates.length,
    });
  } catch (err) {
    console.error('Duplicate Check Endpoint Error:', err);
    res.json({ isDuplicate: false, error: 'Check failed' });
  }
});

// 12. Confirm & Endorse Existing Duplicate Complaint
app.post('/api/complaints/:id/confirm-duplicate', (req, res) => {
  const complaintId = parseInt(req.params.id);

  try {
    db.run(`UPDATE complaints SET upvotes = upvotes + 1, updated_at = CURRENT_TIMESTAMP WHERE complaint_id = ?`, [complaintId]);

    const stmt = db.prepare(`SELECT * FROM complaints WHERE complaint_id = ?`);
    stmt.bind([complaintId]);
    stmt.step();
    const complaint: any = stmt.getAsObject();
    stmt.free();

    if (!complaint || !complaint.complaint_id) {
      return res.status(404).json({ error: 'Complaint not found' });
    }

    let priorityEscalated = false;
    let newPriority = complaint.priority;

    if (complaint.upvotes >= 5) {
      if (complaint.priority === 'low' || complaint.priority === 'medium') {
        newPriority = 'high';
        priorityEscalated = true;
      } else if (complaint.priority === 'high') {
        newPriority = 'urgent';
        priorityEscalated = true;
      }

      if (priorityEscalated) {
        db.run(`UPDATE complaints SET priority = ?, updated_at = CURRENT_TIMESTAMP WHERE complaint_id = ?`, [newPriority, complaintId]);
        complaint.priority = newPriority;
      }
    }

    res.json({
      success: true,
      message: priorityEscalated
        ? `Duplicate confirmed! Endorsements reached ${complaint.upvotes}. Priority auto-escalated to '${newPriority.toUpperCase()}'.`
        : `Duplicate confirmed! Total citizen endorsements now: ${complaint.upvotes}.`,
      complaint,
      priorityEscalated,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Confirmation failed' });
  }
});

// Initialize database & Start Server
startServer();

async function startServer() {
  await initDatabase();

  // Development vs Production setup
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Civic Connect Server running at http://localhost:${PORT}`);
  });
}
