// Enhanced server.js with Admin Panel, Authentication, and User Configuration Management
require('dotenv').config();

const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const axios = require('axios');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 3001;

// JWT Secret for session tokens (different from Sigma embed secret)
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const SALT_ROUNDS = 10;

// Session tokens store (in production, use Redis or database)
const activeSessions = new Map();

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static('public'));

// CORS
app.use((req, res, next) => {
  // Parse allowed origins from environment variable
  const allowedOrigins = process.env.ALLOWED_ORIGINS 
    ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
    : ['https://twells89.github.io', 'http://localhost:4200', 'https://app.sigmacomputing.com'];
  
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  }
  
  res.header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS, PATCH, PUT');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  
  next();
});

// Initialize SQLite Database
const databasePath = process.env.DATABASE_PATH || './bookmarks.db';
const db = new sqlite3.Database(databasePath, (err) => {
  if (err) {
    console.error('Error opening database:', err);
  } else {
    console.log('📚 Bookmark database connected');
    initializeDatabase();
  }
});

// Create new schema for bookmark system and user configurations
function initializeDatabase() {
  db.serialize(() => {
    // Users table with password hashing
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin BOOLEAN DEFAULT 0,
        is_active BOOLEAN DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME
      )
    `, (err) => {
      if (err && !err.message.includes('already exists')) {
        console.error('Error creating users table:', err);
      } else {
        console.log('✅ Users table ready');
        createSuperAdmin();
      }
    });
    
    // User configurations table
    db.run(`
      CREATE TABLE IF NOT EXISTS user_configs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        is_internal BOOLEAN DEFAULT 0,
        teams TEXT,
        account_type TEXT,
        user_attributes TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `, (err) => {
      if (err && !err.message.includes('already exists')) {
        console.error('Error creating user_configs table:', err);
      } else {
        console.log('✅ User configs table ready');
      }
    });

    // Main bookmarks table (one entry per Sigma bookmark)
    db.run(`
      CREATE TABLE IF NOT EXISTS bookmarks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bookmark_id TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        workbook_id TEXT NOT NULL,
        workbook_name TEXT,
        explore_key TEXT,
        workbook_version TEXT,
        created_by TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `, (err) => {
      if (err && !err.message.includes('already exists')) {
        console.error('Error creating bookmarks table:', err);
      } else {
        console.log('✅ Bookmarks table ready');
      }
    });

    // User access table (many-to-many relationship)
    db.run(`
      CREATE TABLE IF NOT EXISTS bookmark_access (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bookmark_id TEXT NOT NULL,
        user_email TEXT NOT NULL,
        access_type TEXT DEFAULT 'viewer',
        custom_name TEXT,
        granted_by TEXT,
        granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(bookmark_id, user_email),
        FOREIGN KEY (bookmark_id) REFERENCES bookmarks(bookmark_id) ON DELETE CASCADE
      )
    `, (err) => {
      if (err && !err.message.includes('already exists')) {
        console.error('Error creating bookmark_access table:', err);
      } else {
        console.log('✅ Bookmark access table ready');
      }
    });

    // Team shares table
    db.run(`
      CREATE TABLE IF NOT EXISTS bookmark_shares (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bookmark_id TEXT NOT NULL,
        team_name TEXT NOT NULL,
        shared_by TEXT NOT NULL,
        shared_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(bookmark_id, team_name),
        FOREIGN KEY (bookmark_id) REFERENCES bookmarks(bookmark_id) ON DELETE CASCADE
      )
    `, (err) => {
      if (err && !err.message.includes('already exists')) {
        console.error('Error creating bookmark_shares table:', err);
      } else {
        console.log('✅ Bookmark shares table ready');
      }
    });

    // Scheduled reports table
    db.run(`
      CREATE TABLE IF NOT EXISTS scheduled_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        schedule_id TEXT UNIQUE NOT NULL,
        bookmark_id TEXT NOT NULL,
        workbook_id TEXT NOT NULL,
        schedule_name TEXT NOT NULL,
        created_by TEXT NOT NULL,
        member_id TEXT,
        cron_expression TEXT,
        destination_type TEXT DEFAULT 'email',
        destination_config TEXT,
        format TEXT DEFAULT 'pdf',
        is_active BOOLEAN DEFAULT 1,
        sigma_schedule_data TEXT,
        last_run DATETIME,
        next_run DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (bookmark_id) REFERENCES bookmarks(bookmark_id) ON DELETE CASCADE
      )
    `, (err) => {
      if (err && !err.message.includes('already exists')) {
        console.error('Error creating scheduled_reports table:', err);
      } else {
        console.log('✅ Scheduled reports table ready');
      }
    });

    // Create indexes for better performance
    setTimeout(() => {
      db.run('CREATE INDEX IF NOT EXISTS idx_bookmarks_workbook ON bookmarks(workbook_id)');
      db.run('CREATE INDEX IF NOT EXISTS idx_bookmark_access_user ON bookmark_access(user_email)');
      db.run('CREATE INDEX IF NOT EXISTS idx_bookmark_access_bookmark ON bookmark_access(bookmark_id)');
      db.run('CREATE INDEX IF NOT EXISTS idx_bookmark_shares_team ON bookmark_shares(team_name)');
      db.run('CREATE INDEX IF NOT EXISTS idx_scheduled_reports_bookmark ON scheduled_reports(bookmark_id)');
      db.run('CREATE INDEX IF NOT EXISTS idx_user_configs_email ON user_configs(email)');
      db.run('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)');
    }, 1000);
  });
}

// Create super admin if not exists
async function createSuperAdmin() {
  const superAdminEmail = 'tj@sigmacomputing.com';
  const defaultPassword = 'Admin@123'; // Should be changed on first login
  
  db.get('SELECT * FROM users WHERE email = ?', [superAdminEmail], async (err, row) => {
    if (err) {
      console.error('Error checking for super admin:', err);
      return;
    }
    
    if (!row) {
      try {
        const hashedPassword = await bcrypt.hash(defaultPassword, SALT_ROUNDS);
        db.run(
          `INSERT INTO users (email, password_hash, is_admin, is_active) 
           VALUES (?, ?, 1, 1)`,
          [superAdminEmail, hashedPassword],
          (err) => {
            if (err) {
              console.error('Error creating super admin:', err);
            } else {
              console.log('👑 Super admin account created');
              console.log(`   Email: ${superAdminEmail}`);
              console.log(`   Default Password: ${defaultPassword}`);
              console.log('   ⚠️  Please change this password after first login!');
            }
          }
        );
      } catch (error) {
        console.error('Error hashing password:', error);
      }
    }
  });
}

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  // Check if session is active
  const sessionData = activeSessions.get(token);
  if (!sessionData) {
    return res.status(401).json({ error: 'Session expired or invalid' });
  }
  
  // Check session expiry
  if (Date.now() > sessionData.expiresAt) {
    activeSessions.delete(token);
    return res.status(401).json({ error: 'Session expired' });
  }
  
  // Verify JWT
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    
    req.user = decoded;
    next();
  });
}

// Admin-only middleware
function requireAdmin(req, res, next) {
  if (!req.user || !req.user.isAdmin) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// Sigma API config
const SIGMA_BASE_URL = process.env.SIGMA_BASE_URL || 'https://aws-api.sigmacomputing.com/v2';
const SIGMA_MEMBERS_URL = `${SIGMA_BASE_URL}/members`;
const SIGMA_WORKBOOKS_URL = `${SIGMA_BASE_URL}/workbooks`;
const SIGMA_DATA_MODELS_URL = `${SIGMA_BASE_URL}/dataModels`;
const SIGMA_TEAMS_URL = `${SIGMA_BASE_URL}/teams`;
const SIGMA_ACCOUNT_TYPES_URL = `${SIGMA_BASE_URL}/account-types`;
const SIGMA_USER_ATTRIBUTES_URL = `${SIGMA_BASE_URL}/user-attributes`;

const embedClientId = process.env.EMBED_CLIENT_ID;
const embedSecret = process.env.EMBED_SECRET;
const sigmaOrg = process.env.SIGMA_ORG;

const clientId = process.env.CLIENT_ID;
const clientSecret = process.env.CLIENT_SECRET;

// Feature flags
const FEATURES = {
  DATA_MODELS: process.env.ENABLE_DATA_MODELS !== 'false', // Default to true
  DATA_MODELS_FALLBACK: true // Try to find data models in files endpoint if dedicated endpoint fails
};

// Token cache to prevent rate limiting
const tokenCache = {
  bearerToken: null,
  bearerTokenExpiry: 0,
  impersonatedTokens: new Map() // Map of email -> {token, expiry}
};

// Utility functions
async function getBearerToken() {
  try {
    // Check if we have a cached token that's still valid (with 5 minute buffer)
    const now = Date.now();
    if (tokenCache.bearerToken && tokenCache.bearerTokenExpiry > now + (5 * 60 * 1000)) {
      console.log('♻️ Using cached bearer token');
      return tokenCache.bearerToken;
    }
    
    console.log('🔑 Requesting new bearer token from Sigma API...');
    const params = new URLSearchParams();
    params.append('grant_type', 'client_credentials');
    params.append('client_id', clientId);
    params.append('client_secret', clientSecret);

    const response = await axios.post(`${SIGMA_BASE_URL}/auth/token`, params, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    // Cache the token (expires in 1 hour typically)
    tokenCache.bearerToken = response.data.access_token;
    tokenCache.bearerTokenExpiry = now + (55 * 60 * 1000); // Cache for 55 minutes
    console.log('✅ New bearer token cached');
    
    return response.data.access_token;
  } catch (error) {
    console.error('Failed to get bearer token:', error.response?.data || error.message);
    throw error;
  }
}

// Get impersonated bearer token using JWT token exchange (proper method)
async function getImpersonatedBearerToken(userEmail) {
  try {
    // Check if we have a cached token for this user that's still valid (with 5 minute buffer)
    const now = Date.now();
    const cachedToken = tokenCache.impersonatedTokens.get(userEmail);
    if (cachedToken && cachedToken.expiry > now + (5 * 60 * 1000)) {
      console.log(`♻️ Using cached impersonated token for: ${userEmail}`);
      return cachedToken.token;
    }
    
    console.log(`🎭 Getting impersonated token for user: ${userEmail}`);
    console.log(`📝 Using JWT token exchange method (proper impersonation)`);
    
    // Step 1: Get actor token (use cached bearer token)
    const actorToken = await getBearerToken();
    console.log(`✅ Got actor token (admin token)`);
    
    // Step 2: Create self-signed JWT for the user we want to impersonate
    const time = Math.floor(Date.now() / 1000);
    const subjectTokenPayload = {
      sub: userEmail,
      iss: clientId,
      iat: time,
      exp: time + 3600
    };
    
    console.log(`📝 Creating subject token (JWT) for: ${userEmail}`);
    const subjectToken = jwt.sign(subjectTokenPayload, clientSecret, {
      algorithm: 'HS256',
      keyid: clientId
    });
    
    // Step 3: Exchange tokens for impersonation token
    // Need actor_token in BOTH Authorization header AND form body
    const exchangeParams = new URLSearchParams();
    exchangeParams.append('grant_type', 'urn:ietf:params:oauth:grant-type:token-exchange');
    exchangeParams.append('actor_token', actorToken);
    exchangeParams.append('actor_token_type', 'urn:ietf:params:oauth:token-type:access_token');
    exchangeParams.append('subject_token', subjectToken);
    exchangeParams.append('subject_token_type', 'urn:ietf:params:oauth:token-type:jwt');
    
    console.log(`🔄 Exchanging tokens for impersonation token...`);
    console.log(`   Sending actor_token in both Authorization header and form body`);
    
    const impersonationResponse = await axios.post(`${SIGMA_BASE_URL}/auth/token`, exchangeParams, {
      headers: { 
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Bearer ${actorToken}`
      }
    });

    const impersonationToken = impersonationResponse.data.access_token;
    
    // Cache the impersonated token for this user (expires in 1 hour typically)
    tokenCache.impersonatedTokens.set(userEmail, {
      token: impersonationToken,
      expiry: now + (55 * 60 * 1000) // Cache for 55 minutes
    });
    console.log(`✅ Successfully obtained and cached impersonation token for: ${userEmail}`);
    
    // Decode the JWT to verify impersonation
    const tokenParts = impersonationToken.split('.');
    if (tokenParts.length === 3) {
      try {
        const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString());
        console.log(`🔍 Impersonation token payload:`);
        console.log(`   - Subject (sub): ${payload.sub || 'N/A'}`);
        console.log(`   - User ID: ${payload.userId || payload.uid || 'N/A'}`);
        console.log(`   - Email: ${payload.email || 'N/A'}`);
        console.log(`   - Actor (original): ${payload.act?.sub || 'N/A'}`);
        
        if (payload.sub === userEmail || payload.email === userEmail) {
          console.log(`✅ Token verified - correctly impersonating ${userEmail}`);
        } else {
          console.log(`⚠️  WARNING: Token subject doesn't match expected user`);
          console.log(`   Expected: ${userEmail}`);
          console.log(`   Got: ${payload.sub || payload.email}`);
        }
      } catch (decodeErr) {
        console.log(`⚠️  Could not decode token payload for inspection`);
      }
    }
    
    return impersonationToken;
  } catch (error) {
    console.error(`❌ Failed to get impersonated token for ${userEmail}:`, error.response?.data || error.message);
    
    if (error.response?.data?.code === 'invalid_request' || error.response?.data?.message?.includes('corrupt authorization header')) {
      console.error(`💡 JWT token exchange failed, falling back to simple impersonation...`);
      
      // Fallback to simple impersonation
      try {
        const params = new URLSearchParams();
        params.append('grant_type', 'client_credentials');
        params.append('client_id', clientId);
        params.append('client_secret', clientSecret);
        params.append('impersonate', userEmail);

        console.log(`🔄 Trying simple impersonation with 'impersonate' parameter...`);
        const response = await axios.post(`${SIGMA_BASE_URL}/auth/token`, params, {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });

        console.log(`✅ Fallback successful - got impersonation token`);
        return response.data.access_token;
      } catch (fallbackError) {
        console.error(`❌ Fallback also failed:`, fallbackError.response?.data || fallbackError.message);
        throw fallbackError;
      }
    }
    
    throw error;
  }
}

async function isInternalUser(userEmail, bearerToken) {
  const url = `${SIGMA_MEMBERS_URL}?search=${encodeURIComponent(userEmail)}`;
  try {
    const response = await axios.get(url, {
      headers: {
        Authorization: `Bearer ${bearerToken}`,
        'Content-Type': 'application/json'
      }
    });

    const entries = response.data.entries || [];
    const matched = entries.find(e => e.email.toLowerCase() === userEmail.toLowerCase());
    const isInternal = matched?.userKind === 'internal';
    console.log(`User ${userEmail} is internal? ${isInternal}`);
    return isInternal;
  } catch (err) {
    console.error('Error checking internal user status:', err.response?.data || err.message);
    return false;
  }
}

async function getMemberId(userEmail, bearerToken) {
  try {
    const searchUrl = `${SIGMA_MEMBERS_URL}?search=${encodeURIComponent(userEmail)}`;
    const searchResponse = await axios.get(searchUrl, {
      headers: {
        Authorization: `Bearer ${bearerToken}`,
        'Content-Type': 'application/json'
      }
    });

    const entries = searchResponse.data.entries || [];
    const user = entries.find(e => e.email.toLowerCase() === userEmail.toLowerCase());
    
    return user?.memberId || null;
  } catch (err) {
    console.error('Error getting member ID:', err.response?.data || err.message);
    return null;
  }
}

async function getUserTeams(userEmail, bearerToken) {
  try {
    const memberId = await getMemberId(userEmail, bearerToken);
    
    if (!memberId) {
      console.log(`User ${userEmail} not found in Sigma`);
      return [];
    }
    
    console.log(`👤 Found member ID: ${memberId}`);
    
    const teamsUrl = `${SIGMA_MEMBERS_URL}/${memberId}/teams`;
    console.log(`Fetching teams from: ${teamsUrl}`);
    
    const teamsResponse = await axios.get(teamsUrl, {
      headers: {
        Authorization: `Bearer ${bearerToken}`,
        'Content-Type': 'application/json'
      }
    });
    
    const teams = teamsResponse.data.entries || [];
    const teamNames = teams.map(team => team.name);
    
    console.log(`User ${userEmail} is in teams:`, teamNames);
    return teamNames;
    
  } catch (err) {
    console.error('Error getting user teams:', err.response?.data || err.message);
    return [];
  }
}

async function getUserConfig(email) {
  return new Promise((resolve, reject) => {
    db.get(
      'SELECT * FROM user_configs WHERE email = ?',
      [email],
      (err, row) => {
        if (err) reject(err);
        else if (row) {
          resolve({
            email: row.email,
            isInternal: row.is_internal === 1,
            teams: row.teams ? JSON.parse(row.teams) : [],
            accountType: row.account_type,
            userAttributes: row.user_attributes ? JSON.parse(row.user_attributes) : {}
          });
        } else {
          resolve(null);
        }
      }
    );
  });
}

function extractWorkbookUrlId(workbook) {
  let urlId = workbook.url || workbook.urlId || workbook.workbookUrlId;
  
  if (!urlId) {
    if (workbook.latestVersion?.path) {
      const pathMatch = workbook.latestVersion.path.match(/\/([^/?#]+)$/);
      if (pathMatch && pathMatch[1]) {
        urlId = pathMatch[1];
        console.log(`📍 Extracted URL ID from latestVersion.path: ${urlId}`);
        return urlId;
      }
    }
    
    console.warn('No URL field found, using workbookId:', workbook.workbookId);
    return workbook.workbookId;
  }
  
  if (typeof urlId === 'string' && urlId.includes('/')) {
    const match = urlId.match(/\/workbook\/([^/?#]+)/);
    if (match && match[1]) {
      urlId = match[1];
      console.log(`📍 Extracted URL ID from full URL: ${urlId}`);
    }
  }
  
  return urlId;
}

// New function to get both workbooks and data models
async function getWorkbooksAndDataModelsForUser(userEmail, bearerToken) {
  try {
    console.log(`\n🔍 === FETCHING ACCESSIBLE ITEMS (INCLUDING DATA MODELS) FOR USER ===`);
    console.log(`👤 User Email: ${userEmail}`);
    
    // Check if user is internal (Sigma member) or external (embed user)
    const isInternal = await isInternalUser(userEmail, bearerToken);
    console.log(`🔑 User Type: ${isInternal ? 'INTERNAL (Sigma member)' : 'EXTERNAL (Embed user)'}`);
    
    let memberId = null;
    if (isInternal) {
      const memberInfo = await getMemberInfo(userEmail, bearerToken);
      if (memberInfo) {
        memberId = memberInfo.memberId;
        console.log(`📊 Member ID: ${memberId}`);
        console.log(`📊 Account Type: ${memberInfo.accountType || 'Unknown'}`);
      }
    }
    
    // Use JWT-based impersonation token for fetching data that respects user permissions
    console.log(`\n🎭 Using JWT-based impersonation for: ${userEmail}`);
    const impersonatedToken = await getImpersonatedBearerToken(userEmail);
    
    console.log(`✅ Got impersonated token (length: ${impersonatedToken?.length || 0} chars)`);
    
    // If we don't have a member ID yet, get it using the impersonated token
    if (!memberId) {
      console.log(`🔍 Getting member ID for: ${userEmail}`);
      const memberInfo = await getMemberInfo(userEmail, impersonatedToken);
      if (memberInfo) {
        memberId = memberInfo.memberId;
        console.log(`📊 Found Member ID: ${memberId}`);
      } else {
        console.error(`❌ Could not find member ID for: ${userEmail}`);
        return { workbooks: [], dataModels: [] };
      }
    }
    
    // FETCH WORKBOOKS using the admin token and member files endpoint
    const inodesListUrl = `${SIGMA_BASE_URL}/members/${memberId}/files?limit=1000`;
    console.log(`\n📍 Fetching workbooks from: ${inodesListUrl}`);
    console.log(`🔐 Using admin token for workbooks endpoint`);
    
    const adminToken = await getBearerToken();
    
    const inodesResponse = await axios.get(inodesListUrl, {
      headers: {
        Authorization: `Bearer ${adminToken}`,
        'Content-Type': 'application/json'
      }
    });
    
    const allInodes = inodesResponse.data.entries || [];
    console.log(`📚 Total accessible items from files endpoint: ${allInodes.length}`);
    
    // Filter for workbooks
    const workbookInodes = allInodes.filter(inode => inode.type === 'workbook');
    const folderInodes = allInodes.filter(inode => inode.type === 'folder');
    
    console.log(`📁 Folders: ${folderInodes.length}`);
    console.log(`📊 Workbooks: ${workbookInodes.length}`);
    
    // FETCH DATA MODELS - only if feature is enabled
    let dataModelsList = [];
    
    if (FEATURES.DATA_MODELS) {
      // FETCH DATA MODELS using the dedicated dataModels endpoint with impersonation
      console.log(`\n📍 Fetching data models from: ${SIGMA_BASE_URL}/dataModels`);
      console.log(`🎭 Using impersonated token to respect user permissions`);
    
    try {
      // First try the standard /dataModels endpoint (camelCase)
      const dataModelsResponse = await axios.get(`${SIGMA_BASE_URL}/dataModels?limit=500`, {
        headers: {
          Authorization: `Bearer ${impersonatedToken}`, // Use impersonated token to see only what user has access to
          'Content-Type': 'application/json'
        }
      });
      
      dataModelsList = dataModelsResponse.data.entries || [];
      console.log(`🗃️ Data Models accessible to user: ${dataModelsList.length}`);
      
      // Debug: Log the first data model to see its structure
      if (dataModelsList.length > 0) {
        console.log(`\n📝 Sample data model structure:`, JSON.stringify(dataModelsList[0], null, 2));
        console.log(`\n🔑 Available fields:`, Object.keys(dataModelsList[0]));
        if (dataModelsList[0].dataModelUrlId) {
          console.log(`✅ Found dataModelUrlId: ${dataModelsList[0].dataModelUrlId}`);
        } else if (dataModelsList[0].urlId) {
          console.log(`✅ Found urlId: ${dataModelsList[0].urlId}`);
        } else {
          console.log(`⚠️ No URL ID field found, will use dataModelId: ${dataModelsList[0].dataModelId}`);
        }
      }
      
      // If there are more data models, fetch them with pagination
      let nextPage = dataModelsResponse.data.nextPage;
      while (nextPage) {
        console.log(`📄 Fetching next page of data models...`);
        const nextResponse = await axios.get(`${SIGMA_BASE_URL}/dataModels?page=${nextPage}&limit=500`, {
          headers: {
            Authorization: `Bearer ${impersonatedToken}`,
            'Content-Type': 'application/json'
          }
        });
        
        const moreDataModels = nextResponse.data.entries || [];
        dataModelsList = [...dataModelsList, ...moreDataModels];
        nextPage = nextResponse.data.nextPage;
      }
      
      console.log(`🗃️ Total Data Models after pagination: ${dataModelsList.length}`);
      
    } catch (dataModelErr) {
      if (dataModelErr.response?.status === 404) {
        console.log(`📝 Note: Data models endpoint returned 404. This could mean:`);
        console.log(`   - Data models are not enabled in your Sigma instance`);
        console.log(`   - Your Sigma version doesn't support data models yet`);
        console.log(`   - The API endpoint might be different for your configuration`);
        
        // Try alternative: Check if data models are in the files endpoint
        console.log(`\n🔍 Checking for data models in files endpoint...`);
        const dataModelInodes = allInodes.filter(inode => 
          inode.type === 'data-model' || 
          inode.type === 'datamodel' || 
          inode.type === 'dataset'
        );
        
        if (dataModelInodes.length > 0) {
          console.log(`✅ Found ${dataModelInodes.length} data model-like items in files endpoint`);
          dataModelsList = dataModelInodes.map(dm => ({
            dataModelId: dm.id,
            urlId: dm.urlId || dm.id,
            name: dm.name,
            path: dm.path,
            permission: dm.permission,
            createdBy: dm.createdBy,
            updatedBy: dm.updatedBy,
            createdAt: dm.createdAt,
            updatedAt: dm.updatedAt
          }));
        } else {
          console.log(`ℹ️ No data models found. They may not be available in your Sigma instance.`);
        }
      } else {
        console.error(`⚠️ Error fetching data models:`, dataModelErr.response?.data || dataModelErr.message);
        if (dataModelErr.response?.status === 403) {
          console.log(`🔒 User may not have permission to view data models`);
        }
      }
      console.log(`Continuing with workbooks only...`);
    }
    } else {
      console.log(`\n📝 Data models feature is disabled via ENABLE_DATA_MODELS flag`);
    }
    
    // Map workbooks
    const workbooks = workbookInodes.map(wb => ({
      itemType: 'workbook',
      workbookId: wb.id,
      workbookUrlId: wb.urlId,
      name: wb.name,
      path: wb.path,
      permission: wb.permission,
      badge: wb.badge,
      parentId: wb.parentId,
      parentUrlId: wb.parentUrlId,
      ownerId: wb.ownerId,
      createdBy: wb.createdBy,
      updatedBy: wb.updatedBy,
      createdAt: wb.createdAt,
      updatedAt: wb.updatedAt,
      isArchived: wb.isArchived
    }));
    
    // Map data models - using the actual structure from the /v2/dataModels endpoint
    const dataModels = dataModelsList.map(dm => {
      // Log the structure for debugging
      if (dataModelsList.indexOf(dm) === 0) {
        console.log(`\n🔍 Mapping data model with structure:`, Object.keys(dm));
        console.log(`📝 Raw data model object:`, JSON.stringify(dm, null, 2));
      }
      
      const mapped = {
        itemType: 'data-model',
        dataModelId: dm.dataModelId || dm.id,  // Try both possible field names
        dataModelUrlId: dm.dataModelUrlId || dm.urlId || dm.dataModelId || dm.id,  // Check dataModelUrlId first!
        name: dm.name,
        path: dm.path || '/',  // Data models might not have paths
        permission: dm.permission || 'view',
        badge: dm.badge || null,
        description: dm.description,
        createdBy: dm.createdBy,
        updatedBy: dm.updatedBy,
        createdAt: dm.createdAt,
        updatedAt: dm.updatedAt,
        isArchived: dm.isArchived || false
      };
      
      // Log what we mapped
      if (dataModelsList.indexOf(dm) === 0) {
        console.log(`\n✅ Mapped data model result:`);
        console.log(`  - dataModelId: ${mapped.dataModelId}`);
        console.log(`  - dataModelUrlId: ${mapped.dataModelUrlId}`);
        console.log(`  - name: ${mapped.name}`);
      }
      
      return mapped;
    });
    
    workbooks.sort((a, b) => a.name.localeCompare(b.name));
    dataModels.sort((a, b) => a.name.localeCompare(b.name));
    
    // Debug: Log the mapped data models
    console.log(`\n📊 Mapped ${workbooks.length} workbooks`);
    console.log(`🗃️ Mapped ${dataModels.length} data models`);
    
    if (dataModels.length > 0) {
      console.log(`\n📝 First mapped data model:`, JSON.stringify(dataModels[0], null, 2));
    }
    
    // Log sample data models for debugging
    if (dataModels.length > 0) {
      console.log(`\n📋 First 3 data models:`);
      dataModels.slice(0, 3).forEach((dm, idx) => {
        console.log(`  ${idx + 1}. ${dm.name}`);
        console.log(`     ID: ${dm.dataModelId}`);
        console.log(`     URL ID: ${dm.dataModelUrlId}`);
        console.log(`     Path: ${dm.path}`);
        console.log(`     Created: ${dm.createdAt}`);
      });
      
      if (dataModels.length > 3) {
        console.log(`  ... and ${dataModels.length - 3} more data models`);
      }
    }
    
    console.log(`\n✅ Successfully fetched ${workbooks.length} workbooks and ${dataModels.length} data models for ${userEmail}`);
    console.log(`===========================================\n`);
    
    // Debug: Verify what we're returning
    const result = { workbooks, dataModels };
    console.log(`📤 Returning: ${result.workbooks.length} workbooks, ${result.dataModels.length} data models`);
    
    return result;
    
  } catch (err) {
    console.error('\n❌ === ERROR FETCHING ACCESSIBLE ITEMS ===');
    console.error('Error details:', err.response?.data || err.message);
    console.error(`===========================================\n`);
    
    return { workbooks: [], dataModels: [] };
  }
}

// Dedicated function to get only data models for a user
async function getDataModelsForUser(userEmail, bearerToken) {
  try {
    console.log(`\n🔍 === FETCHING DATA MODELS FOR USER ===`);
    console.log(`👤 User Email: ${userEmail}`);
    
    // Use JWT-based impersonation token to respect user permissions
    console.log(`\n🎭 Creating impersonated token for: ${userEmail}`);
    const impersonatedToken = await getImpersonatedBearerToken(userEmail);
    console.log(`✅ Got impersonated token`);
    
    // Fetch data models using the dedicated endpoint with impersonation
    console.log(`📍 Fetching data models from: ${SIGMA_DATA_MODELS_URL}`);
    console.log(`🎭 Using impersonated token to respect user permissions`);
    
    let dataModelsList = [];
    const initialResponse = await axios.get(`${SIGMA_DATA_MODELS_URL}?limit=500`, {
      headers: {
        Authorization: `Bearer ${impersonatedToken}`,
        'Content-Type': 'application/json'
      }
    });
    
    dataModelsList = initialResponse.data.entries || [];
    console.log(`🗃️ Initial fetch returned ${dataModelsList.length} data models`);
    
    // Handle pagination if there are more results
    let nextPage = initialResponse.data.nextPage;
    while (nextPage) {
      console.log(`📄 Fetching next page of data models...`);
      const nextResponse = await axios.get(`${SIGMA_DATA_MODELS_URL}?page=${nextPage}&limit=500`, {
        headers: {
          Authorization: `Bearer ${impersonatedToken}`,
          'Content-Type': 'application/json'
        }
      });
      
      const moreDataModels = nextResponse.data.entries || [];
      dataModelsList = [...dataModelsList, ...moreDataModels];
      nextPage = nextResponse.data.nextPage;
    }
    
    // Map data models to our standard format
    const dataModels = dataModelsList.map(dm => ({
      itemType: 'data-model',
      dataModelId: dm.dataModelId,
      dataModelUrlId: dm.dataModelUrlId || dm.urlId || dm.dataModelId,  // Check dataModelUrlId first!
      name: dm.name,
      path: dm.path || '/',
      permission: dm.permission || 'view',
      badge: dm.badge || null,
      description: dm.description,
      createdBy: dm.createdBy,
      updatedBy: dm.updatedBy,
      createdAt: dm.createdAt,
      updatedAt: dm.updatedAt,
      isArchived: dm.isArchived || false
    }));
    
    dataModels.sort((a, b) => a.name.localeCompare(b.name));
    
    console.log(`✅ Successfully fetched ${dataModels.length} data models for ${userEmail}`);
    
    // Log sample for debugging
    if (dataModels.length > 0) {
      console.log(`\nSample data model:`);
      const sample = dataModels[0];
      console.log(`  Name: ${sample.name}`);
      console.log(`  ID: ${sample.dataModelId}`);
      console.log(`  URL ID: ${sample.dataModelUrlId}`);
    }
    
    return dataModels;
    
  } catch (err) {
    console.error('\n❌ Error fetching data models:', err.response?.data || err.message);
    
    if (err.response?.status === 404) {
      console.log(`📝 Data models endpoint not found (404). Possible reasons:`);
      console.log(`   - Data models feature is not enabled in your Sigma instance`);
      console.log(`   - Your Sigma version doesn't support the data models API yet`);
      console.log(`   - The endpoint URL might be different for your configuration`);
      console.log(`\n💡 To check if data models are available:`);
      console.log(`   1. Log into Sigma Computing directly`);
      console.log(`   2. Check if you can create or view data models in the UI`);
      console.log(`   3. Contact Sigma support if the feature should be available`);
    } else if (err.response?.status === 403) {
      console.error('⚠️ User does not have permission to view data models');
    } else if (err.response?.status === 401) {
      console.error('⚠️ Authentication failed - token may be invalid');
    }
    
    return [];
  }
}

async function getWorkbooksForUser(userEmail, bearerToken) {
  try {
    console.log(`\n🔍 === FETCHING ACCESSIBLE ITEMS FOR USER ===`);
    console.log(`👤 User Email: ${userEmail}`);
    
    // Check if user is internal (Sigma member) or external (embed user)
    const isInternal = await isInternalUser(userEmail, bearerToken);
    console.log(`🔑 User Type: ${isInternal ? 'INTERNAL (Sigma member)' : 'EXTERNAL (Embed user)'}`);
    
    let memberId = null;
    if (isInternal) {
      // For internal users, get their member info to see account type and member ID
      const memberInfo = await getMemberInfo(userEmail, bearerToken);
      if (memberInfo) {
        memberId = memberInfo.memberId;
        console.log(`📊 Member ID: ${memberId}`);
        console.log(`📊 Account Type: ${memberInfo.accountType || 'Unknown'}`);
        console.log(`⚠️ Note: Internal users (especially Admins) may see all workbooks`);
      }
    }
    
    // Use JWT-based impersonation token
    console.log(`\n🎭 Using JWT-based impersonation for: ${userEmail}`);
    const impersonatedToken = await getImpersonatedBearerToken(userEmail);
    
    console.log(`✅ Got impersonated token (length: ${impersonatedToken?.length || 0} chars)`);
    
    // If we don't have a member ID yet, we need to get it using the impersonated token
    if (!memberId) {
      console.log(`🔍 Getting member ID for: ${userEmail}`);
      const memberInfo = await getMemberInfo(userEmail, impersonatedToken);
      if (memberInfo) {
        memberId = memberInfo.memberId;
        console.log(`📊 Found Member ID: ${memberId}`);
      } else {
        console.error(`❌ Could not find member ID for: ${userEmail}`);
        return [];
      }
    }
    
    // Use the new listaccessibleinodes endpoint - shows folders/files/workbooks user has access to
    // Format: GET /v2/members/{memberId}/files
    // NOTE: This endpoint requires admin permissions and doesn't work with impersonation
    const inodesListUrl = `${SIGMA_BASE_URL}/members/${memberId}/files?limit=1000`;
    console.log(`📍 Fetching from: ${inodesListUrl}`);
    console.log(`🔐 Using admin token (no impersonation) for admin endpoint`);
    
    // Get admin bearer token WITHOUT impersonation for this admin-only endpoint
    const adminToken = await getBearerToken();
    
    const inodesResponse = await axios.get(inodesListUrl, {
      headers: {
        Authorization: `Bearer ${adminToken}`,
        'Content-Type': 'application/json'
      }
    });
    
    const allInodes = inodesResponse.data.entries || [];
    console.log(`\n📊 === INODES RESPONSE (via Admin Token) ===`);
    console.log(`📚 Total accessible items: ${allInodes.length}`);
    console.log(`👤 Items accessible to: ${userEmail}`);
    console.log(`🔐 Retrieved using admin client credentials`);
    
    // Filter for workbooks only and count other types
    const workbookInodes = allInodes.filter(inode => inode.type === 'workbook');
    const folderInodes = allInodes.filter(inode => inode.type === 'folder');
    const otherInodes = allInodes.filter(inode => inode.type !== 'workbook' && inode.type !== 'folder');
    
    console.log(`📁 Folders: ${folderInodes.length}`);
    console.log(`📊 Workbooks: ${workbookInodes.length}`);
    if (otherInodes.length > 0) {
      console.log(`📄 Other items: ${otherInodes.length}`);
    }
    
    if (isInternal) {
      console.log(`\n⚠️  IMPORTANT: This is an internal Sigma user.`);
      console.log(`   If they're seeing all workbooks, this is likely because:`);
      console.log(`   1. They have Admin account type (Admins can see everything)`);
      console.log(`   2. They have explicit grants to many/all workbooks`);
      console.log(`   3. The impersonation is working correctly, but showing their actual access`);
    } else {
      console.log(`\n✅ This is an external embed user - results are limited to their grants`);
    }
    
    if (workbookInodes.length > 0) {
      console.log(`\n📋 First 10 workbooks:`);
      workbookInodes.slice(0, 10).forEach((wb, idx) => {
        console.log(`  ${idx + 1}. ${wb.name}`);
        console.log(`     ID: ${wb.id}`);
        console.log(`     URL ID: ${wb.urlId}`);
        console.log(`     Path: ${wb.path || 'Root'}`);
        console.log(`     Permission: ${wb.permission}`);
        console.log(`     Badge: ${wb.badge || 'None'}`);
      });
      
      if (workbookInodes.length > 10) {
        console.log(`  ... and ${workbookInodes.length - 10} more workbooks`);
      }
    }
    
    // Map the inodes to our workbook format
    const workbooks = workbookInodes.map(wb => {
      return {
        itemType: 'workbook', // Added itemType field
        workbookId: wb.id,
        workbookUrlId: wb.urlId,
        name: wb.name,
        path: wb.path,
        permission: wb.permission,
        badge: wb.badge,
        parentId: wb.parentId,
        parentUrlId: wb.parentUrlId,
        ownerId: wb.ownerId,
        createdBy: wb.createdBy,
        updatedBy: wb.updatedBy,
        createdAt: wb.createdAt,
        updatedAt: wb.updatedAt,
        isArchived: wb.isArchived
      };
    });
    
    workbooks.sort((a, b) => a.name.localeCompare(b.name));
    
    console.log(`\n✅ Successfully fetched ${workbooks.length} workbook details for ${userEmail}`);
    console.log(`===========================================\n`);
    return workbooks;
    
  } catch (err) {
    console.error('\n❌ === ERROR FETCHING ACCESSIBLE ITEMS ===');
    console.error(`Using Admin Client Credentials`);
    console.error(`Target User: ${userEmail}`);
    console.error('Error details:', err.response?.data || err.message);
    console.error('Status:', err.response?.status);
    
    if (err.response?.status === 403 && err.response?.data?.message?.includes('canManageUsers')) {
      console.error('\n⚠️  Permission Error: The admin account needs "canManageUsers" permission');
      console.error(`   Please ensure your client credentials have Admin account type in Sigma`);
    }
    
    console.error('===========================================\n');
    return [];
  }
}

// Helper function to get detailed member info
async function getMemberInfo(userEmail, bearerToken) {
  try {
    const url = `${SIGMA_MEMBERS_URL}?search=${encodeURIComponent(userEmail)}`;
    const response = await axios.get(url, {
      headers: {
        Authorization: `Bearer ${bearerToken}`,
        'Content-Type': 'application/json'
      }
    });

    const entries = response.data.entries || [];
    if (entries.length > 0) {
      return entries[0];
    }
    return null;
  } catch (error) {
    console.error('Error getting member info:', error.response?.data || error.message);
    return null;
  }
}

// Helper to check if user is an admin (admins can't be impersonated)
async function isAdminUser(userEmail, bearerToken) {
  try {
    const memberInfo = await getMemberInfo(userEmail, bearerToken);
    if (!memberInfo) {
      return false;
    }
    
    const accountType = memberInfo.accountType?.toLowerCase() || '';
    const isAdmin = accountType === 'admin';
    
    if (isAdmin) {
      console.log(`👑 User ${userEmail} is an Admin - cannot impersonate`);
    }
    
    return isAdmin;
  } catch (error) {
    console.error('Error checking admin status:', error);
    return false;
  }
}

function generateUserAttributes(email) {
  const emailParts = email.split('@');
  const domain = emailParts[1];
  const username = emailParts[0];
  
  const nameParts = username.split(/[._+]/);
  const givenName = nameParts[0] ? nameParts[0].charAt(0).toUpperCase() + nameParts[0].slice(1) : 'User';
  const familyName = nameParts[1] ? nameParts[1].charAt(0).toUpperCase() + nameParts[1].slice(1) : 'Demo';
  
  return { givenName, familyName, domain };
}

async function generateSignedUrl(workbookUrlId, email = 'demo@plugselectronics.com', bookmarkId = null, customParams = {}) {
  try {
    console.log(`📐 Generating signed URL for user: ${email}`);
    console.log(`Workbook URL ID: ${workbookUrlId}`);
    
    if (Object.keys(customParams).length > 0) {
      console.log(`Custom parameters:`, customParams);
    }
    
    const sessionLength = 3600;
    const time = Math.floor(Date.now() / 1000);
    const { givenName, familyName } = generateUserAttributes(email);

    const bearerToken = await getBearerToken();
    
    // Get user configuration from database
    const userConfig = await getUserConfig(email);
    let isInternal = false;
    let teams = [];
    let accountType = 'Pro'; // Default
    let userAttributes = {};
    
    if (userConfig) {
      console.log(`👤 Found user configuration for ${email}`);
      isInternal = userConfig.isInternal;
      teams = userConfig.teams || [];
      accountType = userConfig.accountType || 'Pro';
      userAttributes = userConfig.userAttributes || {};
    } else {
      // Check if they're internal in Sigma
      isInternal = await isInternalUser(email, bearerToken);
      console.log(`👤 No configuration found, checking Sigma: internal = ${isInternal}`);
    }

    const tokenData = {
      sub: email,
      iss: embedClientId,
      jti: crypto.randomUUID(),
      iat: time,
      exp: time + sessionLength
    };

    if (!isInternal) {
      console.log(`👤 External user - adding configured attributes`);
      tokenData.first_name = givenName;
      tokenData.last_name = familyName;
      tokenData.account_type = accountType;
      
      if (teams.length > 0) {
        tokenData.teams = teams;
      }
      
      if (Object.keys(userAttributes).length > 0) {
        tokenData.user_attributes = userAttributes;
      }
      
      console.log(`📋 JWT claims: account_type=${accountType}, teams=${teams.join(',')}, attributes=${JSON.stringify(userAttributes)}`);
    } else {
      console.log('🏢 Internal user detected – omitting all optional claims.');
    }

    const tokenHeader = {
      algorithm: 'HS256',
      keyid: embedClientId
    };

    const token = jwt.sign(tokenData, embedSecret, tokenHeader);

    let signedUrl = `https://app.sigmacomputing.com/${sigmaOrg}/workbook/${workbookUrlId}`;
    
    signedUrl += `?:jwt=${token}`;
    signedUrl += `&:embed=true`;
    signedUrl += `&:menu_position=bottom`;
    signedUrl += `&:enable_inbound_events=true`;
    signedUrl += `&:enable_outbound_events=true`;
    signedUrl += `&:show_footer=true`;
    
    if (bookmarkId) {
      signedUrl += `&:bookmark=${bookmarkId}`;
      console.log(`📖 Loading bookmark: ${bookmarkId}`);
    }
    
    // Add any custom parameters passed
    Object.keys(customParams).forEach(key => {
      const value = customParams[key];
      if (value !== undefined && value !== null && value !== '') {
        if (Array.isArray(value)) {
          signedUrl += `&${encodeURIComponent(key)}=${encodeURIComponent(JSON.stringify(value))}`;
        } else {
          signedUrl += `&${encodeURIComponent(key)}=${encodeURIComponent(value)}`;
        }
      }
    });

    console.log(`Signed URL generated successfully`);
    return signedUrl;
  } catch (error) {
    console.error("❌ Failed to generate signed URL:", error);
    throw error;
  }
}

// Enhanced version of generateSignedUrl that supports data models
async function generateSignedUrlV2(itemUrlId, email = 'demo@plugselectronics.com', bookmarkId = null, customParams = {}, itemType = 'workbook') {
  try {
    console.log(`📐 Generating signed URL for user: ${email}`);
    console.log(`${itemType === 'data-model' ? 'Data Model' : 'Workbook'} URL ID: ${itemUrlId}`);
    console.log(`Item Type: ${itemType}`);
    
    if (Object.keys(customParams).length > 0) {
      console.log(`Custom parameters:`, customParams);
    }
    
    const sessionLength = 3600;
    const time = Math.floor(Date.now() / 1000);
    const { givenName, familyName } = generateUserAttributes(email);

    const bearerToken = await getBearerToken();
    
    // Get user configuration from database
    const userConfig = await getUserConfig(email);
    let isInternal = false;
    let teams = [];
    let accountType = 'Pro'; // Default
    let userAttributes = {};
    
    if (userConfig) {
      console.log(`👤 Found user configuration for ${email}`);
      isInternal = userConfig.isInternal;
      teams = userConfig.teams || [];
      accountType = userConfig.accountType || 'Pro';
      userAttributes = userConfig.userAttributes || {};
    } else {
      // Check if they're internal in Sigma
      isInternal = await isInternalUser(email, bearerToken);
      console.log(`👤 No configuration found, checking Sigma: internal = ${isInternal}`);
    }

    const tokenData = {
      sub: email,
      iss: embedClientId,
      jti: crypto.randomUUID(),
      iat: time,
      exp: time + sessionLength
    };

    if (!isInternal) {
      console.log(`👤 External user - adding configured attributes`);
      tokenData.first_name = givenName;
      tokenData.last_name = familyName;
      tokenData.account_type = accountType;
      
      if (teams.length > 0) {
        tokenData.teams = teams;
      }
      
      if (Object.keys(userAttributes).length > 0) {
        tokenData.user_attributes = userAttributes;
      }
      
      console.log(`📋 JWT claims: account_type=${accountType}, teams=${teams.join(',')}, attributes=${JSON.stringify(userAttributes)}`);
    } else {
      console.log('🏢 Internal user detected - omitting all optional claims.');
    }

    const tokenHeader = {
      algorithm: 'HS256',
      keyid: embedClientId
    };

    const token = jwt.sign(tokenData, embedSecret, tokenHeader);

    // Construct the appropriate URL based on item type
    let signedUrl;
    if (itemType === 'data-model') {
      signedUrl = `https://app.sigmacomputing.com/${sigmaOrg}/data-model/${itemUrlId}`;
    } else {
      signedUrl = `https://app.sigmacomputing.com/${sigmaOrg}/workbook/${itemUrlId}`;
    }
    
    signedUrl += `?:jwt=${token}`;
    signedUrl += `&:embed=true`;
    signedUrl += `&:menu_position=bottom`;
    signedUrl += `&:enable_inbound_events=true`;
    signedUrl += `&:enable_outbound_events=true`;
    signedUrl += `&:show_footer=true`;
    
    // Add PLUGS theme - you can choose one of these options:
    
    // Option 1: Only for data models
    if (itemType === 'data-model') {
      signedUrl += `&:theme=PLUGS`;
      console.log('🎨 Applied PLUGS theme to data model');
    }
    
    // Option 2: For both workbooks and data models (uncomment to use)
    // signedUrl += `&:theme=PLUGS`;
    // console.log(`🎨 Applied PLUGS theme to ${itemType}`);
    
    if (bookmarkId) {
      signedUrl += `&:bookmark=${bookmarkId}`;
      console.log(`📖 Loading bookmark: ${bookmarkId}`);
    }
    
    // Add any custom parameters passed
    Object.keys(customParams).forEach(key => {
      const value = customParams[key];
      if (value !== undefined && value !== null && value !== '') {
        if (Array.isArray(value)) {
          signedUrl += `&${encodeURIComponent(key)}=${encodeURIComponent(JSON.stringify(value))}`;
        } else {
          signedUrl += `&${encodeURIComponent(key)}=${encodeURIComponent(value)}`;
        }
      }
    });

    console.log(`✅ Signed URL generated successfully for ${itemType}`);
    return signedUrl;
  } catch (error) {
    console.error(`❌ Failed to generate signed URL for ${itemType}:`, error);
    throw error;
  }
}

// Authentication endpoints (NO authentication required for login!)
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  
  try {
    // Get user from database
    const user = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM users WHERE email = ? AND is_active = 1',
        [email.toLowerCase()],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    // Verify password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    // Update last login
    db.run(
      'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
      [user.id]
    );
    
    // Generate session token
    const sessionToken = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        isAdmin: user.is_admin === 1
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    // Store session
    activeSessions.set(sessionToken, {
      userId: user.id,
      email: user.email,
      isAdmin: user.is_admin === 1,
      expiresAt: Date.now() + (24 * 60 * 60 * 1000) // 24 hours
    });
    
    console.log(`✅ Authentication successful for: ${email}`);
    
    res.json({
      success: true,
      token: sessionToken,
      email: user.email,
      isAdmin: user.is_admin === 1
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
});

app.post('/api/logout', authenticateToken, (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (token) {
    activeSessions.delete(token);
  }
  
  res.json({ success: true, message: 'Logged out successfully' });
});

app.get('/api/verify-session', authenticateToken, (req, res) => {
  res.json({
    valid: true,
    email: req.user.email,
    isAdmin: req.user.isAdmin
  });
});

app.post('/api/register', authenticateToken, requireAdmin, async (req, res) => {
  const { email, password, isAdmin, isInternal, teams, accountType, userAttributes } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  
  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    
    // Create user
    await new Promise((resolve, reject) => {
      db.run(
        `INSERT INTO users (email, password_hash, is_admin, is_active)
         VALUES (?, ?, ?, 1)`,
        [email.toLowerCase(), hashedPassword, isAdmin ? 1 : 0],
        (err) => {
          if (err) {
            if (err.message.includes('UNIQUE')) {
              reject({ code: 'USER_EXISTS' });
            } else {
              reject(err);
            }
          } else {
            resolve();
          }
        }
      );
    });
    
    // Create user config
    await new Promise((resolve, reject) => {
      db.run(
        `INSERT INTO user_configs (email, is_internal, teams, account_type, user_attributes)
         VALUES (?, ?, ?, ?, ?)`,
        [
          email.toLowerCase(),
          isInternal ? 1 : 0,
          teams ? JSON.stringify(teams) : null,
          accountType || null,
          userAttributes ? JSON.stringify(userAttributes) : null
        ],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
    
    console.log(`✅ User created: ${email} (Admin: ${isAdmin})`);
    
    res.json({
      success: true,
      message: 'User created successfully'
    });
    
  } catch (error) {
    if (error.code === 'USER_EXISTS') {
      return res.status(400).json({ error: 'User already exists' });
    }
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Failed to create user' });
  }
});

// ADMIN API ENDPOINTS

// Get all Sigma teams
app.get('/api/sigma/teams', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const bearerToken = await getBearerToken();
    const response = await axios.get(SIGMA_TEAMS_URL, {
      headers: {
        Authorization: `Bearer ${bearerToken}`,
        'Content-Type': 'application/json'
      }
    });
    
    const teams = response.data.entries || [];
    console.log(`📋 Fetched ${teams.length} teams from Sigma`);
    
    res.json({ 
      teams: teams.map(team => ({
        id: team.teamId,
        name: team.name,
        memberCount: team.memberCount
      }))
    });
  } catch (error) {
    console.error('Error fetching teams:', error.response?.data || error.message);
    res.status(500).json({ error: 'Failed to fetch teams' });
  }
});

// Get all Sigma account types
app.get('/api/sigma/account-types', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const bearerToken = await getBearerToken();
    const response = await axios.get(SIGMA_ACCOUNT_TYPES_URL, {
      headers: {
        Authorization: `Bearer ${bearerToken}`,
        'Content-Type': 'application/json'
      }
    });
    
    const accountTypes = response.data.entries || [];
    console.log(`Fetched ${accountTypes.length} account types from Sigma`);
    
    res.json({ 
      accountTypes: accountTypes.map(type => ({
        id: type.accountTypeId,
        name: type.accountTypeName,  // Changed from type.name to type.accountTypeName
        description: type.description,
        isCustom: type.isCustom
      }))
    });
  } catch (error) {
    console.error('Error fetching account types:', error.response?.data || error.message);
    
    // If error, provide fallback account types based on your actual Sigma instance
    const fallbackTypes = [
      { id: 'embed-basic', name: 'Embed Basic', description: '', isCustom: true },
      { id: 'admin', name: 'admin', description: 'Administration of Sigma, full access to all Sigma features', isCustom: false },
      { id: 'pro', name: 'Pro', description: 'Model data, create and analyze data sources, find and share insights', isCustom: false },
      { id: 'lite', name: 'lite', description: 'View pre-existing reports and interact with pre-defined controls', isCustom: false },
      { id: 'essential', name: 'essential', description: 'Deeply explore pre-existing reports, set up schedules and alerts', isCustom: false }
    ];
    
    res.json({ accountTypes: fallbackTypes });
  }
});

// Get all Sigma user attributes
app.get('/api/sigma/user-attributes', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const bearerToken = await getBearerToken();
    
    // Try to fetch from Sigma API
    try {
      const response = await axios.get(SIGMA_USER_ATTRIBUTES_URL, {
        headers: {
          Authorization: `Bearer ${bearerToken}`,
          'Content-Type': 'application/json'
        }
      });
      
      const attributes = response.data.entries || [];
      console.log(`Fetched ${attributes.length} user attributes from Sigma`);
      
      res.json({ 
        attributes: attributes.map(attr => ({
          id: attr.userAttributeId || attr.id,
          name: attr.name,
          defaultValue: attr.defaultValue
        }))
      });
    } catch (apiError) {
      // If the API endpoint doesn't exist or returns 404, provide default attributes
      if (apiError.response?.status === 404) {
        console.log('⚠️ User attributes endpoint not available, using defaults');
        
        // Default user attributes commonly used
        const defaultAttributes = [
          { id: 'region', name: 'Region', defaultValue: '' },
          { id: 'department', name: 'Department', defaultValue: '' },
          { id: 'role', name: 'Role', defaultValue: '' },
          { id: 'country', name: 'Country', defaultValue: '' },
          { id: 'division', name: 'Division', defaultValue: '' },
          { id: 'cost_center', name: 'Cost Center', defaultValue: '' },
          { id: 'manager', name: 'Manager', defaultValue: '' },
          { id: 'employee_id', name: 'Employee ID', defaultValue: '' },
          { id: 'office_location', name: 'Office Location', defaultValue: '' },
          { id: 'access_level', name: 'Access Level', defaultValue: '' }
        ];
        
        res.json({ attributes: defaultAttributes });
      } else {
        throw apiError;
      }
    }
  } catch (error) {
    console.error('Error fetching user attributes:', error.response?.data || error.message);
    
    // Fallback to basic attributes
    const fallbackAttributes = [
      { id: 'department', name: 'Department', defaultValue: '' },
      { id: 'role', name: 'Role', defaultValue: '' },
      { id: 'location', name: 'Location', defaultValue: '' }
    ];
    
    res.json({ attributes: fallbackAttributes });
  }
});

// Get all configured users
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    db.all(`
      SELECT 
        u.email,
        u.is_admin,
        u.is_active,
        u.created_at as user_created_at,
        u.last_login,
        uc.is_internal,
        uc.teams,
        uc.account_type,
        uc.user_attributes,
        uc.created_at,
        uc.updated_at
      FROM users u
      LEFT JOIN user_configs uc ON u.email = uc.email
      ORDER BY u.email ASC
    `, [], (err, rows) => {
      if (err) {
        console.error('Error fetching users:', err);
        return res.status(500).json({ error: 'Failed to fetch users' });
      }
      
      const users = rows.map(row => ({
        email: row.email,
        isAdmin: row.is_admin === 1,
        isActive: row.is_active === 1,
        isInternal: row.is_internal === 1,
        teams: row.teams ? JSON.parse(row.teams) : [],
        accountType: row.account_type,
        userAttributes: row.user_attributes ? JSON.parse(row.user_attributes) : {},
        createdAt: row.user_created_at || row.created_at,
        updatedAt: row.updated_at,
        lastLogin: row.last_login
      }));
      
      res.json({ users });
    });
  } catch (error) {
    console.error('Error in get users endpoint:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Update user configuration
app.put('/api/admin/users/:email', authenticateToken, requireAdmin, async (req, res) => {
  const userEmail = decodeURIComponent(req.params.email);
  const { password, isAdmin, isInternal, teams, accountType, userAttributes } = req.body;
  
  try {
    // Update password if provided
    if (password && password.length >= 8) {
      const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
      await new Promise((resolve, reject) => {
        db.run(
          'UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE email = ?',
          [hashedPassword, userEmail.toLowerCase()],
          (err) => {
            if (err) reject(err);
            else resolve();
          }
        );
      });
      console.log(`✅ Password updated for: ${userEmail}`);
    }
    
    // Update admin status
    if (isAdmin !== undefined) {
      await new Promise((resolve, reject) => {
        db.run(
          'UPDATE users SET is_admin = ?, updated_at = CURRENT_TIMESTAMP WHERE email = ?',
          [isAdmin ? 1 : 0, userEmail.toLowerCase()],
          (err) => {
            if (err) reject(err);
            else resolve();
          }
        );
      });
    }
    
    // Update or create user config
    await new Promise((resolve, reject) => {
      db.run(
        `INSERT INTO user_configs (email, is_internal, teams, account_type, user_attributes, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
         ON CONFLICT(email) DO UPDATE SET
           is_internal = excluded.is_internal,
           teams = excluded.teams,
           account_type = excluded.account_type,
           user_attributes = excluded.user_attributes,
           updated_at = CURRENT_TIMESTAMP`,
        [
          userEmail.toLowerCase(),
          isInternal ? 1 : 0,
          teams ? JSON.stringify(teams) : null,
          accountType || null,
          userAttributes ? JSON.stringify(userAttributes) : null
        ],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
    
    console.log(`✅ Updated configuration for user: ${userEmail}`);
    res.json({ 
      success: true, 
      message: 'User configuration updated successfully'
    });
  } catch (error) {
    console.error('Error updating user config:', error);
    res.status(500).json({ error: 'Failed to update user configuration' });
  }
});

// Delete user configuration
app.delete('/api/admin/users/:email', authenticateToken, requireAdmin, async (req, res) => {
  const userEmail = decodeURIComponent(req.params.email);
  
  // Prevent deletion of super admin
  if (userEmail.toLowerCase() === 'tj@sigmacomputing.com') {
    return res.status(403).json({ error: 'Cannot delete super admin account' });
  }
  
  try {
    // Delete from users table
    await new Promise((resolve, reject) => {
      db.run(
        'DELETE FROM users WHERE email = ?',
        [userEmail.toLowerCase()],
        function(err) {
          if (err) reject(err);
          else resolve(this.changes);
        }
      );
    });
    
    // Delete from user_configs table
    await new Promise((resolve, reject) => {
      db.run(
        'DELETE FROM user_configs WHERE email = ?',
        [userEmail.toLowerCase()],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
    
    console.log(`✅ Deleted user: ${userEmail}`);
    res.json({ 
      success: true, 
      message: 'User deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// Public endpoints (authenticated but not admin-only)
app.get('/api/workbooks', authenticateToken, async (req, res) => {
  const email = req.user.email;
  
  try {
    const bearerToken = await getBearerToken();
    const workbooks = await getWorkbooksForUser(email, bearerToken);
    
    res.json({ workbooks });
  } catch (error) {
    console.error('Error fetching workbooks:', error);
    res.status(500).json({ error: 'Failed to fetch workbooks' });
  }
});

// NEW ENDPOINT: Get both workbooks and data models
app.get('/api/items', authenticateToken, async (req, res) => {
  const email = req.user.email;
  
  try {
    const bearerToken = await getBearerToken();
    const { workbooks, dataModels } = await getWorkbooksAndDataModelsForUser(email, bearerToken);
    
    // Debug: Log what we're sending to the frontend
    if (dataModels.length > 0) {
      console.log(`\n📤 Sending data models to frontend:`);
      dataModels.forEach((dm, idx) => {
        console.log(`  ${idx + 1}. ${dm.name}`);
        console.log(`     - dataModelId: ${dm.dataModelId}`);
        console.log(`     - dataModelUrlId: ${dm.dataModelUrlId}`);
      });
    }
    
    res.json({ 
      workbooks,
      dataModels,
      totalItems: workbooks.length + dataModels.length
    });
  } catch (error) {
    console.error('Error fetching items:', error);
    res.status(500).json({ error: 'Failed to fetch items' });
  }
});

// Get signed URL with workbook and optional bookmark
app.get('/api/signed-url', authenticateToken, async (req, res) => {
  try {
    const workbookId = req.query.workbookId;
    let workbookUrlId = req.query.workbookUrlId;
    const email = req.user.email;
    const bookmarkId = req.query.bookmarkId || null;
    
    const standardParams = ['workbookId', 'workbookUrlId', 'email', 'bookmarkId'];
    const customParams = {};
    
    Object.keys(req.query).forEach(key => {
      if (!standardParams.includes(key)) {
        customParams[key] = req.query[key];
      }
    });
    
    if (workbookUrlId && workbookUrlId.includes('/')) {
      const match = workbookUrlId.match(/\/workbook\/([^/?#]+)/);
      if (match && match[1]) {
        workbookUrlId = match[1];
      }
    }
    
    if (!workbookUrlId && workbookId) {
      const bearerToken = await getBearerToken();
      
      try {
        const workbookResponse = await axios.get(
          `${SIGMA_WORKBOOKS_URL}/${workbookId}`,
          {
            headers: {
              Authorization: `Bearer ${bearerToken}`,
              'Content-Type': 'application/json'
            }
          }
        );
        
        workbookUrlId = extractWorkbookUrlId(workbookResponse.data);
      } catch (err) {
        console.error('Error fetching workbook:', err.response?.data || err.message);
        return res.status(500).json({ error: 'Failed to fetch workbook details' });
      }
    }
    
    if (!workbookUrlId) {
      return res.status(400).json({ error: 'workbookId or workbookUrlId is required' });
    }
    
    const signedUrl = await generateSignedUrl(workbookUrlId, email, bookmarkId, customParams);
    res.json({ 
      url: signedUrl, 
      workbookId,
      workbookUrlId: workbookUrlId,
      email,
      bookmarkId,
      customParams,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('❌ Signed URL generation failed:', error);
    res.status(500).json({ 
      error: 'Failed to generate signed URL', 
      details: error.message 
    });
  }
});

// Enhanced version of generateSignedUrl that supports both workbooks and data models
app.get('/api/signed-url-v2', authenticateToken, async (req, res) => {
  try {
    const email = req.user.email;
    const itemType = req.query.itemType || 'workbook'; // Default to workbook
    const bookmarkId = req.query.bookmarkId || null;
    
    let itemId, itemUrlId;
    
    // Get the appropriate IDs based on item type
    if (itemType === 'data-model') {
      itemId = req.query.dataModelId;
      itemUrlId = req.query.dataModelUrlId || itemId;
    } else {
      itemId = req.query.workbookId;
      itemUrlId = req.query.workbookUrlId || itemId;
    }
    
    // Extract standard parameters
    const standardParams = ['workbookId', 'workbookUrlId', 'dataModelId', 'dataModelUrlId', 'email', 'bookmarkId', 'itemType'];
    const customParams = {};
    
    Object.keys(req.query).forEach(key => {
      if (!standardParams.includes(key)) {
        customParams[key] = req.query[key];
      }
    });
    
    // Clean up URL ID if it contains a full path
    if (itemUrlId && itemUrlId.includes('/')) {
      const match = itemUrlId.match(/\/(?:workbook|data-model)\/([^/?#]+)/);
      if (match && match[1]) {
        itemUrlId = match[1];
      }
    }
    
    // If no URL ID and we have an item ID, try to fetch it from Sigma
    if (!itemUrlId && itemId) {
      const bearerToken = await getBearerToken();
      
      try {
        if (itemType === 'data-model') {
          const response = await axios.get(
            `${SIGMA_DATA_MODELS_URL}/${itemId}`,
            {
              headers: {
                Authorization: `Bearer ${bearerToken}`,
                'Content-Type': 'application/json'
              }
            }
          );
          
          itemUrlId = response.data.dataModelUrlId || response.data.urlId || itemId;
        } else {
          const response = await axios.get(
            `${SIGMA_WORKBOOKS_URL}/${itemId}`,
            {
              headers: {
                Authorization: `Bearer ${bearerToken}`,
                'Content-Type': 'application/json'
              }
            }
          );
          
          itemUrlId = extractWorkbookUrlId(response.data);
        }
      } catch (err) {
        console.error(`Error fetching ${itemType}:`, err.response?.data || err.message);
        return res.status(500).json({ error: `Failed to fetch ${itemType} details` });
      }
    }
    
    if (!itemUrlId) {
      return res.status(400).json({ error: `${itemType === 'data-model' ? 'dataModelId' : 'workbookId'} or corresponding urlId is required` });
    }
    
    // Generate the signed URL with the v2 function that supports both types
    const signedUrl = await generateSignedUrlV2(itemUrlId, email, bookmarkId, customParams, itemType);
    
    res.json({ 
      url: signedUrl, 
      [`${itemType === 'data-model' ? 'dataModel' : 'workbook'}Id`]: itemId,
      [`${itemType === 'data-model' ? 'dataModel' : 'workbook'}UrlId`]: itemUrlId,
      itemType,
      email,
      bookmarkId,
      customParams,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('❌ Signed URL generation failed:', error);
    res.status(500).json({ 
      error: 'Failed to generate signed URL', 
      details: error.message 
    });
  }
});
// Ask Sigma endpoint
app.get('/api/ask-sigma-url', authenticateToken, async (req, res) => {
  try {
    const email = req.user.email;
    const region = req.query.region || 'East';
    const environment = req.query.environment || 'Production';
    const question = req.query.question || '';
    
    console.log(`🧠 Generating Ask Sigma URL for ${email}`);
    console.log(`   Region: ${region}, Environment: ${environment}`);
    console.log(`   Question: ${question || 'None'}`);
    
    const sessionLength = 3600;
    const time = Math.floor(Date.now() / 1000);
    const { givenName, familyName } = generateUserAttributes(email);

    const bearerToken = await getBearerToken();
    
    // Get user configuration from database
    const userConfig = await getUserConfig(email);
    let isInternal = false;
    let teams = [];
    let accountType = 'Pro';
    let userAttributes = {};
    
    if (userConfig) {
      console.log(`👤 Found user configuration for ${email}`);
      isInternal = userConfig.isInternal;
      teams = userConfig.teams || [];
      accountType = userConfig.accountType || 'Pro';
      userAttributes = userConfig.userAttributes || {};
    } else {
      isInternal = await isInternalUser(email, bearerToken);
      console.log(`👤 No configuration found, checking Sigma: internal = ${isInternal}`);
    }

    const tokenData = {
      sub: email,
      iss: embedClientId,
      jti: crypto.randomUUID(),
      iat: time,
      exp: time + sessionLength
    };

    if (!isInternal) {
      console.log(`👤 External user - adding configured attributes`);
      tokenData.first_name = givenName;
      tokenData.last_name = familyName;
      tokenData.account_type = accountType;
      
      if (teams.length > 0) {
        tokenData.teams = teams;
      }
      
      if (Object.keys(userAttributes).length > 0) {
        tokenData.user_attributes = userAttributes;
      }
      
      console.log(`📋 JWT claims: account_type=${accountType}, teams=${teams.join(',')}`);
    } else {
      console.log('🏢 Internal user detected – omitting all optional claims.');
    }

    const tokenHeader = {
      algorithm: 'HS256',
      keyid: embedClientId
    };

    const token = jwt.sign(tokenData, embedSecret, tokenHeader);

    // Ask Sigma URL format
    let signedUrl = `https://app.sigmacomputing.com/${sigmaOrg}/ask`;
    
    signedUrl += `?:jwt=${token}`;
    signedUrl += `&:embed=true`;
    signedUrl += `&:menu_position=bottom`;
    signedUrl += `&:enable_inbound_events=true`;
    signedUrl += `&:enable_outbound_events=true`;
    signedUrl += `&:show_footer=true`;
    
    // Add custom parameters
    if (region) {
      signedUrl += `&Region=${encodeURIComponent(region)}`;
    }
    if (environment) {
      signedUrl += `&Environment=${encodeURIComponent(environment)}`;
    }
    if (question) {
      signedUrl += `&question=${encodeURIComponent(question)}`;
    }

    console.log(`✅ Ask Sigma URL generated successfully`);
    
    res.json({ 
      url: signedUrl,
      email,
      region,
      environment,
      question,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('❌ Ask Sigma URL generation failed:', error);
    res.status(500).json({ 
      error: 'Failed to generate Ask Sigma URL', 
      details: error.message 
    });
  }
});
// Routes
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/workbooks', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'workbooks.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/ask', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'ask-sigma-page.html'));
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    server: 'Plugs Electronics Dashboard Server',
    features: ['authentication', 'workbooks', 'data-models', 'bookmarks', 'admin', 'user-configs', 'dashboard']
  });
});

app.get('*', (req, res) => {
  res.redirect('/');
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('🛑 Shutting down server...');
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err);
    } else {
      console.log('📚 Database connection closed');
    }
    process.exit(0);
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Plugs Electronics Dashboard Server`);
  console.log(`🌐 Server running at http://localhost:${PORT}`);
  console.log(`🔐 Login page: http://localhost:${PORT}/login`);
  console.log(`📚 Workbooks: http://localhost:${PORT}/workbooks`);
  console.log(`📊 Dashboard: http://localhost:${PORT}/`);
  console.log(`👤 Admin Panel: http://localhost:${PORT}/admin`);
  console.log(`🧠 Ask Sigma: http://localhost:${PORT}/ask`);
  console.log(`\n🔒 Authentication is now REQUIRED`);
  console.log(`👑 Default super admin: tj@sigmacomputing.com / Admin@123`);
  console.log(`⚠️  Change the default password after first login!`);
  console.log(`\n✨ Security Features:`);
  console.log(`  - Password hashing with bcrypt`);
  console.log(`  - JWT session tokens`);
  console.log(`  - Admin-only access control`);
  console.log(`  - Session expiry after 24 hours`);
  console.log(`  - Super admin protection`);
});
