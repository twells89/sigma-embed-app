// Enhanced server.js with Admin Panel and User Configuration Management
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const path = require('path');
const axios = require('axios');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = 3001;

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static('public'));

// CORS
app.use((req, res, next) => {
  const allowedOrigins = [
    'https://twells89.github.io',
    'http://localhost:4200',
    'https://app.sigmacomputing.com'
  ];
  
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
const db = new sqlite3.Database('./bookmarks.db', (err) => {
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
    }, 1000);
  });
}

// Sigma API config
const SIGMA_BASE_URL = 'https://aws-api.sigmacomputing.com/v2';
const SIGMA_MEMBERS_URL = `${SIGMA_BASE_URL}/members`;
const SIGMA_WORKBOOKS_URL = `${SIGMA_BASE_URL}/workbooks`;
const SIGMA_DATA_MODELS_URL = `${SIGMA_BASE_URL}/dataModels`;  // Changed to camelCase
const SIGMA_TEAMS_URL = `${SIGMA_BASE_URL}/teams`;
const SIGMA_ACCOUNT_TYPES_URL = `${SIGMA_BASE_URL}/account-types`;
const SIGMA_USER_ATTRIBUTES_URL = `${SIGMA_BASE_URL}/user-attributes`;

const embedClientId = 'ClientId';
const embedSecret = 'Secret';
const sigmaOrg = 'tj-wells-1989';

const clientId = 'ClientId';
const clientSecret = 'Secret';

// Feature flags
const FEATURES = {
  DATA_MODELS: process.env.ENABLE_DATA_MODELS !== 'false', // Default to true, set ENABLE_DATA_MODELS=false to disable
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
      
      console.log(`ðŸ“‹ JWT claims: account_type=${accountType}, teams=${teams.join(',')}, attributes=${JSON.stringify(userAttributes)}`);
    } else {
      console.log('🏢 Internal user detected â€“ omitting all optional claims.');
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
      console.log(`ðŸ“– Loading bookmark: ${bookmarkId}`);
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
    console.error(" Failed to generate signed URL:", error);
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

// Helper function to create bookmark in Sigma
async function createSigmaBookmark(workbookId, bookmarkData, userEmail) {
  try {
    // Use impersonated token to create bookmark as the user
    const impersonatedToken = await getImpersonatedBearerToken(userEmail);
    
    console.log(`📥 Fetching workbook details for ${workbookId}...`);
    const workbookResponse = await axios.get(
      `${SIGMA_WORKBOOKS_URL}/${workbookId}`,
      {
        headers: {
          Authorization: `Bearer ${impersonatedToken}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    console.log(`📄 Workbook API Response:`, JSON.stringify(workbookResponse.data, null, 2));
    const latestVersion = workbookResponse.data.latestVersion;
    console.log(`📌 Using workbook version: ${latestVersion}`);
    
    // Create bookmark as private (isShared: false is the default)
    const payload = {
      name: bookmarkData.name,
      workbookVersion: latestVersion,
      isShared: false, // Bookmarks should be private - sharing is managed in local DB
      exploreKey: bookmarkData.exploreKey || ''
    };
    
    console.log(`📤 Creating Sigma bookmark as user ${userEmail} with payload:`, JSON.stringify(payload, null, 2));
    console.log(`🔒 Note: Creating as private bookmark (isShared=false). Sharing managed in local DB.`);
    
    const response = await axios.post(
      `${SIGMA_WORKBOOKS_URL}/${workbookId}/bookmarks`,
      payload,
      {
        headers: {
          Authorization: `Bearer ${impersonatedToken}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    console.log(`✅ === SIGMA BOOKMARK CREATION SUCCESS ===`);
    console.log(`📊 Full API Response:`, JSON.stringify(response.data, null, 2));
    console.log(`🆔 Bookmark ID: ${response.data.bookmarkId}`);
    console.log(`📝 Bookmark Name: ${response.data.name}`);
    console.log(`👤 Owner ID: ${response.data.ownerId || 'undefined - not returned by API'}`);
    console.log(`📅 Created At: ${response.data.createdAt || 'undefined - not returned by API'}`);
    console.log(`🔗 Workbook Version: ${response.data.workbookVersion}`);
    console.log(`🔍 Explore Key: ${response.data.exploreKey}`);
    console.log(`🔒 Is Shared: ${response.data.isShared}`);
    console.log(`✅ Bookmark successfully created under user: ${userEmail}`);
    console.log(`===========================================\n`);
    
    return response.data;
  } catch (error) {
    console.error(`❌ === SIGMA BOOKMARK CREATION FAILED ===`);
    console.error(`👤 User: ${userEmail}`);
    console.error(`📁 Workbook ID: ${workbookId}`);
    console.error(`🚫 Status Code: ${error.response?.status}`);
    console.error(`📄 Error Response:`, JSON.stringify(error.response?.data, null, 2));
    console.error(`📝 Error Message: ${error.message}`);
    console.error(`===========================================\n`);
    throw error;
  }
}

// Helper function to update bookmark in Sigma with impersonation
async function updateSigmaBookmark(workbookId, bookmarkId, bookmarkData, userEmail) {
  try {
    // Use impersonated token to update bookmark as the user
    const impersonatedToken = await getImpersonatedBearerToken(userEmail);
    
    console.log(`📥 Fetching workbook details for ${workbookId}...`);
    const workbookResponse = await axios.get(
      `${SIGMA_WORKBOOKS_URL}/${workbookId}`,
      {
        headers: {
          Authorization: `Bearer ${impersonatedToken}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    const latestVersion = workbookResponse.data.latestVersion;
    console.log(`📌 Using workbook version: ${latestVersion}`);
    
    const payload = {
      name: bookmarkData.name,
      workbookVersion: latestVersion,
      exploreKey: bookmarkData.exploreKey || ''
    };
    
    console.log(`📤 Updating Sigma bookmark ${bookmarkId} as user ${userEmail} with payload:`, JSON.stringify(payload, null, 2));
    
    const response = await axios.patch(
      `${SIGMA_WORKBOOKS_URL}/${workbookId}/bookmarks/${bookmarkId}`,
      payload,
      {
        headers: {
          Authorization: `Bearer ${impersonatedToken}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    console.log(`✅ === SIGMA BOOKMARK UPDATE SUCCESS ===`);
    console.log(`📊 Full API Response:`, JSON.stringify(response.data, null, 2));
    console.log(`🆔 Bookmark ID: ${response.data.bookmarkId}`);
    console.log(`📝 Updated Name: ${response.data.name}`);
    console.log(`✅ Bookmark successfully updated under user: ${userEmail}`);
    console.log(`===========================================\n`);
    
    return response.data;
  } catch (error) {
    console.error(`❌ === SIGMA BOOKMARK UPDATE FAILED ===`);
    console.error(`👤 User: ${userEmail}`);
    console.error(`📁 Workbook ID: ${workbookId}`);
    console.error(`🔖 Bookmark ID: ${bookmarkId}`);
    console.error(`🚫 Status Code: ${error.response?.status}`);
    console.error(`📄 Error Response:`, JSON.stringify(error.response?.data, null, 2));
    console.error(`📝 Error Message: ${error.message}`);
    console.error(`===========================================\n`);
    throw error;
  }
}

// Helper function to delete bookmark from Sigma with impersonation
async function deleteSigmaBookmark(workbookId, bookmarkId, userEmail) {
  try {
    // Use impersonated token to delete bookmark as the user
    const impersonatedToken = await getImpersonatedBearerToken(userEmail);
    
    console.log(`🗑️ Attempting to delete bookmark ${bookmarkId} from workbook ${workbookId} as user ${userEmail}`);
    
    const response = await axios.delete(
      `${SIGMA_WORKBOOKS_URL}/${workbookId}/bookmarks/${bookmarkId}`,
      {
        headers: {
          Authorization: `Bearer ${impersonatedToken}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    console.log(`✅ === SIGMA BOOKMARK DELETION SUCCESS ===`);
    console.log(`📊 Full API Response:`, JSON.stringify(response.data, null, 2));
    console.log(`🆔 Deleted Bookmark ID: ${bookmarkId}`);
    console.log(`✅ Bookmark successfully deleted by user: ${userEmail}`);
    console.log(`===========================================\n`);
    
    return true;
  } catch (error) {
    if (error.response?.status === 404) {
      console.log(`⚠️ Bookmark ${bookmarkId} not found in Sigma (may have been already deleted)`);
      return true;
    }
    console.error(`❌ === SIGMA BOOKMARK DELETION FAILED ===`);
    console.error(`👤 User: ${userEmail}`);
    console.error(`📁 Workbook ID: ${workbookId}`);
    console.error(`🔖 Bookmark ID: ${bookmarkId}`);
    console.error(`🚫 Status Code: ${error.response?.status}`);
    console.error(`📄 Error Response:`, JSON.stringify(error.response?.data, null, 2));
    console.error(`📝 Error Message: ${error.message}`);
    console.error(`===========================================\n`);
    throw error;
  }
}

// Helper function to verify bookmark exists in Sigma
async function verifyBookmarkInSigma(workbookId, bookmarkId, userEmail) {
  try {
    const impersonatedToken = await getImpersonatedBearerToken(userEmail);
    
    console.log(`🔍 Verifying bookmark ${bookmarkId} exists in Sigma for user ${userEmail}...`);
    
    const response = await axios.get(
      `${SIGMA_WORKBOOKS_URL}/${workbookId}/bookmarks/${bookmarkId}`,
      {
        headers: {
          Authorization: `Bearer ${impersonatedToken}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    console.log(`✅ === BOOKMARK VERIFICATION SUCCESS ===`);
    console.log(`📊 Bookmark Found in Sigma:`, JSON.stringify(response.data, null, 2));
    console.log(`🆔 Bookmark ID: ${response.data.bookmarkId}`);
    console.log(`📝 Name: ${response.data.name}`);
    console.log(`👤 Owner ID: ${response.data.ownerId || 'undefined - not returned by API'}`);
    console.log(`🔍 Explore Key: ${response.data.exploreKey}`);
    console.log(`📅 Created At: ${response.data.createdAt || 'undefined - not returned by API'}`);
    console.log(`===========================================\n`);
    
    return response.data;
  } catch (error) {
    if (error.response?.status === 404) {
      console.error(`❌ === BOOKMARK NOT FOUND IN SIGMA ===`);
      console.error(`🔖 Bookmark ID: ${bookmarkId} does NOT exist in Sigma!`);
      console.error(`👤 User: ${userEmail}`);
      console.error(`📁 Workbook ID: ${workbookId}`);
      console.error(`⚠️ This bookmark may not have been created successfully, or may not be visible to this user.`);
      console.error(`===========================================\n`);
      return null;
    }
    console.error(`❌ === BOOKMARK VERIFICATION FAILED ===`);
    console.error(`👤 User: ${userEmail}`);
    console.error(`🔖 Bookmark ID: ${bookmarkId}`);
    console.error(`🚫 Status Code: ${error.response?.status}`);
    console.error(`📄 Error Response:`, JSON.stringify(error.response?.data, null, 2));
    console.error(`===========================================\n`);
    throw error;
  }
}

// Helper function to sync bookmarks from Sigma to local database
// Helper function to check if user is owner of a bookmark by checking grants
async function isBookmarkOwner(workbookId, bookmarkId, userEmail, bearerToken) {
  try {
    const isAdmin = await isAdminUser(userEmail, bearerToken);
    let token;
    
    if (isAdmin) {
      token = bearerToken;
    } else {
      token = await getImpersonatedBearerToken(userEmail);
    }
    
    // Get grants for this bookmark
    const grantsUrl = `${SIGMA_WORKBOOKS_URL}/${workbookId}/grants`;
    const response = await axios.get(grantsUrl, {
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });
    
    const grants = response.data.entries || [];
    
    // Look for a grant where:
    // 1. The grantee is the user
    // 2. The bookmark is specified
    // 3. The permission is 'write' (owner-level)
    const userGrant = grants.find(grant => 
      grant.grantee?.email?.toLowerCase() === userEmail.toLowerCase() &&
      grant.bookmark?.bookmarkId === bookmarkId &&
      grant.permission === 'write'
    );
    
    return !!userGrant;
  } catch (error) {
    console.error(`Error checking bookmark ownership:`, error.response?.data || error.message);
    // If we can't determine, assume viewer
    return false;
  }
}

async function syncBookmarksFromSigma(workbookId, userEmail) {
  try {
    console.log(`\n🔄 === SYNCING BOOKMARKS FROM SIGMA ===`);
    console.log(`📁 Workbook: ${workbookId}`);
    console.log(`👤 User: ${userEmail}`);
    
    // Get all bookmarks from Sigma for this workbook
    const sigmaBookmarks = await listAllWorkbookBookmarks(workbookId, userEmail);
    
    if (sigmaBookmarks.length === 0) {
      console.log(`ℹ️ No bookmarks found in Sigma for this workbook`);
      return { synced: 0, added: 0, updated: 0 };
    }
    
    let added = 0;
    let updated = 0;
    let accessGranted = 0;
    
    for (const sigmaBm of sigmaBookmarks) {
      // Check if bookmark exists in local DB
      const localBookmark = await new Promise((resolve, reject) => {
        db.get(
          'SELECT * FROM bookmarks WHERE bookmark_id = ?',
          [sigmaBm.bookmarkId],
          (err, row) => {
            if (err) reject(err);
            else resolve(row);
          }
        );
      });
      
      // Determine ownership:
      // 1. If bookmark exists locally, check if created_by matches the user
      // 2. If new bookmark and we used impersonation, user owns it
      // 3. If new bookmark and we're admin (no impersonation), check grants
      let isOwner;
      
      if (localBookmark) {
        // Use the created_by field from local database
        isOwner = localBookmark.created_by && localBookmark.created_by.toLowerCase() === userEmail.toLowerCase();
        console.log(`📌 Bookmark: ${sigmaBm.name} - User is ${isOwner ? 'OWNER' : 'VIEWER'} (created_by: ${localBookmark.created_by})`);
      } else if (sigmaBm._usedImpersonation) {
        // New bookmark, impersonated user owns it
        isOwner = true;
        console.log(`📌 Bookmark: ${sigmaBm.name} - User is OWNER (new bookmark via impersonation)`);
      } else {
        // New bookmark, admin - need to check grants
        console.log(`⚠️ Admin user - checking grants for new bookmark ${sigmaBm.name}...`);
        const bearerToken = await getBearerToken();
        isOwner = await isBookmarkOwner(workbookId, sigmaBm.bookmarkId, userEmail, bearerToken);
        console.log(`📌 Bookmark: ${sigmaBm.name} - User is ${isOwner ? 'OWNER' : 'VIEWER'} (via grants check)`);
      }
      
      const accessType = isOwner ? 'owner' : 'viewer';
      
      if (!localBookmark) {
        // Add new bookmark to local DB
        // For created_by: use the actual creator if we can determine ownership, otherwise use userEmail
        const createdBy = isOwner ? userEmail : (sigmaBm.ownerId || userEmail);
        
        await new Promise((resolve, reject) => {
          db.run(
            `INSERT INTO bookmarks (bookmark_id, name, workbook_id, workbook_name, explore_key, created_by, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
            [sigmaBm.bookmarkId, sigmaBm.name, workbookId, '', sigmaBm.exploreKey || '', createdBy],
            (err) => {
              if (err) reject(err);
              else resolve();
            }
          );
        });
        
        // Grant access to the user with correct access type
        await new Promise((resolve, reject) => {
          db.run(
            `INSERT OR IGNORE INTO bookmark_access (bookmark_id, user_email, access_type, custom_name, granted_by, granted_at)
             VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
            [sigmaBm.bookmarkId, userEmail, accessType, sigmaBm.name, 'system'],
            function(err) {
              if (err) reject(err);
              else {
                if (this.changes > 0) {
                  accessGranted++;
                }
                resolve();
              }
            }
          );
        });
        
        console.log(`✅ Added bookmark to local DB: ${sigmaBm.name} (${sigmaBm.bookmarkId}) as ${accessType}`);
        added++;
      } else {
        // Update existing bookmark if name or explore key changed
        if (localBookmark.name !== sigmaBm.name || localBookmark.explore_key !== (sigmaBm.exploreKey || '')) {
          await new Promise((resolve, reject) => {
            db.run(
              `UPDATE bookmarks SET name = ?, explore_key = ?, updated_at = CURRENT_TIMESTAMP WHERE bookmark_id = ?`,
              [sigmaBm.name, sigmaBm.exploreKey || '', sigmaBm.bookmarkId],
              (err) => {
                if (err) reject(err);
                else resolve();
              }
            );
          });
          console.log(`🔄 Updated bookmark in local DB: ${sigmaBm.name} (${sigmaBm.bookmarkId})`);
          updated++;
        }
        
        // If we determined user is owner but created_by doesn't match, fix it
        if (isOwner && localBookmark.created_by && localBookmark.created_by.toLowerCase() !== userEmail.toLowerCase()) {
          await new Promise((resolve, reject) => {
            db.run(
              `UPDATE bookmarks SET created_by = ?, updated_at = CURRENT_TIMESTAMP WHERE bookmark_id = ?`,
              [userEmail, sigmaBm.bookmarkId],
              (err) => {
                if (err) reject(err);
                else resolve();
              }
            );
          });
          console.log(`🔧 Fixed created_by for bookmark: ${sigmaBm.name} (was: ${localBookmark.created_by}, now: ${userEmail})`);
          updated++;
        }
        
        // Check if user already has access
        const existingAccess = await new Promise((resolve, reject) => {
          db.get(
            'SELECT * FROM bookmark_access WHERE bookmark_id = ? AND user_email = ?',
            [sigmaBm.bookmarkId, userEmail],
            (err, row) => {
              if (err) reject(err);
              else resolve(row);
            }
          );
        });
        
        if (!existingAccess) {
          // Grant access with correct type
          await new Promise((resolve, reject) => {
            db.run(
              `INSERT INTO bookmark_access (bookmark_id, user_email, access_type, custom_name, granted_by, granted_at)
               VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
              [sigmaBm.bookmarkId, userEmail, accessType, sigmaBm.name, 'system'],
              function(err) {
                if (err) reject(err);
                else {
                  if (this.changes > 0) {
                    accessGranted++;
                    console.log(`🔓 Granted ${accessType} access to ${userEmail} for bookmark: ${sigmaBm.name}`);
                  }
                  resolve();
                }
              }
            );
          });
        } else if (existingAccess.access_type !== accessType) {
          // Update access type if it changed (e.g., user became owner)
          await new Promise((resolve, reject) => {
            db.run(
              `UPDATE bookmark_access SET access_type = ? WHERE bookmark_id = ? AND user_email = ?`,
              [accessType, sigmaBm.bookmarkId, userEmail],
              (err) => {
                if (err) reject(err);
                else {
                  console.log(`🔄 Updated access type to ${accessType} for ${userEmail} on bookmark: ${sigmaBm.name}`);
                  resolve();
                }
              }
            );
          });
        }
      }
    }
    
    console.log(`\n✅ Sync complete:`);
    console.log(`   - Total bookmarks in Sigma: ${sigmaBookmarks.length}`);
    console.log(`   - Added to local DB: ${added}`);
    console.log(`   - Updated in local DB: ${updated}`);
    console.log(`   - Access granted: ${accessGranted}`);
    console.log(`===========================================\n`);
    
    return { synced: sigmaBookmarks.length, added, updated, accessGranted };
  } catch (error) {
    console.error(`❌ Error syncing bookmarks from Sigma:`, error);
    return { synced: 0, added: 0, updated: 0, error: error.message };
  }
}

// Helper function to grant access to team-shared bookmarks
async function syncTeamSharedBookmarksAccess(workbookId, userEmail, userTeams) {
  try {
    if (!userTeams || userTeams.length === 0) {
      console.log(`ℹ️ User not in any teams, skipping team bookmark sync`);
      return { accessGranted: 0 };
    }
    
    console.log(`\n👥 === SYNCING TEAM-SHARED BOOKMARKS ACCESS ===`);
    console.log(`📁 Workbook: ${workbookId}`);
    console.log(`👤 User: ${userEmail}`);
    console.log(`🏢 Teams: ${userTeams.join(', ')}`);
    
    let accessGranted = 0;
    
    // Find all bookmarks in this workbook that are shared with user's teams
    const teamPlaceholders = userTeams.map(() => '?').join(',');
    const teamSharedBookmarks = await new Promise((resolve, reject) => {
      db.all(
        `SELECT DISTINCT b.bookmark_id, b.name, bs.team_name
         FROM bookmarks b
         INNER JOIN bookmark_shares bs ON b.bookmark_id = bs.bookmark_id
         WHERE b.workbook_id = ? AND bs.team_name IN (${teamPlaceholders})`,
        [workbookId, ...userTeams],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });
    
    console.log(`📚 Found ${teamSharedBookmarks.length} bookmarks shared with user's teams`);
    
    // Grant access to each team-shared bookmark
    for (const bookmark of teamSharedBookmarks) {
      // Check if user already has access
      const hasAccess = await new Promise((resolve, reject) => {
        db.get(
          `SELECT 1 FROM bookmark_access WHERE bookmark_id = ? AND user_email = ?`,
          [bookmark.bookmark_id, userEmail],
          (err, row) => {
            if (err) reject(err);
            else resolve(!!row);
          }
        );
      });
      
      if (!hasAccess) {
        // Grant access
        await new Promise((resolve, reject) => {
          db.run(
            `INSERT INTO bookmark_access (bookmark_id, user_email, access_type, custom_name, granted_by, granted_at)
             VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
            [bookmark.bookmark_id, userEmail, 'viewer', bookmark.name, 'team:' + bookmark.team_name],
            (err) => {
              if (err) reject(err);
              else resolve();
            }
          );
        });
        
        console.log(`🔓 Granted access to ${userEmail} for team bookmark: ${bookmark.name} (via team: ${bookmark.team_name})`);
        accessGranted++;
      }
    }
    
    console.log(`\n✅ Team sync complete:`);
    console.log(`   - Team-shared bookmarks: ${teamSharedBookmarks.length}`);
    console.log(`   - Access granted: ${accessGranted}`);
    console.log(`===========================================\n`);
    
    return { accessGranted };
  } catch (error) {
    console.error(`❌ Error syncing team-shared bookmarks:`, error);
    return { accessGranted: 0, error: error.message };
  }
}

// Helper function to list all bookmarks in a workbook
async function listAllWorkbookBookmarks(workbookId, userEmail) {
  try {
    const bearerToken = await getBearerToken();
    
    // Check if user is an admin (admins can't be impersonated)
    const isAdmin = await isAdminUser(userEmail, bearerToken);
    
    let token;
    let usedImpersonation = false;
    
    if (isAdmin) {
      console.log(`👑 User ${userEmail} is an Admin - using admin bearer token (no impersonation)`);
      token = bearerToken;
      usedImpersonation = false;
    } else {
      console.log(`👤 User ${userEmail} - getting impersonated token`);
      token = await getImpersonatedBearerToken(userEmail);
      usedImpersonation = true;
    }
    
    console.log(`📚 Listing ALL bookmarks in workbook ${workbookId} as user ${userEmail}...`);
    
    const response = await axios.get(
      `${SIGMA_WORKBOOKS_URL}/${workbookId}/bookmarks`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    const bookmarks = response.data.entries || [];
    console.log(`📋 === ALL WORKBOOK BOOKMARKS ===`);
    console.log(`📊 Total bookmarks found: ${bookmarks.length}`);
    console.log(`🎭 Used impersonation: ${usedImpersonation}`);
    
    // Debug: Log all available fields from the first bookmark
    if (bookmarks.length > 0) {
      console.log(`\n🔍 DEBUG - Available fields in bookmark object:`);
      console.log(JSON.stringify(bookmarks[0], null, 2));
    }
    
    bookmarks.forEach((bm, idx) => {
      console.log(`         ${idx + 1}. ${bm.name}`);
      console.log(`     ID: ${bm.bookmarkId}`);
      console.log(`     Owner: ${bm.ownerId || bm.owner || bm.createdBy || 'N/A'}`);
      console.log(`     Shared: ${bm.isShared}`);
      console.log(`     Created: ${bm.createdAt || 'N/A'}`);
    });
    console.log(`===========================================\n`);
    
    // Return bookmarks with metadata about whether impersonation was used
    return bookmarks.map(bm => ({
      ...bm,
      _usedImpersonation: usedImpersonation
    }));
  } catch (error) {
    console.error(`❌ Failed to list bookmarks for workbook ${workbookId}:`, error.response?.data || error.message);
    return [];
  }
}

// ADMIN API ENDPOINTS

// Get all Sigma teams
app.get('/api/sigma/teams', async (req, res) => {
  try {
    const bearerToken = await getBearerToken();
    const response = await axios.get(SIGMA_TEAMS_URL, {
      headers: {
        Authorization: `Bearer ${bearerToken}`,
        'Content-Type': 'application/json'
      }
    });
    
    const teams = response.data.entries || [];
    console.log(`ðŸ“‹ Fetched ${teams.length} teams from Sigma`);
    
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
app.get('/api/sigma/account-types', async (req, res) => {
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
app.get('/api/sigma/user-attributes', async (req, res) => {
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
        console.log('âš ï¸ User attributes endpoint not available, using defaults');
        
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
app.get('/api/admin/users', async (req, res) => {
  try {
    db.all('SELECT * FROM user_configs ORDER BY email ASC', [], (err, rows) => {
      if (err) {
        console.error('Error fetching users:', err);
        return res.status(500).json({ error: 'Failed to fetch users' });
      }
      
      const users = rows.map(row => ({
        email: row.email,
        isInternal: row.is_internal === 1,
        teams: row.teams ? JSON.parse(row.teams) : [],
        accountType: row.account_type,
        userAttributes: row.user_attributes ? JSON.parse(row.user_attributes) : {},
        createdAt: row.created_at,
        updatedAt: row.updated_at
      }));
      
      res.json({ users });
    });
  } catch (error) {
    console.error('Error in get users endpoint:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Create a new user configuration
app.post('/api/admin/users', async (req, res) => {
  const { email, isInternal, teams, accountType, userAttributes } = req.body;
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }
  
  try {
    db.run(
      `INSERT INTO user_configs (email, is_internal, teams, account_type, user_attributes, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
      [
        email,
        isInternal ? 1 : 0,
        teams ? JSON.stringify(teams) : null,
        accountType || null,
        userAttributes ? JSON.stringify(userAttributes) : null
      ],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE')) {
            return res.status(400).json({ error: 'User configuration already exists' });
          }
          console.error('Error creating user config:', err);
          return res.status(500).json({ error: 'Failed to create user configuration' });
        }
        
        console.log(`✅ Created configuration for user: ${email}`);
        res.json({ 
          success: true, 
          message: 'User configuration created successfully',
          userId: this.lastID
        });
      }
    );
  } catch (error) {
    console.error('Error creating user config:', error);
    res.status(500).json({ error: 'Failed to create user configuration' });
  }
});

// Update user configuration
app.put('/api/admin/users/:email', async (req, res) => {
  const userEmail = decodeURIComponent(req.params.email);
  const { isInternal, teams, accountType, userAttributes } = req.body;
  
  try {
    db.run(
      `UPDATE user_configs 
       SET is_internal = ?, teams = ?, account_type = ?, user_attributes = ?, updated_at = CURRENT_TIMESTAMP
       WHERE email = ?`,
      [
        isInternal ? 1 : 0,
        teams ? JSON.stringify(teams) : null,
        accountType || null,
        userAttributes ? JSON.stringify(userAttributes) : null,
        userEmail
      ],
      function(err) {
        if (err) {
          console.error('Error updating user config:', err);
          return res.status(500).json({ error: 'Failed to update user configuration' });
        }
        
        if (this.changes === 0) {
          return res.status(404).json({ error: 'User configuration not found' });
        }
        
        console.log(`✅ Updated configuration for user: ${userEmail}`);
        res.json({ 
          success: true, 
          message: 'User configuration updated successfully'
        });
      }
    );
  } catch (error) {
    console.error('Error updating user config:', error);
    res.status(500).json({ error: 'Failed to update user configuration' });
  }
});

// Delete user configuration
app.delete('/api/admin/users/:email', async (req, res) => {
  const userEmail = decodeURIComponent(req.params.email);
  
  try {
    db.run(
      'DELETE FROM user_configs WHERE email = ?',
      [userEmail],
      function(err) {
        if (err) {
          console.error('Error deleting user config:', err);
          return res.status(500).json({ error: 'Failed to delete user configuration' });
        }
        
        if (this.changes === 0) {
          return res.status(404).json({ error: 'User configuration not found' });
        }
        
        console.log(`✅ Deleted configuration for user: ${userEmail}`);
        res.json({ 
          success: true, 
          message: 'User configuration deleted successfully'
        });
      }
    );
  } catch (error) {
    console.error('Error deleting user config:', error);
    res.status(500).json({ error: 'Failed to delete user configuration' });
  }
});

// EXISTING API ENDPOINTS

app.get('/api/workbooks', async (req, res) => {
  const email = req.query.email;
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

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
app.get('/api/items', async (req, res) => {
  const email = req.query.email;
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

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

// NEW ENDPOINT: Get only data models
app.get('/api/data-models', async (req, res) => {
  const email = req.query.email;
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    const bearerToken = await getBearerToken();
    const dataModels = await getDataModelsForUser(email, bearerToken);
    
    res.json({ 
      dataModels,
      total: dataModels.length
    });
  } catch (error) {
    console.error('Error fetching data models:', error);
    res.status(500).json({ error: 'Failed to fetch data models' });
  }
});

app.get('/api/user/teams', async (req, res) => {
  const email = req.query.email;
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    console.log(`Fetching teams for user: ${email}`);
    const bearerToken = await getBearerToken();
    const teams = await getUserTeams(email, bearerToken);
    
    res.json({ teams });
  } catch (error) {
    console.error('Error fetching user teams:', error);
    res.status(500).json({ error: 'Failed to fetch user teams' });
  }
});

// Manual sync endpoint to force sync bookmarks from Sigma
app.post('/api/bookmarks/sync', async (req, res) => {
  const { email, workbookId } = req.body;
  
  if (!email || !workbookId) {
    return res.status(400).json({ error: 'Email and workbookId are required' });
  }
  
  try {
    console.log(`🔄 Manual sync requested for workbook ${workbookId} by ${email}`);
    
    // Sync bookmarks from Sigma
    const sigmaResult = await syncBookmarksFromSigma(workbookId, email);
    
    if (sigmaResult.error) {
      return res.status(500).json({ 
        success: false, 
        error: sigmaResult.error 
      });
    }
    
    // Get user's teams and sync team-shared bookmarks
    const bearerToken = await getBearerToken();
    const userTeams = await getUserTeams(email, bearerToken);
    const teamResult = await syncTeamSharedBookmarksAccess(workbookId, email, userTeams);
    
    // Combine results
    const totalAccessGranted = sigmaResult.accessGranted + teamResult.accessGranted;
    
    res.json({ 
      success: true,
      message: 'Bookmarks synced successfully',
      synced: sigmaResult.synced,
      added: sigmaResult.added,
      updated: sigmaResult.updated,
      accessGranted: totalAccessGranted,
      teamAccessGranted: teamResult.accessGranted
    });
  } catch (error) {
    console.error('Error in manual sync:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to sync bookmarks',
      details: error.message 
    });
  }
});

// Get all bookmarks accessible to a user
app.get('/api/bookmarks', async (req, res) => {
  const email = req.query.email;
  const workbookId = req.query.workbookId;
  const sync = req.query.sync !== 'false'; // Default to true, set to false to skip sync
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    console.log(`📚 Fetching bookmarks for user: ${email}`);
    
    const bearerToken = await getBearerToken();
    const userTeams = await getUserTeams(email, bearerToken);
    console.log(`👥 User is in teams:`, userTeams);
    
    if (workbookId) {
      console.log(`Filtered to workbook: ${workbookId}`);
      
      // Sync bookmarks from Sigma if workbookId is provided and sync is enabled
      if (sync) {
        console.log(`🔄 Syncing bookmarks from Sigma first...`);
        await syncBookmarksFromSigma(workbookId, email);
        
        // Also sync team-shared bookmarks
        await syncTeamSharedBookmarksAccess(workbookId, email, userTeams);
      }
    }
    
    // Build query to get all accessible bookmarks
    let query = `
      SELECT DISTINCT 
        b.*,
        ba.access_type,
        ba.custom_name,
        ba.granted_by,
        CASE 
          WHEN ba.access_type = 'owner' THEN 1
          ELSE 0
        END as is_owner
      FROM bookmarks b
      LEFT JOIN bookmark_access ba ON b.bookmark_id = ba.bookmark_id
      LEFT JOIN bookmark_shares bs ON b.bookmark_id = bs.bookmark_id
      WHERE 
        ba.user_email = ?
    `;
    
    let params = [email];
    
    // Add team access
    if (userTeams.length > 0) {
      const teamPlaceholders = userTeams.map(() => '?').join(',');
      query += ` OR bs.team_name IN (${teamPlaceholders})`;
      params.push(...userTeams);
    }
    
    // Filter by workbook if specified
    if (workbookId) {
      query = `
        SELECT * FROM (${query}) AS accessible_bookmarks
        WHERE workbook_id = ?
      `;
      params.push(workbookId);
    }
    
    query += ` ORDER BY created_at DESC`;
    
    db.all(query, params, (err, rows) => {
      if (err) {
        console.error('Error fetching bookmarks:', err);
        return res.status(500).json({ error: 'Failed to fetch bookmarks' });
      }
      
      console.log(`✅ Found ${rows.length} accessible bookmarks in local DB (before deduplication)`);
      
      // Deduplicate by bookmark_id, preferring owner entries
      const bookmarkMap = new Map();
      rows.forEach(bookmark => {
        const existing = bookmarkMap.get(bookmark.bookmark_id);
        // Keep owner version if it exists, otherwise take team version
        if (!existing || (bookmark.access_type === 'owner' && existing.access_type !== 'owner')) {
          bookmarkMap.set(bookmark.bookmark_id, bookmark);
        }
      });
      
      const uniqueRows = Array.from(bookmarkMap.values());
      console.log(`✅ After deduplication: ${uniqueRows.length} unique bookmarks`);
      
      // Get team share info for each bookmark
      const bookmarkIds = [...new Set(uniqueRows.map(r => r.bookmark_id))];
      const placeholders = bookmarkIds.map(() => '?').join(',');
      
      if (bookmarkIds.length === 0) {
        return res.json({ bookmarks: [] });
      }
      
      db.all(
        `SELECT * FROM bookmark_shares WHERE bookmark_id IN (${placeholders})`,
        bookmarkIds,
        (err, shares) => {
          if (err) {
            console.error('Error fetching shares:', err);
            return res.json({ bookmarks: uniqueRows });
          }
          
          // Merge share info
          const shareMap = {};
          shares.forEach(share => {
            if (!shareMap[share.bookmark_id]) {
              shareMap[share.bookmark_id] = [];
            }
            shareMap[share.bookmark_id].push(share);
          });
          
          const bookmarksWithShares = uniqueRows.map(bookmark => ({
            ...bookmark,
            shared_teams: shareMap[bookmark.bookmark_id] || []
          }));
          
          res.json({ bookmarks: bookmarksWithShares });
        }
      );
    });
  } catch (error) {
    console.error('Error in bookmarks endpoint:', error);
    res.status(500).json({ error: 'Failed to fetch bookmarks' });
  }
});

// Create a new bookmark or grant access to existing one
app.post('/api/bookmarks', async (req, res) => {
  const { name, userEmail, team, shareType = 'private', workbookId, workbookName, exploreKey = '' } = req.body;
  
  if (!name || !userEmail || !workbookId) {
    return res.status(400).json({ error: 'Name, userEmail, and workbookId are required' });
  }

  // Check if exploreKey is empty and return helpful error
  if (!exploreKey || exploreKey === '') {
    return res.status(400).json({ 
      error: 'Please navigate to a specific view in the workbook before creating a bookmark. Bookmarks save the current view state.',
      details: 'Click on a chart, apply filters, or navigate to a specific dashboard page first.'
    });
  }

  try {
    console.log(`Creating/sharing bookmark: ${name} for user: ${userEmail}`);
    console.log(`Workbook: ${workbookId} (${workbookName})`);
    console.log(`📊 Explore Key: "${exploreKey}"`);
    
    const bearerToken = await getBearerToken();
    
    // Check if a bookmark with same explore key already exists for this workbook
    const existingBookmark = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM bookmarks WHERE workbook_id = ? AND explore_key = ?',
        [workbookId, exploreKey || ''],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });
    
    let bookmarkId;
    let isNewBookmark = false;
    
    if (existingBookmark) {
      // Bookmark exists, just grant access
      bookmarkId = existingBookmark.bookmark_id;
      console.log(`Bookmark already exists in Sigma with ID: ${bookmarkId}`);
    } else {
      // Create new bookmark in Sigma
      const sigmaBookmark = await createSigmaBookmark(
        workbookId,
        {
          name: name,
          exploreKey: exploreKey || ''
        },
        userEmail
      );
      
      bookmarkId = sigmaBookmark.bookmarkId;
      isNewBookmark = true;
      console.log(`✅ New bookmark created in Sigma with ID: ${bookmarkId}`);
      
      // Verify the bookmark was actually created and is visible
      console.log(`\n🔍 === VERIFYING BOOKMARK CREATION ===`);
      const verifiedBookmark = await verifyBookmarkInSigma(workbookId, bookmarkId, userEmail);
      if (!verifiedBookmark) {
        console.error(`⚠️ WARNING: Bookmark ${bookmarkId} was reportedly created but cannot be found in Sigma!`);
        console.error(`⚠️ This may indicate a permissions issue or the bookmark may not be visible to user ${userEmail}`);
      } else {
        console.log(`✅ Bookmark ${bookmarkId} successfully verified in Sigma and is visible to user ${userEmail}`);
      }
      
      // List all bookmarks to see ownership information
      await listAllWorkbookBookmarks(workbookId, userEmail);
      
      console.log(`===========================================\n`);
      
      // Store in bookmarks table
      await new Promise((resolve, reject) => {
        db.run(
          `INSERT INTO bookmarks (bookmark_id, name, workbook_id, workbook_name, explore_key, created_by, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
          [bookmarkId, name, workbookId, workbookName, exploreKey, userEmail],
          (err) => {
            if (err) reject(err);
            else resolve();
          }
        );
      });
    }
    
    // Grant access to the user
    await new Promise((resolve, reject) => {
      db.run(
        `INSERT OR REPLACE INTO bookmark_access (bookmark_id, user_email, access_type, custom_name, granted_by, granted_at)
         VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
        [bookmarkId, userEmail, isNewBookmark ? 'owner' : 'viewer', name, userEmail],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
    
    // If sharing with team, add to bookmark_shares
    if (shareType === 'team' && team) {
      await new Promise((resolve, reject) => {
        db.run(
          `INSERT OR REPLACE INTO bookmark_shares (bookmark_id, team_name, shared_by, shared_at)
           VALUES (?, ?, ?, CURRENT_TIMESTAMP)`,
          [bookmarkId, team, userEmail],
          (err) => {
            if (err) reject(err);
            else resolve();
          }
        );
      });
      console.log(`👥 Bookmark shared with team: ${team}`);
    }
    
    res.json({
      success: true,
      bookmark: {
        bookmarkId,
        name,
        workbookId,
        workbookName,
        userEmail,
        team,
        shareType,
        exploreKey,
        isNew: isNewBookmark,
        createdAt: new Date().toISOString()
      }
    });
    
  } catch (error) {
    console.error('❌ Error creating bookmark:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Failed to create bookmark',
      details: error.response?.data?.message || error.message
    });
  }
});

// Load a bookmark (no cloning needed)
app.post('/api/bookmarks/load/:bookmarkId', async (req, res) => {
  const { bookmarkId } = req.params;
  const { userEmail, workbookId } = req.body;
  
  if (!userEmail || !workbookId) {
    return res.status(400).json({ error: 'userEmail and workbookId are required' });
  }
  
  try {
    console.log(`Loading bookmark ${bookmarkId} for user: ${userEmail}`);
    
    // Check if user has access
    const hasAccess = await new Promise((resolve, reject) => {
      db.get(
        `SELECT 1 FROM (
          SELECT bookmark_id FROM bookmark_access WHERE bookmark_id = ? AND user_email = ?
          UNION
          SELECT bs.bookmark_id FROM bookmark_shares bs
          JOIN bookmark_access ba ON ba.user_email = ?
          WHERE bs.bookmark_id = ? AND bs.team_name IN (
            SELECT team_name FROM bookmark_shares WHERE bookmark_id IN (
              SELECT bookmark_id FROM bookmark_access WHERE user_email = ?
            )
          )
        ) LIMIT 1`,
        [bookmarkId, userEmail, userEmail, bookmarkId, userEmail],
        (err, row) => {
          if (err) reject(err);
          else resolve(!!row);
        }
      );
    });
    
    if (!hasAccess) {
      // Check if user is in a team that has access
      const bearerToken = await getBearerToken();
      const userTeams = await getUserTeams(userEmail, bearerToken);
      
      const teamAccess = await new Promise((resolve, reject) => {
        if (userTeams.length === 0) {
          resolve(false);
          return;
        }
        
        const placeholders = userTeams.map(() => '?').join(',');
        db.get(
          `SELECT 1 FROM bookmark_shares 
           WHERE bookmark_id = ? AND team_name IN (${placeholders})
           LIMIT 1`,
          [bookmarkId, ...userTeams],
          (err, row) => {
            if (err) reject(err);
            else resolve(!!row);
          }
        );
      });
      
      if (!teamAccess) {
        return res.status(403).json({ error: 'Access denied to this bookmark' });
      }
    }
    
    // Log access for analytics/scheduler
    console.log(`✅ User has access to bookmark ${bookmarkId}`);
    
    res.json({
      success: true,
      bookmarkId: bookmarkId,
      message: 'Bookmark ready to load'
    });
    
  } catch (error) {
    console.error('Error loading bookmark:', error);
    res.status(500).json({ error: 'Failed to load bookmark' });
  }
});

// Update an existing bookmark
app.put('/api/bookmarks/:bookmarkId', async (req, res) => {
  const { bookmarkId } = req.params;
  const { name, userEmail, workbookId, exploreKey } = req.body;
  
  if (!bookmarkId || !userEmail || !workbookId) {
    return res.status(400).json({ error: 'bookmarkId, userEmail, and workbookId are required' });
  }

  try {
    console.log(`📝 Updating bookmark ${bookmarkId} for user: ${userEmail}`);
    
    // Check if user is the owner
    const bookmarkData = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM bookmarks WHERE bookmark_id = ?',
        [bookmarkId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });
    
    if (!bookmarkData) {
      return res.status(404).json({ error: 'Bookmark not found' });
    }
    
    // Check if user has owner access
    const hasOwnerAccess = await new Promise((resolve, reject) => {
      db.get(
        'SELECT 1 FROM bookmark_access WHERE bookmark_id = ? AND user_email = ? AND access_type = \'owner\'',
        [bookmarkId, userEmail],
        (err, row) => {
          if (err) reject(err);
          else resolve(!!row);
        }
      );
    });
    
    if (!hasOwnerAccess) {
      return res.status(403).json({ error: 'Only the bookmark owner can update it' });
    }
    
    // Update bookmark in Sigma using impersonation
    const sigmaBookmark = await updateSigmaBookmark(
      workbookId,
      bookmarkId,
      {
        name: name || bookmarkData.name,
        exploreKey: exploreKey || bookmarkData.explore_key
      },
      userEmail
    );
    
    // Update in local database
    await new Promise((resolve, reject) => {
      db.run(
        `UPDATE bookmarks 
         SET name = ?, explore_key = ?, updated_at = CURRENT_TIMESTAMP
         WHERE bookmark_id = ?`,
        [name || bookmarkData.name, exploreKey || bookmarkData.explore_key, bookmarkId],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
    
    // Update custom name for the user if name changed
    if (name) {
      await new Promise((resolve, reject) => {
        db.run(
          `UPDATE bookmark_access 
           SET custom_name = ?
           WHERE bookmark_id = ? AND user_email = ?`,
          [name, bookmarkId, userEmail],
          (err) => {
            if (err) reject(err);
            else resolve();
          }
        );
      });
    }
    
    console.log(`✅ Bookmark ${bookmarkId} updated successfully`);
    
    res.json({
      success: true,
      message: 'Bookmark updated successfully',
      bookmark: {
        bookmarkId,
        name: name || bookmarkData.name,
        workbookId,
        exploreKey: exploreKey || bookmarkData.explore_key,
        updatedAt: new Date().toISOString()
      }
    });
    
  } catch (error) {
    console.error('❌ Error updating bookmark:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Failed to update bookmark',
      details: error.response?.data?.message || error.message
    });
  }
});

// Delete bookmark or remove access
app.delete('/api/bookmarks/:bookmarkId', async (req, res) => {
  const { bookmarkId } = req.params;
  const { userEmail, workbookId } = req.query;
  
  if (!userEmail || !workbookId) {
    return res.status(400).json({ error: 'userEmail and workbookId are required' });
  }

  try {
    console.log(`Delete request for bookmark ${bookmarkId} by user: ${userEmail}`);
    
    // Check if user is owner
    const ownership = await new Promise((resolve, reject) => {
      db.get(
        'SELECT access_type FROM bookmark_access WHERE bookmark_id = ? AND user_email = ?',
        [bookmarkId, userEmail],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });
    
    if (!ownership) {
      return res.status(404).json({ error: 'Bookmark not found or no access' });
    }
    
    if (ownership.access_type === 'owner') {
      // Owner is deleting - remove from Sigma and database
      console.log(`👤 Owner deleting bookmark - removing from Sigma`);
      
      const bearerToken = await getBearerToken();
      await deleteSigmaBookmark(workbookId, bookmarkId, bearerToken);
      
      // Delete from all tables (cascade will handle related tables if foreign keys are set up)
      await new Promise((resolve, reject) => {
        db.run('DELETE FROM bookmarks WHERE bookmark_id = ?', [bookmarkId], (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
      
      // Clean up access and shares
      await new Promise((resolve, reject) => {
        db.run('DELETE FROM bookmark_access WHERE bookmark_id = ?', [bookmarkId], (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
      
      await new Promise((resolve, reject) => {
        db.run('DELETE FROM bookmark_shares WHERE bookmark_id = ?', [bookmarkId], (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
      
      console.log(`✅ Bookmark completely deleted from Sigma and database`);
      res.json({ 
        success: true, 
        message: 'Bookmark deleted from Sigma and all access removed',
        action: 'deleted'
      });
      
    } else {
      // Viewer is removing access - just remove their access
      console.log(`👤 Viewer removing their access to bookmark`);
      
      await new Promise((resolve, reject) => {
        db.run(
          'DELETE FROM bookmark_access WHERE bookmark_id = ? AND user_email = ?',
          [bookmarkId, userEmail],
          (err) => {
            if (err) reject(err);
            else resolve();
          }
        );
      });
      
      console.log(`✅ Access removed for user ${userEmail}`);
      res.json({ 
        success: true, 
        message: 'Your access to this bookmark has been removed',
        action: 'access_removed'
      });
    }
    
  } catch (error) {
    console.error('❌ Error deleting bookmark:', error);
    res.status(500).json({ 
      error: 'Failed to delete bookmark',
      details: error.message
    });
  }
});

// Schedule a bookmark for automated execution via Sigma REST API
app.post('/api/bookmarks/:bookmarkId/schedule', async (req, res) => {
  const { bookmarkId } = req.params;
  const { 
    scheduleName, 
    cronExpression,
    destinationType = 'email',
    destinationConfig,
    format = 'pdf',
    createdBy 
  } = req.body;
  
  if (!scheduleName || !cronExpression || !createdBy || !destinationConfig) {
    return res.status(400).json({ 
      error: 'scheduleName, cronExpression, destinationConfig, and createdBy are required' 
    });
  }
  
  // Validate destination config based on type
  if (destinationType === 'email') {
    if (!destinationConfig.recipients || destinationConfig.recipients.length === 0) {
      return res.status(400).json({ error: 'Email destination requires at least one recipient' });
    }
  } else if (destinationType === 'googleDrive') {
    if (!destinationConfig.googleDriveFolderUrl) {
      return res.status(400).json({ error: 'Google Drive destination requires a folder URL' });
    }
  } else {
    return res.status(400).json({ error: 'Invalid destination type. Must be "email" or "googleDrive"' });
  }
  
  try {
    // Get bookmark and workbook details
    const bookmark = await new Promise((resolve, reject) => {
      db.get(
        `SELECT b.*, ba.access_type 
         FROM bookmarks b
         JOIN bookmark_access ba ON b.bookmark_id = ba.bookmark_id
         WHERE b.bookmark_id = ? AND ba.user_email = ?`,
        [bookmarkId, createdBy],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });
    
    if (!bookmark) {
      return res.status(404).json({ error: 'Bookmark not found or no access' });
    }
    
    const bearerToken = await getBearerToken();
    
    // Get member ID for the user
    const memberId = await getMemberId(createdBy, bearerToken);
    
    // Create schedule in Sigma via REST API
    const schedulePayload = {
      name: scheduleName,
      type: 'export',
      schedule: {
        cronSpec: cronExpression,
        timezone: 'America/New_York'
      },
      target: [],
      configV2: {
        includeLink: false,
        runAsRecipient: false,
        exportAttachments: [{
          formatOptions: {
            type: format.toUpperCase(),
            ...(format.toLowerCase() === 'pdf' ? { layout: 'portrait' } : {}),
            ...(format.toLowerCase() !== 'pdf' ? { rowLimit: 10000 } : {})
          },
          workbookExportSource: {
            type: 'all'
          }
        }],
        conditionOptions: {
          type: 'always'
        },
        workbookVariant: {
          bookmarkId: bookmarkId
        },
        title: `Scheduled Report: ${scheduleName}`,
        messageBody: `Your scheduled report "${scheduleName}" is attached.`,
        workbookId: bookmark.workbook_id
      }
    };
    
    // Add targets based on destination type
    if (destinationType === 'email') {
      schedulePayload.target = destinationConfig.recipients.map(email => ({ 
        email: email
      }));
    } else if (destinationType === 'googleDrive') {
      schedulePayload.target = [{ 
        googleDriveFolderUrl: destinationConfig.googleDriveFolderUrl 
      }];
    }
    
    console.log('Creating schedule in Sigma:', JSON.stringify(schedulePayload, null, 2));
    
    const scheduleResponse = await axios.post(
      `${SIGMA_BASE_URL}/workbooks/${bookmark.workbook_id}/schedules`,
      schedulePayload,
      {
        headers: {
          Authorization: `Bearer ${bearerToken}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    const sigmaScheduleId = scheduleResponse.data.scheduledNotificationId || scheduleResponse.data.scheduleId || scheduleResponse.data.id;
    
    if (!sigmaScheduleId) {
      console.error('No schedule ID found in response:', scheduleResponse.data);
      throw new Error('Schedule created but no ID returned from Sigma');
    }
    
    // Store schedule mapping in local database
    await new Promise((resolve, reject) => {
      db.run(
        `INSERT INTO scheduled_reports 
         (schedule_id, bookmark_id, workbook_id, schedule_name, created_by, member_id, 
          cron_expression, destination_type, destination_config, format, sigma_schedule_data, 
          created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
        [
          sigmaScheduleId,
          bookmarkId,
          bookmark.workbook_id,
          scheduleName,
          createdBy,
          memberId,
          cronExpression,
          destinationType,
          JSON.stringify(destinationConfig),
          format,
          JSON.stringify(scheduleResponse.data)
        ],
        function(err) {
          if (err) {
            console.error('Database error when inserting schedule:', err);
            reject(err);
          } else {
            resolve(this.lastID);
          }
        }
      );
    });
    
    console.log(`✅ Schedule created with ID: ${sigmaScheduleId} for user: ${createdBy}`);
    res.json({
      success: true,
      scheduleId: sigmaScheduleId,
      message: 'Schedule created successfully'
    });
    
  } catch (error) {
    console.error('Error creating schedule:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Failed to create schedule',
      details: error.response?.data?.message || error.message
    });
  }
});

// Get scheduled reports for a user
app.get('/api/scheduled-reports', async (req, res) => {
  const { email } = req.query;
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }
  
  try {
    const schedules = await new Promise((resolve, reject) => {
      db.all(
        `SELECT sr.*, b.name as bookmark_name, b.workbook_name
         FROM scheduled_reports sr
         JOIN bookmarks b ON sr.bookmark_id = b.bookmark_id
         WHERE sr.created_by = ?
         ORDER BY sr.created_at DESC`,
        [email],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows || []);
        }
      );
    });
    
    // Parse JSON fields
    const schedulesWithParsedData = schedules.map(schedule => ({
      ...schedule,
      destination_config: JSON.parse(schedule.destination_config || '{}'),
      sigma_schedule_data: JSON.parse(schedule.sigma_schedule_data || '{}')
    }));
    
    res.json({ schedules: schedulesWithParsedData });
    
  } catch (error) {
    console.error('Error fetching schedules:', error);
    res.status(500).json({ error: 'Failed to fetch scheduled reports' });
  }
});

// Update a schedule
app.patch('/api/scheduled-reports/:scheduleId', async (req, res) => {
  const { scheduleId } = req.params;
  const { userEmail, isActive, cronExpression, destinationConfig } = req.body;
  
  if (!userEmail) {
    return res.status(400).json({ error: 'userEmail is required' });
  }
  
  try {
    // Verify user owns this schedule
    const schedule = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM scheduled_reports WHERE schedule_id = ? AND created_by = ?',
        [scheduleId, userEmail],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });
    
    if (!schedule) {
      return res.status(404).json({ error: 'Schedule not found or no access' });
    }
    
    const bearerToken = await getBearerToken();
    
    // Update in Sigma if needed
    if (isActive !== undefined || cronExpression || destinationConfig) {
      const updatePayload = {};
      
      if (isActive !== undefined) {
        updatePayload.suspensionAction = isActive ? 'resume' : 'pause';
      }
      
      if (cronExpression) {
        updatePayload.schedule = {
          cronSpec: cronExpression,
          timezone: 'America/New_York'
        };
      }
      
      if (destinationConfig && destinationConfig.recipients) {
        updatePayload.target = destinationConfig.recipients.map(email => ({
          email: email
        }));
      }
      
      console.log(`Updating schedule ${scheduleId} in Sigma:`, updatePayload);
      
      await axios.patch(
        `${SIGMA_BASE_URL}/workbooks/${schedule.workbook_id}/schedules/${scheduleId}`,
        updatePayload,
        {
          headers: {
            Authorization: `Bearer ${bearerToken}`,
            'Content-Type': 'application/json'
          }
        }
      );
      
      console.log(`✅ Schedule ${scheduleId} updated in Sigma`);
    }
    
    // Update local database
    const updates = [];
    const values = [];
    
    if (isActive !== undefined) {
      updates.push('is_active = ?');
      values.push(isActive ? 1 : 0);
    }
    
    if (cronExpression) {
      updates.push('cron_expression = ?');
      values.push(cronExpression);
    }
    
    if (destinationConfig) {
      updates.push('destination_config = ?');
      values.push(JSON.stringify(destinationConfig));
    }
    
    updates.push('updated_at = CURRENT_TIMESTAMP');
    values.push(scheduleId);
    
    await new Promise((resolve, reject) => {
      db.run(
        `UPDATE scheduled_reports SET ${updates.join(', ')} WHERE schedule_id = ?`,
        values,
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
    
    res.json({ success: true, message: 'Schedule updated successfully' });
    
  } catch (error) {
    console.error('Error updating schedule:', error);
    res.status(500).json({ 
      error: 'Failed to update schedule',
      details: error.message 
    });
  }
});

// Delete a schedule
app.delete('/api/scheduled-reports/:scheduleId', async (req, res) => {
  const { scheduleId } = req.params;
  const { userEmail } = req.query;
  
  if (!userEmail) {
    return res.status(400).json({ error: 'userEmail is required' });
  }
  
  try {
    // Verify user owns this schedule
    const schedule = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM scheduled_reports WHERE schedule_id = ? AND created_by = ?',
        [scheduleId, userEmail],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });
    
    if (!schedule) {
      return res.status(404).json({ error: 'Schedule not found or no access' });
    }
    
    const bearerToken = await getBearerToken();
    
    // Delete from Sigma
    try {
      await axios.delete(
        `${SIGMA_BASE_URL}/workbooks/${schedule.workbook_id}/schedules/${scheduleId}`,
        {
          headers: {
            Authorization: `Bearer ${bearerToken}`,
            'Content-Type': 'application/json'
          }
        }
      );
    } catch (error) {
      if (error.response?.status !== 404) {
        throw error;
      }
    }
    
    // Delete from local database
    await new Promise((resolve, reject) => {
      db.run(
        'DELETE FROM scheduled_reports WHERE schedule_id = ?',
        [scheduleId],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
    
    console.log(`✅ Schedule ${scheduleId} deleted successfully`);
    res.json({ success: true, message: 'Schedule deleted successfully' });
    
  } catch (error) {
    console.error('Error deleting schedule:', error);
    res.status(500).json({ 
      error: 'Failed to delete schedule',
      details: error.message 
    });
  }
});

// Get signed URL with workbook and optional bookmark
app.get('/api/signed-url', async (req, res) => {
  try {
    const workbookId = req.query.workbookId;
    let workbookUrlId = req.query.workbookUrlId;
    const email = req.query.email || 'demo@plugselectronics.com';
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

// Enhanced signed URL endpoint that supports both workbooks and data models
app.get('/api/signed-url-v2', async (req, res) => {
  try {
    const itemId = req.query.workbookId || req.query.dataModelId;
    let itemUrlId = req.query.workbookUrlId || req.query.dataModelUrlId;
    const itemType = req.query.itemType || (req.query.dataModelId ? 'data-model' : 'workbook');
    const email = req.query.email || 'demo@plugselectronics.com';
    const bookmarkId = req.query.bookmarkId || null;
    
    console.log(`\n🔧 /api/signed-url-v2 called with:`);
    console.log(`  - itemType: ${itemType}`);
    console.log(`  - itemId: ${itemId}`);
    console.log(`  - itemUrlId: ${itemUrlId}`);
    console.log(`  - dataModelId from query: ${req.query.dataModelId}`);
    console.log(`  - dataModelUrlId from query: ${req.query.dataModelUrlId}`);
    console.log(`  - workbookId from query: ${req.query.workbookId}`);
    console.log(`  - workbookUrlId from query: ${req.query.workbookUrlId}`);
    
    const standardParams = ['workbookId', 'dataModelId', 'workbookUrlId', 'dataModelUrlId', 'email', 'bookmarkId', 'itemType'];
    const customParams = {};
    
    Object.keys(req.query).forEach(key => {
      if (!standardParams.includes(key)) {
        customParams[key] = req.query[key];
      }
    });
    
    // Extract URL ID from full URL if needed
    if (itemUrlId && itemUrlId.includes('/')) {
      const pattern = itemType === 'data-model' 
        ? /\/data-model\/([^/?#]+)/ 
        : /\/workbook\/([^/?#]+)/;
      const match = itemUrlId.match(pattern);
      if (match && match[1]) {
        console.log(`  📍 Extracted URL ID from full URL: ${match[1]}`);
        itemUrlId = match[1];
      }
    }
    
    // If we don't have URL ID but have item ID, fetch it (workbooks only for now)
    if (!itemUrlId && itemId && itemType === 'workbook') {
      const bearerToken = await getBearerToken();
      
      try {
        const workbookResponse = await axios.get(
          `${SIGMA_WORKBOOKS_URL}/${itemId}`,
          {
            headers: {
              Authorization: `Bearer ${bearerToken}`,
              'Content-Type': 'application/json'
            }
          }
        );
        
        itemUrlId = extractWorkbookUrlId(workbookResponse.data);
      } catch (err) {
        console.error(`Error fetching ${itemType}:`, err.response?.data || err.message);
        return res.status(500).json({ error: `Failed to fetch ${itemType} details` });
      }
    }
    
    // For data models, use ID directly if no URL ID is provided
    if (!itemUrlId && itemId && itemType === 'data-model') {
      console.log(`  ⚠️ No dataModelUrlId provided, falling back to dataModelId: ${itemId}`);
      itemUrlId = itemId;
    }
    
    if (!itemUrlId) {
      return res.status(400).json({ error: 'Item ID or URL ID is required' });
    }
    
    console.log(`  ✅ Final itemUrlId being used: ${itemUrlId}`);
    
    // Modify generateSignedUrl call to include itemType
    const signedUrl = await generateSignedUrlV2(itemUrlId, email, bookmarkId, customParams, itemType);
    
    res.json({ 
      url: signedUrl, 
      itemId,
      itemUrlId,
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

// Ask Sigma endpoint without Region/Environment
app.get('/api/ask-sigma-url', async (req, res) => {
  try {
    const email = req.query.email || 'demo@plugselectronics.com';
    const question = req.query.question || '';
    
    console.log(`Ask Sigma request from: ${email}`);
    console.log(`❔ Question: "${question}"`);
    
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
      isInternal = userConfig.isInternal;
      teams = userConfig.teams || [];
      accountType = userConfig.accountType || 'Pro';
      userAttributes = userConfig.userAttributes || {};
    } else {
      isInternal = await isInternalUser(email, bearerToken);
    }

    const tokenData = {
      sub: email,
      iss: embedClientId,
      jti: crypto.randomUUID(),
      iat: time,
      exp: time + sessionLength
    };

    if (!isInternal) {
      tokenData.first_name = givenName;
      tokenData.last_name = familyName;
      tokenData.account_type = accountType;
      
      if (teams.length > 0) {
        tokenData.teams = teams;
      }
      
      if (Object.keys(userAttributes).length > 0) {
        tokenData.user_attributes = userAttributes;
      }
    }

    const tokenHeader = {
      algorithm: 'HS256',
      keyid: embedClientId
    };

    const token = jwt.sign(tokenData, embedSecret, tokenHeader);

    let signedUrl = `https://app.sigmacomputing.com/${sigmaOrg}/ask/answer`;
    signedUrl += `?:jwt=${token}&:embed=true&:menu_position=bottom&:responsive_height=true`;
    signedUrl += `&:enable_inbound_events=true&:enable_outbound_events=true`;
    if (question) {
      signedUrl += `&search=${encodeURIComponent(question)}`;
    }

    res.json({ 
      url: signedUrl, 
      email,
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

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address' });
  }
  
  console.log(`\n📐 Authentication attempt for: ${email}`);
  console.log(`✅ Authentication successful (demo mode)`);
  
  res.json({ 
    success: true, 
    message: 'Authentication successful',
    email: email 
  });
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    server: 'Plugs Electronics Dashboard Server',
    features: ['workbooks', 'data-models', 'bookmarks', 'admin', 'user-configs', 'dashboard', 'scheduler', 'ask-sigma']
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
  console.log(`✨ New Features:`);
  console.log(`  - 🗃️ Support for Data Models in addition to Workbooks`);
  console.log(`  - Enhanced JWT generation for both workbooks and data models`);
  console.log(`  - New /api/items endpoint for fetching both types`);
  console.log(`  - User configuration management via Admin Panel`);
  console.log(`  - Custom teams, account types, and user attributes per user`);
  console.log(`  - Dynamic JWT generation based on user configuration`);
  console.log(`  - Workspace management and workbook organization (user-specific access via grants)`);
  console.log(`💡 Demo Mode: Any password will work for authentication`);
  console.log(`🔧 Configure users in the Admin Panel to customize their JWT tokens\n`);
});
