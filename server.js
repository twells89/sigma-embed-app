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
    console.log('ðŸ“š Bookmark database connected');
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
        console.log('âœ… User configs table ready');
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
        console.log('âœ… Bookmarks table ready');
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
        console.log('âœ… Bookmark access table ready');
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
        console.log('âœ… Bookmark shares table ready');
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
        console.log('âœ… Scheduled reports table ready');
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
const SIGMA_TEAMS_URL = `${SIGMA_BASE_URL}/teams`;
const SIGMA_ACCOUNT_TYPES_URL = `${SIGMA_BASE_URL}/account-types`;
const SIGMA_USER_ATTRIBUTES_URL = `${SIGMA_BASE_URL}/user-attributes`;

const embedClientId = '47e18ee2f96c25f397d9e133c099ace93a92caeaa43c75d477eeadda562987f1';
const embedSecret = 'ea7abbfe9300c2b1ae3cd1a3707dec406a21380e3a87e46bc2c1fd8b6a6c039a433e45a59ac385355396feede27fb2a93686c7ace00940133dd6dec656dba857';
const sigmaOrg = 'tj-wells-1989';

const clientId = '7db69272bcbaf88c2a9eaed83ff2f54c212b9acb391e0792eac2e4c676242781';
const clientSecret = '3bbdc1149cb4774ca8197a7cdcf0196ef4ecaa65b88b7a7f3946521af7e356c0f8bcf35eeb799fd564b475864dca4f966715215df99fa1943422a1251f74e20f';

// Utility functions
async function getBearerToken() {
  try {
    const params = new URLSearchParams();
    params.append('grant_type', 'client_credentials');
    params.append('client_id', clientId);
    params.append('client_secret', clientSecret);

    const response = await axios.post(`${SIGMA_BASE_URL}/auth/token`, params, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    return response.data.access_token;
  } catch (error) {
    console.error('Failed to get bearer token:', error.response?.data || error.message);
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
      console.log(`âš ï¸ User ${userEmail} not found in Sigma`);
      return [];
    }
    
    console.log(`ðŸ‘¤ Found member ID: ${memberId}`);
    
    const teamsUrl = `${SIGMA_MEMBERS_URL}/${memberId}/teams`;
    console.log(`ðŸ“‹ Fetching teams from: ${teamsUrl}`);
    
    const teamsResponse = await axios.get(teamsUrl, {
      headers: {
        Authorization: `Bearer ${bearerToken}`,
        'Content-Type': 'application/json'
      }
    });
    
    const teams = teamsResponse.data.entries || [];
    const teamNames = teams.map(team => team.name);
    
    console.log(`ðŸ“‹ User ${userEmail} is in teams:`, teamNames);
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
        console.log(`ðŸ” Extracted URL ID from latestVersion.path: ${urlId}`);
        return urlId;
      }
    }
    
    console.warn('âš ï¸ No URL field found, using workbookId:', workbook.workbookId);
    return workbook.workbookId;
  }
  
  if (typeof urlId === 'string' && urlId.includes('/')) {
    const match = urlId.match(/\/workbook\/([^/?#]+)/);
    if (match && match[1]) {
      urlId = match[1];
      console.log(`ðŸ” Extracted URL ID from full URL: ${urlId}`);
    }
  }
  
  return urlId;
}

async function getWorkbooksForUser(userEmail, bearerToken) {
  try {
    console.log(`\nðŸ“š Fetching workbooks for user: ${userEmail}`);
    
    const memberId = await getMemberId(userEmail, bearerToken);
    
    if (!memberId) {
      console.log(`âš ï¸ User ${userEmail} not found in Sigma`);
      return [];
    }
    
    console.log(`ðŸ‘¤ Member ID: ${memberId}`);
    
    const grantsUrl = `${SIGMA_BASE_URL}/grants?userId=${memberId}`;
    console.log(`ðŸ” Fetching grants from: ${grantsUrl}`);
    
    const grantsResponse = await axios.get(grantsUrl, {
      headers: {
        Authorization: `Bearer ${bearerToken}`,
        'Content-Type': 'application/json'
      }
    });
    
    const grants = grantsResponse.data.entries || [];
    console.log(`ðŸ“Š Found ${grants.length} total grants for user`);
    
    let workbookIds = [];
    
    const workbookGrants = grants.filter(grant => {
      const isWorkbook = 
        grant.resourceType === 'workbook' ||
        grant.resource?.type === 'workbook' ||
        grant.type === 'workbook' ||
        (grant.resource && grant.resource.includes && grant.resource.includes('workbook'));
      
      return isWorkbook;
    });
    
    console.log(`ðŸ“– Found ${workbookGrants.length} workbook grants`);
    
    workbookIds = workbookGrants.map(grant => {
      return grant.resourceId || 
             grant.resource?.workbookId || 
             grant.resource?.id ||
             grant.workbookId ||
             grant.id;
    }).filter(id => id);
    
    workbookIds = [...new Set(workbookIds)];
    
    console.log(`ðŸ“š Unique workbook IDs:`, workbookIds);
    
    if (workbookIds.length === 0) {
      console.log('âš ï¸ No workbooks found via grants, trying direct workbooks list...');
      
      try {
        const workbooksListUrl = `${SIGMA_WORKBOOKS_URL}`;
        console.log(`ðŸ” Fetching from: ${workbooksListUrl}`);
        
        const workbooksResponse = await axios.get(workbooksListUrl, {
          headers: {
            Authorization: `Bearer ${bearerToken}`,
            'Content-Type': 'application/json'
          }
        });
        
        const allWorkbooks = workbooksResponse.data.entries || [];
        console.log(`ðŸ“š Found ${allWorkbooks.length} total workbooks in organization`);
        
        const workbooks = allWorkbooks.map(wb => {
          const urlId = extractWorkbookUrlId(wb);
          return {
            workbookId: wb.workbookId,
            workbookUrlId: urlId,
            name: wb.name,
            path: wb.path,
            latestVersion: wb.latestVersion,
            createdBy: wb.createdBy,
            updatedAt: wb.updatedAt,
            badge: wb.badge
          };
        });
        
        workbooks.sort((a, b) => a.name.localeCompare(b.name));
        return workbooks;
        
      } catch (listErr) {
        console.error('Error listing workbooks:', listErr.response?.data || listErr.message);
        return [];
      }
    }
    
    const workbooks = [];
    for (const workbookId of workbookIds) {
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
        
        const workbook = workbookResponse.data;
        const urlId = extractWorkbookUrlId(workbook);
        
        workbooks.push({
          workbookId: workbook.workbookId,
          workbookUrlId: urlId,
          name: workbook.name,
          path: workbook.path,
          latestVersion: workbook.latestVersion,
          createdBy: workbook.createdBy,
          updatedAt: workbook.updatedAt,
          badge: workbook.badge
        });
        
      } catch (err) {
        console.error(`  âŒ Error fetching workbook ${workbookId}:`, err.response?.data?.message || err.message);
      }
    }
    
    workbooks.sort((a, b) => a.name.localeCompare(b.name));
    
    console.log(`âœ… Successfully fetched ${workbooks.length} workbook details`);
    return workbooks;
    
  } catch (err) {
    console.error('Error getting workbooks for user:', err.response?.data || err.message);
    return [];
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
    console.log(`\nðŸ” Generating signed URL for user: ${email}`);
    console.log(`ðŸ“– Workbook URL ID: ${workbookUrlId}`);
    
    if (Object.keys(customParams).length > 0) {
      console.log(`ðŸ”Ž Custom parameters:`, customParams);
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
      console.log(`ðŸ‘¤ Found user configuration for ${email}`);
      isInternal = userConfig.isInternal;
      teams = userConfig.teams || [];
      accountType = userConfig.accountType || 'Pro';
      userAttributes = userConfig.userAttributes || {};
    } else {
      // Check if they're internal in Sigma
      isInternal = await isInternalUser(email, bearerToken);
      console.log(`ðŸ‘¤ No configuration found, checking Sigma: internal = ${isInternal}`);
    }

    const tokenData = {
      sub: email,
      iss: embedClientId,
      jti: crypto.randomUUID(),
      iat: time,
      exp: time + sessionLength
    };

    if (!isInternal) {
      console.log(`ðŸ‘¤ External user - adding configured attributes`);
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
      console.log('ðŸ¢ Internal user detected â€“ omitting all optional claims.');
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

    console.log(`âœ… Signed URL generated successfully`);
    return signedUrl;
  } catch (error) {
    console.error("âŒ Failed to generate signed URL:", error);
    throw error;
  }
}

// Helper function to create bookmark in Sigma
async function createSigmaBookmark(workbookId, bookmarkData, bearerToken) {
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
    
    const latestVersion = workbookResponse.data.latestVersion;
    
    const payload = {
      name: bookmarkData.name,
      workbookVersion: latestVersion,
      isShared: false,
      exploreKey: bookmarkData.exploreKey || ''
    };
    
    console.log('ðŸ“¤ Creating Sigma bookmark with payload:', JSON.stringify(payload, null, 2));
    
    const response = await axios.post(
      `${SIGMA_WORKBOOKS_URL}/${workbookId}/bookmarks`,
      payload,
      {
        headers: {
          Authorization: `Bearer ${bearerToken}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    return response.data;
  } catch (error) {
    console.error('Error creating Sigma bookmark:', error.response?.data || error.message);
    throw error;
  }
}

// Helper function to delete bookmark from Sigma
async function deleteSigmaBookmark(workbookId, bookmarkId, bearerToken) {
  try {
    await axios.delete(
      `${SIGMA_WORKBOOKS_URL}/${workbookId}/bookmarks/${bookmarkId}`,
      {
        headers: {
          Authorization: `Bearer ${bearerToken}`,
          'Content-Type': 'application/json'
        }
      }
    );
    return true;
  } catch (error) {
    if (error.response?.status === 404) {
      console.log('Bookmark not found in Sigma (may have been already deleted)');
      return true;
    }
    console.error('Error deleting Sigma bookmark:', error.response?.data || error.message);
    throw error;
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
    console.log(`ðŸ’¼ Fetched ${accountTypes.length} account types from Sigma`);
    
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
      console.log(`ðŸ”‘ Fetched ${attributes.length} user attributes from Sigma`);
      
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
        
        console.log(`âœ… Created configuration for user: ${email}`);
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
        
        console.log(`âœ… Updated configuration for user: ${userEmail}`);
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
        
        console.log(`âœ… Deleted configuration for user: ${userEmail}`);
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

app.get('/api/user/teams', async (req, res) => {
  const email = req.query.email;
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    console.log(`\nðŸ“‹ Fetching teams for user: ${email}`);
    const bearerToken = await getBearerToken();
    const teams = await getUserTeams(email, bearerToken);
    
    res.json({ teams });
  } catch (error) {
    console.error('Error fetching user teams:', error);
    res.status(500).json({ error: 'Failed to fetch user teams' });
  }
});

// Get all bookmarks accessible to a user
app.get('/api/bookmarks', async (req, res) => {
  const email = req.query.email;
  const workbookId = req.query.workbookId;
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    console.log(`\nðŸ“š Fetching bookmarks for user: ${email}`);
    if (workbookId) {
      console.log(`ðŸ“– Filtered to workbook: ${workbookId}`);
    }
    
    const bearerToken = await getBearerToken();
    const userTeams = await getUserTeams(email, bearerToken);
    console.log(`ðŸ‘¥ User is in teams:`, userTeams);
    
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
      
      console.log(`âœ… Found ${rows.length} accessible bookmarks`);
      
      // Get team share info for each bookmark
      const bookmarkIds = [...new Set(rows.map(r => r.bookmark_id))];
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
            return res.json({ bookmarks: rows });
          }
          
          // Merge share info
          const shareMap = {};
          shares.forEach(share => {
            if (!shareMap[share.bookmark_id]) {
              shareMap[share.bookmark_id] = [];
            }
            shareMap[share.bookmark_id].push(share);
          });
          
          const bookmarksWithShares = rows.map(bookmark => ({
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
    console.log(`\nðŸ“– Creating/sharing bookmark: ${name} for user: ${userEmail}`);
    console.log(`ðŸ“– Workbook: ${workbookId} (${workbookName})`);
    console.log(`ðŸ“Š Explore Key: "${exploreKey}"`);
    
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
      console.log(`ðŸ“‹ Bookmark already exists in Sigma with ID: ${bookmarkId}`);
    } else {
      // Create new bookmark in Sigma
      const sigmaBookmark = await createSigmaBookmark(
        workbookId,
        {
          name: name,
          exploreKey: exploreKey || ''
        },
        bearerToken
      );
      
      bookmarkId = sigmaBookmark.bookmarkId;
      isNewBookmark = true;
      console.log(`âœ… New bookmark created in Sigma with ID: ${bookmarkId}`);
      
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
      console.log(`ðŸ‘¥ Bookmark shared with team: ${team}`);
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
    console.error('âŒ Error creating bookmark:', error.response?.data || error.message);
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
    console.log(`\nðŸŽ¯ Loading bookmark ${bookmarkId} for user: ${userEmail}`);
    
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
    console.log(`âœ… User has access to bookmark ${bookmarkId}`);
    
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

// Delete bookmark or remove access
app.delete('/api/bookmarks/:bookmarkId', async (req, res) => {
  const { bookmarkId } = req.params;
  const { userEmail, workbookId } = req.query;
  
  if (!userEmail || !workbookId) {
    return res.status(400).json({ error: 'userEmail and workbookId are required' });
  }

  try {
    console.log(`\nðŸ—‘ï¸ Delete request for bookmark ${bookmarkId} by user: ${userEmail}`);
    
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
      console.log(`ðŸ‘¤ Owner deleting bookmark - removing from Sigma`);
      
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
      
      console.log(`âœ… Bookmark completely deleted from Sigma and database`);
      res.json({ 
        success: true, 
        message: 'Bookmark deleted from Sigma and all access removed',
        action: 'deleted'
      });
      
    } else {
      // Viewer is removing access - just remove their access
      console.log(`ðŸ‘¤ Viewer removing their access to bookmark`);
      
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
      
      console.log(`âœ… Access removed for user ${userEmail}`);
      res.json({ 
        success: true, 
        message: 'Your access to this bookmark has been removed',
        action: 'access_removed'
      });
    }
    
  } catch (error) {
    console.error('âŒ Error deleting bookmark:', error);
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
      target: destinationConfig.recipients.map(email => ({ 
        email: email
      })),
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
    
    console.log('ðŸ“… Creating schedule in Sigma:', JSON.stringify(schedulePayload, null, 2));
    
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
    
    console.log(`âœ… Schedule created with ID: ${sigmaScheduleId} for user: ${createdBy}`);
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
      
      console.log(`ðŸ“… Updating schedule ${scheduleId} in Sigma:`, updatePayload);
      
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
      
      console.log(`âœ… Schedule ${scheduleId} updated in Sigma`);
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
    
    console.log(`âœ… Schedule ${scheduleId} deleted successfully`);
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
    console.error('âŒ Signed URL generation failed:', error);
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
    
    console.log(`\nðŸ§  Ask Sigma request from: ${email}`);
    console.log(`â“ Question: "${question}"`);
    
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
    console.error('âŒ Ask Sigma URL generation failed:', error);
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
  
  console.log(`\nðŸ” Authentication attempt for: ${email}`);
  console.log(`âœ… Authentication successful (demo mode)`);
  
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
    features: ['workbooks', 'bookmarks', 'admin', 'user-configs', 'dashboard', 'scheduler', 'ask-sigma']
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
  console.log(`  - User configuration management via Admin Panel`);
  console.log(`  - Custom teams, account types, and user attributes per user`);
  console.log(`  - Dynamic JWT generation based on user configuration`);
  console.log(`  - Workspace management and workbook organization (user-specific access via grants)`);
  console.log(`💡 Demo Mode: Any password will work for authentication`);
  console.log(`🔧 Configure users in the Admin Panel to customize their JWT tokens\n`);
});