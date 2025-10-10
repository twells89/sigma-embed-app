// Enhanced server.js with Workbook Selection and Bookmark Management
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

// Initialize SQLite Database
const db = new sqlite3.Database('./bookmarks.db', (err) => {
  if (err) {
    console.error('Error opening database:', err);
  } else {
    console.log('📚 Bookmark database connected');
    initializeDatabase();
  }
});

// Create bookmarks table with workbook_id
function initializeDatabase() {
  db.run(`
    CREATE TABLE IF NOT EXISTS bookmarks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      bookmark_id TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      workbook_id TEXT NOT NULL,
      workbook_name TEXT,
      user_email TEXT NOT NULL,
      team TEXT,
      is_shared BOOLEAN DEFAULT 0,
      share_type TEXT DEFAULT 'private',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (err) {
      console.error('Error creating bookmarks table:', err);
    } else {
      console.log('✅ Bookmarks table ready');
    }
  });
}

// Sigma API config
const SIGMA_BASE_URL = 'https://aws-api.sigmacomputing.com/v2';
const SIGMA_MEMBERS_URL = `${SIGMA_BASE_URL}/members`;
const SIGMA_WORKBOOKS_URL = `${SIGMA_BASE_URL}/workbooks`;

const embedClientId = '47e18ee2f96c25f397d9e133c099ace93a92caeaa43c75d477eeadda562987f1';
const embedSecret = 'ea7abbfe9300c2b1ae3cd1a3707dec406a21380e3a87e46bc2c1fd8b6a6c039a433e45a59ac385355396feede27fb2a93686c7ace00940133dd6dec656dba857';
const sigmaOrg = 'tj-wells-1989';

const clientId = '7db69272bcbaf88c2a9eaed83ff2f54c212b9acb391e0792eac2e4c676242781';
const clientSecret = '3bbdc1149cb4774ca8197a7cdcf0196ef4ecaa65b88b7a7f3946521af7e356c0f8bcf35eeb799fd564b475864dca4f966715215df99fa1943422a1251f74e20f';

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

// Get user's member ID
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

// Get user's teams from Sigma API
async function getUserTeams(userEmail, bearerToken) {
  try {
    const memberId = await getMemberId(userEmail, bearerToken);
    
    if (!memberId) {
      console.log(`⚠️ User ${userEmail} not found in Sigma`);
      return [];
    }
    
    console.log(`👤 Found member ID: ${memberId}`);
    
    const teamsUrl = `${SIGMA_MEMBERS_URL}/${memberId}/teams`;
    console.log(`📋 Fetching teams from: ${teamsUrl}`);
    
    const teamsResponse = await axios.get(teamsUrl, {
      headers: {
        Authorization: `Bearer ${bearerToken}`,
        'Content-Type': 'application/json'
      }
    });
    
    const teams = teamsResponse.data.entries || [];
    const teamNames = teams.map(team => team.name);
    
    console.log(`📋 User ${userEmail} is in teams:`, teamNames);
    return teamNames;
    
  } catch (err) {
    console.error('Error getting user teams:', err.response?.data || err.message);
    return [];
  }
}

// Helper function to extract workbook URL ID from various formats
function extractWorkbookUrlId(workbook) {
  // Try different possible fields
  let urlId = workbook.url || workbook.urlId || workbook.workbookUrlId;
  
  if (!urlId) {
    // Check if there's a latestVersion with a path
    if (workbook.latestVersion?.path) {
      const pathMatch = workbook.latestVersion.path.match(/\/([^/?#]+)$/);
      if (pathMatch && pathMatch[1]) {
        urlId = pathMatch[1];
        console.log(`🔍 Extracted URL ID from latestVersion.path: ${urlId}`);
        return urlId;
      }
    }
    
    console.warn('⚠️ No URL field found, using workbookId:', workbook.workbookId);
    return workbook.workbookId;
  }
  
  // If it's a full URL, extract just the ID part
  if (typeof urlId === 'string' && urlId.includes('/')) {
    // Extract from URLs like:
    // "https://app.sigmacomputing.com/tj-wells-1989/workbook/7xGLUnKltkdCLM9z4ZmJSB"
    const match = urlId.match(/\/workbook\/([^/?#]+)/);
    if (match && match[1]) {
      urlId = match[1];
      console.log(`🔍 Extracted URL ID from full URL: ${urlId}`);
    }
  }
  
  return urlId;
}

// Get workbooks shared with a user
async function getWorkbooksForUser(userEmail, bearerToken) {
  try {
    console.log(`\n📚 Fetching workbooks for user: ${userEmail}`);
    
    const memberId = await getMemberId(userEmail, bearerToken);
    
    if (!memberId) {
      console.log(`⚠️ User ${userEmail} not found in Sigma`);
      return [];
    }
    
    console.log(`👤 Member ID: ${memberId}`);
    
    // Use the correct grants API endpoint with userId parameter
    const grantsUrl = `${SIGMA_BASE_URL}/grants?userId=${memberId}`;
    console.log(`🔍 Fetching grants from: ${grantsUrl}`);
    
    const grantsResponse = await axios.get(grantsUrl, {
      headers: {
        Authorization: `Bearer ${bearerToken}`,
        'Content-Type': 'application/json'
      }
    });
    
    const grants = grantsResponse.data.entries || [];
    console.log(`📊 Found ${grants.length} total grants for user`);
    
    // Log first grant to see structure
    if (grants.length > 0) {
      console.log('🔍 Sample grant structure:', JSON.stringify(grants[0], null, 2));
    }
    
    // Try different possible structures
    let workbookIds = [];
    
    // Check different possible grant structures
    const workbookGrants = grants.filter(grant => {
      // Check various possible structures from the API
      const isWorkbook = 
        grant.resourceType === 'workbook' ||
        grant.resource?.type === 'workbook' ||
        grant.type === 'workbook' ||
        (grant.resource && grant.resource.includes && grant.resource.includes('workbook'));
      
      if (isWorkbook) {
        console.log('📖 Found workbook grant:', JSON.stringify(grant, null, 2));
      }
      
      return isWorkbook;
    });
    
    console.log(`📖 Found ${workbookGrants.length} workbook grants`);
    
    // Extract workbook IDs from whatever structure we have
    workbookIds = workbookGrants.map(grant => {
      return grant.resourceId || 
             grant.resource?.workbookId || 
             grant.resource?.id ||
             grant.workbookId ||
             grant.id;
    }).filter(id => id); // Remove undefined/null
    
    // Remove duplicates
    workbookIds = [...new Set(workbookIds)];
    
    console.log(`📚 Unique workbook IDs:`, workbookIds);
    
    // If we still don't have workbooks, try alternative approach: list all workbooks
    if (workbookIds.length === 0) {
      console.log('⚠️ No workbooks found via grants, trying direct workbooks list...');
      
      try {
        const workbooksListUrl = `${SIGMA_WORKBOOKS_URL}`;
        console.log(`🔍 Fetching from: ${workbooksListUrl}`);
        
        const workbooksResponse = await axios.get(workbooksListUrl, {
          headers: {
            Authorization: `Bearer ${bearerToken}`,
            'Content-Type': 'application/json'
          }
        });
        
        const allWorkbooks = workbooksResponse.data.entries || [];
        console.log(`📚 Found ${allWorkbooks.length} total workbooks in organization`);
        
        // For now, return all workbooks (Sigma will enforce permissions via signed URLs)
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
        console.log(`✅ Returning ${workbooks.length} workbooks`);
        
        // Log first workbook to see structure
        if (workbooks.length > 0) {
          console.log('📖 Sample workbook:', JSON.stringify(workbooks[0], null, 2));
        }
        
        return workbooks;
        
      } catch (listErr) {
        console.error('Error listing workbooks:', listErr.response?.data || listErr.message);
        return [];
      }
    }
    
    // Fetch details for each workbook
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
        
        console.log(`  ✅ ${workbook.name} (ID: ${workbook.workbookId}, URL ID: ${urlId})`);
      } catch (err) {
        console.error(`  ❌ Error fetching workbook ${workbookId}:`, err.response?.data?.message || err.message);
      }
    }
    
    // Sort by name
    workbooks.sort((a, b) => a.name.localeCompare(b.name));
    
    console.log(`✅ Successfully fetched ${workbooks.length} workbook details`);
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

async function generateSignedUrl(workbookUrlId, region = 'East', environment = 'Production', email = 'demo@plugselectronics.com', bookmarkId = null) {
  try {
    console.log(`\n🔐 Generating signed URL for user: ${email}`);
    console.log(`📖 Workbook URL ID: ${workbookUrlId}`);
    console.log(`🌍 Region: ${region}, Environment: ${environment}`);
    
    const sessionLength = 3600;
    const time = Math.floor(Date.now() / 1000);
    const { givenName, familyName } = generateUserAttributes(email);

    const bearerToken = await getBearerToken();
    const isInternal = await isInternalUser(email, bearerToken);

    const tokenData = {
      sub: email,
      iss: embedClientId,
      jti: crypto.randomUUID(),
      iat: time,
      exp: time + sessionLength
    };

    if (!isInternal) {
      console.log(`👤 External user detected - adding user attributes`);
      tokenData.first_name = givenName;
      tokenData.last_name = familyName;
      tokenData.account_type = 'Pro';
      tokenData.teams = [region];
      tokenData.user_attributes = { region };
    } else {
      console.log('🏢 Internal user detected — omitting all optional claims.');
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
    signedUrl += `&:theme=${region}`;
    signedUrl += `&:enable_inbound_events=true`;
    signedUrl += `&:enable_outbound_events=true`;
    signedUrl += `&:show_footer=true`;
    
    if (bookmarkId) {
      signedUrl += `&:bookmark=${bookmarkId}`;
      console.log(`📖 Loading bookmark: ${bookmarkId}`);
    }
    
    signedUrl += `&Region=${encodeURIComponent(region)}`;
    signedUrl += `&Environment=${encodeURIComponent(environment)}`;

    console.log(`✅ Signed URL generated successfully`);
    return signedUrl;
  } catch (error) {
    console.error("❌ Failed to generate signed URL:", error);
    throw error;
  }
}

// NEW ENDPOINT: Get workbooks for a user
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

// Get user's teams endpoint
app.get('/api/user/teams', async (req, res) => {
  const email = req.query.email;
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    console.log(`\n📋 Fetching teams for user: ${email}`);
    const bearerToken = await getBearerToken();
    const teams = await getUserTeams(email, bearerToken);
    
    res.json({ teams });
  } catch (error) {
    console.error('Error fetching user teams:', error);
    res.status(500).json({ error: 'Failed to fetch user teams' });
  }
});

// BOOKMARK API ENDPOINTS

// Get all bookmarks for a user (optionally filtered by workbook)
app.get('/api/bookmarks', async (req, res) => {
  const email = req.query.email;
  const workbookId = req.query.workbookId; // Optional filter
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    console.log(`\n📚 Fetching bookmarks for user: ${email}`);
    if (workbookId) {
      console.log(`📖 Filtered to workbook: ${workbookId}`);
    }
    
    const bearerToken = await getBearerToken();
    const userTeams = await getUserTeams(email, bearerToken);
    console.log(`👥 User is in teams:`, userTeams);
    
    let query = `SELECT * FROM bookmarks WHERE user_email = ?`;
    let params = [email];
    
    if (userTeams.length > 0) {
      const teamPlaceholders = userTeams.map(() => '(is_shared = 1 AND share_type = ? AND team = ?)').join(' OR ');
      query += ` OR ${teamPlaceholders}`;
      
      userTeams.forEach(team => {
        params.push('team', team);
      });
    }
    
    // Add workbook filter if provided
    if (workbookId) {
      query = `SELECT * FROM bookmarks WHERE workbook_id = ? AND (user_email = ?`;
      params = [workbookId, email];
      
      if (userTeams.length > 0) {
        const teamPlaceholders = userTeams.map(() => '(is_shared = 1 AND share_type = ? AND team = ?)').join(' OR ');
        query += ` OR ${teamPlaceholders}`;
        
        userTeams.forEach(team => {
          params.push('team', team);
        });
      }
      query += ')';
    }
    
    query += ` ORDER BY updated_at DESC`;
    
    db.all(query, params, (err, rows) => {
      if (err) {
        console.error('Error fetching bookmarks:', err);
        return res.status(500).json({ error: 'Failed to fetch bookmarks' });
      }
      
      console.log(`✅ Found ${rows.length} bookmarks`);
      res.json({ bookmarks: rows });
    });
  } catch (error) {
    console.error('Error in bookmarks endpoint:', error);
    res.status(500).json({ error: 'Failed to fetch bookmarks' });
  }
});

// Create a new bookmark via Sigma API and store locally
app.post('/api/bookmarks', async (req, res) => {
  const { name, userEmail, team, shareType = 'private', workbookId, workbookName, exploreKey = '' } = req.body;
  
  if (!name || !userEmail || !workbookId) {
    return res.status(400).json({ error: 'Name, userEmail, and workbookId are required' });
  }

  try {
    console.log(`\n📖 Creating bookmark: ${name} for user: ${userEmail}`);
    console.log(`📖 Workbook: ${workbookId} (${workbookName})`);
    console.log(`📊 Explore Key: "${exploreKey}" ${exploreKey ? '(specific explore)' : '(workbook level)'}`);
    
    const bearerToken = await getBearerToken();
    
    const workbookResponse = await axios.get(
      `${SIGMA_WORKBOOKS_URL}/${workbookId}`,
      {
        headers: {
          Authorization: `Bearer ${bearerToken}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    const version = workbookResponse.data.latestVersion;
    console.log(`📋 Workbook version: ${version}`);
    
    const bookmarkPayload = {
      name: name,
      workbookVersion: version,
      isShared: false,
      exploreKey: exploreKey
    };
    
    console.log('Creating bookmark with payload:', JSON.stringify(bookmarkPayload, null, 2));
    
    const bookmarkResponse = await axios.post(
      `${SIGMA_WORKBOOKS_URL}/${workbookId}/bookmarks`,
      bookmarkPayload,
      {
        headers: {
          Authorization: `Bearer ${bearerToken}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    const bookmarkId = bookmarkResponse.data.bookmarkId;
    console.log(`✅ Bookmark created in Sigma with ID: ${bookmarkId}`);
    
    const isSharedLocally = shareType === 'team' ? 1 : 0;
    const query = `
      INSERT INTO bookmarks (bookmark_id, name, workbook_id, workbook_name, user_email, team, is_shared, share_type)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;
    
    db.run(query, [bookmarkId, name, workbookId, workbookName, userEmail, team, isSharedLocally, shareType], function(err) {
      if (err) {
        console.error('Error storing bookmark locally:', err);
        return res.status(500).json({ error: 'Failed to store bookmark' });
      }
      
      console.log(`✅ Bookmark stored locally with ID: ${this.lastID}`);
      
      res.json({
        success: true,
        bookmark: {
          id: this.lastID,
          bookmarkId,
          name,
          workbookId,
          workbookName,
          userEmail,
          team,
          isShared: isSharedLocally,
          shareType
        }
      });
    });
  } catch (error) {
    console.error('Error creating bookmark:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Failed to create bookmark',
      details: error.response?.data || error.message
    });
  }
});

// Delete a bookmark
app.delete('/api/bookmarks/:bookmarkId', async (req, res) => {
  const { bookmarkId } = req.params;
  const { userEmail, workbookId } = req.query;
  
  if (!userEmail || !workbookId) {
    return res.status(400).json({ error: 'userEmail and workbookId are required' });
  }

  try {
    console.log(`\n🗑️ Deleting bookmark ${bookmarkId} for user: ${userEmail}`);
    
    const bearerToken = await getBearerToken();
    
    await axios.delete(
      `${SIGMA_WORKBOOKS_URL}/${workbookId}/bookmarks/${bookmarkId}`,
      {
        headers: {
          Authorization: `Bearer ${bearerToken}`
        }
      }
    );
    
    console.log(`✅ Bookmark deleted from Sigma`);
    
    const query = `DELETE FROM bookmarks WHERE bookmark_id = ? AND user_email = ?`;
    
    db.run(query, [bookmarkId, userEmail], function(err) {
      if (err) {
        console.error('Error deleting bookmark from database:', err);
        return res.status(500).json({ error: 'Failed to delete bookmark' });
      }
      
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Bookmark not found or unauthorized' });
      }
      
      console.log(`✅ Bookmark deleted from local database`);
      res.json({ success: true, message: 'Bookmark deleted' });
    });
  } catch (error) {
    console.error('Error deleting bookmark:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Failed to delete bookmark',
      details: error.response?.data || error.message
    });
  }
});

// Get signed URL with workbook and optional bookmark
app.get('/api/signed-url', async (req, res) => {
  try {
    const workbookId = req.query.workbookId; // This is the API workbookId
    let workbookUrlId = req.query.workbookUrlId; // This is the URL-friendly ID
    const region = req.query.region || 'East';
    const environment = req.query.environment || 'Production';
    const email = req.query.email || 'demo@plugselectronics.com';
    const bookmarkId = req.query.bookmarkId || null;
    
    // If workbookUrlId is a full URL, extract just the ID
    if (workbookUrlId && workbookUrlId.includes('/')) {
      const match = workbookUrlId.match(/\/workbook\/([^/?#]+)/);
      if (match && match[1]) {
        workbookUrlId = match[1];
        console.log(`🔍 Extracted URL ID from parameter: ${workbookUrlId}`);
      }
    }
    
    // If we still don't have a URL ID and we have a workbook ID, fetch it
    if (!workbookUrlId && workbookId) {
      console.log(`🔍 Fetching workbook details to get URL ID for: ${workbookId}`);
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
        console.log(`✅ Found URL ID: ${workbookUrlId}`);
      } catch (err) {
        console.error('Error fetching workbook:', err.response?.data || err.message);
        return res.status(500).json({ error: 'Failed to fetch workbook details' });
      }
    }
    
    if (!workbookUrlId) {
      return res.status(400).json({ error: 'workbookId or workbookUrlId is required' });
    }
    
    console.log(`\n📊 Dashboard request from: ${email}`);
    console.log(`📖 Workbook URL ID: ${workbookUrlId}`);
    if (bookmarkId) {
      console.log(`📖 Loading with bookmark: ${bookmarkId}`);
    }
    
    const signedUrl = await generateSignedUrl(workbookUrlId, region, environment, email, bookmarkId);
    res.json({ 
      url: signedUrl, 
      workbookId,
      workbookUrlId: workbookUrlId,
      region, 
      environment, 
      email,
      bookmarkId,
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

// Routes
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/workbooks', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'workbooks.html'));
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
  
  console.log(`\n🔐 Authentication attempt for: ${email}`);
  console.log(`✅ Authentication successful (demo mode)`);
  
  res.json({ 
    success: true, 
    message: 'Authentication successful',
    email: email 
  });
});

app.get('/api/ask-sigma-url', async (req, res) => {
  try {
    const region = req.query.region || 'East';
    const environment = req.query.environment || 'Production';
    const email = req.query.email || 'demo@plugselectronics.com';
    const question = req.query.question || '';
    
    console.log(`\n🧠 Ask Sigma request from: ${email}`);
    console.log(`❓ Question: "${question}"`);
    
    const sessionLength = 3600;
    const time = Math.floor(Date.now() / 1000);
    const { givenName, familyName } = generateUserAttributes(email);

    const bearerToken = await getBearerToken();
    const isInternal = await isInternalUser(email, bearerToken);

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
      tokenData.account_type = 'Pro';
      tokenData.teams = [region];
      tokenData.user_attributes = { region };
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
    signedUrl += `&Region=${encodeURIComponent(region)}&Environment=${encodeURIComponent(environment)}`;

    res.json({ 
      url: signedUrl, 
      region, 
      environment, 
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

app.get('/ask', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'ask-sigma-page.html'));
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    server: 'Plugs Electronics Dashboard Server',
    features: ['workbooks', 'bookmarks', 'ask-sigma', 'dashboard']
  });
});

app.get('*', (req, res) => {
  res.redirect('/');
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n\n🛑 Shutting down server...');
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
  console.log(`\n🚀 Plugs Electronics Dashboard Server`);
  console.log(`🌐 Server running at http://localhost:${PORT}`);
  console.log(`🔐 Login page: http://localhost:${PORT}/login`);
  console.log(`📚 Workbooks: http://localhost:${PORT}/workbooks`);
  console.log(`📊 Dashboard: http://localhost:${PORT}/`);
  console.log(`📖 Bookmarks: Enabled with local SQLite database`);
  console.log(`\n💡 Demo Mode: Any password will work for authentication`);
  console.log(`🔧 Test with different emails to see internal vs external user behavior\n`);
});