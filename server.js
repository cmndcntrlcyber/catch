#!/usr/bin/env node

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { parse } = require('url');
const dns = require('dns');
const { config, getBaseUrl, getEndpointUrl, isDevelopment, isProduction, shouldUseHttps } = require('./config');
const scrubber = require('./lib/data-scrubber');

// Function to extract the real client IP address
function getClientIP(req) {
  // Check for Cloudflare headers first
  const cfConnectingIP = req.headers['cf-connecting-ip'];
  if (cfConnectingIP) {
    return cfConnectingIP.trim();
  }
  
  // Check for X-Forwarded-For header (proxy/load balancer)
  const xForwardedFor = req.headers['x-forwarded-for'];
  if (xForwardedFor) {
    // X-Forwarded-For can contain multiple IPs, take the first one
    return xForwardedFor.split(',')[0].trim();
  }
  
  // Check for X-Real-IP header (alternative proxy header)
  const xRealIP = req.headers['x-real-ip'];
  if (xRealIP) {
    return xRealIP.trim();
  }
  
  // Fall back to connection remote address
  const remoteAddress = req.connection?.remoteAddress || 
                       req.socket?.remoteAddress || 
                       req.connection?.socket?.remoteAddress;
  
  if (remoteAddress) {
    // Handle IPv6-mapped IPv4 addresses
    if (remoteAddress.startsWith('::ffff:')) {
      return remoteAddress.substring(7);
    }
    return remoteAddress;
  }
  
  return 'unknown';
}

// Function to handle request body for methods that can have body content
function handleRequestWithBody(req, callback) {
  let body = '';
  const maxBodySize = config.dataCollection.maxBodySize; // Configurable limit
  
  req.on('data', chunk => {
    body += chunk.toString();
    // Prevent abuse with body size limit
    if (body.length > maxBodySize) {
      const error = new Error('Request entity too large');
      error.statusCode = 413;
      return callback(error);
    }
  });
  
  req.on('end', () => {
    callback(null, body);
  });
  
  req.on('error', (err) => {
    callback(err);
  });
}

// Function to create comprehensive log entry
function createLogEntry(req, clientIP, timestamp, body = '') {
  const method = req.method;
  const hostname = req.headers.host || 'unknown';
  const userAgent = req.headers['user-agent'] || 'unknown';
  const referer = req.headers.referer || req.headers.referrer || '';
  const origin = req.headers.origin || '';
  const contentType = req.headers['content-type'] || '';

  const logIP = scrubber.scrubIP(clientIP);
  const logUA = scrubber.scrubUserAgent(userAgent);
  const logBody = body.length > 0 ? scrubber.scrubBody(body.substring(0, 500)) : '';

  let logEntry = `${timestamp} | IP: ${logIP} | Method: ${method} | Host: ${hostname} | URL: ${req.url}`;
  logEntry += ` | UA: ${logUA}`;

  if (contentType) logEntry += ` | Content-Type: ${contentType}`;
  if (referer) logEntry += ` | Referer: ${referer}`;
  if (origin) logEntry += ` | Origin: ${origin}`;
  if (logBody.length > 0) {
    logEntry += ` | Body: ${logBody}${body.length > 500 ? '...[truncated]' : ''}`;
  }
  logEntry += '\n';

  return logEntry;
}

// ============================================================================
// BLOCKING AND SECURITY FUNCTIONS
// ============================================================================

// Rate limiting storage
const rateLimitStore = new Map(); // { ip: { count: number, resetTime: timestamp } }

// Violation tracking storage
const violationStore = new Map(); // { ip: { count: number, firstViolation: timestamp } }

/**
 * Clean up expired rate limit entries
 */
function cleanupRateLimitStore() {
  const now = Date.now();
  for (const [ip, data] of rateLimitStore.entries()) {
    if (now > data.resetTime) {
      rateLimitStore.delete(ip);
    }
  }
}

// Clean up every minute
setInterval(cleanupRateLimitStore, 60000);

/**
 * Check if IP has exceeded rate limit
 * @param {string} clientIP - Client IP address
 * @returns {Object} { limited: boolean, resetTime: number|null }
 */
function checkRateLimit(clientIP) {
  if (!config.blocking.rateLimitEnabled) {
    return { limited: false, resetTime: null };
  }

  const now = Date.now();
  const entry = rateLimitStore.get(clientIP);

  if (!entry || now > entry.resetTime) {
    // New window or expired entry
    rateLimitStore.set(clientIP, {
      count: 1,
      resetTime: now + config.security.rateLimit.windowMs
    });
    return { limited: false, resetTime: null };
  }

  // Increment count
  entry.count++;

  if (entry.count > config.security.rateLimit.maxRequests) {
    return { limited: true, resetTime: entry.resetTime };
  }

  return { limited: false, resetTime: null };
}

/**
 * Record a violation and check if IP should be auto-blocked
 * @param {string} clientIP - Client IP address
 * @returns {boolean} True if IP should be auto-blocked
 */
function recordViolation(clientIP) {
  if (!config.blocking.autoBlockAfterViolations) {
    return false;
  }

  const now = Date.now();
  const entry = violationStore.get(clientIP);

  if (!entry) {
    violationStore.set(clientIP, { count: 1, firstViolation: now });
    return false;
  }

  entry.count++;

  if (entry.count >= config.blocking.autoBlockAfterViolations) {
    // Add to blocked IPs list
    if (!config.blocking.blockedIPs.includes(clientIP)) {
      config.blocking.blockedIPs.push(clientIP);
      console.log(`🚨 AUTO-BLOCKED IP after ${entry.count} violations: ${scrubber.scrubIP(clientIP)}`);

      // Schedule unblock
      if (config.blocking.autoBlockDuration > 0) {
        setTimeout(() => {
          const index = config.blocking.blockedIPs.indexOf(clientIP);
          if (index > -1) {
            config.blocking.blockedIPs.splice(index, 1);
            violationStore.delete(clientIP);
            console.log(`✅ AUTO-UNBLOCKED IP after timeout: ${scrubber.scrubIP(clientIP)}`);
          }
        }, config.blocking.autoBlockDuration);
      }
    }
    return true;
  }

  return false;
}

/**
 * Check if IP matches CIDR range
 * @param {string} ip - IP address to check
 * @param {string} cidr - CIDR notation (e.g., "192.168.1.0/24")
 * @returns {boolean} True if IP is in CIDR range
 */
function ipInCIDR(ip, cidr) {
  if (!cidr.includes('/')) {
    return ip === cidr; // Exact match
  }

  const [range, bits] = cidr.split('/');
  const mask = ~(2 ** (32 - parseInt(bits)) - 1);

  const ipToInt = (ipStr) => {
    return ipStr.split('.').reduce((int, octet) => (int << 8) + parseInt(octet), 0) >>> 0;
  };

  return (ipToInt(ip) & mask) === (ipToInt(range) & mask);
}

/**
 * Check if IP is in any blocked CIDR range or exact blocklist
 * @param {string} clientIP - Client IP address
 * @returns {boolean} True if IP is blocked
 */
function isIPBlocked(clientIP) {
  // Check exact IPs
  if (config.blocking.blockedIPs.includes(clientIP)) {
    return true;
  }

  // Check CIDR ranges
  for (const cidr of config.blocking.blockedCIDRs || []) {
    if (ipInCIDR(clientIP, cidr)) {
      return true;
    }
  }

  return false;
}

/**
 * Check if request is whitelisted and should bypass blocking
 * @param {Object} req - HTTP request object
 * @param {string} clientIP - Client IP address
 * @returns {boolean} True if whitelisted
 */
function isWhitelisted(req, clientIP) {
  if (!config.blocking.whitelistEnabled) {
    return false;
  }

  // Check IP whitelist
  if (config.blocking.whitelistedIPs.includes(clientIP)) {
    return true;
  }

  // Check CIDR whitelist
  for (const cidr of config.blocking.whitelistedCIDRs) {
    if (ipInCIDR(clientIP, cidr)) {
      return true;
    }
  }

  // Check User-Agent whitelist
  const userAgent = req.headers['user-agent'] || '';
  for (const pattern of config.blocking.whitelistedUserAgents) {
    try {
      const regex = new RegExp(pattern, 'i');
      if (regex.test(userAgent)) {
        return true;
      }
    } catch (err) {
      console.error(`Invalid whitelist regex: ${pattern}`);
    }
  }

  return false;
}

/**
 * Check if IP should be blocked based on GeoIP
 * @param {string} clientIP - Client IP address
 * @returns {Object} { blocked: boolean, reason: string|null, country: string|null }
 */
function checkGeoIPBlocking(clientIP) {
  if (!config.blocking.geoIPEnabled) {
    return { blocked: false, reason: null, country: null };
  }

  try {
    const geoip = require('geoip-lite');
    const geo = geoip.lookup(clientIP);

    if (!geo) {
      // Unknown country - block if configured
      if (config.blocking.blockUnknownCountries) {
        return { blocked: true, reason: 'Unknown country/region', country: null };
      }
      return { blocked: false, reason: null, country: null };
    }

    const country = geo.country;

    // Check blocked countries
    if (config.blocking.blockedCountries.includes(country)) {
      return { blocked: true, reason: `Blocked country: ${country}`, country };
    }

    // Check allowed countries (if whitelist mode)
    if (config.blocking.allowedCountries.length > 0 &&
        !config.blocking.allowedCountries.includes(country)) {
      return { blocked: true, reason: `Country not in allowlist: ${country}`, country };
    }

    return { blocked: false, reason: null, country };
  } catch (err) {
    // GeoIP module not installed or error occurred
    return { blocked: false, reason: null, country: null };
  }
}

/**
 * Check IP against threat intelligence feeds
 * @param {string} clientIP - Client IP address
 * @returns {Promise<Object>} { blocked: boolean, reason: string|null, feed: string|null }
 */
async function checkThreatFeeds(clientIP) {
  if (!config.blocking.threatFeedsEnabled) {
    return { blocked: false, reason: null, feed: null };
  }

  // Check AbuseIPDB
  if (config.blocking.abuseIPDBKey) {
    try {
      const https = require('https');

      return new Promise((resolve) => {
        const options = {
          hostname: 'api.abuseipdb.com',
          path: `/api/v2/check?ipAddress=${clientIP}`,
          method: 'GET',
          headers: {
            'Key': config.blocking.abuseIPDBKey,
            'Accept': 'application/json'
          }
        };

        const req = https.request(options, (res) => {
          let data = '';

          res.on('data', (chunk) => {
            data += chunk;
          });

          res.on('end', () => {
            try {
              const json = JSON.parse(data);
              if (json.data && json.data.abuseConfidenceScore > config.blocking.threatScoreThreshold) {
                resolve({
                  blocked: true,
                  reason: `Threat feed: AbuseIPDB score ${json.data.abuseConfidenceScore}%`,
                  feed: 'AbuseIPDB'
                });
              } else {
                resolve({ blocked: false, reason: null, feed: null });
              }
            } catch (err) {
              console.error('Error parsing AbuseIPDB response:', err);
              resolve({ blocked: false, reason: null, feed: null });
            }
          });
        });

        req.on('error', (err) => {
          console.error('Error checking AbuseIPDB:', err);
          resolve({ blocked: false, reason: null, feed: null });
        });

        req.end();
      });
    } catch (err) {
      console.error('Error in threat feed check:', err);
      return { blocked: false, reason: null, feed: null };
    }
  }

  return { blocked: false, reason: null, feed: null };
}

/**
 * Check if text matches any pattern in the array
 * @param {string} text - Text to check
 * @param {Array<string>} patterns - Array of regex pattern strings
 * @returns {Object} { matched: boolean, pattern: string|null }
 */
function matchesPattern(text, patterns) {
  if (!text || !patterns || patterns.length === 0) {
    return { matched: false, pattern: null };
  }

  for (const pattern of patterns) {
    try {
      const regex = new RegExp(pattern, 'i');
      if (regex.test(text)) {
        return { matched: true, pattern: pattern };
      }
    } catch (err) {
      console.error(`Invalid regex pattern: ${pattern}`, err);
    }
  }

  return { matched: false, pattern: null };
}

/**
 * Check if request should be blocked based on configured rules
 * @param {Object} req - HTTP request object
 * @param {string} clientIP - Client IP address
 * @param {string} body - Request body (optional)
 * @returns {Promise<Object>} { blocked: boolean, reason: string|null }
 */
async function shouldBlockRequest(req, clientIP, body = null) {
  if (!config.blocking.enabled) {
    return { blocked: false, reason: null };
  }

  // Check whitelist first
  if (isWhitelisted(req, clientIP)) {
    return { blocked: false, reason: null };
  }

  // Check rate limit
  const rateCheck = checkRateLimit(clientIP);
  if (rateCheck.limited) {
    return { blocked: true, reason: 'Rate limit exceeded' };
  }

  // Check IP blocklist
  if (isIPBlocked(clientIP)) {
    return { blocked: true, reason: `Blocked IP: ${clientIP}` };
  }

  // Check GeoIP blocking
  const geoCheck = checkGeoIPBlocking(clientIP);
  if (geoCheck.blocked) {
    return { blocked: true, reason: geoCheck.reason };
  }

  // Check threat feeds
  const threatCheck = await checkThreatFeeds(clientIP);
  if (threatCheck.blocked) {
    return { blocked: true, reason: threatCheck.reason };
  }

  // Check User-Agent patterns
  const userAgent = req.headers['user-agent'] || '';
  const uaMatch = matchesPattern(userAgent, config.blocking.blockedUserAgents);
  if (uaMatch.matched) {
    return { blocked: true, reason: `Blocked User-Agent pattern: ${uaMatch.pattern}` };
  }

  // Check URL patterns
  const url = req.url || '';
  const urlMatch = matchesPattern(url, config.blocking.blockedUrlPatterns);
  if (urlMatch.matched) {
    return { blocked: true, reason: `Blocked URL pattern: ${urlMatch.pattern}` };
  }

  // Check POST body patterns if body provided
  if (body) {
    const bodyMatch = matchesPattern(body, config.blocking.blockedBodyPatterns);
    if (bodyMatch.matched) {
      return { blocked: true, reason: `Blocked POST body pattern: ${bodyMatch.pattern}` };
    }
  }

  return { blocked: false, reason: null };
}

/**
 * Send blocked response to client
 * @param {Object} res - HTTP response object
 * @param {string} reason - Reason for blocking
 * @param {string} clientIP - Client IP address
 * @param {string} timestamp - Request timestamp
 */
function sendBlockedResponse(res, reason, clientIP, timestamp) {
  const responseCode = config.blocking.responseCode;
  const responseMessage = responseCode === 444 ? '' : `Blocked: ${reason}`;

  console.log(`[${timestamp}] 🚫 BLOCKED REQUEST from ${scrubber.scrubIP(clientIP)}: ${reason}`);

  // Log blocked request to separate file
  const blockLogEntry = `${timestamp} | IP: ${scrubber.scrubIP(clientIP)} | STATUS: BLOCKED | REASON: ${reason}\n`;
  fs.appendFile('logs/blocked-requests.log', blockLogEntry, (err) => {
    if (err) console.error('Error writing to blocked log:', err);
  });

  // Record violation for auto-blocking
  recordViolation(clientIP);

  if (responseCode === 444) {
    // Nginx-style: close connection without response
    res.destroy();
    return;
  }

  // Send HTTP error response
  res.writeHead(responseCode, {
    'Content-Type': 'text/plain',
    'X-Blocked-Reason': reason.substring(0, 100),
    'Connection': 'close'
  });
  res.end(responseMessage);
}

// ============================================================================
// END BLOCKING AND SECURITY FUNCTIONS
// ============================================================================

// ============================================================================
// ADMIN INTERFACE FUNCTIONS
// ============================================================================

// Admin authentication token from environment
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'change-me-in-production-use-strong-random-token';

/**
 * Check admin authentication
 * @param {Object} req - HTTP request object
 * @returns {boolean} True if authenticated
 */
function checkAdminAuth(req) {
  const token = req.headers['x-admin-token'] || parse(req.url, true).query.token;
  return token === ADMIN_TOKEN;
}

const STATS_RANGES = {
  '1h':  { windowMs:      60 * 60 * 1000, bucketMs:      60 * 1000 },
  '24h': { windowMs: 24 * 60 * 60 * 1000, bucketMs: 15 * 60 * 1000 },
  '7d':  { windowMs: 7 * 24 * 60 * 60 * 1000, bucketMs: 60 * 60 * 1000 },
  'all': { windowMs: null,                bucketMs: 24 * 60 * 60 * 1000 }
};

function formatBucketLabel(ms, bucketMs) {
  const d = new Date(ms);
  const pad = n => String(n).padStart(2, '0');
  if (bucketMs < 60 * 60 * 1000) {
    return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }
  if (bucketMs < 24 * 60 * 60 * 1000) {
    return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:00`;
  }
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/**
 * Calculate statistics from log file
 * @param {Array<string>} lines - Log file lines
 * @param {string} [range] - Time range key: '1h' | '24h' | '7d' | 'all'
 * @returns {Object} Statistics object
 */
function calculateStats(lines, range = '24h') {
  const rangeDef = STATS_RANGES[range] || STATS_RANGES['24h'];
  const now = Date.now();
  const cutoff = rangeDef.windowMs ? now - rangeDef.windowMs : null;
  const buckets = new Map();
  let earliestBucket = null;
  let latestBucket = null;

  const stats = {
    totalRequests: 0,
    blockedRequests: 0,
    uniqueIPs: new Set(),
    threatScore: 0,
    topAttackers: {},
    attackPatterns: {},
    requestTrends: [],
    range
  };

  lines.forEach(line => {
    const log = parseLogLine(line);
    if (!log) return;

    const ts = log.timestamp ? Date.parse(log.timestamp) : NaN;
    if (Number.isNaN(ts)) return;
    if (cutoff !== null && ts < cutoff) return;

    stats.totalRequests++;

    // Count unique IPs
    if (log.IP) {
      stats.uniqueIPs.add(log.IP);
    }

    const blocked = log.STATUS === 'BLOCKED';

    // Count blocked requests
    if (blocked) {
      stats.blockedRequests++;

      // Track top attackers
      if (log.IP) {
        stats.topAttackers[log.IP] = (stats.topAttackers[log.IP] || 0) + 1;
      }

      // Track attack patterns
      if (log.REASON) {
        const pattern = log.REASON.split(':')[0]; // Extract pattern type
        stats.attackPatterns[pattern] = (stats.attackPatterns[pattern] || 0) + 1;
      }
    }

    // Bucket by floor(timestamp / bucketMs)
    const bucketKey = Math.floor(ts / rangeDef.bucketMs) * rangeDef.bucketMs;
    let bucket = buckets.get(bucketKey);
    if (!bucket) {
      bucket = { total: 0, blocked: 0 };
      buckets.set(bucketKey, bucket);
    }
    bucket.total++;
    if (blocked) bucket.blocked++;

    if (earliestBucket === null || bucketKey < earliestBucket) earliestBucket = bucketKey;
    if (latestBucket === null || bucketKey > latestBucket) latestBucket = bucketKey;
  });

  // Build a contiguous series so the x-axis has no gaps.
  if (earliestBucket !== null) {
    const start = cutoff !== null
      ? Math.floor(cutoff / rangeDef.bucketMs) * rangeDef.bucketMs
      : earliestBucket;
    const end = cutoff !== null
      ? Math.floor(now / rangeDef.bucketMs) * rangeDef.bucketMs
      : latestBucket;
    for (let t = start; t <= end; t += rangeDef.bucketMs) {
      const b = buckets.get(t) || { total: 0, blocked: 0 };
      stats.requestTrends.push({
        time: formatBucketLabel(t, rangeDef.bucketMs),
        total: b.total,
        blocked: b.blocked
      });
    }
  }

  // Convert unique IPs set to count
  stats.uniqueIPs = stats.uniqueIPs.size;

  // Calculate threat score (percentage of blocked requests)
  stats.threatScore = stats.totalRequests > 0
    ? Math.round((stats.blockedRequests / stats.totalRequests) * 100)
    : 0;

  // Sort and limit top attackers
  stats.topAttackers = Object.entries(stats.topAttackers)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([ip, count]) => ({ ip, count }));

  // Sort and limit attack patterns
  stats.attackPatterns = Object.entries(stats.attackPatterns)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([pattern, count]) => ({ pattern, count }));

  return stats;
}

/**
 * Parse log line into object
 * @param {string} line - Log line
 * @returns {Object|null} Parsed log object
 */
function parseLogLine(line) {
  const parts = line.split(' | ');
  if (parts.length < 3) return null;

  const log = {};
  parts.forEach((part, index) => {
    if (index === 0) {
      // First part is always the timestamp (ISO format contains colons)
      log.timestamp = part.trim();
      return;
    }
    const colonIndex = part.indexOf(':');
    if (colonIndex > 0) {
      const key = part.substring(0, colonIndex).trim();
      const value = part.substring(colonIndex + 1).trim();
      log[key] = value;
    }
  });

  return log;
}

// ============================================================================
// END ADMIN INTERFACE FUNCTIONS
// ============================================================================

// Function to serve static files
function serveStaticFile(req, res, filePath) {
  const extname = path.extname(filePath).toLowerCase();
  const mimeTypes = {
    '.html': 'text/html',
    '.js': 'text/javascript',
    '.css': 'text/css',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon'
  };

  const contentType = mimeTypes[extname] || 'application/octet-stream';

  fs.readFile(filePath, (error, content) => {
    if (error) {
      if (error.code == 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('File not found');
      } else {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Server error: ' + error.code);
      }
    } else {
      const cacheControl = filePath.includes('admin') ? 'no-cache' : 'public, max-age=3600';
      res.writeHead(200, {
        'Content-Type': contentType,
        'Cache-Control': cacheControl
      });
      res.end(content, 'utf-8');
    }
  });
}

// Function to provide fingerprint data as JSON API
function serveFingerprintAPI(req, res, clientIP, timestamp) {
  const fingerprintData = {
    timestamp: timestamp,
    server: {
      clientIP: scrubber.scrubIP(clientIP),
      userAgent: scrubber.scrubUserAgent(req.headers['user-agent'] || 'unknown'),
      acceptLanguage: req.headers['accept-language'] || 'unknown',
      acceptEncoding: req.headers['accept-encoding'] || 'unknown',
      connection: req.headers.connection || 'unknown',
      host: req.headers.host || 'unknown',
      referer: req.headers.referer || req.headers.referrer || '',
      origin: req.headers.origin || '',
      xForwardedFor: scrubber.scrubIP(req.headers['x-forwarded-for'] || ''),
      xRealIP: scrubber.scrubIP(req.headers['x-real-ip'] || ''),
      cfConnectingIP: scrubber.scrubIP(req.headers['cf-connecting-ip'] || ''),
      cfRay: req.headers['cf-ray'] || '',
      cfIPCountry: req.headers['cf-ipcountry'] || '',
      dnt: req.headers.dnt || '',
      upgradeInsecureRequests: req.headers['upgrade-insecure-requests'] || '',
      secFetchDest: req.headers['sec-fetch-dest'] || '',
      secFetchMode: req.headers['sec-fetch-mode'] || '',
      secFetchSite: req.headers['sec-fetch-site'] || '',
      allHeaders: scrubber.scrubHeaders(req.headers)
    },
    url: req.url,
    method: req.method,
    httpVersion: req.httpVersion,
    protocol: req.connection.encrypted ? 'https' : 'http'
  };

  res.writeHead(200, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Origin, Referer, Authorization, X-Requested-With, Accept, Accept-Language, Accept-Encoding',
  });
  
  res.end(JSON.stringify(fingerprintData, null, 2));
}

// Function to log request details to console
function logRequestDetails(req, clientIP, timestamp, body = '') {
  const method = req.method;
  const hostname = req.headers.host || 'unknown';
  const userAgent = req.headers['user-agent'] || 'unknown';
  const referer = req.headers.referer || req.headers.referrer || '';
  const origin = req.headers.origin || '';
  const contentType = req.headers['content-type'] || '';

  const logIP = scrubber.scrubIP(clientIP);
  const logUA = scrubber.scrubUserAgent(userAgent);

  console.log(`[${timestamp}] ${method} request from IP: ${logIP}`);
  console.log(`[${timestamp}] Host domain: ${hostname}`);
  console.log(`[${timestamp}] URL: ${req.url}`);
  console.log(`[${timestamp}] User-Agent: ${logUA}`);

  if (contentType) console.log(`[${timestamp}] Content-Type: ${contentType}`);
  if (referer) console.log(`[${timestamp}] Referer: ${referer}`);
  if (origin) console.log(`[${timestamp}] Origin: ${origin}`);

  const { query } = parse(req.url, true);
  if (Object.keys(query).length > 0) {
    console.log(`[${timestamp}] Query parameters:`, query);
  }

  if (body.length > 0) {
    const logBody = scrubber.scrubBody(body.substring(0, 1000));
    console.log(`[${timestamp}] ${method} body length: ${body.length} bytes`);
    console.log(`[${timestamp}] ${method} body content:`, logBody + (body.length > 1000 ? '...[truncated]' : ''));
  }
}

// Function to send response
function sendResponse(res, req, clientIP, timestamp, body = '') {
  const method = req.method;
  const hostname = req.headers.host || 'unknown';
  
  // Set comprehensive CORS headers
  res.writeHead(200, {
    'Content-Type': 'text/plain',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, CONNECT, TRACE',
    'Access-Control-Allow-Headers': 'Content-Type, Origin, Referer, Authorization, X-Requested-With, Accept, Accept-Language, Accept-Encoding',
    'Access-Control-Max-Age': '86400',
    'Server': 'Universal-Catch-Server/1.0'
  });
  
  let responseText = `${method} Request captured!\n`;
  responseText += `Client IP: ${scrubber.scrubIP(clientIP)}\n`;
  responseText += `Hostname: ${hostname}\n`;
  responseText += `Timestamp: ${timestamp}\n`;
  responseText += `URL: ${req.url}\n`;

  // Add method-specific information
  switch (method) {
    case 'POST':
    case 'PUT':
    case 'PATCH':
      if (body.length > 0) {
        responseText += `\n${method} Data Length: ${body.length} bytes\n`;
        responseText += `${method} Data Preview: ${scrubber.scrubBody(body.substring(0, 200))}${body.length > 200 ? '...[truncated]' : ''}\n`;
      }
      break;
    case 'DELETE':
      responseText += `\nDELETE operation logged for resource: ${req.url}\n`;
      break;
    case 'HEAD':
      // For HEAD requests, only send headers, no body
      res.end();
      return;
    case 'OPTIONS':
      responseText += `\nOPTIONS preflight request - CORS headers provided\n`;
      break;
    case 'TRACE':
      responseText = `TRACE ${req.url} HTTP/1.1\n`;
      responseText += `Host: ${hostname}\n`;
      responseText += `User-Agent: ${req.headers['user-agent'] || 'unknown'}\n`;
      break;
    case 'CONNECT':
      responseText += `\nCONNECT method detected - Tunnel request logged\n`;
      break;
    default:
      responseText += `\n${method} method successfully processed\n`;
  }
  
  res.end(responseText);
}

// SSL options with fallback for development
let options = null;
let useHttps = shouldUseHttps();

try {
  if (useHttps && config.ssl.keyPath && config.ssl.certPath) {
    options = {
      key: fs.readFileSync(config.ssl.keyPath, 'utf8'),
      cert: fs.readFileSync(config.ssl.certPath, 'utf8')
    };
    console.log('SSL certificates loaded successfully');
  }
} catch (error) {
  console.log('SSL certificates not available:', error.code);
  console.log('Running in development mode without HTTPS');
  useHttps = false;
}

// Main request handler for HTTPS server
async function handleRequest(req, res) {
  const timestamp = new Date().toISOString();
  const clientIP = getClientIP(req);
  const method = req.method;
  const url = parse(req.url, true);

  // Check if request should be blocked (for GET/HEAD/OPTIONS and methods without body)
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    const blockCheck = await shouldBlockRequest(req, clientIP);
    if (blockCheck.blocked) {
      if (config.blocking.mode === 'block') {
        sendBlockedResponse(res, blockCheck.reason, clientIP, timestamp);
        return;
      } else {
        // Log-only mode: continue but log the detection
        console.log(`[${timestamp}] ⚠️  WOULD BLOCK (log mode): ${blockCheck.reason}`);
      }
    }
  }

  // Route handling for GET requests
  if (method === 'GET') {
    // Serve fingerprinting landing page
    if (url.pathname === '/' || url.pathname === '/index.html') {
      logRequestDetails(req, clientIP, timestamp);
      const logEntry = createLogEntry(req, clientIP, timestamp);
      fs.appendFile(config.logging.file, logEntry, (err) => {
        if (err) console.error('Error writing to log file:', err);
      });
      serveStaticFile(req, res, path.join(__dirname, 'public', 'index.html'));
      return;
    }
    
    // Serve fingerprint API
    if (url.pathname === '/api/fingerprint') {
      logRequestDetails(req, clientIP, timestamp);
      const logEntry = createLogEntry(req, clientIP, timestamp);
      fs.appendFile(config.logging.file, logEntry, (err) => {
        if (err) console.error('Error writing to log file:', err);
      });
      serveFingerprintAPI(req, res, clientIP, timestamp);
      return;
    }
    
    // Serve static files from js directory
    if (url.pathname.startsWith('/js/')) {
      const filePath = path.join(__dirname, 'public', url.pathname);
      if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
        logRequestDetails(req, clientIP, timestamp);
        const logEntry = createLogEntry(req, clientIP, timestamp);
        fs.appendFile(config.logging.file, logEntry, (err) => {
          if (err) console.error('Error writing to log file:', err);
        });
        serveStaticFile(req, res, filePath);
        return;
      }
    }
    
    // Handle data exfiltration endpoint (image beacon method)
    if (url.pathname === '/exfil') {
      logRequestDetails(req, clientIP, timestamp);
      const exfilDataRaw = url.query.data ? decodeURIComponent(url.query.data) : 'No data';
      const exfilData = scrubber.scrubExfilData(exfilDataRaw);

      console.log(`[${timestamp}] EXFILTRATION DATA RECEIVED:`, exfilData);

      const logEntry = `${timestamp} | IP: ${scrubber.scrubIP(clientIP)} | Method: EXFIL-BEACON | Host: ${req.headers.host || 'unknown'} | URL: ${req.url} | UA: ${scrubber.scrubUserAgent(req.headers['user-agent'] || 'unknown')} | EXFIL-DATA: ${exfilData.substring(0, 1000)}\n`;
      fs.appendFile(config.logging.file, logEntry, (err) => {
        if (err) console.error('Error writing to log file:', err);
      });
      
      // Send a 1x1 transparent pixel as response
      const pixel = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
      res.writeHead(200, {
        'Content-Type': 'image/gif',
        'Content-Length': pixel.length,
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Access-Control-Allow-Origin': '*'
      });
      res.end(pixel);
      return;
    }
    
    // Handle data exfiltration iframe endpoint
    if (url.pathname === '/exfil-frame') {
      logRequestDetails(req, clientIP, timestamp);
      const exfilDataRaw = url.query.data ? decodeURIComponent(url.query.data) : 'No data';
      const exfilData = scrubber.scrubExfilData(exfilDataRaw);

      console.log(`[${timestamp}] EXFILTRATION DATA RECEIVED (IFRAME):`, exfilData);

      const logEntry = `${timestamp} | IP: ${scrubber.scrubIP(clientIP)} | Method: EXFIL-IFRAME | Host: ${req.headers.host || 'unknown'} | URL: ${req.url} | UA: ${scrubber.scrubUserAgent(req.headers['user-agent'] || 'unknown')} | EXFIL-DATA: ${exfilData.substring(0, 1000)}\n`;
      fs.appendFile(config.logging.file, logEntry, (err) => {
        if (err) console.error('Error writing to log file:', err);
      });
      
      // Send minimal HTML response for iframe
      res.writeHead(200, {
        'Content-Type': 'text/html',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Access-Control-Allow-Origin': '*'
      });
      res.end('<html><body><script>console.log("Data received");</script></body></html>');
      return;
    }

    // Handle admin interface
    if (url.pathname === '/admin' || url.pathname === '/admin.html') {
      if (!checkAdminAuth(req)) {
        res.writeHead(401, { 'Content-Type': 'text/plain' });
        res.end('Unauthorized - Invalid admin token');
        return;
      }
      serveStaticFile(req, res, path.join(__dirname, 'public', 'admin.html'));
      return;
    }

    // GET /api/admin/config - Get current configuration
    if (url.pathname === '/api/admin/config') {
      if (!checkAdminAuth(req)) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }

      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store'
      });
      const safeBlocking = Object.assign({}, config.blocking, {
        abuseIPDBKey: scrubber.maskApiKey(config.blocking.abuseIPDBKey),
        otxAPIKey: scrubber.maskApiKey(config.blocking.otxAPIKey),
        virusTotalAPIKey: scrubber.maskApiKey(config.blocking.virusTotalAPIKey),
      });
      res.end(JSON.stringify({
        blocking: safeBlocking,
        security: config.security
      }));
      return;
    }

    // GET /api/admin/logs - Get recent logs
    if (url.pathname === '/api/admin/logs') {
      if (!checkAdminAuth(req)) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }

      const limit = parseInt(url.query.limit) || 100;
      const filter = url.query.filter || 'all';

      fs.readFile(config.logging.file, 'utf8', (err, data) => {
        if (err) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Failed to read logs' }));
          return;
        }

        let lines = data.trim().split('\n').filter(line => line.length > 0);

        // Apply filter
        if (filter === 'blocked') {
          lines = lines.filter(line => line.includes('BLOCKED'));
        } else if (filter === 'malicious') {
          lines = lines.filter(line =>
            line.includes('BLOCKED') ||
            line.includes('python-requests') ||
            line.includes('androxgh0st') ||
            line.includes('%3Cscript')
          );
        }

        // Get last N lines
        lines = lines.slice(-limit);

        const logs = lines.map(line => parseLogLine(scrubber.scrubLogEntry(line))).filter(Boolean);

        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store'
        });
        res.end(JSON.stringify({ logs, count: logs.length }));
      });
      return;
    }

    // GET /api/admin/unique-ips - Get unique IPs with details
    if (url.pathname === '/api/admin/unique-ips') {
      if (!checkAdminAuth(req)) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }

      fs.readFile(config.logging.file, 'utf8', async (err, data) => {
        if (err) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Failed to read logs' }));
          return;
        }

        const lines = data.trim().split('\n').filter(line => line.length > 0);
        const ipMap = {};

        lines.forEach(line => {
          const log = parseLogLine(line);
          if (!log || !log.IP) return;

          const displayIP = scrubber.scrubIP(log.IP);

          if (!ipMap[displayIP]) {
            ipMap[displayIP] = { requests: [], firstSeen: log.timestamp, lastSeen: log.timestamp };
          }

          ipMap[displayIP].lastSeen = log.timestamp;
          ipMap[displayIP].requests.push({
            timestamp: log.timestamp,
            method: log.Method || '',
            url: log.URL || '',
            host: log.HOST || log.Host || '',
            ua: scrubber.scrubUserAgent(log.UA || ''),
            status: log.STATUS || '',
            reason: log.REASON || ''
          });
        });

        const ipAddresses = Object.keys(ipMap);

        // Skip reverse DNS when scrubbing is enabled (hashed/truncated IPs can't be resolved)
        let dnsResults;
        if (scrubber.isEnabled()) {
          dnsResults = ipAddresses.map(() => ({ status: 'fulfilled', value: [] }));
        } else {
          dnsResults = await Promise.allSettled(
            ipAddresses.map(ip => dns.promises.reverse(ip).catch(() => []))
          );
        }

        const ips = ipAddresses.map((ip, i) => {
          const info = ipMap[ip];
          const hostnames = dnsResults[i].status === 'fulfilled' ? dnsResults[i].value : [];
          const hosts = [...new Set(info.requests.map(r => r.host).filter(Boolean))];
          return {
            ip,
            reverseDns: hostnames,
            hostHeaders: hosts,
            requestCount: info.requests.length,
            firstSeen: info.firstSeen,
            lastSeen: info.lastSeen,
            requests: info.requests
          };
        });

        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store'
        });
        res.end(JSON.stringify({ ips, count: ips.length }));
      });
      return;
    }

    // GET /api/admin/stats - Get statistics
    if (url.pathname === '/api/admin/stats') {
      if (!checkAdminAuth(req)) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }

      const requestedRange = url.query.range;
      const range = Object.prototype.hasOwnProperty.call(STATS_RANGES, requestedRange)
        ? requestedRange
        : '24h';

      // Cap bytes read per range so short ranges don't scan the whole log.
      const MAX_BYTES = {
        '1h':  256 * 1024,
        '24h':   2 * 1024 * 1024,
        '7d':   16 * 1024 * 1024,
        'all': Infinity
      };
      const maxBytes = MAX_BYTES[range];

      const handleData = data => {
        const lines = data.split('\n').filter(line => line.length > 0);
        const stats = calculateStats(lines, range);

        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store'
        });
        res.end(JSON.stringify(stats));
      };

      const handleErr = () => {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Failed to read logs' }));
      };

      fs.stat(config.logging.file, (statErr, st) => {
        if (statErr) return handleErr();

        if (st.size <= maxBytes) {
          fs.readFile(config.logging.file, 'utf8', (err, data) => {
            if (err) return handleErr();
            handleData(data);
          });
          return;
        }

        // Tail-read the last maxBytes, then drop the first (partial) line.
        const stream = fs.createReadStream(config.logging.file, {
          start: st.size - maxBytes,
          encoding: 'utf8'
        });
        let buf = '';
        stream.on('data', chunk => { buf += chunk; });
        stream.on('error', handleErr);
        stream.on('end', () => {
          const nl = buf.indexOf('\n');
          handleData(nl === -1 ? '' : buf.slice(nl + 1));
        });
      });
      return;
    }

    // GET /api/admin/threat-intel/:ip - Get threat intelligence for an IP
    if (url.pathname.startsWith('/api/admin/threat-intel/')) {
      if (!checkAdminAuth(req)) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }

      const ip = url.pathname.split('/').pop();

      if (scrubber.isEnabled()) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Threat intel lookups are disabled when data scrubbing is active' }));
        return;
      }

      // Validate IP format
      if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid IP address format' }));
        return;
      }

      // Import threat intel module and perform correlation
      const threatIntel = require('./lib/threat-intel');
      
      threatIntel.correlateIP(ip)
        .then(result => {
          res.writeHead(200, {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store'
          });
          res.end(JSON.stringify(result));
        })
        .catch(error => {
          console.error('[ADMIN] Threat intel error:', error);
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Failed to query threat intelligence' }));
        });
      return;
    }
  }

  // Handle POST requests for admin API
  if (method === 'POST' && url.pathname === '/api/admin/config') {
    if (!checkAdminAuth(req)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }

    handleRequestWithBody(req, async (err, body) => {
      if (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Bad Request' }));
        return;
      }

      try {
        const updates = JSON.parse(body);

        // Update config object (in-memory)
        if (updates.blocking) {
          Object.assign(config.blocking, updates.blocking);
        }
        if (updates.security) {
          Object.assign(config.security, updates.security);
        }

        console.log('[ADMIN] Configuration updated:', updates);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: true,
          message: 'Configuration updated successfully'
        }));
      } catch (error) {
        console.error('[ADMIN] Config update error:', error);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON' }));
      }
    });
    return;
  }

  // POST /api/admin/blacklist/add - Add IP to blacklist
  if (method === 'POST' && url.pathname === '/api/admin/blacklist/add') {
    if (!checkAdminAuth(req)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }

    handleRequestWithBody(req, async (err, body) => {
      if (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Bad Request' }));
        return;
      }

      try {
        const { ip } = JSON.parse(body);

        // Validate IP format
        if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid IP address format' }));
          return;
        }

        // Add to blacklist if not already present
        if (!config.blocking.blockedIPs.includes(ip)) {
          config.blocking.blockedIPs.push(ip);
          console.log(`[ADMIN] IP added to blacklist: ${ip}`);
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: true,
          message: `IP ${ip} added to blacklist`,
          blockedIPs: config.blocking.blockedIPs
        }));
      } catch (error) {
        console.error('[ADMIN] Blacklist add error:', error);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
    });
    return;
  }

  // POST /api/admin/whitelist/add - Add IP to whitelist
  if (method === 'POST' && url.pathname === '/api/admin/whitelist/add') {
    if (!checkAdminAuth(req)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }

    handleRequestWithBody(req, async (err, body) => {
      if (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Bad Request' }));
        return;
      }

      try {
        const { ip } = JSON.parse(body);

        // Validate IP format
        if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid IP address format' }));
          return;
        }

        // Add to whitelist if not already present
        if (!config.blocking.whitelistedIPs.includes(ip)) {
          config.blocking.whitelistedIPs.push(ip);
          console.log(`[ADMIN] IP added to whitelist: ${ip}`);
        }

        // Remove from blacklist if present
        const blacklistIndex = config.blocking.blockedIPs.indexOf(ip);
        if (blacklistIndex > -1) {
          config.blocking.blockedIPs.splice(blacklistIndex, 1);
          console.log(`[ADMIN] IP removed from blacklist: ${ip}`);
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: true,
          message: `IP ${ip} added to whitelist`,
          whitelistedIPs: config.blocking.whitelistedIPs
        }));
      } catch (error) {
        console.error('[ADMIN] Whitelist add error:', error);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
    });
    return;
  }

  // POST /api/admin/blacklist/remove - Remove IP from blacklist
  if (method === 'POST' && url.pathname === '/api/admin/blacklist/remove') {
    if (!checkAdminAuth(req)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }

    handleRequestWithBody(req, async (err, body) => {
      if (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Bad Request' }));
        return;
      }

      try {
        const { ip } = JSON.parse(body);

        const index = config.blocking.blockedIPs.indexOf(ip);
        if (index > -1) {
          config.blocking.blockedIPs.splice(index, 1);
          console.log(`[ADMIN] IP removed from blacklist: ${ip}`);
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: true,
          message: `IP ${ip} removed from blacklist`,
          blockedIPs: config.blocking.blockedIPs
        }));
      } catch (error) {
        console.error('[ADMIN] Blacklist remove error:', error);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
    });
    return;
  }

  // POST /api/admin/whitelist/remove - Remove IP from whitelist
  if (method === 'POST' && url.pathname === '/api/admin/whitelist/remove') {
    if (!checkAdminAuth(req)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }

    handleRequestWithBody(req, async (err, body) => {
      if (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Bad Request' }));
        return;
      }

      try {
        const { ip } = JSON.parse(body);

        const index = config.blocking.whitelistedIPs.indexOf(ip);
        if (index > -1) {
          config.blocking.whitelistedIPs.splice(index, 1);
          console.log(`[ADMIN] IP removed from whitelist: ${ip}`);
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: true,
          message: `IP ${ip} removed from whitelist`,
          whitelistedIPs: config.blocking.whitelistedIPs
        }));
      } catch (error) {
        console.error('[ADMIN] Whitelist remove error:', error);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
    });
    return;
  }

  // Define methods that can have request bodies
  const methodsWithBody = ['POST', 'PUT', 'PATCH', 'DELETE'];
  
  if (methodsWithBody.includes(method)) {
    // Handle methods that can have request bodies
    handleRequestWithBody(req, async (err, body) => {
      if (err) {
        console.error(`[${timestamp}] Error reading ${method} body:`, err);
        const statusCode = err.statusCode || 400;
        res.writeHead(statusCode, { 'Content-Type': 'text/plain' });
        res.end(statusCode === 413 ? 'Request entity too large' : 'Bad Request');
        return;
      }

      // Check blocking with body content
      const blockCheck = await shouldBlockRequest(req, clientIP, body);
      if (blockCheck.blocked) {
        if (config.blocking.mode === 'block') {
          // Log before blocking
          logRequestDetails(req, clientIP, timestamp, body);
          const logEntry = createLogEntry(req, clientIP, timestamp, body);
          fs.appendFile(config.logging.file, logEntry, (err) => {
            if (err) console.error('Error writing to log file:', err);
          });

          sendBlockedResponse(res, blockCheck.reason, clientIP, timestamp);
          return;
        } else {
          console.log(`[${timestamp}] ⚠️  WOULD BLOCK (log mode): ${blockCheck.reason}`);
        }
      }

      // Log request details
      logRequestDetails(req, clientIP, timestamp, body);

      // Create and write log entry
      const logEntry = createLogEntry(req, clientIP, timestamp, body);
      fs.appendFile(config.logging.file, logEntry, (err) => {
        if (err) console.error('Error writing to log file:', err);
      });

      // Send response
      sendResponse(res, req, clientIP, timestamp, body);
    });
  } else {
    // Handle methods without request bodies (GET, HEAD, OPTIONS, TRACE, CONNECT, etc.)
    logRequestDetails(req, clientIP, timestamp);
    
    // Create and write log entry
    const logEntry = createLogEntry(req, clientIP, timestamp);
    fs.appendFile(config.logging.file, logEntry, (err) => {
      if (err) console.error('Error writing to log file:', err);
    });
    
    // Send response
    sendResponse(res, req, clientIP, timestamp);
  }
}

// Create server based on SSL availability
let server;
if (useHttps && options) {
  server = https.createServer(options, handleRequest);
  
  // Enhanced SSL error handling for HTTPS server
  server.on('tlsClientError', (error, tlsSocket) => {
    console.error('TLS Client Error (expected for HTTP to HTTPS):', error.message);
    // Don't log these as critical errors - they're expected when HTTP hits HTTPS port
  });
} else {
  server = http.createServer(handleRequest);
}

// CRITICAL: Configure timeouts for Cloudflare compatibility
server.keepAliveTimeout = 61 * 1000;  // 61 seconds (longer than Cloudflare's 60s)
server.headersTimeout = 65 * 1000;    // Must be > keepAliveTimeout
server.requestTimeout = 120 * 1000;   // 2 minutes for long requests
server.timeout = 120 * 1000;          // Overall server timeout

// Configure socket-level keep-alive
server.on('connection', (socket) => {
  socket.setKeepAlive(true, 60000);
  socket.setTimeout(120000);
});

// Enhanced error handling
server.on('error', (error) => {
  console.error('Server error:', error);
  if (error.code === 'EADDRINUSE') {
    console.error(`Port ${useHttps ? config.server.port : (config.server.port === 443 ? 80 : config.server.port)} already in use`);
    process.exit(1);
  }
});

server.on('clientError', (error, socket) => {
  console.error('Client error:', error.message);
  if (socket.writable) {
    socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  }
});

// Graceful shutdown handling
process.on('SIGTERM', () => {
  console.log('Shutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
  
  setTimeout(() => {
    console.error('Forced shutdown');
    process.exit(1);
  }, 30000);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught exception:', error);
  server.close(() => process.exit(1));
  setTimeout(() => process.exit(1), 10000);
});

// HTTP Redirect Server to eliminate SSL errors
const httpServer = http.createServer((req, res) => {
  const timestamp = new Date().toISOString();
  const clientIP = getClientIP(req);
  const hostname = req.headers.host || 'localhost';
  
  // Log HTTP request for tracking
  console.log(`[${timestamp}] HTTP->HTTPS redirect for IP: ${scrubber.scrubIP(clientIP)}`);
  console.log(`[${timestamp}] Original HTTP URL: http://${hostname}${req.url}`);

  // Create log entry for HTTP redirect
  const logEntry = `${timestamp} | IP: ${scrubber.scrubIP(clientIP)} | Method: HTTP-REDIRECT | Host: ${hostname} | URL: ${req.url} | UA: ${scrubber.scrubUserAgent(req.headers['user-agent'] || 'unknown')} | Redirected to HTTPS\n`;
  fs.appendFile(config.logging.file, logEntry, (err) => {
    if (err) console.error('Error writing redirect log:', err);
  });
  
  // Handle specific routes for HTTP
  const url = parse(req.url, true);
  
  // For root path, redirect to HTTPS landing page
  if (url.pathname === '/' || url.pathname === '/index.html') {
    res.writeHead(301, {
      'Location': `https://${hostname}${req.url}`,
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0'
    });
    res.end(`HTTP to HTTPS Redirect\nRedirecting to: https://${hostname}${req.url}`);
    return;
  }
  
  // For API endpoints, redirect to HTTPS
  if (url.pathname.startsWith('/api/')) {
    res.writeHead(301, {
      'Location': `https://${hostname}${req.url}`,
      'Content-Type': 'application/json',
      'Cache-Control': 'no-cache, no-store, must-revalidate'
    });
    res.end(JSON.stringify({
      status: 'redirect',
      message: 'API only available via HTTPS',
      redirect: `https://${hostname}${req.url}`
    }));
    return;
  }
  
  // For all other requests, provide a helpful message and redirect
  res.writeHead(301, {
    'Location': `https://${hostname}${req.url}`,
    'Content-Type': 'text/plain',
    'Cache-Control': 'no-cache, no-store, must-revalidate',
    'Server': 'HTTP-Redirect-Server/1.0'
  });
  
  const redirectMessage = `HTTP Request Captured and Redirected!\n\n` +
    `Original HTTP URL: http://${hostname}${req.url}\n` +
    `Redirecting to HTTPS: https://${hostname}${req.url}\n\n` +
    `Client IP: ${scrubber.scrubIP(clientIP)}\n` +
    `Timestamp: ${timestamp}\n` +
    `Method: ${req.method}\n` +
    `User-Agent: ${scrubber.scrubUserAgent(req.headers['user-agent'] || 'unknown')}\n\n` +
    `Note: This server requires HTTPS for security. You are being redirected automatically.`;
  
  res.end(redirectMessage);
});

// Enhanced error handling for HTTP server
httpServer.on('error', (error) => {
  console.error('HTTP redirect server error:', error);
  if (error.code === 'EADDRINUSE') {
    console.error('Port 80 already in use - HTTP redirect server not started');
  }
});

httpServer.on('clientError', (error, socket) => {
  console.error('HTTP redirect client error:', error.message);
  if (socket.writable) {
    socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  }
});

// Enhanced SSL error handling for HTTPS server
server.on('tlsClientError', (error, tlsSocket) => {
  console.error('TLS Client Error (expected for HTTP to HTTPS):', error.message);
  // Don't log these as critical errors - they're expected when HTTP hits HTTPS port
});

// Start servers based on mode
if (useHttps) {
  // Production mode with HTTPS
  
  // Start HTTP redirect server on port 80
  httpServer.listen(config.server.httpPort, config.server.bindAddress, () => {
    console.log(`HTTP redirect server listening on port ${config.server.httpPort}`);
    console.log('HTTP traffic will be redirected to HTTPS');
  });

  // Start HTTPS server on configured port
  server.listen(config.server.httpsPort, config.server.bindAddress, () => {
    console.log(`HTTPS server listening on port ${config.server.httpsPort}`);
    console.log('Universal HTTP method support enabled');
    console.log('Configured for Cloudflare compatibility');
    console.log('Supported methods: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, CONNECT, TRACE');
    console.log('Fingerprinting landing page available at: /');
    console.log('Fingerprinting API available at: /api/fingerprint');
  });
} else {
  // Development mode without SSL
  const devPort = config.server.port;
  
  server.listen(devPort, config.server.bindAddress, () => {
    console.log(`Development HTTP server listening on port ${devPort}`);
    console.log('Running in development mode (no SSL)');
    console.log('Universal HTTP method support enabled');
    console.log('Supported methods: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, CONNECT, TRACE');
    console.log(`Fingerprinting landing page available at: http://localhost:${devPort}/`);
    console.log(`Fingerprinting API available at: http://localhost:${devPort}/api/fingerprint`);
    console.log('');
    console.log('Note: This eliminates SSL errors by running in HTTP mode for development.');
  });
}
