#!/usr/bin/env node

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { parse } = require('url');
const { config, getBaseUrl, getEndpointUrl, isDevelopment, isProduction, shouldUseHttps } = require('./config');

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
  
  let logEntry = `${timestamp} | IP: ${clientIP} | Method: ${method} | Host: ${hostname} | URL: ${req.url}`;
  logEntry += ` | UA: ${userAgent}`;
  
  if (contentType) logEntry += ` | Content-Type: ${contentType}`;
  if (referer) logEntry += ` | Referer: ${referer}`;
  if (origin) logEntry += ` | Origin: ${origin}`;
  if (body.length > 0) {
    logEntry += ` | Body: ${body.substring(0, 500)}${body.length > 500 ? '...[truncated]' : ''}`;
  }
  logEntry += '\n';
  
  return logEntry;
}

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
      res.writeHead(200, { 
        'Content-Type': contentType,
        'Cache-Control': 'public, max-age=3600'
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
      clientIP: clientIP,
      userAgent: req.headers['user-agent'] || 'unknown',
      acceptLanguage: req.headers['accept-language'] || 'unknown',
      acceptEncoding: req.headers['accept-encoding'] || 'unknown',
      connection: req.headers.connection || 'unknown',
      host: req.headers.host || 'unknown',
      referer: req.headers.referer || req.headers.referrer || '',
      origin: req.headers.origin || '',
      xForwardedFor: req.headers['x-forwarded-for'] || '',
      xRealIP: req.headers['x-real-ip'] || '',
      cfConnectingIP: req.headers['cf-connecting-ip'] || '',
      cfRay: req.headers['cf-ray'] || '',
      cfIPCountry: req.headers['cf-ipcountry'] || '',
      dnt: req.headers.dnt || '',
      upgradeInsecureRequests: req.headers['upgrade-insecure-requests'] || '',
      secFetchDest: req.headers['sec-fetch-dest'] || '',
      secFetchMode: req.headers['sec-fetch-mode'] || '',
      secFetchSite: req.headers['sec-fetch-site'] || '',
      allHeaders: req.headers
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
  
  console.log(`[${timestamp}] ${method} request from IP: ${clientIP}`);
  console.log(`[${timestamp}] Host domain: ${hostname}`);
  console.log(`[${timestamp}] URL: ${req.url}`);
  console.log(`[${timestamp}] User-Agent: ${userAgent}`);
  
  if (contentType) console.log(`[${timestamp}] Content-Type: ${contentType}`);
  if (referer) console.log(`[${timestamp}] Referer: ${referer}`);
  if (origin) console.log(`[${timestamp}] Origin: ${origin}`);
  
  const { query } = parse(req.url, true);
  if (Object.keys(query).length > 0) {
    console.log(`[${timestamp}] Query parameters:`, query);
  }
  
  if (body.length > 0) {
    console.log(`[${timestamp}] ${method} body length: ${body.length} bytes`);
    console.log(`[${timestamp}] ${method} body content:`, body.substring(0, 1000) + (body.length > 1000 ? '...[truncated]' : ''));
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
  responseText += `Client IP: ${clientIP}\n`;
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
        responseText += `${method} Data Preview: ${body.substring(0, 200)}${body.length > 200 ? '...[truncated]' : ''}\n`;
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
function handleRequest(req, res) {
  const timestamp = new Date().toISOString();
  const clientIP = getClientIP(req);
  const method = req.method;
  const url = parse(req.url, true);
  
  // Route handling for GET requests
  if (method === 'GET') {
    // Serve fingerprinting landing page
    if (url.pathname === '/' || url.pathname === '/index.html') {
      logRequestDetails(req, clientIP, timestamp);
      const logEntry = createLogEntry(req, clientIP, timestamp);
      fs.appendFile(config.logging.file, logEntry, (err) => {
        if (err) console.error('Error writing to log file:', err);
      });
      serveStaticFile(req, res, path.join(__dirname, 'index.html'));
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
      const filePath = path.join(__dirname, url.pathname);
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
      const exfilData = url.query.data ? decodeURIComponent(url.query.data) : 'No data';
      
      console.log(`[${timestamp}] EXFILTRATION DATA RECEIVED:`, exfilData);
      
      const logEntry = `${timestamp} | IP: ${clientIP} | Method: EXFIL-BEACON | Host: ${req.headers.host || 'unknown'} | URL: ${req.url} | UA: ${req.headers['user-agent'] || 'unknown'} | EXFIL-DATA: ${exfilData.substring(0, 1000)}\n`;
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
      const exfilData = url.query.data ? decodeURIComponent(url.query.data) : 'No data';
      
      console.log(`[${timestamp}] EXFILTRATION DATA RECEIVED (IFRAME):`, exfilData);
      
      const logEntry = `${timestamp} | IP: ${clientIP} | Method: EXFIL-IFRAME | Host: ${req.headers.host || 'unknown'} | URL: ${req.url} | UA: ${req.headers['user-agent'] || 'unknown'} | EXFIL-DATA: ${exfilData.substring(0, 1000)}\n`;
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
  }
  
  // Define methods that can have request bodies
  const methodsWithBody = ['POST', 'PUT', 'PATCH', 'DELETE'];
  
  if (methodsWithBody.includes(method)) {
    // Handle methods that can have request bodies
    handleRequestWithBody(req, (err, body) => {
      if (err) {
        console.error(`[${timestamp}] Error reading ${method} body:`, err);
        const statusCode = err.statusCode || 400;
        res.writeHead(statusCode, { 'Content-Type': 'text/plain' });
        res.end(statusCode === 413 ? 'Request entity too large' : 'Bad Request');
        return;
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
    console.error(`Port ${useHttps ? config.server.port : (config.server.port === 443 ? 8080 : config.server.port)} already in use`);
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
  console.log(`[${timestamp}] HTTP->HTTPS redirect for IP: ${clientIP}`);
  console.log(`[${timestamp}] Original HTTP URL: http://${hostname}${req.url}`);
  
  // Create log entry for HTTP redirect
  const logEntry = `${timestamp} | IP: ${clientIP} | Method: HTTP-REDIRECT | Host: ${hostname} | URL: ${req.url} | UA: ${req.headers['user-agent'] || 'unknown'} | Redirected to HTTPS\n`;
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
    `Client IP: ${clientIP}\n` +
    `Timestamp: ${timestamp}\n` +
    `Method: ${req.method}\n` +
    `User-Agent: ${req.headers['user-agent'] || 'unknown'}\n\n` +
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
