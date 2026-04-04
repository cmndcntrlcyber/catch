// Universal Web Security Framework Configuration Manager
// Handles environment variables and configuration settings

require('dotenv').config();

/**
 * Configuration object that combines environment variables with sensible defaults
 */
const config = {
  // Server Configuration
  server: {
    port: process.env.PORT || (process.env.NODE_ENV === 'production' ? 443 : 8443),
    httpsPort: parseInt(process.env.HTTPS_PORT) || 443,
    httpPort: parseInt(process.env.HTTP_PORT) || 80,
    bindAddress: process.env.BIND_ADDRESS || '0.0.0.0',
    environment: process.env.NODE_ENV || 'development'
  },

  // SSL/TLS Configuration
  ssl: {
    keyPath: process.env.SSL_KEY_PATH || '/etc/letsencrypt/live/catch.attck-deploy.net/privkey.pem',
    certPath: process.env.SSL_CERT_PATH || '/etc/letsencrypt/live/catch.attck-deploy.net/fullchain.pem',
    useHttps: process.env.USE_HTTPS === 'true' || process.env.NODE_ENV === 'production',
    forceHttps: process.env.FORCE_HTTPS === 'true' || process.env.NODE_ENV === 'production'
  },

  // Application Configuration
  app: {
    baseUrl: process.env.BASE_URL || `http://localhost:${process.env.PORT || 8080}`,
    apiEndpoint: process.env.API_ENDPOINT || '/api/fingerprint',
    exfilEndpoint: process.env.EXFIL_ENDPOINT || '/exfil',
    exfilFrameEndpoint: process.env.EXFIL_FRAME_ENDPOINT || '/exfil-frame',
    staticPath: process.env.STATIC_PATH || '/js/',
    healthCheckEndpoint: process.env.HEALTH_CHECK_ENDPOINT || '/health',
    metricsEndpoint: process.env.METRICS_ENDPOINT || '/metrics'
  },

  // Security Configuration
  security: {
    cors: {
      origin: process.env.CORS_ORIGIN || '*',
      methods: process.env.CORS_METHODS || 'GET,POST,PUT,PATCH,DELETE,HEAD,OPTIONS,CONNECT,TRACE',
      headers: process.env.CORS_HEADERS || 'Content-Type,Origin,Referer,Authorization,X-Requested-With,Accept,Accept-Language,Accept-Encoding'
    },
    rateLimit: {
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
      maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100
    },
    headers: {
      hstsMaxAge: parseInt(process.env.HSTS_MAX_AGE) || 31536000,
      xFrameOptions: process.env.X_FRAME_OPTIONS || 'DENY',
      xContentTypeOptions: process.env.X_CONTENT_TYPE_OPTIONS || 'nosniff',
      referrerPolicy: process.env.REFERRER_POLICY || 'strict-origin-when-cross-origin'
    }
  },

  // Request Blocking Configuration
  blocking: {
    enabled: process.env.ENABLE_BLOCKING === 'true',
    mode: process.env.BLOCKING_MODE || 'log', // 'log' or 'block'
    responseCode: parseInt(process.env.BLOCKING_RESPONSE_CODE) || 403,

    // IP blocklist
    blockedIPs: (process.env.BLOCKED_IPS || '').split(',').filter(Boolean),
    blockedCIDRs: (process.env.BLOCKED_CIDR_RANGES || '').split(',').filter(Boolean),

    // User-Agent patterns (regex strings)
    blockedUserAgents: (process.env.BLOCKED_USER_AGENTS ||
      'python-requests,python-httpx,Go-http-client,masscan').split(',').filter(Boolean),

    // URL patterns (regex strings)
    blockedUrlPatterns: (process.env.BLOCKED_URL_PATTERNS ||
      '%3Cscript,%3Ciframe,<script,<iframe,0x%5B%5D,\\.\\./,/\\.env,/\\.git').split(',').filter(Boolean),

    // POST body patterns (regex strings)
    blockedBodyPatterns: (process.env.BLOCKED_BODY_PATTERNS ||
      'androxgh0st,c99shell,r57shell,phpinfo\\(\\)').split(',').filter(Boolean),

    // Rate limiting
    rateLimitEnabled: process.env.ENABLE_RATE_LIMITING === 'true',

    // Auto-blocking
    autoBlockAfterViolations: parseInt(process.env.AUTO_BLOCK_AFTER_VIOLATIONS) || 5,
    autoBlockDuration: parseInt(process.env.AUTO_BLOCK_DURATION) || 3600000, // 1 hour

    // Whitelist
    whitelistEnabled: process.env.ENABLE_WHITELIST === 'true',
    whitelistedIPs: (process.env.WHITELISTED_IPS || '').split(',').filter(Boolean),
    whitelistedCIDRs: (process.env.WHITELISTED_CIDR_RANGES || '').split(',').filter(Boolean),
    whitelistedUserAgents: (process.env.WHITELISTED_USER_AGENTS || '').split(',').filter(Boolean),

    // GeoIP blocking
    geoIPEnabled: process.env.ENABLE_GEOIP_BLOCKING === 'true',
    blockedCountries: (process.env.BLOCKED_COUNTRIES || '').split(',').filter(Boolean),
    allowedCountries: (process.env.ALLOWED_COUNTRIES || '').split(',').filter(Boolean),
    blockUnknownCountries: process.env.BLOCK_UNKNOWN_COUNTRIES === 'true',

    // Threat intelligence
    threatFeedsEnabled: process.env.ENABLE_THREAT_FEEDS === 'true',
    abuseIPDBKey: process.env.ABUSEIPDB_API_KEY || '',
    otxAPIKey: process.env.OTX_API_KEY || '',
    virusTotalAPIKey: process.env.VIRUSTOTAL_API_KEY || '',
    threatScoreThreshold: parseInt(process.env.THREAT_SCORE_THRESHOLD) || 75,
    
    // IOC Correlation
    iocCorrelationEnabled: process.env.ENABLE_IOC_CORRELATION === 'true',
    autoBlacklistThreshold: parseInt(process.env.AUTO_BLACKLIST_THRESHOLD) || 85,
    threatIntelCacheTTL: parseInt(process.env.THREAT_INTEL_CACHE_TTL) || 3600
  },

  // Logging Configuration
  logging: {
    file: process.env.LOG_FILE || 'access.log',
    level: process.env.LOG_LEVEL || 'info',
    rotation: process.env.LOG_ROTATION === 'true',
    maxSize: parseInt(process.env.MAX_LOG_SIZE) || 100, // MB
    maxFiles: parseInt(process.env.MAX_LOG_FILES) || 5
  },

  // Data Collection Configuration
  dataCollection: {
    maxBodySize: parseInt(process.env.MAX_BODY_SIZE) || 10 * 1024 * 1024, // 10MB
    retentionDays: parseInt(process.env.DATA_RETENTION_DAYS) || 30,
    enableImageBeacon: process.env.ENABLE_IMAGE_BEACON !== 'false',
    enableFetchApi: process.env.ENABLE_FETCH_API !== 'false',
    enableXhrMethod: process.env.ENABLE_XHR_METHOD !== 'false',
    enableIframeMethod: process.env.ENABLE_IFRAME_METHOD !== 'false'
  },

  // Development Configuration
  development: {
    debug: process.env.DEBUG === 'true',
    reload: process.env.DEV_RELOAD !== 'false',
    mockSsl: process.env.MOCK_SSL === 'true'
  },

  // Deployment Configuration
  deployment: {
    pm2Instances: parseInt(process.env.PM2_INSTANCES) || 1,
    pm2MaxMemory: process.env.PM2_MAX_MEMORY || '512M',
    containerPort: parseInt(process.env.CONTAINER_PORT) || 3000,
    containerHealthCheck: process.env.CONTAINER_HEALTH_CHECK !== 'false'
  }
};

/**
 * Get configuration value with dot notation support
 * @param {string} path - Dot notation path to configuration value
 * @param {*} defaultValue - Default value if path is not found
 * @returns {*} Configuration value
 */
function get(path, defaultValue = undefined) {
  const keys = path.split('.');
  let value = config;
  
  for (const key of keys) {
    if (value && typeof value === 'object' && key in value) {
      value = value[key];
    } else {
      return defaultValue;
    }
  }
  
  return value;
}

/**
 * Check if running in development mode
 * @returns {boolean} True if in development mode
 */
function isDevelopment() {
  return config.server.environment === 'development';
}

/**
 * Check if running in production mode
 * @returns {boolean} True if in production mode
 */
function isProduction() {
  return config.server.environment === 'production';
}

/**
 * Check if HTTPS should be used
 * @returns {boolean} True if HTTPS should be used
 */
function shouldUseHttps() {
  return config.ssl.useHttps && !isDevelopment();
}

/**
 * Get the base URL for the application
 * @returns {string} Base URL
 */
function getBaseUrl() {
  if (config.app.baseUrl && config.app.baseUrl !== 'AUTO') {
    return config.app.baseUrl;
  }
  
  const protocol = shouldUseHttps() ? 'https' : 'http';
  const port = shouldUseHttps() ? config.server.httpsPort : config.server.port;
  const defaultPort = shouldUseHttps() ? 443 : 80;
  
  let url = `${protocol}://localhost`;
  if (port && port !== defaultPort) {
    url += `:${port}`;
  }
  
  return url;
}

/**
 * Get full URL for an endpoint
 * @param {string} endpoint - Endpoint path
 * @returns {string} Full URL
 */
function getEndpointUrl(endpoint) {
  const baseUrl = getBaseUrl();
  return baseUrl + (endpoint.startsWith('/') ? endpoint : '/' + endpoint);
}

/**
 * Validate configuration and throw errors for critical missing values
 */
function validate() {
  const errors = [];
  
  // Check SSL configuration in production
  if (isProduction() && shouldUseHttps()) {
    if (!config.ssl.keyPath || !config.ssl.certPath) {
      errors.push('SSL certificate paths are required in production mode');
    }
  }
  
  // Check required ports
  if (!config.server.port) {
    errors.push('Server port is required');
  }
  
  if (errors.length > 0) {
    throw new Error('Configuration validation failed:\n' + errors.join('\n'));
  }
}

/**
 * Print current configuration (excluding sensitive values)
 */
function printConfig() {
  const safeLogs = {
    environment: config.server.environment,
    port: config.server.port,
    httpsEnabled: shouldUseHttps(),
    baseUrl: getBaseUrl(),
    apiEndpoint: config.app.apiEndpoint,
    logLevel: config.logging.level,
    debug: config.development.debug
  };
  
  console.log('Current Configuration:');
  console.log(JSON.stringify(safeLogs, null, 2));
}

// Export configuration and utility functions
module.exports = {
  config,
  get,
  isDevelopment,
  isProduction,
  shouldUseHttps,
  getBaseUrl,
  getEndpointUrl,
  validate,
  printConfig
};

// Auto-validate configuration on require
try {
  validate();
} catch (error) {
  console.error('Configuration Error:', error.message);
  if (isProduction()) {
    process.exit(1);
  }
}
