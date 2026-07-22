const crypto = require('crypto');
const { config } = require('../config');

const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const CC_RE = /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7}\b/g;
const SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/g;
const JWT_RE = /eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}/g;
const PASSWORD_JSON_RE = /"(password|passwd|pass|pwd)"\s*:\s*"[^"]*"/gi;

const SENSITIVE_KEYS = new Set([
  'password', 'passwd', 'pass', 'pwd', 'secret', 'token', 'apikey', 'api_key',
  'authorization', 'cookie', 'cookies', 'session_data', 'credential',
  'credentials', 'access_token', 'refresh_token', 'private_key',
  'localstorage', 'sessionstorage', 'auth_tokens_in_dom', 'csrf_tokens',
  'jwt', 'session_id', 'sessionid'
]);

const IP_HEADERS = new Set(['x-forwarded-for', 'x-real-ip', 'cf-connecting-ip']);

const SENSITIVE_HEADERS = new Set([
  'cookie', 'authorization', 'x-csrf-token', 'x-admin-token',
  'set-cookie', 'proxy-authorization'
]);

function isEnabled() {
  return config.scrubbing && config.scrubbing.enabled;
}

function getLevel() {
  return (config.scrubbing && config.scrubbing.level) || 'partial';
}

function getSalt() {
  return (config.scrubbing && config.scrubbing.ipSalt) || 'default-salt';
}

function scrubIP(ip) {
  if (!isEnabled() || !ip) return ip;
  if (ip === 'unknown' || ip === '::1' || ip === '127.0.0.1') return '[localhost]';

  const level = getLevel();

  if (level === 'full') {
    const hmac = crypto.createHmac('sha256', getSalt());
    hmac.update(ip);
    return 'anon-' + hmac.digest('hex').substring(0, 16);
  }

  // partial: zero last octet for IPv4, last 80 bits for IPv6
  if (ip.includes('.')) {
    const parts = ip.split('.');
    if (parts.length === 4) {
      parts[3] = '0';
      return parts.join('.');
    }
  }

  if (ip.includes(':')) {
    const parts = ip.split(':');
    const zeroCount = Math.min(5, parts.length);
    for (let i = parts.length - zeroCount; i < parts.length; i++) {
      parts[i] = '0';
    }
    return parts.join(':');
  }

  return ip;
}

function scrubUserAgent(ua) {
  if (!isEnabled() || !ua || ua === 'unknown') return ua;

  const level = getLevel();

  if (level === 'full') return '[REDACTED]';

  // partial: keep browser family and OS, strip versions
  const browserMatch = ua.match(/(Chrome|Firefox|Safari|Edge|Opera|MSIE|Trident|curl|wget|python|Go-http-client|axios)/i);
  const osMatch = ua.match(/(Windows|Linux|Mac OS X|Android|iOS|iPhone|iPad)/i);

  const browser = browserMatch ? browserMatch[1] : 'Unknown';
  const os = osMatch ? osMatch[1] : 'Unknown OS';
  return `${browser}/*** (${os})`;
}

function scrubHeaders(headersObj) {
  if (!isEnabled() || !headersObj) return headersObj;

  const scrubbed = Object.assign({}, headersObj);

  for (const key of Object.keys(scrubbed)) {
    const lower = key.toLowerCase();
    if (SENSITIVE_HEADERS.has(lower)) {
      scrubbed[key] = '[REDACTED]';
    } else if (IP_HEADERS.has(lower)) {
      scrubbed[key] = scrubIP(scrubbed[key]);
    }
  }

  return scrubbed;
}

function scrubObjectKeys(obj) {
  if (!obj || typeof obj !== 'object') return obj;

  if (Array.isArray(obj)) {
    return obj.map(item => scrubObjectKeys(item));
  }

  const result = {};
  for (const [key, value] of Object.entries(obj)) {
    if (SENSITIVE_KEYS.has(key.toLowerCase())) {
      result[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      result[key] = scrubObjectKeys(value);
    } else if (typeof value === 'string') {
      result[key] = value
        .replace(EMAIL_RE, '[EMAIL-REDACTED]')
        .replace(SSN_RE, '[SSN-REDACTED]')
        .replace(CC_RE, '[CC-REDACTED]')
        .replace(JWT_RE, '[JWT-REDACTED]');
    } else {
      result[key] = value;
    }
  }
  return result;
}

function scrubBody(bodyStr) {
  if (!isEnabled() || !bodyStr || bodyStr.length === 0) return bodyStr;

  // Try JSON parse for key-based scrubbing
  try {
    const parsed = JSON.parse(bodyStr);
    if (typeof parsed === 'object' && parsed !== null) {
      return JSON.stringify(scrubObjectKeys(parsed));
    }
  } catch (_) {
    // not JSON, fall through to regex scrubbing
  }

  let scrubbed = bodyStr;
  scrubbed = scrubbed.replace(EMAIL_RE, '[EMAIL-REDACTED]');
  scrubbed = scrubbed.replace(CC_RE, '[CC-REDACTED]');
  scrubbed = scrubbed.replace(SSN_RE, '[SSN-REDACTED]');
  scrubbed = scrubbed.replace(JWT_RE, '[JWT-REDACTED]');
  scrubbed = scrubbed.replace(PASSWORD_JSON_RE, '"$1":"[REDACTED]"');

  return scrubbed;
}

function scrubExfilData(dataStr) {
  if (!isEnabled() || !dataStr) return dataStr;

  let decoded = dataStr;

  // Try base64 decode
  try {
    const buf = Buffer.from(dataStr, 'base64');
    const asString = buf.toString('utf8');
    if (/^[\x20-\x7E\s]+$/.test(asString)) {
      decoded = asString;
    }
  } catch (_) {}

  // Try URL decode
  try {
    decoded = decodeURIComponent(decoded);
  } catch (_) {}

  // Try JSON parse and key-scrub
  try {
    const parsed = JSON.parse(decoded);
    if (typeof parsed === 'object' && parsed !== null) {
      const scrubbed = scrubObjectKeys(parsed);
      return JSON.stringify(scrubbed);
    }
  } catch (_) {}

  // Fall back to regex scrubbing
  return scrubBody(decoded);
}

function scrubLogEntry(logLine) {
  if (!isEnabled() || !logLine || logLine.trim().length === 0) return logLine;

  let scrubbed = logLine;

  // Scrub IP field: | IP: <value> |
  scrubbed = scrubbed.replace(/\| IP: ([^\|]+?)(?=\s*\|)/g, (match, ip) => {
    return '| IP: ' + scrubIP(ip.trim());
  });

  // Scrub UA field: | UA: <value> |
  scrubbed = scrubbed.replace(/\| UA: ([^\|]+?)(?=\s*\||\s*$)/g, (match, ua) => {
    return '| UA: ' + scrubUserAgent(ua.trim());
  });

  // Scrub Body field: | Body: <value>
  scrubbed = scrubbed.replace(/\| Body: (.+?)(?=\s*\||\s*$)/g, (match, body) => {
    return '| Body: ' + scrubBody(body.trim());
  });

  // Scrub any emails or tokens that appear elsewhere in the line
  scrubbed = scrubbed.replace(EMAIL_RE, '[EMAIL-REDACTED]');
  scrubbed = scrubbed.replace(JWT_RE, '[JWT-REDACTED]');

  return scrubbed;
}

function maskApiKey(key) {
  if (!key || key.length < 8) return '[REDACTED]';
  return '****' + key.slice(-4);
}

module.exports = {
  isEnabled,
  scrubIP,
  scrubUserAgent,
  scrubHeaders,
  scrubBody,
  scrubExfilData,
  scrubLogEntry,
  scrubObjectKeys,
  maskApiKey
};
