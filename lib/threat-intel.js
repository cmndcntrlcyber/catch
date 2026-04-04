// Threat Intelligence Integration Library
// Integrates AbuseIPDB, AlienVault OTX, and VirusTotal APIs

const axios = require('axios');
const NodeCache = require('node-cache');
const { config } = require('../config');

// Cache for threat intelligence results (TTL from config)
const threatCache = new NodeCache({ stdTTL: config.blocking.threatIntelCacheTTL });

/**
 * Check IP reputation using AbuseIPDB
 * @param {string} ip - IP address to check
 * @returns {Promise<Object>} AbuseIPDB results
 */
async function checkAbuseIPDB(ip) {
  if (!config.blocking.abuseIPDBKey) {
    return { available: false, error: 'No API key configured' };
  }

  const cacheKey = `abuseipdb:${ip}`;
  const cached = threatCache.get(cacheKey);
  if (cached) return cached;

  try {
    const response = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      params: { ipAddress: ip, maxAgeInDays: 90 },
      headers: {
        'Key': config.blocking.abuseIPDBKey,
        'Accept': 'application/json'
      },
      timeout: 5000
    });

    const result = {
      available: true,
      score: response.data.data.abuseConfidenceScore || 0,
      reports: response.data.data.totalReports || 0,
      country: response.data.data.countryCode || 'Unknown',
      isp: response.data.data.isp || 'Unknown',
      usageType: response.data.data.usageType || 'Unknown',
      isWhitelisted: response.data.data.isWhitelisted || false,
      lastReportedAt: response.data.data.lastReportedAt || null
    };

    threatCache.set(cacheKey, result);
    return result;
  } catch (error) {
    console.error('AbuseIPDB API error:', error.message);
    return {
      available: false,
      error: error.message,
      score: 0,
      reports: 0
    };
  }
}

/**
 * Check IP reputation using AlienVault OTX
 * @param {string} ip - IP address to check
 * @returns {Promise<Object>} OTX results
 */
async function checkOTX(ip) {
  if (!config.blocking.otxAPIKey) {
    return { available: false, error: 'No API key configured' };
  }

  const cacheKey = `otx:${ip}`;
  const cached = threatCache.get(cacheKey);
  if (cached) return cached;

  try {
    // Get general IP info
    const generalResponse = await axios.get(`https://otx.alienvault.com/api/v1/indicators/IPv4/${ip}/general`, {
      headers: { 'X-OTX-API-KEY': config.blocking.otxAPIKey },
      timeout: 5000
    });

    // Get reputation data
    const reputationResponse = await axios.get(`https://otx.alienvault.com/api/v1/indicators/IPv4/${ip}/reputation`, {
      headers: { 'X-OTX-API-KEY': config.blocking.otxAPIKey },
      timeout: 5000
    });

    const pulseCount = generalResponse.data.pulse_info?.count || 0;
    const pulses = generalResponse.data.pulse_info?.pulses || [];
    const reputation = reputationResponse.data.reputation || null;

    // Extract tags from pulses
    const tags = new Set();
    pulses.forEach(pulse => {
      if (pulse.tags) pulse.tags.forEach(tag => tags.add(tag));
    });

    const result = {
      available: true,
      pulseCount: pulseCount,
      reputation: reputation,
      tags: Array.from(tags),
      pulses: pulses.slice(0, 5).map(p => ({
        name: p.name,
        created: p.created,
        tags: p.tags || []
      })),
      threatScore: pulseCount > 10 ? 100 : pulseCount > 5 ? 75 : pulseCount > 0 ? 50 : 0
    };

    threatCache.set(cacheKey, result);
    return result;
  } catch (error) {
    console.error('OTX API error:', error.message);
    return {
      available: false,
      error: error.message,
      pulseCount: 0,
      tags: [],
      threatScore: 0
    };
  }
}

/**
 * Check IP reputation using VirusTotal
 * @param {string} ip - IP address to check
 * @returns {Promise<Object>} VirusTotal results
 */
async function checkVirusTotal(ip) {
  if (!config.blocking.virusTotalAPIKey) {
    return { available: false, error: 'No API key configured' };
  }

  const cacheKey = `virustotal:${ip}`;
  const cached = threatCache.get(cacheKey);
  if (cached) return cached;

  try {
    const response = await axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
      headers: {
        'x-apikey': config.blocking.virusTotalAPIKey,
        'Accept': 'application/json'
      },
      timeout: 5000
    });

    const data = response.data.data;
    const attributes = data.attributes;

    // Count malicious detections
    const lastAnalysisStats = attributes.last_analysis_stats || {};
    const malicious = lastAnalysisStats.malicious || 0;
    const suspicious = lastAnalysisStats.suspicious || 0;
    const harmless = lastAnalysisStats.harmless || 0;
    const undetected = lastAnalysisStats.undetected || 0;

    // Calculate threat score based on detections
    const totalEngines = malicious + suspicious + harmless + undetected;
    const threatScore = totalEngines > 0 ? Math.round(((malicious + suspicious * 0.5) / totalEngines) * 100) : 0;

    const result = {
      available: true,
      malicious: malicious,
      suspicious: suspicious,
      harmless: harmless,
      undetected: undetected,
      threatScore: threatScore,
      country: attributes.country || 'Unknown',
      asOwner: attributes.as_owner || 'Unknown',
      asn: attributes.asn || null,
      categories: Object.keys(attributes.categories || {})
    };

    threatCache.set(cacheKey, result);
    return result;
  } catch (error) {
    console.error('VirusTotal API error:', error.message);
    return {
      available: false,
      error: error.message,
      malicious: 0,
      suspicious: 0,
      threatScore: 0
    };
  }
}

/**
 * Perform comprehensive IOC correlation across all threat intelligence sources
 * @param {string} ip - IP address to analyze
 * @returns {Promise<Object>} Correlation results
 */
async function correlateIP(ip) {
  console.log(`[Threat Intel] Correlating IP: ${ip}`);

  // Query all sources in parallel
  const [abuseDB, otx, virusTotal] = await Promise.all([
    checkAbuseIPDB(ip),
    checkOTX(ip),
    checkVirusTotal(ip)
  ]);

  // Calculate combined threat score (weighted average)
  let combinedScore = 0;
  let sourceCount = 0;

  if (abuseDB.available && abuseDB.score !== undefined) {
    combinedScore += abuseDB.score;
    sourceCount++;
  }

  if (otx.available && otx.threatScore !== undefined) {
    combinedScore += otx.threatScore;
    sourceCount++;
  }

  if (virusTotal.available && virusTotal.threatScore !== undefined) {
    combinedScore += virusTotal.threatScore;
    sourceCount++;
  }

  const avgScore = sourceCount > 0 ? Math.round(combinedScore / sourceCount) : 0;

  // Determine recommendation based on combined score
  let recommendation = 'SAFE';
  if (avgScore >= config.blocking.autoBlacklistThreshold) {
    recommendation = 'BLACKLIST';
  } else if (avgScore >= 50) {
    recommendation = 'MONITOR';
  }

  // Collect all tags and categories
  const allTags = new Set();
  if (otx.tags) otx.tags.forEach(tag => allTags.add(tag));
  if (virusTotal.categories) virusTotal.categories.forEach(cat => allTags.add(cat));

  const result = {
    ip: ip,
    timestamp: new Date().toISOString(),
    combinedThreatScore: avgScore,
    recommendation: recommendation,
    sources: {
      abuseipdb: abuseDB,
      otx: otx,
      virustotal: virusTotal
    },
    summary: {
      totalSources: sourceCount,
      availableSources: sourceCount,
      tags: Array.from(allTags),
      country: abuseDB.country || virusTotal.country || 'Unknown',
      isp: abuseDB.isp || virusTotal.asOwner || 'Unknown'
    }
  };

  console.log(`[Threat Intel] IP ${ip} - Score: ${avgScore}, Recommendation: ${recommendation}`);
  return result;
}

/**
 * Clear threat intelligence cache
 */
function clearCache() {
  threatCache.flushAll();
  console.log('[Threat Intel] Cache cleared');
}

/**
 * Get cache statistics
 * @returns {Object} Cache stats
 */
function getCacheStats() {
  return threatCache.getStats();
}

module.exports = {
  checkAbuseIPDB,
  checkOTX,
  checkVirusTotal,
  correlateIP,
  clearCache,
  getCacheStats
};
