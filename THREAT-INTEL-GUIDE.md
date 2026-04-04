# Threat Intelligence & IOC Correlation Guide

## Overview

The Catch Framework now includes comprehensive threat intelligence integration with:
- **AbuseIPDB** - IP reputation and abuse reports
- **AlienVault OTX** - Threat intelligence pulses and indicators
- **VirusTotal** - Malware detection and IP/domain reputation

This guide explains how to use the IOC correlation workflow and blacklist/whitelist management features.

---

## Features

### 1. Quick Blacklist/Whitelist Management

Each unique IP in the admin interface now has dedicated buttons for instant list management:

- **Add to Blacklist** - Block all future requests from this IP
- **Add to Whitelist** - Allow all requests from this IP (bypasses all blocking rules)

### 2. IOC Correlation Workflow

Analyze any IP address across three threat intelligence sources simultaneously to get:
- Combined threat score (0-100)
- Automated recommendations (SAFE, MONITOR, BLACKLIST)
- Detailed findings from each source
- Associated threat tags and categories

---

## Setup

### API Keys Configuration

The API keys are configured in your `.env` file:

```env
# Threat Intelligence APIs
OTX_API_KEY=3a2a041740da0337f520ed9a0f17fbf5ea0f3e8bfbbb7729492d139e176bb0f5
VIRUSTOTAL_API_KEY=2804d54328ea0387822f92a04b583de5689520e60c461fd8ebba2f0b44b3d65b
ABUSEIPDB_API_KEY=your_key_here

# IOC Correlation Settings
ENABLE_IOC_CORRELATION=true
AUTO_BLACKLIST_THRESHOLD=85
THREAT_INTEL_CACHE_TTL=3600
```

### Getting API Keys

1. **AlienVault OTX**: 
   - Sign up at https://otx.alienvault.com/
   - Navigate to Settings → API Integration
   - Copy your API key

2. **VirusTotal**:
   - Create account at https://www.virustotal.com/
   - Go to your profile → API Key
   - Copy your API key (free tier: 4 requests/minute)

3. **AbuseIPDB**:
   - Register at https://www.abuseipdb.com/
   - Navigate to Account → API
   - Generate and copy API key (free tier: 1000 requests/day)

---

## Usage

### Accessing the Admin Interface

1. Start the server:
   ```bash
   npm start
   ```

2. Navigate to the admin interface:
   ```
   https://your-domain.com/admin?token=YOUR_ADMIN_TOKEN
   ```

3. Click on the **Unique IPs** tab

### Analyzing an IP

1. **Expand IP Details**: Click on any IP address in the list
2. **Click "Analyze Threat Intel"**: This triggers the IOC correlation workflow
3. **Review Results**: Wait a few seconds while data is collected from all three APIs
4. **Take Action**: Based on the recommendation, click the appropriate button

### Understanding the Results

#### Combined Threat Score (0-100)

- **0-25**: Low risk - Typically safe
- **25-50**: Medium risk - Monitor activity
- **50-85**: High risk - Consider blocking
- **85-100**: Critical risk - Recommended to blacklist

#### Recommendations

- **SAFE**: No significant threat indicators found
- **MONITOR**: Some suspicious activity, keep an eye on it
- **BLACKLIST**: High threat score, immediate blocking recommended

#### Source Details

**AbuseIPDB**:
- Abuse Confidence Score (0-100%)
- Total abuse reports
- ISP and usage type information
- Last reported date

**AlienVault OTX**:
- Number of threat intelligence pulses
- Associated threat tags (malware, botnet, etc.)
- Recent pulse names
- Reputation score

**VirusTotal**:
- Malicious detections count
- Suspicious detections count
- Vendor categories
- ASN and country information

---

## Workflow Examples

### Example 1: High-Risk IP Detection

```
IP: 192.0.2.123
Combined Threat Score: 92
Recommendation: BLACKLIST

Sources:
- AbuseIPDB: 95% confidence, 42 reports
- OTX: 8 pulses, tags: [malware, botnet, scanner]
- VirusTotal: 5 malicious detections

Action: Click "Add to Blacklist (Recommended)"
```

### Example 2: Safe IP Verification

```
IP: 198.51.100.45
Combined Threat Score: 0
Recommendation: SAFE

Sources:
- AbuseIPDB: 0% confidence, 0 reports
- OTX: 0 pulses
- VirusTotal: 0 detections, all harmless

Action: No action needed, or add to whitelist if trusted
```

### Example 3: Monitoring Scenario

```
IP: 203.0.113.67
Combined Threat Score: 55
Recommendation: MONITOR

Sources:
- AbuseIPDB: 65% confidence, 3 reports
- OTX: 2 pulses, tags: [scanning]
- VirusTotal: 1 suspicious detection

Action: Monitor logs, consider blocking if activity increases
```

---

## API Endpoints

The following REST API endpoints are available for programmatic access:

### Get Threat Intelligence for IP
```http
GET /api/admin/threat-intel/:ip
Headers: X-Admin-Token: YOUR_TOKEN
```

Response:
```json
{
  "ip": "192.0.2.123",
  "timestamp": "2026-03-09T00:00:00.000Z",
  "combinedThreatScore": 92,
  "recommendation": "BLACKLIST",
  "sources": {
    "abuseipdb": { "score": 95, "reports": 42 },
    "otx": { "pulseCount": 8, "tags": ["malware"] },
    "virustotal": { "malicious": 5, "threatScore": 89 }
  },
  "summary": {
    "country": "US",
    "isp": "Example ISP",
    "tags": ["malware", "botnet", "scanner"]
  }
}
```

### Add IP to Blacklist
```http
POST /api/admin/blacklist/add
Headers: X-Admin-Token: YOUR_TOKEN
Body: { "ip": "192.0.2.123" }
```

### Add IP to Whitelist
```http
POST /api/admin/whitelist/add
Headers: X-Admin-Token: YOUR_TOKEN
Body: { "ip": "192.0.2.123" }
```

### Remove IP from Blacklist
```http
POST /api/admin/blacklist/remove
Headers: X-Admin-Token: YOUR_TOKEN
Body: { "ip": "192.0.2.123" }
```

### Remove IP from Whitelist
```http
POST /api/admin/whitelist/remove
Headers: X-Admin-Token: YOUR_TOKEN
Body: { "ip": "192.0.2.123" }
```

---

## Caching

To avoid hitting API rate limits, threat intelligence results are cached for 1 hour (configurable via `THREAT_INTEL_CACHE_TTL` in `.env`).

**Cache behavior**:
- First query: Fetches fresh data from all APIs
- Subsequent queries: Returns cached data if available
- Cache TTL: 3600 seconds (1 hour) by default
- Cache cleared: On server restart

---

## Rate Limits & Best Practices

### API Rate Limits

- **AbuseIPDB Free Tier**: 1,000 requests/day
- **VirusTotal Free Tier**: 4 requests/minute, 500 requests/day
- **AlienVault OTX**: No strict limits for standard use

### Best Practices

1. **Use Caching**: Results are automatically cached for 1 hour
2. **Analyze Selectively**: Don't analyze every IP - focus on suspicious ones
3. **Monitor API Usage**: Keep track of your daily API quota
4. **Upgrade Plans**: Consider paid plans for high-volume environments

---

## Automation

### Auto-Blacklisting

Configure automatic blacklisting based on threat scores in `.env`:

```env
AUTO_BLACKLIST_THRESHOLD=85
```

When an IP is analyzed and receives a combined threat score ≥ 85, it will be automatically recommended for blacklisting.

### Integration with Existing Blocking

The threat intelligence system integrates seamlessly with existing blocking features:

- **Whitelist Override**: Whitelisted IPs bypass threat feed checks
- **Manual Blocking**: IPs added to blacklist are blocked immediately
- **Auto-Blocking**: IPs can be auto-blocked after violation threshold

---

## Troubleshooting

### API Errors

**"No API key configured"**
- Check your `.env` file for the specific API key
- Ensure the key is not empty or invalid

**"Failed to query threat intelligence"**
- Check your internet connection
- Verify API keys are correct
- Check if you've exceeded rate limits

### No Results Displayed

- Open browser developer console to check for JavaScript errors
- Verify admin token is valid
- Check server logs for backend errors

### Caching Issues

To clear the threat intelligence cache, restart the server:
```bash
npm start
```

---

## Security Considerations

1. **API Key Protection**: Never commit `.env` file to version control
2. **Admin Token**: Use a strong, randomly generated admin token
3. **HTTPS Only**: Access admin interface only via HTTPS in production
4. **Audit Logging**: All blacklist/whitelist changes are logged to console
5. **Rate Limiting**: Respect API provider rate limits to avoid IP bans

---

## Advanced Usage

### Bulk IP Analysis

For analyzing multiple IPs, you can script API calls:

```bash
curl -X GET \
  -H "X-Admin-Token: YOUR_TOKEN" \
  https://your-domain.com/api/admin/threat-intel/192.0.2.123
```

### Automated Response

Create automation scripts that:
1. Query threat intel API regularly
2. Auto-add high-risk IPs to blacklist
3. Send alerts for critical threats

---

## Support

For issues or questions:
1. Check server logs: `npm run logs`
2. Review browser console for frontend errors
3. Verify API keys and configuration
4. Open an issue on the GitHub repository

---

## References

- [AbuseIPDB API Documentation](https://docs.abuseipdb.com/)
- [AlienVault OTX API Documentation](https://otx.alienvault.com/api)
- [VirusTotal API Documentation](https://developers.virustotal.com/reference/overview)
