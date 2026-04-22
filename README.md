# Catch - Web Security Research Framework

A browser fingerprinting and data collection framework for authorized security research, penetration testing, and security awareness demonstrations.

## Legal Notice

**FOR AUTHORIZED SECURITY RESEARCH ONLY.** Users must obtain explicit written permission before testing any system. See [docs/SECURITY.md](docs/SECURITY.md) for full policy.

## Project Structure

```
catch/
├── server.js                 # Node.js HTTP/HTTPS server
├── config.js                 # Configuration manager (.env loader)
├── package.json
├── .env                      # Environment configuration
├── public/                   # Client-facing static assets
│   ├── index.html            #   Fingerprinting landing page
│   ├── admin.html            #   Admin dashboard
│   └── js/
│       ├── fingerprint.js    #   Browser fingerprinting engine
│       ├── test.js           #   Data exfiltration methods
│       ├── admin.js          #   Admin interface logic
│       └── admin.css         #   Admin styles
├── lib/                      # Server-side modules
│   └── threat-intel.js       #   AbuseIPDB / OTX / VirusTotal
├── scripts/                  # Operational scripts
│   ├── install-ssl-automation.sh
│   ├── renew-ssl-certs.sh
│   ├── cron-ssl-renewal.txt
│   └── sudoers-ssl-renewal
├── docs/                     # Documentation
│   ├── SECURITY.md
│   ├── THREAT-INTEL-GUIDE.md
│   ├── IMPLEMENTATION-SUMMARY.md
│   ├── implementation-guide.md
│   ├── SSL-AUTOMATION-README.md
│   └── download_js_exploit_poc.html
├── logs/                     # Log files (gitignored)
├── ssl/                      # SSL certificates (gitignored)
└── DEPLOY.md                 # Deployment guide
```

## Quick Start

```bash
npm install
npm run dev       # Development: HTTP on port 8081
npm start         # Production: HTTPS + HTTP redirect
```

See [DEPLOY.md](DEPLOY.md) for full deployment, configuration, and operations reference.

## Features

- **Browser Fingerprinting**: Canvas, WebGL, audio context, fonts, media devices, hardware profiling
- **Data Exfiltration**: Image beacon, Fetch API, XHR, hidden iframe methods
- **Request Blocking**: IP/CIDR, User-Agent, URL/body pattern matching, GeoIP, auto-blocking
- **Threat Intelligence**: AbuseIPDB, AlienVault OTX, VirusTotal integration with IOC correlation
- **Admin Dashboard**: Real-time logs, IP management, threat intel, statistics
- **SSL Automation**: Let's Encrypt certificate renewal with cron

## API Endpoints

| Path | Description |
|------|-------------|
| `/` | Fingerprinting landing page |
| `/api/fingerprint` | Server-side fingerprint data |
| `/exfil` | Image beacon endpoint |
| `/admin?token=<TOKEN>` | Admin dashboard |
| `/api/admin/*` | Admin API (config, logs, stats, threat-intel, blacklist, whitelist) |

## Documentation

- [DEPLOY.md](DEPLOY.md) - Deployment, configuration, and operations
- [docs/THREAT-INTEL-GUIDE.md](docs/THREAT-INTEL-GUIDE.md) - Threat intelligence usage
- [docs/implementation-guide.md](docs/implementation-guide.md) - Deployment vectors
- [docs/SSL-AUTOMATION-README.md](docs/SSL-AUTOMATION-README.md) - SSL certificate automation
- [docs/SECURITY.md](docs/SECURITY.md) - Security policy

## License

MIT - see [LICENSE](LICENSE).
