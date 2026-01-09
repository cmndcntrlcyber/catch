# SSL Certificate Automation Documentation

This directory contains scripts and configurations for automatically renewing SSL certificates from Let's Encrypt and keeping the Catch framework running with up-to-date certificates.

## Overview

The automation system consists of:
1. **Renewal Script** (`renew-ssl-certs.sh`) - Copies renewed certificates and restarts the server
2. **Cron Job** - Runs the renewal script daily at 3:00 AM
3. **Sudoers Configuration** - Allows passwordless sudo for the renewal script
4. **Installation Script** (`install-ssl-automation.sh`) - Sets everything up automatically

## Quick Start

### Automatic Installation (Recommended)

Run the installation script with sudo:

```bash
sudo ./install-ssl-automation.sh
```

This will:
- Configure sudoers to allow passwordless script execution
- Install the cron job
- Create the log file
- Run a test to verify everything works

### Manual Installation

If you prefer to set up manually:

1. **Install sudoers configuration:**
   ```bash
   sudo cp sudoers-ssl-renewal /etc/sudoers.d/catch-ssl-renewal
   sudo chmod 440 /etc/sudoers.d/catch-ssl-renewal
   sudo visudo -c -f /etc/sudoers.d/catch-ssl-renewal
   ```

2. **Install cron job:**
   ```bash
   crontab -l > temp_cron 2>/dev/null || true
   echo "0 3 * * * sudo /home/cmndcntrl/code/catch/renew-ssl-certs.sh >> /home/cmndcntrl/code/catch/ssl-renewal.log 2>&1" >> temp_cron
   crontab temp_cron
   rm temp_cron
   ```

3. **Create log file:**
   ```bash
   touch ssl-renewal.log
   chmod 644 ssl-renewal.log
   ```

## How It Works

### Certificate Renewal Detection

The script intelligently detects when certificates need updating:

1. **Recent Updates**: Checks if Let's Encrypt certificates were modified in the last 24 hours
2. **Missing Certificates**: Copies certificates if the app directory is missing them
3. **No Action Needed**: Exits gracefully if certificates are current

### Automated Process

When certificates are renewed:

1. ✅ Backs up existing certificates with timestamps
2. ✅ Copies new certificates from Let's Encrypt directory
3. ✅ Sets correct ownership and permissions
4. ✅ Validates certificate integrity
5. ✅ Restarts the Node.js server
6. ✅ Cleans up old backups (keeps last 5)

### Server Restart

The script automatically:
- Detects if the Node.js server is running
- Gracefully stops the old server process
- Starts a new instance with updated certificates
- Verifies the server restarted successfully

## Files

| File | Purpose |
|------|---------|
| `renew-ssl-certs.sh` | Main renewal script (runs via cron) |
| `install-ssl-automation.sh` | One-command installer |
| `sudoers-ssl-renewal` | Sudoers template for passwordless sudo |
| `cron-ssl-renewal.txt` | Cron job template (for reference) |
| `ssl-renewal.log` | Log file for renewal operations |
| `SSL-AUTOMATION-README.md` | This documentation file |

## Configuration

### Paths (in renew-ssl-certs.sh)

```bash
LETSENCRYPT_DOMAIN="catch.attck-deploy.net"
LETSENCRYPT_PATH="/etc/letsencrypt/live/${LETSENCRYPT_DOMAIN}"
APP_DIR="/home/cmndcntrl/code/catch"
SSL_DIR="${APP_DIR}/ssl"
USER="cmndcntrl"
```

**To use with a different domain**: Edit `LETSENCRYPT_DOMAIN` in `renew-ssl-certs.sh`

### Cron Schedule

Default: Daily at 3:00 AM
```cron
0 3 * * * sudo /home/cmndcntrl/code/catch/renew-ssl-certs.sh
```

**Alternative schedules** (edit with `crontab -e`):

- **Every 12 hours** (3:00 AM and 3:00 PM):
  ```cron
  0 3,15 * * * sudo /home/cmndcntrl/code/catch/renew-ssl-certs.sh
  ```

- **Weekly** (Mondays at 3:00 AM):
  ```cron
  0 3 * * 1 sudo /home/cmndcntrl/code/catch/renew-ssl-certs.sh
  ```

## Usage

### Manual Test Run

Test the renewal script manually:
```bash
sudo ./renew-ssl-certs.sh
```

### View Logs

Monitor the renewal log:
```bash
tail -f ssl-renewal.log
```

View recent renewal attempts:
```bash
tail -n 50 ssl-renewal.log
```

Search for errors:
```bash
grep ERROR ssl-renewal.log
```

### Check Cron Job

List installed cron jobs:
```bash
crontab -l
```

View cron execution logs:
```bash
grep CRON /var/log/syslog | grep renew-ssl-certs
```

### Verify Certificate Status

Check current certificate expiration:
```bash
openssl x509 -in ssl/fullchain.pem -noout -enddate
```

View certificate details:
```bash
openssl x509 -in ssl/fullchain.pem -noout -text
```

## Troubleshooting

### Cron Job Not Running

1. **Check cron service is running:**
   ```bash
   sudo systemctl status cron
   ```

2. **Verify cron job is installed:**
   ```bash
   crontab -l | grep renew-ssl-certs
   ```

3. **Check syslog for cron errors:**
   ```bash
   grep CRON /var/log/syslog | tail -n 20
   ```

### Permission Errors

1. **Verify sudoers configuration:**
   ```bash
   sudo visudo -c -f /etc/sudoers.d/catch-ssl-renewal
   ```

2. **Test sudo access:**
   ```bash
   sudo -n /home/cmndcntrl/code/catch/renew-ssl-certs.sh
   ```
   (Should run without asking for password)

3. **Check file ownership:**
   ```bash
   ls -la renew-ssl-certs.sh
   ls -la ssl/
   ```

### Server Not Restarting

1. **Check if server process exists:**
   ```bash
   pgrep -f "node server.js"
   ```

2. **Manually restart server:**
   ```bash
   pkill -f "node server.js"
   node server.js &
   ```

3. **Check server logs:**
   ```bash
   tail -f access.log
   ```

### Certificate Copy Failures

1. **Verify Let's Encrypt certificates exist:**
   ```bash
   sudo ls -la /etc/letsencrypt/live/catch.attck-deploy.net/
   ```

2. **Check certificate validity:**
   ```bash
   sudo openssl x509 -in /etc/letsencrypt/live/catch.attck-deploy.net/fullchain.pem -noout -text
   ```

3. **Test manual copy:**
   ```bash
   sudo cp /etc/letsencrypt/live/catch.attck-deploy.net/privkey.pem ./ssl/
   sudo cp /etc/letsencrypt/live/catch.attck-deploy.net/fullchain.pem ./ssl/
   ```

## Let's Encrypt Renewal

Let's Encrypt certificates expire every 90 days. Certbot (Let's Encrypt's renewal tool) automatically:
- Runs renewal checks twice daily
- Renews certificates when they have 30 days or less remaining
- Stores renewed certificates in `/etc/letsencrypt/live/`

**Our script runs after certbot**, detecting and deploying renewed certificates automatically.

### Verifying Certbot

Check certbot timer status:
```bash
sudo systemctl status certbot.timer
```

Test certbot renewal (dry run):
```bash
sudo certbot renew --dry-run
```

View certbot logs:
```bash
sudo tail -f /var/log/letsencrypt/letsencrypt.log
```

## Security Considerations

### Sudoers Configuration

The sudoers file is carefully configured to:
- Only allow running ONE specific script
- Use absolute paths (prevents path manipulation)
- Require no parameters (prevents command injection)
- Only grant access to the `cmndcntrl` user

### File Permissions

- **Private key** (`privkey.pem`): 600 (owner read/write only)
- **Certificate** (`fullchain.pem`): 644 (world-readable)
- **Renewal script**: 755 (executable by all, writable by owner)
- **Sudoers file**: 440 (read-only, root-owned)

### Backup Management

- Backups are created with timestamps
- Last 5 backups are retained
- Older backups are automatically deleted
- Backups use the same permissions as originals

## Uninstallation

To remove the automation:

1. **Remove cron job:**
   ```bash
   crontab -l | grep -v renew-ssl-certs | crontab -
   ```

2. **Remove sudoers file:**
   ```bash
   sudo rm /etc/sudoers.d/catch-ssl-renewal
   ```

3. **Remove scripts (optional):**
   ```bash
   rm renew-ssl-certs.sh install-ssl-automation.sh sudoers-ssl-renewal
   ```

## Support

For issues or questions:
1. Check the logs: `tail -f ssl-renewal.log`
2. Review this documentation
3. Test manually: `sudo ./renew-ssl-certs.sh`
4. Verify cron setup: `crontab -l`

## Changelog

- **2026-01-09**: Initial automation setup
  - Created renewal script with intelligent detection
  - Added automatic server restart
  - Implemented backup management
  - Created installation script
  - Added comprehensive documentation
