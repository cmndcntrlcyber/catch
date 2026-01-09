#!/bin/bash
#
# SSL Certificate Renewal Script for Catch Framework
# This script copies renewed Let's Encrypt certificates to the application directory
# and restarts the Node.js server if certificates were updated.
#
# Usage: ./renew-ssl-certs.sh
# Cron: Run daily after certbot renewal (typically at 2:30 AM)
#

set -e

# Configuration
LETSENCRYPT_DOMAIN="catch.attck-deploy.net"
LETSENCRYPT_PATH="/etc/letsencrypt/live/${LETSENCRYPT_DOMAIN}"
APP_DIR="/home/cmndcntrl/code/catch"
SSL_DIR="${APP_DIR}/ssl"
LOG_FILE="${APP_DIR}/ssl-renewal.log"
USER="cmndcntrl"
GROUP="cmndcntrl"

# Function to log messages with timestamp
log_message() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function to check if certificates were recently updated (within last 24 hours)
cert_recently_updated() {
    local cert_file="$1"
    if [ ! -f "$cert_file" ]; then
        return 1
    fi

    # Get file modification time in seconds since epoch
    local mod_time=$(stat -c %Y "$cert_file" 2>/dev/null || stat -f %m "$cert_file" 2>/dev/null)
    local current_time=$(date +%s)
    local age=$((current_time - mod_time))

    # Check if modified in last 24 hours (86400 seconds)
    if [ $age -lt 86400 ]; then
        return 0
    else
        return 1
    fi
}

# Start logging
log_message "=== SSL Certificate Renewal Process Started ==="

# Check if Let's Encrypt certificates exist
if [ ! -d "$LETSENCRYPT_PATH" ]; then
    log_message "ERROR: Let's Encrypt certificate directory not found: $LETSENCRYPT_PATH"
    exit 1
fi

if [ ! -f "${LETSENCRYPT_PATH}/privkey.pem" ] || [ ! -f "${LETSENCRYPT_PATH}/fullchain.pem" ]; then
    log_message "ERROR: Certificate files not found in $LETSENCRYPT_PATH"
    exit 1
fi

# Check if certificates were recently renewed
if cert_recently_updated "${LETSENCRYPT_PATH}/privkey.pem" || cert_recently_updated "${LETSENCRYPT_PATH}/fullchain.pem"; then
    log_message "Certificates were recently updated. Proceeding with copy..."
    CERTS_UPDATED=true
else
    log_message "Certificates have not been updated recently. Checking if app directory needs refresh..."

    # Check if app SSL directory has valid certificates
    if [ ! -f "${SSL_DIR}/privkey.pem" ] || [ ! -f "${SSL_DIR}/fullchain.pem" ]; then
        log_message "App SSL directory missing certificates. Copying..."
        CERTS_UPDATED=true
    else
        log_message "No certificate renewal detected and app directory has valid certificates. Exiting."
        exit 0
    fi
fi

# Create SSL directory if it doesn't exist
if [ ! -d "$SSL_DIR" ]; then
    log_message "Creating SSL directory: $SSL_DIR"
    mkdir -p "$SSL_DIR"
fi

# Backup existing certificates if they exist
if [ -f "${SSL_DIR}/privkey.pem" ]; then
    log_message "Backing up existing certificates..."
    cp "${SSL_DIR}/privkey.pem" "${SSL_DIR}/privkey.pem.backup.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
    cp "${SSL_DIR}/fullchain.pem" "${SSL_DIR}/fullchain.pem.backup.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
fi

# Copy certificates
log_message "Copying certificates from Let's Encrypt to application directory..."
if cp "${LETSENCRYPT_PATH}/privkey.pem" "${SSL_DIR}/privkey.pem" && \
   cp "${LETSENCRYPT_PATH}/fullchain.pem" "${SSL_DIR}/fullchain.pem"; then
    log_message "Certificates copied successfully"
else
    log_message "ERROR: Failed to copy certificates"
    exit 1
fi

# Set ownership
log_message "Setting certificate ownership to ${USER}:${GROUP}..."
if chown "${USER}:${GROUP}" "${SSL_DIR}/privkey.pem" "${SSL_DIR}/fullchain.pem"; then
    log_message "Ownership set successfully"
else
    log_message "ERROR: Failed to set ownership"
    exit 1
fi

# Set permissions
log_message "Setting certificate permissions..."
if chmod 600 "${SSL_DIR}/privkey.pem" && chmod 644 "${SSL_DIR}/fullchain.pem"; then
    log_message "Permissions set successfully (privkey: 600, fullchain: 644)"
else
    log_message "ERROR: Failed to set permissions"
    exit 1
fi

# Verify certificate validity
log_message "Verifying certificate validity..."
if openssl x509 -in "${SSL_DIR}/fullchain.pem" -noout -text > /dev/null 2>&1; then
    CERT_EXPIRY=$(openssl x509 -in "${SSL_DIR}/fullchain.pem" -noout -enddate | cut -d= -f2)
    log_message "Certificate is valid. Expiry date: ${CERT_EXPIRY}"
else
    log_message "ERROR: Certificate validation failed"
    exit 1
fi

# Restart Node.js server if it's running
log_message "Checking for running Node.js server..."
if pgrep -f "node server.js" > /dev/null; then
    log_message "Node.js server is running. Restarting to load new certificates..."

    # Kill existing server
    pkill -f "node server.js" || true
    sleep 2

    # Start server in background
    cd "$APP_DIR"
    nohup node server.js > /dev/null 2>&1 &

    # Wait a moment and check if server started
    sleep 3
    if pgrep -f "node server.js" > /dev/null; then
        log_message "Server restarted successfully with new certificates"
    else
        log_message "WARNING: Server may not have restarted properly. Please check manually."
    fi
else
    log_message "No running Node.js server detected. Certificates updated but server not restarted."
fi

# Clean up old backup files (keep last 5)
log_message "Cleaning up old certificate backups..."
cd "$SSL_DIR"
ls -t privkey.pem.backup.* 2>/dev/null | tail -n +6 | xargs rm -f 2>/dev/null || true
ls -t fullchain.pem.backup.* 2>/dev/null | tail -n +6 | xargs rm -f 2>/dev/null || true

log_message "=== SSL Certificate Renewal Process Completed Successfully ==="
exit 0
