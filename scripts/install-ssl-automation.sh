#!/bin/bash
#
# SSL Certificate Automation Installer
# This script sets up automatic SSL certificate renewal for the Catch framework
#
# Usage: sudo ./install-ssl-automation.sh
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(dirname "$SCRIPT_DIR")"
RENEWAL_SCRIPT="${SCRIPT_DIR}/renew-ssl-certs.sh"
SUDOERS_FILE="/etc/sudoers.d/catch-ssl-renewal"
USER="cmndcntrl"

# Function to print colored messages
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${YELLOW}ℹ${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run as root (use sudo)"
    exit 1
fi

echo "=== SSL Certificate Automation Installer ==="
echo ""

# Step 1: Verify renewal script exists and is executable
print_info "Checking renewal script..."
if [ ! -f "$RENEWAL_SCRIPT" ]; then
    print_error "Renewal script not found: $RENEWAL_SCRIPT"
    exit 1
fi

if [ ! -x "$RENEWAL_SCRIPT" ]; then
    print_info "Making renewal script executable..."
    chmod +x "$RENEWAL_SCRIPT"
fi
print_success "Renewal script found and executable"

# Step 2: Install sudoers configuration
print_info "Installing sudoers configuration..."
if [ -f "${SCRIPT_DIR}/sudoers-ssl-renewal" ]; then
    cp "${SCRIPT_DIR}/sudoers-ssl-renewal" "$SUDOERS_FILE"
    chmod 440 "$SUDOERS_FILE"

    # Validate sudoers syntax
    if visudo -c -f "$SUDOERS_FILE" > /dev/null 2>&1; then
        print_success "Sudoers configuration installed and validated"
    else
        print_error "Sudoers configuration has syntax errors"
        rm -f "$SUDOERS_FILE"
        exit 1
    fi
else
    print_error "Sudoers template file not found: ${SCRIPT_DIR}/sudoers-ssl-renewal"
    exit 1
fi

# Step 3: Set up cron job
print_info "Setting up cron job for user: $USER"

# Create cron entry
CRON_ENTRY="0 3 * * * sudo ${RENEWAL_SCRIPT} >> ${APP_DIR}/logs/ssl-renewal.log 2>&1"

# Check if cron entry already exists
if sudo -u "$USER" crontab -l 2>/dev/null | grep -q "$RENEWAL_SCRIPT"; then
    print_info "Cron job already exists, skipping..."
else
    # Add cron entry
    (sudo -u "$USER" crontab -l 2>/dev/null; echo "$CRON_ENTRY") | sudo -u "$USER" crontab -
    print_success "Cron job installed (runs daily at 3:00 AM)"
fi

# Step 4: Create log file with proper permissions
print_info "Setting up log file..."
touch "${APP_DIR}/logs/ssl-renewal.log"
chown "$USER:$USER" "${APP_DIR}/logs/ssl-renewal.log"
chmod 644 "${APP_DIR}/logs/ssl-renewal.log"
print_success "Log file created: ${APP_DIR}/logs/ssl-renewal.log"

# Step 5: Test the renewal script
echo ""
print_info "Running test of renewal script..."
echo ""

if sudo -u "$USER" sudo "$RENEWAL_SCRIPT"; then
    print_success "Test run completed successfully"
else
    print_error "Test run failed. Check the output above for errors."
    exit 1
fi

# Summary
echo ""
echo "=== Installation Complete ==="
echo ""
print_success "SSL certificate automation is now configured"
echo ""
echo "Configuration summary:"
echo "  • Renewal script: $RENEWAL_SCRIPT"
echo "  • Cron schedule: Daily at 3:00 AM"
echo "  • Log file: ${APP_DIR}/logs/ssl-renewal.log"
echo "  • Sudoers file: $SUDOERS_FILE"
echo ""
echo "Next steps:"
echo "  1. Monitor the first automated run after 3:00 AM"
echo "  2. Check logs with: tail -f ${APP_DIR}/logs/ssl-renewal.log"
echo "  3. Verify cron job with: crontab -l"
echo "  4. Test manual run with: sudo ${RENEWAL_SCRIPT}"
echo ""
print_info "The script will automatically:"
echo "  • Detect when Let's Encrypt renews certificates"
echo "  • Copy new certificates to the application directory"
echo "  • Restart the Node.js server with new certificates"
echo "  • Keep backups of previous certificates"
echo ""
