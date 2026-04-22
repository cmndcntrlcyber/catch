// Admin Interface JavaScript
// Handles all frontend logic for the Catch Framework admin interface

// Get admin token from URL or local storage
const urlParams = new URLSearchParams(window.location.search);
const adminToken = urlParams.get('token') || localStorage.getItem('adminToken');

if (!adminToken) {
    document.body.innerHTML = '<div style="padding: 50px; text-align: center;"><h1>Authentication Required</h1><p>Please provide an admin token in the URL: ?token=YOUR_TOKEN</p></div>';
    throw new Error('No admin token provided');
}

// Store token for future requests
localStorage.setItem('adminToken', adminToken);

// API base URL
const API_BASE = window.location.origin;

// Global data storage
let currentConfig = {};
let currentLogs = [];
let currentStats = {};
let requestChart = null;

// ============================================================================
// DARK MODE
// ============================================================================

(function initTheme() {
    const saved = localStorage.getItem('theme');
    if (saved === 'dark') {
        document.documentElement.setAttribute('data-theme', 'dark');
    }
    document.addEventListener('DOMContentLoaded', () => {
        const toggle = document.getElementById('theme-toggle');
        if (!toggle) return;
        const icon = toggle.querySelector('i');
        if (saved === 'dark') {
            icon.classList.replace('fa-moon', 'fa-sun');
        }
        toggle.addEventListener('click', () => {
            const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
            if (isDark) {
                document.documentElement.removeAttribute('data-theme');
                icon.classList.replace('fa-sun', 'fa-moon');
                localStorage.setItem('theme', 'light');
            } else {
                document.documentElement.setAttribute('data-theme', 'dark');
                icon.classList.replace('fa-moon', 'fa-sun');
                localStorage.setItem('theme', 'dark');
            }
            // Update chart colors if chart exists
            if (requestChart) {
                const legendColor = getComputedStyle(document.documentElement).getPropertyValue('--text-primary').trim();
                requestChart.options.scales.x.ticks.color = legendColor;
                requestChart.options.scales.y.ticks.color = legendColor;
                requestChart.options.plugins.legend.labels.color = legendColor;
                requestChart.update();
            }
        });
    });
})();

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Make authenticated API request
 */
async function apiRequest(endpoint, options = {}) {
    const headers = {
        'X-Admin-Token': adminToken,
        'Content-Type': 'application/json',
        ...options.headers
    };

    try {
        const response = await fetch(`${API_BASE}${endpoint}`, {
            ...options,
            headers
        });

        if (!response.ok) {
            if (response.status === 401) {
                showToast('Authentication failed. Invalid token.', 'error');
                throw new Error('Unauthorized');
            }
            throw new Error(`API request failed: ${response.statusText}`);
        }

        return await response.json();
    } catch (error) {
        console.error('API request error:', error);
        showToast(`Error: ${error.message}`, 'error');
        throw error;
    }
}

/**
 * Show toast notification
 */
function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = `toast ${type} show`;

    setTimeout(() => {
        toast.className = 'toast';
    }, 3000);
}

/**
 * Format timestamp for display
 */
function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString();
}

/**
 * Escape HTML to prevent XSS when inserting log data into innerHTML
 */
function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

/**
 * Parse log line into object
 */
function parseLogLine(line) {
    const parts = line.split(' | ');
    if (parts.length < 3) return null;

    const log = {};
    parts.forEach((part, index) => {
        if (index === 0) {
            log.timestamp = part.trim();
            return;
        }
        const colonIndex = part.indexOf(':');
        if (colonIndex > 0) {
            const key = part.substring(0, colonIndex).trim();
            const value = part.substring(colonIndex + 1).trim();
            log[key] = value;
        }
    });

    return log;
}

// ============================================================================
// TAB NAVIGATION
// ============================================================================

document.querySelectorAll('.tab-button').forEach(button => {
    button.addEventListener('click', () => {
        // Remove active class from all buttons and contents
        document.querySelectorAll('.tab-button').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

        // Add active class to clicked button and corresponding content
        button.classList.add('active');
        const tabId = button.getAttribute('data-tab');
        document.getElementById(tabId).classList.add('active');

        // Load data for the tab
        loadTabData(tabId);
    });
});

/**
 * Load data when tab is switched
 */
function loadTabData(tabId) {
    switch(tabId) {
        case 'dashboard':
            loadDashboard();
            break;
        case 'blocking':
            loadBlockingRules();
            break;
        case 'logs':
            refreshLogs();
            break;
        case 'stats':
            loadStatistics();
            break;
        case 'unique-ips':
            loadUniqueIPs();
            break;
        case 'config':
            loadConfiguration();
            break;
    }
}

// ============================================================================
// DASHBOARD TAB
// ============================================================================

async function loadDashboard() {
    try {
        const stats = await apiRequest('/api/admin/stats');
        currentStats = stats;

        // Update stat cards
        document.getElementById('total-requests').textContent = stats.totalRequests || 0;
        document.getElementById('blocked-requests').textContent = stats.blockedRequests || 0;
        document.getElementById('threat-score').textContent = stats.threatScore || 0;
        document.getElementById('unique-ips-count').textContent = stats.uniqueIPs || 0;

        // Load recent activity
        const logs = await apiRequest('/api/admin/logs?limit=10');
        displayActivityFeed(logs.logs || []);
    } catch (error) {
        console.error('Error loading dashboard:', error);
    }
}

function displayActivityFeed(logs) {
    const feed = document.getElementById('activity-feed');

    if (logs.length === 0) {
        feed.innerHTML = '<p class="no-data">No recent activity</p>';
        return;
    }

    feed.innerHTML = logs.map(log => {
        const isBlocked = log.STATUS === 'BLOCKED' || log.Method === 'HTTP-REDIRECT';
        const icon = isBlocked ? 'fa-ban' : 'fa-network-wired';
        const className = isBlocked ? 'blocked' : 'normal';

        return `
            <div class="activity-item ${className}">
                <i class="fas ${icon}"></i>
                <div class="activity-details">
                    <div class="activity-time">${escapeHtml(log.timestamp) || 'Unknown time'}</div>
                    <div class="activity-info">
                        <strong>IP:</strong> ${escapeHtml(log.IP) || 'Unknown'} |
                        <strong>Method:</strong> ${escapeHtml(log.Method) || 'Unknown'} |
                        <strong>URL:</strong> ${escapeHtml(log.URL) || 'Unknown'}
                    </div>
                    ${log.REASON ? `<div class="activity-reason">Reason: ${escapeHtml(log.REASON)}</div>` : ''}
                </div>
            </div>
        `;
    }).join('');
}

// ============================================================================
// BLOCKING RULES TAB
// ============================================================================

async function loadBlockingRules() {
    try {
        const config = await apiRequest('/api/admin/config');
        currentConfig = config;

        // Load blocked IPs
        document.getElementById('blocked-ips').value = (config.blocking.blockedIPs || []).join('\n');
        document.getElementById('blocked-cidrs').value = (config.blocking.blockedCIDRs || []).join('\n');

        // Load blocked User-Agents
        document.getElementById('blocked-user-agents').value = (config.blocking.blockedUserAgents || []).join('\n');

        // Load blocked URL patterns
        document.getElementById('blocked-url-patterns').value = (config.blocking.blockedUrlPatterns || []).join('\n');

        // Load blocked body patterns
        document.getElementById('blocked-body-patterns').value = (config.blocking.blockedBodyPatterns || []).join('\n');

        // Load whitelist
        document.getElementById('whitelist-enabled').checked = config.blocking.whitelistEnabled || false;
        document.getElementById('whitelisted-ips').value = (config.blocking.whitelistedIPs || []).join('\n');
        document.getElementById('whitelisted-cidrs').value = (config.blocking.whitelistedCIDRs || []).join('\n');
        document.getElementById('whitelisted-user-agents').value = (config.blocking.whitelistedUserAgents || []).join('\n');
    } catch (error) {
        console.error('Error loading blocking rules:', error);
    }
}

async function saveIPRules() {
    const blockedIPs = document.getElementById('blocked-ips').value
        .split(/[\n,]/)
        .map(ip => ip.trim())
        .filter(ip => ip.length > 0);

    const blockedCIDRs = document.getElementById('blocked-cidrs').value
        .split(/[\n,]/)
        .map(cidr => cidr.trim())
        .filter(cidr => cidr.length > 0);

    try {
        await apiRequest('/api/admin/config', {
            method: 'POST',
            body: JSON.stringify({
                blocking: {
                    blockedIPs,
                    blockedCIDRs
                }
            })
        });
        showToast('IP blocking rules saved successfully', 'success');
    } catch (error) {
        showToast('Failed to save IP rules', 'error');
    }
}

async function saveUARules() {
    const blockedUserAgents = document.getElementById('blocked-user-agents').value
        .split('\n')
        .map(ua => ua.trim())
        .filter(ua => ua.length > 0);

    try {
        await apiRequest('/api/admin/config', {
            method: 'POST',
            body: JSON.stringify({
                blocking: {
                    blockedUserAgents
                }
            })
        });
        showToast('User-Agent blocking rules saved successfully', 'success');
    } catch (error) {
        showToast('Failed to save User-Agent rules', 'error');
    }
}

async function saveURLRules() {
    const blockedUrlPatterns = document.getElementById('blocked-url-patterns').value
        .split('\n')
        .map(pattern => pattern.trim())
        .filter(pattern => pattern.length > 0);

    try {
        await apiRequest('/api/admin/config', {
            method: 'POST',
            body: JSON.stringify({
                blocking: {
                    blockedUrlPatterns
                }
            })
        });
        showToast('URL pattern blocking rules saved successfully', 'success');
    } catch (error) {
        showToast('Failed to save URL rules', 'error');
    }
}

async function saveBodyRules() {
    const blockedBodyPatterns = document.getElementById('blocked-body-patterns').value
        .split('\n')
        .map(pattern => pattern.trim())
        .filter(pattern => pattern.length > 0);

    try {
        await apiRequest('/api/admin/config', {
            method: 'POST',
            body: JSON.stringify({
                blocking: {
                    blockedBodyPatterns
                }
            })
        });
        showToast('POST body blocking rules saved successfully', 'success');
    } catch (error) {
        showToast('Failed to save body rules', 'error');
    }
}

async function saveWhitelist() {
    const whitelistEnabled = document.getElementById('whitelist-enabled').checked;
    const whitelistedIPs = document.getElementById('whitelisted-ips').value
        .split(/[\n,]/)
        .map(ip => ip.trim())
        .filter(ip => ip.length > 0);

    const whitelistedCIDRs = document.getElementById('whitelisted-cidrs').value
        .split(/[\n,]/)
        .map(cidr => cidr.trim())
        .filter(cidr => cidr.length > 0);

    const whitelistedUserAgents = document.getElementById('whitelisted-user-agents').value
        .split('\n')
        .map(ua => ua.trim())
        .filter(ua => ua.length > 0);

    try {
        await apiRequest('/api/admin/config', {
            method: 'POST',
            body: JSON.stringify({
                blocking: {
                    whitelistEnabled,
                    whitelistedIPs,
                    whitelistedCIDRs,
                    whitelistedUserAgents
                }
            })
        });
        showToast('Whitelist rules saved successfully', 'success');
    } catch (error) {
        showToast('Failed to save whitelist rules', 'error');
    }
}

// ============================================================================
// LOGS TAB
// ============================================================================

async function refreshLogs() {
    const limit = document.getElementById('log-limit').value || 100;
    const filter = document.getElementById('log-filter').value;

    try {
        const response = await apiRequest(`/api/admin/logs?limit=${limit}&filter=${filter}`);
        currentLogs = response.logs || [];
        displayLogs(currentLogs);
    } catch (error) {
        console.error('Error loading logs:', error);
    }
}

function displayLogs(logs) {
    const viewer = document.getElementById('log-viewer');

    if (logs.length === 0) {
        viewer.innerHTML = '<p class="no-data">No logs found</p>';
        return;
    }

    viewer.innerHTML = logs.map(log => {
        const isBlocked = log.STATUS === 'BLOCKED';
        const className = isBlocked ? 'log-entry blocked' : 'log-entry';

        return `
            <div class="${className}">
                <div class="log-header">
                    <span class="log-time">${escapeHtml(log.timestamp) || 'Unknown'}</span>
                    <span class="log-ip">${escapeHtml(log.IP) || 'Unknown'}</span>
                    <span class="log-method">${escapeHtml(log.Method) || 'Unknown'}</span>
                    ${isBlocked ? '<span class="log-status-badge blocked">BLOCKED</span>' : ''}
                </div>
                <div class="log-details">
                    <div><strong>URL:</strong> ${escapeHtml(log.URL) || 'Unknown'}</div>
                    <div><strong>User-Agent:</strong> ${escapeHtml(log.UA) || 'Unknown'}</div>
                    ${log.REASON ? `<div class="log-reason"><strong>Reason:</strong> ${escapeHtml(log.REASON)}</div>` : ''}
                    ${log.Body ? `<div class="log-body"><strong>Body:</strong> ${escapeHtml(log.Body.substring(0, 200))}${log.Body.length > 200 ? '...' : ''}</div>` : ''}
                </div>
            </div>
        `;
    }).join('');
}

function filterLogs() {
    const filter = document.getElementById('log-filter').value;
    refreshLogs();
}

function searchLogs() {
    const searchTerm = document.getElementById('log-search').value.toLowerCase();

    if (!searchTerm) {
        displayLogs(currentLogs);
        return;
    }

    const filtered = currentLogs.filter(log => {
        return Object.values(log).some(value =>
            String(value).toLowerCase().includes(searchTerm)
        );
    });

    displayLogs(filtered);
}

// ============================================================================
// STATISTICS TAB
// ============================================================================

async function loadStatistics() {
    try {
        const stats = await apiRequest('/api/admin/stats');
        currentStats = stats;

        // Display request trends chart
        displayRequestChart(stats.requestTrends || []);

        // Display top attackers
        displayTopAttackers(stats.topAttackers || []);

        // Display attack patterns
        displayAttackPatterns(stats.attackPatterns || {});
    } catch (error) {
        console.error('Error loading statistics:', error);
    }
}

function displayRequestChart(trends) {
    const ctx = document.getElementById('request-chart');

    if (requestChart) {
        requestChart.destroy();
    }

    requestChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: trends.map(t => t.time),
            datasets: [
                {
                    label: 'Total Requests',
                    data: trends.map(t => t.total),
                    borderColor: 'rgb(75, 192, 192)',
                    tension: 0.1
                },
                {
                    label: 'Blocked Requests',
                    data: trends.map(t => t.blocked),
                    borderColor: 'rgb(255, 99, 132)',
                    tension: 0.1
                }
            ]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    display: true,
                    labels: {
                        color: getComputedStyle(document.documentElement).getPropertyValue('--text-primary').trim()
                    }
                }
            },
            scales: {
                x: { ticks: { color: getComputedStyle(document.documentElement).getPropertyValue('--text-secondary').trim() } },
                y: { ticks: { color: getComputedStyle(document.documentElement).getPropertyValue('--text-secondary').trim() } }
            }
        }
    });
}

function displayTopAttackers(attackers) {
    const container = document.getElementById('top-attackers');

    if (attackers.length === 0) {
        container.innerHTML = '<p class="no-data">No attack data available</p>';
        return;
    }

    container.innerHTML = attackers.map((attacker, index) => `
        <div class="attacker-item">
            <span class="attacker-rank">#${index + 1}</span>
            <span class="attacker-ip">${escapeHtml(attacker.ip)}</span>
            <span class="attacker-count">${attacker.count} requests</span>
        </div>
    `).join('');
}

function displayAttackPatterns(patterns) {
    const container = document.getElementById('attack-patterns');

    if (Object.keys(patterns).length === 0) {
        container.innerHTML = '<p class="no-data">No attack patterns detected</p>';
        return;
    }

    container.innerHTML = Object.entries(patterns).map(([pattern, count]) => `
        <div class="pattern-item">
            <span class="pattern-name">${pattern}</span>
            <span class="pattern-count">${count} occurrences</span>
        </div>
    `).join('');
}

// ============================================================================
// UNIQUE IPs TAB
// ============================================================================

let uniqueIPsData = [];

function navigateToUniqueIPs() {
    document.querySelectorAll('.tab-button').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

    const btn = document.querySelector('.tab-button[data-tab="unique-ips"]');
    if (btn) btn.classList.add('active');
    document.getElementById('unique-ips').classList.add('active');
    loadUniqueIPs();
}

async function loadUniqueIPs() {
    const listEl = document.getElementById('ip-list');
    listEl.innerHTML = '<p class="loading">Loading unique IPs</p>';

    try {
        const response = await apiRequest('/api/admin/logs?limit=10000');
        const logs = response.logs || [];

        // Aggregate logs by IP client-side
        const ipMap = {};
        logs.forEach(log => {
            const ip = log.IP;
            if (!ip) return;

            if (!ipMap[ip]) {
                ipMap[ip] = { requests: [], firstSeen: log.timestamp, lastSeen: log.timestamp, hosts: new Set() };
            }

            if (log.timestamp) ipMap[ip].lastSeen = log.timestamp;
            if (log.HOST || log.Host) ipMap[ip].hosts.add(log.HOST || log.Host);

            ipMap[ip].requests.push({
                timestamp: log.timestamp || '',
                method: log.Method || '',
                url: log.URL || '',
                host: log.HOST || log.Host || '',
                ua: log.UA || '',
                status: log.STATUS || '',
                reason: log.REASON || ''
            });
        });

        uniqueIPsData = Object.keys(ipMap).map(ip => {
            const info = ipMap[ip];
            return {
                ip,
                reverseDns: [],
                hostHeaders: [...info.hosts],
                requestCount: info.requests.length,
                firstSeen: info.firstSeen,
                lastSeen: info.lastSeen,
                requests: info.requests
            };
        });

        sortAndDisplayIPs();
    } catch (error) {
        listEl.innerHTML = '<p class="no-data">Failed to load unique IPs</p>';
        console.error('Error loading unique IPs:', error);
    }
}

function sortAndDisplayIPs() {
    const sortValue = document.getElementById('ip-sort').value;
    let sorted = [...uniqueIPsData];

    switch (sortValue) {
        case 'count-desc':
            sorted.sort((a, b) => b.requestCount - a.requestCount);
            break;
        case 'count-asc':
            sorted.sort((a, b) => a.requestCount - b.requestCount);
            break;
        case 'last-desc':
            sorted.sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen));
            break;
        case 'last-asc':
            sorted.sort((a, b) => new Date(a.lastSeen) - new Date(b.lastSeen));
            break;
        case 'first-desc':
            sorted.sort((a, b) => new Date(b.firstSeen) - new Date(a.firstSeen));
            break;
        case 'first-asc':
            sorted.sort((a, b) => new Date(a.firstSeen) - new Date(b.firstSeen));
            break;
        case 'ip-asc':
            sorted.sort((a, b) => a.ip.localeCompare(b.ip));
            break;
    }

    filterIPs(sorted);
}

function filterIPs(sorted) {
    const searchTerm = document.getElementById('ip-search').value.toLowerCase();
    let filtered = sorted || [...uniqueIPsData];

    if (!Array.isArray(filtered) || filtered.length === 0) {
        filtered = [...uniqueIPsData];
    }

    if (searchTerm) {
        filtered = filtered.filter(entry =>
            entry.ip.toLowerCase().includes(searchTerm) ||
            (entry.reverseDns && entry.reverseDns.some(h => h.toLowerCase().includes(searchTerm))) ||
            (entry.hostHeaders && entry.hostHeaders.some(h => h.toLowerCase().includes(searchTerm)))
        );
    }

    displayIPList(filtered);
}

function displayIPList(ips) {
    const listEl = document.getElementById('ip-list');

    if (ips.length === 0) {
        listEl.innerHTML = '<p class="no-data">No matching IPs found</p>';
        return;
    }

    listEl.innerHTML = ips.map((entry, index) => {
        const dnsStr = entry.reverseDns && entry.reverseDns.length > 0
            ? entry.reverseDns.map(d => escapeHtml(d)).join(', ')
            : '<span class="text-muted">No PTR record</span>';
        const hostsStr = entry.hostHeaders && entry.hostHeaders.length > 0
            ? entry.hostHeaders.map(h => escapeHtml(h)).join(', ')
            : '<span class="text-muted">N/A</span>';

        const requestRows = entry.requests.map(r => `
            <tr>
                <td>${escapeHtml(r.timestamp) || 'Unknown'}</td>
                <td>${escapeHtml(r.host) || 'N/A'}</td>
                <td><span class="log-method">${escapeHtml(r.method)}</span></td>
                <td class="url-cell">${escapeHtml(r.url)}</td>
                <td>${r.status === 'BLOCKED' ? '<span class="log-status-badge blocked">BLOCKED</span>' : '<span class="text-muted">OK</span>'}</td>
            </tr>
        `).join('');

        return `
            <div class="ip-list-item" id="ip-item-${index}">
                <div class="ip-list-header" onclick="toggleIPDetail(${index})">
                    <div class="ip-list-summary">
                        <span class="ip-address">${escapeHtml(entry.ip)}</span>
                        <span class="ip-dns">${dnsStr}</span>
                    </div>
                    <div class="ip-list-meta">
                        <span class="ip-count">${entry.requestCount} requests</span>
                        <span class="ip-seen">First: ${escapeHtml(formatTimestamp(entry.firstSeen))} | Last: ${escapeHtml(formatTimestamp(entry.lastSeen))}</span>
                        <i class="fas fa-chevron-down ip-toggle-icon"></i>
                    </div>
                </div>
                <div class="ip-detail" id="ip-detail-${index}">
                    <div class="ip-detail-dns">
                        <strong>Reverse DNS:</strong> ${dnsStr}<br>
                        <strong>Host Headers:</strong> ${hostsStr}
                    </div>
                    <div class="ip-actions" style="margin: 15px 0; display: flex; gap: 10px; flex-wrap: wrap;">
                        <button class="btn-danger" onclick="addToBlacklist('${escapeHtml(entry.ip)}', event)">
                            <i class="fas fa-ban"></i> Add to Blacklist
                        </button>
                        <button class="btn-success" onclick="addToWhitelist('${escapeHtml(entry.ip)}', event)">
                            <i class="fas fa-check-circle"></i> Add to Whitelist
                        </button>
                        <button class="btn-primary" onclick="analyzeThreatIntel('${escapeHtml(entry.ip)}', event)">
                            <i class="fas fa-shield-virus"></i> Analyze Threat Intel
                        </button>
                    </div>
                    <div id="threat-intel-${index}" class="threat-intel-result" style="display: none;"></div>
                    <div class="ip-detail-table-wrap">
                        <table class="ip-detail-table">
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>Host</th>
                                    <th>Method</th>
                                    <th>URL / URI Path</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>${requestRows}</tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function toggleIPDetail(index) {
    const item = document.getElementById(`ip-item-${index}`);
    item.classList.toggle('expanded');
}

// ============================================================================
// CONFIGURATION TAB
// ============================================================================

async function loadConfiguration() {
    try {
        const config = await apiRequest('/api/admin/config');
        currentConfig = config;

        // Blocking configuration
        document.getElementById('blocking-enabled').checked = config.blocking.enabled || false;
        document.getElementById('blocking-mode').value = config.blocking.mode || 'log';
        document.getElementById('response-code').value = config.blocking.responseCode || 403;

        // Rate limiting
        document.getElementById('rate-limit-enabled').checked = config.blocking.rateLimitEnabled || false;
        document.getElementById('rate-limit-max').value = config.security.rateLimit.maxRequests || 100;
        document.getElementById('rate-limit-window').value = config.security.rateLimit.windowMs || 900000;

        // Auto-blocking
        document.getElementById('auto-block-violations').value = config.blocking.autoBlockAfterViolations || 5;
        document.getElementById('auto-block-duration').value = config.blocking.autoBlockDuration || 3600000;

        // GeoIP
        document.getElementById('geoip-enabled').checked = config.blocking.geoIPEnabled || false;
        document.getElementById('blocked-countries').value = (config.blocking.blockedCountries || []).join(',');
        document.getElementById('allowed-countries').value = (config.blocking.allowedCountries || []).join(',');
        document.getElementById('block-unknown-countries').checked = config.blocking.blockUnknownCountries || false;

        // Threat intelligence
        document.getElementById('threat-feeds-enabled').checked = config.blocking.threatFeedsEnabled || false;
        document.getElementById('abuseipdb-key').value = config.blocking.abuseIPDBKey || '';
        document.getElementById('threat-threshold').value = config.blocking.threatScoreThreshold || 75;
    } catch (error) {
        console.error('Error loading configuration:', error);
    }
}

async function saveConfiguration() {
    const config = {
        blocking: {
            enabled: document.getElementById('blocking-enabled').checked,
            mode: document.getElementById('blocking-mode').value,
            responseCode: parseInt(document.getElementById('response-code').value),
            rateLimitEnabled: document.getElementById('rate-limit-enabled').checked,
            autoBlockAfterViolations: parseInt(document.getElementById('auto-block-violations').value),
            autoBlockDuration: parseInt(document.getElementById('auto-block-duration').value),
            geoIPEnabled: document.getElementById('geoip-enabled').checked,
            blockedCountries: document.getElementById('blocked-countries').value.split(',').map(c => c.trim()).filter(c => c),
            allowedCountries: document.getElementById('allowed-countries').value.split(',').map(c => c.trim()).filter(c => c),
            blockUnknownCountries: document.getElementById('block-unknown-countries').checked,
            threatFeedsEnabled: document.getElementById('threat-feeds-enabled').checked,
            abuseIPDBKey: document.getElementById('abuseipdb-key').value,
            threatScoreThreshold: parseInt(document.getElementById('threat-threshold').value)
        },
        security: {
            rateLimit: {
                maxRequests: parseInt(document.getElementById('rate-limit-max').value),
                windowMs: parseInt(document.getElementById('rate-limit-window').value)
            }
        }
    };

    try {
        await apiRequest('/api/admin/config', {
            method: 'POST',
            body: JSON.stringify(config)
        });
        showToast('Configuration saved successfully. Restart server for some changes to take effect.', 'success');
    } catch (error) {
        showToast('Failed to save configuration', 'error');
    }
}

// ============================================================================
// BLACKLIST/WHITELIST MANAGEMENT
// ============================================================================

/**
 * Add IP to blacklist
 */
async function addToBlacklist(ip, event) {
    if (event) event.stopPropagation();
    
    if (!confirm(`Are you sure you want to add ${ip} to the blacklist?`)) {
        return;
    }

    try {
        await apiRequest('/api/admin/blacklist/add', {
            method: 'POST',
            body: JSON.stringify({ ip })
        });
        showToast(`IP ${ip} added to blacklist`, 'success');
        // Reload blocking rules to show updated list
        loadBlockingRules();
    } catch (error) {
        showToast(`Failed to add IP to blacklist: ${error.message}`, 'error');
    }
}

/**
 * Add IP to whitelist
 */
async function addToWhitelist(ip, event) {
    if (event) event.stopPropagation();
    
    if (!confirm(`Are you sure you want to add ${ip} to the whitelist?`)) {
        return;
    }

    try {
        await apiRequest('/api/admin/whitelist/add', {
            method: 'POST',
            body: JSON.stringify({ ip })
        });
        showToast(`IP ${ip} added to whitelist`, 'success');
        // Reload blocking rules to show updated list
        loadBlockingRules();
    } catch (error) {
        showToast(`Failed to add IP to whitelist: ${error.message}`, 'error');
    }
}

// ============================================================================
// THREAT INTELLIGENCE ANALYSIS
// ============================================================================

/**
 * Analyze IP using threat intelligence APIs
 */
async function analyzeThreatIntel(ip, event) {
    if (event) event.stopPropagation();

    // Find the IP item index from the current displayed list
    const ipItems = document.querySelectorAll('.ip-list-item');
    let targetIndex = -1;
    ipItems.forEach((item, idx) => {
        if (item.querySelector('.ip-address').textContent === ip) {
            targetIndex = idx;
        }
    });

    if (targetIndex === -1) {
        showToast('Could not find IP in list', 'error');
        return;
    }

    const resultDiv = document.getElementById(`threat-intel-${targetIndex}`);
    if (!resultDiv) {
        showToast('Could not find result container', 'error');
        return;
    }

    // Show loading state
    resultDiv.style.display = 'block';
    resultDiv.innerHTML = '<div class="loading-spinner"><i class="fas fa-spinner fa-spin"></i> Analyzing threat intelligence...</div>';

    try {
        const result = await apiRequest(`/api/admin/threat-intel/${ip}`);
        displayThreatIntelResults(result, resultDiv, ip);
    } catch (error) {
        resultDiv.innerHTML = `<div class="error-message"><i class="fas fa-exclamation-triangle"></i> Failed to analyze: ${escapeHtml(error.message)}</div>`;
    }
}

/**
 * Display threat intelligence results
 */
function displayThreatIntelResults(result, container, ip) {
    const score = result.combinedThreatScore || 0;
    const recommendation = result.recommendation || 'UNKNOWN';

    // Determine threat level color
    let scoreClass = 'safe';
    if (score >= 85) scoreClass = 'critical';
    else if (score >= 50) scoreClass = 'warning';

    let html = `
        <div class="threat-intel-report">
            <div class="threat-header">
                <h4><i class="fas fa-shield-virus"></i> Threat Intelligence Report for ${escapeHtml(ip)}</h4>
                <div class="threat-score ${scoreClass}">
                    <span class="score-value">${score}</span>
                    <span class="score-label">Threat Score</span>
                </div>
            </div>
            
            <div class="threat-recommendation ${recommendation.toLowerCase()}">
                <strong>Recommendation:</strong> ${escapeHtml(recommendation)}
            </div>

            <div class="threat-summary">
                <p><strong>Country:</strong> ${escapeHtml(result.summary.country)}</p>
                <p><strong>ISP:</strong> ${escapeHtml(result.summary.isp)}</p>
                <p><strong>Tags:</strong> ${result.summary.tags.length > 0 ? result.summary.tags.map(t => `<span class="tag">${escapeHtml(t)}</span>`).join(' ') : 'None'}</p>
            </div>

            <div class="threat-sources">
                <h5>Intelligence Sources</h5>
    `;

    // AbuseIPDB
    if (result.sources.abuseipdb.available) {
        const abuseDB = result.sources.abuseipdb;
        html += `
            <div class="source-result">
                <h6><i class="fas fa-database"></i> AbuseIPDB</h6>
                <p>Abuse Score: <strong>${abuseDB.score}%</strong></p>
                <p>Total Reports: ${abuseDB.reports}</p>
                <p>Usage Type: ${escapeHtml(abuseDB.usageType)}</p>
                ${abuseDB.isWhitelisted ? '<p class="text-success">✓ Whitelisted on AbuseIPDB</p>' : ''}
            </div>
        `;
    } else {
        html += `<div class="source-result"><h6><i class="fas fa-database"></i> AbuseIPDB</h6><p class="text-muted">Not available</p></div>`;
    }

    // AlienVault OTX
    if (result.sources.otx.available) {
        const otx = result.sources.otx;
        html += `
            <div class="source-result">
                <h6><i class="fas fa-satellite"></i> AlienVault OTX</h6>
                <p>Pulse Count: <strong>${otx.pulseCount}</strong></p>
                <p>Threat Score: ${otx.threatScore}%</p>
                ${otx.pulses.length > 0 ? `
                    <p>Recent Pulses:</p>
                    <ul>
                        ${otx.pulses.slice(0, 3).map(p => `<li>${escapeHtml(p.name)}</li>`).join('')}
                    </ul>
                ` : ''}
            </div>
        `;
    } else {
        html += `<div class="source-result"><h6><i class="fas fa-satellite"></i> AlienVault OTX</h6><p class="text-muted">Not available</p></div>`;
    }

    // VirusTotal
    if (result.sources.virustotal.available) {
        const vt = result.sources.virustotal;
        html += `
            <div class="source-result">
                <h6><i class="fas fa-virus"></i> VirusTotal</h6>
                <p>Malicious Detections: <strong class="text-danger">${vt.malicious}</strong></p>
                <p>Suspicious Detections: <strong class="text-warning">${vt.suspicious}</strong></p>
                <p>Harmless: ${vt.harmless} | Undetected: ${vt.undetected}</p>
                <p>Threat Score: ${vt.threatScore}%</p>
            </div>
        `;
    } else {
        html += `<div class="source-result"><h6><i class="fas fa-virus"></i> VirusTotal</h6><p class="text-muted">Not available</p></div>`;
    }

    html += `
            </div>
            
            <div class="threat-actions" style="margin-top: 15px; display: flex; gap: 10px;">
                ${recommendation === 'BLACKLIST' ? `
                    <button class="btn-danger" onclick="addToBlacklist('${escapeHtml(ip)}', event)">
                        <i class="fas fa-ban"></i> Add to Blacklist (Recommended)
                    </button>
                ` : ''}
                <button class="btn-secondary" onclick="document.getElementById('threat-intel-${container.id.split('-')[2]}').style.display='none'">
                    <i class="fas fa-times"></i> Close
                </button>
            </div>
        </div>
    `;

    container.innerHTML = html;
}

// ============================================================================
// INITIALIZATION
// ============================================================================

// Load dashboard on page load
document.addEventListener('DOMContentLoaded', () => {
    loadDashboard();

    // Auto-refresh dashboard every 30 seconds
    setInterval(() => {
        const activeTab = document.querySelector('.tab-button.active').getAttribute('data-tab');
        if (activeTab === 'dashboard') {
            loadDashboard();
        }
    }, 30000);
});
