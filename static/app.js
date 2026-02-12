/**
 * ServerControl - Frontend Application
 * ====================================
 * Handles server management UI interactions,
 * API communication, and real-time updates
 */

// ============================================
// CONFIGURATION
// ============================================

const CONFIG = {
    // API endpoints
    API_BASE: '/api',
    ENDPOINTS: {
        SERVERS: '/api/servers',
        START: '/api/servers/{id}/start',
        STOP: '/api/servers/{id}/stop',
        RESTART: '/api/servers/{id}/restart',
        STATUS: '/api/servers/{id}/status'
    },

    // Refresh settings
    REFRESH_INTERVAL: 3000,  // 3 seconds

    // Toast settings
    TOAST_DURATION: 4000,    // 4 seconds

    // Metric thresholds
    METRIC_THRESHOLDS: {
        LOW: 40,
        MEDIUM: 70
    }
};

// ============================================
// STATE MANAGEMENT
// ============================================

const state = {
    servers: [],
    autoRefresh: true,
    refreshTimer: null,
    isLoading: false,
    connectionStatus: 'connected'
};

// ============================================
// DOM ELEMENTS
// ============================================

const elements = {
    serversGrid: document.getElementById('serversGrid'),
    loadingState: document.getElementById('loadingState'),
    emptyState: document.getElementById('emptyState'),
    errorState: document.getElementById('errorState'),
    onlineCount: document.getElementById('onlineCount'),
    offlineCount: document.getElementById('offlineCount'),
    totalCount: document.getElementById('totalCount'),
    lastUpdateTime: document.getElementById('lastUpdateTime'),
    autoRefreshToggle: document.getElementById('autoRefreshToggle'),
    refreshBtn: document.getElementById('refreshBtn'),
    toastContainer: document.getElementById('toastContainer'),
    connectionStatus: document.getElementById('connectionStatus'),
    confirmModal: document.getElementById('confirmModal'),
    loadingOverlay: document.getElementById('loadingOverlay'),
    footerStatusDot: document.getElementById('footerStatusDot'),
    footerStatusText: document.getElementById('footerStatusText')
};

// ============================================
// INITIALIZATION
// ============================================

/**
 * Initialize the application
 */
function init() {
    console.log('🚀 ServerControl initialized');

    // Setup event listeners
    setupEventListeners();

    // Load initial server data
    loadServers();

    // Start auto-refresh
    startAutoRefresh();
}

/**
 * Setup event listeners
 */
function setupEventListeners() {
    // Auto-refresh toggle
    if (elements.autoRefreshToggle) {
        elements.autoRefreshToggle.addEventListener('change', (e) => {
            state.autoRefresh = e.target.checked;
            if (state.autoRefresh) {
                startAutoRefresh();
                showToast('success', 'Auto-refresh enabled', 'Servers will update every 3 seconds');
            } else {
                stopAutoRefresh();
                showToast('info', 'Auto-refresh disabled', 'Click refresh to update manually');
            }
        });
    }

    // Manual refresh button
    if (elements.refreshBtn) {
        elements.refreshBtn.addEventListener('click', () => {
            loadServers();
            animateButton(elements.refreshBtn);
        });
    }

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        // R key to refresh
        if (e.key === 'r' && !e.ctrlKey && !e.metaKey) {
            const activeElement = document.activeElement;
            if (activeElement.tagName !== 'INPUT' && activeElement.tagName !== 'TEXTAREA') {
                loadServers();
            }
        }
    });
}

// ============================================
// API COMMUNICATION
// ============================================

/**
 * Make API request with error handling
 * @param {string} url - API endpoint URL
 * @param {Object} options - Fetch options
 * @returns {Promise<Object>} Response data
 */
async function apiRequest(url, options = {}) {
    try {
        const response = await fetch(url, {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        });

        // Handle authentication errors
        if (response.status === 401) {
            window.location.href = '/login';
            return null;
        }

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Request failed');
        }

        return data;
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

/**
 * Load all servers from API
 */
async function loadServers() {
    if (state.isLoading) return;

    state.isLoading = true;

    try {
        // Show loading state on first load
        if (state.servers.length === 0) {
            showLoadingState();
        }

        const servers = await apiRequest(CONFIG.ENDPOINTS.SERVERS);

        if (servers) {
            state.servers = servers;
            state.connectionStatus = 'connected';
            updateConnectionStatus(true);
            renderServers();
            updateStats();
            updateLastUpdateTime();
        }
    } catch (error) {
        state.connectionStatus = 'disconnected';
        updateConnectionStatus(false);

        if (state.servers.length === 0) {
            showErrorState();
        } else {
            showToast('error', 'Connection Error', 'Failed to refresh server data');
        }
    } finally {
        state.isLoading = false;
    }
}

/**
 * Start a server
 * @param {string} serverId - Server ID
 */
async function startServer(serverId) {
    const server = state.servers.find(s => s.id === serverId);
    if (!server) return;

    const url = CONFIG.ENDPOINTS.START.replace('{id}', serverId);

    try {
        setServerProcessing(serverId, true);
        showToast('info', 'Starting Server', `Starting ${server.name}...`);

        const result = await apiRequest(url, { method: 'POST' });

        if (result && result.success) {
            showToast('success', 'Server Started', result.message);
            await loadServers();
        }
    } catch (error) {
        showToast('error', 'Start Failed', error.message || 'Failed to start server');
    } finally {
        setServerProcessing(serverId, false);
    }
}

/**
 * Stop a server
 * @param {string} serverId - Server ID
 */
async function stopServer(serverId) {
    const server = state.servers.find(s => s.id === serverId);
    if (!server) return;

    const url = CONFIG.ENDPOINTS.STOP.replace('{id}', serverId);

    try {
        setServerProcessing(serverId, true);
        showToast('info', 'Stopping Server', `Stopping ${server.name}...`);

        const result = await apiRequest(url, { method: 'POST' });

        if (result && result.success) {
            showToast('success', 'Server Stopped', result.message);
            await loadServers();
        }
    } catch (error) {
        showToast('error', 'Stop Failed', error.message || 'Failed to stop server');
    } finally {
        setServerProcessing(serverId, false);
    }
}

/**
 * Restart a server
 * @param {string} serverId - Server ID
 */
async function restartServer(serverId) {
    const server = state.servers.find(s => s.id === serverId);
    if (!server) return;

    const url = CONFIG.ENDPOINTS.RESTART.replace('{id}', serverId);

    try {
        setServerProcessing(serverId, true);
        showToast('info', 'Restarting Server', `Restarting ${server.name}...`);

        const result = await apiRequest(url, { method: 'POST' });

        if (result && result.success) {
            showToast('success', 'Server Restarted', result.message);
            await loadServers();
        }
    } catch (error) {
        showToast('error', 'Restart Failed', error.message || 'Failed to restart server');
    } finally {
        setServerProcessing(serverId, false);
    }
}

// ============================================
// UI RENDERING
// ============================================

/**
 * Render all server cards
 */
function renderServers() {
    // Hide loading/error states
    hideAllStates();

    // Check for empty state
    if (state.servers.length === 0) {
        showEmptyState();
        return;
    }

    // Generate HTML for all server cards
    const cardsHtml = state.servers.map(server => createServerCard(server)).join('');

    // Update grid
    elements.serversGrid.innerHTML = cardsHtml;

    // Add event listeners to buttons
    attachButtonListeners();
}

/**
 * Create HTML for a server card
 * @param {Object} server - Server data
 * @returns {string} HTML string
 */
function createServerCard(server) {
    const isOnline = server.status === 'online';
    const statusClass = isOnline ? 'online' : 'offline';
    const statusText = isOnline ? 'Online' : 'Offline';

    // Determine metric bar levels
    const cpuLevel = getMetricLevel(server.cpu);
    const ramLevel = getMetricLevel(server.ram);

    return `
        <div class="server-card ${statusClass}" data-server-id="${server.id}">
            <!-- Card Header -->
            <div class="card-header">
                <div class="card-info">
                    <h3 class="server-name" title="${server.name}">${escapeHtml(server.name)}</h3>
                    <div class="server-meta">
                        <span class="server-type">
                            <span class="type-icon">${getServerTypeIcon(server.type)}</span>
                            ${escapeHtml(server.type)}
                        </span>
                        <span class="server-ip">${escapeHtml(server.ip)}</span>
                    </div>
                </div>
                <div class="card-status">
                    <span class="status-badge ${statusClass}">
                        <span class="badge-dot"></span>
                        ${statusText}
                    </span>
                </div>
            </div>

            <!-- Card Metrics -->
            <div class="card-metrics">
                <div class="metric">
                    <div class="metric-header">
                        <span class="metric-label">
                            <span class="metric-icon">💻</span>
                            CPU
                        </span>
                        <span class="metric-value">${isOnline ? server.cpu : 0}%</span>
                    </div>
                    <div class="metric-bar">
                        <div class="metric-bar-fill ${cpuLevel}" style="width: ${isOnline ? server.cpu : 0}%"></div>
                    </div>
                </div>
                <div class="metric">
                    <div class="metric-header">
                        <span class="metric-label">
                            <span class="metric-icon">🧠</span>
                            RAM
                        </span>
                        <span class="metric-value">${isOnline ? server.ram : 0}%</span>
                    </div>
                    <div class="metric-bar">
                        <div class="metric-bar-fill ${ramLevel}" style="width: ${isOnline ? server.ram : 0}%"></div>
                    </div>
                </div>
            </div>

            <!-- Card Actions -->
            <div class="card-actions">
                <button
                    class="btn btn-success"
                    data-action="start"
                    data-server-id="${server.id}"
                    ${isOnline ? 'disabled' : ''}
                    title="Start server"
                >
                    <span class="icon">▶️</span>
                    <span class="text">Start</span>
                </button>
                <button
                    class="btn btn-danger"
                    data-action="stop"
                    data-server-id="${server.id}"
                    ${!isOnline ? 'disabled' : ''}
                    title="Stop server"
                >
                    <span class="icon">⏹️</span>
                    <span class="text">Stop</span>
                </button>
                <button
                    class="btn btn-warning"
                    data-action="restart"
                    data-server-id="${server.id}"
                    title="Restart server"
                >
                    <span class="icon">🔄</span>
                    <span class="text">Restart</span>
                </button>
            </div>
        </div>
    `;
}

/**
 * Attach event listeners to action buttons
 */
function attachButtonListeners() {
    const buttons = elements.serversGrid.querySelectorAll('[data-action]');

    buttons.forEach(button => {
        button.addEventListener('click', async (e) => {
            e.preventDefault();

            if (button.disabled) return;

            const action = button.dataset.action;
            const serverId = button.dataset.serverId;

            switch (action) {
                case 'start':
                    await startServer(serverId);
                    break;
                case 'stop':
                    await stopServer(serverId);
                    break;
                case 'restart':
                    await restartServer(serverId);
                    break;
            }
        });
    });
}

/**
 * Get icon for server type
 * @param {string} type - Server type
 * @returns {string} Emoji icon
 */
function getServerTypeIcon(type) {
    const icons = {
        'Web Server': '🌐',
        'Database': '🗄️',
        'Gateway': '🚪',
        'Redis': '⚡',
        'Storage': '💾',
        'Email': '📧',
        'Monitoring': '📊',
        'default': '🖥️'
    };
    return icons[type] || icons['default'];
}

/**
 * Get metric level class based on value
 * @param {number} value - Metric value (0-100)
 * @returns {string} Level class
 */
function getMetricLevel(value) {
    if (value < CONFIG.METRIC_THRESHOLDS.LOW) return 'low';
    if (value < CONFIG.METRIC_THRESHOLDS.MEDIUM) return 'medium';
    return 'high';
}

// ============================================
// UI STATE MANAGEMENT
// ============================================

/**
 * Show loading state
 */
function showLoadingState() {
    elements.loadingState?.classList.remove('hidden');
    elements.emptyState?.classList.add('hidden');
    elements.errorState?.classList.add('hidden');
}

/**
 * Show empty state
 */
function showEmptyState() {
    elements.loadingState?.classList.add('hidden');
    elements.emptyState?.classList.remove('hidden');
    elements.errorState?.classList.add('hidden');
}

/**
 * Show error state
 */
function showErrorState() {
    elements.loadingState?.classList.add('hidden');
    elements.emptyState?.classList.add('hidden');
    elements.errorState?.classList.remove('hidden');
}

/**
 * Hide all states
 */
function hideAllStates() {
    elements.loadingState?.classList.add('hidden');
    elements.emptyState?.classList.add('hidden');
    elements.errorState?.classList.add('hidden');
}

/**
 * Set server card processing state
 * @param {string} serverId - Server ID
 * @param {boolean} processing - Is processing
 */
function setServerProcessing(serverId, processing) {
    const card = document.querySelector(`[data-server-id="${serverId}"]`);
    if (card) {
        if (processing) {
            card.classList.add('processing');
        } else {
            card.classList.remove('processing');
        }
    }
}

/**
 * Update connection status indicator
 * @param {boolean} connected - Is connected
 */
function updateConnectionStatus(connected) {
    const statusDot = elements.connectionStatus?.querySelector('.status-dot');
    const statusText = elements.connectionStatus?.querySelector('.status-text');

    if (statusDot) {
        statusDot.className = `status-dot ${connected ? 'online' : 'offline'}`;
    }

    if (statusText) {
        statusText.textContent = connected ? 'Connected' : 'Disconnected';
    }

    // Update footer status
    if (elements.footerStatusDot) {
        elements.footerStatusDot.className = `status-dot ${connected ? 'online' : 'offline'}`;
    }

    if (elements.footerStatusText) {
        elements.footerStatusText.textContent = connected ? 'System Operational' : 'Connection Lost';
    }
}

/**
 * Update server statistics
 */
function updateStats() {
    const online = state.servers.filter(s => s.status === 'online').length;
    const offline = state.servers.filter(s => s.status === 'offline').length;
    const total = state.servers.length;

    if (elements.onlineCount) {
        animateCounter(elements.onlineCount, parseInt(elements.onlineCount.textContent) || 0, online);
    }

    if (elements.offlineCount) {
        animateCounter(elements.offlineCount, parseInt(elements.offlineCount.textContent) || 0, offline);
    }

    if (elements.totalCount) {
        animateCounter(elements.totalCount, parseInt(elements.totalCount.textContent) || 0, total);
    }
}

/**
 * Update last update time display
 */
function updateLastUpdateTime() {
    if (elements.lastUpdateTime) {
        const now = new Date();
        const timeString = now.toLocaleTimeString();
        elements.lastUpdateTime.textContent = timeString;
    }
}

// ============================================
// AUTO-REFRESH
// ============================================

/**
 * Start auto-refresh timer
 */
function startAutoRefresh() {
    if (state.refreshTimer) {
        clearInterval(state.refreshTimer);
    }

    if (state.autoRefresh) {
        state.refreshTimer = setInterval(() => {
            loadServers();
        }, CONFIG.REFRESH_INTERVAL);

        console.log(`⏰ Auto-refresh started (${CONFIG.REFRESH_INTERVAL / 1000}s interval)`);
    }
}

/**
 * Stop auto-refresh timer
 */
function stopAutoRefresh() {
    if (state.refreshTimer) {
        clearInterval(state.refreshTimer);
        state.refreshTimer = null;
        console.log('⏰ Auto-refresh stopped');
    }
}

/**
 * Refresh servers manually
 */
function refreshServers() {
    loadServers();
}

// ============================================
// TOAST NOTIFICATIONS
// ============================================

/**
 * Show a toast notification
 * @param {string} type - Toast type (success, error, warning, info)
 * @param {string} title - Toast title
 * @param {string} message - Toast message
 */
function showToast(type, title, message) {
    const icons = {
        success: '✅',
        error: '❌',
        warning: '⚠️',
        info: 'ℹ️'
    };

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || icons.info}</span>
        <div class="toast-content">
            <div class="toast-title">${escapeHtml(title)}</div>
            <div class="toast-message">${escapeHtml(message)}</div>
        </div>
        <button class="toast-close" onclick="this.parentElement.remove()">&times;</button>
        <div class="toast-progress"></div>
    `;

    elements.toastContainer.appendChild(toast);

    // Auto-remove after duration
    setTimeout(() => {
        toast.classList.add('removing');
        setTimeout(() => toast.remove(), 300);
    }, CONFIG.TOAST_DURATION);
}

// ============================================
// MODAL DIALOGS
// ============================================

/**
 * Show confirmation modal
 * @param {string} title - Modal title
 * @param {string} message - Modal message
 * @param {Function} onConfirm - Callback on confirm
 */
function showConfirmModal(title, message, onConfirm) {
    const modal = elements.confirmModal;
    const modalTitle = document.getElementById('modalTitle');
    const modalMessage = document.getElementById('modalMessage');
    const confirmBtn = document.getElementById('modalConfirmBtn');

    if (modalTitle) modalTitle.textContent = title;
    if (modalMessage) modalMessage.textContent = message;

    if (confirmBtn) {
        confirmBtn.onclick = () => {
            closeModal();
            onConfirm();
        };
    }

    modal?.classList.remove('hidden');
}

/**
 * Close modal dialog
 */
function closeModal() {
    elements.confirmModal?.classList.add('hidden');
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

/**
 * Escape HTML special characters
 * @param {string} text - Text to escape
 * @returns {string} Escaped text
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Animate button click
 * @param {HTMLElement} button - Button element
 */
function animateButton(button) {
    button.classList.add('loading');
    setTimeout(() => button.classList.remove('loading'), 500);
}

/**
 * Animate counter from one value to another
 * @param {HTMLElement} element - Element to update
 * @param {number} from - Start value
 * @param {number} to - End value
 */
function animateCounter(element, from, to) {
    const duration = 500;
    const start = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - start;
        const progress = Math.min(elapsed / duration, 1);

        const current = Math.round(from + (to - from) * progress);
        element.textContent = current;

        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }

    requestAnimationFrame(update);
}

// ============================================
// INITIALIZE ON DOM READY
// ============================================

// Wait for DOM to be ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}

// Expose functions globally for inline handlers
window.refreshServers = refreshServers;
window.closeModal = closeModal;
window.loadServers = loadServers;
