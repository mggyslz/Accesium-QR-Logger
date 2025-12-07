// Security Configuration
const SECURITY_CONFIG = {
    sessionTimeout: 30 * 60 * 1000,           // Keep at 30 minutes
    warningTime: 2 * 60 * 1000,               // Keep at 2 minutes
    inactivityCheckInterval: 60000,           // Keep at 1 minute
    apiRateLimit: 200,                        // Keep at 200 ms between API calls
    maxFailedAttempts: 5,                     // Keep at 5 attempts
    lockoutDuration: 15 * 60 * 1000          // Keep at 15 minutes
};

// SSE Connection Management
let adminEventSource = null;
let reconnectTimeout = null;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 5;
const RECONNECT_DELAY = 3000;
let attendanceNeedsRefresh = false;
let lastAttendanceUpdate = 0;
const ATTENDANCE_UPDATE_COOLDOWN = 2000;

function getTimeAgo(timestamp) {
    const now = new Date();
    const activityTime = new Date(timestamp);
    const diffMs = now - activityTime;
    const diffSecs = Math.floor(diffMs / 1000);
    const diffMins = Math.floor(diffSecs / 60);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);
    
    if (diffSecs < 60) return 'Just now';
    if (diffMins < 60) return `${diffMins} minute${diffMins !== 1 ? 's' : ''} ago`;
    if (diffHours < 24) return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`;
    return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`;
}

let securityState = {
    lastActivity: Date.now(),
    sessionTimer: null,
    warningTimer: null,
    failedAttempts: 0,
    lastApiCall: 0,
    isLocked: false
};

function getCSRFToken() {
    const metaTag = document.querySelector('meta[name="csrf-token"]');
    return metaTag ? metaTag.getAttribute('content') : '';
}

function createFormDataWithCSRF() {
    const fd = new FormData();
    const csrfToken = getCSRFToken();
    if (csrfToken) {
        fd.append('csrf_token', csrfToken);
    }
    return fd;
}

let currentPage = 1;
let totalPages = 1;
const recordsPerPage = 10;
let lastLogId = 0;
let attendanceLoaded = false;
let isLoading = false;

// Add these variables at the top of admin.js (near the existing pagination variables)
let currentUserPage = 1;
let totalUserPages = 1;
const usersPerPage = 10;
let isLoadingUsers = false;
let allUsersCache = []; // Cache all users for filtering


function formatDateTime(timestamp) {
    if (!timestamp) return { date: '--', time: '--' };
    
    // Split timestamp into date and time parts
    // Expected format from backend: "2025-01-15 02:30:45 PM"
    const parts = timestamp.split(' ');
    
    if (parts.length >= 3) {
        return {
            date: parts[0],                    // "2025-01-15"
            time: `${parts[1]} ${parts[2]}`    // "02:30:45 PM"
        };
    } else if (parts.length === 2) {
        return {
            date: parts[0],
            time: parts[1]
        };
    }
    
    return { date: timestamp, time: '--' };
}


document.addEventListener('DOMContentLoaded', function () {
    initializeSecurity();
    initializeDarkMode();
    initializeAdminSSE(); // Initialize real-time updates

    document.getElementById('addUserForm').addEventListener('submit', async function (e) {
        e.preventDefault();

        if (!checkRateLimit()) {
            showNotification('Please wait before making another request', 'Rate Limit Exceeded', 'warning');
            return;
        }

        // NO USERNAME INPUT - it will be auto-generated from name
        const email = document.getElementById('add_email').value.trim();
        const name = document.getElementById('add_name').value.trim();
        const role = document.getElementById('add_role').value;

        if (!email || !name || !role) {
            alert('All fields are required');
            return;
        }

        if (!email.includes('@')) {
            alert('Please enter a valid email address');
            return;
        }

        if (name.length < 3) {
            alert('Full name must be at least 3 characters');
            return;
        }

        if (!document.getElementById('notification-animations')) {
            const style = document.createElement('style');
            style.id = 'notification-animations';
            style.textContent = `
                @keyframes slideInRight {
                    from { 
                        opacity: 0;
                        transform: translateX(400px);
                    }
                    to { 
                        opacity: 1;
                        transform: translateX(0);
                    }
                }
            `;
            document.head.appendChild(style);
        }

        const button = e.target.querySelector('button[type="submit"]');
        const originalText = button.textContent;
        button.disabled = true;
        button.innerHTML = '<span class="loading"></span> Creating...';

        try {
            const fd = createFormDataWithCSRF();
            fd.append('email', email);
            fd.append('name', name);
            fd.append('role', role);

            const res = await fetch(API_URLS.addUser, {
                method: 'POST',
                body: fd
            });

            const json = await res.json();

            if (json.status === 'success') {
                const generatedUsername = json.username || 'auto-generated';
                const generatedPIN = json.pin || 'N/A';

                // Show notification with username AND PIN
                showNotification(
                    json.message +
                    `<br><strong>Username:</strong> ${json.username}` +
                    `<br><strong>QR PIN:</strong> <span style="font-family: 'Courier New', monospace; font-size: 18px; letter-spacing: 2px; color: #dc3545; font-weight: bold;">${generatedPIN}</span>` +
                    `<br><small style="color: #666;">PIN has been emailed to user</small>`,
                    'User Created Successfully ✓',
                    'success'
                );
                document.getElementById('addUserForm').reset();
                logSecurityEvent('USER_CREATED', `Created user: ${name} (${generatedUsername}) with PIN: ${generatedPIN}`);

                // Don't auto-reload immediately so admin can see the PIN
                setTimeout(() => location.reload(), 8000); // 8 seconds instead of 2
            } else {
                alert('Error: ' + json.message);
            }
        } catch (err) {
            alert('Failed to create user: ' + err.message);
        } finally {
            button.disabled = false;
            button.textContent = originalText;
        }
    });

    document.getElementById('filterDateFrom').valueAsDate = new Date();
    document.getElementById('filterDateTo').valueAsDate = new Date();

    autoRefresh();
});

document.addEventListener('DOMContentLoaded', function () {
    const logoutForms = document.querySelectorAll('form[action*="logout"]');

    logoutForms.forEach(form => {
        form.addEventListener('submit', function (e) {
            // Don't prevent default - let the form submit normally
            if (!confirm('Are you sure you want to logout?')) {
                e.preventDefault();
                return false;
            }
            // If confirmed, let the form submit naturally
            this.dataset.submitting = 'true';
        });
    });
});

async function loadUsers(page = 1) {
    if (isLoadingUsers) return;
    isLoadingUsers = true;
    
    document.getElementById('prevUserBtn').disabled = true;
    document.getElementById('nextUserBtn').disabled = true;

    try {
        const search = document.getElementById('searchInput').value.toLowerCase();
        
        let filteredUsers = allUsersCache;
        
        if (search) {
            filteredUsers = allUsersCache.filter(user => {
                const name = user.name.toLowerCase();
                const role = user.role.toLowerCase();
                return name.includes(search) || role.includes(search);
            });
        }
        
        const totalRecords = filteredUsers.length;
        totalUserPages = Math.max(1, Math.ceil(totalRecords / usersPerPage));
        currentUserPage = Math.min(page, totalUserPages);
        
        const startIndex = (currentUserPage - 1) * usersPerPage;
        const endIndex = startIndex + usersPerPage;
        const pageUsers = filteredUsers.slice(startIndex, endIndex);
        
        const tbody = document.getElementById('usersTbody');
        tbody.innerHTML = '';
        
        if (pageUsers.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No users found</td></tr>';
        } else {
            pageUsers.forEach(user => {
                const tr = document.createElement('tr');
                tr.setAttribute('data-name', user.name.toLowerCase());
                tr.setAttribute('data-role', user.role.toLowerCase());
                
                let qrCell = '';
                if (user.qr_filename) {
                    qrCell = `
                        <img src="/static/qrcodes/${user.qr_filename}" alt="QR Code" class="qr" onerror="this.src='/static/img/no_qr.png'">
                        <br>
                        <a href="/static/qrcodes/${user.qr_filename}" download="${user.name.replace(/ /g, '_')}_QR.png" style="font-size:12px;color:#666;">Download</a>
                    `;
                } else {
                    qrCell = '<img src="/static/img/no_qr.png" alt="No QR" class="qr">';
                }
                
                const escapedName = user.name.replace(/'/g, "\\'");
                const escapedEmail = (user.email || '').replace(/'/g, "\\'");
                
                tr.innerHTML = `
                    <td><code style="background:#f0f0f0;padding:2px 6px;border-radius:3px;font-size:12px;">${user.username}</code></td>
                    <td><strong>${user.name}</strong></td>
                    <td>${user.role}</td>
                    <td style="font-size: 13px; color: #666;">${user.email || 'No email'}</td>
                    <td>${user.status}</td>
                    <td>${qrCell}</td>
                    <td>
                        <button class="btn btn-secondary" 
                                onclick="editUser(${user.user_id}, '${escapedName}', '${user.role}', '${escapedEmail}')" 
                                style="margin-right: 8px;">
                            Edit
                        </button>
                        <button class="btn btn-secondary" 
                                onclick="resetUserPassword(${user.user_id}, '${escapedName}', '${escapedEmail}')" 
                                style="margin-right: 8px;">
                            Reset Password
                        </button>
                        <button class="btn btn-danger" 
                                onclick="deleteUser(${user.user_id})">
                            Delete
                        </button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        }
        
        document.getElementById('userPageInfo').textContent = `Page ${currentUserPage} of ${totalUserPages}`;
        document.getElementById('prevUserBtn').disabled = currentUserPage <= 1;
        document.getElementById('nextUserBtn').disabled = currentUserPage >= totalUserPages;
        
    } catch (err) {
        console.error('Failed to load users:', err);
        document.getElementById('usersTbody').innerHTML = `<tr><td colspan="7" class="empty-state">Error loading users: ${err.message}</td></tr>`;
    } finally {
        isLoadingUsers = false;
    }
}

document.addEventListener('DOMContentLoaded', function() {
    // Cache all users from the rendered HTML
    const userRows = document.querySelectorAll('#usersTbody tr[data-name]');
    allUsersCache = Array.from(userRows).map(row => {
        const cells = row.querySelectorAll('td');
        
        // Extract user_id from the delete button's onclick attribute
        const deleteBtn = row.querySelector('button.btn-danger');
        const onclickAttr = deleteBtn ? deleteBtn.getAttribute('onclick') : '';
        const userIdMatch = onclickAttr.match(/deleteUser\((\d+)\)/);
        const userId = userIdMatch ? parseInt(userIdMatch[1]) : 0;
        
        return {
            user_id: userId,
            username: cells[0].textContent.trim(),  // Now first column
            name: cells[1].textContent.trim(),
            role: cells[2].textContent.trim(),
            email: cells[3].textContent.trim(),
            status: cells[4].textContent.trim(),
            qr_filename: row.querySelector('img.qr')?.src.includes('qrcodes/') 
                ? row.querySelector('img.qr').src.split('qrcodes/')[1] 
                : null
        };
    });
    
    // Initialize pagination if users exist
    if (allUsersCache.length > 0) {
        loadUsers(1);
    }
});

async function checkSessionStatus() {
    try {
        const response = await fetch('/admin/stats', {  // Use an admin endpoint
            method: 'GET',
            credentials: 'include'
        });

        if (response.status === 401 || response.status === 403) {
            // Session expired
            showNotification('Your session has expired. Redirecting to login...', 'Session Expired', 'warning');
            setTimeout(() => {
                window.location.href = API_URLS.authLogin;
            }, 2000);
            return false;
        }
        
        return true;
    } catch (error) {
        console.error('Session check failed:', error);
        // Don't redirect on network errors
        return true;
    }
}

// Check session every 2 minutes
setInterval(checkSessionStatus, 2 * 60 * 1000);

// Prevent back button after logout
window.addEventListener('pageshow', function (event) {
    // Check if page was loaded from cache (back/forward button)
    if (event.persisted || (window.performance && window.performance.navigation.type === 2)) {
        // Check if we're on a protected page without a session
        const isProtectedPage = window.location.pathname.includes('/admin/') ||
            window.location.pathname.includes('/user/dashboard');

        if (isProtectedPage) {
            // Force reload to check session status
            window.location.reload();
        }
    }
});

// Clear sensitive data on page unload (logout)
window.addEventListener('beforeunload', function (e) {
    // Check if this is a logout action
    if (document.querySelector('form[action*="logout"]')?.dataset.submitting === 'true') {
        // Clear any cached data
        if (window.sessionStorage) {
            sessionStorage.clear();
        }
        if (window.localStorage) {
            // Only clear app-specific data, not trusted device tokens
            const keysToKeep = ['user_device_token', 'admin_device_token'];
            Object.keys(localStorage).forEach(key => {
                if (!keysToKeep.includes(key)) {
                    localStorage.removeItem(key);
                }
            });
        }
    }
});

// Mark form as submitting when logout is clicked
document.addEventListener('DOMContentLoaded', function () {
    const logoutForms = document.querySelectorAll('form[action*="logout"]');

    logoutForms.forEach(form => {
        form.addEventListener('submit', function (e) {
            this.dataset.submitting = 'true';
        });
    });
});

function initializeSecurity() {
    document.addEventListener('mousemove', resetSessionTimer);
    document.addEventListener('keypress', resetSessionTimer);
    document.addEventListener('click', resetSessionTimer);
    document.addEventListener('scroll', resetSessionTimer);

    startSessionTimer();
    setInterval(checkSecurityStatus, SECURITY_CONFIG.inactivityCheckInterval);
}

function startSessionTimer() {
    if (securityState.sessionTimer) clearTimeout(securityState.sessionTimer);
    if (securityState.warningTimer) clearTimeout(securityState.warningTimer);

    securityState.warningTimer = setTimeout(showSessionWarning,
        SECURITY_CONFIG.sessionTimeout - SECURITY_CONFIG.warningTime);

    securityState.sessionTimer = setTimeout(logoutUser, SECURITY_CONFIG.sessionTimeout);
}

function resetSessionTimer() {
    securityState.lastActivity = Date.now();
    startSessionTimer();
}

function showSessionWarning() {
    document.getElementById('sessionTimeoutWarning').classList.remove('section-hidden');

    let timeLeft = SECURITY_CONFIG.warningTime / 1000;
    const countdownElement = document.getElementById('countdown');

    const countdownInterval = setInterval(() => {
        timeLeft--;
        const minutes = Math.floor(timeLeft / 60);
        const seconds = timeLeft % 60;
        countdownElement.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;

        if (timeLeft <= 0) {
            clearInterval(countdownInterval);
        }
    }, 1000);
}

function extendSession() {
    document.getElementById('sessionTimeoutWarning').classList.add('section-hidden');

    const fd = createFormDataWithCSRF();
    
    fetch(API_URLS.extendSession, {  // Changed from resendCode to extendSession
        method: 'POST',
        body: fd
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            resetSessionTimer();
            showNotification('Session extended successfully', 'Session Extended');
        } else {
            throw new Error(data.message || 'Failed to extend session');
        }
    })
    .catch(error => {
        console.error('Error extending session:', error);
        showNotification('Failed to extend session: ' + error.message, 'Error', 'danger');
    });
}

function logoutUser() {
    window.location.href = API_URLS.authLogout;
}

function checkRateLimit() {
    const now = Date.now();
    if (now - securityState.lastApiCall < SECURITY_CONFIG.apiRateLimit) {
        return false;
    }
    securityState.lastApiCall = now;
    return true;
}


function checkSecurityStatus() {
    // Periodic security check placeholder
}

function logSecurityEvent(action, details) {
    console.log(`Security Event: ${action} - ${details}`);

    const auditLog = document.getElementById('securityAuditLog');
    if (auditLog) {
        const now = new Date();
        const timeString = now.toLocaleTimeString();

        const entry = document.createElement('div');
        entry.className = 'audit-entry';
        entry.innerHTML = `
          <div class="audit-time">${timeString}</div>
          <div class="audit-action">${action}</div>
          <div class="audit-user">Admin</div>
          <div class="audit-details">${details}</div>
        `;

        auditLog.prepend(entry);

        if (auditLog.children.length > 10) {
            auditLog.removeChild(auditLog.lastChild);
        }
    }
}

function refreshSecurityLogs() {
    showNotification('Security logs refreshed', 'Security Dashboard');
}

function updateSessionSettings() {
    if (!checkRateLimit()) {
        showNotification('Please wait before making another request', 'Rate Limit', 'warning');
        return;
    }

    const timeout = document.getElementById('sessionTimeout').value;
    const button = event.target;
    const originalText = button.textContent;
    button.disabled = true;
    button.innerHTML = '<span class="loading"></span> Updating...';
    
    const formData = createFormDataWithCSRF();
    formData.append('session_timeout', timeout);
    
    fetch(API_URLS.updateSessionSettings, {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            showNotification(
                `Session timeout updated to ${timeout} minutes. This applies to all future logins.`,
                'Settings Updated ✓',
                'success'
            );
            logSecurityEvent('SETTINGS_CHANGED', `Session timeout changed to ${timeout} minutes`);
        } else {
            showNotification(data.message || 'Failed to update settings', 'Error', 'danger');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('Failed to update settings: ' + error.message, 'Error', 'danger');
    })
    .finally(() => {
        button.disabled = false;
        button.textContent = originalText;
    });
}


function updateLoginSecurity() {
    if (!checkRateLimit()) {
        showNotification('Please wait before making another request', 'Rate Limit', 'warning');
        return;
    }

    const button = event.target;
    const originalText = button.textContent;
    button.disabled = true;
    button.innerHTML = '<span class="loading"></span> Updating...';
    
    const enable2FA = document.getElementById('enable2FA').checked;
    const lockoutEnabled = document.getElementById('lockoutPolicy').checked;
    const lockoutThreshold = document.getElementById('lockoutThreshold') 
        ? document.getElementById('lockoutThreshold').value 
        : 5;
    
    const formData = createFormDataWithCSRF();
    formData.append('enable2FA', enable2FA ? '1' : '0');
    formData.append('lockoutPolicy', lockoutEnabled ? '1' : '0');
    formData.append('lockoutThreshold', lockoutThreshold);
    
    fetch(API_URLS.updateLoginSecurity, {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            // Build detailed message
            let message = 'Security settings updated:\n\n';
            message += `2FA: ${enable2FA ? 'REQUIRED' : 'Optional'}\n`;
            message += `Account Lockout: ${lockoutEnabled ? 'ENABLED' : 'Disabled'}`;
            
            if (lockoutEnabled) {
                message += ` (${lockoutThreshold} attempts)`;
            }
            
            message += '\n\nChanges apply to all admin and user accounts.';
            
            showNotification(message, 'Security Settings Updated ✓', 'success');
            logSecurityEvent('SETTINGS_CHANGED', `2FA: ${enable2FA}, Lockout: ${lockoutEnabled}`);
            
            // Show visual confirmation
            showSecuritySettingsStatus(enable2FA, lockoutEnabled, lockoutThreshold);
        } else {
            showNotification(data.message || 'Failed to update settings', 'Error', 'danger');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('Failed to update settings: ' + error.message, 'Error', 'danger');
    })
    .finally(() => {
        button.disabled = false;
        button.textContent = originalText;
    });
}

function showSecuritySettingsStatus(enable2FA, lockoutEnabled, threshold) {
    const statusDiv = document.getElementById('securitySettingsStatus');
    if (!statusDiv) return;
    
    let statusHTML = '<strong>Current Security Policy:</strong><br>';
    statusHTML += `• 2FA: <strong style="color: ${enable2FA ? '#28a745' : '#ffc107'}">${enable2FA ? 'REQUIRED' : 'Optional'}</strong><br>`;
    statusHTML += `• Account Lockout: <strong style="color: ${lockoutEnabled ? '#28a745' : '#dc3545'}">${lockoutEnabled ? 'ENABLED' : 'DISABLED'}</strong>`;
    
    if (lockoutEnabled) {
        statusHTML += ` (${threshold} attempts)`;
    }
    
    statusDiv.innerHTML = statusHTML;
    statusDiv.style.display = 'block';
    statusDiv.style.backgroundColor = '#e8f5e9';
    statusDiv.style.border = '1px solid #4caf50';
    statusDiv.style.color = '#2e7d32';
}


function loadSystemSettings() {
    fetch(API_URLS.getSystemSettings)
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                const settings = data.settings;
                
                // Update form values
                const sessionTimeout = document.getElementById('sessionTimeout');
                const enable2FA = document.getElementById('enable2FA');
                const lockoutPolicy = document.getElementById('lockoutPolicy');
                
                if (sessionTimeout) {
                    sessionTimeout.value = settings.session_timeout;
                }
                
                if (enable2FA) {
                    enable2FA.checked = settings.require_2fa;
                }
                
                if (lockoutPolicy) {
                    lockoutPolicy.checked = settings.lockout_enabled;
                }
                
                // Add lockout threshold if you want to make it configurable
                const lockoutThreshold = document.getElementById('lockoutThreshold');
                if (lockoutThreshold) {
                    lockoutThreshold.value = settings.lockout_threshold;
                }
                
                console.log('✅ System settings loaded:', settings);
            } else {
                console.error('Failed to load settings:', data.message);
                showNotification('Failed to load system settings', 'Error', 'danger');
            }
        })
        .catch(error => {
            console.error('Error loading settings:', error);
            showNotification('Failed to load settings: ' + error.message, 'Error', 'danger');
        });
}

function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('active');
}

function showSection(e, sectionName) {
    e.preventDefault();

    document.querySelectorAll('[id^="section-"]').forEach(section => {
        section.classList.add('section-hidden');
    });

    document.getElementById('section-' + sectionName).classList.remove('section-hidden');

    document.querySelectorAll('.menu-item').forEach(item => {
        item.classList.remove('active');
    });
    e.currentTarget.classList.add('active');

    const titles = {
        'dashboard': 'Dashboard',
        'attendance': 'Attendance Records',
        'users': 'Registered Users',
        'analytics': 'Analytics',
        'trusted-devices': 'Trusted Devices',
        'security': 'Security',
        'settings': 'Settings',
        'access-rules': 'Access Rules'
    };
    document.getElementById('pageTitle').textContent = titles[sectionName];

    if (sectionName === 'attendance') {
        if (!attendanceLoaded) {
            loadAttendance(1);
            populateLocationFilter();
            attendanceLoaded = true;
        } else if (attendanceNeedsRefresh) {
            // ✅ ADD THIS: Refresh if there were updates while section was hidden
            console.log('[Section Switch] Refreshing attendance due to pending updates');
            loadAttendance(currentPage, true);
            attendanceNeedsRefresh = false;
        }
    }

    if (window.innerWidth <= 768) {
        document.getElementById('sidebar').classList.remove('active');
    }

    if (sectionName !== 'dashboard') {
        logSecurityEvent('SECTION_VIEWED', `Viewed section: ${sectionName}`);
    }
}


// Initialize charts after DOM is loaded
let activityChart, hourlyChart;

document.addEventListener('DOMContentLoaded', function() {
    const activityCtx = document.getElementById('activityChart')?.getContext('2d');
    const hourlyCtx = document.getElementById('hourlyChart')?.getContext('2d');
    
    // Detect dark mode
    const isDarkMode = document.body.classList.contains('dark-mode');
    const textColor = isDarkMode ? '#e0e0e0' : '#333';
    const gridColor = isDarkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)';
    
    // Green and Red colors for both modes
    const greenBg = isDarkMode ? 'rgba(76, 175, 80, 0.2)' : 'rgba(76, 175, 80, 0.15)';
    const greenBorder = isDarkMode ? '#66bb6a' : '#4caf50';
    const redBg = isDarkMode ? 'rgba(244, 67, 54, 0.2)' : 'rgba(244, 67, 54, 0.15)';
    const redBorder = isDarkMode ? '#ef5350' : '#f44336';

    if (activityCtx && CHART_LABELS) {
        activityChart = new Chart(activityCtx, {
            type: 'line',
            data: {
                labels: CHART_LABELS,
                datasets: [
                    {
                        label: 'IN',
                        data: CHART_INS,
                        tension: 0.3,
                        fill: true,
                        backgroundColor: greenBg,
                        borderColor: greenBorder,
                        borderWidth: 2
                    },
                    {
                        label: 'OUT',
                        data: CHART_OUTS,
                        tension: 0.3,
                        fill: true,
                        backgroundColor: redBg,
                        borderColor: redBorder,
                        borderWidth: 2
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { 
                        position: 'bottom',
                        labels: {
                            color: textColor
                        }
                    }
                },
                scales: {
                    y: { 
                        beginAtZero: true,
                        ticks: {
                            color: textColor
                        },
                        grid: {
                            color: gridColor
                        }
                    },
                    x: {
                        ticks: {
                            color: textColor
                        },
                        grid: {
                            color: gridColor
                        }
                    }
                }
            }
        });
    }

    if (hourlyCtx && HOURLY_LABELS) {
        hourlyChart = new Chart(hourlyCtx, {
            type: 'bar',
            data: {
                labels: HOURLY_LABELS,
                datasets: [
                    {
                        label: 'IN',
                        data: HOURLY_INS,
                        backgroundColor: greenBorder
                    },
                    {
                        label: 'OUT',
                        data: HOURLY_OUTS,
                        backgroundColor: redBorder
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { 
                        position: 'bottom',
                        labels: {
                            color: textColor
                        }
                    }
                },
                scales: {
                    y: { 
                        beginAtZero: true,
                        ticks: {
                            color: textColor
                        },
                        grid: {
                            color: gridColor
                        }
                    },
                    x: {
                        ticks: {
                            color: textColor
                        },
                        grid: {
                            color: gridColor
                        }
                    }
                }
            }
        });
    }
});


function updateChartsForTheme() {
    const isDarkMode = document.body.classList.contains('dark-mode');
    const textColor = isDarkMode ? '#e0e0e0' : '#333';
    const gridColor = isDarkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)';
    
    // Green and Red colors for both modes
    const greenBg = isDarkMode ? 'rgba(76, 175, 80, 0.2)' : 'rgba(76, 175, 80, 0.15)';
    const greenBorder = isDarkMode ? '#66bb6a' : '#4caf50';
    const redBg = isDarkMode ? 'rgba(244, 67, 54, 0.2)' : 'rgba(244, 67, 54, 0.15)';
    const redBorder = isDarkMode ? '#ef5350' : '#f44336';
    
    if (activityChart) {
        activityChart.options.plugins.legend.labels.color = textColor;
        activityChart.options.scales.y.ticks.color = textColor;
        activityChart.options.scales.x.ticks.color = textColor;
        activityChart.options.scales.y.grid.color = gridColor;
        activityChart.options.scales.x.grid.color = gridColor;
        
        activityChart.data.datasets[0].backgroundColor = greenBg;
        activityChart.data.datasets[0].borderColor = greenBorder;
        activityChart.data.datasets[1].backgroundColor = redBg;
        activityChart.data.datasets[1].borderColor = redBorder;
        
        activityChart.update();
    }
    
    if (hourlyChart) {
        hourlyChart.options.plugins.legend.labels.color = textColor;
        hourlyChart.options.scales.y.ticks.color = textColor;
        hourlyChart.options.scales.x.ticks.color = textColor;
        hourlyChart.options.scales.y.grid.color = gridColor;
        hourlyChart.options.scales.x.grid.color = gridColor;
        
        hourlyChart.data.datasets[0].backgroundColor = greenBorder;
        hourlyChart.data.datasets[1].backgroundColor = redBorder;
        
        hourlyChart.update();
    }
}

async function changeLocation() {
    const location = document.getElementById('locationSelect').value;
    
    // Update last API call time without checking (bypass rate limit for this action)
    securityState.lastApiCall = Date.now();
    
    try {
        const fd = createFormDataWithCSRF();
        fd.append('location', location);

        const res = await fetch(API_URLS.setLocation, {
            method: 'POST',
            body: fd
        });
        const data = await res.json();
        if (data.status === 'success') {
            showNotification(`Active location changed to: ${location}`, 'Location Updated');
            await autoRefresh();
            if (attendanceLoaded) await loadAttendance(currentPage);

            logSecurityEvent('LOCATION_CHANGED', `Changed active location to: ${location}`);
        } else {
            alert('Error: ' + (data.message || 'Failed to change location'));
        }
    } catch (err) {
        alert('Failed to change location: ' + err.message);
    }
}

async function autoRefresh() {
    try {
        const res = await fetch(API_URLS.stats);
        const json = await res.json();
        if (json.status !== 'success') return;

        // Store current values BEFORE updating
        const currentInside = document.getElementById('totalInsideCount');
        const oldInsideValue = parseInt(currentInside.textContent) || 0;
        const newInsideValue = json.total_inside;
        
        // Update the display AFTER checking for changes
        currentInside.textContent = newInsideValue;

        // Update today's scans count
        const todayScansEl = document.getElementById('todayScansCount');
        if (todayScansEl && json.today_scans !== undefined) {
            todayScansEl.textContent = json.today_scans;
        }

        // Update Last Activity in Welcome Section
        if (json.recent_logs && json.recent_logs.length > 0) {
            const mostRecent = json.recent_logs[0];
            const lastActivityTime = document.getElementById('lastActivityTime');
            const lastActivityAction = document.getElementById('lastActivityAction');
            
            if (lastActivityTime && lastActivityAction) {
                lastActivityTime.textContent = getTimeAgo(mostRecent.timestamp);
                lastActivityAction.textContent = `${mostRecent.name} - ${mostRecent.action} at ${mostRecent.location}`;
            }
        } else {
            const lastActivityTime = document.getElementById('lastActivityTime');
            const lastActivityAction = document.getElementById('lastActivityAction');
            
            if (lastActivityTime && lastActivityAction) {
                lastActivityTime.textContent = 'No activity';
                lastActivityAction.textContent = 'No recent activity recorded';
            }
        }

        const tbody = document.getElementById('recentLogsBody');
        tbody.innerHTML = '';
        if (!json.recent_logs || json.recent_logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No recent logs</td></tr>';
        } else {
            json.recent_logs.forEach(r => {
                const tr = document.createElement('tr');
                const badgeClass = r.action === 'IN' ? 'badge-in' : 'badge-out';
                
                // ✅ USE formatDateTime helper - just extract time
                const { date, time } = formatDateTime(r.timestamp);
                
                tr.innerHTML = `
                    <td><strong>${r.name}</strong></td>
                    <td><span class="badge ${badgeClass}">${r.action}</span></td>
                    <td>${time}</td>
                    <td>${r.location}</td>
                `;
                tbody.appendChild(tr);
            });
        }

        const insideBody = document.getElementById('currentInsideBody');
        insideBody.innerHTML = '';
        if (!json.current_inside || json.current_inside.length === 0) {
            insideBody.innerHTML = '<tr><td colspan="3" class="empty-state">No one currently inside</td></tr>';
        } else {
            json.current_inside.forEach(u => {
                const tr = document.createElement('tr');
                
                // ✅ USE formatDateTime helper - show full timestamp
                const { date, time } = formatDateTime(u.timestamp);
                
                tr.innerHTML = `
                    <td><strong>${u.name}</strong></td>
                    <td>${u.role}</td>
                    <td>${time}</td>
                `;
                insideBody.appendChild(tr);
            });
        }

        if (json.active_location) {
            const locationSelect = document.getElementById('locationSelect');
            const locationValueEl = document.querySelector('#statCardLocation .value');
            
            if (locationSelect && locationSelect.value !== json.active_location) {
                locationSelect.value = json.active_location;
            }
            
            if (locationValueEl && locationValueEl.textContent !== json.active_location) {
                locationValueEl.textContent = json.active_location;
            }
        }

        if (json.daily_counts && activityChart) {
            activityChart.data.labels = json.daily_counts.map(d => d.day);
            activityChart.data.datasets[0].data = json.daily_counts.map(d => d.ins);
            activityChart.data.datasets[1].data = json.daily_counts.map(d => d.outs);
            activityChart.update('none');
        }
        if (json.hourly_counts && hourlyChart) {
            hourlyChart.data.labels = json.hourly_counts.map(h => h.hour);
            hourlyChart.data.datasets[0].data = json.hourly_counts.map(h => h.ins);
            hourlyChart.data.datasets[1].data = json.hourly_counts.map(h => h.outs);
            hourlyChart.update('none');
        }
    } catch (err) {
        console.error('Auto-refresh failed:', err);
    }
}

async function loadAttendance(page = 1, silent = false) {
    if (isLoading && !silent) {
        console.log('[Attendance] Already loading, skipping...');
        return;
    }

    if (!checkRateLimit() && !silent) {
        showNotification('Please wait before making another request', 'Rate Limit Exceeded', 'warning');
        return;
    }

    currentPage = Math.max(1, Math.min(page, totalPages || 1));
    isLoading = true;

    const tbody = document.getElementById('attendanceTbody');
    
    // **FIX: Don't show loading message on silent refresh**
    if (tbody && !silent) {
        tbody.innerHTML = `<tr><td colspan="6" class="empty-state"><span class="loading"></span> Loading attendance records...</td></tr>`;
    }

    try {
        const dateFrom = document.getElementById('filterDateFrom')?.value || '';
        const dateTo = document.getElementById('filterDateTo')?.value || '';
        const action = document.getElementById('filterAction')?.value || '';
        const location = document.getElementById('filterLocation')?.value || '';
        const search = document.getElementById('searchAttendance')?.value || '';

        const params = new URLSearchParams({
            page: currentPage,
            per_page: recordsPerPage,
            date_from: dateFrom,
            date_to: dateTo,
            action: action,
            location: location,
            search: search
        });

        const logPrefix = silent ? '[Attendance-BG]' : '[Attendance]';
        console.log(`${logPrefix} Loading page ${currentPage}...`);
        
        const res = await fetch(`${API_URLS.getAttendance}?${params}`);
        const json = await res.json();

        if (json.status !== 'success') throw new Error(json.message || 'Failed to load');

        totalPages = json.total_pages;
        
        if (tbody) {
            tbody.innerHTML = '';

            if (!json.records || json.records.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No records found</td></tr>';
            } else {
                json.records.forEach((record, index) => {
                    const { date, time } = formatDateTime(record.timestamp);
                    const badgeClass = record.action === 'IN' ? 'badge-in' : 'badge-out';

                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td><strong>${record.name}</strong></td>
                        <td>${record.role}</td>
                        <td><span class="badge ${badgeClass}">${record.action}</span></td>
                        <td>${date}</td>
                        <td>${time}</td>
                        <td>${record.location}</td>
                    `;
                
                    // **FIX: Highlight new records on silent refresh**
                    if (index === 0 && silent) {
                        tr.style.animation = 'fadeIn 0.5s ease-in';
                        tr.style.backgroundColor = record.action === 'IN' ? 'rgba(76, 175, 80, 0.1)' : 'rgba(244, 67, 54, 0.1)';
                        
                        // Remove highlight after 2 seconds
                        setTimeout(() => {
                            tr.style.backgroundColor = '';
                        }, 2000);
                    }
                    
                    tbody.appendChild(tr);
                });
            }
        }

        const pageInfo = document.getElementById('pageInfo');
        if (pageInfo) {
            pageInfo.textContent = `Page ${currentPage} of ${totalPages}`;
        }
        
        const prevBtn = document.getElementById('prevBtn');
        const nextBtn = document.getElementById('nextBtn');
        if (prevBtn) prevBtn.disabled = currentPage <= 1;
        if (nextBtn) nextBtn.disabled = currentPage >= totalPages;

        console.log(`${logPrefix} ✅ Loaded ${json.records.length} records`);
        attendanceNeedsRefresh = false;
        
    } catch (err) {
        console.error('[Attendance] Error loading:', err);
        if (tbody && !silent) {
            tbody.innerHTML = `<tr><td colspan="6" class="empty-state" style="color: #e53e3e;">Error: ${err.message}</td></tr>`;
        }
    } finally {
        isLoading = false;
    }
}


async function populateLocationFilter() {
    try {
        const res = await fetch(`${API_URLS.getAttendance}?page=1&per_page=1`);
        const json = await res.json();

        if (json.locations && json.locations.length > 0) {
            const select = document.getElementById('filterLocation');
            json.locations.forEach(loc => {
                const option = document.createElement('option');
                option.value = loc;
                option.textContent = loc;
                select.appendChild(option);
            });
        }
    } catch (err) {
        console.error('Failed to load locations:', err);
    }
}

function exportAttendanceExcel() {
    const search = document.getElementById('searchAttendance').value;
    const dateFrom = document.getElementById('filterDateFrom').value;
    const dateTo = document.getElementById('filterDateTo').value;
    const action = document.getElementById('filterAction').value;
    const location = document.getElementById('filterLocation').value;

    const params = new URLSearchParams({
        search: search,
        date_from: dateFrom,
        date_to: dateTo,
        action: action,
        location: location
    });

    window.location.href = `${API_URLS.exportAttendanceExcel}?${params}`;

    logSecurityEvent('DATA_EXPORTED', 'Exported attendance data to Excel');
}

// Add at the top with other global variables
let editingUserId = null;

// Add these functions anywhere in the file

function editUser(userId, currentName, currentRole, currentEmail) {
    editingUserId = userId;
    
    // Populate modal fields
    document.getElementById('edit_user_name').value = currentName;
    document.getElementById('edit_user_role').value = currentRole;
    document.getElementById('edit_user_email').value = currentEmail || '';
    
    // Update modal title
    document.getElementById('editUserModalTitle').textContent = `Edit User: ${currentName}`;
    
    // Show modal
    document.getElementById('editUserModal').classList.remove('section-hidden');
}

function closeEditModal() {
    editingUserId = null;
    document.getElementById('editUserModal').classList.add('section-hidden');
    document.getElementById('editUserForm').reset();
}

async function submitEditUser(event) {
    event.preventDefault();
    
    if (!editingUserId) {
        showNotification('No user selected for editing', 'Error', 'danger');
        return;
    }
    
    if (!checkRateLimit()) {
        showNotification('Please wait before making another request', 'Rate Limit', 'warning');
        return;
    }
    
    const name = document.getElementById('edit_user_name').value.trim();
    const role = document.getElementById('edit_user_role').value;
    const email = document.getElementById('edit_user_email').value.trim();
    
    // Validation
    if (!name || !role || !email) {
        showNotification('All fields are required', 'Validation Error', 'warning');
        return;
    }
    
    if (!email.includes('@')) {
        showNotification('Please enter a valid email address', 'Validation Error', 'warning');
        return;
    }
    
    const button = event.target.querySelector('button[type="submit"]');
    const originalText = button.textContent;
    button.disabled = true;
    button.innerHTML = '<span class="loading"></span> Updating...';
    
    try {
        const fd = createFormDataWithCSRF();
        fd.append('name', name);
        fd.append('role', role);
        fd.append('email', email);
        
        const res = await fetch(`/admin/edit-user/${editingUserId}`, {
            method: 'POST',
            body: fd
        });
        
        const json = await res.json();
        
        if (json.status === 'success' || json.status === 'info') {
            showNotification(json.message, 'User Updated ✓', 'success');
            
            logSecurityEvent('USER_UPDATED', `Updated user ID: ${editingUserId} - ${name}`);
            
            closeEditModal();
            
            setTimeout(() => location.reload(), 2000);
        } else {
            showNotification(json.message || 'Failed to update user', 'Error', 'danger');
        }
    } catch (err) {
        console.error('Edit user error:', err);
        showNotification('Failed to update user: ' + err.message, 'Error', 'danger');
    } finally {
        button.disabled = false;
        button.textContent = originalText;
    }
}

// Initialize edit form (add to existing DOMContentLoaded)
document.addEventListener('DOMContentLoaded', function() {
    const editUserForm = document.getElementById('editUserForm');
    if (editUserForm) {
        editUserForm.addEventListener('submit', submitEditUser);
    }
});

async function deleteUser(userId) {
    if (!confirm('Are you sure you want to delete this user?')) return;

    if (!checkRateLimit()) {
        showNotification('Please wait before making another request', 'Rate Limit Exceeded', 'warning');
        return;
    }

    try {
        const fd = createFormDataWithCSRF();

        const res = await fetch(API_URLS.deleteUser.replace('/0', `/${userId}`), {
            method: 'POST',
            body: fd
        });
        const json = await res.json();
        if (json.status === 'success') {
            showNotification('User deleted successfully', 'User Deleted');

            logSecurityEvent('USER_DELETED', `Deleted user with ID: ${userId}`);

            setTimeout(() => location.reload(), 1000);
        } else {
            alert('Error: ' + (json.message || 'Failed to delete user'));
        }
    } catch (err) {
        alert('Failed to delete user: ' + err.message);
    }
}

async function resetUserPassword(userId, userName, userEmail) {
    // Validate inputs
    if (!userId || !userName) {
        showNotification('Invalid user information', 'Error', 'danger');
        return;
    }
    
    if (!userEmail || !userEmail.includes('@')) {
        showNotification(
            'This user does not have a valid email address. Cannot send password reset.',
            'Email Required',
            'warning'
        );
        return;
    }
    
    // Confirm action
    if (!confirm(`Reset password for ${userName}?\n\nA new temporary password will be generated and emailed to:\n${userEmail}\n\nThe user will be required to change their password on next login.`)) {
        return;
    }

    if (!checkRateLimit()) {
        showNotification('Please wait before making another request', 'Rate Limit Exceeded', 'warning');
        return;
    }

    // Show loading state
    const notification = showNotification(
        `Generating new password for ${userName}...`,
        'Processing',
        'info'
    );

    try {
        const fd = createFormDataWithCSRF();
        fd.append('user_id', userId);

        const res = await fetch('/admin/reset-user-password', {
            method: 'POST',
            body: fd
        });
        
        const json = await res.json();
        
        if (json.status === 'success') {
            showNotification(
                `Password reset successful!\n\nA new temporary password has been sent to ${userEmail}.\n\nThe user will be required to change their password on next login.`,
                'Password Reset ✓',
                'success'
            );
            
            logSecurityEvent('USER_PASSWORD_RESET', `Reset password for user: ${userName} (ID: ${userId})`);
            
            // Optional: Reload to show updated user status
            setTimeout(() => location.reload(), 3000);
        } else {
            showNotification(
                json.message || 'Failed to reset password',
                'Reset Failed',
                'danger'
            );
        }
    } catch (err) {
        console.error('Password reset error:', err);
        showNotification(
            'Failed to reset password: ' + err.message,
            'Error',
            'danger'
        );
    }
}

function showNotification(title, message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = 'professional-notification';
    
    // Ensure animation styles exist
    if (!document.getElementById('notification-animations')) {
        const style = document.createElement('style');
        style.id = 'notification-animations';
        style.textContent = `
            @keyframes slideInRight {
                from { 
                    opacity: 0;
                    transform: translateX(400px);
                }
                to { 
                    opacity: 1;
                    transform: translateX(0);
                }
            }
            @keyframes fadeIn {
                from { opacity: 0; transform: translateY(-5px); }
                to { opacity: 1; transform: translateY(0); }
            }
        `;
        document.head.appendChild(style);
    }
    
    // Type-based styling with dark mode support
    let bgColor, borderColor, icon, textColor;
    
    // Check if dark mode is active
    const isDarkMode = document.body.classList.contains('dark-mode');
    
    switch (type) {
        case 'success':
            bgColor = isDarkMode ? '#1e3a1e' : '#f0f9f4';
            borderColor = isDarkMode ? '#4caf50' : '#38a169';
            textColor = isDarkMode ? '#e0e0e0' : '#2d3748';
            icon = '✓';
            break;
        case 'warning':
            bgColor = isDarkMode ? '#3a3a1e' : '#fffaf0';
            borderColor = isDarkMode ? '#ff9800' : '#dd6b20';
            textColor = isDarkMode ? '#e0e0e0' : '#2d3748';
            icon = '!';
            break;
        case 'danger':
            bgColor = isDarkMode ? '#3a1e1e' : '#fef2f2';
            borderColor = isDarkMode ? '#f44336' : '#dc3545';
            textColor = isDarkMode ? '#e0e0e0' : '#2d3748';
            icon = '✕';
            break;
        case 'info':
        default:
            bgColor = isDarkMode ? '#1e2a3a' : '#f0f9ff';
            borderColor = isDarkMode ? '#42a5f5' : '#3182ce';
            textColor = isDarkMode ? '#e0e0e0' : '#2d3748';
            icon = 'i';
    }

    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${bgColor};
        border: 1px solid ${borderColor};
        border-left: 4px solid ${borderColor};
        padding: 16px 20px;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        z-index: 9999;
        min-width: 300px;
        max-width: 400px;
        animation: slideInRight 0.3s ease-out;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;

    const secondaryTextColor = isDarkMode ? '#b0b0b0' : '#4a5568';
    const tertiaryTextColor = isDarkMode ? '#888888' : '#718096';
    const closeBtnColor = isDarkMode ? '#b0b0b0' : '#a0aec0';

    notification.innerHTML = `
        <div style="display: flex; align-items: flex-start; gap: 12px;">
            <div style="
                width: 20px;
                height: 20px;
                border-radius: 50%;
                background: ${borderColor};
                color: white;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 12px;
                font-weight: bold;
                flex-shrink: 0;
            ">${icon}</div>
            <div style="flex: 1;">
                <div style="font-weight: 600; font-size: 14px; color: ${textColor}; margin-bottom: 4px;">${title}</div>
                <div style="font-size: 13px; color: ${secondaryTextColor}; line-height: 1.4;">${message}</div>
                <div style="font-size: 11px; color: ${tertiaryTextColor}; margin-top: 6px;">${new Date().toLocaleTimeString()}</div>
            </div>
            <button onclick="this.parentElement.parentElement.remove()" 
                    style="background: none; border: none; font-size: 16px; cursor: pointer; padding: 0; color: ${closeBtnColor}; line-height: 1; align-self: flex-start;">×</button>
        </div>
    `;

    document.body.appendChild(notification);

    // Auto remove after 5 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.style.opacity = '0';
            notification.style.transform = 'translateX(400px)';
            notification.style.transition = 'all 0.3s ease-out';
            setTimeout(() => notification.remove(), 300);
        }
    }, 5000);
}

// Check if current admin is first admin
function checkFirstAdminStatus() {
    // This would be set by the server in the template
    return window.isFirstAdmin || false;
}

// Load admin list (first admin only)
async function loadAdminList() {
    if (!window.isFirstAdmin) {
        return;
    }
    
    try {
        const res = await fetch(API_URLS.getAdminList);
        const json = await res.json();
        
        if (json.status === 'success') {
            const tbody = document.getElementById('adminListBody');
            tbody.innerHTML = '';
            
            if (!json.admins || json.admins.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No admin accounts found</td></tr>';
            } else {
                json.admins.forEach(admin => {
                    const tr = document.createElement('tr');
                    
                    // Determine if this is the first admin
                    const isFirstAdmin = admin.admin_id === 1;
                    
                    tr.innerHTML = `
                        <td><code style="background:#f0f0f0;padding:2px 6px;border-radius:3px;font-size:12px;">${admin.username}</code></td>
                        <td><strong>${admin.name}</strong></td>
                        <td style="font-size: 13px; color: #666;">${admin.email}</td>
                        <td>${new Date(admin.created_at).toLocaleDateString()}</td>
                        <td>
                            <span class="badge ${admin.email_verified ? 'badge-in' : 'badge-out'}">
                                ${admin.email_verified ? 'Verified' : 'Pending'}
                            </span>
                        </td>
                        <td>
                            ${isFirstAdmin 
                                ? '<span style="color: #999; font-size: 12px; font-style: italic;">Primary Admin (Protected)</span>'
                                : `<button class="btn btn-danger btn-sm" onclick="deleteAdmin(${admin.admin_id}, '${admin.username.replace(/'/g, "\\'")}')">Delete</button>`
                            }
                        </td>
                    `;
                    tbody.appendChild(tr);
                });
            }
        } else {
            const tbody = document.getElementById('adminListBody');
            tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Failed to load admin list</td></tr>';
        }
    } catch (err) {
        console.error('Failed to load admin list:', err);
        const tbody = document.getElementById('adminListBody');
        tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Error loading admin list</td></tr>';
    }
}

async function deleteAdmin(adminId, adminUsername) {
    // Prevent deleting first admin
    if (adminId === 1) {
        showNotification('The first administrator account cannot be deleted for security reasons.', 'Cannot Delete', 'warning');
        return;
    }
    
    // Double confirmation
    if (!confirm(`DELETE ADMIN ACCOUNT\n\nAre you sure you want to delete "${adminUsername}"?\n\nThis will:\n• Remove the admin account permanently\n• Delete all their trusted devices\n• This action CANNOT be undone\n\nType the username to confirm.`)) {
        return;
    }
    
    // Ask user to type username for extra confirmation
    const confirmation = prompt(`To confirm deletion, please type the username: ${adminUsername}`);
    
    if (confirmation !== adminUsername) {
        showNotification('Username did not match. Deletion cancelled.', 'Cancelled', 'info');
        return;
    }
    
    if (!checkRateLimit()) {
        showNotification('Please wait before making another request', 'Rate Limit', 'warning');
        return;
    }
    
    const url = API_URLS.deleteAdmin.replace('0', adminId);
    
    try {
        const fd = createFormDataWithCSRF();
        
        const res = await fetch(url, {
            method: 'POST',
            body: fd
        });
        
        const json = await res.json();
        
        if (json.status === 'success') {
            showNotification(
                `Admin account "${adminUsername}" has been permanently deleted.`,
                'Admin Deleted ✓',
                'success'
            );
            
            // Reload admin list
            setTimeout(() => {
                loadAdminList();
            }, 1500);
            
            logSecurityEvent('ADMIN_DELETED', `Deleted admin: ${adminUsername} (ID: ${adminId})`);
        } else {
            showNotification(json.message || 'Failed to delete admin', 'Error', 'danger');
        }
    } catch (error) {
        console.error('Error:', error);
        showNotification('An error occurred while deleting admin: ' + error.message, 'Error', 'danger');
    }
}

// Add new admin (first admin only)
document.addEventListener('DOMContentLoaded', function() {
    const addAdminForm = document.getElementById('addAdminForm');
    if (addAdminForm) {
        addAdminForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            if (!checkRateLimit()) {
                showNotification('Please wait before making another request', 'Rate Limit', 'warning');
                return;
            }
            
            const username = document.getElementById('admin_username').value.trim();
            const email = document.getElementById('admin_email').value.trim();
            const name = document.getElementById('admin_name').value.trim();
            const password = document.getElementById('admin_password').value;
            
            if (!username || !email || !name || !password) {
                showNotification('All fields are required', 'Validation Error', 'warning');
                return;
            }
            
            if (password.length < 8) {
                showNotification('Password must be at least 8 characters', 'Validation Error', 'warning');
                return;
            }
            
            const button = e.target.querySelector('button[type="submit"]');
            const originalText = button.textContent;
            button.disabled = true;
            button.innerHTML = '<span class="loading"></span> Creating...';
            
            try {
                const fd = createFormDataWithCSRF();
                fd.append('username', username);
                fd.append('email', email);
                fd.append('name', name);
                fd.append('password', password);
                
                const res = await fetch(API_URLS.addAdmin, {
                    method: 'POST',
                    body: fd
                });
                
                const json = await res.json();
                
                if (json.status === 'success') {
                    showNotification(json.message, 'Admin Created', 'success');
                    addAdminForm.reset();
                    loadAdminList();
                    logSecurityEvent('ADMIN_CREATED', `Created admin account for: ${name} (${username})`);
                } else {
                    showNotification(json.message, 'Error', 'danger');
                }
            } catch (err) {
                showNotification('Failed to create admin: ' + err.message, 'Error', 'danger');
            } finally {
                button.disabled = false;
                button.textContent = originalText;
            }
        });
    }
});

// ==========================================
// ACCESS RULES - ENHANCED USER SELECTION
// ==========================================

let allUsers = [];
let selectedUserIds = new Set();

// Initialize user search when access-rules section is shown
document.addEventListener('DOMContentLoaded', function() {
    const originalShowSection = window.showSection;
    window.showSection = function(e, sectionName) {
        originalShowSection(e, sectionName);
        if (sectionName === 'access-rules') {
            loadAccessRules();
            initializeUserSelection();
        }
    };
});

async function initializeUserSelection() {
    try {
        // Load all users initially
        await searchUsers();
        
        // Setup event listeners
        const searchInput = document.getElementById('userSearchInput');
        const roleCheckboxes = document.querySelectorAll('.role-filter-checkbox');
        
        if (searchInput) {
            // Debounce search
            let searchTimeout;
            searchInput.addEventListener('input', function() {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => searchUsers(), 300);
            });
        }
        
        if (roleCheckboxes) {
            roleCheckboxes.forEach(checkbox => {
                checkbox.addEventListener('change', () => searchUsers());
            });
        }
    } catch (err) {
        console.error('Failed to initialize user selection:', err);
    }
}

async function searchUsers() {
    try {
        const searchQuery = document.getElementById('userSearchInput')?.value || '';
        const selectedRoles = Array.from(document.querySelectorAll('.role-filter-checkbox:checked'))
            .map(cb => cb.value);
        
        const params = new URLSearchParams();
        params.append('search', searchQuery);
        selectedRoles.forEach(role => params.append('roles[]', role));
        
        const res = await fetch(`${API_URLS.searchUsers}?${params}`);
        const json = await res.json();
        
        if (json.status === 'success') {
            allUsers = json.users;
            renderUserSelectionList(json.users);
        }
    } catch (err) {
        console.error('Search users failed:', err);
        showNotification('Failed to search users', 'Error', 'danger');
    }
}

function renderUserSelectionList(users) {
    const container = document.getElementById('userSelectionList');
    
    if (!container) return;
    
    if (users.length === 0) {
        container.innerHTML = '<div class="empty-state" style="padding: 20px;">No users found</div>';
        return;
    }
    
    container.innerHTML = users.map(user => `
        <div class="user-selection-item ${selectedUserIds.has(user.user_id) ? 'selected' : ''}" 
             data-user-id="${user.user_id}">
            <input type="checkbox" 
                   class="user-checkbox" 
                   value="${user.user_id}"
                   ${selectedUserIds.has(user.user_id) ? 'checked' : ''}
                   onchange="toggleUserSelection(${user.user_id})">
            <div class="user-info-inline">
                <div class="user-name-inline"><strong>${user.name}</strong></div>
                <div class="user-meta-inline">
                    <span class="badge badge-role">${user.role}</span>
                    <span style="color: #666; font-size: 12px;">ID: ${user.user_id}</span>
                    <span style="color: #999; font-size: 11px;">${user.email}</span>
                </div>
            </div>
        </div>
    `).join('');
    
    updateSelectedCount();
}

function toggleUserSelection(userId) {
    if (selectedUserIds.has(userId)) {
        selectedUserIds.delete(userId);
    } else {
        selectedUserIds.add(userId);
    }
    
    // Update UI
    const item = document.querySelector(`[data-user-id="${userId}"]`);
    if (item) {
        item.classList.toggle('selected', selectedUserIds.has(userId));
    }
    
    updateSelectedCount();
}

function selectAllUsers() {
    allUsers.forEach(user => selectedUserIds.add(user.user_id));
    
    document.querySelectorAll('.user-checkbox').forEach(cb => {
        cb.checked = true;
    });
    
    document.querySelectorAll('.user-selection-item').forEach(item => {
        item.classList.add('selected');
    });
    
    updateSelectedCount();
}

function deselectAllUsers() {
    selectedUserIds.clear();
    
    document.querySelectorAll('.user-checkbox').forEach(cb => {
        cb.checked = false;
    });
    
    document.querySelectorAll('.user-selection-item').forEach(item => {
        item.classList.remove('selected');
    });
    
    updateSelectedCount();
}

function updateSelectedCount() {
    const countElement = document.getElementById('selectedUserCount');
    if (countElement) {
        const count = selectedUserIds.size;
        countElement.textContent = count;
        countElement.style.display = count > 0 ? 'inline' : 'none';
    }
    
    // Enable/disable submit button
    const submitBtn = document.getElementById('bulkAddRuleBtn');
    if (submitBtn) {
        submitBtn.disabled = selectedUserIds.size === 0;
    }
}

// Enhanced add rule form submission
document.addEventListener('DOMContentLoaded', function() {
    const addRuleForm = document.getElementById('addRuleForm');
    if (addRuleForm) {
        addRuleForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            if (!checkRateLimit()) {
                showNotification('Please wait before making another request', 'Rate Limit', 'warning');
                return;
            }
            
            // Check if any users are selected
            if (selectedUserIds.size === 0) {
                showNotification(
                    'Please select at least one user from the list above',
                    'No User Selected',
                    'warning'
                );
                return;
            }
            
            // Always use bulk submission (even for single user)
            await submitBulkRules();
        });
    }
});


async function submitBulkRules() {
    const fd = createFormDataWithCSRF();
    
    selectedUserIds.forEach(id => fd.append('user_ids[]', id));
    fd.append('rule_type', document.getElementById('rule_type').value);
    fd.append('location', document.getElementById('rule_location').value);
    fd.append('time_from', document.getElementById('rule_time_from').value);
    fd.append('time_to', document.getElementById('rule_time_to').value);
    fd.append('date_from', document.getElementById('rule_date_from').value);
    fd.append('date_to', document.getElementById('rule_date_to').value);
    fd.append('specific_dates', document.getElementById('rule_specific_dates').value);
    
    try {
        const res = await fetch(API_URLS.bulkAddAccessRules, {
            method: 'POST',
            body: fd
        });
        const json = await res.json();
        
        if (json.status === 'success') {
            showNotification(json.message, 'Success', 'success');
            document.getElementById('addRuleForm').reset();
            deselectAllUsers();
            loadAccessRules();
        } else {
            showNotification(json.message, 'Error', 'danger');
        }
    } catch (err) {
        showNotification('Failed to add rules: ' + err.message, 'Error', 'danger');
    }
}

async function submitSingleRule() {
    const userId = document.getElementById('rule_user_id').value;
    
    if (!userId) {
        showNotification('Please select a user', 'Error', 'warning');
        return;
    }
    
    const fd = createFormDataWithCSRF();
    fd.append('user_id', userId);
    fd.append('rule_type', document.getElementById('rule_type').value);
    fd.append('location', document.getElementById('rule_location').value);
    fd.append('time_from', document.getElementById('rule_time_from').value);
    fd.append('time_to', document.getElementById('rule_time_to').value);
    fd.append('date_from', document.getElementById('rule_date_from').value);
    fd.append('date_to', document.getElementById('rule_date_to').value);
    fd.append('specific_dates', document.getElementById('rule_specific_dates').value);
    
    try {
        const res = await fetch(API_URLS.addAccessRule, {
            method: 'POST',
            body: fd
        });
        const json = await res.json();
        
        if (json.status === 'success') {
            showNotification(json.message, 'Success', 'success');
            document.getElementById('addRuleForm').reset();
            loadAccessRules();
        } else {
            showNotification(json.message, 'Error', 'danger');
        }
    } catch (err) {
        showNotification('Failed to add rule: ' + err.message, 'Error', 'danger');
    }
}

function initializeDarkMode() {
    const savedTheme = localStorage.getItem('theme');
    
    if (savedTheme === 'dark') {
        enableDarkMode(false);
    } else {
        disableDarkMode(false);
    }
    
    const toggle = document.getElementById('darkModeToggle');
    if (toggle) {
        toggle.checked = document.body.classList.contains('dark-mode');
    }
}

function toggleDarkMode() {
    if (document.body.classList.contains('dark-mode')) {
        disableDarkMode(true);
    } else {
        enableDarkMode(true);
    }
}

function enableDarkMode(save = true) {
    document.body.classList.add('dark-mode');
    
    if (save) {
        localStorage.setItem('theme', 'dark');
        showNotification('Dark mode enabled', 'Appearance', 'info');
    }
    
    const toggle = document.getElementById('darkModeToggle');
    if (toggle) {
        toggle.checked = true;
    }
    
    // Update charts if they exist
    if (typeof updateChartsForTheme === 'function') {
        updateChartsForTheme();
    }
}

function disableDarkMode(save = true) {
    document.body.classList.remove('dark-mode');
    
    if (save) {
        localStorage.setItem('theme', 'light');
        showNotification('Light mode enabled', 'Appearance', 'info');
    }
    
    const toggle = document.getElementById('darkModeToggle');
    if (toggle) {
        toggle.checked = false;
    }
    
    // Update charts if they exist
    if (typeof updateChartsForTheme === 'function') {
        updateChartsForTheme();
    }
}


// ==========================================
// ADMIN PASSWORD CHANGE
// ==========================================

document.addEventListener('DOMContentLoaded', function() {
    const changePasswordForm = document.getElementById('changePasswordForm');
    const newPasswordInput = document.getElementById('new_password');
    const confirmPasswordInput = document.getElementById('confirm_password');
    
    if (changePasswordForm) {
        // Password strength checker
        if (newPasswordInput) {
            newPasswordInput.addEventListener('input', function() {
                checkPasswordStrength(this.value);
                checkPasswordRequirements(this.value);
                checkPasswordMatch();
            });
        }
        
        // Password match checker
        if (confirmPasswordInput) {
            confirmPasswordInput.addEventListener('input', checkPasswordMatch);
        }
        
        // Form submission
        changePasswordForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            if (!checkRateLimit()) {
                showNotification('Please wait before trying again', 'Rate Limit', 'warning');
                return;
            }
            
            const currentPassword = document.getElementById('current_password').value;
            const newPassword = document.getElementById('new_password').value;
            const confirmPassword = document.getElementById('confirm_password').value;
            
            // Validate
            if (!currentPassword || !newPassword || !confirmPassword) {
                showNotification('All fields are required', 'Validation Error', 'warning');
                return;
            }
            
            if (newPassword !== confirmPassword) {
                showNotification('New passwords do not match', 'Validation Error', 'warning');
                return;
            }
            
            if (newPassword.length < 8) {
                showNotification('Password must be at least 6 characters', 'Validation Error', 'warning');
                return;
            }
            
            const button = e.target.querySelector('button[type="submit"]');
            const originalText = button.textContent;
            button.disabled = true;
            button.innerHTML = '<span class="loading"></span> Changing...';
            
            try {
                const fd = createFormDataWithCSRF();
                fd.append('current_password', currentPassword);
                fd.append('new_password', newPassword);
                fd.append('confirm_password', confirmPassword);
                
                const res = await fetch('/admin/change-password', {
                    method: 'POST',
                    body: fd
                });
                
                const json = await res.json();
                
                if (json.status === 'success') {
                    showNotification(
                        'Your password has been changed successfully. You will need to use the new password on your next login.',
                        'Password Changed ✓',
                        'success'
                    );
                    
                    // Clear form
                    changePasswordForm.reset();
                    
                    // Hide indicators
                    document.getElementById('passwordStrength').style.display = 'none';
                    document.getElementById('matchIndicator').style.display = 'none';
                    
                    // Reset requirement checks
                    ['req-length', 'req-letter', 'req-special'].forEach(id => {
                        const el = document.getElementById(id);
                        if (el) {
                            el.style.color = '';
                            el.innerHTML = el.innerHTML.replace('✓ ', '').replace('✗ ', '');
                        }
                    });
                    
                    logSecurityEvent('PASSWORD_CHANGED', 'Admin password changed successfully');
                    
                } else {
                    showNotification(json.message || 'Failed to change password', 'Error', 'danger');
                }
            } catch (err) {
                console.error('Password change error:', err);
                showNotification('Failed to change password: ' + err.message, 'Error', 'danger');
            } finally {
                button.disabled = false;
                button.textContent = originalText;
            }
        });
    }
});


function checkPasswordStrength(password) {
    const strengthIndicator = document.getElementById('passwordStrength');
    const strengthFill = document.getElementById('strengthFill');
    const strengthText = document.getElementById('strengthText');
    
    if (!password) {
        strengthIndicator.style.display = 'none';
        return;
    }
    
    strengthIndicator.style.display = 'block';
    
    let strength = 0;
    let color = '';
    let text = '';
    
    // Length check
    if (password.length >= 8) strength += 25;
    if (password.length >= 10) strength += 15;
    if (password.length >= 14) strength += 10;
    
    // Character variety
    if (/[a-z]/.test(password)) strength += 10;
    if (/[A-Z]/.test(password)) strength += 15;
    if (/[0-9]/.test(password)) strength += 15;
    if (/[^a-zA-Z0-9]/.test(password)) strength += 10;
    
    // Determine color and text
    if (strength < 30) {
        color = '#dc3545';
        text = 'Weak';
    } else if (strength < 50) {
        color = '#ffc107';
        text = 'Fair';
    } else if (strength < 75) {
        color = '#17a2b8';
        text = 'Good';
    } else {
        color = '#28a745';
        text = 'Strong';
    }
    
    strengthFill.style.width = strength + '%';
    strengthFill.style.backgroundColor = color;
    strengthText.textContent = text;
    strengthText.style.color = color;
}

function checkPasswordRequirements(password) {
    const requirements = {
        'req-length': password.length >= 8,
        'req-letter': /[a-zA-Z]/.test(password),
        'req-special': /[\d!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/;~`]/.test(password)
    };
    
    Object.keys(requirements).forEach(id => {
        const element = document.getElementById(id);
        if (!element) return;
        
        const originalText = element.textContent.replace('✓ ', '').replace('✗ ', '');
        
        if (requirements[id]) {
            element.style.color = '#28a745';
            element.textContent = '✓ ' + originalText;
        } else {
            element.style.color = '#dc3545';
            element.textContent = '✗ ' + originalText;
        }
    });
}

function checkPasswordMatch() {
    const newPassword = document.getElementById('new_password').value;
    const confirmPassword = document.getElementById('confirm_password').value;
    const matchIndicator = document.getElementById('matchIndicator');
    const matchIcon = document.getElementById('matchIcon');
    const matchText = document.getElementById('matchText');
    
    if (!confirmPassword) {
        matchIndicator.style.display = 'none';
        return;
    }
    
    matchIndicator.style.display = 'flex';
    
    if (newPassword === confirmPassword) {
        matchIcon.textContent = '✓';
        matchIcon.style.color = '#28a745';
        matchText.textContent = 'Passwords match';
        matchText.style.color = '#28a745';
    } else {
        matchIcon.textContent = '✗';
        matchIcon.style.color = '#dc3545';
        matchText.textContent = 'Passwords do not match';
        matchText.style.color = '#dc3545';
    }
}

// Enhanced add rule form submission
document.addEventListener('DOMContentLoaded', function() {
    const addRuleForm = document.getElementById('addRuleForm');
    if (addRuleForm) {
        addRuleForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            if (!checkRateLimit()) {
                showNotification('Please wait before making another request', 'Rate Limit', 'warning');
                return;
            }
            
            // Get single user dropdown value
            const singleUserId = document.getElementById('rule_user_id').value;
            
            // Check if using bulk selection (checkboxes) or single selection (dropdown)
            const useBulk = selectedUserIds.size > 0;
            
            // Validation: Must have EITHER bulk selection OR single selection
            if (!useBulk && !singleUserId) {
                showNotification(
                    'Please select at least one user using either the checkboxes above or the dropdown below',
                    'No User Selected',
                    'warning'
                );
                return;
            }
            
            // Prevent using both methods simultaneously
            if (useBulk && singleUserId) {
                showNotification(
                    'Please use either bulk selection (checkboxes) OR single user dropdown, not both. Clear one to proceed.',
                    'Multiple Selection Methods',
                    'warning'
                );
                return;
            }
            
            // Submit based on selection method
            if (useBulk) {
                await submitBulkRules();
            } else {
                await submitSingleRule();
            }
        });
    }
});

async function submitSingleRule() {
    const userId = document.getElementById('rule_user_id').value;
    
    if (!userId) {
        showNotification('Please select a user', 'Error', 'warning');
        return;
    }
    
    const fd = createFormDataWithCSRF();
    fd.append('user_id', userId);
    fd.append('rule_type', document.getElementById('rule_type').value);
    fd.append('location', document.getElementById('rule_location').value);
    fd.append('time_from', document.getElementById('rule_time_from').value);
    fd.append('time_to', document.getElementById('rule_time_to').value);
    fd.append('date_from', document.getElementById('rule_date_from').value);
    fd.append('date_to', document.getElementById('rule_date_to').value);
    fd.append('specific_dates', document.getElementById('rule_specific_dates').value);
    
    try {
        const res = await fetch(API_URLS.addAccessRule, {
            method: 'POST',
            body: fd
        });
        const json = await res.json();
        
        if (json.status === 'success') {
            showNotification(json.message, 'Success', 'success');
            document.getElementById('addRuleForm').reset();
            loadAccessRules();
        } else {
            showNotification(json.message, 'Error', 'danger');
        }
    } catch (err) {
        showNotification('Failed to add rule: ' + err.message, 'Error', 'danger');
    }
}

async function loadAccessRules() {
    try {
        const res = await fetch(API_URLS.getAccessRules);
        const json = await res.json();

        if (json.status !== 'success') {
            throw new Error(json.message || 'Failed to load rules');
        }

        const tbody = document.getElementById('rulesTableBody');
        tbody.innerHTML = '';

        if (!json.rules || json.rules.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No access rules configured</td></tr>';
            return;
        }

        json.rules.forEach(rule => {
            const tr = document.createElement('tr');

            const typeClass = rule.rule_type === 'whitelist' ? 'badge-in' : 'badge-out';
            const statusClass = rule.enabled ? 'badge-in' : 'badge-out';

            tr.innerHTML = `
            <td><strong>${rule.user_name}</strong></td>
            <td><span class="badge ${typeClass}">${rule.rule_type.toUpperCase()}</span></td>
            <td>${rule.location || 'Any'}</td>
            <td>${rule.time_from && rule.time_to ? `${rule.time_from} - ${rule.time_to}` : 'Any'}</td>
            <td>${rule.date_from && rule.date_to ? `${rule.date_from} to ${rule.date_to}` : 'Any'}</td>
            <td style="font-size: 12px;">${rule.specific_dates || '-'}</td>
            <td><span class="badge ${statusClass}">${rule.enabled ? 'ENABLED' : 'DISABLED'}</span></td>
            <td>
              <button class="btn btn-secondary" onclick="toggleRule(${rule.rule_id}, ${rule.enabled ? 0 : 1})" 
                      style="font-size: 12px; padding: 4px 8px;">
                ${rule.enabled ? 'Disable' : 'Enable'}
              </button>
              <button class="btn btn-danger" onclick="deleteRule(${rule.rule_id})" 
                      style="font-size: 12px; padding: 4px 8px;">
                Delete
              </button>
            </td>
          `;
            tbody.appendChild(tr);
        });
    } catch (err) {
        document.getElementById('rulesTableBody').innerHTML =
            `<tr><td colspan="8" class="empty-state" style="color: #e53e3e;">Error: ${err.message}</td></tr>`;
    }
}

async function deleteRule(ruleId) {
    if (!confirm('Delete this access rule?')) return;

    if (!checkRateLimit()) {
        showNotification('Please wait before making another request', 'Rate Limit', 'warning');
        return;
    }

    try {
        const fd = createFormDataWithCSRF();
        const res = await fetch(API_URLS.deleteAccessRule.replace('/0', `/${ruleId}`), {
            method: 'POST',
            body: fd
        });
        const json = await res.json();

        if (json.status === 'success') {
            showNotification('Rule deleted', 'Success', 'success');
            loadAccessRules();
        } else {
            showNotification(json.message, 'Error', 'danger');
        }
    } catch (err) {
        showNotification('Failed to delete rule: ' + err.message, 'Error', 'danger');
    }
}

async function toggleRule(ruleId, enabled) {
    if (!checkRateLimit()) {
        showNotification('Please wait before making another request', 'Rate Limit', 'warning');
        return;
    }

    try {
        const fd = createFormDataWithCSRF();
        fd.append('enabled', enabled);

        const res = await fetch(API_URLS.toggleAccessRule.replace('/0', `/${ruleId}`), {
            method: 'POST',
            body: fd
        });
        const json = await res.json();

        if (json.status === 'success') {
            showNotification('Rule updated', 'Success', 'success');
            loadAccessRules();
        } else {
            showNotification(json.message, 'Error', 'danger');
        }
    } catch (err) {
        showNotification('Failed to update rule: ' + err.message, 'Error', 'danger');
    }
}


// Load rules when section is shown
const originalShowSection = showSection;
showSection = function(event, sectionId) {
    originalShowSection(event, sectionId);
    
    if (sectionId === 'settings') {
        loadSystemSettings();  // Load settings when Settings section is opened
        loadAdminList();
    }
    
    if (sectionId === 'access-rules') {
        loadAccessRules();
        initializeUserSelection();
    }
};

document.getElementById('searchInput').addEventListener('input', function () {
    loadUsers(1); 
});

document.getElementById('searchAttendance').addEventListener('input', function () {
    if (attendanceLoaded) loadAttendance(1);
});

document.getElementById('filterDateFrom').addEventListener('change', function () {
    if (attendanceLoaded) loadAttendance(1);
});
document.getElementById('filterDateTo').addEventListener('change', function () {
    if (attendanceLoaded) loadAttendance(1);
});
document.getElementById('filterAction').addEventListener('change', function () {
    if (attendanceLoaded) loadAttendance(1);
});
document.getElementById('filterLocation').addEventListener('change', function () {
    if (attendanceLoaded) loadAttendance(1);
});

setInterval(autoRefresh, 45000);

// ==========================================
// SSE FUNCTIONS
// ==========================================

/**
 * Initialize SSE connection for admin real-time updates
 */
function initializeAdminSSE() {
    if (adminEventSource) {
        adminEventSource.close();
    }

    console.log('[Admin SSE] Connecting to stream...');
    adminEventSource = new EventSource('/sse/admin-stream');

    adminEventSource.onopen = function() {
        console.log('[Admin SSE] Connection established');
        reconnectAttempts = 0;
    };

    adminEventSource.onmessage = function(event) {
        try {
            const data = JSON.parse(event.data);
            handleAdminSSEEvent(data);
        } catch (error) {
            console.error('[Admin SSE] Error parsing message:', error);
        }
    };

    adminEventSource.onerror = function(error) {
        console.error('[Admin SSE] Connection error:', error);
        adminEventSource.close();
        
        attemptAdminReconnect();
    };
}

/**
 * Handle incoming admin SSE events
 */
function handleAdminSSEEvent(event) {
    switch (event.type) {
        case 'connected':
            console.log('[Admin SSE] Stream connected');
            break;
            
        case 'heartbeat':
            // Connection alive
            break;
            
        case 'admin_scan_event':
            handleAdminScanEvent(event.data);
            break;
            
        default:
            console.log('[Admin SSE] Unknown event:', event);
    }
}

function initializeAdminSSE() {
    if (adminEventSource) {
        console.log('[Admin SSE] Closing existing connection');
        adminEventSource.close();
        adminEventSource = null;
    }

    if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
        reconnectTimeout = null;
    }

    console.log('[Admin SSE] Connecting to /sse/admin-stream');
    
    adminEventSource = new EventSource('/sse/admin-stream');

    adminEventSource.onopen = function() {
        console.log('[Admin SSE] ✅ Connection established');
        reconnectAttempts = 0;
    };

    adminEventSource.onmessage = function(event) {
        try {
            const data = JSON.parse(event.data);
            console.log('[Admin SSE] Message received:', data);
            handleAdminSSEEvent(data);
        } catch (error) {
            console.error('[Admin SSE] Parse error:', error);
        }
    };

    adminEventSource.onerror = function(error) {
        console.error('[Admin SSE] Connection error:', error);
        console.log('[Admin SSE] ReadyState:', adminEventSource.readyState);
        
        if (adminEventSource.readyState === EventSource.CLOSED) {
            console.log('[Admin SSE] Connection closed, attempting reconnect');
            adminEventSource.close();
            attemptAdminReconnect();
        }
    };
}

function handleAdminScanEvent(data) {
    console.log('[Admin SSE] 📢 Scan event received:', data);
    
    const totalInsideEl = document.getElementById('totalInsideCount');
    if (totalInsideEl) {
        const oldValue = parseInt(totalInsideEl.textContent) || 0;
        const newValue = data.total_inside || 0;
        
        totalInsideEl.textContent = newValue;
        
        if (oldValue !== newValue) {
            totalInsideEl.style.animation = 'none';
            setTimeout(() => {
                totalInsideEl.style.animation = 'pulse 0.5s ease-in-out';
            }, 10);
        }
    }
    
    const locationValueEl = document.querySelector('#statCardLocation .value');
    if (locationValueEl && data.location) {
        locationValueEl.textContent = data.location;
    }
    
    const locationSelect = document.getElementById('locationSelect');
    if (locationSelect && data.location) {
        locationSelect.value = data.location;
    }
    
    updateLastActivity(data);
    
    const action = data.action === 'IN' ? 'entered' : 'exited';
    
    showNotification(
        `${data.name} ${action} at ${data.location}`,
        `Scan Recorded - ${data.action}`,
        data.action === 'IN' ? 'success' : 'info'
    );
    
    playAdminNotificationSound();
    
    console.log('[Admin SSE] Refreshing dashboard...');
    autoRefresh();
    
    const attendanceSection = document.getElementById('section-attendance');
    const isAttendanceVisible = attendanceSection && !attendanceSection.classList.contains('section-hidden');
    
    console.log('[Admin SSE] Attendance section exists:', !!attendanceSection);
    console.log('[Admin SSE] Attendance visible:', isAttendanceVisible);
    console.log('[Admin SSE] Attendance loaded:', attendanceLoaded);
    
    if (isAttendanceVisible && attendanceLoaded) {
        console.log('[Admin SSE] ✅ Refreshing attendance NOW');
        
        setTimeout(() => {
            lastAttendanceUpdate = Date.now();
            loadAttendance(currentPage, true);
        }, 300);
    } else {
        console.log('[Admin SSE] ⏸️ Attendance not visible, marking for refresh');
        attendanceNeedsRefresh = true;
    }
}



/**
 * Update last activity display
 */
function updateLastActivity(data) {
    const lastActivityTime = document.getElementById('lastActivityTime');
    const lastActivityAction = document.getElementById('lastActivityAction');
    
    if (lastActivityTime && lastActivityAction) {
        lastActivityTime.textContent = 'Just now';
        const action = data.action === 'IN' ? 'Entered' : 'Exited';
        lastActivityAction.textContent = `${data.name} - ${action} at ${data.location}`;
    }
}

/**
 * Refresh dashboard data in background
 */
function refreshDashboardInBackground() {
    const dashboardSection = document.getElementById('section-dashboard');
    const isVisible = dashboardSection && !dashboardSection.classList.contains('section-hidden');
    
    if (isVisible) {
        console.log('[Admin SSE] Refreshing dashboard data');
        autoRefresh();
    }
}

/**
 * Refresh attendance in background
 */
function refreshAttendanceInBackground() {
    const now = Date.now();
    
    if (now - lastAttendanceUpdate < ATTENDANCE_UPDATE_COOLDOWN) {
        console.log('[Admin SSE] Attendance cooldown active');
        attendanceNeedsRefresh = true;
        return;
    }
    
    if (isLoading) {
        console.log('[Admin SSE] Attendance already loading');
        attendanceNeedsRefresh = true;
        return;
    }
    
    lastAttendanceUpdate = now;
    
    const attendanceSection = document.getElementById('section-attendance');
    const isVisible = attendanceSection && !attendanceSection.classList.contains('section-hidden');
    
    if (isVisible && attendanceLoaded) {
        console.log('[Admin SSE] Refreshing attendance data');
        currentPage = 1;
        loadAttendance(1, true); // Silent refresh
    }
}

/**
 * Play admin notification sound
 */
function playAdminNotificationSound() {
    try {
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioContext.createOscillator();
        const gainNode = audioContext.createGain();
        
        oscillator.connect(gainNode);
        gainNode.connect(audioContext.destination);
        
        oscillator.frequency.value = 600;
        oscillator.type = 'sine';
        
        gainNode.gain.setValueAtTime(0.05, audioContext.currentTime);
        gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.15);
        
        oscillator.start(audioContext.currentTime);
        oscillator.stop(audioContext.currentTime + 0.15);
    } catch (e) {
        console.log('Audio not supported');
    }
}

/**
 * Attempt to reconnect admin SSE
 */
function attemptAdminReconnect() {
    if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
        console.error('[Admin SSE] Max reconnection attempts reached');
        showNotification(
            'Lost connection to server. Please refresh the page.',
            'Connection Lost',
            'danger'
        );
        return;
    }
    
    reconnectAttempts++;
    console.log(`[Admin SSE] Reconnecting (${reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS})...`);
    
    reconnectTimeout = setTimeout(() => {
        initializeAdminSSE();
    }, RECONNECT_DELAY * reconnectAttempts);
}

/**
 * Cleanup admin SSE on page unload
 */
window.addEventListener('beforeunload', function() {
    if (adminEventSource) {
        adminEventSource.close();
    }
    if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
    }
});