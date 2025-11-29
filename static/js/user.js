const SECURITY_CONFIG = {
    sessionTimeout: 30 * 60 * 1000,
    warningTime: 2 * 60 * 1000,
    inactivityCheckInterval: 60000,
    apiRateLimit: 300,
    maxFailedAttempts: 5,
    lockoutDuration: 15 * 60 * 1000
};

let securityState = {
    lastActivity: Date.now(),
    sessionTimer: null,
    warningTimer: null,
    failedAttempts: 0,
    lastApiCall: 0,
    isLocked: false
};

// SSE connection
let eventSource = null;
let reconnectTimeout = null;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 5;
const RECONNECT_DELAY = 3000;

// Attendance state management
let attendanceNeedsRefresh = false;
let lastAttendanceUpdate = 0;
const ATTENDANCE_UPDATE_COOLDOWN = 1000; // Reduced for better real-time
let pendingRefresh = false;
let currentPage = 1;
let totalPages = 1;
const recordsPerPage = 10;
let attendanceLoaded = false;
let isLoading = false;

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

/**
 * Initialize SSE connection for real-time updates
 */
function initializeSSE() {
    if (eventSource) {
        eventSource.close();
    }

    console.log('Connecting to SSE stream...');
    eventSource = new EventSource('/sse/stream');

    eventSource.onopen = function() {
        console.log('SSE connection established');
        reconnectAttempts = 0;
        
        // Show connection indicator
        const indicator = document.getElementById('realtimeIndicator');
        if (indicator) {
            indicator.textContent = '● Live';
            indicator.style.color = '#38a169';
        }
    };

    eventSource.onmessage = function(event) {
        try {
            const data = JSON.parse(event.data);
            handleSSEEvent(data);
        } catch (error) {
            console.error('Error parsing SSE message:', error);
        }
    };

    eventSource.onerror = function(error) {
        console.error('SSE connection error:', error);
        eventSource.close();
        
        // Update connection indicator
        const indicator = document.getElementById('realtimeIndicator');
        if (indicator) {
            indicator.textContent = '● Disconnected';
            indicator.style.color = '#e53e3e';
        }
        
        // Attempt reconnection
        attemptReconnect();
    };
}

/**
 * Handle incoming SSE events
 */
function handleSSEEvent(event) {
    switch (event.type) {
        case 'connected':
            console.log('SSE stream connected');
            break;
            
        case 'heartbeat':
            // Connection is alive
            break;
            
        case 'scan_event':
            handleScanEvent(event.data);
            break;
            
        default:
            console.log('Unknown SSE event:', event);
    }
}

function handleScanEvent(data) {
    console.log('Scan event received:', data);
    
    // Update stats instantly
    if (data.stats) {
        document.getElementById('totalScansToday').textContent = data.stats.total;
        document.getElementById('timesInToday').textContent = data.stats.in_count;
        document.getElementById('timesOutToday').textContent = data.stats.out_count;
    }
    
    // Update current status
    if (data.status) {
        updateCurrentStatusDisplay(data.status);
    }
    
    // Update recent location
    updateRecentLocationDisplay(data);
    
    // Show professional notification without emoji
    const action = data.action === 'IN' ? 'Entered' : 'Exited';
    const location = data.location || 'Gate';
    
    showProfessionalNotification(
        `Access ${action}`,
        `${action} at ${location}`,
        data.action === 'IN' ? 'success' : 'info'
    );
    
    // Play notification sound
    playNotificationSound();
    
    // Refresh attendance with improved real-time handling
    refreshAttendanceInBackground();
    
    // Refresh activity heatmap (debounced)
    debounceHeatmapRefresh();
    loadRecentActivity();
}

/**
 * Professional notification system without emojis
 */
function showProfessionalNotification(title, message, type = 'info') {
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


function refreshAttendanceInBackground() {
    const now = Date.now();
    
    // Prevent too frequent updates
    if (now - lastAttendanceUpdate < ATTENDANCE_UPDATE_COOLDOWN) {
        console.log('[Attendance] Cooldown active, queuing refresh');
        pendingRefresh = true;
        setTimeout(() => {
            if (pendingRefresh) {
                pendingRefresh = false;
                refreshAttendanceInBackground();
            }
        }, ATTENDANCE_UPDATE_COOLDOWN);
        return;
    }
    
    // If already loading, queue the refresh for later
    if (isLoading) {
        console.log('[Attendance] Already loading, queuing refresh');
        pendingRefresh = true;
        
        setTimeout(() => {
            if (pendingRefresh && !isLoading) {
                pendingRefresh = false;
                refreshAttendanceInBackground();
            }
        }, 1000);
        return;
    }
    
    lastAttendanceUpdate = now;
    pendingRefresh = false;
    
    console.log('[Attendance] Background refresh triggered');
    
    // Reset to page 1 to show newest records
    currentPage = 1;
    
    // Load attendance without showing loading state if not visible
    const attendanceSection = document.getElementById('section-attendance');
    const isVisible = attendanceSection && !attendanceSection.classList.contains('section-hidden');
    
    loadAttendance(1, !isVisible); // Pass 'silent' flag if not visible
}

/**
 * Update current status display
 */
function updateCurrentStatusDisplay(status) {
    const statusElement = document.getElementById('currentStatus');
    if (!statusElement) return;
    
    let badgeClass = 'status-badge';
    let statusText = status.status;
    
    if (status.status === 'IN') {
        badgeClass += ' status-in';
        statusText = `Inside (${status.location})`;
    } else if (status.status === 'OUT') {
        badgeClass += ' status-out';
        statusText = `Outside`;
    } else {
        badgeClass += ' status-unknown';
        statusText = 'No Records';
    }
    
    statusElement.innerHTML = `<span class="${badgeClass}">${statusText}</span>`;
}

/**
 * Update recent location display
 */
function updateRecentLocationDisplay(data) {
    const locationNameEl = document.getElementById('recentLocation');
    const locationTimeEl = document.getElementById('recentLocationTime');
    
    if (!locationNameEl || !locationTimeEl) return;
    
    const action = data.action === 'IN' ? 'Entered' : 'Exited';
    locationNameEl.textContent = `${action} at ${data.location}`;
    
    if (data.timestamp) {
        const timeParts = data.timestamp.split(' ');
        locationTimeEl.textContent = `${timeParts[0]} at ${timeParts[1]}`;
    }
}

/**
 * Play notification sound
 */
function playNotificationSound() {
    try {
        // Simple beep using Web Audio API
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        
        // Only proceed if audio context is available and not suspended
        if (audioContext) {
            const oscillator = audioContext.createOscillator();
            const gainNode = audioContext.createGain();
            
            oscillator.connect(gainNode);
            gainNode.connect(audioContext.destination);
            
            oscillator.frequency.value = 800;
            oscillator.type = 'sine';
            gainNode.gain.value = 0.1;
            
            oscillator.start(audioContext.currentTime);
            oscillator.stop(audioContext.currentTime + 0.1);
        }
    } catch (error) {
        console.log('Notification sound not available:', error);
        // Silently fail - audio is non-essential
    }
}

/**
 * Debounced heatmap refresh
 */
let heatmapRefreshTimeout = null;
function debounceHeatmapRefresh() {
    if (heatmapRefreshTimeout) {
        clearTimeout(heatmapRefreshTimeout);
    }
    heatmapRefreshTimeout = setTimeout(() => {
        loadActivityHeatmap();
    }, 2000);
}

/**
 * Attempt to reconnect SSE
 */
function attemptReconnect() {
    if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
        console.error('Max reconnection attempts reached');
        showProfessionalNotification(
            'Connection Lost',
            'Lost connection to server. Please refresh the page.',
            'warning'
        );
        return;
    }
    
    reconnectAttempts++;
    console.log(`Attempting to reconnect (${reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS})...`);
    
    reconnectTimeout = setTimeout(() => {
        initializeSSE();
    }, RECONNECT_DELAY * reconnectAttempts);
}

/**
 * Cleanup SSE on page unload
 */
window.addEventListener('beforeunload', function() {
    if (eventSource) {
        eventSource.close();
    }
    if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
    }
});

document.addEventListener('DOMContentLoaded', function () {
    if (typeof APP_CONFIG === 'undefined') {
        console.error('APP_CONFIG not found. Make sure it is defined in the HTML file.');
        return;
    }

    initializeSecurity();
    initializeDarkMode();
    
    // Initialize SSE for real-time updates
    initializeSSE();

    const filterDateFrom = document.getElementById('filterDateFrom');
    const filterDateTo = document.getElementById('filterDateTo');
    
    if (filterDateFrom) {
        filterDateFrom.valueAsDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
        filterDateFrom.addEventListener('change', instantRefresh);
    }
    
    if (filterDateTo) {
        filterDateTo.valueAsDate = new Date();
        filterDateTo.addEventListener('change', instantRefresh);
    }

    const filterAction = document.getElementById('filterAction');
    if (filterAction) {
        filterAction.addEventListener('change', instantRefresh);
    }

    const profileForm = document.getElementById('profileForm');
    if (profileForm) {
        profileForm.addEventListener('submit', handleProfileSubmit);
    }

    const newPassword = document.getElementById('new_password');
    const confirmPassword = document.getElementById('confirm_password');
    
    if (newPassword) newPassword.addEventListener('input', validatePassword);
    if (confirmPassword) confirmPassword.addEventListener('input', validatePasswordMatch);

    if (APP_CONFIG.forcePasswordChange) {
        const passwordAlert = document.getElementById('passwordAlert');
        const passwordInfoBox = document.getElementById('passwordInfoBox');
        
        if (passwordAlert) passwordAlert.style.display = 'block';
        if (passwordInfoBox) passwordInfoBox.style.display = 'none';

        const profileLink = document.querySelector('[onclick*="profile"]');
        if (profileLink) {
            profileLink.addEventListener('click', function (e) {
                setTimeout(() => {
                    const profileSection = document.getElementById('section-profile');
                    if (profileSection) {
                        profileSection.scrollIntoView({ behavior: 'smooth' });
                    }
                }, 100);
            });
        }
    }

    setupLogoutConfirmation();
    loadAttendance(1);
    attendanceLoaded = true;

    loadDailyStats();
    loadCurrentStatus();
    loadRecentLocation();     
    loadActivityHeatmap();
    loadRecentActivity();
    
    console.log('[Init] Real-time attendance updates enabled');
    
    // Add CSS animations for notifications
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
});

function instantRefresh() {
    if (!isLoading) {
        currentPage = 1;
        loadAttendance(1, false); // Not silent - user initiated
    }
}

function setupLogoutConfirmation() {
    const logoutForms = document.querySelectorAll('form[action*="logout"]');

    logoutForms.forEach(form => {
        form.addEventListener('submit', function (e) {
            if (!confirm('Are you sure you want to logout?')) {
                e.preventDefault();
                return false;
            }
            
            // Close SSE connection before logout
            if (eventSource) {
                eventSource.close();
            }
            
            this.dataset.submitting = 'true';
        });
    });
}

function handleProfileSubmit(e) {
    if (!checkRateLimit()) {
        e.preventDefault();
        showProfessionalNotification('Rate Limit', 'Please wait before making another request', 'warning');
        return false;
    }

    const username = document.getElementById('username').value.trim();
    const name = document.getElementById('name').value.trim();
    const newPassword = document.getElementById('new_password').value;
    const confirmPassword = document.getElementById('confirm_password').value;

    if (!username || username.length < 3) {
        e.preventDefault();
        showProfessionalNotification('Validation Error', 'Username must be at least 3 characters long', 'warning');
        document.getElementById('username').focus();
        return false;
    }

    if (!name) {
        e.preventDefault();
        showProfessionalNotification('Validation Error', 'Name is required', 'warning');
        document.getElementById('name').focus();
        return false;
    }

    if (newPassword || confirmPassword) {
        if (!newPassword || !confirmPassword) {
            e.preventDefault();
            showProfessionalNotification('Password Change', 'Please fill both password fields to change your password', 'warning');
            document.getElementById('new_password').focus();
            return false;
        }

        if (newPassword.length < 8) {
            e.preventDefault();
            showProfessionalNotification('Password Requirements', 'Password must be at least 8 characters long', 'warning');
            document.getElementById('new_password').focus();
            return false;
        }

        if (newPassword !== confirmPassword) {
            e.preventDefault();
            showProfessionalNotification('Password Mismatch', 'Passwords do not match. Please ensure both passwords are identical.', 'warning');
            document.getElementById('confirm_password').focus();
            return false;
        }
    }

    const btn = document.getElementById('saveProfileBtn');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="loading"></span> Saving...';
    }

    return true;
}

async function loadRecentLocation() {
    try {
        const response = await fetch(APP_CONFIG.getCurrentStatusUrl);
        const data = await response.json();
        
        if (data.status === 'success') {
            updateCurrentStatusDisplay(data.user_status);
            
            const status = data.user_status;
            const locationNameEl = document.getElementById('recentLocation');
            const locationTimeEl = document.getElementById('recentLocationTime');
            
            if (status.status === 'UNKNOWN') {
                locationNameEl.textContent = 'No recent activity';
                locationTimeEl.textContent = 'Start scanning to see your location history';
            } else {
                const action = status.status === 'IN' ? 'Entered' : 'Exited';
                locationNameEl.textContent = `${action} at ${status.location}`;
                
                if (status.timestamp) {
                    // NEW: Use formatDateTime helper
                    const { date, time } = formatDateTime(status.timestamp);
                    locationTimeEl.textContent = `${date} at ${time}`;
                }
            }
        }
    } catch (error) {
        console.error('Error loading recent location:', error);
        document.getElementById('recentLocation').textContent = 'Unable to load location';
    }
}

async function loadActivityHeatmap() {
    try {
        const response = await fetch(`${window.location.origin}/user/activity-heatmap`);
        const data = await response.json();
        
        if (data.status === 'success') {
            renderHeatmapVertical(data.activity);
        }
    } catch (error) {
        console.error('Error loading activity heatmap:', error);
        document.getElementById('heatmapColumns').innerHTML = 
            '<div style="text-align: center; padding: 40px; color: var(--text-tertiary);">Failed to load activity data</div>';
    }
}

function renderHeatmapVertical(activityData) {
    const columnsEl = document.getElementById('heatmapColumns');
    const monthsEl = document.getElementById('heatmapMonths');
    
    if (!activityData || activityData.length === 0) {
        columnsEl.innerHTML = '<div style="text-align: center; padding: 20px; color: var(--text-tertiary); font-size: 12px;">No activity data available</div>';
        return;
    }
    
    columnsEl.innerHTML = '';
    monthsEl.innerHTML = '';
    
    const counts = activityData.map(d => d.count);
    const maxCount = Math.max(...counts, 1);
    
    const tooltip = document.createElement('div');
    tooltip.className = 'heatmap-tooltip';
    document.body.appendChild(tooltip);
    
    const dateMap = new Map();
    activityData.forEach(day => {
        dateMap.set(day.date, day.count);
    });
    
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(endDate.getDate() - 364);
    
    const allDays = [];
    const currentDate = new Date(startDate);
    
    while (currentDate <= endDate) {
        const dateStr = currentDate.toISOString().split('T')[0];
        const count = dateMap.get(dateStr) || 0;
        
        allDays.push({
            date: dateStr,
            count: count,
            dayOfWeek: currentDate.getDay(),
            month: currentDate.toLocaleDateString('en-US', { month: 'short' }),
            monthKey: currentDate.toLocaleDateString('en-US', { month: 'short', year: 'numeric' }),
            year: currentDate.getFullYear(),
            monthIndex: currentDate.getMonth()
        });
        
        currentDate.setDate(currentDate.getDate() + 1);
    }
    
    const monthGroups = new Map();
    
    allDays.forEach(day => {
        if (!monthGroups.has(day.monthKey)) {
            monthGroups.set(day.monthKey, {
                name: day.month,
                days: [],
                year: day.year,
                monthIndex: day.monthIndex
            });
        }
        monthGroups.get(day.monthKey).days.push(day);
    });
    
    const monthArray = Array.from(monthGroups.entries())
        .sort((a, b) => {
            if (a[1].year !== b[1].year) return a[1].year - b[1].year;
            return a[1].monthIndex - b[1].monthIndex;
        });
    
    columnsEl.innerHTML = `
        <div class="heatmap-day-labels">
            <div class="day-label">M</div>
            <div class="day-label"></div>
            <div class="day-label">W</div>
            <div class="day-label"></div>
            <div class="day-label">F</div>
            <div class="day-label"></div>
            <div class="day-label">S</div>
        </div>
        <div class="heatmap-grid" id="heatmapGrid"></div>
    `;
    
    const heatmapGrid = document.getElementById('heatmapGrid');
    const monthWidths = [];
    
    monthArray.forEach(([monthKey, monthData]) => {
        const weeks = [];
        let currentWeek = [];
        let currentWeekStartDay = -1;
        
        monthData.days.forEach(day => {
            const dayOfWeek = day.dayOfWeek;
            
            if (currentWeekStartDay === -1) {
                currentWeekStartDay = dayOfWeek;
            }
            
            while (currentWeek.length < dayOfWeek) {
                currentWeek.push({ empty: true, dayOfWeek: currentWeek.length });
            }
            
            currentWeek.push(day);
            
            if (dayOfWeek === 6 || day === monthData.days[monthData.days.length - 1]) {
                while (currentWeek.length < 7) {
                    currentWeek.push({ empty: true, dayOfWeek: currentWeek.length });
                }
                weeks.push(currentWeek);
                currentWeek = [];
                currentWeekStartDay = -1;
            }
        });
        
        monthData.weeks = weeks;
        const monthWidth = weeks.length * 10 - 2;
        monthWidths.push(monthWidth);
    });
    
    monthArray.forEach(([monthKey, monthData], index) => {
        const monthLabel = document.createElement('div');
        monthLabel.className = 'month-label';
        monthLabel.textContent = monthData.name;
        monthLabel.title = `${monthData.name} ${monthData.year}`;
        monthLabel.style.flex = `0 0 ${monthWidths[index]}px`;
        monthsEl.appendChild(monthLabel);
    });
    
    monthArray.forEach(([monthKey, monthData], monthIndex) => {
        const monthGroup = document.createElement('div');
        monthGroup.className = 'heatmap-month-group';
        
        const monthColumns = document.createElement('div');
        monthColumns.className = 'heatmap-columns';
        
        monthData.weeks.forEach(week => {
            const column = document.createElement('div');
            column.className = 'heatmap-column';
            
            week.forEach(day => {
                const square = document.createElement('div');
                square.className = 'heatmap-day';
                
                if (day.empty) {
                    square.classList.add('empty');
                } else {
                    let level = 0;
                    if (day.count > 0) {
                        const percentage = day.count / maxCount;
                        if (percentage <= 0.25) level = 1;
                        else if (percentage <= 0.5) level = 2;
                        else if (percentage <= 0.75) level = 3;
                        else level = 4;
                    }
                    
                    square.classList.add(`level-${level}`);
                    square.dataset.date = day.date;
                    square.dataset.count = day.count;
                    
                    square.addEventListener('mouseenter', (e) => {
                        const date = new Date(day.date);
                        const formattedDate = date.toLocaleDateString('en-US', { 
                            weekday: 'short', 
                            year: 'numeric', 
                            month: 'short', 
                            day: 'numeric' 
                        });
                        
                        tooltip.textContent = `${day.count} ${day.count === 1 ? 'scan' : 'scans'} on ${formattedDate}`;
                        tooltip.classList.add('show');
                        
                        const rect = square.getBoundingClientRect();
                        tooltip.style.left = (rect.left + window.scrollX - (tooltip.offsetWidth / 2) + 4) + 'px';
                        tooltip.style.top = (rect.top + window.scrollY - tooltip.offsetHeight - 4) + 'px';
                    });
                    
                    square.addEventListener('mouseleave', () => {
                        tooltip.classList.remove('show');
                    });
                }
                
                column.appendChild(square);
            });
            
            monthColumns.appendChild(column);
        });
        
        monthGroup.appendChild(monthColumns);
        heatmapGrid.appendChild(monthGroup);
        
        if (monthIndex < monthArray.length - 1) {
            const separator = document.createElement('div');
            separator.className = 'month-separator';
            heatmapGrid.appendChild(separator);
        }
    });
    
    setTimeout(() => {
        const gridRect = heatmapGrid.getBoundingClientRect();
        const dayLabelsRect = document.querySelector('.heatmap-day-labels').getBoundingClientRect();
        const totalGridWidth = gridRect.width - dayLabelsRect.width;
        monthsEl.style.width = `${totalGridWidth}px`;
        monthsEl.style.marginLeft = `${dayLabelsRect.width}px`;
    }, 100);
}

async function checkSessionStatus() {
    try {
        const response = await fetch('/health', {
            method: 'GET',
            credentials: 'include'
        });

        if (response.status === 401 || response.status === 403) {
            window.location.href = APP_CONFIG.loginUrl || '/login';
        }
    } catch (error) {
        console.error('Session check failed:', error);
    }
}

setInterval(checkSessionStatus, 5 * 60 * 1000);

window.addEventListener('pageshow', function (event) {
    if (event.persisted || (window.performance && window.performance.navigation.type === 2)) {
        const isProtectedPage = window.location.pathname.includes('/admin/') ||
            window.location.pathname.includes('/user/dashboard');

        if (isProtectedPage) {
            window.location.reload();
        }
    }
});

window.addEventListener('beforeunload', function (e) {
    const logoutForm = document.querySelector('form[action*="logout"]');
    if (logoutForm && logoutForm.dataset.submitting === 'true') {
        if (window.sessionStorage) {
            sessionStorage.clear();
        }
        if (window.localStorage) {
            const keysToKeep = ['user_device_token', 'admin_device_token'];
            Object.keys(localStorage).forEach(key => {
                if (!keysToKeep.includes(key)) {
                    localStorage.removeItem(key);
                }
            });
        }
    }
});

function validatePassword() {
    const password = document.getElementById('new_password').value;
    const confirmPassword = document.getElementById('confirm_password').value;
    const strengthFill = document.getElementById('strengthFill');
    const strengthText = document.getElementById('strengthText');

    let strength = 0;

    if (password.length >= 8) strength += 25;
    if (/[A-Z]/.test(password)) strength += 25;
    if (/[0-9]/.test(password) || /[^A-Za-z0-9]/.test(password)) strength += 25;

    if (strengthFill) {
        strengthFill.style.width = strength + '%';

        if (password.length === 0) {
            strengthText.textContent = 'Password strength';
            strengthFill.style.backgroundColor = '#ddd';
        } else if (strength < 50) {
            strengthText.textContent = 'Weak';
            strengthFill.style.backgroundColor = '#e53e3e';
        } else if (strength < 75) {
            strengthText.textContent = 'Fair';
            strengthFill.style.backgroundColor = '#dd6b20';
        } else {
            strengthText.textContent = 'Strong';
            strengthFill.style.backgroundColor = '#38a169';
        }
    }

    updateValidationSummary();

    if (confirmPassword) {
        validatePasswordMatch();
    }
}

function validatePasswordMatch() {
    const password = document.getElementById('new_password').value;
    const confirmPassword = document.getElementById('confirm_password').value;
    const matchIcon = document.getElementById('matchIcon');
    const matchText = document.getElementById('matchText');
    const matchIndicator = document.getElementById('matchIndicator');

    if (matchIcon && matchText && matchIndicator) {
        if (confirmPassword.length === 0) {
            matchIcon.textContent = '—';
            matchText.textContent = 'Passwords must match';
            matchIndicator.style.color = '#666';
        } else if (password === confirmPassword) {
            matchIcon.textContent = '✓';
            matchText.textContent = 'Passwords match';
            matchIndicator.style.color = '#38a169';
        } else {
            matchIcon.textContent = '✗';
            matchText.textContent = 'Passwords do not match';
            matchIndicator.style.color = '#e53e3e';
        }
    }

    updateValidationSummary();
}

function updateValidationSummary() {
    const password = document.getElementById('new_password').value;
    const confirmPassword = document.getElementById('confirm_password').value;
    const validationSummary = document.getElementById('validationSummary');
    const validationLength = document.getElementById('validationLength');
    const validationMatch = document.getElementById('validationMatch');

    if (validationSummary) {
        if (password.length > 0 || confirmPassword.length > 0) {
            validationSummary.style.display = 'block';
        } else {
            validationSummary.style.display = 'none';
            return;
        }
    }

    if (validationLength) {
        const lengthValid = password.length >= 8;
        validationLength.querySelector('.validation-icon').textContent = lengthValid ? '✓' : '○';
        validationLength.querySelector('.validation-icon').style.color = lengthValid ? '#38a169' : '#666';
        validationLength.querySelector('.validation-text').style.color = lengthValid ? '#38a169' : '#666';
    }

    if (validationMatch) {
        const matchValid = password === confirmPassword && password.length > 0 && confirmPassword.length > 0;
        validationMatch.querySelector('.validation-icon').textContent = matchValid ? '✓' : '○';
        validationMatch.querySelector('.validation-icon').style.color = matchValid ? '#38a169' : '#666';
        validationMatch.querySelector('.validation-text').style.color = matchValid ? '#38a169' : '#666';
    }
}

function initializeSecurity() {
    document.addEventListener('mousemove', resetSessionTimer);
    document.addEventListener('keypress', resetSessionTimer);
    document.addEventListener('click', resetSessionTimer);
    document.addEventListener('scroll', resetSessionTimer);

    startSessionTimer();
    setInterval(checkSecurityStatus, SECURITY_CONFIG.inactivityCheckInterval);
    checkConnectionSecurity();

    updateActivityTime();
    setInterval(updateActivityTime, 60000);
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
    const warningEl = document.getElementById('sessionTimeoutWarning');
    if (warningEl) {
        warningEl.classList.remove('section-hidden');

        let timeLeft = SECURITY_CONFIG.warningTime / 1000;
        const countdownElement = document.getElementById('countdown');

        const countdownInterval = setInterval(() => {
            timeLeft--;
            const minutes = Math.floor(timeLeft / 60);
            const seconds = timeLeft % 60;
            if (countdownElement) {
                countdownElement.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
            }

            if (timeLeft <= 0) {
                clearInterval(countdownInterval);
            }
        }, 1000);
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
        showProfessionalNotification('Appearance', 'Dark mode enabled', 'info');
    }
    
    const toggle = document.getElementById('darkModeToggle');
    if (toggle) {
        toggle.checked = true;
    }
}

function disableDarkMode(save = true) {
    document.body.classList.remove('dark-mode');
    
    if (save) {
        localStorage.setItem('theme', 'light');
        showProfessionalNotification('Appearance', 'Light mode enabled', 'info');
    }
    
    const toggle = document.getElementById('darkModeToggle');
    if (toggle) {
        toggle.checked = false;
    }
}


function extendSession() {
    const warningEl = document.getElementById('sessionTimeoutWarning');
    if (warningEl) {
        warningEl.classList.add('section-hidden');
    }

    if (!APP_CONFIG.resendCodeUrl) {
        console.error('Resend code URL not configured');
        resetSessionTimer();
        return;
    }

    fetch(APP_CONFIG.resendCodeUrl, {
        method: 'POST',
        headers: {
            'X-CSRF-Token': getCSRFToken()
        }
    })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success' || data.status === 'error') {
                resetSessionTimer();
                showProfessionalNotification('Session Extended', 'Session extended successfully', 'success');
            }
        })
        .catch(error => {
            console.error('Error extending session:', error);
            resetSessionTimer();
        });
}

function logoutUser() {
    window.location.href = APP_CONFIG.logoutUrl || '/logout';
}

function checkRateLimit() {
    const now = Date.now();
    if (now - securityState.lastApiCall < SECURITY_CONFIG.apiRateLimit) {
        return false;
    }
    securityState.lastApiCall = now;
    return true;
}

function checkConnectionSecurity() {
    const securityStatus = document.getElementById('securityStatus');

    if (!securityStatus) return;

    const isLocalhost = window.location.hostname === 'localhost' ||
        window.location.hostname === '127.0.0.1' ||
        window.location.hostname === '[::1]';

    const isHTTPS = window.location.protocol === 'https:';

    if (isHTTPS) {
        securityStatus.className = 'security-indicator secure';
        securityStatus.textContent = 'Secure Connection';

        setTimeout(() => {
            showProfessionalNotification(
                'Secure Connection Active',
                'Your connection is encrypted with HTTPS. All data is transmitted securely.',
                'success'
            );
        }, 1000);

    } else if (isLocalhost) {
        securityStatus.className = 'security-indicator warning';
        securityStatus.textContent = 'Development Mode';

        setTimeout(() => {
            showProfessionalNotification(
                'Development Environment',
                'Running in development mode. Always use HTTPS in production environments.',
                'warning'
            );
        }, 1000);

    } else {
        securityStatus.className = 'security-indicator danger';
        securityStatus.textContent = 'INSECURE CONNECTION';

        setTimeout(() => {
            showProfessionalNotification(
                'CRITICAL: INSECURE CONNECTION',
                'CRITICAL SECURITY WARNING: This connection is NOT encrypted. All data including passwords are transmitted in plain text and can be intercepted. HTTPS MUST be enabled immediately!',
                'danger'
            );
        }, 500);

        console.error('SECURITY ALERT: Production site accessed over unencrypted HTTP connection');
    }
}

function checkSecurityStatus() {
    const timeSinceLastActivity = Date.now() - securityState.lastActivity;

    if (timeSinceLastActivity > 15 * 60 * 1000) {
        const securityStatus = document.getElementById('securityStatus');
        if (securityStatus && securityStatus.className === 'security-indicator secure') {
            securityStatus.className = 'security-indicator warning';
            securityStatus.textContent = 'Inactive';
        }
    }
}

function updateActivityTime() {
    const timeSinceActivity = Date.now() - securityState.lastActivity;
    const minutes = Math.floor(timeSinceActivity / 60000);
    const activityElement = document.getElementById('lastActivityTime');

    if (activityElement) {
        if (minutes === 0) {
            activityElement.textContent = 'Just now';
        } else if (minutes === 1) {
            activityElement.textContent = '1 minute ago';
        } else if (minutes < 60) {
            activityElement.textContent = `${minutes} minutes ago`;
        } else {
            const hours = Math.floor(minutes / 60);
            activityElement.textContent = hours === 1 ? '1 hour ago' : `${hours} hours ago`;
        }
    }
}

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    if (sidebar) {
        sidebar.classList.toggle('active');
    }
}

function showSection(e, sectionName) {
    e.preventDefault();

    // Hide all sections
    document.querySelectorAll('[id^="section-"]').forEach(section => {
        section.classList.add('section-hidden');
    });

    // Show target section
    const targetSection = document.getElementById('section-' + sectionName);
    if (targetSection) {
        targetSection.classList.remove('section-hidden');
    }

    // Update active menu item
    document.querySelectorAll('.menu-item').forEach(item => {
        item.classList.remove('active');
    });
    e.currentTarget.classList.add('active');

    // Update page title
    const titles = {
        'dashboard': 'Dashboard',
        'qr': 'My QR Code',
        'attendance': 'Attendance Records',
        'trusted-devices': 'Trusted Devices',
        'profile': 'Profile Settings'
    };
    
    const pageTitleEl = document.getElementById('pageTitle');
    if (pageTitleEl) {
        pageTitleEl.textContent = titles[sectionName] || 'Dashboard';
    }

    // Handle attendance section
    if (sectionName === 'attendance') {
        // If attendance hasn't been loaded yet, load it
        if (!attendanceLoaded) {
            console.log('[Attendance] Loading for first time');
            loadAttendance(1);
            attendanceLoaded = true;
        }
        // If there's a pending refresh flag, clear it
        // (data should already be updated from background refresh)
        attendanceNeedsRefresh = false;
    }

    // Close sidebar on mobile
    if (window.innerWidth <= 768) {
        const sidebar = document.getElementById('sidebar');
        if (sidebar) {
            sidebar.classList.remove('active');
        }
    }
}

async function loadAttendance(page = 1, silent = false) {
    // If we're already loading and this is a background refresh, queue it
    if (isLoading && silent) {
        console.log('[Attendance-BG] Already loading, marking for refresh');
        attendanceNeedsRefresh = true;
        return;
    }

    if (!checkRateLimit()) {
        if (!silent) {
            showProfessionalNotification('Rate Limit', 'Please wait before making another request', 'warning');
        }
        return;
    }

    if (!APP_CONFIG.getUserAttendanceUrl) {
        console.error('Get attendance URL not configured');
        return;
    }

    currentPage = Math.max(1, Math.min(page, totalPages || 1));
    isLoading = true;

    const tbody = document.getElementById('attendanceBody');
    
    // Only show loading state if not in silent mode
    if (tbody && !silent) {
        tbody.innerHTML = `<tr><td colspan="4" class="empty-state"><span class="loading"></span> Loading attendance records...</td></tr>`;
    }

    try {
        const dateFrom = document.getElementById('filterDateFrom')?.value || '';
        const dateTo = document.getElementById('filterDateTo')?.value || '';
        const action = document.getElementById('filterAction')?.value || '';

        const params = new URLSearchParams({
            page: currentPage,
            per_page: recordsPerPage,
            date_from: dateFrom,
            date_to: dateTo,
            action: action
        });

        const logPrefix = silent ? '[Attendance-BG]' : '[Attendance]';
        console.log(`${logPrefix} Loading page ${currentPage}...`);
        
        const res = await fetch(`${APP_CONFIG.getUserAttendanceUrl}?${params}`);
        const json = await res.json();

        if (json.status !== 'success') throw new Error(json.message || 'Failed to load');

        totalPages = json.total_pages;
        renderAttendance(json.records);
        updatePagination(json.total_records);

        const totalRecordsEl = document.getElementById('totalRecords');
        if (totalRecordsEl) {
            totalRecordsEl.textContent = json.total_records;
        }

        console.log(`${logPrefix} Loaded ${json.records.length} records`);
        
        // Clear the refresh flag after successful load
        attendanceNeedsRefresh = false;
        
        // Show subtle notification if updated in background
        if (silent) {
            console.log('[Attendance-BG] Records updated silently');
        }
        
        // If there was a refresh request while loading, process it now
        if (attendanceNeedsRefresh && silent) {
            console.log('[Attendance-BG] Processing queued refresh');
            setTimeout(() => {
                attendanceNeedsRefresh = false;
                refreshAttendanceInBackground();
            }, 100);
        }
        
    } catch (err) {
        console.error('[Attendance] Error loading:', err);
        if (tbody && !silent) {
            tbody.innerHTML = `<tr><td colspan="4" class="empty-state" style="color: #e53e3e;">Error: ${err.message}</td></tr>`;
        }
    } finally {
        isLoading = false;
    }
}

function renderAttendance(records) {
    const tbody = document.getElementById('attendanceBody');
    if (!tbody) return;
    
    const container = tbody.closest('.table-container');
    const scrollTop = container ? container.scrollTop : 0;
    
    tbody.innerHTML = '';

    if (!records || records.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="empty-state">No attendance records found</td></tr>`;
        return;
    }

    records.forEach((r, index) => {
        const tr = document.createElement('tr');
        
        // NEW: Use formatDateTime helper
        const { date, time } = formatDateTime(r.timestamp);
        const badgeClass = r.action === 'IN' ? 'badge-in' : 'badge-out';
        
        tr.innerHTML = `
            <td><span class="badge ${badgeClass}">${r.action}</span></td>
            <td>${date}</td>
            <td>${time}</td>
            <td>${r.location || 'Gate'}</td>
        `;
        
        if (index < 3) {
            tr.style.animation = 'fadeIn 0.3s ease-in';
        }
        
        tbody.appendChild(tr);
    });
    
    if (container) {
        container.scrollTop = scrollTop;
    }
}

function updatePagination(totalRecords) {
    const pageInfo = document.getElementById('pageInfo');
    if (pageInfo) {
        pageInfo.textContent = `Page ${currentPage} of ${totalPages} (${totalRecords} total)`;
    }
    
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    
    if (prevBtn) prevBtn.disabled = currentPage <= 1;
    if (nextBtn) nextBtn.disabled = currentPage >= totalPages;
}

async function loadRecentActivity() {
    try {
        const response = await fetch(`${window.location.origin}/user/recent-activity`);
        const data = await response.json();
        
        if (data.status === 'success') {
            renderRecentActivityTable(data.activity);
        }
    } catch (error) {
        console.error('Error loading recent activity:', error);
        const tableBody = document.getElementById('recentActivityTableBody');
        if (tableBody) {
            tableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: var(--text-tertiary);">Failed to load</td></tr>';
        }
    }
}

function renderRecentActivityTable(activity) {
    const tableBody = document.getElementById('recentActivityTableBody');
    if (!tableBody) return;
    
    tableBody.innerHTML = '';
    
    // Add IN row
    const inRow = document.createElement('tr');
    if (activity.in) {
        // NEW: Use formatDateTime helper
        const { date, time } = formatDateTime(activity.in.timestamp);
        const location = activity.in.location || 'Gate';
        
        inRow.innerHTML = `
            <td><span class="badge badge-in">IN</span></td>
            <td style="font-size: 12px; color: var(--text-secondary);">${date} ${time}</td>
            <td style="font-size: 12px; color: var(--text-secondary);">${location}</td>
        `;
    } else {
        inRow.innerHTML = `
            <td><span class="badge badge-in">IN</span></td>
            <td style="font-size: 12px; color: var(--text-tertiary);">No records</td>
            <td style="font-size: 12px; color: var(--text-tertiary);">--</td>
        `;
    }
    tableBody.appendChild(inRow);
    
    // Add OUT row
    const outRow = document.createElement('tr');
    if (activity.out) {
        // NEW: Use formatDateTime helper
        const { date, time } = formatDateTime(activity.out.timestamp);
        const location = activity.out.location || 'Gate';
        
        outRow.innerHTML = `
            <td><span class="badge badge-out">OUT</span></td>
            <td style="font-size: 12px; color: var(--text-secondary);">${date} ${time}</td>
            <td style="font-size: 12px; color: var(--text-secondary);">${location}</td>
        `;
    } else {
        outRow.innerHTML = `
            <td><span class="badge badge-out">OUT</span></td>
            <td style="font-size: 12px; color: var(--text-tertiary);">No records</td>
            <td style="font-size: 12px; color: var(--text-tertiary);">--</td>
        `;
    }
    tableBody.appendChild(outRow);
}

async function loadDailyStats() {
    try {
        const response = await fetch(APP_CONFIG.getDailyStatsUrl);
        const data = await response.json();
        
        if (data.status === 'success') {
            const stats = data.stats;
            document.getElementById('totalScansToday').textContent = stats.total;
            document.getElementById('timesInToday').textContent = stats.in_count;
            document.getElementById('timesOutToday').textContent = stats.out_count;
        }
    } catch (error) {
        console.error('Error loading daily stats:', error);
    }
}

async function loadCurrentStatus() {
    try {
        const response = await fetch(APP_CONFIG.getCurrentStatusUrl);
        const data = await response.json();
        
        if (data.status === 'success') {
            updateCurrentStatusDisplay(data.user_status);
        }
    } catch (error) {
        console.error('Error loading current status:', error);
    }
}