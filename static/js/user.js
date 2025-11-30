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

let eventSource = null;
let reconnectTimeout = null;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 5;
const RECONNECT_DELAY = 3000;

let attendanceNeedsRefresh = false;
let lastAttendanceUpdate = 0;
const ATTENDANCE_UPDATE_COOLDOWN = 1000;
let pendingRefresh = false;
let currentPage = 1;
let totalPages = 1;
const recordsPerPage = 10;
let attendanceLoaded = false;
let isLoading = false;

const NotificationType = {
    SUCCESS: 'success',
    WARNING: 'warning',
    DANGER: 'danger',
    INFO: 'info'
};

const StatusType = {
    IN: 'IN',
    OUT: 'OUT',
    UNKNOWN: 'UNKNOWN'
};

function formatDateTime(timestamp) {
    if (!timestamp) return { date: '--', time: '--' };
    
    const parts = timestamp.split(' ');
    if (parts.length >= 3) {
        return {
            date: parts[0],
            time: `${parts[1]} ${parts[2]}`
        };
    }
    return parts.length === 2 ? { date: parts[0], time: parts[1] } : { date: timestamp, time: '--' };
}

function getCSRFToken() {
    const metaTag = document.querySelector('meta[name="csrf-token"]');
    return metaTag?.getAttribute('content') || '';
}

function createFormDataWithCSRF() {
    const fd = new FormData();
    const csrfToken = getCSRFToken();
    if (csrfToken) fd.append('csrf_token', csrfToken);
    return fd;
}

function initializeSSE() {
    eventSource?.close();

    console.log('Connecting to SSE stream...');
    eventSource = new EventSource('/sse/stream');

    eventSource.onopen = () => {
        console.log('SSE connection established');
        reconnectAttempts = 0;
        updateConnectionIndicator('● Live', '#38a169');
    };

    eventSource.onmessage = (event) => {
        try {
            handleSSEEvent(JSON.parse(event.data));
        } catch (error) {
            console.error('Error parsing SSE message:', error);
        }
    };

    eventSource.onerror = (error) => {
        console.error('SSE connection error:', error);
        eventSource.close();
        updateConnectionIndicator('● Disconnected', '#e53e3e');
        attemptReconnect();
    };
}

function updateConnectionIndicator(text, color) {
    const indicator = document.getElementById('realtimeIndicator');
    if (indicator) {
        indicator.textContent = text;
        indicator.style.color = color;
    }
}

function handleSSEEvent(event) {
    
    if (event.type === 'connected') {
        console.log('SSE stream connected');
    } else if (event.type === 'heartbeat') {
        // Do nothing
    } else if (event.type === 'scan_event') {
        handleScanEvent(event.data);
    } else {
        console.log('Unknown SSE event:', event);
    }
}

function handleScanEvent(data) {
    console.log('Scan event received:', data);
    
    if (data.stats) updateStats(data.stats);
    if (data.status) updateCurrentStatusDisplay(data.status);
    
    updateRecentLocationDisplay(data);
    showScanNotification(data);
    playNotificationSound();
    
    refreshAttendanceInBackground();
    debounceHeatmapRefresh();
    loadRecentActivity();
}

function updateStats(stats) {
    document.getElementById('totalScansToday').textContent = stats.total;
    document.getElementById('timesInToday').textContent = stats.in_count;
    document.getElementById('timesOutToday').textContent = stats.out_count;
}

function showScanNotification(data) {
    const action = data.action === StatusType.IN ? 'Entered' : 'Exited';
    const location = data.location || 'Gate';
    
    showProfessionalNotification(
        `Access ${action}`,
        `${action} at ${location}`,
        data.action === StatusType.IN ? NotificationType.SUCCESS : NotificationType.INFO
    );
}

function refreshAttendanceInBackground() {
    const now = Date.now();
    
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
    
    currentPage = 1;
    const attendanceSection = document.getElementById('section-attendance');
    const isVisible = attendanceSection && !attendanceSection.classList.contains('section-hidden');
    loadAttendance(1, !isVisible);
}

function updateCurrentStatusDisplay(status) {
    const statusElement = document.getElementById('currentStatus');
    if (!statusElement) return;
    
    const statusConfig = {
        [StatusType.IN]: { class: 'status-in', text: `Inside (${status.location})` },
        [StatusType.OUT]: { class: 'status-out', text: 'Outside' },
        [StatusType.UNKNOWN]: { class: 'status-unknown', text: 'No Records' }
    };
    
    const config = statusConfig[status.status] || statusConfig[StatusType.UNKNOWN];
    statusElement.innerHTML = `<span class="status-badge ${config.class}">${config.text}</span>`;
}

function updateRecentLocationDisplay(data) {
    const locationNameEl = document.getElementById('recentLocation');
    const locationTimeEl = document.getElementById('recentLocationTime');
    if (!locationNameEl || !locationTimeEl) return;
    
    const action = data.action === StatusType.IN ? 'Entered' : 'Exited';
    locationNameEl.textContent = `${action} at ${data.location}`;
    
    if (data.timestamp) {
        const { date, time } = formatDateTime(data.timestamp);
        locationTimeEl.textContent = `${date} at ${time}`;
    }
}

function playNotificationSound() {
    try {
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        if (!audioContext) return;
        
        const oscillator = audioContext.createOscillator();
        const gainNode = audioContext.createGain();
        
        oscillator.connect(gainNode);
        gainNode.connect(audioContext.destination);
        
        oscillator.frequency.value = 800;
        oscillator.type = 'sine';
        gainNode.gain.value = 0.1;
        
        oscillator.start(audioContext.currentTime);
        oscillator.stop(audioContext.currentTime + 0.1);
    } catch (error) {
        console.log('Notification sound not available:', error);
    }
}

let heatmapRefreshTimeout = null;
function debounceHeatmapRefresh() {
    clearTimeout(heatmapRefreshTimeout);
    heatmapRefreshTimeout = setTimeout(() => loadActivityHeatmap(), 2000);
}

function attemptReconnect() {
    if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
        console.error('Max reconnection attempts reached');
        showProfessionalNotification(
            'Connection Lost',
            'Lost connection to server. Please refresh the page.',
            NotificationType.WARNING
        );
        return;
    }
    
    reconnectAttempts++;
    console.log(`Attempting to reconnect (${reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS})...`);
    
    reconnectTimeout = setTimeout(() => initializeSSE(), RECONNECT_DELAY * reconnectAttempts);
}

function showProfessionalNotification(title, message, type = NotificationType.INFO) {
    ensureNotificationStyles();
    
    const notification = document.createElement('div');
    notification.className = 'professional-notification';
    
    const isDarkMode = document.body.classList.contains('dark-mode');
    const styleConfig = getNotificationStyle(type, isDarkMode);
    
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${styleConfig.bgColor};
        border: 1px solid ${styleConfig.borderColor};
        border-left: 4px solid ${styleConfig.borderColor};
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
                background: ${styleConfig.borderColor};
                color: white;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 12px;
                font-weight: bold;
                flex-shrink: 0;
            ">${styleConfig.icon}</div>
            <div style="flex: 1;">
                <div style="font-weight: 600; font-size: 14px; color: ${styleConfig.textColor}; margin-bottom: 4px;">${title}</div>
                <div style="font-size: 13px; color: ${secondaryTextColor}; line-height: 1.4;">${message}</div>
                <div style="font-size: 11px; color: ${tertiaryTextColor}; margin-top: 6px;">${new Date().toLocaleTimeString()}</div>
            </div>
            <button onclick="this.parentElement.parentElement.remove()" 
                    style="background: none; border: none; font-size: 16px; cursor: pointer; padding: 0; color: ${closeBtnColor}; line-height: 1; align-self: flex-start;">×</button>
        </div>
    `;

    document.body.appendChild(notification);
    autoRemoveNotification(notification);
}

function getNotificationStyle(type, isDarkMode) {
    const styles = {
        [NotificationType.SUCCESS]: {
            bgColor: isDarkMode ? '#1e3a1e' : '#f0f9f4',
            borderColor: isDarkMode ? '#4caf50' : '#38a169',
            textColor: isDarkMode ? '#e0e0e0' : '#2d3748',
            icon: '✓'
        },
        [NotificationType.WARNING]: {
            bgColor: isDarkMode ? '#3a3a1e' : '#fffaf0',
            borderColor: isDarkMode ? '#ff9800' : '#dd6b20',
            textColor: isDarkMode ? '#e0e0e0' : '#2d3748',
            icon: '!'
        },
        [NotificationType.DANGER]: {
            bgColor: isDarkMode ? '#3a1e1e' : '#fef2f2',
            borderColor: isDarkMode ? '#f44336' : '#dc3545',
            textColor: isDarkMode ? '#e0e0e0' : '#2d3748',
            icon: '✗'
        },
        [NotificationType.INFO]: {
            bgColor: isDarkMode ? '#1e2a3a' : '#f0f9ff',
            borderColor: isDarkMode ? '#42a5f5' : '#3182ce',
            textColor: isDarkMode ? '#e0e0e0' : '#2d3748',
            icon: 'i'
        }
    };
    
    return styles[type] || styles[NotificationType.INFO];
}

function ensureNotificationStyles() {
    if (document.getElementById('notification-animations')) return;
    
    const style = document.createElement('style');
    style.id = 'notification-animations';
    style.textContent = `
        @keyframes slideInRight {
            from { opacity: 0; transform: translateX(400px); }
            to { opacity: 1; transform: translateX(0); }
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-5px); }
            to { opacity: 1; transform: translateY(0); }
        }
    `;
    document.head.appendChild(style);
}

function autoRemoveNotification(notification) {
    setTimeout(() => {
        if (notification.parentElement) {
            notification.style.opacity = '0';
            notification.style.transform = 'translateX(400px)';
            notification.style.transition = 'all 0.3s ease-out';
            setTimeout(() => notification.remove(), 300);
        }
    }, 5000);
}

document.addEventListener('DOMContentLoaded', function() {
    if (typeof APP_CONFIG === 'undefined') {
        console.error('APP_CONFIG not found. Make sure it is defined in the HTML file.');
        return;
    }

    initializeSecurity();
    initializeDarkMode();
    initializeSSE();
    setupEventListeners();
    setupLogoutConfirmation();
    
    // Auto-dismiss flash messages after 3 seconds
    document.querySelectorAll('.flash').forEach(flash => {
        setTimeout(() => {
            flash.style.opacity = '0';
            flash.style.transition = 'opacity 0.3s ease-out';
            setTimeout(() => flash.remove(), 300);
        }, 3000);
    });
    
    loadInitialData();
    console.log('[Init] Real-time attendance updates enabled');
});

function setupEventListeners() {
    const filterDateFrom = document.getElementById('filterDateFrom');
    const filterDateTo = document.getElementById('filterDateTo');
    const filterAction = document.getElementById('filterAction');
    const profileForm = document.getElementById('profileForm');
    const newPassword = document.getElementById('new_password');
    const confirmPassword = document.getElementById('confirm_password');
    
    if (filterDateFrom) {
        filterDateFrom.valueAsDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
        filterDateFrom.addEventListener('change', instantRefresh);
    }
    
    if (filterDateTo) {
        filterDateTo.valueAsDate = new Date();
        filterDateTo.addEventListener('change', instantRefresh);
    }

    if (filterAction) filterAction.addEventListener('change', instantRefresh);
    if (profileForm) profileForm.addEventListener('submit', handleProfileSubmit);
    if (newPassword) newPassword.addEventListener('input', validatePassword);
    if (confirmPassword) confirmPassword.addEventListener('input', validatePasswordMatch);

    handleForcePasswordChange();
}

function handleForcePasswordChange() {
    if (!APP_CONFIG.forcePasswordChange) return;
    
    const passwordAlert = document.getElementById('passwordAlert');
    const passwordInfoBox = document.getElementById('passwordInfoBox');
    
    if (passwordAlert) passwordAlert.style.display = 'block';
    if (passwordInfoBox) passwordInfoBox.style.display = 'none';

    const profileLink = document.querySelector('[onclick*="profile"]');
    if (profileLink) {
        profileLink.addEventListener('click', (e) => {
            setTimeout(() => {
                const profileSection = document.getElementById('section-profile');
                if (profileSection) profileSection.scrollIntoView({ behavior: 'smooth' });
            }, 100);
        });
    }
}

function loadInitialData() {
    loadAttendance(1);
    attendanceLoaded = true;
    loadDailyStats();
    loadCurrentStatus();
    loadRecentLocation();     
    loadActivityHeatmap();
    loadRecentActivity();
}

function instantRefresh() {
    if (!isLoading) {
        currentPage = 1;
        loadAttendance(1, false);
    }
}

function setupLogoutConfirmation() {
    document.querySelectorAll('form[action*="logout"]').forEach(form => {
        form.addEventListener('submit', function(e) {
            if (!confirm('Are you sure you want to logout?')) {
                e.preventDefault();
                return false;
            }
            
            eventSource?.close();
            this.dataset.submitting = 'true';
        });
    });
}

function handleProfileSubmit(e) {
    if (!checkRateLimit()) {
        e.preventDefault();
        showProfessionalNotification('Rate Limit', 'Please wait before making another request', NotificationType.WARNING);
        return false;
    }

    const username = document.getElementById('username').value.trim();
    const name = document.getElementById('name').value.trim();
    const newPassword = document.getElementById('new_password').value;
    const confirmPassword = document.getElementById('confirm_password').value;

    if (!validateProfileForm(username, name, newPassword, confirmPassword)) {
        e.preventDefault();
        return false;
    }

    const btn = document.getElementById('saveProfileBtn');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="loading"></span> Saving...';
    }

    return true;
}

function validateProfileForm(username, name, newPassword, confirmPassword) {
    if (!username || username.length < 3) {
        showProfessionalNotification('Validation Error', 'Username must be at least 3 characters long', NotificationType.WARNING);
        document.getElementById('username').focus();
        return false;
    }

    if (!name) {
        showProfessionalNotification('Validation Error', 'Name is required', NotificationType.WARNING);
        document.getElementById('name').focus();
        return false;
    }

    if (newPassword || confirmPassword) {
        if (!newPassword || !confirmPassword) {
            showProfessionalNotification('Password Change', 'Please fill both password fields to change your password', NotificationType.WARNING);
            document.getElementById('new_password').focus();
            return false;
        }

        if (newPassword.length < 8) {
            showProfessionalNotification('Password Requirements', 'Password must be at least 8 characters long', NotificationType.WARNING);
            document.getElementById('new_password').focus();
            return false;
        }

        if (newPassword !== confirmPassword) {
            showProfessionalNotification('Password Mismatch', 'Passwords do not match. Please ensure both passwords are identical.', NotificationType.WARNING);
            document.getElementById('confirm_password').focus();
            return false;
        }
    }

    return true;
}

async function loadRecentLocation() {
    try {
        const response = await fetch(APP_CONFIG.getCurrentStatusUrl);
        const data = await response.json();
        
        if (data.status === 'success') {
            updateCurrentStatusDisplay(data.user_status);
            updateLocationDisplay(data.user_status);
        }
    } catch (error) {
        console.error('Error loading recent location:', error);
        document.getElementById('recentLocation').textContent = 'Unable to load location';
    }
}

function updateLocationDisplay(status) {
    const locationNameEl = document.getElementById('recentLocation');
    const locationTimeEl = document.getElementById('recentLocationTime');
    
    if (status.status === StatusType.UNKNOWN) {
        locationNameEl.textContent = 'No recent activity';
        locationTimeEl.textContent = 'Start scanning to see your location history';
    } else {
        const action = status.status === StatusType.IN ? 'Entered' : 'Exited';
        locationNameEl.textContent = `${action} at ${status.location}`;
        
        if (status.timestamp) {
            const { date, time } = formatDateTime(status.timestamp);
            locationTimeEl.textContent = `${date} at ${time}`;
        }
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
    
    if (!activityData?.length) {
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
    
    const dateMap = new Map(activityData.map(day => [day.date, day.count]));
    const { allDays, monthGroups } = generateDayData(dateMap);
    renderHeatmapStructure(columnsEl, monthsEl, allDays, monthGroups, maxCount, tooltip);
}

function generateDayData(dateMap) {
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(endDate.getDate() - 364);
    
    const allDays = [];
    const currentDate = new Date(startDate);
    const monthGroups = new Map();
    
    while (currentDate <= endDate) {
        const dateStr = currentDate.toISOString().split('T')[0];
        const count = dateMap.get(dateStr) || 0;
        const monthKey = currentDate.toLocaleDateString('en-US', { month: 'short', year: 'numeric' });
        
        const dayData = {
            date: dateStr,
            count,
            dayOfWeek: currentDate.getDay(),
            month: currentDate.toLocaleDateString('en-US', { month: 'short' }),
            monthKey,
            year: currentDate.getFullYear(),
            monthIndex: currentDate.getMonth()
        };
        
        allDays.push(dayData);
        
        if (!monthGroups.has(monthKey)) {
            monthGroups.set(monthKey, {
                name: dayData.month,
                days: [],
                year: dayData.year,
                monthIndex: dayData.monthIndex
            });
        }
        monthGroups.get(monthKey).days.push(dayData);
        
        currentDate.setDate(currentDate.getDate() + 1);
    }
    
    return { allDays, monthGroups };
}

function renderHeatmapStructure(columnsEl, monthsEl, allDays, monthGroups, maxCount, tooltip) {
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
    const monthArray = Array.from(monthGroups.entries())
        .sort((a, b) => a[1].year !== b[1].year ? a[1].year - b[1].year : a[1].monthIndex - b[1].monthIndex);
    
    const monthWidths = monthArray.map(([, monthData]) => {
        const weeks = groupDaysIntoWeeks(monthData.days);
        monthData.weeks = weeks;
        return weeks.length * 10 - 2;
    });
    
    renderMonthLabels(monthsEl, monthArray, monthWidths);
    renderHeatmapGrid(heatmapGrid, monthArray, maxCount, tooltip);
    adjustHeatmapLayout(heatmapGrid, monthsEl);
}

function groupDaysIntoWeeks(days) {
    const weeks = [];
    let currentWeek = [];
    let currentWeekStartDay = -1;
    
    days.forEach(day => {
        const dayOfWeek = day.dayOfWeek;
        
        if (currentWeekStartDay === -1) currentWeekStartDay = dayOfWeek;
        
        while (currentWeek.length < dayOfWeek) {
            currentWeek.push({ empty: true, dayOfWeek: currentWeek.length });
        }
        
        currentWeek.push(day);
        
        if (dayOfWeek === 6 || day === days[days.length - 1]) {
            while (currentWeek.length < 7) {
                currentWeek.push({ empty: true, dayOfWeek: currentWeek.length });
            }
            weeks.push(currentWeek);
            currentWeek = [];
            currentWeekStartDay = -1;
        }
    });
    
    return weeks;
}

function renderMonthLabels(monthsEl, monthArray, monthWidths) {
    monthArray.forEach(([monthKey, monthData], index) => {
        const monthLabel = document.createElement('div');
        monthLabel.className = 'month-label';
        monthLabel.textContent = monthData.name;
        monthLabel.title = `${monthData.name} ${monthData.year}`;
        monthLabel.style.flex = `0 0 ${monthWidths[index]}px`;
        monthsEl.appendChild(monthLabel);
    });
}

function renderHeatmapGrid(heatmapGrid, monthArray, maxCount, tooltip) {
    monthArray.forEach(([monthKey, monthData], monthIndex) => {
        const monthGroup = document.createElement('div');
        monthGroup.className = 'heatmap-month-group';
        
        const monthColumns = document.createElement('div');
        monthColumns.className = 'heatmap-columns';
        
        monthData.weeks.forEach(week => {
            const column = document.createElement('div');
            column.className = 'heatmap-column';
            
            week.forEach(day => renderHeatmapDay(column, day, maxCount, tooltip));
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
}

function renderHeatmapDay(column, day, maxCount, tooltip) {
    const square = document.createElement('div');
    square.className = 'heatmap-day';
    
    if (day.empty) {
        square.classList.add('empty');
    } else {
        const level = calculateHeatmapLevel(day.count, maxCount);
        square.classList.add(`level-${level}`);
        square.dataset.date = day.date;
        square.dataset.count = day.count;
        setupHeatmapDayEvents(square, day, tooltip);
    }
    
    column.appendChild(square);
}

function calculateHeatmapLevel(count, maxCount) {
    if (count === 0) return 0;
    const percentage = count / maxCount;
    if (percentage <= 0.25) return 1;
    if (percentage <= 0.5) return 2;
    if (percentage <= 0.75) return 3;
    return 4;
}

function setupHeatmapDayEvents(square, day, tooltip) {
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
    
    square.addEventListener('mouseleave', () => tooltip.classList.remove('show'));
}

function adjustHeatmapLayout(heatmapGrid, monthsEl) {
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
        const response = await fetch('/health', { method: 'GET', credentials: 'include' });
        if (response.status === 401 || response.status === 403) {
            window.location.href = APP_CONFIG.loginUrl || '/login';
        }
    } catch (error) {
        console.error('Session check failed:', error);
    }
}

setInterval(checkSessionStatus, 5 * 60 * 1000);

window.addEventListener('pageshow', function(event) {
    if (event.persisted || (window.performance && window.performance.navigation.type === 2)) {
        const isProtectedPage = window.location.pathname.includes('/admin/') || window.location.pathname.includes('/user/dashboard');
        if (isProtectedPage) window.location.reload();
    }
});

window.addEventListener('beforeunload', function() {
    if (eventSource) eventSource.close();
    if (reconnectTimeout) clearTimeout(reconnectTimeout);
});

window.addEventListener('beforeunload', function(e) {
    const logoutForm = document.querySelector('form[action*="logout"]');
    if (logoutForm?.dataset.submitting === 'true') {
        cleanupStorage();
    }
});

function cleanupStorage() {
    if (window.sessionStorage) sessionStorage.clear();
    if (window.localStorage) {
        const keysToKeep = ['user_device_token', 'admin_device_token'];
        Object.keys(localStorage).forEach(key => {
            if (!keysToKeep.includes(key)) localStorage.removeItem(key);
        });
    }
}

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
        const strengthConfig = getPasswordStrengthConfig(strength, password.length);
        strengthText.textContent = strengthConfig.text;
        strengthFill.style.backgroundColor = strengthConfig.color;
    }

    updateValidationSummary();
    if (confirmPassword) validatePasswordMatch();
}

function getPasswordStrengthConfig(strength, passwordLength) {
    if (passwordLength === 0) return { text: 'Password strength', color: '#ddd' };
    if (strength < 50) return { text: 'Weak', color: '#e53e3e' };
    if (strength < 75) return { text: 'Fair', color: '#dd6b20' };
    return { text: 'Strong', color: '#38a169' };
}

function validatePasswordMatch() {
    const password = document.getElementById('new_password').value;
    const confirmPassword = document.getElementById('confirm_password').value;
    const matchIcon = document.getElementById('matchIcon');
    const matchText = document.getElementById('matchText');
    const matchIndicator = document.getElementById('matchIndicator');

    if (!matchIcon || !matchText || !matchIndicator) return;

    const matchConfig = getPasswordMatchConfig(password, confirmPassword);
    matchIcon.textContent = matchConfig.icon;
    matchText.textContent = matchConfig.text;
    matchIndicator.style.color = matchConfig.color;

    updateValidationSummary();
}

function getPasswordMatchConfig(password, confirmPassword) {
    if (confirmPassword.length === 0) return { icon: '—', text: 'Passwords must match', color: '#666' };
    if (password === confirmPassword) return { icon: '✓', text: 'Passwords match', color: '#38a169' };
    return { icon: '✗', text: 'Passwords do not match', color: '#e53e3e' };
}

function updateValidationSummary() {
    const password = document.getElementById('new_password').value;
    const confirmPassword = document.getElementById('confirm_password').value;
    const validationSummary = document.getElementById('validationSummary');
    const validationLength = document.getElementById('validationLength');
    const validationMatch = document.getElementById('validationMatch');

    if (validationSummary) {
        validationSummary.style.display = (password.length > 0 || confirmPassword.length > 0) ? 'block' : 'none';
    }

    updateValidationItem(validationLength, password.length >= 8);
    updateValidationItem(validationMatch, password === confirmPassword && password.length > 0 && confirmPassword.length > 0);
}

function updateValidationItem(validationElement, isValid) {
    if (!validationElement) return;
    const icon = validationElement.querySelector('.validation-icon');
    const text = validationElement.querySelector('.validation-text');
    const color = isValid ? '#38a169' : '#666';
    
    icon.textContent = isValid ? '✓' : '○';
    icon.style.color = color;
    text.style.color = color;
}

function initializeSecurity() {
    const events = ['mousemove', 'keypress', 'click', 'scroll'];
    events.forEach(event => document.addEventListener(event, resetSessionTimer));

    startSessionTimer();
    setInterval(checkSecurityStatus, SECURITY_CONFIG.inactivityCheckInterval);

    updateActivityTime();
    setInterval(updateActivityTime, 60000);
}

function startSessionTimer() {
    clearTimeout(securityState.sessionTimer);
    clearTimeout(securityState.warningTimer);

    securityState.warningTimer = setTimeout(showSessionWarning, SECURITY_CONFIG.sessionTimeout - SECURITY_CONFIG.warningTime);
    securityState.sessionTimer = setTimeout(logoutUser, SECURITY_CONFIG.sessionTimeout);
}

function resetSessionTimer() {
    securityState.lastActivity = Date.now();
    startSessionTimer();
}

function showSessionWarning() {
    const warningEl = document.getElementById('sessionTimeoutWarning');
    if (!warningEl) return;
    
    warningEl.classList.remove('section-hidden');
    startCountdown();
}

function startCountdown() {
    let timeLeft = SECURITY_CONFIG.warningTime / 1000;
    const countdownElement = document.getElementById('countdown');

    const countdownInterval = setInterval(() => {
        timeLeft--;
        const minutes = Math.floor(timeLeft / 60);
        const seconds = timeLeft % 60;
        if (countdownElement) {
            countdownElement.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
        }

        if (timeLeft <= 0) clearInterval(countdownInterval);
    }, 1000);
}

function initializeDarkMode() {
    const savedTheme = localStorage.getItem('theme');
    const isDark = savedTheme === 'dark';
    
    if (isDark) enableDarkMode(false);
    else disableDarkMode(false);
    
    const toggle = document.getElementById('darkModeToggle');
    if (toggle) toggle.checked = isDark;
}

function toggleDarkMode() {
    if (document.body.classList.contains('dark-mode')) disableDarkMode(true);
    else enableDarkMode(true);
}

function enableDarkMode(save = true) {
    document.body.classList.add('dark-mode');
    if (save) {
        localStorage.setItem('theme', 'dark');
        showProfessionalNotification('Appearance', 'Dark mode enabled', NotificationType.INFO);
    }
    updateDarkModeToggle(true);
}

function disableDarkMode(save = true) {
    document.body.classList.remove('dark-mode');
    if (save) {
        localStorage.setItem('theme', 'light');
        showProfessionalNotification('Appearance', 'Light mode enabled', NotificationType.INFO);
    }
    updateDarkModeToggle(false);
}

function updateDarkModeToggle(checked) {
    const toggle = document.getElementById('darkModeToggle');
    if (toggle) toggle.checked = checked;
}

function extendSession() {
    const warningEl = document.getElementById('sessionTimeoutWarning');
    if (warningEl) warningEl.classList.add('section-hidden');

    if (!APP_CONFIG.resendCodeUrl) {
        console.error('Resend code URL not configured');
        resetSessionTimer();
        return;
    }

    fetch(APP_CONFIG.resendCodeUrl, {
        method: 'POST',
        headers: { 'X-CSRF-Token': getCSRFToken() }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success' || data.status === 'error') {
            resetSessionTimer();
            showProfessionalNotification('Session Extended', 'Session extended successfully', NotificationType.SUCCESS);
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
    if (now - securityState.lastApiCall < SECURITY_CONFIG.apiRateLimit) return false;
    securityState.lastApiCall = now;
    return true;
}


function checkSecurityStatus() {
    const timeSinceLastActivity = Date.now() - securityState.lastActivity;
    const securityStatus = document.getElementById('securityStatus');
    
    if (timeSinceLastActivity > 15 * 60 * 1000 && securityStatus?.className === 'security-indicator secure') {
        securityStatus.className = 'security-indicator warning';
        securityStatus.textContent = 'Inactive';
    }
}

function updateActivityTime() {
    const timeSinceActivity = Date.now() - securityState.lastActivity;
    const minutes = Math.floor(timeSinceActivity / 60000);
    const activityElement = document.getElementById('lastActivityTime');

    if (activityElement) {
        activityElement.textContent = formatActivityTime(minutes);
    }
}

function formatActivityTime(minutes) {
    if (minutes === 0) return 'Just now';
    if (minutes === 1) return '1 minute ago';
    if (minutes < 60) return `${minutes} minutes ago`;
    
    const hours = Math.floor(minutes / 60);
    return hours === 1 ? '1 hour ago' : `${hours} hours ago`;
}

function toggleSidebar() {
    document.getElementById('sidebar')?.classList.toggle('active');
}

function showSection(e, sectionName) {
    e.preventDefault();

    document.querySelectorAll('[id^="section-"]').forEach(section => section.classList.add('section-hidden'));
    document.querySelectorAll('.menu-item').forEach(item => item.classList.remove('active'));

    const targetSection = document.getElementById('section-' + sectionName);
    if (targetSection) targetSection.classList.remove('section-hidden');
    e.currentTarget.classList.add('active');

    updatePageTitle(sectionName);
    handleSectionSpecificLogic(sectionName);
    closeMobileSidebar();
}

function updatePageTitle(sectionName) {
    const titles = {
        'dashboard': 'Dashboard',
        'qr': 'My QR Code',
        'attendance': 'Attendance Records',
        'trusted-devices': 'Trusted Devices',
        'profile': 'Profile Settings'
    };
    
    const pageTitleEl = document.getElementById('pageTitle');
    if (pageTitleEl) pageTitleEl.textContent = titles[sectionName] || 'Dashboard';
}

function handleSectionSpecificLogic(sectionName) {
    if (sectionName === 'attendance') {
        if (!attendanceLoaded) {
            console.log('[Attendance] Loading for first time');
            loadAttendance(1);
            attendanceLoaded = true;
        }
        attendanceNeedsRefresh = false;
    }
}

function closeMobileSidebar() {
    if (window.innerWidth <= 768) {
        document.getElementById('sidebar')?.classList.remove('active');
    }
}

async function loadAttendance(page = 1, silent = false) {
    if (isLoading && silent) {
        console.log('[Attendance-BG] Already loading, marking for refresh');
        attendanceNeedsRefresh = true;
        return;
    }

    if (!checkRateLimit()) {
        if (!silent) showProfessionalNotification('Rate Limit', 'Please wait before making another request', NotificationType.WARNING);
        return;
    }

    if (!APP_CONFIG.getUserAttendanceUrl) {
        console.error('Get attendance URL not configured');
        return;
    }

    currentPage = Math.max(1, Math.min(page, totalPages || 1));
    isLoading = true;

    const tbody = document.getElementById('attendanceBody');
    if (tbody && !silent) {
        tbody.innerHTML = `<tr><td colspan="4" class="empty-state"><span class="loading"></span> Loading attendance records...</td></tr>`;
    }

    try {
        const params = buildAttendanceParams();
        const logPrefix = silent ? '[Attendance-BG]' : '[Attendance]';
        console.log(`${logPrefix} Loading page ${currentPage}...`);
        
        const res = await fetch(`${APP_CONFIG.getUserAttendanceUrl}?${params}`);
        const json = await res.json();

        if (json.status !== 'success') throw new Error(json.message || 'Failed to load');

        totalPages = json.total_pages;
        renderAttendance(json.records);
        updatePagination(json.total_records);


        console.log(`${logPrefix} Loaded ${json.records.length} records`);
        
        attendanceNeedsRefresh = false;
        if (silent) console.log('[Attendance-BG] Records updated silently');
        
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


function buildAttendanceParams() {
    const dateFrom = document.getElementById('filterDateFrom')?.value || '';
    const dateTo = document.getElementById('filterDateTo')?.value || '';
    const action = document.getElementById('filterAction')?.value || '';

    return new URLSearchParams({
        page: currentPage,
        per_page: recordsPerPage,
        date_from: dateFrom,
        date_to: dateTo,
        action: action
    });
}


function renderAttendance(records) {
    const tbody = document.getElementById('attendanceBody');
    if (!tbody) return;
    
    const container = tbody.closest('.table-container');
    const scrollTop = container ? container.scrollTop : 0;
    
    tbody.innerHTML = '';

    if (!records?.length) {
        tbody.innerHTML = `<tr><td colspan="4" class="empty-state">No attendance records found</td></tr>`;
        return;
    }

    records.forEach((r, index) => {
        const tr = document.createElement('tr');
        const { date, time } = formatDateTime(r.timestamp);
        const badgeClass = r.action === StatusType.IN ? 'badge-in' : 'badge-out';
        
        tr.innerHTML = `
            <td><span class="badge ${badgeClass}">${r.action}</span></td>
            <td>${date}</td>
            <td>${time}</td>
            <td>${r.location || 'Gate'}</td>
        `;
        
        if (index < 3) tr.style.animation = 'fadeIn 0.3s ease-in';
        tbody.appendChild(tr);
    });
    
    if (container) container.scrollTop = scrollTop;
}

function updatePagination(totalRecords) {
    const pageInfo = document.getElementById('pageInfo');
    if (pageInfo) pageInfo.textContent = `Page ${currentPage} of ${totalPages} (${totalRecords} total)`;
    
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    
    if (prevBtn) prevBtn.disabled = currentPage <= 1;
    if (nextBtn) nextBtn.disabled = currentPage >= totalPages;
}

async function loadRecentActivity() {
    try {
        const response = await fetch(`${window.location.origin}/user/recent-activity`);
        const data = await response.json();
        
        if (data.status === 'success') renderRecentActivityTable(data.activity);
    } catch (error) {
        console.error('Error loading recent activity:', error);
        const tableBody = document.getElementById('recentActivityTableBody');
        if (tableBody) tableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: var(--text-tertiary);">Failed to load</td></tr>';
    }
}

function renderRecentActivityTable(activity) {
    const tableBody = document.getElementById('recentActivityTableBody');
    if (!tableBody) return;
    
    tableBody.innerHTML = '';
    
    renderActivityRow(tableBody, StatusType.IN, activity.in);
    renderActivityRow(tableBody, StatusType.OUT, activity.out);
}

function renderActivityRow(tableBody, action, data) {
    const row = document.createElement('tr');
    const badgeClass = action === StatusType.IN ? 'badge-in' : 'badge-out';
    
    if (data) {
        const { date, time } = formatDateTime(data.timestamp);
        const location = data.location || 'Gate';
        
        row.innerHTML = `
            <td><span class="badge ${badgeClass}">${action}</span></td>
            <td style="font-size: 12px; color: var(--text-secondary);">${date} ${time}</td>
            <td style="font-size: 12px; color: var(--text-secondary);">${location}</td>
        `;
    } else {
        row.innerHTML = `
            <td><span class="badge ${badgeClass}">${action}</span></td>
            <td style="font-size: 12px; color: var(--text-tertiary);">No records</td>
            <td style="font-size: 12px; color: var(--text-tertiary);">--</td>
        `;
    }
    tableBody.appendChild(row);
}

async function loadDailyStats() {
    try {
        const response = await fetch(APP_CONFIG.getDailyStatsUrl);
        const data = await response.json();
        
        if (data.status === 'success') updateStats(data.stats);
    } catch (error) {
        console.error('Error loading daily stats:', error);
    }
}

async function loadCurrentStatus() {
    try {
        const response = await fetch(APP_CONFIG.getCurrentStatusUrl);
        const data = await response.json();
        
        if (data.status === 'success') updateCurrentStatusDisplay(data.user_status);
    } catch (error) {
        console.error('Error loading current status:', error);
    }
}