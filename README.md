# Accesium

A modern QR-based access control system for tracking and managing personnel entry and exit in facilities, schools, offices, and secure locations.

## Overview

Accesium provides secure, contactless access control through QR code scanning combined with PIN verification. The system offers real-time tracking, comprehensive analytics, and robust user management capabilities.

## Key Features

- **Secure Authentication**: Two-factor authentication with email verification and trusted device management
- **Real-time Analytics**: Live dashboards with activity charts, heatmaps, and attendance tracking
- **User Management**: Complete lifecycle management with role-based access control
- **QR Code Scanning**: Fast, contactless entry with unique QR codes and PIN verification
- **Access Rules**: Granular control based on location, time, and date
- **Multiple Locations**: Support for multiple entry points with detailed tracking
- **Data Export**: Excel and CSV export formats with comprehensive reporting
- **Dark Mode**: Comfortable viewing experience with theme switching
- **Session Management**: Configurable timeouts and security features

## Technology Stack

- **Backend**: Python Flask
- **Database**: SQLite
- **Frontend**: HTML5, CSS3, JavaScript
- **Libraries**: Chart.js, qrcode, openpyxl

## System Components

### Admin Portal
System management, user creation, analytics, and configuration. Administrators have full control over users, attendance records, access rules, and security settings.

### User Portal
Personal dashboard with QR code access, attendance records, activity heatmaps, and profile management. Users can view their scan history and manage trusted devices.

### Scanner Interface
Real-time QR code scanning for entry and exit logging. Automatic detection of entry vs exit based on last action, with live statistics display.

## Security Features

- Password hashing with unique salts
- CSRF protection on all forms
- Account lockout after failed login attempts
- Rate limiting on sensitive endpoints
- Input validation and sanitization
- Secure session management with timeouts
- Audit logging for all system actions
- Two-factor authentication via email

## Installation

```bash
# Clone the repository
git clone https://github.com/mggyslz/accesium.git
cd accesium

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

## First-Time Setup

1. Navigate to the landing page
2. Click "Admin Login" then "Sign Up"
3. Create the first admin account
4. Configure SMTP settings for email notifications (optional but recommended)
5. Begin adding users and configuring access rules

## Configuration

### Email Configuration
Configure SMTP settings in the admin panel to enable:
- Two-factor authentication codes
- Account creation notifications
- Password change confirmations
- Security alerts

### Session Settings
Adjust session timeout duration (15-480 minutes) and enable/disable automatic logout warnings.

### Security Settings
Configure 2FA requirements, account lockout thresholds, and failed attempt limits.

## Usage

### For Administrators
- Create and manage user accounts
- Configure access rules and restrictions
- Monitor real-time facility occupancy
- Export attendance data for reporting
- Manage system security settings

### For Users
- Access personal QR code and PIN
- View attendance history and statistics
- Manage trusted devices for 2FA
- Update profile information
- Download QR code for printing

### For Scanner Operators
- Scan user QR codes for entry/exit
- Monitor current facility occupancy
- View real-time scan statistics
- Assist users with scanning issues

## System Requirements

### Client Requirements
- Modern web browser (Chrome 90+, Firefox 88+, Safari 14+, Edge 90+)
- JavaScript and cookies enabled
- Minimum 1024x768 screen resolution
- Stable internet connection (512 Kbps minimum)

### Scanner Requirements
- Webcam (720p minimum, 1080p recommended)
- Camera permissions enabled in browser
- Adequate lighting (300+ lux)

### Server Requirements
- Python 3.8 or higher
- Flask framework
- SQLite database
- SMTP server (optional)

## Browser Support

Accesium works best on modern browsers. Chrome is recommended for optimal QR scanning performance.

## License

Copyright © 2025 mggyslz. All rights reserved.

This software is currently distributed without a formal license. All rights are reserved by the developer. For licensing inquiries or permission to use, modify, or distribute this software, please contact the developer.

## Developer

**mggyslz**

- Email: qrcodecode49@gmail.com
- GitHub: [github.com/mggyslz](https://github.com/mggyslz)
- Facebook: [facebook.com/miggzz.imperialcea](https://www.facebook.com/miggzz.imperialcea)

## Support

For technical support, bug reports, or feature requests, please contact qrcodecode49@gmail.com or open an issue on GitHub.

## Version

Current Version: 1.0 (2025)