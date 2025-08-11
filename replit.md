# Cyber Amenti - Network Intelligence Tool

## Overview

Cyber Amenti is a comprehensive red team network intelligence gathering tool designed for cybersecurity professionals. The application provides an advanced command-line interface with cyberpunk-themed styling for conducting network reconnaissance, vulnerability assessment, and exploitation research. It integrates multiple security tools including Nmap scanning, Netcat operations, device profiling, and exploit database correlation to provide a unified platform for network intelligence gathering.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Terminal-based CLI Interface**: Rich-powered interactive command-line interface with cyberpunk theming
- **Multi-language Support**: Internationalization system supporting English, Spanish, French, and German
- **Theme System**: Customizable color schemes including Matrix, Cyberpunk, and Starlight themes
- **Interactive Menus**: Context-aware menu systems with progress bars and status indicators

### Backend Architecture
- **Modular Component Design**: Separation of concerns with distinct modules for scanning, networking, profiling, and database operations
- **Scanner Integration**: Wrapper around Nmap with predefined command templates and result parsing
- **Netcat Operations Manager**: Handles network probing, banner grabbing, and connectivity testing
- **Device Profiler**: Advanced fingerprinting system for device categorization and risk assessment
- **Exploit Database**: Vulnerability correlation engine that matches discovered services with known exploits

### Data Storage Solutions
- **SQLite Database**: Local intelligence database storing scan results, device profiles, and dossiers
- **JSON Configuration**: File-based configuration management with automatic backup support
- **Session Management**: Persistent storage of scan history and device intelligence
- **Export Capabilities**: Multiple format support for data export and reporting

### Configuration Management
- **Settings Persistence**: JSON-based configuration with default fallbacks
- **Runtime Configuration**: Dynamic theme switching and language selection
- **Security Controls**: Configurable timeout values, scan limits, and risk thresholds
- **Backup System**: Automated database backup with configurable intervals

## External Dependencies

### Core Security Tools
- **Nmap**: Primary network discovery and port scanning engine
- **Netcat**: Network connectivity testing and banner grabbing operations

### Python Libraries
- **Rich**: Terminal styling, progress bars, and interactive interface components
- **Click**: Command-line interface framework for argument parsing
- **SQLite3**: Built-in database connectivity for intelligence storage

### System Requirements
- **Python 3.x**: Core runtime environment
- **Unix/Linux Compatible**: Designed for POSIX-compliant systems
- **Network Tools**: Requires Nmap and Netcat to be installed and accessible in system PATH

### Optional Integrations
- **CVE Databases**: External vulnerability database integration for exploit correlation
- **Export Formats**: JSON, CSV, and custom report format support
- **Notification Systems**: Configurable alert mechanisms for completed operations