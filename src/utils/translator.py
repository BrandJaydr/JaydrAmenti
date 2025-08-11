"""
Translation and Internationalization Manager
Handles multi-language support for the Cyber Amenti interface
"""

import json
import os
from typing import Dict, Optional, List

class Translator:
    def __init__(self, default_language: str = 'en'):
        self.default_language = default_language
        self.current_language = default_language
        self.translations = {}
        self.available_languages = ['en', 'es', 'fr', 'de']
        
        # Load all available translations
        self.load_translations()
    
    def load_translations(self):
        """Load translation files for all available languages"""
        locales_dir = 'locales'
        
        for lang in self.available_languages:
            locale_file = os.path.join(locales_dir, f'{lang}.json')
            
            if os.path.exists(locale_file):
                try:
                    with open(locale_file, 'r', encoding='utf-8') as f:
                        self.translations[lang] = json.load(f)
                except (json.JSONDecodeError, IOError) as e:
                    print(f"Error loading translation file {locale_file}: {e}")
                    if lang == self.default_language:
                        # Load fallback translations
                        self.translations[lang] = self._get_fallback_translations()
            else:
                if lang == self.default_language:
                    # Create default translation file if it doesn't exist
                    self.translations[lang] = self._get_fallback_translations()
                    self._save_translation_file(lang)
    
    def _get_fallback_translations(self) -> Dict[str, str]:
        """Get fallback English translations"""
        return {
            # Main menu
            "main_menu": "Main Menu",
            "scan_target": "Scan Network Targets",
            "netcat_operations": "Netcat Operations",
            "device_profiles": "Device Profiles",
            "exploit_search": "Exploit Database",
            "dossier_management": "Intelligence Dossiers",
            "settings": "Settings",
            "help": "Help & Documentation",
            "exit": "Exit",
            "select_option": "Select an option",
            "back_to_main": "Back to Main Menu",
            "confirm_exit": "Are you sure you want to exit?",
            
            # Scanning operations
            "scan_operations": "Network Scanning Operations",
            "basic_scans": "Basic Scans",
            "discovery_scans": "Discovery Scans", 
            "port_scans": "Port Scans",
            "version_scans": "Version Detection",
            "evasion_scans": "Firewall Evasion",
            "script_scans": "NSE Scripts",
            "scan_history": "Scan History",
            "select_scan_type": "Select scan type",
            
            "basic_scans_desc": "Single target, aggressive, subnet, and range scans",
            "discovery_scans_desc": "Host discovery and ping techniques",
            "port_scans_desc": "TCP/UDP port scanning methods",
            "version_scans_desc": "OS and service version detection",
            "evasion_scans_desc": "Firewall and IDS evasion techniques",
            "script_scans_desc": "Nmap Scripting Engine operations",
            "scan_history_desc": "View previous scan results",
            
            # Netcat operations
            "port_scanning": "Port Scanning",
            "connectivity_test": "Connectivity Testing",
            "banner_grabbing": "Banner Grabbing",
            "setup_listener": "Setup Listener",
            "create_tunnel": "Create Tunnel",
            "active_listeners": "Active Listeners",
            "select_operation": "Select operation",
            
            # Device profiles
            "list_profiles": "List All Profiles",
            "search_profiles": "Search Profiles",
            "view_profile_details": "View Profile Details",
            "export_profiles": "Export Profiles",
            "profile_statistics": "Profile Statistics",
            
            # Exploit database
            "exploit_database": "Exploit Database",
            "search_vulnerabilities": "Search Vulnerabilities",
            "search_exploits": "Search Exploits",
            "update_database": "Update Database",
            "exploit_statistics": "Database Statistics",
            "service_correlation": "Service Correlation",
            
            # Dossier management
            "generate_dossier": "Generate Dossier",
            "list_dossiers": "List Dossiers",
            "view_dossier": "View Dossier",
            "export_dossier": "Export Dossier",
            "delete_dossier": "Delete Dossier",
            
            # Settings
            "change_theme": "Change Theme",
            "change_language": "Change Language",
            "view_settings": "View Current Settings",
            "reset_settings": "Reset to Defaults",
            
            # Help
            "help_documentation": "Help & Documentation",
            "nmap_help": "Nmap Command Guide",
            "netcat_help": "Netcat Operations Guide",
            "features_overview": "Features Overview",
            "about": "About Cyber Amenti",
            "keyboard_shortcuts": "Keyboard Shortcuts",
            
            # Common terms
            "target": "Target",
            "hostname": "Hostname",
            "ip_address": "IP Address",
            "port": "Port",
            "service": "Service",
            "version": "Version",
            "status": "Status",
            "risk_score": "Risk Score",
            "confidence": "Confidence",
            "vulnerability": "Vulnerability",
            "exploit": "Exploit",
            "severity": "Severity",
            "description": "Description",
            "timestamp": "Timestamp",
            "success": "Success",
            "failed": "Failed",
            "unknown": "Unknown",
            "scanning": "Scanning",
            "complete": "Complete",
            "error": "Error",
            "warning": "Warning",
            "info": "Info",
            
            # Scan modes
            "aggressive_mode": "Aggressive Mode",
            "stealth_mode": "Stealth Mode",
            "discovery_mode": "Discovery Mode",
            "comprehensive_mode": "Comprehensive Mode",
            
            # Device types
            "server": "Server",
            "workstation": "Workstation",
            "router": "Router",
            "switch": "Switch",
            "printer": "Printer",
            "iot_device": "IoT Device",
            "database": "Database",
            "firewall": "Firewall",
            
            # Risk levels
            "critical_risk": "Critical Risk",
            "high_risk": "High Risk",
            "medium_risk": "Medium Risk",
            "low_risk": "Low Risk",
            "no_risk": "No Risk",
            
            # Status messages
            "scan_started": "Scan started",
            "scan_completed": "Scan completed",
            "scan_failed": "Scan failed",
            "connection_successful": "Connection successful",
            "connection_failed": "Connection failed",
            "data_exported": "Data exported successfully",
            "export_failed": "Export failed",
            "database_updated": "Database updated",
            "update_failed": "Update failed",
            
            # Input prompts
            "enter_target": "Enter target IP or hostname",
            "enter_port": "Enter port number",
            "enter_range": "Enter port range (e.g., 1-1000)",
            "select_format": "Select export format",
            "confirm_action": "Confirm this action",
            "press_enter": "Press Enter to continue",
            
            # Errors and warnings
            "invalid_target": "Invalid target specified",
            "invalid_port": "Invalid port number",
            "scan_error": "Scan execution error",
            "network_error": "Network connection error",
            "file_error": "File operation error",
            "permission_error": "Permission denied",
            "not_found": "Resource not found",
            "already_exists": "Resource already exists",
            
            # Progress messages
            "initializing": "Initializing...",
            "connecting": "Connecting...",
            "analyzing": "Analyzing results...",
            "generating_report": "Generating report...",
            "saving_data": "Saving data...",
            "loading_data": "Loading data...",
            "processing": "Processing...",
            "finalizing": "Finalizing...",
            
            # Color themes
            "matrix_theme": "Matrix Green",
            "cyberpunk_theme": "Cyberpunk",
            "starlight_theme": "Starlight",
            "theme_description_matrix": "Classic terminal green on black",
            "theme_description_cyberpunk": "Dark blue background with pink neon accents",
            "theme_description_starlight": "Dark mode with blue, yellow and white highlights",
            
            # Languages
            "english": "English",
            "spanish": "Spanish", 
            "french": "French",
            "german": "German",
            
            # Time and date
            "seconds": "seconds",
            "minutes": "minutes",
            "hours": "hours",
            "days": "days",
            "weeks": "weeks",
            "months": "months",
            "years": "years",
            "never": "Never",
            "now": "Now",
            "today": "Today",
            "yesterday": "Yesterday",
            
            # File operations
            "save": "Save",
            "load": "Load",
            "import": "Import",
            "export": "Export",
            "backup": "Backup",
            "restore": "Restore",
            "delete": "Delete",
            "create": "Create",
            "edit": "Edit",
            "copy": "Copy",
            "move": "Move",
            
            # Network protocols
            "tcp": "TCP",
            "udp": "UDP",
            "icmp": "ICMP",
            "http": "HTTP",
            "https": "HTTPS",
            "ssh": "SSH",
            "ftp": "FTP",
            "telnet": "Telnet",
            "smtp": "SMTP",
            "dns": "DNS",
            "snmp": "SNMP",
            "rdp": "RDP",
            "vnc": "VNC",
            
            # Cyber Amenti specific
            "cyber_amenti": "Cyber Amenti",
            "red_team_tool": "Red Team Network Intelligence Gathering Tool",
            "by_jaydr_nexus": "by Jaydr Nexus",
            "version_info": "Version 1.0 (Maze Mouse)",
            "intelligence_gathering": "Intelligence Gathering",
            "device_fingerprinting": "Device Fingerprinting",
            "vulnerability_correlation": "Vulnerability Correlation",
            "exploit_analysis": "Exploit Analysis",
            "network_reconnaissance": "Network Reconnaissance"
        }
    
    def set_language(self, language_code: str) -> bool:
        """Set the current language"""
        if language_code in self.available_languages:
            self.current_language = language_code
            if language_code not in self.translations:
                self.load_translations()
            return True
        return False
    
    def get(self, key: str, fallback: Optional[str] = None, **kwargs) -> str:
        """Get translated string for the given key"""
        # Try current language first
        if (self.current_language in self.translations and 
            key in self.translations[self.current_language]):
            text = self.translations[self.current_language][key]
        
        # Fallback to default language
        elif (self.default_language in self.translations and 
              key in self.translations[self.default_language]):
            text = self.translations[self.default_language][key]
        
        # Use provided fallback or key itself
        else:
            text = fallback if fallback is not None else key
        
        # Apply string formatting if kwargs provided
        if kwargs:
            try:
                text = text.format(**kwargs)
            except (KeyError, ValueError):
                pass  # Return unformatted text if formatting fails
        
        return text
    
    def get_plural(self, key: str, count: int, **kwargs) -> str:
        """Get plural form of translated string"""
        # Simple pluralization - could be enhanced for complex language rules
        if count == 1:
            return self.get(key, **kwargs)
        else:
            plural_key = f"{key}_plural"
            if self._has_translation(plural_key):
                return self.get(plural_key, count=count, **kwargs)
            else:
                # Simple English pluralization fallback
                text = self.get(key, **kwargs)
                if text.endswith('y'):
                    return text[:-1] + 'ies'
                elif text.endswith(('s', 'sh', 'ch', 'x', 'z')):
                    return text + 'es'
                else:
                    return text + 's'
    
    def _has_translation(self, key: str) -> bool:
        """Check if translation exists for key"""
        return (self.current_language in self.translations and 
                key in self.translations[self.current_language]) or \
               (self.default_language in self.translations and 
                key in self.translations[self.default_language])
    
    def get_available_languages(self) -> List[Dict[str, str]]:
        """Get list of available languages with names"""
        language_names = {
            'en': 'English',
            'es': 'Español', 
            'fr': 'Français',
            'de': 'Deutsch'
        }
        
        return [
            {
                'code': lang,
                'name': language_names.get(lang, lang),
                'native_name': language_names.get(lang, lang),
                'loaded': lang in self.translations
            }
            for lang in self.available_languages
        ]
    
    def get_current_language(self) -> str:
        """Get current language code"""
        return self.current_language
    
    def get_language_name(self, language_code: str = None) -> str:
        """Get human-readable name for language"""
        if not language_code:
            language_code = self.current_language
        
        language_names = {
            'en': 'English',
            'es': 'Español',
            'fr': 'Français', 
            'de': 'Deutsch'
        }
        
        return language_names.get(language_code, language_code)
    
    def add_translation(self, language_code: str, key: str, value: str):
        """Add or update a translation"""
        if language_code not in self.translations:
            self.translations[language_code] = {}
        
        self.translations[language_code][key] = value
        self._save_translation_file(language_code)
    
    def remove_translation(self, language_code: str, key: str) -> bool:
        """Remove a translation"""
        if (language_code in self.translations and 
            key in self.translations[language_code]):
            del self.translations[language_code][key]
            self._save_translation_file(language_code)
            return True
        return False
    
    def _save_translation_file(self, language_code: str):
        """Save translations to file"""
        locales_dir = 'locales'
        os.makedirs(locales_dir, exist_ok=True)
        
        locale_file = os.path.join(locales_dir, f'{language_code}.json')
        
        try:
            with open(locale_file, 'w', encoding='utf-8') as f:
                json.dump(self.translations[language_code], f, 
                         ensure_ascii=False, indent=2, sort_keys=True)
        except IOError as e:
            print(f"Error saving translation file {locale_file}: {e}")
    
    def export_translations(self, export_path: str, language_code: str = None):
        """Export translations to specified path"""
        if language_code:
            # Export single language
            if language_code in self.translations:
                export_data = {
                    'language': language_code,
                    'translations': self.translations[language_code],
                    'export_timestamp': self._get_timestamp()
                }
            else:
                raise ValueError(f"Language {language_code} not found")
        else:
            # Export all languages
            export_data = {
                'languages': self.translations,
                'current_language': self.current_language,
                'default_language': self.default_language,
                'export_timestamp': self._get_timestamp()
            }
        
        try:
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, ensure_ascii=False, indent=2, sort_keys=True)
            return True
        except IOError as e:
            print(f"Error exporting translations: {e}")
            return False
    
    def import_translations(self, import_path: str) -> bool:
        """Import translations from specified path"""
        try:
            with open(import_path, 'r', encoding='utf-8') as f:
                import_data = json.load(f)
            
            if 'language' in import_data and 'translations' in import_data:
                # Single language import
                language_code = import_data['language']
                self.translations[language_code] = import_data['translations']
                self._save_translation_file(language_code)
            
            elif 'languages' in import_data:
                # Multiple languages import
                for lang_code, translations in import_data['languages'].items():
                    self.translations[lang_code] = translations
                    self._save_translation_file(lang_code)
            
            else:
                return False
            
            return True
            
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error importing translations: {e}")
            return False
    
    def get_translation_stats(self) -> Dict[str, Dict[str, int]]:
        """Get statistics about loaded translations"""
        stats = {}
        
        for lang_code, translations in self.translations.items():
            stats[lang_code] = {
                'total_keys': len(translations),
                'language_name': self.get_language_name(lang_code),
                'is_current': lang_code == self.current_language,
                'is_default': lang_code == self.default_language
            }
        
        return stats
    
    def find_missing_translations(self, reference_language: str = None) -> Dict[str, List[str]]:
        """Find missing translations compared to reference language"""
        if not reference_language:
            reference_language = self.default_language
        
        if reference_language not in self.translations:
            return {}
        
        reference_keys = set(self.translations[reference_language].keys())
        missing = {}
        
        for lang_code, translations in self.translations.items():
            if lang_code == reference_language:
                continue
            
            current_keys = set(translations.keys())
            missing_keys = reference_keys - current_keys
            
            if missing_keys:
                missing[lang_code] = sorted(list(missing_keys))
        
        return missing
    
    def validate_translations(self) -> Dict[str, List[str]]:
        """Validate translations for formatting errors"""
        errors = {}
        
        for lang_code, translations in self.translations.items():
            lang_errors = []
            
            for key, value in translations.items():
                if not isinstance(value, str):
                    lang_errors.append(f"Key '{key}': Value must be a string")
                elif '{' in value and '}' in value:
                    # Check for valid format strings
                    try:
                        value.format()  # Test with no arguments
                    except (KeyError, ValueError) as e:
                        lang_errors.append(f"Key '{key}': Invalid format string - {e}")
            
            if lang_errors:
                errors[lang_code] = lang_errors
        
        return errors
    
    def auto_translate_missing(self, target_language: str, reference_language: str = None):
        """Auto-translate missing keys (placeholder for future implementation)"""
        # This would integrate with translation APIs like Google Translate
        # For now, just copy from reference language with a marker
        
        if not reference_language:
            reference_language = self.default_language
        
        missing = self.find_missing_translations(reference_language)
        
        if target_language in missing:
            if target_language not in self.translations:
                self.translations[target_language] = {}
            
            for key in missing[target_language]:
                reference_text = self.translations[reference_language][key]
                # Mark as needing translation
                self.translations[target_language][key] = f"[TRANSLATE] {reference_text}"
            
            self._save_translation_file(target_language)
    
    def _get_timestamp(self) -> str:
        """Get current timestamp string"""
        import time
        return time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
    
    def format_relative_time(self, timestamp: float) -> str:
        """Format timestamp as relative time string"""
        import time
        
        now = time.time()
        diff = now - timestamp
        
        if diff < 60:
            return self.get("now")
        elif diff < 3600:
            minutes = int(diff / 60)
            return self.get_plural("minutes_ago", minutes, count=minutes)
        elif diff < 86400:
            hours = int(diff / 3600)
            return self.get_plural("hours_ago", hours, count=hours)
        elif diff < 2592000:  # 30 days
            days = int(diff / 86400)
            return self.get_plural("days_ago", days, count=days)
        else:
            return time.strftime('%Y-%m-%d', time.localtime(timestamp))
    
    def get_localized_number(self, number: float, decimal_places: int = 1) -> str:
        """Get localized number format"""
        # Simple implementation - could be enhanced with locale-specific formatting
        if self.current_language in ['de', 'fr']:
            # European format (comma as decimal separator)
            formatted = f"{number:.{decimal_places}f}".replace('.', ',')
        else:
            # US/UK format (dot as decimal separator) 
            formatted = f"{number:.{decimal_places}f}"
        
        return formatted
