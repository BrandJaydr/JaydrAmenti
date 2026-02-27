"""
Configuration Manager
Handles application settings and configuration persistence
"""

import json
import os
from typing import Dict, Any, Optional
from pathlib import Path

class ConfigManager:
    def __init__(self, config_file: str = "config/settings.json"):
        self.config_file = config_file
        self.config_data = {}
        self.default_config = {
            'theme': 'cyberpunk',
            'language': 'en',
            'auto_save': True,
            'max_scan_history': 100,
            'database_path': 'data/cyber_amenti.db',
            'scan_timeout': 300,
            'netcat_timeout': 30,
            'auto_profile': True,
            'auto_correlate_vulns': True,
            'export_format': 'json',
            'log_level': 'INFO',
            'backup_enabled': True,
            'backup_interval': 86400,  # 24 hours in seconds
            'max_concurrent_scans': 5,
            'nmap_path': 'nmap',
            'netcat_path': 'nc',
            'update_exploits_on_startup': False,
            'risk_threshold_high': 7.0,
            'risk_threshold_medium': 4.0,
            'confidence_threshold': 0.5,
            'session_timeout': 3600,  # 1 hour in seconds
            'max_targets_per_scan': 256,
            'banner_enabled': True,
            'sound_enabled': False,
            'notifications_enabled': True,
            'debug_mode': False,
            'hotkey_terminate': 'ctrl+c',
            'split_screen': False
        }
        
        self.ensure_config_directory()
        self.load_config()
    
    def ensure_config_directory(self):
        """Ensure configuration directory exists"""
        config_dir = os.path.dirname(self.config_file)
        if config_dir:
            os.makedirs(config_dir, exist_ok=True)
    
    def load_config(self):
        """Load configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    file_config = json.load(f)
                
                # Merge with defaults, giving priority to file config
                self.config_data = self.default_config.copy()
                self.config_data.update(file_config)
            else:
                # Use default config and create file
                self.config_data = self.default_config.copy()
                self.save_config()
                
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error loading config file: {e}")
            print("Using default configuration...")
            self.config_data = self.default_config.copy()
    
    def save_config(self):
        """Save current configuration to file"""
        try:
            self.ensure_config_directory()
            
            with open(self.config_file, 'w') as f:
                json.dump(self.config_data, f, indent=4, sort_keys=True)
                
        except IOError as e:
            print(f"Error saving config file: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        return self.config_data.get(key, default)
    
    def set(self, key: str, value: Any):
        """Set configuration value"""
        self.config_data[key] = value
        self.save_config()
    
    def update(self, updates: Dict[str, Any]):
        """Update multiple configuration values"""
        self.config_data.update(updates)
        self.save_config()
    
    def reset_to_defaults(self):
        """Reset configuration to defaults"""
        self.config_data = self.default_config.copy()
        self.save_config()
    
    def get_all(self) -> Dict[str, Any]:
        """Get all configuration values"""
        return self.config_data.copy()
    
    def validate_config(self) -> Dict[str, str]:
        """Validate current configuration and return any errors"""
        errors = {}
        
        # Validate theme
        valid_themes = ['matrix', 'cyberpunk', 'starlight']
        if self.config_data.get('theme') not in valid_themes:
            errors['theme'] = f"Invalid theme. Must be one of: {', '.join(valid_themes)}"
        
        # Validate language
        valid_languages = ['en', 'es', 'fr', 'de']
        if self.config_data.get('language') not in valid_languages:
            errors['language'] = f"Invalid language. Must be one of: {', '.join(valid_languages)}"
        
        # Validate numeric values
        numeric_fields = {
            'max_scan_history': (1, 10000),
            'scan_timeout': (10, 3600),
            'netcat_timeout': (1, 300),
            'backup_interval': (3600, 604800),  # 1 hour to 1 week
            'max_concurrent_scans': (1, 50),
            'risk_threshold_high': (0.0, 10.0),
            'risk_threshold_medium': (0.0, 10.0),
            'confidence_threshold': (0.0, 1.0),
            'session_timeout': (60, 86400),  # 1 minute to 24 hours
            'max_targets_per_scan': (1, 65536)
        }
        
        for field, (min_val, max_val) in numeric_fields.items():
            value = self.config_data.get(field)
            if not isinstance(value, (int, float)) or not (min_val <= value <= max_val):
                errors[field] = f"Must be a number between {min_val} and {max_val}"
        
        # Validate boolean fields
        boolean_fields = ['auto_save', 'auto_profile', 'auto_correlate_vulns', 'backup_enabled',
                         'update_exploits_on_startup', 'banner_enabled', 'sound_enabled',
                         'notifications_enabled', 'debug_mode']
        
        for field in boolean_fields:
            if not isinstance(self.config_data.get(field), bool):
                errors[field] = "Must be true or false"
        
        # Validate paths
        nmap_path = self.config_data.get('nmap_path', 'nmap')
        netcat_path = self.config_data.get('netcat_path', 'nc')
        
        # Check if executables exist in PATH (simplified check)
        import shutil
        if not shutil.which(nmap_path):
            errors['nmap_path'] = f"nmap executable not found: {nmap_path}"
        
        if not shutil.which(netcat_path):
            errors['netcat_path'] = f"netcat executable not found: {netcat_path}"
        
        # Validate export format
        valid_formats = ['json', 'csv', 'xml', 'html']
        if self.config_data.get('export_format') not in valid_formats:
            errors['export_format'] = f"Invalid export format. Must be one of: {', '.join(valid_formats)}"
        
        # Validate log level
        valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if self.config_data.get('log_level') not in valid_log_levels:
            errors['log_level'] = f"Invalid log level. Must be one of: {', '.join(valid_log_levels)}"
        
        return errors
    
    def backup_config(self, backup_path: str = None):
        """Create a backup of current configuration"""
        if not backup_path:
            import time
            timestamp = int(time.time())
            backup_path = f"{self.config_file}.backup.{timestamp}"
        
        try:
            with open(backup_path, 'w') as f:
                json.dump(self.config_data, f, indent=4, sort_keys=True)
            return backup_path
        except IOError as e:
            print(f"Error creating config backup: {e}")
            return None
    
    def restore_config(self, backup_path: str):
        """Restore configuration from backup"""
        try:
            with open(backup_path, 'r') as f:
                backup_config = json.load(f)
            
            # Validate backup config
            temp_config = self.config_data
            self.config_data = backup_config
            errors = self.validate_config()
            
            if errors:
                # Restore original config if backup is invalid
                self.config_data = temp_config
                return False, f"Invalid backup config: {errors}"
            
            self.save_config()
            return True, "Configuration restored successfully"
            
        except (json.JSONDecodeError, IOError) as e:
            return False, f"Error restoring config: {e}"
    
    def export_config(self, export_path: str):
        """Export configuration to specified path"""
        try:
            with open(export_path, 'w') as f:
                export_data = {
                    'cyber_amenti_config': self.config_data,
                    'export_timestamp': self._get_timestamp(),
                    'version': '1.0'
                }
                json.dump(export_data, f, indent=4, sort_keys=True)
            return True
        except IOError as e:
            print(f"Error exporting config: {e}")
            return False
    
    def import_config(self, import_path: str) -> tuple:
        """Import configuration from specified path"""
        try:
            with open(import_path, 'r') as f:
                import_data = json.load(f)
            
            if 'cyber_amenti_config' not in import_data:
                return False, "Invalid config file format"
            
            imported_config = import_data['cyber_amenti_config']
            
            # Validate imported config
            temp_config = self.config_data
            self.config_data = imported_config
            errors = self.validate_config()
            
            if errors:
                self.config_data = temp_config
                return False, f"Invalid imported config: {errors}"
            
            self.save_config()
            return True, "Configuration imported successfully"
            
        except (json.JSONDecodeError, IOError) as e:
            return False, f"Error importing config: {e}"
    
    def get_user_config_path(self) -> str:
        """Get user-specific configuration path"""
        home_dir = Path.home()
        user_config_dir = home_dir / '.cyber_amenti'
        user_config_dir.mkdir(exist_ok=True)
        return str(user_config_dir / 'settings.json')
    
    def migrate_config(self, old_version: str, new_version: str):
        """Migrate configuration from old version to new version"""
        # This would handle configuration migrations between versions
        migration_map = {
            '0.9': {
                # Example migration from 0.9 to 1.0
                'scan_delay': 'scan_timeout',  # Renamed field
                'max_history': 'max_scan_history'  # Renamed field
            }
        }
        
        if old_version in migration_map:
            migrations = migration_map[old_version]
            for old_key, new_key in migrations.items():
                if old_key in self.config_data:
                    self.config_data[new_key] = self.config_data.pop(old_key)
            
            self.save_config()
    
    def _get_timestamp(self) -> str:
        """Get current timestamp string"""
        import time
        return time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
    
    def get_effective_config(self) -> Dict[str, Any]:
        """Get effective configuration with environment variable overrides"""
        effective_config = self.config_data.copy()
        
        # Environment variable overrides
        env_overrides = {
            'CYBER_AMENTI_THEME': 'theme',
            'CYBER_AMENTI_LANGUAGE': 'language',
            'CYBER_AMENTI_DB_PATH': 'database_path',
            'CYBER_AMENTI_DEBUG': 'debug_mode',
            'CYBER_AMENTI_LOG_LEVEL': 'log_level',
            'NMAP_PATH': 'nmap_path',
            'NETCAT_PATH': 'netcat_path'
        }
        
        for env_var, config_key in env_overrides.items():
            env_value = os.getenv(env_var)
            if env_value:
                # Type conversion for specific fields
                if config_key in ['debug_mode', 'auto_save', 'banner_enabled']:
                    env_value = env_value.lower() in ('true', '1', 'yes', 'on')
                elif config_key in ['max_scan_history', 'scan_timeout', 'netcat_timeout']:
                    try:
                        env_value = int(env_value)
                    except ValueError:
                        continue
                elif config_key in ['risk_threshold_high', 'risk_threshold_medium', 'confidence_threshold']:
                    try:
                        env_value = float(env_value)
                    except ValueError:
                        continue
                
                effective_config[config_key] = env_value
        
        return effective_config
    
    def reset_to_factory_defaults(self):
        """Reset to factory defaults and remove config file"""
        self.config_data = self.default_config.copy()
        if os.path.exists(self.config_file):
            try:
                os.remove(self.config_file)
            except IOError:
                pass
        self.save_config()
    
    def get_config_summary(self) -> Dict[str, Any]:
        """Get configuration summary for display"""
        return {
            'config_file': self.config_file,
            'config_exists': os.path.exists(self.config_file),
            'total_settings': len(self.config_data),
            'theme': self.config_data.get('theme'),
            'language': self.config_data.get('language'),
            'debug_mode': self.config_data.get('debug_mode'),
            'last_modified': self._get_file_mtime() if os.path.exists(self.config_file) else None
        }
    
    def _get_file_mtime(self) -> str:
        """Get file modification time"""
        import time
        mtime = os.path.getmtime(self.config_file)
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mtime))
