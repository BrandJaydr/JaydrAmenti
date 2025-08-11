"""
Intelligence Database Manager
SQLite-based storage for scan results, device profiles, and dossiers
"""

import sqlite3
import json
import time
import os
from typing import Dict, List, Optional, Any
from contextlib import contextmanager
import csv

class IntelligenceDB:
    def __init__(self, db_path: str = "data/cyber_amenti.db"):
        self.db_path = db_path
        self.ensure_directory()
        self.initialize()
    
    def ensure_directory(self):
        """Ensure database directory exists"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def initialize(self):
        """Initialize database schema"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Scan results table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    command TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    scan_subtype TEXT NOT NULL,
                    target TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    return_code INTEGER,
                    stdout TEXT,
                    stderr TEXT,
                    xml_output TEXT,
                    parsed_results TEXT,  -- JSON
                    created_at REAL DEFAULT (julianday('now'))
                )
            ''')
            
            # Device profiles table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS device_profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    mac_address TEXT,
                    hostname TEXT,
                    os_family TEXT,
                    os_version TEXT,
                    device_type TEXT,
                    vendor TEXT,
                    open_ports TEXT,  -- JSON array
                    services TEXT,    -- JSON object
                    vulnerabilities TEXT,  -- JSON array
                    risk_score REAL DEFAULT 0.0,
                    confidence REAL DEFAULT 0.0,
                    tags TEXT,        -- JSON array
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    created_at REAL DEFAULT (julianday('now')),
                    updated_at REAL DEFAULT (julianday('now'))
                )
            ''')
            
            # Vulnerability data table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT UNIQUE NOT NULL,
                    severity TEXT NOT NULL,
                    score REAL NOT NULL,
                    description TEXT NOT NULL,
                    affected_versions TEXT,  -- JSON array
                    exploit_available BOOLEAN DEFAULT 0,
                    exploit_references TEXT, -- JSON array
                    mitigation TEXT,
                    created_at REAL DEFAULT (julianday('now')),
                    updated_at REAL DEFAULT (julianday('now'))
                )
            ''')
            
            # Exploit information table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS exploits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    exploit_id TEXT UNIQUE NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    type TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    exploit_references TEXT,  -- JSON array
                    difficulty TEXT,
                    reliability TEXT,
                    author TEXT,
                    date_published TEXT,
                    created_at REAL DEFAULT (julianday('now'))
                )
            ''')
            
            # Intelligence dossiers table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS dossiers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    target TEXT NOT NULL,
                    description TEXT,
                    scan_results TEXT,    -- JSON array of scan result IDs
                    device_profiles TEXT, -- JSON array of device profile IDs
                    vulnerabilities TEXT, -- JSON array of vulnerability IDs
                    notes TEXT,
                    tags TEXT,           -- JSON array
                    created_at REAL DEFAULT (julianday('now')),
                    updated_at REAL DEFAULT (julianday('now'))
                )
            ''')
            
            # Network sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_name TEXT NOT NULL,
                    target_network TEXT NOT NULL,
                    start_time REAL NOT NULL,
                    end_time REAL,
                    scan_count INTEGER DEFAULT 0,
                    devices_found INTEGER DEFAULT 0,
                    vulnerabilities_found INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'active',
                    created_at REAL DEFAULT (julianday('now'))
                )
            ''')
            
            # Create indexes for performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_device_profiles_ip ON device_profiles(ip_address)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_results_target ON scan_results(target)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_results_timestamp ON scan_results(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve ON vulnerabilities(cve_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_exploits_id ON exploits(exploit_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_dossiers_target ON dossiers(target)')
            
            conn.commit()
    
    def save_scan_result(self, scan_result: Dict) -> int:
        """Save scan result to database"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Extract target from scan result
            target = scan_result.get('target', 'unknown')
            if 'parsed_results' in scan_result and scan_result['parsed_results']:
                # Try to extract target from parsed results
                hosts = scan_result['parsed_results'].get('hosts', [])
                if hosts and hosts[0].get('addresses'):
                    for addr in hosts[0]['addresses']:
                        if addr.get('addrtype') == 'ipv4':
                            target = addr.get('addr', target)
                            break
            
            cursor.execute('''
                INSERT INTO scan_results 
                (command, scan_type, scan_subtype, target, timestamp, return_code, 
                 stdout, stderr, xml_output, parsed_results)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_result.get('command', ''),
                scan_result.get('scan_type', ''),
                scan_result.get('scan_subtype', ''),
                target,
                scan_result.get('timestamp', time.time()),
                scan_result.get('return_code'),
                scan_result.get('stdout', ''),
                scan_result.get('stderr', ''),
                scan_result.get('xml_output', ''),
                json.dumps(scan_result.get('parsed_results')) if scan_result.get('parsed_results') else None
            ))
            
            conn.commit()
            return cursor.lastrowid
    
    def save_device_profile(self, profile) -> int:
        """Save device profile to database"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Convert profile to dict if it's a DeviceProfile object
            if hasattr(profile, '__dict__'):
                profile_data = profile.__dict__.copy()
            else:
                profile_data = profile
            
            # Convert sets to lists for JSON serialization
            if 'tags' in profile_data and isinstance(profile_data['tags'], set):
                profile_data['tags'] = list(profile_data['tags'])
            
            # Check if profile already exists
            cursor.execute('SELECT id FROM device_profiles WHERE ip_address = ?', 
                          (profile_data['ip_address'],))
            existing = cursor.fetchone()
            
            if existing:
                # Update existing profile
                cursor.execute('''
                    UPDATE device_profiles SET
                        mac_address = ?, hostname = ?, os_family = ?, os_version = ?,
                        device_type = ?, vendor = ?, open_ports = ?, services = ?,
                        vulnerabilities = ?, risk_score = ?, confidence = ?, tags = ?,
                        last_seen = ?, updated_at = julianday('now')
                    WHERE ip_address = ?
                ''', (
                    profile_data.get('mac_address'),
                    profile_data.get('hostname'),
                    profile_data.get('os_family'),
                    profile_data.get('os_version'),
                    profile_data.get('device_type'),
                    profile_data.get('vendor'),
                    json.dumps(profile_data.get('open_ports', [])),
                    json.dumps(profile_data.get('services', {})),
                    json.dumps(profile_data.get('vulnerabilities', [])),
                    profile_data.get('risk_score', 0.0),
                    profile_data.get('confidence', 0.0),
                    json.dumps(profile_data.get('tags', [])),
                    profile_data.get('last_seen', time.time()),
                    profile_data['ip_address']
                ))
                return existing['id']
            else:
                # Insert new profile
                cursor.execute('''
                    INSERT INTO device_profiles 
                    (ip_address, mac_address, hostname, os_family, os_version, device_type, vendor,
                     open_ports, services, vulnerabilities, risk_score, confidence, tags,
                     first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    profile_data['ip_address'],
                    profile_data.get('mac_address'),
                    profile_data.get('hostname'),
                    profile_data.get('os_family'),
                    profile_data.get('os_version'),
                    profile_data.get('device_type'),
                    profile_data.get('vendor'),
                    json.dumps(profile_data.get('open_ports', [])),
                    json.dumps(profile_data.get('services', {})),
                    json.dumps(profile_data.get('vulnerabilities', [])),
                    profile_data.get('risk_score', 0.0),
                    profile_data.get('confidence', 0.0),
                    json.dumps(profile_data.get('tags', [])),
                    profile_data.get('first_seen', time.time()),
                    profile_data.get('last_seen', time.time())
                ))
                
                conn.commit()
                return cursor.lastrowid
    
    def get_device_profile_by_ip(self, ip_address: str) -> Optional[Dict]:
        """Get device profile by IP address"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM device_profiles WHERE ip_address = ?', (ip_address,))
            row = cursor.fetchone()
            
            if row:
                profile = dict(row)
                # Parse JSON fields
                profile['open_ports'] = json.loads(profile['open_ports']) if profile['open_ports'] else []
                profile['services'] = json.loads(profile['services']) if profile['services'] else {}
                profile['vulnerabilities'] = json.loads(profile['vulnerabilities']) if profile['vulnerabilities'] else []
                profile['tags'] = set(json.loads(profile['tags'])) if profile['tags'] else set()
                return profile
            
            return None
    
    def get_all_device_profiles(self) -> List[Dict]:
        """Get all device profiles"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM device_profiles ORDER BY last_seen DESC')
            rows = cursor.fetchall()
            
            profiles = []
            for row in rows:
                profile = dict(row)
                # Parse JSON fields
                profile['open_ports'] = json.loads(profile['open_ports']) if profile['open_ports'] else []
                profile['services'] = json.loads(profile['services']) if profile['services'] else {}
                profile['vulnerabilities'] = json.loads(profile['vulnerabilities']) if profile['vulnerabilities'] else []
                profile['tags'] = set(json.loads(profile['tags'])) if profile['tags'] else set()
                profiles.append(profile)
            
            return profiles
    
    def search_device_profiles(self, search_term: str) -> List[Dict]:
        """Search device profiles by various fields"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            search_pattern = f'%{search_term}%'
            
            cursor.execute('''
                SELECT * FROM device_profiles 
                WHERE ip_address LIKE ? OR hostname LIKE ? OR os_family LIKE ? 
                   OR device_type LIKE ? OR vendor LIKE ?
                ORDER BY last_seen DESC
            ''', (search_pattern, search_pattern, search_pattern, search_pattern, search_pattern))
            
            rows = cursor.fetchall()
            
            profiles = []
            for row in rows:
                profile = dict(row)
                # Parse JSON fields
                profile['open_ports'] = json.loads(profile['open_ports']) if profile['open_ports'] else []
                profile['services'] = json.loads(profile['services']) if profile['services'] else {}
                profile['vulnerabilities'] = json.loads(profile['vulnerabilities']) if profile['vulnerabilities'] else []
                profile['tags'] = set(json.loads(profile['tags'])) if profile['tags'] else set()
                profiles.append(profile)
            
            return profiles
    
    def get_scan_results(self, limit: int = 100) -> List[Dict]:
        """Get recent scan results"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM scan_results 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            
            rows = cursor.fetchall()
            results = []
            
            for row in rows:
                result = dict(row)
                if result['parsed_results']:
                    result['parsed_results'] = json.loads(result['parsed_results'])
                results.append(result)
            
            return results
    
    def save_vulnerability(self, vulnerability) -> int:
        """Save vulnerability to database"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Convert vulnerability to dict if it's an object
            if hasattr(vulnerability, '__dict__'):
                vuln_data = vulnerability.__dict__.copy()
            else:
                vuln_data = vulnerability
            
            cursor.execute('''
                INSERT OR REPLACE INTO vulnerabilities 
                (cve_id, severity, score, description, affected_versions, 
                 exploit_available, exploit_references, mitigation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                vuln_data['cve_id'],
                vuln_data['severity'],
                vuln_data['score'],
                vuln_data['description'],
                json.dumps(vuln_data.get('affected_versions', [])),
                vuln_data.get('exploit_available', False),
                json.dumps(vuln_data.get('exploit_references', [])),
                vuln_data.get('mitigation', '')
            ))
            
            conn.commit()
            return cursor.lastrowid
    
    def save_exploit(self, exploit) -> int:
        """Save exploit to database"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Convert exploit to dict if it's an object
            if hasattr(exploit, '__dict__'):
                exploit_data = exploit.__dict__.copy()
            else:
                exploit_data = exploit
            
            cursor.execute('''
                INSERT OR REPLACE INTO exploits 
                (exploit_id, title, description, type, platform, exploit_references,
                 difficulty, reliability, author, date_published)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                exploit_data['exploit_id'],
                exploit_data['title'],
                exploit_data['description'],
                exploit_data['type'],
                exploit_data['platform'],
                json.dumps(exploit_data.get('references', [])),
                exploit_data.get('difficulty', ''),
                exploit_data.get('reliability', ''),
                exploit_data.get('author', ''),
                exploit_data.get('date_published', '')
            ))
            
            conn.commit()
            return cursor.lastrowid
    
    def create_dossier(self, target: str, title: str, description: str = "") -> int:
        """Create new intelligence dossier"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO dossiers (title, target, description, scan_results, 
                                    device_profiles, vulnerabilities, notes, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                title,
                target,
                description,
                json.dumps([]),  # Empty arrays for new dossier
                json.dumps([]),
                json.dumps([]),
                "",
                json.dumps([])
            ))
            
            conn.commit()
            return cursor.lastrowid
    
    def get_dossier(self, dossier_id: int) -> Optional[Dict]:
        """Get dossier by ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM dossiers WHERE id = ?', (dossier_id,))
            row = cursor.fetchone()
            
            if row:
                dossier = dict(row)
                # Parse JSON fields
                dossier['scan_results'] = json.loads(dossier['scan_results']) if dossier['scan_results'] else []
                dossier['device_profiles'] = json.loads(dossier['device_profiles']) if dossier['device_profiles'] else []
                dossier['vulnerabilities'] = json.loads(dossier['vulnerabilities']) if dossier['vulnerabilities'] else []
                dossier['tags'] = json.loads(dossier['tags']) if dossier['tags'] else []
                return dossier
            
            return None
    
    def get_all_dossiers(self) -> List[Dict]:
        """Get all dossiers"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM dossiers ORDER BY created_at DESC')
            rows = cursor.fetchall()
            
            dossiers = []
            for row in rows:
                dossier = dict(row)
                # Parse JSON fields
                dossier['scan_results'] = json.loads(dossier['scan_results']) if dossier['scan_results'] else []
                dossier['device_profiles'] = json.loads(dossier['device_profiles']) if dossier['device_profiles'] else []
                dossier['vulnerabilities'] = json.loads(dossier['vulnerabilities']) if dossier['vulnerabilities'] else []
                dossier['tags'] = json.loads(dossier['tags']) if dossier['tags'] else []
                dossiers.append(dossier)
            
            return dossiers
    
    def delete_dossier(self, dossier_id: int) -> bool:
        """Delete dossier by ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM dossiers WHERE id = ?', (dossier_id,))
            conn.commit()
            return cursor.rowcount > 0
    
    def export_dossier(self, dossier_id: int, format: str = 'json') -> str:
        """Export dossier in specified format"""
        dossier = self.get_dossier(dossier_id)
        if not dossier:
            raise ValueError(f"Dossier {dossier_id} not found")
        
        # Get related data
        scan_results = []
        for scan_id in dossier['scan_results']:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM scan_results WHERE id = ?', (scan_id,))
                row = cursor.fetchone()
                if row:
                    scan_results.append(dict(row))
        
        device_profiles = []
        for profile_id in dossier['device_profiles']:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM device_profiles WHERE id = ?', (profile_id,))
                row = cursor.fetchone()
                if row:
                    device_profiles.append(dict(row))
        
        export_data = {
            'dossier': dossier,
            'scan_results': scan_results,
            'device_profiles': device_profiles,
            'export_timestamp': time.time()
        }
        
        filename = f"dossier_{dossier_id}_{int(time.time())}.{format}"
        
        if format == 'json':
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
        elif format == 'html':
            self._export_dossier_html(export_data, filename)
        elif format == 'pdf':
            # Would implement PDF generation here
            raise NotImplementedError("PDF export not yet implemented")
        
        return filename
    
    def _export_dossier_html(self, data: Dict, filename: str):
        """Export dossier as HTML report"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Cyber Amenti Dossier Report</title>
            <style>
                body {{ font-family: 'Courier New', monospace; background: #000; color: #0f0; }}
                .header {{ text-align: center; border-bottom: 2px solid #0f0; padding: 20px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #0f0; }}
                .device {{ background: #001a00; margin: 10px 0; padding: 10px; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #0f0; padding: 8px; text-align: left; }}
                th {{ background: #003300; }}
                .risk-high {{ color: #ff0000; }}
                .risk-medium {{ color: #ffff00; }}
                .risk-low {{ color: #00ff00; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>CYBER AMENTI INTELLIGENCE DOSSIER</h1>
                <h2>{data['dossier']['title']}</h2>
                <p>Target: {data['dossier']['target']}</p>
                <p>Generated: {time.ctime(data['export_timestamp'])}</p>
            </div>
            
            <div class="section">
                <h3>EXECUTIVE SUMMARY</h3>
                <p>{data['dossier'].get('description', 'No description provided')}</p>
            </div>
            
            <div class="section">
                <h3>DISCOVERED DEVICES</h3>
        """
        
        for profile in data['device_profiles']:
            risk_class = 'risk-high' if profile.get('risk_score', 0) >= 7 else 'risk-medium' if profile.get('risk_score', 0) >= 4 else 'risk-low'
            html_content += f"""
                <div class="device">
                    <h4>{profile['ip_address']} - {profile.get('hostname', 'Unknown')}</h4>
                    <p><strong>OS:</strong> {profile.get('os_family', 'Unknown')}</p>
                    <p><strong>Device Type:</strong> {profile.get('device_type', 'Unknown')}</p>
                    <p><strong>Risk Score:</strong> <span class="{risk_class}">{profile.get('risk_score', 0):.1f}/10.0</span></p>
                </div>
            """
        
        html_content += """
            </div>
        </body>
        </html>
        """
        
        with open(filename, 'w') as f:
            f.write(html_content)
    
    def get_profile_statistics(self) -> Dict:
        """Get device profile statistics"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            stats = {}
            
            # Total profiles
            cursor.execute('SELECT COUNT(*) as count FROM device_profiles')
            stats['total_profiles'] = cursor.fetchone()['count']
            
            # High risk devices (risk score >= 7.0)
            cursor.execute('SELECT COUNT(*) as count FROM device_profiles WHERE risk_score >= 7.0')
            stats['high_risk_count'] = cursor.fetchone()['count']
            
            # Most common OS
            cursor.execute('''
                SELECT os_family, COUNT(*) as count 
                FROM device_profiles 
                WHERE os_family IS NOT NULL 
                GROUP BY os_family 
                ORDER BY count DESC 
                LIMIT 1
            ''')
            row = cursor.fetchone()
            stats['most_common_os'] = row['os_family'] if row else 'Unknown'
            
            # Most common device type
            cursor.execute('''
                SELECT device_type, COUNT(*) as count 
                FROM device_profiles 
                WHERE device_type IS NOT NULL 
                GROUP BY device_type 
                ORDER BY count DESC 
                LIMIT 1
            ''')
            row = cursor.fetchone()
            stats['most_common_device_type'] = row['device_type'] if row else 'Unknown'
            
            # Average risk score
            cursor.execute('SELECT AVG(risk_score) as avg_risk FROM device_profiles')
            stats['avg_risk_score'] = cursor.fetchone()['avg_risk'] or 0.0
            
            # Device type breakdown
            cursor.execute('''
                SELECT device_type, COUNT(*) as count 
                FROM device_profiles 
                WHERE device_type IS NOT NULL 
                GROUP BY device_type 
                ORDER BY count DESC
            ''')
            stats['device_type_breakdown'] = {row['device_type']: row['count'] for row in cursor.fetchall()}
            
            return stats
    
    def export_profiles_csv(self, filename: str):
        """Export device profiles to CSV"""
        profiles = self.get_all_device_profiles()
        
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['ip_address', 'hostname', 'os_family', 'device_type', 'vendor', 
                         'risk_score', 'confidence', 'first_seen', 'last_seen']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for profile in profiles:
                row = {field: profile.get(field, '') for field in fieldnames}
                # Convert timestamps to readable format
                if row['first_seen']:
                    row['first_seen'] = time.ctime(row['first_seen'])
                if row['last_seen']:
                    row['last_seen'] = time.ctime(row['last_seen'])
                writer.writerow(row)
    
    def cleanup_old_data(self, days: int = 30):
        """Clean up old scan results and temporary data"""
        cutoff_time = time.time() - (days * 24 * 60 * 60)
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Clean up old scan results
            cursor.execute('DELETE FROM scan_results WHERE timestamp < ?', (cutoff_time,))
            
            # Update device profiles last seen that are older than cutoff
            cursor.execute('''
                UPDATE device_profiles 
                SET last_seen = ? 
                WHERE last_seen < ?
            ''', (cutoff_time, cutoff_time))
            
            conn.commit()
    
    def backup_database(self, backup_path: str):
        """Create database backup"""
        with self.get_connection() as conn:
            with open(backup_path, 'w') as f:
                for line in conn.iterdump():
                    f.write('%s\n' % line)
    
    def get_database_info(self) -> Dict:
        """Get database information and statistics"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            info = {}
            
            # Table counts
            tables = ['scan_results', 'device_profiles', 'vulnerabilities', 'exploits', 'dossiers']
            for table in tables:
                cursor.execute(f'SELECT COUNT(*) as count FROM {table}')
                info[f'{table}_count'] = cursor.fetchone()['count']
            
            # Database size
            info['database_size'] = os.path.getsize(self.db_path)
            info['database_path'] = self.db_path
            
            return info
