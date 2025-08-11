"""
Device Profiler
Advanced device fingerprinting and categorization system
"""

import time
import json
import hashlib
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

@dataclass
class DeviceProfile:
    """Device profile data structure"""
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    os_family: Optional[str] = None
    os_version: Optional[str] = None
    device_type: Optional[str] = None
    vendor: Optional[str] = None
    open_ports: List[int] = None
    services: Dict[str, Dict] = None
    vulnerabilities: List[Dict] = None
    risk_score: float = 0.0
    confidence: float = 0.0
    last_seen: float = None
    first_seen: float = None
    tags: Set[str] = None
    
    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []
        if self.services is None:
            self.services = {}
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.tags is None:
            self.tags = set()
        if self.last_seen is None:
            self.last_seen = time.time()
        if self.first_seen is None:
            self.first_seen = time.time()

class DeviceProfiler:
    def __init__(self):
        self.console = Console()
        self.profiles = {}
        
        # Device fingerprinting rules
        self.fingerprint_rules = {
            'os_detection': {
                'windows': {
                    'ports': [135, 139, 445, 3389],
                    'services': ['microsoft-ds', 'netbios-ssn', 'ms-wbt-server'],
                    'banners': ['Microsoft', 'Windows']
                },
                'linux': {
                    'ports': [22, 111, 2049],
                    'services': ['ssh', 'rpcbind', 'nfs'],
                    'banners': ['OpenSSH', 'Ubuntu', 'CentOS', 'Red Hat']
                },
                'macos': {
                    'ports': [22, 548, 631],
                    'services': ['ssh', 'afp', 'ipp'],
                    'banners': ['Darwin', 'Mac OS']
                },
                'freebsd': {
                    'ports': [22],
                    'services': ['ssh'],
                    'banners': ['FreeBSD']
                },
                'embedded': {
                    'ports': [23, 80, 443],
                    'services': ['telnet', 'http', 'https'],
                    'banners': ['embedded', 'router', 'switch']
                }
            },
            
            'device_types': {
                'server': {
                    'indicators': ['ssh', 'http', 'https', 'smtp', 'dns', 'ftp'],
                    'port_ranges': [(20, 25), (53, 53), (80, 80), (110, 110), (143, 143), (443, 443)]
                },
                'workstation': {
                    'indicators': ['rdp', 'vnc', 'smb'],
                    'port_ranges': [(3389, 3389), (5900, 5910), (139, 139), (445, 445)]
                },
                'router': {
                    'indicators': ['snmp', 'telnet', 'ssh'],
                    'port_ranges': [(23, 23), (161, 161), (22, 22)],
                    'banners': ['cisco', 'juniper', 'mikrotik']
                },
                'printer': {
                    'indicators': ['ipp', 'lpd', 'snmp'],
                    'port_ranges': [(515, 515), (631, 631), (9100, 9100)],
                    'banners': ['hp', 'canon', 'epson']
                },
                'iot': {
                    'indicators': ['http', 'telnet', 'upnp'],
                    'port_ranges': [(80, 80), (23, 23), (1900, 1900)],
                    'unusual_ports': True
                },
                'database': {
                    'indicators': ['mysql', 'postgresql', 'mssql', 'oracle'],
                    'port_ranges': [(1433, 1433), (1521, 1521), (3306, 3306), (5432, 5432)]
                }
            },
            
            'vendor_detection': {
                'cisco': ['cisco', 'ios'],
                'hp': ['hp', 'hewlett'],
                'dell': ['dell'],
                'microsoft': ['microsoft', 'windows'],
                'apple': ['apple', 'darwin', 'macos'],
                'linux': ['linux', 'ubuntu', 'centos', 'redhat', 'debian'],
                'vmware': ['vmware', 'esxi'],
                'juniper': ['juniper', 'junos']
            }
        }
        
        # Risk scoring weights
        self.risk_weights = {
            'open_ports': 0.2,
            'vulnerable_services': 0.4,
            'os_vulnerabilities': 0.3,
            'exposed_services': 0.1
        }
    
    def create_profile(self, scan_results: Dict) -> DeviceProfile:
        """Create device profile from scan results"""
        if not scan_results.get('parsed_results'):
            raise ValueError("No parsed scan results provided")
        
        hosts = scan_results['parsed_results'].get('hosts', [])
        if not hosts:
            raise ValueError("No hosts found in scan results")
        
        # Process first host (extend for multiple hosts)
        host_data = hosts[0]
        
        # Extract basic information
        ip_address = self._extract_ip_address(host_data)
        mac_address = self._extract_mac_address(host_data)
        hostname = self._extract_hostname(host_data)
        
        # Create profile
        profile = DeviceProfile(
            ip_address=ip_address,
            mac_address=mac_address,
            hostname=hostname
        )
        
        # Extract port and service information
        self._analyze_ports_and_services(profile, host_data)
        
        # Perform OS detection
        self._detect_operating_system(profile, host_data)
        
        # Determine device type
        self._classify_device_type(profile)
        
        # Detect vendor
        self._detect_vendor(profile)
        
        # Calculate confidence score
        self._calculate_confidence(profile)
        
        # Add to profiles cache
        profile_id = self._generate_profile_id(profile)
        self.profiles[profile_id] = profile
        
        return profile
    
    def _extract_ip_address(self, host_data: Dict) -> str:
        """Extract IP address from host data"""
        addresses = host_data.get('addresses', [])
        for addr in addresses:
            if addr.get('addrtype') == 'ipv4':
                return addr.get('addr')
        return 'unknown'
    
    def _extract_mac_address(self, host_data: Dict) -> Optional[str]:
        """Extract MAC address from host data"""
        addresses = host_data.get('addresses', [])
        for addr in addresses:
            if addr.get('addrtype') == 'mac':
                return addr.get('addr')
        return None
    
    def _extract_hostname(self, host_data: Dict) -> Optional[str]:
        """Extract hostname from host data"""
        hostnames = host_data.get('hostnames', [])
        if hostnames:
            return hostnames[0].get('name')
        return None
    
    def _analyze_ports_and_services(self, profile: DeviceProfile, host_data: Dict):
        """Analyze ports and services from scan data"""
        ports = host_data.get('ports', [])
        
        for port_data in ports:
            port_num = int(port_data.get('portid', 0))
            state = port_data.get('state', {}).get('state')
            
            if state == 'open':
                profile.open_ports.append(port_num)
                
                # Extract service information
                service_data = port_data.get('service', {})
                if service_data:
                    service_info = {
                        'name': service_data.get('name', 'unknown'),
                        'product': service_data.get('product'),
                        'version': service_data.get('version'),
                        'extrainfo': service_data.get('extrainfo'),
                        'method': service_data.get('method'),
                        'confidence': service_data.get('conf')
                    }
                    
                    # Add script results
                    scripts = port_data.get('scripts', [])
                    if scripts:
                        service_info['scripts'] = scripts
                    
                    profile.services[str(port_num)] = service_info
    
    def _detect_operating_system(self, profile: DeviceProfile, host_data: Dict):
        """Detect operating system from various indicators"""
        # Try OS detection from nmap results first
        os_data = host_data.get('os', {})
        if os_data:
            osmatch = os_data.get('osmatch', [])
            if osmatch:
                best_match = max(osmatch, key=lambda x: float(x.get('accuracy', 0)))
                profile.os_family = best_match.get('name')
                
                # Extract OS family from osclass
                osclass = best_match.get('osclass', [])
                if osclass:
                    profile.os_version = osclass[0].get('osgen')
                return
        
        # Fallback to port-based OS detection
        for os_name, indicators in self.fingerprint_rules['os_detection'].items():
            score = 0
            
            # Check port indicators
            for port in indicators.get('ports', []):
                if port in profile.open_ports:
                    score += 1
            
            # Check service indicators
            for service in indicators.get('services', []):
                for port_services in profile.services.values():
                    if service in port_services.get('name', ''):
                        score += 2
            
            # Check banner indicators
            for banner_keyword in indicators.get('banners', []):
                for port_services in profile.services.values():
                    service_info = str(port_services).lower()
                    if banner_keyword.lower() in service_info:
                        score += 3
            
            # Set OS if score is high enough
            if score >= 2:
                profile.os_family = os_name
                break
    
    def _classify_device_type(self, profile: DeviceProfile):
        """Classify device type based on services and ports"""
        device_scores = {}
        
        for device_type, indicators in self.fingerprint_rules['device_types'].items():
            score = 0
            
            # Check service indicators
            for service in indicators.get('indicators', []):
                for port_services in profile.services.values():
                    if service in port_services.get('name', ''):
                        score += 2
            
            # Check port ranges
            for start_port, end_port in indicators.get('port_ranges', []):
                for port in profile.open_ports:
                    if start_port <= port <= end_port:
                        score += 1
            
            # Check banner indicators
            for banner_keyword in indicators.get('banners', []):
                for port_services in profile.services.values():
                    service_info = str(port_services).lower()
                    if banner_keyword.lower() in service_info:
                        score += 3
            
            # Special handling for IoT devices (unusual port combinations)
            if indicators.get('unusual_ports') and len(profile.open_ports) > 0:
                common_ports = {22, 23, 53, 80, 135, 139, 443, 445}
                unusual_count = sum(1 for port in profile.open_ports if port not in common_ports)
                if unusual_count > len(profile.open_ports) / 2:
                    score += 1
            
            device_scores[device_type] = score
        
        # Select device type with highest score
        if device_scores:
            best_type = max(device_scores, key=device_scores.get)
            if device_scores[best_type] > 0:
                profile.device_type = best_type
    
    def _detect_vendor(self, profile: DeviceProfile):
        """Detect device vendor from various indicators"""
        vendor_scores = {}
        
        for vendor, keywords in self.fingerprint_rules['vendor_detection'].items():
            score = 0
            
            # Check service banners and product information
            for port_services in profile.services.values():
                service_text = ' '.join([
                    port_services.get('product', ''),
                    port_services.get('extrainfo', ''),
                    str(port_services.get('scripts', []))
                ]).lower()
                
                for keyword in keywords:
                    if keyword.lower() in service_text:
                        score += 1
            
            # Check MAC address vendor (if available)
            if profile.mac_address:
                mac_prefix = profile.mac_address[:8].upper()
                # This would be enhanced with a proper MAC vendor database
                vendor_mac_mapping = {
                    '00:50:56': 'vmware',
                    '00:0C:29': 'vmware',
                    '08:00:27': 'virtualbox'
                }
                
                for mac_pattern, mac_vendor in vendor_mac_mapping.items():
                    if mac_prefix.startswith(mac_pattern.replace(':', '')):
                        if vendor == mac_vendor:
                            score += 3
            
            vendor_scores[vendor] = score
        
        # Select vendor with highest score
        if vendor_scores:
            best_vendor = max(vendor_scores, key=vendor_scores.get)
            if vendor_scores[best_vendor] > 0:
                profile.vendor = best_vendor
    
    def _calculate_confidence(self, profile: DeviceProfile):
        """Calculate confidence score for the profile"""
        confidence_factors = {
            'has_hostname': 0.1 if profile.hostname else 0,
            'has_mac': 0.1 if profile.mac_address else 0,
            'has_os': 0.3 if profile.os_family else 0,
            'has_device_type': 0.2 if profile.device_type else 0,
            'has_vendor': 0.1 if profile.vendor else 0,
            'service_count': min(len(profile.services) * 0.05, 0.2)
        }
        
        profile.confidence = sum(confidence_factors.values())
    
    def calculate_risk_score(self, profile: DeviceProfile, vulnerabilities: List[Dict] = None) -> float:
        """Calculate risk score for device profile"""
        if vulnerabilities:
            profile.vulnerabilities = vulnerabilities
        
        risk_components = {
            'open_ports': self._score_open_ports(profile),
            'vulnerable_services': self._score_vulnerable_services(profile),
            'os_vulnerabilities': self._score_os_vulnerabilities(profile),
            'exposed_services': self._score_exposed_services(profile)
        }
        
        # Calculate weighted risk score
        total_risk = 0
        for component, score in risk_components.items():
            weight = self.risk_weights.get(component, 0)
            total_risk += score * weight
        
        profile.risk_score = min(total_risk, 10.0)  # Cap at 10.0
        return profile.risk_score
    
    def _score_open_ports(self, profile: DeviceProfile) -> float:
        """Score based on number and type of open ports"""
        if not profile.open_ports:
            return 0.0
        
        # High-risk ports
        high_risk_ports = {21, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432}
        
        risk_score = len(profile.open_ports) * 0.1  # Base score
        
        # Add extra risk for high-risk ports
        for port in profile.open_ports:
            if port in high_risk_ports:
                risk_score += 0.5
        
        return min(risk_score, 5.0)
    
    def _score_vulnerable_services(self, profile: DeviceProfile) -> float:
        """Score based on vulnerable services"""
        if not profile.vulnerabilities:
            return 0.0
        
        # Score based on vulnerability severity
        severity_scores = {'critical': 3.0, 'high': 2.0, 'medium': 1.0, 'low': 0.5}
        
        total_score = 0
        for vuln in profile.vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            total_score += severity_scores.get(severity, 0.5)
        
        return min(total_score, 5.0)
    
    def _score_os_vulnerabilities(self, profile: DeviceProfile) -> float:
        """Score based on OS vulnerabilities"""
        # This would be enhanced with actual vulnerability database
        os_risk_scores = {
            'windows': 2.0,
            'linux': 1.0,
            'embedded': 3.0,
            'unknown': 1.5
        }
        
        os_family = profile.os_family or 'unknown'
        return os_risk_scores.get(os_family.lower(), 1.5)
    
    def _score_exposed_services(self, profile: DeviceProfile) -> float:
        """Score based on exposed services"""
        if not profile.services:
            return 0.0
        
        # Services that should typically not be exposed
        risky_services = {
            'telnet': 2.0,
            'ftp': 1.0,
            'rsh': 2.0,
            'rlogin': 2.0,
            'vnc': 1.5,
            'rdp': 1.0,
            'mysql': 1.5,
            'postgresql': 1.5,
            'mssql': 1.5,
            'oracle': 1.5
        }
        
        risk_score = 0
        for service_info in profile.services.values():
            service_name = service_info.get('name', '').lower()
            risk_score += risky_services.get(service_name, 0)
        
        return min(risk_score, 5.0)
    
    def add_tags(self, profile: DeviceProfile, tags: List[str]):
        """Add tags to device profile"""
        profile.tags.update(tags)
    
    def update_profile(self, profile_id: str, new_data: Dict):
        """Update existing device profile"""
        if profile_id in self.profiles:
            profile = self.profiles[profile_id]
            profile.last_seen = time.time()
            
            # Update fields if provided
            for field, value in new_data.items():
                if hasattr(profile, field):
                    setattr(profile, field, value)
    
    def get_profile_by_ip(self, ip_address: str) -> Optional[DeviceProfile]:
        """Get device profile by IP address"""
        for profile in self.profiles.values():
            if profile.ip_address == ip_address:
                return profile
        return None
    
    def get_profiles_by_type(self, device_type: str) -> List[DeviceProfile]:
        """Get all profiles of a specific device type"""
        return [p for p in self.profiles.values() if p.device_type == device_type]
    
    def get_high_risk_profiles(self, risk_threshold: float = 7.0) -> List[DeviceProfile]:
        """Get profiles with risk score above threshold"""
        return [p for p in self.profiles.values() if p.risk_score >= risk_threshold]
    
    def _generate_profile_id(self, profile: DeviceProfile) -> str:
        """Generate unique profile ID"""
        identifier = f"{profile.ip_address}_{profile.mac_address or 'nomac'}_{profile.hostname or 'nohost'}"
        return hashlib.md5(identifier.encode()).hexdigest()[:16]
    
    def export_profile(self, profile: DeviceProfile) -> Dict:
        """Export profile to dictionary format"""
        export_data = asdict(profile)
        export_data['tags'] = list(profile.tags)  # Convert set to list for JSON serialization
        return export_data
    
    def import_profile(self, profile_data: Dict) -> DeviceProfile:
        """Import profile from dictionary format"""
        # Convert tags back to set
        if 'tags' in profile_data:
            profile_data['tags'] = set(profile_data['tags'])
        
        profile = DeviceProfile(**profile_data)
        profile_id = self._generate_profile_id(profile)
        self.profiles[profile_id] = profile
        
        return profile
    
    def get_profile_summary_table(self, profile: DeviceProfile) -> Table:
        """Generate summary table for device profile"""
        table = Table(title=f"Device Profile: {profile.ip_address}")
        table.add_column("Attribute", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("IP Address", profile.ip_address)
        table.add_row("MAC Address", profile.mac_address or "Unknown")
        table.add_row("Hostname", profile.hostname or "Unknown")
        table.add_row("OS Family", profile.os_family or "Unknown")
        table.add_row("OS Version", profile.os_version or "Unknown")
        table.add_row("Device Type", profile.device_type or "Unknown")
        table.add_row("Vendor", profile.vendor or "Unknown")
        table.add_row("Open Ports", f"{len(profile.open_ports)} ports")
        table.add_row("Services", f"{len(profile.services)} services")
        table.add_row("Risk Score", f"{profile.risk_score:.1f}/10.0")
        table.add_row("Confidence", f"{profile.confidence:.1f}/1.0")
        table.add_row("First Seen", time.ctime(profile.first_seen))
        table.add_row("Last Seen", time.ctime(profile.last_seen))
        
        if profile.tags:
            table.add_row("Tags", ", ".join(profile.tags))
        
        return table
