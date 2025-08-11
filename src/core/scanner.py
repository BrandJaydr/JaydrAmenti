"""
Nmap Scanner Integration
Handles all nmap scanning operations with advanced parsing and categorization
"""

import subprocess
import json
import xml.etree.ElementTree as ET
import re
import time
from typing import Dict, List, Optional, Tuple
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.table import Table

class NmapScanner:
    def __init__(self):
        self.console = Console()
        self.scan_history = []
        
        # Nmap command templates based on the cheat sheet
        self.scan_types = {
            # Basic Scanning
            'basic': {
                'single_target': 'nmap {target}',
                'multiple_targets': 'nmap {targets}',
                'target_list': 'nmap -iL {list_file}',
                'ip_range': 'nmap {range}',
                'subnet': 'nmap {subnet}',
                'random_hosts': 'nmap -iR {number}',
                'exclude_targets': 'nmap {targets} --exclude {exclude}',
                'exclude_file': 'nmap {targets} --excludefile {exclude_file}',
                'aggressive': 'nmap -A {target}',
                'ipv6': 'nmap -6 {target}'
            },
            
            # Discovery Options
            'discovery': {
                'ping_scan': 'nmap -sP {target}',
                'no_ping': 'nmap -PN {target}',
                'tcp_syn_ping': 'nmap -PS {target}',
                'tcp_ack_ping': 'nmap -PA {target}',
                'udp_ping': 'nmap -PU {target}',
                'sctp_ping': 'nmap -PY {target}',
                'icmp_echo': 'nmap -PE {target}',
                'icmp_timestamp': 'nmap -PP {target}',
                'icmp_mask': 'nmap -PM {target}',
                'ip_protocol': 'nmap -PO {target}',
                'arp_ping': 'nmap -PR {target}',
                'traceroute': 'nmap --traceroute {target}',
                'force_dns': 'nmap -R {target}',
                'no_dns': 'nmap -n {target}',
                'system_dns': 'nmap --system-dns {target}',
                'custom_dns': 'nmap --dns-servers {servers} {target}',
                'host_list': 'nmap -sL {targets}'
            },
            
            # Firewall Evasion
            'evasion': {
                'fragment': 'nmap -f {target}',
                'mtu': 'nmap --mtu {mtu} {target}',
                'decoy': 'nmap -D RND:{number} {target}',
                'zombie_scan': 'nmap -sI {zombie} {target}',
                'source_port': 'nmap --source-port {port} {target}',
                'random_data': 'nmap --data-length {size} {target}',
                'randomize_hosts': 'nmap --randomize-hosts {target}',
                'spoof_mac': 'nmap --spoof-mac {mac} {target}',
                'bad_checksums': 'nmap --badsum {target}'
            },
            
            # Version Detection
            'version': {
                'os_detection': 'nmap -O {target}',
                'os_guess': 'nmap -O --osscan-guess {target}',
                'service_version': 'nmap -sV {target}',
                'version_trace': 'nmap -sV --version-trace {target}',
                'rpc_scan': 'nmap -sR {target}'
            },
            
            # Port Scanning
            'ports': {
                'tcp_syn': 'nmap -sS {target}',
                'tcp_connect': 'nmap -sT {target}',
                'udp_scan': 'nmap -sU {target}',
                'tcp_null': 'nmap -sN {target}',
                'tcp_fin': 'nmap -sF {target}',
                'tcp_xmas': 'nmap -sX {target}',
                'tcp_ack': 'nmap -sA {target}',
                'tcp_window': 'nmap -sW {target}',
                'tcp_maimon': 'nmap -sM {target}',
                'custom_ports': 'nmap -p {ports} {target}',
                'port_range': 'nmap -p {start}-{end} {target}',
                'top_ports': 'nmap --top-ports {number} {target}',
                'fast_scan': 'nmap -F {target}'
            },
            
            # Scripting Engine
            'scripts': {
                'default_scripts': 'nmap -sC {target}',
                'custom_script': 'nmap --script {script} {target}',
                'script_category': 'nmap --script {category} {target}',
                'multiple_categories': 'nmap --script {categories} {target}',
                'script_trace': 'nmap --script {script} --script-trace {target}',
                'vuln_scripts': 'nmap --script vuln {target}',
                'auth_scripts': 'nmap --script auth {target}',
                'brute_scripts': 'nmap --script brute {target}',
                'discovery_scripts': 'nmap --script discovery {target}'
            }
        }
    
    def execute_scan(self, scan_type: str, scan_subtype: str, **kwargs) -> Dict:
        """Execute an nmap scan with specified parameters"""
        try:
            # Get command template
            if scan_type not in self.scan_types:
                raise ValueError(f"Unknown scan type: {scan_type}")
            
            if scan_subtype not in self.scan_types[scan_type]:
                raise ValueError(f"Unknown scan subtype: {scan_subtype}")
            
            command_template = self.scan_types[scan_type][scan_subtype]
            
            # Format command with provided arguments
            command = command_template.format(**kwargs)
            
            # Add XML output for parsing
            xml_output = f"/tmp/nmap_scan_{int(time.time())}.xml"
            command += f" -oX {xml_output}"
            
            # Display scan information
            scan_info = Panel(
                f"[bold]Executing:[/bold] {command}\n[bold]Type:[/bold] {scan_type}/{scan_subtype}",
                title="Nmap Scan",
                style="cyan"
            )
            self.console.print(scan_info)
            
            # Execute scan with progress indicator
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=self.console
            ) as progress:
                task = progress.add_task("Scanning...", total=None)
                
                # Run nmap command
                process = subprocess.Popen(
                    command.split(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                stdout, stderr = process.communicate()
                progress.update(task, completed=True)
            
            # Parse results
            results = {
                'command': command,
                'scan_type': scan_type,
                'scan_subtype': scan_subtype,
                'timestamp': time.time(),
                'return_code': process.returncode,
                'stdout': stdout,
                'stderr': stderr,
                'xml_output': xml_output,
                'parsed_results': None
            }
            
            if process.returncode == 0:
                # Parse XML output if available
                try:
                    parsed_data = self.parse_xml_output(xml_output)
                    results['parsed_results'] = parsed_data
                    self.console.print("[green]✓[/green] Scan completed successfully")
                except Exception as e:
                    self.console.print(f"[yellow]⚠[/yellow] Scan completed but XML parsing failed: {e}")
            else:
                self.console.print(f"[red]✗[/red] Scan failed with return code {process.returncode}")
                if stderr:
                    self.console.print(f"[red]Error:[/red] {stderr}")
            
            # Add to history
            self.scan_history.append(results)
            
            return results
            
        except Exception as e:
            error_results = {
                'error': str(e),
                'timestamp': time.time(),
                'scan_type': scan_type,
                'scan_subtype': scan_subtype
            }
            self.scan_history.append(error_results)
            self.console.print(f"[red]Error executing scan:[/red] {e}")
            return error_results
    
    def parse_xml_output(self, xml_file: str) -> Dict:
        """Parse nmap XML output into structured data"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            results = {
                'scan_info': {},
                'hosts': [],
                'scan_stats': {}
            }
            
            # Parse scan info
            scaninfo = root.find('scaninfo')
            if scaninfo is not None:
                results['scan_info'] = {
                    'type': scaninfo.get('type'),
                    'protocol': scaninfo.get('protocol'),
                    'numservices': scaninfo.get('numservices'),
                    'services': scaninfo.get('services')
                }
            
            # Parse hosts
            for host in root.findall('host'):
                host_data = self.parse_host_data(host)
                if host_data:
                    results['hosts'].append(host_data)
            
            # Parse scan statistics
            runstats = root.find('runstats')
            if runstats is not None:
                finished = runstats.find('finished')
                hosts = runstats.find('hosts')
                
                if finished is not None:
                    results['scan_stats']['elapsed'] = finished.get('elapsed')
                    results['scan_stats']['timestr'] = finished.get('timestr')
                
                if hosts is not None:
                    results['scan_stats']['up'] = hosts.get('up')
                    results['scan_stats']['down'] = hosts.get('down')
                    results['scan_stats']['total'] = hosts.get('total')
            
            return results
            
        except Exception as e:
            raise Exception(f"Failed to parse XML output: {e}")
    
    def parse_host_data(self, host_element) -> Optional[Dict]:
        """Parse individual host data from XML"""
        try:
            host_data = {
                'addresses': [],
                'hostnames': [],
                'status': {},
                'ports': [],
                'os': {},
                'uptime': {},
                'distance': {},
                'tcpsequence': {},
                'ipidsequence': {},
                'tcptssequence': {}
            }
            
            # Parse addresses
            for address in host_element.findall('address'):
                addr_data = {
                    'addr': address.get('addr'),
                    'addrtype': address.get('addrtype')
                }
                if address.get('vendor'):
                    addr_data['vendor'] = address.get('vendor')
                host_data['addresses'].append(addr_data)
            
            # Parse hostnames
            hostnames = host_element.find('hostnames')
            if hostnames is not None:
                for hostname in hostnames.findall('hostname'):
                    host_data['hostnames'].append({
                        'name': hostname.get('name'),
                        'type': hostname.get('type')
                    })
            
            # Parse status
            status = host_element.find('status')
            if status is not None:
                host_data['status'] = {
                    'state': status.get('state'),
                    'reason': status.get('reason'),
                    'reason_ttl': status.get('reason_ttl')
                }
            
            # Parse ports
            ports = host_element.find('ports')
            if ports is not None:
                for port in ports.findall('port'):
                    port_data = self.parse_port_data(port)
                    if port_data:
                        host_data['ports'].append(port_data)
            
            # Parse OS detection
            os_element = host_element.find('os')
            if os_element is not None:
                host_data['os'] = self.parse_os_data(os_element)
            
            # Parse uptime
            uptime = host_element.find('uptime')
            if uptime is not None:
                host_data['uptime'] = {
                    'seconds': uptime.get('seconds'),
                    'lastboot': uptime.get('lastboot')
                }
            
            # Parse distance
            distance = host_element.find('distance')
            if distance is not None:
                host_data['distance'] = {
                    'value': distance.get('value')
                }
            
            return host_data
            
        except Exception as e:
            self.console.print(f"[yellow]Warning:[/yellow] Failed to parse host data: {e}")
            return None
    
    def parse_port_data(self, port_element) -> Optional[Dict]:
        """Parse port information from XML"""
        try:
            port_data = {
                'portid': port_element.get('portid'),
                'protocol': port_element.get('protocol'),
                'state': {},
                'service': {},
                'scripts': []
            }
            
            # Parse state
            state = port_element.find('state')
            if state is not None:
                port_data['state'] = {
                    'state': state.get('state'),
                    'reason': state.get('reason'),
                    'reason_ttl': state.get('reason_ttl')
                }
            
            # Parse service
            service = port_element.find('service')
            if service is not None:
                service_data = {
                    'name': service.get('name'),
                    'method': service.get('method'),
                    'conf': service.get('conf')
                }
                
                # Optional service attributes
                for attr in ['product', 'version', 'extrainfo', 'ostype', 'devicetype', 'servicefp']:
                    value = service.get(attr)
                    if value:
                        service_data[attr] = value
                
                port_data['service'] = service_data
            
            # Parse scripts
            for script in port_element.findall('script'):
                script_data = {
                    'id': script.get('id'),
                    'output': script.get('output')
                }
                port_data['scripts'].append(script_data)
            
            return port_data
            
        except Exception as e:
            return None
    
    def parse_os_data(self, os_element) -> Dict:
        """Parse OS detection data from XML"""
        os_data = {
            'portused': [],
            'osmatch': [],
            'osfingerprint': []
        }
        
        # Parse port used for OS detection
        for portused in os_element.findall('portused'):
            os_data['portused'].append({
                'state': portused.get('state'),
                'proto': portused.get('proto'),
                'portid': portused.get('portid')
            })
        
        # Parse OS matches
        for osmatch in os_element.findall('osmatch'):
            match_data = {
                'name': osmatch.get('name'),
                'accuracy': osmatch.get('accuracy'),
                'line': osmatch.get('line'),
                'osclass': []
            }
            
            for osclass in osmatch.findall('osclass'):
                class_data = {
                    'type': osclass.get('type'),
                    'vendor': osclass.get('vendor'),
                    'osfamily': osclass.get('osfamily'),
                    'osgen': osclass.get('osgen'),
                    'accuracy': osclass.get('accuracy')
                }
                match_data['osclass'].append(class_data)
            
            os_data['osmatch'].append(match_data)
        
        return os_data
    
    def get_scan_summary(self, results: Dict) -> Table:
        """Generate a summary table of scan results"""
        table = Table(title="Scan Summary")
        table.add_column("Attribute", style="cyan")
        table.add_column("Value", style="white")
        
        if 'parsed_results' in results and results['parsed_results']:
            parsed = results['parsed_results']
            
            # Scan statistics
            if 'scan_stats' in parsed:
                stats = parsed['scan_stats']
                table.add_row("Hosts Up", stats.get('up', 'N/A'))
                table.add_row("Hosts Down", stats.get('down', 'N/A'))
                table.add_row("Total Hosts", stats.get('total', 'N/A'))
                table.add_row("Scan Time", stats.get('elapsed', 'N/A') + 's')
            
            # Host count and port summary
            hosts = parsed.get('hosts', [])
            table.add_row("Discovered Hosts", str(len(hosts)))
            
            total_open_ports = 0
            for host in hosts:
                for port in host.get('ports', []):
                    if port.get('state', {}).get('state') == 'open':
                        total_open_ports += 1
            
            table.add_row("Open Ports Found", str(total_open_ports))
        
        table.add_row("Scan Type", f"{results.get('scan_type', 'N/A')}/{results.get('scan_subtype', 'N/A')}")
        table.add_row("Return Code", str(results.get('return_code', 'N/A')))
        
        return table
    
    def get_available_scans(self) -> Dict[str, List[str]]:
        """Get all available scan types and subtypes"""
        return {category: list(scans.keys()) for category, scans in self.scan_types.items()}
    
    def get_scan_description(self, scan_type: str, scan_subtype: str) -> str:
        """Get human-readable description of scan type"""
        descriptions = {
            'basic': {
                'single_target': 'Scan a single IP address or hostname',
                'multiple_targets': 'Scan multiple targets separated by commas',
                'target_list': 'Scan targets from a file list',
                'ip_range': 'Scan a range of IP addresses',
                'subnet': 'Scan an entire subnet using CIDR notation',
                'random_hosts': 'Scan random hosts on the internet',
                'exclude_targets': 'Scan targets while excluding specific IPs',
                'exclude_file': 'Scan targets while excluding IPs from file',
                'aggressive': 'Aggressive scan with OS detection, version detection, script scanning, and traceroute',
                'ipv6': 'Scan IPv6 targets'
            },
            'discovery': {
                'ping_scan': 'Ping scan only (no port scan)',
                'no_ping': 'Skip ping discovery',
                'tcp_syn_ping': 'TCP SYN ping discovery',
                'tcp_ack_ping': 'TCP ACK ping discovery',
                'udp_ping': 'UDP ping discovery',
                'sctp_ping': 'SCTP INIT ping discovery',
                'icmp_echo': 'ICMP echo ping discovery',
                'icmp_timestamp': 'ICMP timestamp ping discovery',
                'icmp_mask': 'ICMP address mask ping discovery',
                'ip_protocol': 'IP protocol ping discovery',
                'arp_ping': 'ARP ping discovery',
                'traceroute': 'Enable traceroute',
                'force_dns': 'Force reverse DNS resolution',
                'no_dns': 'Disable reverse DNS resolution',
                'system_dns': 'Use system DNS resolver',
                'custom_dns': 'Use custom DNS servers',
                'host_list': 'List scan targets without scanning'
            },
            'evasion': {
                'fragment': 'Fragment packets to evade firewalls',
                'mtu': 'Use custom MTU for packet fragmentation',
                'decoy': 'Use decoy IPs to mask scan source',
                'zombie_scan': 'Idle zombie scan technique',
                'source_port': 'Specify source port for scan',
                'random_data': 'Append random data to packets',
                'randomize_hosts': 'Randomize target scan order',
                'spoof_mac': 'Spoof MAC address',
                'bad_checksums': 'Send packets with bad checksums'
            },
            'version': {
                'os_detection': 'Operating system detection',
                'os_guess': 'Aggressive OS detection with guessing',
                'service_version': 'Service version detection',
                'version_trace': 'Version detection with trace output',
                'rpc_scan': 'RPC service scan'
            },
            'ports': {
                'tcp_syn': 'TCP SYN stealth scan',
                'tcp_connect': 'TCP connect scan',
                'udp_scan': 'UDP port scan',
                'tcp_null': 'TCP NULL scan',
                'tcp_fin': 'TCP FIN scan',
                'tcp_xmas': 'TCP Xmas scan',
                'tcp_ack': 'TCP ACK scan',
                'tcp_window': 'TCP Window scan',
                'tcp_maimon': 'TCP Maimon scan',
                'custom_ports': 'Scan specific ports',
                'port_range': 'Scan port range',
                'top_ports': 'Scan most common ports',
                'fast_scan': 'Fast scan of common ports'
            },
            'scripts': {
                'default_scripts': 'Run default NSE scripts',
                'custom_script': 'Run specific NSE script',
                'script_category': 'Run scripts from category',
                'multiple_categories': 'Run scripts from multiple categories',
                'script_trace': 'Run script with trace output',
                'vuln_scripts': 'Run vulnerability detection scripts',
                'auth_scripts': 'Run authentication scripts',
                'brute_scripts': 'Run brute force scripts',
                'discovery_scripts': 'Run discovery scripts'
            }
        }
        
        return descriptions.get(scan_type, {}).get(scan_subtype, 'No description available')
