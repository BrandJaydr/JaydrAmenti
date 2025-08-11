"""
Netcat Operations Manager
Handles netcat operations for network probing and data transfer testing
"""

import subprocess
import threading
import time
import socket
from typing import Dict, List, Optional, Tuple
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

class NetcatManager:
    def __init__(self):
        self.console = Console()
        self.active_connections = []
        self.listeners = []
        
        # Common netcat operations
        self.operations = {
            'scanning': {
                'port_scan': 'nc -zv {host} {port}',
                'port_range': 'nc -zv {host} {start_port}-{end_port}',
                'udp_scan': 'nc -zuv {host} {port}',
                'timeout_scan': 'nc -zv -w{timeout} {host} {port}'
            },
            
            'listening': {
                'tcp_listen': 'nc -lvp {port}',
                'udp_listen': 'nc -luvp {port}',
                'exec_listen': 'nc -lvp {port} -e /bin/bash',
                'file_receive': 'nc -lvp {port} > {filename}'
            },
            
            'connecting': {
                'tcp_connect': 'nc {host} {port}',
                'udp_connect': 'nc -u {host} {port}',
                'file_send': 'nc {host} {port} < {filename}',
                'banner_grab': 'echo "" | nc -v -n -w1 {host} {port}'
            },
            
            'tunneling': {
                'relay': 'nc -l -p {local_port} -c "nc {remote_host} {remote_port}"',
                'backpipe': 'nc -l -p {port} 0<backpipe | nc {target_host} {target_port} | tee backpipe'
            },
            
            'testing': {
                'http_test': 'echo -e "GET / HTTP/1.0\\r\\n\\r\\n" | nc {host} {port}',
                'smtp_test': 'nc {host} 25',
                'pop3_test': 'nc {host} 110',
                'ssh_test': 'nc {host} 22'
            }
        }
    
    def execute_operation(self, operation_type: str, operation_name: str, **kwargs) -> Dict:
        """Execute a netcat operation"""
        try:
            if operation_type not in self.operations:
                raise ValueError(f"Unknown operation type: {operation_type}")
            
            if operation_name not in self.operations[operation_type]:
                raise ValueError(f"Unknown operation: {operation_name}")
            
            command_template = self.operations[operation_type][operation_name]
            command = command_template.format(**kwargs)
            
            # Display operation info
            op_info = Panel(
                f"[bold]Executing:[/bold] {command}\n[bold]Type:[/bold] {operation_type}/{operation_name}",
                title="Netcat Operation",
                style="magenta"
            )
            self.console.print(op_info)
            
            # Execute command
            start_time = time.time()
            
            if operation_type == 'listening':
                return self._execute_listener(command, **kwargs)
            else:
                return self._execute_command(command, **kwargs)
            
        except Exception as e:
            error_result = {
                'error': str(e),
                'timestamp': time.time(),
                'operation_type': operation_type,
                'operation_name': operation_name
            }
            self.console.print(f"[red]Error executing operation:[/red] {e}")
            return error_result
    
    def _execute_command(self, command: str, timeout: int = 30, **kwargs) -> Dict:
        """Execute a standard netcat command"""
        try:
            process = subprocess.Popen(
                command.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(timeout=timeout)
            
            result = {
                'command': command,
                'timestamp': time.time(),
                'return_code': process.returncode,
                'stdout': stdout,
                'stderr': stderr,
                'success': process.returncode == 0
            }
            
            if result['success']:
                self.console.print("[green]✓[/green] Operation completed successfully")
            else:
                self.console.print(f"[red]✗[/red] Operation failed with return code {process.returncode}")
                if stderr:
                    self.console.print(f"[red]Error:[/red] {stderr}")
            
            return result
            
        except subprocess.TimeoutExpired:
            process.kill()
            return {
                'command': command,
                'timestamp': time.time(),
                'error': 'Operation timed out',
                'timeout': timeout
            }
        except Exception as e:
            return {
                'command': command,
                'timestamp': time.time(),
                'error': str(e)
            }
    
    def _execute_listener(self, command: str, **kwargs) -> Dict:
        """Execute a netcat listener in background"""
        try:
            listener_info = {
                'command': command,
                'timestamp': time.time(),
                'port': kwargs.get('port'),
                'status': 'starting'
            }
            
            # Start listener in background thread
            def start_listener():
                try:
                    process = subprocess.Popen(
                        command.split(),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    
                    listener_info['process'] = process
                    listener_info['status'] = 'listening'
                    self.console.print(f"[green]✓[/green] Listener started on port {kwargs.get('port')}")
                    
                    # Wait for connection or termination
                    stdout, stderr = process.communicate()
                    
                    listener_info['stdout'] = stdout
                    listener_info['stderr'] = stderr
                    listener_info['return_code'] = process.returncode
                    listener_info['status'] = 'terminated'
                    
                except Exception as e:
                    listener_info['error'] = str(e)
                    listener_info['status'] = 'error'
            
            thread = threading.Thread(target=start_listener)
            thread.daemon = True
            thread.start()
            
            listener_info['thread'] = thread
            self.listeners.append(listener_info)
            
            return listener_info
            
        except Exception as e:
            return {
                'command': command,
                'timestamp': time.time(),
                'error': str(e),
                'status': 'failed'
            }
    
    def port_scan(self, host: str, ports: List[int], timeout: int = 5) -> Dict:
        """Perform port scan using netcat"""
        results = {
            'host': host,
            'timestamp': time.time(),
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': [],
            'scan_results': []
        }
        
        self.console.print(f"[cyan]Scanning {len(ports)} ports on {host}...[/cyan]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("Port scanning...", total=len(ports))
            
            for port in ports:
                try:
                    # Use socket for faster scanning
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    
                    result = sock.connect_ex((host, port))
                    sock.close()
                    
                    port_result = {
                        'port': port,
                        'status': 'open' if result == 0 else 'closed',
                        'timestamp': time.time()
                    }
                    
                    if result == 0:
                        results['open_ports'].append(port)
                        # Try banner grabbing for open ports
                        banner = self.grab_banner(host, port, timeout=2)
                        if banner:
                            port_result['banner'] = banner
                    else:
                        results['closed_ports'].append(port)
                    
                    results['scan_results'].append(port_result)
                    
                except Exception as e:
                    port_result = {
                        'port': port,
                        'status': 'filtered',
                        'error': str(e),
                        'timestamp': time.time()
                    }
                    results['filtered_ports'].append(port)
                    results['scan_results'].append(port_result)
                
                progress.advance(task)
        
        self.console.print(f"[green]✓[/green] Scan complete: {len(results['open_ports'])} open, {len(results['closed_ports'])} closed, {len(results['filtered_ports'])} filtered")
        
        return results
    
    def grab_banner(self, host: str, port: int, timeout: int = 5) -> Optional[str]:
        """Grab service banner from a host:port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Send appropriate probe based on common ports
            probe = self._get_probe_for_port(port)
            if probe:
                sock.send(probe.encode())
            
            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner if banner else None
            
        except Exception:
            return None
    
    def _get_probe_for_port(self, port: int) -> Optional[str]:
        """Get appropriate probe string for common ports"""
        probes = {
            21: "",  # FTP
            22: "",  # SSH
            23: "",  # Telnet
            25: "HELO test\r\n",  # SMTP
            53: "",  # DNS
            80: "GET / HTTP/1.0\r\n\r\n",  # HTTP
            110: "",  # POP3
            143: "",  # IMAP
            443: "",  # HTTPS
            993: "",  # IMAPS
            995: ""   # POP3S
        }
        
        return probes.get(port, "")
    
    def test_connectivity(self, host: str, port: int, protocol: str = 'tcp') -> Dict:
        """Test connectivity to a specific host and port"""
        result = {
            'host': host,
            'port': port,
            'protocol': protocol,
            'timestamp': time.time(),
            'connected': False,
            'response_time': None,
            'banner': None,
            'error': None
        }
        
        try:
            start_time = time.time()
            
            if protocol.lower() == 'tcp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            sock.settimeout(10)
            
            if protocol.lower() == 'tcp':
                sock.connect((host, port))
                result['connected'] = True
                result['response_time'] = time.time() - start_time
                
                # Try to grab banner
                try:
                    probe = self._get_probe_for_port(port)
                    if probe:
                        sock.send(probe.encode())
                    
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        result['banner'] = banner
                except:
                    pass
            else:
                # UDP connectivity test
                sock.sendto(b'test', (host, port))
                sock.recvfrom(1024)
                result['connected'] = True
                result['response_time'] = time.time() - start_time
            
            sock.close()
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def create_tunnel(self, local_port: int, remote_host: str, remote_port: int) -> Dict:
        """Create a netcat tunnel"""
        command = f"nc -l -p {local_port} -c \"nc {remote_host} {remote_port}\""
        
        tunnel_info = {
            'command': command,
            'local_port': local_port,
            'remote_host': remote_host,
            'remote_port': remote_port,
            'timestamp': time.time(),
            'status': 'starting'
        }
        
        try:
            def start_tunnel():
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                tunnel_info['process'] = process
                tunnel_info['status'] = 'active'
                
                # Wait for process to complete
                stdout, stderr = process.communicate()
                tunnel_info['stdout'] = stdout.decode()
                tunnel_info['stderr'] = stderr.decode()
                tunnel_info['status'] = 'terminated'
            
            thread = threading.Thread(target=start_tunnel)
            thread.daemon = True
            thread.start()
            
            tunnel_info['thread'] = thread
            self.active_connections.append(tunnel_info)
            
            return tunnel_info
            
        except Exception as e:
            tunnel_info['error'] = str(e)
            tunnel_info['status'] = 'failed'
            return tunnel_info
    
    def get_active_listeners(self) -> List[Dict]:
        """Get list of active netcat listeners"""
        active = []
        for listener in self.listeners:
            if listener.get('status') == 'listening':
                active.append(listener)
        return active
    
    def stop_listener(self, port: int) -> bool:
        """Stop a netcat listener on specified port"""
        for listener in self.listeners:
            if listener.get('port') == port and listener.get('status') == 'listening':
                try:
                    if 'process' in listener:
                        listener['process'].terminate()
                        listener['status'] = 'stopped'
                        return True
                except:
                    pass
        return False
    
    def get_operation_summary(self, result: Dict) -> Table:
        """Generate summary table for netcat operation"""
        table = Table(title="Netcat Operation Summary")
        table.add_column("Attribute", style="cyan")
        table.add_column("Value", style="white")
        
        if 'command' in result:
            table.add_row("Command", result['command'])
        
        if 'operation_type' in result:
            table.add_row("Operation Type", result['operation_type'])
        
        if 'timestamp' in result:
            table.add_row("Timestamp", time.ctime(result['timestamp']))
        
        if 'success' in result:
            status = "✓ Success" if result['success'] else "✗ Failed"
            table.add_row("Status", status)
        
        if 'return_code' in result:
            table.add_row("Return Code", str(result['return_code']))
        
        if 'error' in result:
            table.add_row("Error", result['error'])
        
        if 'host' in result and 'port' in result:
            table.add_row("Target", f"{result['host']}:{result['port']}")
        
        if 'open_ports' in result:
            table.add_row("Open Ports", str(len(result['open_ports'])))
            if result['open_ports']:
                table.add_row("Open Port List", ', '.join(map(str, result['open_ports'])))
        
        return table
    
    def get_available_operations(self) -> Dict[str, List[str]]:
        """Get all available netcat operations"""
        return {category: list(ops.keys()) for category, ops in self.operations.items()}
