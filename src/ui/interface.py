"""
Cyber Amenti User Interface
Advanced cyberpunk-themed CLI interface for red team operations
"""

import os
import time
import json
import shutil
import threading
import keyboard
from typing import Dict, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.layout import Layout
from rich.text import Text
from rich.align import Align
from rich.columns import Columns
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.tree import Tree
from rich.markdown import Markdown

class CyberAmentiInterface:
    def __init__(self, config_manager=None):
        self.console = Console()
        self.terminal_width = self.get_terminal_width()
        self.terminal_height = self.get_terminal_height()
        self.config = config_manager
        self._setup_hotkeys()
    
    def _setup_hotkeys(self):
        if self.config:
            hotkey = self.config.get('hotkey_terminate', 'ctrl+c')
            try:
                keyboard.add_hotkey(hotkey, self._terminate_operation)
            except:
                pass

    def _terminate_operation(self):
        self.console.print("\n[bold red]!!! HOTKEY TERMINATION TRIGGERED !!![/bold red]")
        os._exit(1)
    
    def display_split_screen(self, left_content, right_content, left_title="Left", right_title="Right"):
        layout = Layout()
        layout.split_row(
            Layout(Panel(left_content, title=left_title), name="left"),
            Layout(Panel(right_content, title=right_title), name="right")
        )
        self.console.print(layout)

    def show_sherlock_menu(self, theme_manager, translator):
        theme = theme_manager.current_theme
        self.clear_screen()
        self.console.print(Panel("Sherlock Intelligence Integration", style=theme['primary']))
        username = Prompt.ask(f"[{theme['accent']}]Enter username to search[/]")
        
        self.console.print(f"[{theme['info']}]Searching for {username} across platforms...[/]")
        # Simplified call to sherlock
        try:
            import subprocess
            cmd = [sys.executable, "src/core/sherlock/sherlock", username]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            self.console.print(stdout)
        except Exception as e:
            self.console.print(f"[red]Sherlock failed: {e}[/red]")
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")

    def get_terminal_width(self) -> int:
        """Get terminal width for responsive design"""
        try:
            return shutil.get_terminal_size().columns
        except:
            return 80  # Fallback width
    
    def get_terminal_height(self) -> int:
        """Get terminal height for responsive design"""
        try:
            return shutil.get_terminal_size().lines
        except:
            return 24  # Fallback height
    
    def update_terminal_size(self):
        """Update terminal dimensions (call when screen might have resized)"""
        self.terminal_width = self.get_terminal_width()
        self.terminal_height = self.get_terminal_height()
    
    def get_responsive_table_width(self, columns: int) -> Optional[int]:
        """Calculate responsive table width based on terminal size"""
        if self.terminal_width < 80:  # Mobile/small terminal
            return None  # Let Rich handle auto-sizing
        elif self.terminal_width < 120:  # Medium terminal
            return max(10, (self.terminal_width - 10) // columns)
        else:  # Large terminal
            return max(15, (self.terminal_width - 20) // columns)
    
    def truncate_text(self, text: str, max_length: int) -> str:
        """Truncate text for responsive display"""
        if not text:
            return "N/A"
        if len(text) <= max_length:
            return text
        return text[:max_length-3] + "..."
    
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
        # Update terminal size after clearing
        self.update_terminal_size()
    
    def show_scan_menu(self, scanner, profiler, exploits, db, theme_manager, translator):
        """Display network scanning operations menu"""
        while True:
            self.clear_screen()
            theme = theme_manager.current_theme
            
            # Create scan menu
            menu_title = translator.get("scan_operations")
            scan_panel = Panel(
                self._create_scan_options_table(scanner, translator, theme),
                title=f"[bold]{menu_title}[/bold]",
                style=theme['primary'],
                border_style=theme['accent']
            )
            
            self.console.print(scan_panel)
            
            choice = Prompt.ask(
                f"\n[{theme['accent']}]►[/] {translator.get('select_scan_type')}",
                choices=["1", "2", "3", "4", "5", "6", "7", "0"],
                show_choices=False
            )
            
            if choice == "1":
                self._handle_basic_scan(scanner, profiler, exploits, db, theme_manager, translator)
            elif choice == "2":
                self._handle_discovery_scan(scanner, theme_manager, translator)
            elif choice == "3":
                self._handle_port_scan(scanner, theme_manager, translator)
            elif choice == "4":
                self._handle_version_scan(scanner, theme_manager, translator)
            elif choice == "5":
                self._handle_evasion_scan(scanner, theme_manager, translator)
            elif choice == "6":
                self._handle_script_scan(scanner, theme_manager, translator)
            elif choice == "7":
                self._show_scan_history(scanner, theme_manager, translator)
            elif choice == "0":
                break
    
    def _create_scan_options_table(self, scanner, translator, theme):
        """Create responsive scan options table"""
        table = Table(show_header=False, style=theme['text'])
        
        # Responsive column widths
        option_width = 8 if self.terminal_width < 100 else 10
        desc_width = self.get_responsive_table_width(3)
        
        table.add_column("Option", style=theme['accent'], width=option_width)
        table.add_column("Description", style=theme['text'], width=desc_width)
        
        # Only add details column on larger screens
        if self.terminal_width >= 100:
            table.add_column("Details", style=theme['secondary'], width=desc_width)
        
        options = [
            ("1", translator.get("basic_scans"), translator.get("basic_scans_desc")),
            ("2", translator.get("discovery_scans"), translator.get("discovery_scans_desc")),
            ("3", translator.get("port_scans"), translator.get("port_scans_desc")),
            ("4", translator.get("version_scans"), translator.get("version_scans_desc")),
            ("5", translator.get("evasion_scans"), translator.get("evasion_scans_desc")),
            ("6", translator.get("script_scans"), translator.get("script_scans_desc")),
            ("7", translator.get("scan_history"), translator.get("scan_history_desc")),
            ("0", translator.get("back_to_main"), "")
        ]
        
        max_desc_length = max(30, (self.terminal_width - 20) // 2) if self.terminal_width > 80 else 25
        
        for option, desc, details in options:
            truncated_desc = self.truncate_text(desc, max_desc_length)
            if self.terminal_width >= 100 and details:
                truncated_details = self.truncate_text(details, max_desc_length)
                table.add_row(f"[{option}]", truncated_desc, truncated_details)
            else:
                table.add_row(f"[{option}]", truncated_desc)
        
        return table
    
    def _handle_basic_scan(self, scanner, profiler, exploits, db, theme_manager, translator):
        """Handle basic scan operations"""
        theme = theme_manager.current_theme
        
        # Get target from user
        target = Prompt.ask(f"[{theme['accent']}]Target (IP/hostname/range)[/]")
        
        # Get scan type
        scan_types = {
            "1": ("single_target", "Single target scan"),
            "2": ("aggressive", "Aggressive scan (-A)"),
            "3": ("subnet", "Subnet scan"),
            "4": ("ip_range", "IP range scan")
        }
        
        self.console.print("\n[bold]Available scan types:[/bold]")
        for key, (_, desc) in scan_types.items():
            self.console.print(f"  [{theme['accent']}]{key}[/] - {desc}")
        
        scan_choice = Prompt.ask(
            f"\n[{theme['accent']}]Select scan type[/]",
            choices=list(scan_types.keys())
        )
        
        scan_type, _ = scan_types[scan_choice]
        
        # Execute scan
        self.console.print(f"\n[{theme['primary']}]Initiating scan...[/]")
        
        try:
            results = scanner.execute_scan('basic', scan_type, target=target)
            
            # Display results
            if results.get('parsed_results'):
                # Create device profile
                try:
                    profile = profiler.create_profile(results)
                    
                    # Get vulnerabilities
                    vulns = exploits.correlate_scan_results(results)
                    
                    # Calculate risk score
                    if profile.ip_address in vulns:
                        profiler.calculate_risk_score(profile, vulns[profile.ip_address])
                    
                    # Save to database
                    db.save_scan_result(results)
                    db.save_device_profile(profile)
                    
                    # Display profile
                    self.console.print("\n" + "="*80)
                    self.console.print(profiler.get_profile_summary_table(profile))
                    
                    # Display vulnerabilities if found
                    if vulns and vulns.get(profile.ip_address):
                        self.console.print("\n" + "="*80)
                        vuln_table = exploits.generate_vulnerability_report({profile.ip_address: vulns[profile.ip_address]})
                        self.console.print(vuln_table)
                    
                except Exception as e:
                    self.console.print(f"[red]Error creating profile:[/red] {e}")
            
            # Display scan summary
            summary_table = scanner.get_scan_summary(results)
            self.console.print("\n" + "="*80)
            self.console.print(summary_table)
            
        except Exception as e:
            self.console.print(f"[red]Scan failed:[/red] {e}")
        
        # Wait for user input
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _handle_discovery_scan(self, scanner, theme_manager, translator):
        """Handle discovery scan operations"""
        theme = theme_manager.current_theme
        
        # Discovery scan submenu
        discovery_types = scanner.get_available_scans()['discovery']
        
        self.console.print(f"\n[bold {theme['primary']}]Discovery Scan Types:[/bold {theme['primary']}]")
        for i, scan_type in enumerate(discovery_types, 1):
            desc = scanner.get_scan_description('discovery', scan_type)
            self.console.print(f"  [{theme['accent']}]{i:2d}[/] - {scan_type}: {desc}")
        
        choice = IntPrompt.ask(
            f"\n[{theme['accent']}]Select discovery scan[/]",
            default=1
        )
        
        if 1 <= choice <= len(discovery_types):
            scan_subtype = discovery_types[choice - 1]
            target = Prompt.ask(f"[{theme['accent']}]Target[/]")
            
            # Execute discovery scan
            results = scanner.execute_scan('discovery', scan_subtype, target=target)
            
            # Display results
            summary_table = scanner.get_scan_summary(results)
            self.console.print(summary_table)
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _handle_port_scan(self, scanner, theme_manager, translator):
        """Handle port scanning operations"""
        theme = theme_manager.current_theme
        
        target = Prompt.ask(f"[{theme['accent']}]Target[/]")
        
        # Port scan options
        port_options = {
            "1": ("tcp_syn", "TCP SYN scan"),
            "2": ("tcp_connect", "TCP Connect scan"),
            "3": ("udp_scan", "UDP scan"),
            "4": ("custom_ports", "Custom port range"),
            "5": ("top_ports", "Top ports scan"),
            "6": ("fast_scan", "Fast scan")
        }
        
        self.console.print(f"\n[bold {theme['primary']}]Port Scan Types:[/bold {theme['primary']}]")
        for key, (_, desc) in port_options.items():
            self.console.print(f"  [{theme['accent']}]{key}[/] - {desc}")
        
        choice = Prompt.ask(
            f"\n[{theme['accent']}]Select port scan type[/]",
            choices=list(port_options.keys())
        )
        
        scan_subtype, _ = port_options[choice]
        
        # Get additional parameters
        kwargs = {'target': target}
        
        if scan_subtype == 'custom_ports':
            ports = Prompt.ask(f"[{theme['accent']}]Port range (e.g., 1-1000, 80,443,8080)[/]")
            kwargs['ports'] = ports
        elif scan_subtype == 'top_ports':
            num_ports = IntPrompt.ask(f"[{theme['accent']}]Number of top ports[/]", default=1000)
            kwargs['number'] = str(num_ports)
        
        # Execute scan
        results = scanner.execute_scan('ports', scan_subtype, **kwargs)
        
        # Display results
        summary_table = scanner.get_scan_summary(results)
        self.console.print(summary_table)
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _handle_version_scan(self, scanner, theme_manager, translator):
        """Handle version detection scans"""
        theme = theme_manager.current_theme
        
        target = Prompt.ask(f"[{theme['accent']}]Target[/]")
        
        version_options = {
            "1": ("os_detection", "OS Detection"),
            "2": ("service_version", "Service Version Detection"),
            "3": ("os_guess", "Aggressive OS Detection"),
            "4": ("version_trace", "Version Detection with Trace")
        }
        
        self.console.print(f"\n[bold {theme['primary']}]Version Detection Types:[/bold {theme['primary']}]")
        for key, (_, desc) in version_options.items():
            self.console.print(f"  [{theme['accent']}]{key}[/] - {desc}")
        
        choice = Prompt.ask(
            f"\n[{theme['accent']}]Select version scan[/]",
            choices=list(version_options.keys())
        )
        
        scan_subtype, _ = version_options[choice]
        
        # Execute scan
        results = scanner.execute_scan('version', scan_subtype, target=target)
        
        # Display detailed results for version scans
        if results.get('parsed_results'):
            hosts = results['parsed_results'].get('hosts', [])
            for host in hosts:
                self._display_host_details(host, theme)
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _handle_evasion_scan(self, scanner, theme_manager, translator):
        """Handle firewall evasion scans"""
        theme = theme_manager.current_theme
        
        target = Prompt.ask(f"[{theme['accent']}]Target[/]")
        
        evasion_options = {
            "1": ("fragment", "Fragment packets"),
            "2": ("decoy", "Decoy scan"),
            "3": ("source_port", "Custom source port"),
            "4": ("spoof_mac", "MAC address spoofing"),
            "5": ("randomize_hosts", "Randomize host order")
        }
        
        self.console.print(f"\n[bold {theme['primary']}]Evasion Techniques:[/bold {theme['primary']}]")
        for key, (_, desc) in evasion_options.items():
            self.console.print(f"  [{theme['accent']}]{key}[/] - {desc}")
        
        choice = Prompt.ask(
            f"\n[{theme['accent']}]Select evasion technique[/]",
            choices=list(evasion_options.keys())
        )
        
        scan_subtype, _ = evasion_options[choice]
        
        # Get additional parameters for specific evasion techniques
        kwargs = {'target': target}
        
        if scan_subtype == 'decoy':
            num_decoys = IntPrompt.ask(f"[{theme['accent']}]Number of decoy IPs[/]", default=5)
            kwargs['number'] = str(num_decoys)
        elif scan_subtype == 'source_port':
            port = IntPrompt.ask(f"[{theme['accent']}]Source port[/]", default=53)
            kwargs['port'] = str(port)
        elif scan_subtype == 'spoof_mac':
            mac = Prompt.ask(f"[{theme['accent']}]MAC address (or 0 for random)[/]", default="0")
            kwargs['mac'] = mac
        
        # Execute scan
        results = scanner.execute_scan('evasion', scan_subtype, **kwargs)
        
        # Display results
        summary_table = scanner.get_scan_summary(results)
        self.console.print(summary_table)
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _handle_script_scan(self, scanner, theme_manager, translator):
        """Handle NSE script scans"""
        theme = theme_manager.current_theme
        
        target = Prompt.ask(f"[{theme['accent']}]Target[/]")
        
        script_options = {
            "1": ("default_scripts", "Default scripts"),
            "2": ("vuln_scripts", "Vulnerability scripts"),
            "3": ("auth_scripts", "Authentication scripts"),
            "4": ("brute_scripts", "Brute force scripts"),
            "5": ("discovery_scripts", "Discovery scripts"),
            "6": ("custom_script", "Custom script")
        }
        
        self.console.print(f"\n[bold {theme['primary']}]NSE Script Categories:[/bold {theme['primary']}]")
        for key, (_, desc) in script_options.items():
            self.console.print(f"  [{theme['accent']}]{key}[/] - {desc}")
        
        choice = Prompt.ask(
            f"\n[{theme['accent']}]Select script category[/]",
            choices=list(script_options.keys())
        )
        
        scan_subtype, _ = script_options[choice]
        
        kwargs = {'target': target}
        
        if scan_subtype == 'custom_script':
            script_name = Prompt.ask(f"[{theme['accent']}]Script name[/]")
            kwargs['script'] = script_name
        
        # Execute scan
        results = scanner.execute_scan('scripts', scan_subtype, **kwargs)
        
        # Display script results
        if results.get('parsed_results'):
            self._display_script_results(results, theme)
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _show_scan_history(self, scanner, theme_manager, translator):
        """Show scan history"""
        theme = theme_manager.current_theme
        
        if not scanner.scan_history:
            self.console.print(f"[{theme['secondary']}]No scan history available[/]")
            Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
            return
        
        # Create history table
        history_table = Table(title="Scan History")
        history_table.add_column("Index", style=theme['accent'])
        history_table.add_column("Timestamp", style=theme['text'])
        history_table.add_column("Type", style=theme['primary'])
        history_table.add_column("Status", style=theme['text'])
        
        for i, scan in enumerate(scanner.scan_history[-20:], 1):  # Show last 20 scans
            timestamp = time.ctime(scan.get('timestamp', 0))
            scan_type = f"{scan.get('scan_type', 'N/A')}/{scan.get('scan_subtype', 'N/A')}"
            status = "✓ Success" if scan.get('return_code') == 0 else "✗ Failed"
            
            history_table.add_row(str(i), timestamp, scan_type, status)
        
        self.console.print(history_table)
        
        # Option to view details
        if Confirm.ask(f"\n[{theme['accent']}]View details of a specific scan?[/]"):
            index = IntPrompt.ask(f"[{theme['accent']}]Enter scan index[/]")
            if 1 <= index <= len(scanner.scan_history):
                scan = scanner.scan_history[index - 1]
                self._display_scan_details(scan, theme)
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _display_host_details(self, host_data, theme):
        """Display detailed host information with responsive design"""
        # Extract host IP
        ip = "Unknown"
        addresses = host_data.get('addresses', [])
        for addr in addresses:
            if addr.get('addrtype') == 'ipv4':
                ip = addr.get('addr')
                break
        
        # Create responsive host details table
        col_width = self.get_responsive_table_width(4)
        max_text_length = max(15, (self.terminal_width - 30) // 4) if self.terminal_width > 80 else 12
        
        host_table = Table(title=f"Host Details: {ip}")
        host_table.add_column("Port", style=theme['accent'], width=col_width)
        host_table.add_column("State", style=theme['text'], width=col_width)
        host_table.add_column("Service", style=theme['primary'], width=col_width)
        host_table.add_column("Version", style=theme['text'], width=col_width)
        
        ports = host_data.get('ports', [])
        for port_data in ports:
            port_num = port_data.get('portid', 'N/A')
            state = port_data.get('state', {}).get('state', 'N/A')
            service_info = port_data.get('service', {})
            service_name = self.truncate_text(service_info.get('name', 'N/A'), max_text_length)
            version = self.truncate_text(service_info.get('version', 'N/A'), max_text_length)
            
            # Color code the state
            if state == 'open':
                state = f"[green]{state}[/green]"
            elif state == 'closed':
                state = f"[red]{state}[/red]"
            elif state == 'filtered':
                state = f"[yellow]{state}[/yellow]"
            
            host_table.add_row(port_num, state, service_name, version)
        
        self.console.print(host_table)
    
    def _display_script_results(self, results, theme):
        """Display NSE script results"""
        if not results.get('parsed_results'):
            return
        
        hosts = results['parsed_results'].get('hosts', [])
        for host_data in hosts:
            ports = host_data.get('ports', [])
            for port_data in ports:
                scripts = port_data.get('scripts', [])
                if scripts:
                    port_num = port_data.get('portid', 'N/A')
                    
                    script_panel = Panel(
                        self._format_script_output(scripts),
                        title=f"Scripts for Port {port_num}",
                        style=theme['primary'],
                        border_style=theme['accent']
                    )
                    self.console.print(script_panel)
    
    def _format_script_output(self, scripts):
        """Format NSE script output"""
        output_lines = []
        for script in scripts:
            script_id = script.get('id', 'Unknown')
            script_output = script.get('output', 'No output')
            
            output_lines.append(f"[bold cyan]{script_id}:[/bold cyan]")
            output_lines.append(script_output)
            output_lines.append("")
        
        return "\n".join(output_lines)
    
    def _display_scan_details(self, scan, theme):
        """Display detailed scan information"""
        details_table = Table(title="Scan Details")
        details_table.add_column("Attribute", style=theme['accent'])
        details_table.add_column("Value", style=theme['text'])
        
        details_table.add_row("Command", scan.get('command', 'N/A'))
        details_table.add_row("Type", f"{scan.get('scan_type', 'N/A')}/{scan.get('scan_subtype', 'N/A')}")
        details_table.add_row("Timestamp", time.ctime(scan.get('timestamp', 0)))
        details_table.add_row("Return Code", str(scan.get('return_code', 'N/A')))
        
        if scan.get('stdout'):
            details_table.add_row("Output", scan['stdout'][:200] + "..." if len(scan['stdout']) > 200 else scan['stdout'])
        
        if scan.get('stderr'):
            details_table.add_row("Errors", scan['stderr'])
        
        self.console.print(details_table)
    
    def show_netcat_menu(self, netcat, theme_manager, translator):
        """Display netcat operations menu"""
        while True:
            self.clear_screen()
            theme = theme_manager.current_theme
            
            menu_title = translator.get("netcat_operations")
            netcat_panel = Panel(
                self._create_netcat_options_table(translator, theme),
                title=f"[bold]{menu_title}[/bold]",
                style=theme['primary'],
                border_style=theme['accent']
            )
            
            self.console.print(netcat_panel)
            
            choice = Prompt.ask(
                f"\n[{theme['accent']}]►[/] {translator.get('select_operation')}",
                choices=["1", "2", "3", "4", "5", "6", "0"],
                show_choices=False
            )
            
            if choice == "1":
                self._handle_port_scanning_nc(netcat, theme_manager, translator)
            elif choice == "2":
                self._handle_connectivity_test(netcat, theme_manager, translator)
            elif choice == "3":
                self._handle_banner_grabbing(netcat, theme_manager, translator)
            elif choice == "4":
                self._handle_listener_setup(netcat, theme_manager, translator)
            elif choice == "5":
                self._handle_tunnel_creation(netcat, theme_manager, translator)
            elif choice == "6":
                self._show_active_listeners(netcat, theme_manager, translator)
            elif choice == "0":
                break
    
    def _create_netcat_options_table(self, translator, theme):
        """Create responsive netcat options table"""
        table = Table(show_header=False, style=theme['text'])
        
        # Responsive design
        option_width = 8 if self.terminal_width < 100 else 10
        desc_width = self.get_responsive_table_width(2)
        
        table.add_column("Option", style=theme['accent'], width=option_width)
        table.add_column("Description", style=theme['text'], width=desc_width)
        
        options = [
            ("1", translator.get("port_scanning")),
            ("2", translator.get("connectivity_test")),
            ("3", translator.get("banner_grabbing")),
            ("4", translator.get("setup_listener")),
            ("5", translator.get("create_tunnel")),
            ("6", translator.get("active_listeners")),
            ("0", translator.get("back_to_main"))
        ]
        
        max_desc_length = max(25, (self.terminal_width - 15)) if self.terminal_width > 60 else 20
        
        for option, desc in options:
            truncated_desc = self.truncate_text(desc, max_desc_length)
            table.add_row(f"[{option}]", truncated_desc)
        
        return table
    
    def _handle_port_scanning_nc(self, netcat, theme_manager, translator):
        """Handle netcat port scanning"""
        theme = theme_manager.current_theme
        
        host = Prompt.ask(f"[{theme['accent']}]Target host[/]")
        
        scan_type = Prompt.ask(
            f"[{theme['accent']}]Scan type[/]",
            choices=["single", "range"],
            default="range"
        )
        
        if scan_type == "single":
            port = IntPrompt.ask(f"[{theme['accent']}]Port[/]")
            ports = [port]
        else:
            start_port = IntPrompt.ask(f"[{theme['accent']}]Start port[/]", default=1)
            end_port = IntPrompt.ask(f"[{theme['accent']}]End port[/]", default=1000)
            ports = list(range(start_port, end_port + 1))
        
        # Execute port scan
        results = netcat.port_scan(host, ports)
        
        # Display results
        summary_table = netcat.get_operation_summary(results)
        self.console.print(summary_table)
        
        # Show open ports with banners
        if results['open_ports']:
            open_ports_table = Table(title="Open Ports Details")
            open_ports_table.add_column("Port", style=theme['accent'])
            open_ports_table.add_column("Banner", style=theme['text'])
            
            for port_result in results['scan_results']:
                if port_result.get('status') == 'open':
                    port = str(port_result['port'])
                    banner = port_result.get('banner', 'No banner')
                    open_ports_table.add_row(port, banner[:50] + "..." if len(banner) > 50 else banner)
            
            self.console.print(open_ports_table)
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _handle_connectivity_test(self, netcat, theme_manager, translator):
        """Handle connectivity testing"""
        theme = theme_manager.current_theme
        
        host = Prompt.ask(f"[{theme['accent']}]Target host[/]")
        port = IntPrompt.ask(f"[{theme['accent']}]Port[/]")
        protocol = Prompt.ask(f"[{theme['accent']}]Protocol[/]", choices=["tcp", "udp"], default="tcp")
        
        # Test connectivity
        result = netcat.test_connectivity(host, port, protocol)
        
        # Display results
        conn_table = Table(title="Connectivity Test Results")
        conn_table.add_column("Attribute", style=theme['accent'])
        conn_table.add_column("Value", style=theme['text'])
        
        conn_table.add_row("Target", f"{host}:{port}")
        conn_table.add_row("Protocol", protocol.upper())
        conn_table.add_row("Status", "✓ Connected" if result['connected'] else "✗ Failed")
        
        if result['response_time']:
            conn_table.add_row("Response Time", f"{result['response_time']:.3f}s")
        
        if result['banner']:
            conn_table.add_row("Banner", result['banner'])
        
        if result['error']:
            conn_table.add_row("Error", result['error'])
        
        self.console.print(conn_table)
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _handle_banner_grabbing(self, netcat, theme_manager, translator):
        """Handle banner grabbing operations"""
        theme = theme_manager.current_theme
        
        host = Prompt.ask(f"[{theme['accent']}]Target host[/]")
        
        # Common ports for banner grabbing
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        
        banners_table = Table(title=f"Banner Grabbing Results: {host}")
        banners_table.add_column("Port", style=theme['accent'])
        banners_table.add_column("Service", style=theme['primary'])
        banners_table.add_column("Banner", style=theme['text'])
        
        for port in common_ports:
            banner = netcat.grab_banner(host, port, timeout=3)
            if banner:
                # Determine service name
                service_names = {
                    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
                    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
                    443: "HTTPS", 993: "IMAPS", 995: "POP3S"
                }
                service = service_names.get(port, "Unknown")
                
                # Truncate banner if too long
                display_banner = banner[:60] + "..." if len(banner) > 60 else banner
                banners_table.add_row(str(port), service, display_banner)
        
        self.console.print(banners_table)
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _handle_listener_setup(self, netcat, theme_manager, translator):
        """Handle setting up netcat listeners"""
        theme = theme_manager.current_theme
        
        port = IntPrompt.ask(f"[{theme['accent']}]Listen port[/]")
        protocol = Prompt.ask(f"[{theme['accent']}]Protocol[/]", choices=["tcp", "udp"], default="tcp")
        
        listener_type = "tcp_listen" if protocol == "tcp" else "udp_listen"
        
        # Start listener
        result = netcat.execute_operation('listening', listener_type, port=port)
        
        if result.get('status') == 'starting':
            self.console.print(f"[green]✓[/green] Listener started on port {port}/{protocol}")
            self.console.print(f"[{theme['secondary']}]Listener is running in background...[/]")
        else:
            self.console.print(f"[red]✗[/red] Failed to start listener: {result.get('error', 'Unknown error')}")
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _handle_tunnel_creation(self, netcat, theme_manager, translator):
        """Handle creating netcat tunnels"""
        theme = theme_manager.current_theme
        
        local_port = IntPrompt.ask(f"[{theme['accent']}]Local port[/]")
        remote_host = Prompt.ask(f"[{theme['accent']}]Remote host[/]")
        remote_port = IntPrompt.ask(f"[{theme['accent']}]Remote port[/]")
        
        # Create tunnel
        result = netcat.create_tunnel(local_port, remote_host, remote_port)
        
        if result.get('status') == 'starting':
            self.console.print(f"[green]✓[/green] Tunnel created: localhost:{local_port} -> {remote_host}:{remote_port}")
            self.console.print(f"[{theme['secondary']}]Tunnel is running in background...[/]")
        else:
            self.console.print(f"[red]✗[/red] Failed to create tunnel: {result.get('error', 'Unknown error')}")
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _show_active_listeners(self, netcat, theme_manager, translator):
        """Show active netcat listeners"""
        theme = theme_manager.current_theme
        
        listeners = netcat.get_active_listeners()
        
        if not listeners:
            self.console.print(f"[{theme['secondary']}]No active listeners[/]")
        else:
            listeners_table = Table(title="Active Listeners")
            listeners_table.add_column("Port", style=theme['accent'])
            listeners_table.add_column("Status", style=theme['text'])
            listeners_table.add_column("Started", style=theme['secondary'])
            
            for listener in listeners:
                port = str(listener.get('port', 'N/A'))
                status = listener.get('status', 'Unknown')
                started = time.ctime(listener.get('timestamp', 0))
                
                listeners_table.add_row(port, status, started)
            
            self.console.print(listeners_table)
            
            # Option to stop a listener
            if Confirm.ask(f"\n[{theme['accent']}]Stop a listener?[/]"):
                stop_port = IntPrompt.ask(f"[{theme['accent']}]Port to stop[/]")
                if netcat.stop_listener(stop_port):
                    self.console.print(f"[green]✓[/green] Listener on port {stop_port} stopped")
                else:
                    self.console.print(f"[red]✗[/red] Could not stop listener on port {stop_port}")
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def show_profiles_menu(self, profiler, db, theme_manager, translator):
        """Display device profiles management menu"""
        while True:
            self.clear_screen()
            theme = theme_manager.current_theme
            
            menu_title = translator.get("device_profiles")
            profiles_panel = Panel(
                self._create_profiles_options_table(translator, theme),
                title=f"[bold]{menu_title}[/bold]",
                style=theme['primary'],
                border_style=theme['accent']
            )
            
            self.console.print(profiles_panel)
            
            choice = Prompt.ask(
                f"\n[{theme['accent']}]►[/] {translator.get('select_option')}",
                choices=["1", "2", "3", "4", "5", "0"],
                show_choices=False
            )
            
            if choice == "1":
                self._list_device_profiles(profiler, db, theme_manager, translator)
            elif choice == "2":
                self._search_profiles(profiler, db, theme_manager, translator)
            elif choice == "3":
                self._view_profile_details(profiler, db, theme_manager, translator)
            elif choice == "4":
                self._export_profiles(profiler, db, theme_manager, translator)
            elif choice == "5":
                self._profile_statistics(profiler, db, theme_manager, translator)
            elif choice == "0":
                break
    
    def _create_profiles_options_table(self, translator, theme):
        """Create profiles options table"""
        table = Table(show_header=False, style=theme['text'])
        table.add_column("Option", style=theme['accent'], width=10)
        table.add_column("Description", style=theme['text'])
        
        options = [
            ("1", translator.get("list_profiles")),
            ("2", translator.get("search_profiles")),
            ("3", translator.get("view_profile_details")),
            ("4", translator.get("export_profiles")),
            ("5", translator.get("profile_statistics")),
            ("0", translator.get("back_to_main"))
        ]
        
        for option, desc in options:
            table.add_row(f"[{option}]", desc)
        
        return table
    
    def _list_device_profiles(self, profiler, db, theme_manager, translator):
        """List all device profiles"""
        theme = theme_manager.current_theme
        
        profiles = db.get_all_device_profiles()
        
        if not profiles:
            self.console.print(f"[{theme['secondary']}]No device profiles found[/]")
        else:
            profiles_table = Table(title="Device Profiles")
            profiles_table.add_column("IP Address", style=theme['accent'])
            profiles_table.add_column("Hostname", style=theme['text'])
            profiles_table.add_column("OS", style=theme['primary'])
            profiles_table.add_column("Device Type", style=theme['text'])
            profiles_table.add_column("Risk Score", style=theme['text'])
            profiles_table.add_column("Last Seen", style=theme['secondary'])
            
            for profile_data in profiles:
                ip = profile_data.get('ip_address', 'N/A')
                hostname = profile_data.get('hostname', 'Unknown')
                os_family = profile_data.get('os_family', 'Unknown')
                device_type = profile_data.get('device_type', 'Unknown')
                risk_score = f"{profile_data.get('risk_score', 0):.1f}/10.0"
                last_seen = time.ctime(profile_data.get('last_seen', 0))
                
                # Color code risk score
                risk_float = profile_data.get('risk_score', 0)
                if risk_float >= 7.0:
                    risk_score = f"[red]{risk_score}[/red]"
                elif risk_float >= 4.0:
                    risk_score = f"[yellow]{risk_score}[/yellow]"
                else:
                    risk_score = f"[green]{risk_score}[/green]"
                
                profiles_table.add_row(ip, hostname, os_family, device_type, risk_score, last_seen)
            
            self.console.print(profiles_table)
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _display_profiles_table(self, profiles, theme, translator):
        """Display profiles in a responsive table format"""
        if not profiles:
            return
        
        # Responsive table design
        col_width = self.get_responsive_table_width(6)
        max_text_length = max(20, (self.terminal_width - 40) // 6) if self.terminal_width > 80 else 15
        
        profiles_table = Table(title="Device Profiles")
        profiles_table.add_column("IP Address", style=theme['accent'], width=col_width)
        profiles_table.add_column("Hostname", style=theme['text'], width=col_width)
        profiles_table.add_column("OS Family", style=theme['text'], width=col_width)
        profiles_table.add_column("Device Type", style=theme['primary'], width=col_width)
        profiles_table.add_column("Risk Score", style=theme['text'], width=col_width)
        profiles_table.add_column("Last Seen", style=theme['secondary'], width=col_width)
        
        for profile_data in profiles:
            ip = profile_data.get('ip_address', 'N/A')
            hostname = self.truncate_text(profile_data.get('hostname', 'N/A'), max_text_length)
            os_family = self.truncate_text(profile_data.get('os_family', 'N/A'), max_text_length)
            device_type = self.truncate_text(profile_data.get('device_type', 'N/A'), max_text_length)
            risk_score = f"{profile_data.get('risk_score', 0):.1f}/10.0"
            last_seen = time.ctime(profile_data.get('last_seen', 0))
            
            # Color code risk score
            risk_float = profile_data.get('risk_score', 0)
            if risk_float >= 7.0:
                risk_score = f"[red]{risk_score}[/red]"
            elif risk_float >= 4.0:
                risk_score = f"[yellow]{risk_score}[/yellow]"
            else:
                risk_score = f"[green]{risk_score}[/green]"
            
            profiles_table.add_row(ip, hostname, os_family, device_type, risk_score, last_seen)
        
        self.console.print(profiles_table)
    
    def _search_profiles(self, profiler, db, theme_manager, translator):
        """Search device profiles"""
        theme = theme_manager.current_theme
        
        search_term = Prompt.ask(f"[{theme['accent']}]Search term (IP, hostname, OS, etc.)[/]")
        
        profiles = db.search_device_profiles(search_term)
        
        if not profiles:
            self.console.print(f"[{theme['secondary']}]No profiles found matching '{search_term}'[/]")
        else:
            self.console.print(f"[{theme['primary']}]Found {len(profiles)} profiles matching '{search_term}'[/]")
            # Display using the same table format as list_profiles
            self._display_profiles_table(profiles, theme, translator)
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _view_profile_details(self, profiler, db, theme_manager, translator):
        """View detailed profile information"""
        theme = theme_manager.current_theme
        
        ip_address = Prompt.ask(f"[{theme['accent']}]IP address[/]")
        
        profile_data = db.get_device_profile_by_ip(ip_address)
        
        if not profile_data:
            self.console.print(f"[{theme['secondary']}]No profile found for {ip_address}[/]")
        else:
            # Convert dict to DeviceProfile object for display
            from src.core.profiler import DeviceProfile
            profile = DeviceProfile(**profile_data)
            
            # Display detailed profile
            profile_table = profiler.get_profile_summary_table(profile)
            self.console.print(profile_table)
            
            # Show ports and services with responsive design
            if profile.services:
                col_width = self.get_responsive_table_width(4)
                max_text_length = max(12, (self.terminal_width - 25) // 4) if self.terminal_width > 80 else 10
                
                services_table = Table(title="Services")
                services_table.add_column("Port", style=theme['accent'], width=col_width)
                services_table.add_column("Service", style=theme['primary'], width=col_width)
                services_table.add_column("Product", style=theme['text'], width=col_width)
                services_table.add_column("Version", style=theme['text'], width=col_width)
                
                for port, service_info in profile.services.items():
                    product = self.truncate_text(service_info.get('product', 'N/A'), max_text_length)
                    version = self.truncate_text(service_info.get('version', 'N/A'), max_text_length)
                    service_name = self.truncate_text(service_info.get('name', 'N/A'), max_text_length)
                    
                    services_table.add_row(port, service_name, product, version)
                
                self.console.print(services_table)
            
            # Show vulnerabilities if any
            if profile.vulnerabilities:
                vulns_table = Table(title="Vulnerabilities")
                vulns_table.add_column("CVE", style=theme['accent'])
                vulns_table.add_column("Severity", style=theme['text'])
                vulns_table.add_column("Description", style=theme['text'])
                
                for vuln in profile.vulnerabilities:
                    cve = vuln.get('cve_id', 'N/A')
                    severity = vuln.get('severity', 'N/A')
                    description = vuln.get('description', 'N/A')
                    
                    vulns_table.add_row(cve, severity, description[:50] + "..." if len(description) > 50 else description)
                
                self.console.print(vulns_table)
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _export_profiles(self, profiler, db, theme_manager, translator):
        """Export device profiles"""
        theme = theme_manager.current_theme
        
        export_format = Prompt.ask(
            f"[{theme['accent']}]Export format[/]",
            choices=["json", "csv"],
            default="json"
        )
        
        filename = Prompt.ask(
            f"[{theme['accent']}]Output filename[/]",
            default=f"device_profiles.{export_format}"
        )
        
        try:
            if export_format == "json":
                profiles = db.get_all_device_profiles()
                with open(filename, 'w') as f:
                    json.dump(profiles, f, indent=2, default=str)
            else:  # CSV
                db.export_profiles_csv(filename)
            
            self.console.print(f"[green]✓[/green] Profiles exported to {filename}")
            
        except Exception as e:
            self.console.print(f"[red]✗[/red] Export failed: {e}")
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _profile_statistics(self, profiler, db, theme_manager, translator):
        """Show profile statistics"""
        theme = theme_manager.current_theme
        
        stats = db.get_profile_statistics()
        
        stats_table = Table(title="Profile Statistics")
        stats_table.add_column("Metric", style=theme['accent'])
        stats_table.add_column("Value", style=theme['text'])
        
        stats_table.add_row("Total Profiles", str(stats.get('total_profiles', 0)))
        stats_table.add_row("High Risk Devices", str(stats.get('high_risk_count', 0)))
        stats_table.add_row("Most Common OS", stats.get('most_common_os', 'N/A'))
        stats_table.add_row("Most Common Device Type", stats.get('most_common_device_type', 'N/A'))
        stats_table.add_row("Average Risk Score", f"{stats.get('avg_risk_score', 0):.1f}")
        
        self.console.print(stats_table)
        
        # Device type breakdown
        if stats.get('device_type_breakdown'):
            breakdown_table = Table(title="Device Type Breakdown")
            breakdown_table.add_column("Device Type", style=theme['primary'])
            breakdown_table.add_column("Count", style=theme['text'])
            
            for device_type, count in stats['device_type_breakdown'].items():
                breakdown_table.add_row(device_type, str(count))
            
            self.console.print(breakdown_table)
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def show_exploits_menu(self, exploits, theme_manager, translator):
        """Display exploit database menu"""
        while True:
            self.clear_screen()
            theme = theme_manager.current_theme
            
            menu_title = translator.get("exploit_database")
            exploits_panel = Panel(
                self._create_exploits_options_table(translator, theme),
                title=f"[bold]{menu_title}[/bold]",
                style=theme['primary'],
                border_style=theme['accent']
            )
            
            self.console.print(exploits_panel)
            
            choice = Prompt.ask(
                f"\n[{theme['accent']}]►[/] {translator.get('select_option')}",
                choices=["1", "2", "3", "4", "5", "0"],
                show_choices=False
            )
            
            if choice == "1":
                self._search_vulnerabilities(exploits, theme_manager, translator)
            elif choice == "2":
                self._search_exploits(exploits, theme_manager, translator)
            elif choice == "3":
                self._update_exploit_db(exploits, theme_manager, translator)
            elif choice == "4":
                self._exploit_statistics(exploits, theme_manager, translator)
            elif choice == "5":
                self._correlate_service_vulns(exploits, theme_manager, translator)
            elif choice == "0":
                break
    
    def _create_exploits_options_table(self, translator, theme):
        """Create exploits options table"""
        table = Table(show_header=False, style=theme['text'])
        table.add_column("Option", style=theme['accent'], width=10)
        table.add_column("Description", style=theme['text'])
        
        options = [
            ("1", translator.get("search_vulnerabilities")),
            ("2", translator.get("search_exploits")),
            ("3", translator.get("update_database")),
            ("4", translator.get("exploit_statistics")),
            ("5", translator.get("service_correlation")),
            ("0", translator.get("back_to_main"))
        ]
        
        for option, desc in options:
            table.add_row(f"[{option}]", desc)
        
        return table
    
    def _search_vulnerabilities(self, exploits, theme_manager, translator):
        """Search vulnerability database"""
        theme = theme_manager.current_theme
        
        service = Prompt.ask(f"[{theme['accent']}]Service name[/]")
        version = Prompt.ask(f"[{theme['accent']}]Version (optional)[/]", default="")
        
        vulns = exploits.search_vulnerabilities_by_service(service, version if version else None)
        
        if not vulns:
            self.console.print(f"[{theme['secondary']}]No vulnerabilities found for {service}[/]")
        else:
            vulns_table = Table(title=f"Vulnerabilities for {service}")
            vulns_table.add_column("CVE ID", style=theme['accent'])
            vulns_table.add_column("Severity", style=theme['text'])
            vulns_table.add_column("Score", style=theme['text'])
            vulns_table.add_column("Description", style=theme['text'])
            vulns_table.add_column("Exploit", style=theme['primary'])
            
            for vuln in vulns:
                severity_style = exploits._get_severity_style(vuln.severity)
                exploit_status = "✓" if vuln.exploit_available else "✗"
                
                vulns_table.add_row(
                    vuln.cve_id,
                    f"[{severity_style}]{vuln.severity.upper()}[/{severity_style}]",
                    f"{vuln.score:.1f}",
                    vuln.description[:50] + "..." if len(vuln.description) > 50 else vuln.description,
                    exploit_status
                )
            
            self.console.print(vulns_table)
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _search_exploits(self, exploits, theme_manager, translator):
        """Search exploit database"""
        theme = theme_manager.current_theme
        
        query = Prompt.ask(f"[{theme['accent']}]Search query[/]")
        
        exploit_results = exploits.search_exploits(query)
        
        if not exploit_results:
            self.console.print(f"[{theme['secondary']}]No exploits found for '{query}'[/]")
        else:
            exploits_table = Table(title=f"Exploits matching '{query}'")
            exploits_table.add_column("ID", style=theme['accent'])
            exploits_table.add_column("Title", style=theme['text'])
            exploits_table.add_column("Type", style=theme['primary'])
            exploits_table.add_column("Platform", style=theme['text'])
            exploits_table.add_column("Difficulty", style=theme['text'])
            
            for exploit in exploit_results:
                exploits_table.add_row(
                    exploit.exploit_id,
                    exploit.title[:40] + "..." if len(exploit.title) > 40 else exploit.title,
                    exploit.type,
                    exploit.platform,
                    exploit.difficulty
                )
            
            self.console.print(exploits_table)
            
            # Option to view details
            if Confirm.ask(f"\n[{theme['accent']}]View exploit details?[/]"):
                exploit_id = Prompt.ask(f"[{theme['accent']}]Exploit ID[/]")
                for exploit in exploit_results:
                    if exploit.exploit_id == exploit_id:
                        details_table = exploits.get_exploit_summary_table(exploit)
                        self.console.print(details_table)
                        break
                else:
                    self.console.print(f"[{theme['secondary']}]Exploit {exploit_id} not found[/]")
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _update_exploit_db(self, exploits, theme_manager, translator):
        """Update exploit database"""
        theme = theme_manager.current_theme
        
        self.console.print(f"[{theme['primary']}]Updating exploit database...[/]")
        
        success = exploits.update_vulnerability_database()
        
        if success:
            self.console.print(f"[green]✓[/green] Database update completed successfully")
        else:
            self.console.print(f"[red]✗[/red] Database update failed")
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _exploit_statistics(self, exploits, theme_manager, translator):
        """Show exploit database statistics"""
        theme = theme_manager.current_theme
        
        stats = exploits.get_statistics()
        
        stats_table = Table(title="Exploit Database Statistics")
        stats_table.add_column("Metric", style=theme['accent'])
        stats_table.add_column("Value", style=theme['text'])
        
        stats_table.add_row("Total Vulnerabilities", str(stats['total_vulnerabilities']))
        stats_table.add_row("Total Exploits", str(stats['total_exploits']))
        stats_table.add_row("Exploitable Vulnerabilities", str(stats['exploitable_vulns']))
        
        self.console.print(stats_table)
        
        # Severity breakdown
        severity_table = Table(title="Vulnerability Severity Breakdown")
        severity_table.add_column("Severity", style=theme['primary'])
        severity_table.add_column("Count", style=theme['text'])
        
        for severity, count in stats['severity_breakdown'].items():
            severity_style = exploits._get_severity_style(severity)
            severity_table.add_row(
                f"[{severity_style}]{severity.upper()}[/{severity_style}]",
                str(count)
            )
        
        self.console.print(severity_table)
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _correlate_service_vulns(self, exploits, theme_manager, translator):
        """Correlate service with vulnerabilities"""
        theme = theme_manager.current_theme
        
        self.console.print(f"[{theme['primary']}]This feature requires scan results.[/]")
        self.console.print(f"[{theme['secondary']}]Perform a scan first to correlate vulnerabilities.[/]")
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def show_dossier_menu(self, db, theme_manager, translator):
        """Display dossier management menu"""
        while True:
            self.clear_screen()
            theme = theme_manager.current_theme
            
            menu_title = translator.get("dossier_management")
            dossier_panel = Panel(
                self._create_dossier_options_table(translator, theme),
                title=f"[bold]{menu_title}[/bold]",
                style=theme['primary'],
                border_style=theme['accent']
            )
            
            self.console.print(dossier_panel)
            
            choice = Prompt.ask(
                f"\n[{theme['accent']}]►[/] {translator.get('select_option')}",
                choices=["1", "2", "3", "4", "5", "0"],
                show_choices=False
            )
            
            if choice == "1":
                self._generate_dossier(db, theme_manager, translator)
            elif choice == "2":
                self._list_dossiers(db, theme_manager, translator)
            elif choice == "3":
                self._view_dossier(db, theme_manager, translator)
            elif choice == "4":
                self._export_dossier(db, theme_manager, translator)
            elif choice == "5":
                self._delete_dossier(db, theme_manager, translator)
            elif choice == "0":
                break
    
    def _create_dossier_options_table(self, translator, theme):
        """Create dossier options table"""
        table = Table(show_header=False, style=theme['text'])
        table.add_column("Option", style=theme['accent'], width=10)
        table.add_column("Description", style=theme['text'])
        
        options = [
            ("1", translator.get("generate_dossier")),
            ("2", translator.get("list_dossiers")),
            ("3", translator.get("view_dossier")),
            ("4", translator.get("export_dossier")),
            ("5", translator.get("delete_dossier")),
            ("0", translator.get("back_to_main"))
        ]
        
        for option, desc in options:
            table.add_row(f"[{option}]", desc)
        
        return table
    
    def _generate_dossier(self, db, theme_manager, translator):
        """Generate new dossier"""
        theme = theme_manager.current_theme
        
        target = Prompt.ask(f"[{theme['accent']}]Target (IP/subnet)[/]")
        title = Prompt.ask(f"[{theme['accent']}]Dossier title[/]", default=f"Reconnaissance: {target}")
        
        try:
            dossier_id = db.create_dossier(target, title)
            self.console.print(f"[green]✓[/green] Dossier created with ID: {dossier_id}")
        except Exception as e:
            self.console.print(f"[red]✗[/red] Failed to create dossier: {e}")
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _list_dossiers(self, db, theme_manager, translator):
        """List all dossiers"""
        theme = theme_manager.current_theme
        
        dossiers = db.get_all_dossiers()
        
        if not dossiers:
            self.console.print(f"[{theme['secondary']}]No dossiers found[/]")
        else:
            dossiers_table = Table(title="Intelligence Dossiers")
            dossiers_table.add_column("ID", style=theme['accent'])
            dossiers_table.add_column("Title", style=theme['text'])
            dossiers_table.add_column("Target", style=theme['primary'])
            dossiers_table.add_column("Created", style=theme['secondary'])
            
            for dossier in dossiers:
                dossier_id = str(dossier.get('id', 'N/A'))
                title = dossier.get('title', 'N/A')
                target = dossier.get('target', 'N/A')
                created = time.ctime(dossier.get('created_at', 0))
                
                dossiers_table.add_row(dossier_id, title, target, created)
            
            self.console.print(dossiers_table)
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _view_dossier(self, db, theme_manager, translator):
        """View dossier details"""
        theme = theme_manager.current_theme
        
        dossier_id = Prompt.ask(f"[{theme['accent']}]Dossier ID[/]")
        
        try:
            dossier = db.get_dossier(int(dossier_id))
            if not dossier:
                self.console.print(f"[{theme['secondary']}]Dossier not found[/]")
            else:
                # Display dossier information
                dossier_info = Panel(
                    f"[bold]Title:[/bold] {dossier.get('title', 'N/A')}\n"
                    f"[bold]Target:[/bold] {dossier.get('target', 'N/A')}\n"
                    f"[bold]Created:[/bold] {time.ctime(dossier.get('created_at', 0))}\n"
                    f"[bold]Description:[/bold] {dossier.get('description', 'No description')}",
                    title=f"Dossier {dossier_id}",
                    style=theme['primary'],
                    border_style=theme['accent']
                )
                self.console.print(dossier_info)
        except Exception as e:
            self.console.print(f"[red]✗[/red] Error viewing dossier: {e}")
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _export_dossier(self, db, theme_manager, translator):
        """Export dossier"""
        theme = theme_manager.current_theme
        
        dossier_id = Prompt.ask(f"[{theme['accent']}]Dossier ID[/]")
        export_format = Prompt.ask(
            f"[{theme['accent']}]Export format[/]",
            choices=["json", "html", "pdf"],
            default="json"
        )
        
        try:
            filename = db.export_dossier(int(dossier_id), export_format)
            self.console.print(f"[green]✓[/green] Dossier exported to {filename}")
        except Exception as e:
            self.console.print(f"[red]✗[/red] Export failed: {e}")
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _delete_dossier(self, db, theme_manager, translator):
        """Delete dossier"""
        theme = theme_manager.current_theme
        
        dossier_id = Prompt.ask(f"[{theme['accent']}]Dossier ID[/]")
        
        if Confirm.ask(f"[{theme['accent']}]Are you sure you want to delete dossier {dossier_id}?[/]"):
            try:
                db.delete_dossier(int(dossier_id))
                self.console.print(f"[green]✓[/green] Dossier {dossier_id} deleted")
            except Exception as e:
                self.console.print(f"[red]✗[/red] Failed to delete dossier: {e}")
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def show_settings_menu(self, config, theme_manager, translator):
        """Display settings configuration menu"""
        while True:
            self.clear_screen()
            theme = theme_manager.current_theme
            
            menu_title = translator.get("settings")
            settings_panel = Panel(
                self._create_settings_options_table(translator, theme, config),
                title=f"[bold]{menu_title}[/bold]",
                style=theme['primary'],
                border_style=theme['accent']
            )
            
            self.console.print(settings_panel)
            
            choice = Prompt.ask(
                f"\n[{theme['accent']}]►[/] {translator.get('select_option')}",
                choices=["1", "2", "3", "4", "5", "0"],
                show_choices=False
            )
            
            if choice == "1":
                self._change_theme(config, theme_manager, translator)
            elif choice == "2":
                self._change_language(config, theme_manager, translator)
            elif choice == "3":
                new_hotkey = Prompt.ask(f"[{theme['accent']}]Enter new termination hotkey (current: {config.get('hotkey_terminate')})[/]")
                config.set('hotkey_terminate', new_hotkey)
                self._setup_hotkeys()
            elif choice == "4":
                self._view_current_settings(config, theme_manager, translator)
            elif choice == "5":
                self._reset_settings(config, theme_manager, translator)
            elif choice == "0":
                break
    
    def _create_settings_options_table(self, translator, theme, config=None):
        """Create settings options table"""
        table = Table(show_header=False, style=theme['text'])
        table.add_column("Option", style=theme['accent'], width=10)
        table.add_column("Description", style=theme['text'])
        
        hotkey = config.get('hotkey_terminate', 'N/A') if config else 'N/A'
        
        options = [
            ("1", translator.get("change_theme")),
            ("2", translator.get("change_language")),
            ("3", f"Change Termination Hotkey (Current: {hotkey})"),
            ("4", translator.get("view_settings")),
            ("5", translator.get("reset_settings")),
            ("0", translator.get("back_to_main"))
        ]
        
        for option, desc in options:
            table.add_row(f"[{option}]", desc)
        
        return table
    
    def _change_theme(self, config, theme_manager, translator):
        """Change color theme"""
        theme = theme_manager.current_theme
        
        available_themes = ["matrix", "cyberpunk", "starlight"]
        current_theme = config.get('theme', 'cyberpunk')
        
        self.console.print(f"\n[bold]Available themes:[/bold]")
        for i, theme_name in enumerate(available_themes, 1):
            marker = " (current)" if theme_name == current_theme else ""
            self.console.print(f"  [{theme['accent']}]{i}[/] - {theme_name}{marker}")
        
        choice = IntPrompt.ask(
            f"\n[{theme['accent']}]Select theme[/]",
            default=available_themes.index(current_theme) + 1
        )
        
        if 1 <= choice <= len(available_themes):
            new_theme = available_themes[choice - 1]
            config.set('theme', new_theme)
            theme_manager.set_theme(new_theme)
            self.console.print(f"[green]✓[/green] Theme changed to {new_theme}")
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _change_language(self, config, theme_manager, translator):
        """Change interface language"""
        theme = theme_manager.current_theme
        
        available_languages = {"en": "English", "es": "Español", "fr": "Français", "de": "Deutsch"}
        current_language = config.get('language', 'en')
        
        self.console.print(f"\n[bold]Available languages:[/bold]")
        for i, (code, name) in enumerate(available_languages.items(), 1):
            marker = " (current)" if code == current_language else ""
            self.console.print(f"  [{theme['accent']}]{i}[/] - {name}{marker}")
        
        choice = IntPrompt.ask(
            f"\n[{theme['accent']}]Select language[/]",
            default=list(available_languages.keys()).index(current_language) + 1
        )
        
        if 1 <= choice <= len(available_languages):
            new_language = list(available_languages.keys())[choice - 1]
            config.set('language', new_language)
            translator.set_language(new_language)
            self.console.print(f"[green]✓[/green] Language changed to {available_languages[new_language]}")
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _view_current_settings(self, config, theme_manager, translator):
        """View current settings"""
        theme = theme_manager.current_theme
        
        settings_table = Table(title="Current Settings")
        settings_table.add_column("Setting", style=theme['accent'])
        settings_table.add_column("Value", style=theme['text'])
        
        settings_table.add_row("Theme", config.get('theme', 'cyberpunk'))
        settings_table.add_row("Language", config.get('language', 'en'))
        settings_table.add_row("Auto-save", str(config.get('auto_save', True)))
        settings_table.add_row("Max scan history", str(config.get('max_scan_history', 100)))
        
        self.console.print(settings_table)
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _reset_settings(self, config, theme_manager, translator):
        """Reset settings to defaults"""
        theme = theme_manager.current_theme
        
        if Confirm.ask(f"[{theme['accent']}]Reset all settings to defaults?[/]"):
            config.reset_to_defaults()
            theme_manager.set_theme('cyberpunk')
            translator.set_language('en')
            self.console.print(f"[green]✓[/green] Settings reset to defaults")
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def show_help_menu(self, theme_manager, translator):
        """Display help and documentation menu"""
        while True:
            self.clear_screen()
            theme = theme_manager.current_theme
            
            menu_title = translator.get("help_documentation")
            help_panel = Panel(
                self._create_help_options_table(translator, theme),
                title=f"[bold]{menu_title}[/bold]",
                style=theme['primary'],
                border_style=theme['accent']
            )
            
            self.console.print(help_panel)
            
            choice = Prompt.ask(
                f"\n[{theme['accent']}]►[/] {translator.get('select_option')}",
                choices=["1", "2", "3", "4", "5", "0"],
                show_choices=False
            )
            
            if choice == "1":
                self._show_nmap_help(theme_manager, translator)
            elif choice == "2":
                self._show_netcat_help(theme_manager, translator)
            elif choice == "3":
                self._show_features_overview(theme_manager, translator)
            elif choice == "4":
                self._show_about(theme_manager, translator)
            elif choice == "5":
                self._show_keyboard_shortcuts(theme_manager, translator)
            elif choice == "0":
                break
    
    def _create_help_options_table(self, translator, theme):
        """Create help options table"""
        table = Table(show_header=False, style=theme['text'])
        table.add_column("Option", style=theme['accent'], width=10)
        table.add_column("Description", style=theme['text'])
        
        options = [
            ("1", translator.get("nmap_help")),
            ("2", translator.get("netcat_help")),
            ("3", translator.get("features_overview")),
            ("4", translator.get("about")),
            ("5", translator.get("keyboard_shortcuts")),
            ("0", translator.get("back_to_main"))
        ]
        
        for option, desc in options:
            table.add_row(f"[{option}]", desc)
        
        return table
    
    def _show_nmap_help(self, theme_manager, translator):
        """Show nmap command help"""
        theme = theme_manager.current_theme
        
        nmap_help = """
# Nmap Scanning Guide

## Basic Scans
- **Single Target**: Scan one IP address or hostname
- **Aggressive**: Comprehensive scan with OS detection, version detection, script scanning, and traceroute
- **Subnet**: Scan entire subnet using CIDR notation
- **Range**: Scan range of IP addresses

## Discovery Options
- **Ping Scan**: Host discovery without port scanning
- **TCP SYN Ping**: Use TCP SYN packets for host discovery
- **UDP Ping**: Use UDP packets for host discovery
- **No Ping**: Skip host discovery phase

## Port Scanning
- **TCP SYN**: Stealth scan using SYN packets
- **TCP Connect**: Full TCP connection scan
- **UDP Scan**: Scan UDP ports
- **Custom Ports**: Specify custom port ranges

## Version Detection
- **OS Detection**: Identify operating system
- **Service Version**: Detect service versions
- **Aggressive OS**: Enhanced OS detection with guessing

## Firewall Evasion
- **Fragment**: Split packets to evade detection
- **Decoy**: Use decoy IPs to mask scan source
- **Source Port**: Specify custom source port
- **MAC Spoofing**: Spoof MAC address
        """
        
        help_panel = Panel(
            Markdown(nmap_help),
            title="Nmap Help",
            style=theme['primary'],
            border_style=theme['accent']
        )
        
        self.console.print(help_panel)
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _show_netcat_help(self, theme_manager, translator):
        """Show netcat command help"""
        theme = theme_manager.current_theme
        
        netcat_help = """
# Netcat Operations Guide

## Port Scanning
- **Single Port**: Test connectivity to a specific port
- **Port Range**: Scan multiple ports in sequence
- **Banner Grabbing**: Capture service banners

## Listeners
- **TCP Listener**: Listen for incoming TCP connections
- **UDP Listener**: Listen for incoming UDP packets
- **File Receiver**: Receive files over the network

## Connectivity Testing
- **TCP Test**: Test TCP connectivity to a host:port
- **UDP Test**: Test UDP connectivity to a host:port
- **Response Time**: Measure connection response time

## Tunneling
- **Port Relay**: Create port forwarding tunnel
- **Reverse Shell**: Set up reverse shell connections

## Common Use Cases
- Network reconnaissance
- Service enumeration
- File transfers
- Network debugging
- Penetration testing
        """
        
        help_panel = Panel(
            Markdown(netcat_help),
            title="Netcat Help",
            style=theme['primary'],
            border_style=theme['accent']
        )
        
        self.console.print(help_panel)
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _show_features_overview(self, theme_manager, translator):
        """Show features overview"""
        theme = theme_manager.current_theme
        
        features_help = """
# Cyber Amenti Features Overview

## Core Capabilities
- **Network Scanning**: Comprehensive nmap integration with all scan types
- **Service Enumeration**: Advanced service detection and banner grabbing
- **Device Profiling**: Automated device fingerprinting and classification
- **Vulnerability Correlation**: Integration with exploit databases
- **Intelligence Gathering**: Automated dossier generation

## Device Profiling
- Operating system detection
- Device type classification (server, workstation, router, IoT, etc.)
- Vendor identification
- Risk scoring based on exposed services and vulnerabilities
- Historical tracking

## Exploit Integration
- CVE database integration
- Exploit availability checking
- Vulnerability severity assessment
- Service-specific exploit correlation

## Data Management
- SQLite database for persistent storage
- Export capabilities (JSON, CSV, HTML, PDF)
- Search and filtering
- Historical data analysis

## Interface Features
- Multiple color themes (Matrix, Cyberpunk, Starlight)
- Multi-language support (English, Spanish, French, German)
- Interactive CLI with rich formatting
- Progress indicators and real-time feedback
        """
        
        help_panel = Panel(
            Markdown(features_help),
            title="Features Overview",
            style=theme['primary'],
            border_style=theme['accent']
        )
        
        self.console.print(help_panel)
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _show_about(self, theme_manager, translator):
        """Show about information"""
        theme = theme_manager.current_theme
        
        about_text = """
# Cyber Amenti v1.0 (Maze Mouse)

**Red Team Network Intelligence Gathering Tool**

## Created by Jaydr Nexus

Cyber Amenti is a comprehensive red team tool designed for network reconnaissance, 
device profiling, and exploit correlation. It combines the power of nmap and netcat 
with advanced intelligence gathering capabilities.

## Features
- Advanced network scanning with nmap integration
- Netcat operations for connectivity testing and tunneling
- Automated device fingerprinting and profiling
- Vulnerability correlation with exploit databases
- Intelligence dossier generation and management
- Multi-theme cyberpunk interface
- Multi-language support

## Version Information
- Version: 1.0 (Maze Mouse)
- Author: Jaydr Nexus
- License: MIT
- Platform: Cross-platform (Linux, macOS, Windows)

## Requirements
- Python 3.8+
- nmap
- netcat
- Internet connection for vulnerability updates

## Support
For support and updates, visit the Jaydr Nexus GitHub repository.
        """
        
        about_panel = Panel(
            Markdown(about_text),
            title="About Cyber Amenti",
            style=theme['primary'],
            border_style=theme['accent']
        )
        
        self.console.print(about_panel)
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
    
    def _show_keyboard_shortcuts(self, theme_manager, translator):
        """Show keyboard shortcuts"""
        theme = theme_manager.current_theme
        
        shortcuts_table = Table(title="Keyboard Shortcuts")
        shortcuts_table.add_column("Key", style=theme['accent'])
        shortcuts_table.add_column("Action", style=theme['text'])
        
        shortcuts = [
            ("Ctrl+C", "Cancel current operation / Exit"),
            ("Ctrl+D", "Exit current menu"),
            ("Enter", "Confirm selection"),
            ("↑/↓", "Navigate menu options"),
            ("Tab", "Auto-complete (where available)"),
            ("?", "Show help for current context"),
            ("q", "Quick exit from most menus")
        ]
        
        for key, action in shortcuts:
            shortcuts_table.add_row(key, action)
        
        self.console.print(shortcuts_table)
        
        Prompt.ask(f"\n[{theme['secondary']}]Press Enter to continue...[/]", default="")
