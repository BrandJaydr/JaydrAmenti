#!/usr/bin/env python3
"""
Cyber Amenti v1.0 (Maze Mouse)
A comprehensive red team network intelligence gathering tool by Jaydr Nexus

Author: Jaydr Nexus
Version: 1.0
License: MIT
"""

import sys
import os
import click
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.layout import Layout
import json
import threading
import time

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from ui.interface import CyberAmentiInterface
from ui.themes import ThemeManager
from core.scanner import NmapScanner
from core.netcat import NetcatManager
from core.profiler import DeviceProfiler
from core.exploits import ExploitDatabase
from utils.database import IntelligenceDB
from utils.config import ConfigManager
from utils.translator import Translator
from assets.banner import get_banner

class CyberAmenti:
    def __init__(self):
        self.console = Console()
        self.config = ConfigManager()
        self.theme_manager = ThemeManager()
        self.translator = Translator()
        self.interface = CyberAmentiInterface()
        self.scanner = NmapScanner()
        self.netcat = NetcatManager()
        self.profiler = DeviceProfiler()
        self.exploits = ExploitDatabase()
        self.db = IntelligenceDB()
        
        # Initialize components
        self.setup()
    
    def setup(self):
        """Initialize the application"""
        # Set theme
        theme = self.config.get('theme', 'cyberpunk')
        self.theme_manager.set_theme(theme)
        
        # Set language
        language = self.config.get('language', 'en')
        self.translator.set_language(language)
        
        # Initialize database
        self.db.initialize()
    
    def show_banner(self):
        """Display the Cyber Amenti banner"""
        banner = get_banner()
        theme = self.theme_manager.current_theme
        
        banner_panel = Panel(
            banner,
            title="[bold]Cyber Amenti v1.0 (Maze Mouse)[/bold]",
            subtitle="[italic]Red Team Network Intelligence Gathering Tool by Jaydr Nexus[/italic]",
            style=theme['primary'],
            border_style=theme['accent']
        )
        
        self.console.print(banner_panel)
        self.console.print()
    
    def main_menu(self):
        """Display main menu and handle navigation"""
        while True:
            self.interface.clear_screen()
            self.show_banner()
            
            # Main menu options with responsive design
            menu_table = Table(show_header=False, style=self.theme_manager.current_theme['text'])
            
            # Get terminal width from interface for responsive design
            terminal_width = self.interface.get_terminal_width()
            option_width = 8 if terminal_width < 100 else 10
            desc_width = max(30, terminal_width - 20) if terminal_width > 50 else None
            
            menu_table.add_column("Option", style=self.theme_manager.current_theme['accent'], width=option_width)
            menu_table.add_column("Description", style=self.theme_manager.current_theme['text'], width=desc_width)
            
            menu_options = [
                ("1", self.translator.get("scan_target")),
                ("2", self.translator.get("netcat_operations")),
                ("3", self.translator.get("device_profiles")),
                ("4", self.translator.get("exploit_database")),
                ("5", self.translator.get("intelligence_gathering")),
                ("6", self.translator.get("settings")),
                ("7", self.translator.get("help")),
                ("0", self.translator.get("exit"))
            ]
            
            for option, description in menu_options:
                # Truncate descriptions on smaller screens
                max_desc_length = max(25, terminal_width - 25) if terminal_width > 50 else 20
                truncated_desc = description[:max_desc_length] + "..." if len(description) > max_desc_length else description
                menu_table.add_row(f"[{option}]", truncated_desc)
            
            menu_panel = Panel(
                menu_table,
                title=self.translator.get("main_menu"),
                style=self.theme_manager.current_theme['primary'],
                border_style=self.theme_manager.current_theme['accent']
            )
            
            self.console.print(menu_panel)
            
            choice = Prompt.ask(
                f"\n[{self.theme_manager.current_theme['accent']}]►[/] {self.translator.get('select_option')}",
                choices=["0", "1", "2", "3", "4", "5", "6", "7"],
                show_choices=False
            )
            
            if choice == "1":
                self.scan_menu()
            elif choice == "2":
                self.netcat_menu()
            elif choice == "3":
                self.profiles_menu()
            elif choice == "4":
                self.exploits_menu()
            elif choice == "5":
                self.dossier_menu()
            elif choice == "6":
                self.settings_menu()
            elif choice == "7":
                self.help_menu()
            elif choice == "0":
                if Confirm.ask(self.translator.get("confirm_exit")):
                    break
    
    def scan_menu(self):
        """Network scanning operations menu"""
        self.interface.show_scan_menu(
            self.scanner, 
            self.profiler, 
            self.exploits, 
            self.db,
            self.theme_manager,
            self.translator
        )
    
    def netcat_menu(self):
        """Netcat operations menu"""
        self.interface.show_netcat_menu(
            self.netcat,
            self.theme_manager,
            self.translator
        )
    
    def profiles_menu(self):
        """Device profiles management menu"""
        self.interface.show_profiles_menu(
            self.profiler,
            self.db,
            self.theme_manager,
            self.translator
        )
    
    def exploits_menu(self):
        """Exploit database menu"""
        self.interface.show_exploits_menu(
            self.exploits,
            self.theme_manager,
            self.translator
        )
    
    def dossier_menu(self):
        """Dossier management menu"""
        self.interface.show_dossier_menu(
            self.db,
            self.theme_manager,
            self.translator
        )
    
    def settings_menu(self):
        """Settings configuration menu"""
        self.interface.show_settings_menu(
            self.config,
            self.theme_manager,
            self.translator
        )
    
    def help_menu(self):
        """Help and documentation menu"""
        self.interface.show_help_menu(
            self.theme_manager,
            self.translator
        )

@click.command()
@click.option('--theme', '-t', default='cyberpunk', 
              type=click.Choice(['matrix', 'cyberpunk', 'starlight']),
              help='Color theme for the interface')
@click.option('--language', '-l', default='en',
              type=click.Choice(['en', 'es', 'fr', 'de']),
              help='Interface language')
@click.option('--config', '-c', default='config/settings.json',
              help='Configuration file path')
def main(theme, language, config):
    """
    Cyber Amenti - Red Team Network Intelligence Gathering Tool
    
    A comprehensive tool for network reconnaissance, device profiling,
    and exploit correlation designed for red team operations.
    """
    try:
        # Check for required dependencies
        import subprocess
        
        # Check for nmap
        try:
            subprocess.run(['nmap', '--version'], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("ERROR: nmap is required but not installed.")
            print("Please install nmap: sudo apt install nmap")
            sys.exit(1)
        
        # Check for netcat
        try:
            subprocess.run(['nc', '-h'], capture_output=True)
        except FileNotFoundError:
            print("ERROR: netcat is required but not installed.")
            print("Please install netcat: sudo apt install netcat")
            sys.exit(1)
        
        # Initialize and run application
        app = CyberAmenti()
        
        # Override config if command line options provided
        if theme:
            app.config.set('theme', theme)
            app.theme_manager.set_theme(theme)
        
        if language:
            app.config.set('language', language)
            app.translator.set_language(language)
        
        # Start main application
        app.main_menu()
        
    except KeyboardInterrupt:
        print("\n\nOperation terminated by user.")
        sys.exit(0)
    except Exception as e:
        print(f"ERROR: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
