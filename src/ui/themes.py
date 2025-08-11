"""
Cyber Amenti Color Themes
Cyberpunk-styled color schemes for the terminal interface
"""

from typing import Dict, Any

class ThemeManager:
    def __init__(self):
        self.current_theme_name = 'cyberpunk'
        self.themes = {
            'matrix': {
                'name': 'Matrix Green',
                'description': 'Classic terminal green on black',
                'primary': 'bright_green',
                'secondary': 'green',
                'accent': 'bright_cyan',
                'text': 'white',
                'background': 'black',
                'success': 'bright_green',
                'warning': 'yellow',
                'error': 'red',
                'info': 'cyan',
                'dim': 'dim white',
                'border': 'green',
                'highlight': 'black on bright_green'
            },
            
            'cyberpunk': {
                'name': 'Cyberpunk',
                'description': 'Dark blue background with pink neon accents',
                'primary': 'bright_blue',
                'secondary': 'blue',
                'accent': 'bright_magenta',
                'text': 'white',
                'background': 'black',
                'success': 'bright_green',
                'warning': 'bright_yellow',
                'error': 'bright_red',
                'info': 'bright_cyan',
                'dim': 'dim white',
                'border': 'bright_magenta',
                'highlight': 'black on bright_magenta'
            },
            
            'starlight': {
                'name': 'Starlight',
                'description': 'Dark mode with blue, yellow and white highlights',
                'primary': 'bright_white',
                'secondary': 'white',
                'accent': 'bright_yellow',
                'text': 'white',
                'background': 'black',
                'success': 'bright_green',
                'warning': 'bright_yellow',
                'error': 'bright_red',
                'info': 'bright_blue',
                'dim': 'dim white',
                'border': 'bright_blue',
                'highlight': 'black on bright_yellow'
            }
        }
        
        # Set initial theme
        self.current_theme = self.themes[self.current_theme_name]
    
    def set_theme(self, theme_name: str) -> bool:
        """Set the current theme"""
        if theme_name in self.themes:
            self.current_theme_name = theme_name
            self.current_theme = self.themes[theme_name]
            return True
        return False
    
    def get_theme(self, theme_name: str = None) -> Dict[str, str]:
        """Get theme configuration"""
        if theme_name and theme_name in self.themes:
            return self.themes[theme_name]
        return self.current_theme
    
    def get_available_themes(self) -> Dict[str, Dict[str, str]]:
        """Get all available themes"""
        return self.themes
    
    def get_theme_names(self) -> list:
        """Get list of theme names"""
        return list(self.themes.keys())
    
    def get_color(self, color_type: str, theme_name: str = None) -> str:
        """Get specific color from theme"""
        theme = self.get_theme(theme_name)
        return theme.get(color_type, 'white')
    
    def create_gradient_style(self, start_color: str, end_color: str, steps: int = 5) -> list:
        """Create gradient color progression (simplified for terminal)"""
        # Terminal gradient simulation using available colors
        gradient_colors = []
        
        # Define color progressions for common gradients
        color_progressions = {
            ('blue', 'magenta'): ['blue', 'bright_blue', 'magenta', 'bright_magenta'],
            ('green', 'cyan'): ['green', 'bright_green', 'cyan', 'bright_cyan'],
            ('red', 'yellow'): ['red', 'bright_red', 'yellow', 'bright_yellow'],
            ('black', 'white'): ['black', 'dim white', 'white', 'bright_white']
        }
        
        # Find matching progression or return single colors
        for (start, end), progression in color_progressions.items():
            if start_color.endswith(start) and end_color.endswith(end):
                return progression[:steps]
        
        # Fallback to alternating between start and end colors
        return [start_color if i % 2 == 0 else end_color for i in range(steps)]
    
    def get_ascii_art_colors(self) -> Dict[str, str]:
        """Get colors specifically for ASCII art rendering"""
        theme_art_colors = {
            'matrix': {
                'primary': 'bright_green',
                'secondary': 'green',
                'accent': 'bright_cyan',
                'shadow': 'dim green'
            },
            'cyberpunk': {
                'primary': 'bright_magenta',
                'secondary': 'bright_blue',
                'accent': 'bright_cyan',
                'shadow': 'dim magenta'
            },
            'starlight': {
                'primary': 'bright_yellow',
                'secondary': 'bright_white',
                'accent': 'bright_blue',
                'shadow': 'dim white'
            }
        }
        
        return theme_art_colors.get(self.current_theme_name, theme_art_colors['cyberpunk'])
    
    def get_status_colors(self) -> Dict[str, str]:
        """Get colors for status indicators"""
        return {
            'online': self.current_theme['success'],
            'offline': self.current_theme['error'],
            'unknown': self.current_theme['warning'],
            'scanning': self.current_theme['info'],
            'vulnerable': self.current_theme['error'],
            'secure': self.current_theme['success'],
            'medium_risk': self.current_theme['warning'],
            'high_risk': self.current_theme['error'],
            'critical_risk': 'bold red'
        }
    
    def get_progress_colors(self) -> Dict[str, str]:
        """Get colors for progress indicators"""
        return {
            'complete': self.current_theme['success'],
            'processing': self.current_theme['info'],
            'waiting': self.current_theme['dim'],
            'error': self.current_theme['error']
        }
    
    def get_cyberpunk_panel_style(self) -> Dict[str, str]:
        """Get cyberpunk-specific panel styling"""
        styles = {
            'matrix': {
                'border': 'green',
                'title': 'bright_green',
                'content': 'white',
                'highlight': 'bright_cyan'
            },
            'cyberpunk': {
                'border': 'bright_magenta',
                'title': 'bright_blue',
                'content': 'white',
                'highlight': 'bright_magenta'
            },
            'starlight': {
                'border': 'bright_blue',
                'title': 'bright_yellow',
                'content': 'white',
                'highlight': 'bright_white'
            }
        }
        
        return styles.get(self.current_theme_name, styles['cyberpunk'])
    
    def get_table_style(self) -> Dict[str, str]:
        """Get table styling for current theme"""
        return {
            'header': self.current_theme['accent'],
            'border': self.current_theme['border'],
            'title': self.current_theme['primary'],
            'row': self.current_theme['text'],
            'row_alt': self.current_theme['dim'],
            'highlight': self.current_theme['highlight']
        }
    
    def apply_theme_to_text(self, text: str, style_type: str) -> str:
        """Apply theme styling to text"""
        color = self.get_color(style_type)
        return f"[{color}]{text}[/{color}]"
    
    def create_themed_border(self, width: int = 80, char: str = '═') -> str:
        """Create a themed border line"""
        border_color = self.current_theme['border']
        return f"[{border_color}]{char * width}[/{border_color}]"
    
    def create_themed_divider(self, title: str = "", width: int = 80) -> str:
        """Create a themed section divider"""
        if title:
            title_len = len(title)
            padding = (width - title_len - 2) // 2
            left_border = '═' * padding
            right_border = '═' * (width - title_len - 2 - padding)
            divider = f"{left_border} {title} {right_border}"
        else:
            divider = '═' * width
        
        return self.apply_theme_to_text(divider, 'border')
    
    def get_vulnerability_colors(self) -> Dict[str, str]:
        """Get colors for vulnerability severity levels"""
        return {
            'critical': 'bold red',
            'high': 'red',
            'medium': 'yellow',
            'low': 'green',
            'info': 'blue',
            'unknown': 'dim white'
        }
    
    def get_port_status_colors(self) -> Dict[str, str]:
        """Get colors for port status indicators"""
        return {
            'open': 'bright_green',
            'closed': 'red',
            'filtered': 'yellow',
            'unknown': 'dim white'
        }
    
    def get_device_type_colors(self) -> Dict[str, str]:
        """Get colors for different device types"""
        base_colors = {
            'server': 'bright_blue',
            'workstation': 'bright_green',
            'router': 'bright_yellow',
            'switch': 'bright_cyan',
            'printer': 'magenta',
            'iot': 'bright_red',
            'database': 'blue',
            'firewall': 'red',
            'unknown': 'dim white'
        }
        
        # Adapt colors to current theme
        if self.current_theme_name == 'matrix':
            # Matrix theme uses mostly green variations
            return {k: v.replace('bright_blue', 'bright_green').replace('blue', 'green') 
                   for k, v in base_colors.items()}
        elif self.current_theme_name == 'starlight':
            # Starlight theme emphasizes yellow and white
            return {k: v.replace('bright_red', 'bright_yellow').replace('red', 'yellow')
                   for k, v in base_colors.items()}
        
        return base_colors
    
    def create_banner_gradient(self, text_lines: list) -> list:
        """Apply gradient effect to banner text"""
        art_colors = self.get_ascii_art_colors()
        colored_lines = []
        
        total_lines = len(text_lines)
        for i, line in enumerate(text_lines):
            # Create gradient effect by cycling through colors
            if i < total_lines // 3:
                color = art_colors['primary']
            elif i < 2 * total_lines // 3:
                color = art_colors['secondary']
            else:
                color = art_colors['accent']
            
            colored_lines.append(f"[{color}]{line}[/{color}]")
        
        return colored_lines
    
    def get_risk_score_color(self, risk_score: float) -> str:
        """Get color based on risk score (0-10)"""
        if risk_score >= 8.0:
            return 'bold red'
        elif risk_score >= 6.0:
            return 'red'
        elif risk_score >= 4.0:
            return 'yellow'
        elif risk_score >= 2.0:
            return 'green'
        else:
            return 'bright_green'
    
    def get_confidence_color(self, confidence: float) -> str:
        """Get color based on confidence score (0-1)"""
        if confidence >= 0.8:
            return 'bright_green'
        elif confidence >= 0.6:
            return 'green'
        elif confidence >= 0.4:
            return 'yellow'
        else:
            return 'red'
    
    def create_progress_bar_style(self) -> Dict[str, str]:
        """Get progress bar styling for current theme"""
        return {
            'bar.complete': self.current_theme['success'],
            'bar.finished': self.current_theme['success'],
            'bar.pulse': self.current_theme['accent'],
            'progress.description': self.current_theme['text'],
            'progress.percentage': self.current_theme['accent'],
            'progress.data.speed': self.current_theme['info'],
            'progress.elapsed': self.current_theme['dim']
        }
    
    def export_theme_config(self) -> Dict[str, Any]:
        """Export current theme configuration"""
        return {
            'current_theme': self.current_theme_name,
            'theme_config': self.current_theme,
            'available_themes': list(self.themes.keys())
        }
    
    def import_theme_config(self, config: Dict[str, Any]) -> bool:
        """Import theme configuration"""
        try:
            if 'current_theme' in config and config['current_theme'] in self.themes:
                self.set_theme(config['current_theme'])
                return True
        except Exception:
            pass
        return False
