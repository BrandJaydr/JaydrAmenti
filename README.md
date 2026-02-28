# Cyber Amenti v1.0 (Maze Mouse)

**Red Team Network Intelligence Gathering Tool**

Cyber Amenti is a comprehensive red team tool designed for network reconnaissance, device profiling, and exploit correlation. It combines the power of `nmap` and `netcat` with advanced intelligence gathering capabilities, all wrapped in a highly interactive and customizable cyberpunk-themed CLI.

## 🚀 Features

- **Advanced Network Scanning**: Full `nmap` integration for discovery, port scanning, OS detection, and firewall evasion.
- **Netcat Operations**: Interactive management of `netcat` for connectivity testing, banner grabbing, listeners, and tunneling.
- **Automated Device Profiling**: Intelligent fingerprinting that classifies devices (Server, Workstation, IoT, Router, etc.) and calculates risk scores.
- **Vulnerability Correlation**: Automatically maps discovered services to known CVEs and identifies available exploits.
- **Sherlock OSINT Integration**: Hunt down social media accounts by username across hundreds of platforms.
- **Intelligence Dossiers**: Create, manage, and export detailed intelligence reports in JSON, HTML, or CSV formats.
- **Cyberpunk UI**: Responsive CLI with multiple themes (Matrix, Cyberpunk, Starlight) and multi-language support (EN, ES, FR, DE).

## 🛠 Installation

### Prerequisites

- **Python**: 3.11+
- **System Tools**: 
  - `nmap` (Network Mapper)
  - `nc` (Netcat)

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/jaydrnexus/cyber-amenti.git
   cd cyber-amenti
   ```

2. Install dependencies:
   ```bash
   pip install -e .
   ```
   *Note: If using `uv`, run `uv sync`.*

## 🖥 Usage

Start the application by running:

```bash
python3 main.py
```

### Main Menu Options

1. **Scan Network Targets**: Access comprehensive nmap scanning suites.
2. **Netcat Operations**: Perform manual network probing and data transfer tests.
3. **Device Profiles**: View and manage the database of fingerprinted devices.
4. **Exploit Database**: Search for vulnerabilities and cross-reference with exploits.
5. **Intelligence Dossiers**: Group scan results into organized mission reports.
6. **Sherlock Search**: Perform OSINT username lookups.
7. **Settings**: Customize the interface theme and language.

## 📂 Project Structure

- `main.py`: Entry point and main menu logic.
- `src/core/`: Core functional modules (Scanner, Profiler, Exploits, Netcat, Sherlock).
- `src/ui/`: Interactive interface and theme management.
- `src/utils/`: Database, translation, and configuration helpers.
- `locales/`: i18n translation files.
- `data/`: SQLite database storage.

## ⚠️ Requirements & Permissions

- **Nmap**: Some advanced scan types (like OS detection) require root/sudo privileges.
- **Keyboard Hotkeys**: The global termination hotkey (`Ctrl+C` by default) may require root privileges on Linux to intercept system-level interrupts.

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Created by Jaydr Nexus**  
*Unveiling the Hidden Layers of the Network.*
