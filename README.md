# PC Helper Tools

A comprehensive Python script with cross-platform system utilities for both Windows and Linux systems. This tool provides an easy-to-use interface for system monitoring, maintenance, and diagnostics.

## Features

### 🖥️ System Information
- Complete system specifications (OS, CPU, RAM, Disk)
- Real-time CPU and memory usage monitoring
- Disk space analysis and usage statistics

### 🔄 Process Management
- View running processes with CPU and memory usage
- Kill processes by PID
- Process performance monitoring

### 🌐 Network Tools
- Ping hosts to check connectivity
- Port scanner to find open ports
- Network speed test and bandwidth monitoring
- Network diagnostics and troubleshooting

### 💾 Disk Management
- Find large files consuming disk space
- Clean up temporary files and cache
- Disk usage analysis

### 🏥 System Health Check
- Comprehensive system health monitoring
- Identify performance issues
- Memory and CPU usage alerts

### 📊 Real-time Monitoring
- Live system performance monitoring
- Real-time CPU, memory, and disk usage
- Top processes monitoring
- Network I/O statistics
- Customizable monitoring duration

### 🔐 Security Tools
- Secure password generator with customizable options
- File encryption and decryption
- Password strength analysis
- Secure file handling

### 💾 Backup & Restore
- Create compressed backups of files and directories
- Timestamped backup files
- Backup size reporting
- Support for both files and directories

### 🌡️ Hardware Monitoring
- CPU temperature monitoring
- Fan speed monitoring
- Battery status and charge level
- Hardware sensor information

### ⚡ System Optimizer
- Large log file detection
- Temporary file cleanup recommendations
- Disk fragmentation analysis (Windows)
- System optimization suggestions

### 🔧 Disk Defragmentation
- Windows disk defragmentation with built-in defrag utility
- Linux filesystem-specific defragmentation guidance
- Fragmentation analysis without defragmenting
- Support for ext4, XFS, Btrfs, and F2FS filesystems
- Cross-platform defragmentation recommendations

### 🔧 System Repair Tools
- SFC /scannow - System File Checker for Windows
- DISM repair - Windows image repair and restoration
- Automatic corruption detection and repair
- Administrator privilege validation
- Comprehensive error handling and troubleshooting

### 📋 Log Analyzer
- System log analysis for errors and warnings
- Cross-platform log directory support
- Error and warning pattern matching
- Log analysis summary reports

### 🚀 Startup Manager
- View system startup programs
- Windows and Linux startup location support
- Startup program management
- Service and application startup control

### 📊 Reporting
- Generate detailed system reports in JSON format
- Export system information for analysis
- Timestamped reports for tracking changes

## Installation

### Prerequisites
- Python 3.6 or higher
- pip (Python package installer)

### Setup
1. Clone or download this repository
2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Interactive Mode
Run the script without arguments to enter interactive mode:
```bash
python pc_helper_tools.py
```

### Command Line Mode
Use specific commands for quick operations:

```bash
# Show system information
python pc_helper_tools.py --info

# Run system health check
python pc_helper_tools.py --health

# Create system report
python pc_helper_tools.py --report

# Ping a host
python pc_helper_tools.py --ping google.com

# Scan ports on a host
python pc_helper_tools.py --scan 192.168.1.1
```

## Menu Options

1. **System Information** - Display comprehensive system details
2. **Process Management** - View and manage running processes
3. **Network Tools** - Ping hosts, scan ports, and test network speed
4. **Disk Management** - Clean up files and find large files
5. **System Health Check** - Run diagnostics and identify issues
6. **Real-time Monitoring** - Live system performance monitoring
7. **Security Tools** - Password generator and file encryption
8. **Backup & Restore** - Create and manage system backups
9. **Hardware Monitor** - Monitor temperature, fans, and battery
10. **System Optimizer** - System optimization and cleanup recommendations
11. **Log Analyzer** - Analyze system logs for errors and warnings
12. **Startup Manager** - Manage system startup programs
13. **Disk Defragmentation** - Analyze and defragment disk drives
14. **System Repair Tools** - SFC and DISM repair utilities
15. **Create System Report** - Generate detailed system report
16. **Exit** - Close the application

## Platform Support

- ✅ **Windows** (Windows 7, 8, 10, 11)
- ✅ **Linux** (Ubuntu, Debian, CentOS, Fedora, etc.)
- ❌ **macOS** (Not currently supported)

## Requirements

- `psutil` - Cross-platform library for system and process utilities

## Features by Platform

### Windows
- Windows-specific temporary file cleanup
- Windows service management
- Registry access (future enhancement)

### Linux
- Linux-specific temporary directory cleanup
- System service management
- Package management integration (future enhancement)

## Security Notes

- Some operations may require administrator/root privileges
- Process killing and system modifications require elevated permissions
- Network scanning should only be performed on authorized networks

## Troubleshooting

### Permission Errors
If you encounter permission errors:
- **Windows**: Run as Administrator
- **Linux**: Use `sudo` or run as root

### Missing Dependencies
If you get import errors:
```bash
pip install --upgrade psutil
```

### Network Issues
- Ensure firewall allows the application
- Check network connectivity before using network tools

## Contributing

Feel free to submit issues, feature requests, or pull requests to improve this tool.

## License

This project is open source and available under the MIT License.

## Version History

- **v2.0.0** - Major feature expansion
  - Real-time system monitoring with live updates
  - Security tools (password generator, file encryption/decryption)
  - Backup and restore functionality
  - Hardware monitoring (temperature, fans, battery)
  - System optimizer with cleanup recommendations
  - Log file analyzer for error detection
  - Startup program manager
  - Network speed testing
  - Enhanced user interface with 14 menu options

- **v1.0.0** - Initial release with core functionality
  - System information gathering
  - Process management
  - Network utilities
  - Disk management
  - Health monitoring
  - Interactive menu system
