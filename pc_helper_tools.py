#!/usr/bin/env python3
"""
PC Helper Tools - Cross-platform system utilities for Windows and Linux
Author: AI Assistant
Description: A comprehensive collection of system management and diagnostic tools
"""

import os
import sys
import platform
import subprocess
import psutil
import shutil
import time
import json
import socket
import threading
import hashlib
import secrets
import string
import zipfile
import tempfile
import logging
import re
import urllib.request
import urllib.parse
from datetime import datetime, timedelta
from pathlib import Path
import argparse
import base64
import getpass

class PCHelperTools:
    def __init__(self):
        self.system = platform.system().lower()
        self.is_windows = self.system == 'windows'
        self.is_linux = self.system == 'linux'
        self.is_admin = self.check_admin_privileges()
    
    def check_admin_privileges(self):
        """Check if running with administrator privileges"""
        if self.is_windows:
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin()
            except:
                return False
        else:
            return os.geteuid() == 0
        
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if self.is_windows else 'clear')
    
    def print_banner(self):
        """Print the application banner"""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                    PC HELPER TOOLS                          ║
║              Cross-platform System Utilities                ║
║                    Windows & Linux                          ║
╚══════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def get_system_info(self):
        """Get comprehensive system information"""
        print("🖥️  SYSTEM INFORMATION")
        print("=" * 50)
        
        # Basic system info
        print(f"Operating System: {platform.system()} {platform.release()}")
        print(f"Architecture: {platform.machine()}")
        print(f"Processor: {platform.processor()}")
        print(f"Python Version: {platform.python_version()}")
        
        # CPU information
        print(f"\n💻 CPU Information:")
        print(f"Physical cores: {psutil.cpu_count(logical=False)}")
        print(f"Total cores: {psutil.cpu_count(logical=True)}")
        print(f"CPU Usage: {psutil.cpu_percent(interval=1)}%")
        
        # Memory information
        print(f"\n🧠 Memory Information:")
        memory = psutil.virtual_memory()
        print(f"Total RAM: {self.format_bytes(memory.total)}")
        print(f"Available RAM: {self.format_bytes(memory.available)}")
        print(f"Used RAM: {self.format_bytes(memory.used)}")
        print(f"Memory Usage: {memory.percent}%")
        
        # Disk information
        print(f"\n💾 Disk Information:")
        for partition in psutil.disk_partitions():
            try:
                partition_usage = psutil.disk_usage(partition.mountpoint)
                print(f"Drive: {partition.device}")
                print(f"  Total: {self.format_bytes(partition_usage.total)}")
                print(f"  Used: {self.format_bytes(partition_usage.used)}")
                print(f"  Free: {self.format_bytes(partition_usage.free)}")
                print(f"  Usage: {(partition_usage.used / partition_usage.total) * 100:.1f}%")
            except PermissionError:
                print(f"Drive: {partition.device} (Access Denied)")
    
    def format_bytes(self, bytes_value):
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f} PB"
    
    def get_process_info(self):
        """Display running processes"""
        print("🔄 RUNNING PROCESSES")
        print("=" * 50)
        
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Sort by CPU usage
        processes.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
        
        print(f"{'PID':<8} {'Name':<20} {'CPU%':<8} {'Memory%':<10}")
        print("-" * 50)
        
        for proc in processes[:20]:  # Show top 20 processes
            pid = proc['pid']
            name = proc['name'][:19] if proc['name'] else 'N/A'
            cpu = f"{proc['cpu_percent']:.1f}" if proc['cpu_percent'] else "0.0"
            memory = f"{proc['memory_percent']:.1f}" if proc['memory_percent'] else "0.0"
            print(f"{pid:<8} {name:<20} {cpu:<8} {memory:<10}")
    
    def kill_process(self, pid):
        """Kill a process by PID"""
        try:
            process = psutil.Process(pid)
            process.terminate()
            print(f"✅ Process {pid} terminated successfully")
        except psutil.NoSuchProcess:
            print(f"❌ Process {pid} not found")
        except psutil.AccessDenied:
            print(f"❌ Access denied. Try running as administrator/root")
    
    def network_scan(self, host="127.0.0.1", start_port=1, end_port=1000):
        """Scan for open ports on a host"""
        print(f"🌐 SCANNING PORTS ON {host}")
        print("=" * 50)
        
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        # Use threading for faster scanning
        threads = []
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=scan_port, args=(port,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        if open_ports:
            print(f"Open ports on {host}:")
            for port in sorted(open_ports):
                print(f"  Port {port}: Open")
        else:
            print(f"No open ports found on {host}")
    
    def ping_host(self, host):
        """Ping a host to check connectivity"""
        print(f"🏓 PINGING {host}")
        print("=" * 50)
        
        try:
            if self.is_windows:
                result = subprocess.run(['ping', '-n', '4', host], 
                                      capture_output=True, text=True, timeout=30)
            else:
                result = subprocess.run(['ping', '-c', '4', host], 
                                      capture_output=True, text=True, timeout=30)
            
            print(result.stdout)
            if result.returncode != 0:
                print(f"❌ Ping failed to {host}")
        except subprocess.TimeoutExpired:
            print(f"❌ Ping timeout to {host}")
        except Exception as e:
            print(f"❌ Error pinging {host}: {e}")
    
    def disk_cleanup(self):
        """Clean up temporary files and cache"""
        print("🧹 DISK CLEANUP")
        print("=" * 50)
        
        temp_dirs = []
        if self.is_windows:
            temp_dirs = [
                os.path.expandvars('%TEMP%'),
                os.path.expandvars('%TMP%'),
                os.path.expandvars('%WINDIR%\\Temp'),
                os.path.expandvars('%LOCALAPPDATA%\\Temp')
            ]
        else:
            temp_dirs = ['/tmp', '/var/tmp']
        
        total_freed = 0
        
        for temp_dir in temp_dirs:
            if os.path.exists(temp_dir):
                print(f"Cleaning: {temp_dir}")
                try:
                    for root, dirs, files in os.walk(temp_dir):
                        for file in files:
                            try:
                                file_path = os.path.join(root, file)
                                size = os.path.getsize(file_path)
                                os.remove(file_path)
                                total_freed += size
                            except (OSError, PermissionError):
                                pass
                except PermissionError:
                    print(f"  ⚠️  Access denied: {temp_dir}")
        
        print(f"✅ Cleanup completed. Freed: {self.format_bytes(total_freed)}")
    
    def find_large_files(self, directory=".", min_size_mb=100):
        """Find large files in a directory"""
        print(f"🔍 FINDING LARGE FILES (>={min_size_mb}MB)")
        print("=" * 50)
        
        min_size_bytes = min_size_mb * 1024 * 1024
        large_files = []
        
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    try:
                        file_path = os.path.join(root, file)
                        size = os.path.getsize(file_path)
                        if size >= min_size_bytes:
                            large_files.append((file_path, size))
                    except (OSError, PermissionError):
                        pass
        except PermissionError:
            print(f"❌ Access denied to directory: {directory}")
            return
        
        # Sort by size (largest first)
        large_files.sort(key=lambda x: x[1], reverse=True)
        
        if large_files:
            print(f"Found {len(large_files)} large files:")
            for file_path, size in large_files[:20]:  # Show top 20
                print(f"  {self.format_bytes(size):>10} - {file_path}")
        else:
            print(f"No files larger than {min_size_mb}MB found")
    
    def system_health_check(self):
        """Perform a comprehensive system health check"""
        print("🏥 SYSTEM HEALTH CHECK")
        print("=" * 50)
        
        issues = []
        
        # Check memory usage
        memory = psutil.virtual_memory()
        if memory.percent > 90:
            issues.append(f"⚠️  High memory usage: {memory.percent:.1f}%")
        
        # Check disk usage
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                usage_percent = (usage.used / usage.total) * 100
                if usage_percent > 90:
                    issues.append(f"⚠️  High disk usage on {partition.device}: {usage_percent:.1f}%")
            except PermissionError:
                pass
        
        # Check CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        if cpu_percent > 90:
            issues.append(f"⚠️  High CPU usage: {cpu_percent:.1f}%")
        
        # Check for high memory processes
        high_memory_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'memory_percent']):
            try:
                if proc.info['memory_percent'] and proc.info['memory_percent'] > 10:
                    high_memory_processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        if high_memory_processes:
            issues.append(f"⚠️  {len(high_memory_processes)} processes using >10% memory")
        
        if issues:
            print("Issues found:")
            for issue in issues:
                print(f"  {issue}")
        else:
            print("✅ System health check passed - no major issues found")
    
    def create_system_report(self):
        """Create a comprehensive system report"""
        print("📊 CREATING SYSTEM REPORT")
        print("=" * 50)
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "system": {
                "os": platform.system(),
                "release": platform.release(),
                "architecture": platform.machine(),
                "processor": platform.processor()
            },
            "hardware": {
                "cpu_cores": psutil.cpu_count(logical=False),
                "cpu_threads": psutil.cpu_count(logical=True),
                "memory_total": psutil.virtual_memory().total,
                "memory_available": psutil.virtual_memory().available
            },
            "performance": {
                "cpu_usage": psutil.cpu_percent(interval=1),
                "memory_usage": psutil.virtual_memory().percent
            }
        }
        
        # Add disk information
        report["storage"] = []
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                report["storage"].append({
                    "device": partition.device,
                    "total": usage.total,
                    "used": usage.used,
                    "free": usage.free,
                    "usage_percent": (usage.used / usage.total) * 100
                })
            except PermissionError:
                pass
        
        # Save report to file
        report_file = f"system_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"✅ System report saved to: {report_file}")
    
    def real_time_monitor(self, duration=60):
        """Real-time system monitoring with live updates"""
        print("📊 REAL-TIME SYSTEM MONITORING")
        print("=" * 50)
        print(f"Monitoring for {duration} seconds... Press Ctrl+C to stop early")
        print()
        
        # Prime CPU percent to avoid initial 0.0 readings and avoid blocking calls
        psutil.cpu_percent(interval=0.1)
        refresh_rate = 0.5  # seconds
        start_time = time.time()
        prev_net = psutil.net_io_counters()
        prev_time = start_time
        
        try:
            while time.time() - start_time < duration:
                now = time.time()
                elapsed = now - start_time
                remaining = max(0, duration - int(elapsed))
                delta_t = max(1e-6, now - prev_time)
                
                # Lightweight clear to reduce flicker (ANSI clear if supported)
                print("\033[2J\033[H", end='')
                print("📊 REAL-TIME SYSTEM MONITORING")
                print("=" * 50)
                print(f"Time remaining: {remaining} seconds")
                print()
                
                # CPU usage (non-blocking)
                cpu_percent = psutil.cpu_percent(interval=None)
                print(f"💻 CPU Usage: {cpu_percent:6.1f}% {'█' * int(cpu_percent/2)}")
                
                # Memory usage
                memory = psutil.virtual_memory()
                print(f"🧠 Memory:    {memory.percent:6.1f}% {'█' * int(memory.percent/2)}")
                
                # Disk usage (root/primary)
                try:
                    disk = psutil.disk_usage('/') if not self.is_windows else psutil.disk_usage('C:\\')
                    disk_percent = (disk.used / disk.total) * 100
                    print(f"💾 Disk:      {disk_percent:6.1f}% {'█' * int(disk_percent/2)}")
                except Exception:
                    print("💾 Disk:      N/A")
                
                # Network throughput (bytes/sec)
                net_io = psutil.net_io_counters()
                sent_rate = (net_io.bytes_sent - prev_net.bytes_sent) / delta_t
                recv_rate = (net_io.bytes_recv - prev_net.bytes_recv) / delta_t
                print(f"🌐 Network:   Up: {self.format_bytes(sent_rate)}/s  Down: {self.format_bytes(recv_rate)}/s")
                
                # Top processes (CPU)
                processes = []
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                    try:
                        cpu = proc.info['cpu_percent'] or 0.0
                        if cpu > 0:
                            processes.append(proc.info)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                processes.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
                print(f"\n🔥 Top CPU Processes:")
                for proc in processes[:5]:
                    name = proc['name'][:24] if proc['name'] else 'N/A'
                    cpu = proc['cpu_percent'] or 0.0
                    print(f"  {name:<24} {cpu:6.1f}%")
                
                # Update previous network snapshot
                prev_net = net_io
                prev_time = now
                
                time.sleep(refresh_rate)
        except KeyboardInterrupt:
            print("\n\n⏹️  Monitoring stopped by user")
    
    def generate_password(self, length=16, include_symbols=True, include_numbers=True, include_uppercase=True, include_lowercase=True):
        """Generate a secure password"""
        print("🔐 PASSWORD GENERATOR")
        print("=" * 50)
        
        characters = ""
        if include_lowercase:
            characters += string.ascii_lowercase
        if include_uppercase:
            characters += string.ascii_uppercase
        if include_numbers:
            characters += string.digits
        if include_symbols:
            characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        if not characters:
            print("❌ No character types selected")
            return
        
        password = ''.join(secrets.choice(characters) for _ in range(length))
        
        print(f"Generated Password ({length} characters):")
        print(f"🔑 {password}")
        print(f"\nPassword strength:")
        print(f"  Length: {length}")
        print(f"  Character set: {len(characters)} characters")
        print(f"  Entropy: {length * (len(characters) ** 0.5):.1f} bits")
        
        return password
    
    def encrypt_file(self, file_path, password):
        """Encrypt a file with password"""
        print("🔒 FILE ENCRYPTION")
        print("=" * 50)
        
        if not os.path.exists(file_path):
            print(f"❌ File not found: {file_path}")
            return
        
        try:
            # Read file
            with open(file_path, 'rb') as f:
                data = f.read()

            # Prefer strong encryption if cryptography is available
            try:
                from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.backends import default_backend
                from cryptography.fernet import Fernet
                salt = os.urandom(16)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=200_000,
                    backend=default_backend()
                )
                key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
                fernet = Fernet(key)
                token = fernet.encrypt(data)
                encrypted_path = file_path + '.encrypted'
                with open(encrypted_path, 'wb') as f:
                    f.write(b'FENC1' + salt + token)
                print(f"✅ File encrypted successfully (AES-128/256 via Fernet): {encrypted_path}")
                return
            except Exception:
                # Fallback to XOR with strong KDF, with clear warning
                salt = os.urandom(32)
                key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200_000)
                encrypted_data = bytearray()
                for i, byte in enumerate(data):
                    encrypted_data.append(byte ^ key[i % len(key)])
                encrypted_path = file_path + '.encrypted'
                with open(encrypted_path, 'wb') as f:
                    f.write(b'XENC1' + salt + encrypted_data)
                print("⚠️  cryptography not available; used fallback XOR. Install 'cryptography' for strong encryption.")
                print(f"✅ File encrypted: {encrypted_path}")
            
        except Exception as e:
            print(f"❌ Encryption failed: {e}")
    
    def decrypt_file(self, encrypted_path, password):
        """Decrypt a file with password"""
        print("🔓 FILE DECRYPTION")
        print("=" * 50)
        
        if not os.path.exists(encrypted_path):
            print(f"❌ Encrypted file not found: {encrypted_path}")
            return
        
        try:
            with open(encrypted_path, 'rb') as f:
                data = f.read()

            if data.startswith(b'FENC1'):
                salt = data[5:21]
                token = data[21:]
                try:
                    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                    from cryptography.hazmat.primitives import hashes
                    from cryptography.hazmat.backends import default_backend
                    from cryptography.fernet import Fernet
                except Exception:
                    print("❌ cryptography is required to decrypt this file")
                    return
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=200_000,
                    backend=default_backend()
                )
                key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
                fernet = Fernet(key)
                decrypted_data = fernet.decrypt(token)
                decrypted_path = encrypted_path.replace('.encrypted', '.decrypted')
                with open(decrypted_path, 'wb') as f:
                    f.write(decrypted_data)
                print(f"✅ File decrypted successfully: {decrypted_path}")
            elif data.startswith(b'XENC1'):
                salt = data[5:37]
                encrypted_data = data[37:]
                key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200_000)
                decrypted_data = bytearray()
                for i, byte in enumerate(encrypted_data):
                    decrypted_data.append(byte ^ key[i % len(key)])
                decrypted_path = encrypted_path.replace('.encrypted', '.decrypted')
                with open(decrypted_path, 'wb') as f:
                    f.write(decrypted_data)
                print("⚠️  Decrypted XOR-encrypted file. Consider re-encrypting with strong encryption.")
                print(f"✅ File decrypted successfully: {decrypted_path}")
            else:
                # Legacy format without header (assume old XOR with 32-byte salt)
                if len(data) < 32:
                    print("❌ Encrypted data too short or unrecognized format")
                    return
                salt = data[:32]
                encrypted_data = data[32:]
                key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000)
                decrypted_data = bytearray()
                for i, byte in enumerate(encrypted_data):
                    decrypted_data.append(byte ^ key[i % len(key)])
                decrypted_path = encrypted_path.replace('.encrypted', '.decrypted')
                with open(decrypted_path, 'wb') as f:
                    f.write(decrypted_data)
                print("⚠️  Decrypted legacy format (weak). Consider re-encrypting with strong encryption.")
                print(f"✅ File decrypted successfully: {decrypted_path}")
            
        except Exception as e:
            print(f"❌ Decryption failed: {e}")

    def check_password_strength(self, password):
        """Assess password strength and provide guidance"""
        print("🛡️  PASSWORD STRENGTH CHECK")
        print("=" * 50)
        score = 0
        length = len(password)
        categories = {
            'lower': any(c.islower() for c in password),
            'upper': any(c.isupper() for c in password),
            'digit': any(c.isdigit() for c in password),
            'symbol': any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?/" for c in password)
        }
        unique_chars = len(set(password))
        repeats = length - unique_chars
        if length >= 12: score += 2
        elif length >= 8: score += 1
        score += sum(1 for v in categories.values() if v)
        if repeats <= length * 0.2: score += 1
        print(f"Length: {length}")
        print(f"Character sets: lower={categories['lower']} upper={categories['upper']} digit={categories['digit']} symbol={categories['symbol']}")
        print(f"Unique characters: {unique_chars}")
        levels = {0: 'Very Weak', 1: 'Weak', 2: 'Fair', 3: 'Good', 4: 'Strong', 5: 'Very Strong'}
        print(f"Strength: {levels.get(score, 'Unknown')}")
        print("Recommendations:")
        if length < 12: print("  - Use at least 12 characters")
        if not categories['symbol']: print("  - Add symbols for complexity")
        if not categories['upper'] or not categories['lower']: print("  - Mix upper and lower case")
        if not categories['digit']: print("  - Include digits")
        if repeats > length * 0.2: print("  - Reduce repeated characters")

    def compute_file_hash(self, file_path, algo='sha256', chunk_size=1024*1024):
        """Compute file hash (default SHA-256)"""
        print("🔎 FILE HASH")
        print("=" * 50)
        if not os.path.exists(file_path):
            print(f"❌ File not found: {file_path}")
            return
        try:
            h = hashlib.new(algo)
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    h.update(chunk)
            print(f"Algorithm: {algo}")
            print(f"Path: {file_path}")
            print(f"Hash: {h.hexdigest()}")
        except Exception as e:
            print(f"❌ Hashing failed: {e}")

    def secure_delete(self, file_path, passes=1):
        """Securely delete a file by overwriting then removing"""
        print("🧹 SECURE DELETE")
        print("=" * 50)
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            print(f"❌ File not found: {file_path}")
            return
        try:
            size = os.path.getsize(file_path)
            with open(file_path, 'r+b', buffering=0) as f:
                for p in range(passes):
                    f.seek(0)
                    remaining = size
                    block = 1024 * 1024
                    while remaining > 0:
                        write_len = min(block, remaining)
                        f.write(os.urandom(write_len))
                        remaining -= write_len
            os.remove(file_path)
            print(f"✅ File securely deleted ({passes} passes)")
        except Exception as e:
            print(f"❌ Secure delete failed: {e}")

    def list_listening_ports(self):
        """List listening network ports and associated processes"""
        print("🔒 LISTENING PORTS")
        print("=" * 50)
        try:
            if self.is_windows:
                result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True, timeout=15)
                print(result.stdout)
            else:
                # Prefer ss if available
                try:
                    result = subprocess.run(['ss', '-tulpn'], capture_output=True, text=True, timeout=15)
                    if result.returncode == 0:
                        print(result.stdout)
                    else:
                        raise Exception('ss not available')
                except Exception:
                    result = subprocess.run(['netstat', '-tulpn'], capture_output=True, text=True, timeout=15)
                    print(result.stdout)
        except Exception as e:
            print(f"❌ Failed to list ports: {e}")
    
    def kill_port(self, port):
        """Kill the process using a specific port"""
        print(f"🔪 KILLING PROCESS ON PORT {port}")
        print("=" * 50)
        
        try:
            port = int(port)
        except (ValueError, TypeError):
            print(f"❌ Invalid port number: {port}")
            return
        
        pids = []
        
        try:
            if self.is_windows:
                # Find PID using netstat
                result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True, timeout=15)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if f':{port}' in line and 'LISTENING' in line:
                            parts = line.split()
                            if len(parts) > 0:
                                try:
                                    pid = int(parts[-1])
                                    if pid not in pids:
                                        pids.append(pid)
                                except (ValueError, IndexError):
                                    pass
                
                if not pids:
                    # Also check for ESTABLISHED connections
                    for line in lines:
                        if f':{port}' in line:
                            parts = line.split()
                            if len(parts) > 0:
                                try:
                                    pid = int(parts[-1])
                                    if pid not in pids:
                                        pids.append(pid)
                                except (ValueError, IndexError):
                                    pass
                
                if pids:
                    for pid in pids:
                        try:
                            # Try graceful termination first
                            process = psutil.Process(pid)
                            process_name = process.name()
                            print(f"Found process: {process_name} (PID: {pid})")
                            process.terminate()
                            try:
                                process.wait(timeout=3)
                                print(f"✅ Process {pid} ({process_name}) terminated successfully")
                            except psutil.TimeoutExpired:
                                # Force kill if graceful termination fails
                                process.kill()
                                print(f"✅ Process {pid} ({process_name}) force killed")
                        except psutil.NoSuchProcess:
                            print(f"⚠️  Process {pid} not found (may have already terminated)")
                        except psutil.AccessDenied:
                            # Try using taskkill as fallback
                            try:
                                result = subprocess.run(['taskkill', '/PID', str(pid), '/F'], 
                                                      capture_output=True, text=True, timeout=10)
                                if result.returncode == 0:
                                    print(f"✅ Process {pid} killed using taskkill")
                                else:
                                    print(f"❌ Failed to kill process {pid}: {result.stderr}")
                                    print("💡 Try running as Administrator")
                            except Exception as e:
                                print(f"❌ Failed to kill process {pid}: {e}")
                                print("💡 Try running as Administrator")
                        except Exception as e:
                            print(f"❌ Error killing process {pid}: {e}")
                else:
                    print(f"❌ No process found using port {port}")
            else:
                # Linux/Mac - try multiple methods
                # Method 1: lsof
                try:
                    result = subprocess.run(['lsof', '-ti', f':{port}'], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        pids = [int(pid.strip()) for pid in result.stdout.strip().split('\n') if pid.strip()]
                except (FileNotFoundError, subprocess.CalledProcessError):
                    pass
                
                # Method 2: fuser (if lsof didn't work)
                if not pids:
                    try:
                        result = subprocess.run(['fuser', f'{port}/tcp'], 
                                              capture_output=True, text=True, timeout=10)
                        if result.returncode == 0:
                            # fuser output format: "port/tcp:  1234  5678"
                            output = result.stdout.strip()
                            for line in output.split('\n'):
                                if ':' in line:
                                    pid_strs = line.split(':')[1].strip().split()
                                    pids = [int(pid) for pid in pid_strs if pid.isdigit()]
                                    break
                    except (FileNotFoundError, subprocess.CalledProcessError):
                        pass
                
                # Method 3: ss/netstat as fallback
                if not pids:
                    try:
                        result = subprocess.run(['ss', '-tulpn'], capture_output=True, text=True, timeout=15)
                        if result.returncode == 0:
                            for line in result.stdout.split('\n'):
                                if f':{port}' in line and 'LISTEN' in line:
                                    # Extract PID from output like "pid=1234"
                                    import re
                                    match = re.search(r'pid=(\d+)', line)
                                    if match:
                                        pids.append(int(match.group(1)))
                    except Exception:
                        pass
                
                if pids:
                    for pid in pids:
                        try:
                            process = psutil.Process(pid)
                            process_name = process.name()
                            print(f"Found process: {process_name} (PID: {pid})")
                            process.terminate()
                            try:
                                process.wait(timeout=3)
                                print(f"✅ Process {pid} ({process_name}) terminated successfully")
                            except psutil.TimeoutExpired:
                                process.kill()
                                print(f"✅ Process {pid} ({process_name}) force killed")
                        except psutil.NoSuchProcess:
                            print(f"⚠️  Process {pid} not found (may have already terminated)")
                        except psutil.AccessDenied:
                            print(f"❌ Access denied. Cannot kill process {pid}")
                            print("💡 Try running with sudo/root privileges")
                        except Exception as e:
                            print(f"❌ Error killing process {pid}: {e}")
                else:
                    print(f"❌ No process found using port {port}")
                    print("💡 Make sure the port number is correct and a process is listening on it")
        
        except Exception as e:
            print(f"❌ Failed to kill port {port}: {e}")

    def show_firewall_status(self):
        """Show firewall status"""
        print("🧱 FIREWALL STATUS")
        print("=" * 50)
        try:
            if self.is_windows:
                result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], capture_output=True, text=True, timeout=15)
                print(result.stdout)
            else:
                # Try ufw
                try:
                    result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=10)
                    print(result.stdout)
                except Exception:
                    result = subprocess.run(['iptables', '-L'], capture_output=True, text=True, timeout=10)
                    print(result.stdout)
        except Exception as e:
            print(f"❌ Failed to get firewall status: {e}")

    def run_quick_defender_scan(self):
        """Run a quick malware scan using Microsoft Defender (Windows)"""
        print("🦠 QUICK MALWARE SCAN (Windows Defender)")
        print("=" * 50)
        if not self.is_windows:
            print("❌ Windows Defender is only available on Windows systems")
            print("💡 On Linux, consider using:")
            print("   - ClamAV: sudo clamscan -r /")
            print("   - rkhunter: sudo rkhunter --check")
            print("   - chkrootkit: sudo chkrootkit")
            return
        try:
            candidates = [
                r"C:\\Program Files\\Windows Defender\\MpCmdRun.exe",
                r"C:\\Program Files\\Microsoft Defender\\MpCmdRun.exe",
                r"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MpCmdRun.exe",
            ]
            exe = None
            for p in candidates:
                if os.path.exists(p):
                    exe = p
                    break
            if not exe:
                print("❌ MpCmdRun.exe not found")
                return
            print("Starting quick scan... This may take a few minutes")
            result = subprocess.run([exe, '-Scan', '-ScanType', '1'], capture_output=True, text=True, timeout=1800)
            if result.returncode == 0:
                print("✅ Scan completed")
                print(result.stdout)
            else:
                print("❌ Scan failed")
                print(result.stdout or result.stderr)
        except subprocess.TimeoutExpired:
            print("⏰ Scan timed out")
        except Exception as e:
            print(f"❌ Defender scan error: {e}")
    
    def backup_files(self, source_path, backup_path):
        """Create a backup of files/directories"""
        print("💾 FILE BACKUP")
        print("=" * 50)
        
        if not os.path.exists(source_path):
            print(f"❌ Source path not found: {source_path}")
            return
        
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_name = f"backup_{timestamp}.zip"
            full_backup_path = os.path.join(backup_path, backup_name)
            
            # Create backup directory if it doesn't exist
            os.makedirs(backup_path, exist_ok=True)
            
            with zipfile.ZipFile(full_backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                if os.path.isfile(source_path):
                    zipf.write(source_path, os.path.basename(source_path))
                else:
                    for root, dirs, files in os.walk(source_path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arcname = os.path.relpath(file_path, source_path)
                            zipf.write(file_path, arcname)
            
            # Get backup size
            backup_size = os.path.getsize(full_backup_path)
            print(f"✅ Backup created successfully: {full_backup_path}")
            print(f"📦 Backup size: {self.format_bytes(backup_size)}")
            
        except Exception as e:
            print(f"❌ Backup failed: {e}")
    
    def network_speed_test(self):
        """Test network speed (simplified version)"""
        print("🌐 NETWORK SPEED TEST")
        print("=" * 50)
        
        # Test URLs for speed testing
        test_urls = [
            "http://speedtest.tele2.net/1MB.zip",
            "http://speedtest.tele2.net/10MB.zip"
        ]
        
        for url in test_urls:
            try:
                print(f"Testing with {url}...")
                start_time = time.time()
                
                with urllib.request.urlopen(url, timeout=30) as response:
                    data = response.read()
                
                end_time = time.time()
                duration = end_time - start_time
                size_mb = len(data) / (1024 * 1024)
                speed_mbps = (size_mb * 8) / duration
                
                print(f"  Size: {size_mb:.2f} MB")
                print(f"  Time: {duration:.2f} seconds")
                print(f"  Speed: {speed_mbps:.2f} Mbps")
                print()
                
            except Exception as e:
                print(f"  ❌ Test failed: {e}")
                print()
    
    def analyze_logs(self, log_directory="/var/log"):
        """Analyze system logs for errors and warnings"""
        print("📋 LOG FILE ANALYZER")
        print("=" * 50)
        
        if self.is_windows:
            log_directory = os.path.expandvars('%WINDIR%\\Logs')
        
        if not os.path.exists(log_directory):
            print(f"❌ Log directory not found: {log_directory}")
            return
        
        error_patterns = [
            r'error', r'ERROR', r'Error',
            r'fail', r'FAIL', r'Fail',
            r'critical', r'CRITICAL', r'Critical',
            r'exception', r'EXCEPTION', r'Exception'
        ]
        
        warning_patterns = [
            r'warn', r'WARN', r'Warn',
            r'warning', r'WARNING', r'Warning'
        ]
        
        error_count = 0
        warning_count = 0
        analyzed_files = 0
        
        print(f"Analyzing logs in: {log_directory}")
        print()
        
        for root, dirs, files in os.walk(log_directory):
            for file in files:
                if file.endswith(('.log', '.txt')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        file_errors = 0
                        file_warnings = 0
                        
                        for pattern in error_patterns:
                            file_errors += len(re.findall(pattern, content))
                        
                        for pattern in warning_patterns:
                            file_warnings += len(re.findall(pattern, content))
                        
                        if file_errors > 0 or file_warnings > 0:
                            print(f"📄 {os.path.basename(file_path)}")
                            print(f"   Errors: {file_errors}, Warnings: {file_warnings}")
                        
                        error_count += file_errors
                        warning_count += file_warnings
                        analyzed_files += 1
                        
                    except (PermissionError, UnicodeDecodeError):
                        pass
        
        print(f"\n📊 Analysis Summary:")
        print(f"  Files analyzed: {analyzed_files}")
        print(f"  Total errors: {error_count}")
        print(f"  Total warnings: {warning_count}")
    
    def startup_manager(self):
        """Manage system startup programs"""
        print("🚀 STARTUP MANAGER")
        print("=" * 50)
        
        if self.is_windows:
            # Windows startup locations
            startup_locations = [
                os.path.expandvars('%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
                os.path.expandvars('%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
                r'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run',
                r'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
            ]
            
            print("Windows Startup Programs:")
            for location in startup_locations:
                if os.path.exists(location):
                    print(f"\n📁 {location}")
                    try:
                        for item in os.listdir(location):
                            print(f"  • {item}")
                    except PermissionError:
                        print("  ⚠️  Access denied")
        else:
            # Linux startup locations
            startup_locations = [
                '/etc/init.d',
                '/etc/systemd/system',
                os.path.expanduser('~/.config/autostart'),
                os.path.expanduser('~/.local/share/applications')
            ]
            
            print("Linux Startup Programs:")
            for location in startup_locations:
                if os.path.exists(location):
                    print(f"\n📁 {location}")
                    try:
                        for item in os.listdir(location):
                            if item.endswith(('.service', '.desktop')):
                                print(f"  • {item}")
                    except PermissionError:
                        print("  ⚠️  Access denied")
    
    def hardware_monitor(self):
        """Monitor hardware sensors (temperature, fan speed)"""
        print("🌡️  HARDWARE MONITOR")
        print("=" * 50)
        
        try:
            # CPU details
            print("🧩 CPU:")
            try:
                physical = psutil.cpu_count(logical=False)
                logical = psutil.cpu_count(logical=True)
                print(f"  Cores: physical={physical}, logical={logical}")
            except Exception:
                pass
            try:
                freq = psutil.cpu_freq()
                if freq:
                    print(f"  Frequency: current={freq.current:.0f} MHz, min={freq.min:.0f} MHz, max={freq.max:.0f} MHz")
            except Exception:
                pass
            try:
                per_core = psutil.cpu_percent(percpu=True, interval=0.2)
                bars = ''.join('█' if p > 50 else '▓' if p > 25 else '░' for p in per_core)
                print(f"  Utilization per core: {', '.join(f'{p:.0f}%' for p in per_core)}")
                print(f"  Load bar: {bars}")
            except Exception:
                pass

            # CPU temperature
            if hasattr(psutil, 'sensors_temperatures'):
                temps = psutil.sensors_temperatures()
                if temps:
                    print("🌡️  Temperature Sensors:")
                    for name, entries in temps.items():
                        for entry in entries:
                            print(f"  {name}: {entry.current}°C (High: {entry.high}°C, Critical: {entry.critical}°C)")
                else:
                    print("❌ No temperature sensors found")
            
            # Fan speeds
            if hasattr(psutil, 'sensors_fans'):
                fans = psutil.sensors_fans()
                if fans:
                    print("\n🌀 Fan Speeds:")
                    for name, entries in fans.items():
                        for entry in entries:
                            print(f"  {name}: {entry.current} RPM")
                else:
                    print("❌ No fan sensors found")
            
            # Battery information
            if hasattr(psutil, 'sensors_battery'):
                battery = psutil.sensors_battery()
                if battery:
                    print(f"\n🔋 Battery:")
                    print(f"  Charge: {battery.percent}%")
                    print(f"  Status: {battery.power_plugged}")
                    if battery.secsleft != psutil.POWER_TIME_UNLIMITED:
                        print(f"  Time left: {battery.secsleft // 3600}h {(battery.secsleft % 3600) // 60}m")
                else:
                    print("❌ No battery information available")

            # Memory details
            try:
                mem = psutil.virtual_memory()
                swap = psutil.swap_memory()
                print("\n📦 Memory:")
                print(f"  RAM: total={self.format_bytes(mem.total)}, used={self.format_bytes(mem.used)} ({mem.percent}%)")
                print(f"  Swap: total={self.format_bytes(swap.total)}, used={self.format_bytes(swap.used)} ({swap.percent}%)")
            except Exception:
                pass

            # Disk I/O per device
            try:
                disk_io = psutil.disk_io_counters(perdisk=True)
                if disk_io:
                    print("\n💽 Disk I/O (cumulative):")
                    for dev, io in list(disk_io.items())[:10]:
                        print(f"  {dev}: read={self.format_bytes(io.read_bytes)}, write={self.format_bytes(io.write_bytes)}")
            except Exception:
                pass

            # GPU information (best effort)
            print("\n🎮 GPU:")
            gpu_reported = False
            try:
                # Try NVIDIA via nvidia-smi
                result = subprocess.run(['nvidia-smi', '--query-gpu=name,memory.total,memory.used,temperature.gpu,utilization.gpu', '--format=csv,noheader,nounits'], capture_output=True, text=True, timeout=3)
                if result.returncode == 0 and result.stdout.strip():
                    for line in result.stdout.strip().splitlines():
                        parts = [p.strip() for p in line.split(',')]
                        if len(parts) >= 5:
                            name, mem_total, mem_used, temp, util = parts[:5]
                            print(f"  {name}: util={util}% temp={temp}°C mem={mem_used}/{mem_total} MiB")
                            gpu_reported = True
            except Exception:
                pass
            if not gpu_reported and self.is_windows:
                try:
                    # Fallback via PowerShell CIM on Windows
                    ps_cmd = "Get-CimInstance Win32_VideoController | Select-Object Name, AdapterRAM"
                    result = subprocess.run(['powershell', '-NoProfile', '-Command', ps_cmd], capture_output=True, text=True, timeout=4)
                    if result.returncode == 0 and result.stdout.strip():
                        lines = [l for l in result.stdout.splitlines() if l.strip()]
                        for line in lines[2:]:
                            name = line.strip()
                            if name:
                                print(f"  {name}")
                                gpu_reported = True
                except Exception:
                    pass
            if not gpu_reported:
                print("  No GPU details available")
        
        except Exception as e:
            print(f"❌ Hardware monitoring failed: {e}")
    
    def system_optimizer(self):
        """System optimization and cleanup"""
        print("⚡ SYSTEM OPTIMIZER")
        print("=" * 50)
        
        optimizations = []
        
        # Check for large log files
        log_files = []
        if self.is_windows:
            log_dirs = [os.path.expandvars('%WINDIR%\\Logs')]
        else:
            log_dirs = ['/var/log', '/tmp']
        
        for log_dir in log_dirs:
            if os.path.exists(log_dir):
                for root, dirs, files in os.walk(log_dir):
                    for file in files:
                        if file.endswith('.log'):
                            file_path = os.path.join(root, file)
                            try:
                                size = os.path.getsize(file_path)
                                if size > 100 * 1024 * 1024:  # 100MB
                                    log_files.append((file_path, size))
                            except OSError:
                                pass
        
        if log_files:
            optimizations.append(f"Found {len(log_files)} large log files ({sum(size for _, size in log_files) / (1024*1024):.1f} MB)")
        
        # Check for temporary files
        temp_size = 0
        temp_files = 0
        temp_dirs = []
        
        if self.is_windows:
            temp_dirs = [
                os.path.expandvars('%TEMP%'),
                os.path.expandvars('%TMP%'),
                os.path.expandvars('%WINDIR%\\Temp')
            ]
        else:
            temp_dirs = ['/tmp', '/var/tmp']
        
        for temp_dir in temp_dirs:
            if os.path.exists(temp_dir):
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        try:
                            file_path = os.path.join(root, file)
                            size = os.path.getsize(file_path)
                            temp_size += size
                            temp_files += 1
                        except OSError:
                            pass
        
        if temp_files > 0:
            optimizations.append(f"Found {temp_files} temporary files ({temp_size / (1024*1024):.1f} MB)")
        
        # Check disk fragmentation (Windows only)
        if self.is_windows:
            try:
                result = subprocess.run(['defrag', '/A', 'C:'], capture_output=True, text=True)
                if 'fragmented' in result.stdout.lower():
                    optimizations.append("Disk fragmentation detected - consider defragmentation")
            except:
                pass
        
        # Display recommendations
        if optimizations:
            print("🔍 Optimization Recommendations:")
            for i, opt in enumerate(optimizations, 1):
                print(f"  {i}. {opt}")
            
            print(f"\n💡 Run disk cleanup to free up space")
        else:
            print("✅ System appears to be well optimized")
    
    def defragment_disk(self, drive=None):
        """Defragment disk drives"""
        print("🔧 DISK DEFRAGMENTATION")
        print("=" * 50)
        
        # Set default drive based on OS
        if drive is None:
            drive = "C:" if self.is_windows else "/"
        
        if self.is_windows:
            print(f"Defragmenting drive {drive}...")
            print("⚠️  This may take a while depending on disk size and fragmentation level")
            
            try:
                # Check if defrag is available
                result = subprocess.run(['defrag', '/A', drive], capture_output=True, text=True)
                
                # Check for privilege error first
                if "insufficient privileges" in result.stderr.lower() or "0x89000024" in result.stderr:
                    print("❌ Administrator privileges required for defragmentation")
                    print("\n💡 Solutions:")
                    print("  1. Run this script as Administrator:")
                    print("     - Right-click Command Prompt/PowerShell")
                    print("     - Select 'Run as administrator'")
                    print("     - Navigate to script directory and run: python pc_helper_tools.py")
                    print("  2. Use Windows built-in defrag tool:")
                    print("     - Press Win+R, type 'dfrgui' and press Enter")
                    print("     - Or search 'Defragment and Optimize Drives' in Start menu")
                    print("  3. Use PowerShell as Administrator:")
                    print("     - Optimize-Volume -DriveLetter C -Analyze")
                    return
                
                if result.returncode == 0 and 'fragmented' in result.stdout.lower():
                    print(f"Drive {drive} is fragmented. Starting defragmentation...")
                    print("⚠️  This process may take several hours for large drives")
                    print("💡 You can press Ctrl+C to cancel if needed")
                    
                    try:
                        # Run defragmentation with progress tracking
                        print(f"\n🔄 Starting defragmentation of {drive}...")
                        defrag_result = subprocess.run(['defrag', drive, '/D', '/U', '/V'], 
                                                    capture_output=True, text=True, timeout=7200)
                        
                        if defrag_result.returncode == 0:
                            print(f"✅ Defragmentation completed successfully for drive {drive}")
                            print("Defragmentation summary:")
                            print(defrag_result.stdout)
                        else:
                            print(f"❌ Defragmentation failed for drive {drive}")
                            print(f"Error: {defrag_result.stderr}")
                            
                            # Try alternative defrag method
                            print("\n🔄 Trying alternative defragmentation method...")
                            alt_result = subprocess.run(['defrag', drive, '/O'], 
                                                      capture_output=True, text=True, timeout=3600)
                            if alt_result.returncode == 0:
                                print(f"✅ Alternative optimization completed for drive {drive}")
                                print("Optimization summary:")
                                print(alt_result.stdout)
                            else:
                                print(f"❌ Alternative optimization also failed: {alt_result.stderr}")
                                
                    except subprocess.TimeoutExpired:
                        print(f"⏰ Defragmentation timed out for drive {drive}")
                        print("💡 This is normal for large drives. The process may still be running in the background.")
                    except KeyboardInterrupt:
                        print(f"\n⏹️  Defragmentation cancelled by user")
                        
                elif result.returncode == 0:
                    print(f"✅ Drive {drive} is already optimized - no defragmentation needed")
                    print("Analysis result:")
                    print(result.stdout)
                else:
                    print(f"❌ Analysis failed: {result.stderr}")
                    
            except subprocess.TimeoutExpired:
                print(f"⏰ Defragmentation timed out for drive {drive}")
                print("💡 Try running defragmentation manually or check if drive is in use")
            except FileNotFoundError:
                print("❌ Defrag utility not found. Please run as Administrator")
            except Exception as e:
                print(f"❌ Defragmentation failed: {e}")
                print("💡 Try running as Administrator or use Windows built-in tools")
        
        else:
            # Linux defragmentation
            print("Linux defragmentation options:")
            print("1. Check filesystem type")
            print("2. Run filesystem-specific optimization")
            print("3. Manual defragmentation commands")
            
            try:
                # Check filesystem type
                result = subprocess.run(['df', '-T', '/'], capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    if len(lines) > 1:
                        fs_type = lines[1].split()[1]
                        print(f"\n📁 Root filesystem type: {fs_type}")
                        
                        if fs_type in ['ext4', 'ext3', 'ext2']:
                            print("\nFor ext4/ext3/ext2 filesystems:")
                            print("  sudo e4defrag /")
                            print("  sudo e2fsck -f /dev/sda1")
                        elif fs_type in ['xfs']:
                            print("\nFor XFS filesystems:")
                            print("  sudo xfs_fsr /")
                        elif fs_type in ['btrfs']:
                            print("\nFor Btrfs filesystems:")
                            print("  sudo btrfs filesystem defrag /")
                        elif fs_type in ['f2fs']:
                            print("\nFor F2FS filesystems:")
                            print("  sudo f2fs_io defrag /")
                        else:
                            print(f"\n⚠️  Filesystem {fs_type} may not support defragmentation")
                            print("  Check your filesystem documentation for optimization options")
                
                # Check if any defrag tools are available
                defrag_tools = ['e4defrag', 'xfs_fsr', 'btrfs', 'f2fs_io']
                available_tools = []
                
                for tool in defrag_tools:
                    try:
                        subprocess.run(['which', tool], check=True, capture_output=True)
                        available_tools.append(tool)
                    except subprocess.CalledProcessError:
                        pass
                
                if available_tools:
                    print(f"\n🔧 Available defragmentation tools: {', '.join(available_tools)}")
                else:
                    print("\n❌ No defragmentation tools found")
                    print("  Install filesystem-specific tools:")
                    print("  - For ext4: sudo apt install e2fsprogs")
                    print("  - For XFS: sudo apt install xfsprogs")
                    print("  - For Btrfs: sudo apt install btrfs-progs")
                    print("  - For F2FS: sudo apt install f2fs-tools")
                
            except Exception as e:
                print(f"❌ Error checking filesystem: {e}")
    
    def analyze_disk_fragmentation(self, drive=None):
        """Analyze disk fragmentation without defragmenting"""
        print("📊 DISK FRAGMENTATION ANALYSIS")
        print("=" * 50)
        
        # Set default drive based on OS
        if drive is None:
            drive = "C:" if self.is_windows else "/"
        
        if self.is_windows:
            print(f"Analyzing fragmentation for drive {drive}...")
            try:
                result = subprocess.run(['defrag', '/A', drive], capture_output=True, text=True)
                if result.returncode == 0:
                    print("Fragmentation Analysis:")
                    print(result.stdout)
                    
                    # Parse fragmentation percentage
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'fragmented' in line.lower() and '%' in line:
                            print(f"\n📈 Fragmentation Status: {line.strip()}")
                            break
                else:
                    print(f"❌ Analysis failed: {result.stderr}")
                    
                    # Check for privilege error
                    if "insufficient privileges" in result.stderr.lower() or "0x89000024" in result.stderr:
                        print("\n⚠️  Administrator privileges required for defragmentation analysis")
                        print("💡 Solutions:")
                        print("  1. Run this script as Administrator")
                        print("  2. Use Windows built-in defrag tool:")
                        print(f"     - Press Win+R, type 'dfrgui' and press Enter")
                        print(f"     - Or search 'Defragment and Optimize Drives' in Start menu")
                        print("  3. Use PowerShell as Administrator:")
                        print(f"     - Get-Volume {drive[0]} | Get-Disk | Get-Partition | Get-Volume")
                        
                        # Alternative analysis using PowerShell
                        print(f"\n🔍 Attempting alternative analysis for drive {drive}...")
                        try:
                            ps_cmd = f"Get-Volume {drive[0]} | Select-Object DriveLetter, FileSystemLabel, Size, SizeRemaining, @{{Name='Fragmentation';Expression='N/A (requires admin)'}}"
                            ps_result = subprocess.run(['powershell', '-Command', ps_cmd], 
                                                    capture_output=True, text=True, timeout=30)
                            if ps_result.returncode == 0:
                                print("Drive Information:")
                                print(ps_result.stdout)
                            else:
                                print("❌ Alternative analysis also failed")
                        except Exception as ps_e:
                            print(f"❌ PowerShell analysis failed: {ps_e}")
                    
            except Exception as e:
                print(f"❌ Analysis error: {e}")
                print("\n💡 Try running as Administrator or use Windows built-in tools")
    
    def show_defrag_alternatives(self, drive=None):
        """Show alternative defragmentation methods when admin privileges are not available"""
        print("🔧 ALTERNATIVE DEFRAGMENTATION METHODS")
        print("=" * 50)
        
        # Set default drive based on OS
        if drive is None:
            drive = "C:" if self.is_windows else "/"
        
        if self.is_windows:
            print("Since you don't have Administrator privileges, here are alternative methods:")
            print()
            print("1. 🖥️  Windows Built-in Defrag Tool:")
            print("   - Press Win+R, type 'dfrgui' and press Enter")
            print("   - Or search 'Defragment and Optimize Drives' in Start menu")
            print("   - Select your drive and click 'Optimize'")
            print()
            print("2. 💻 PowerShell (Run as Administrator):")
            print(f"   - Open PowerShell as Administrator")
            print(f"   - Run: Optimize-Volume -DriveLetter {drive[0]} -Analyze")
            print(f"   - Run: Optimize-Volume -DriveLetter {drive[0]} -Defrag")
            print()
            print("3. 🖱️  File Explorer Method:")
            print(f"   - Right-click on {drive} in File Explorer")
            print("   - Select 'Properties' > 'Tools' tab")
            print("   - Click 'Optimize' under 'Optimize and defragment drive'")
            print()
            print("4. 🔧 Command Prompt (Run as Administrator):")
            print(f"   - Open Command Prompt as Administrator")
            print(f"   - Run: defrag {drive} /A (to analyze)")
            print(f"   - Run: defrag {drive} /D /U /V (to defragment with progress)")
            print()
            print("5. 📊 Third-party Tools:")
            print("   - Auslogics Disk Defrag")
            print("   - Defraggler")
            print("   - Smart Defrag")
            print("   - MyDefrag")
        
        else:
            print("Linux defragmentation methods:")
            print("1. Check filesystem type: df -T /")
            print("2. Use filesystem-specific tools:")
            print("   - ext4: sudo e4defrag /")
            print("   - XFS: sudo xfs_fsr /")
            print("   - Btrfs: sudo btrfs filesystem defrag /")
            print("   - F2FS: sudo f2fs_io defrag /")
    
    def run_sfc_scannow(self):
        """Run System File Checker to scan and repair system files"""
        print("🔍 SYSTEM FILE CHECKER (SFC /SCANNOW)")
        print("=" * 50)
        
        if not self.is_windows:
            print("❌ SFC is only available on Windows systems")
            return
        
        if not self.is_admin:
            print("⚠️  Administrator privileges required for SFC scan")
            print("💡 Please run this script as Administrator")
            return
        
        print("🔄 Starting System File Checker scan...")
        print("⚠️  This may take 15-30 minutes depending on system size")
        print("💡 You can press Ctrl+C to cancel if needed")
        print()
        
        try:
            # Run SFC /scannow
            print("🔍 Scanning system files for corruption...")
            sfc_result = subprocess.run(['sfc', '/scannow'], 
                                      capture_output=True, text=True, timeout=1800)
            
            if sfc_result.returncode == 0:
                print("✅ SFC scan completed successfully")
                print("System File Checker Results:")
                print(sfc_result.stdout)
                
                # Check if any files were repaired
                if "found corrupt files" in sfc_result.stdout.lower():
                    print("\n🔧 Some corrupt files were found and repaired")
                    print("💡 You may need to restart your computer for changes to take effect")
                elif "did not find any integrity violations" in sfc_result.stdout.lower():
                    print("\n✅ No corrupt files found - system is healthy")
                else:
                    print("\n📋 Check the output above for detailed results")
                    
            else:
                print("❌ SFC scan failed")
                print(f"Error: {sfc_result.stderr}")
                print("\n💡 Common solutions:")
                print("  1. Run Command Prompt as Administrator")
                print("  2. Try running: DISM /Online /Cleanup-Image /RestoreHealth")
                print("  3. Check if Windows Update is running")
                print("  4. Restart computer and try again")
                
        except subprocess.TimeoutExpired:
            print("⏰ SFC scan timed out (30 minutes)")
            print("💡 This is normal for large systems. The scan may still be running in the background.")
        except KeyboardInterrupt:
            print("\n⏹️  SFC scan cancelled by user")
        except Exception as e:
            print(f"❌ SFC scan error: {e}")
    
    def run_dism_repair(self):
        """Run DISM to repair Windows image"""
        print("🔧 DISM REPAIR (DISM /Online /Cleanup-Image /RestoreHealth)")
        print("=" * 50)
        
        if not self.is_windows:
            print("❌ DISM is only available on Windows systems")
            return
        
        if not self.is_admin:
            print("⚠️  Administrator privileges required for DISM repair")
            print("💡 Please run this script as Administrator")
            return
        
        print("🔄 Starting DISM repair...")
        print("⚠️  This may take 30-60 minutes depending on system size")
        print("💡 You can press Ctrl+C to cancel if needed")
        print()
        
        try:
            # Run DISM repair
            print("🔧 Repairing Windows image...")
            dism_result = subprocess.run(['DISM', '/Online', '/Cleanup-Image', '/RestoreHealth'], 
                                       capture_output=True, text=True, timeout=3600)
            
            if dism_result.returncode == 0:
                print("✅ DISM repair completed successfully")
                print("DISM Repair Results:")
                print(dism_result.stdout)
                
                # Check if repair was successful
                if "restore operation completed successfully" in dism_result.stdout.lower():
                    print("\n✅ Windows image repair completed successfully")
                    print("💡 You may need to restart your computer for changes to take effect")
                else:
                    print("\n📋 Check the output above for detailed results")
                    
            else:
                print("❌ DISM repair failed")
                print(f"Error: {dism_result.stderr}")
                print("\n💡 Common solutions:")
                print("  1. Ensure you have internet connection")
                print("  2. Try running: DISM /Online /Cleanup-Image /CheckHealth")
                print("  3. Check Windows Update service")
                print("  4. Restart computer and try again")
                
        except subprocess.TimeoutExpired:
            print("⏰ DISM repair timed out (60 minutes)")
            print("💡 This is normal for large systems. The repair may still be running in the background.")
        except KeyboardInterrupt:
            print("\n⏹️  DISM repair cancelled by user")
        except Exception as e:
            print(f"❌ DISM repair error: {e}")
    
    def show_menu(self):
        """Display the main menu"""
        admin_status = "Admin" if self.is_admin else "Standard"
        os_name = f"{platform.system()} {platform.release()}"
        menu = f"""
╔══════════════════════════════════════════════════════════════╗
║                        MAIN MENU                             ║
╠══════════════════════════════════════════════════════════════╣
║  Status: {os_name} • {admin_status}                                  ║
╠══════════════════════════════════════════════════════════════╣
║  1. System Information                                       ║
║  2. System Health Check                                      ║
║  3. Real-time Monitoring                                     ║
║  4. Hardware Monitor                                         ║
║  5. Process Management                                       ║
║  6. Network Tools                                            ║
║  7. Disk Management                                          ║
║  8. Disk Defragmentation                                     ║
║  9. System Optimizer                                         ║
║ 10. Startup Manager                                          ║
║ 11. Security Tools                                           ║
║ 12. Backup & Restore                                         ║
║ 13. Log Analyzer                                             ║
║ 14. System Repair Tools                                      ║
║ 15. Create System Report                                     ║
║ 16. Exit                                                     ║
╚══════════════════════════════════════════════════════════════╝
        """
        print(menu)
    
    def run(self):
        """Main application loop"""
        self.clear_screen()
        self.print_banner()
        
        while True:
            self.show_menu()
            choice = input("\nEnter your choice (1-16): ").strip()
            
            if choice == '1':
                self.clear_screen()
                self.get_system_info()
                input("\nPress Enter to continue...")
                self.clear_screen()
            
            elif choice == '2':
                self.clear_screen()
                self.system_health_check()
                input("\nPress Enter to continue...")
                self.clear_screen()
            
            elif choice == '3':
                self.clear_screen()
                try:
                    duration = int(input("Enter monitoring duration in seconds (default: 60): ") or "60")
                    self.real_time_monitor(duration)
                except ValueError:
                    print("❌ Invalid duration")
                input("\nPress Enter to continue...")
                self.clear_screen()
            
            elif choice == '4':
                self.clear_screen()
                self.hardware_monitor()
                input("\nPress Enter to continue...")
                self.clear_screen()
            
            elif choice == '5':
                self.clear_screen()
                self.get_process_info()
                print("\nOptions:")
                print("1. Kill a process by PID")
                print("2. Return to main menu")
                sub_choice = input("Enter choice: ").strip()
                if sub_choice == '1':
                    try:
                        pid = int(input("Enter PID to kill: "))
                        self.kill_process(pid)
                    except ValueError:
                        print("❌ Invalid PID")
                input("\nPress Enter to continue...")
                self.clear_screen()
            
            elif choice == '6':
                self.clear_screen()
                print("🌐 NETWORK TOOLS")
                print("=" * 50)
                print("1. Ping a host")
                print("2. Port scanner")
                print("3. Network speed test")
                print("4. Return to main menu")
                sub_choice = input("Enter choice: ").strip()
                
                if sub_choice == '1':
                    host = input("Enter host to ping: ").strip()
                    if host:
                        self.ping_host(host)
                elif sub_choice == '2':
                    host = input("Enter host to scan (default: 127.0.0.1): ").strip() or "127.0.0.1"
                    try:
                        start_port = int(input("Start port (default: 1): ") or "1")
                        end_port = int(input("End port (default: 1000): ") or "1000")
                        self.network_scan(host, start_port, end_port)
                    except ValueError:
                        print("❌ Invalid port numbers")
                elif sub_choice == '3':
                    self.network_speed_test()
                
                input("\nPress Enter to continue...")
                self.clear_screen()
            
            elif choice == '7':
                self.clear_screen()
                print("💾 DISK MANAGEMENT")
                print("=" * 50)
                print("1. Disk cleanup")
                print("2. Find large files")
                print("3. Return to main menu")
                sub_choice = input("Enter choice: ").strip()
                
                if sub_choice == '1':
                    self.disk_cleanup()
                elif sub_choice == '2':
                    directory = input("Enter directory to scan (default: current): ").strip() or "."
                    try:
                        min_size = int(input("Minimum file size in MB (default: 100): ") or "100")
                        self.find_large_files(directory, min_size)
                    except ValueError:
                        print("❌ Invalid size")
                
                input("\nPress Enter to continue...")
                self.clear_screen()
            
            elif choice == '11':
                self.clear_screen()
                print("🔐 SECURITY TOOLS")
                print("=" * 50)
                print("1. Generate Password")
                print("2. Check Password Strength")
                print("3. Encrypt File (secure)")
                print("4. Decrypt File")
                print("5. File Hash (SHA-256)")
                print("6. Secure Delete File")
                print("7. List Listening Ports")
                print("8. Firewall Status")
                print("9. Quick Malware Scan (Windows Defender)")
                print("10. Return to main menu")
                sub_choice = input("Enter choice: ").strip()
                
                if sub_choice == '1':
                    try:
                        length = int(input("Password length (default: 16): ") or "16")
                        self.generate_password(length)
                    except ValueError:
                        print("❌ Invalid length")
                elif sub_choice == '2':
                    pwd = getpass.getpass("Enter password to evaluate: ")
                    self.check_password_strength(pwd)
                elif sub_choice == '3':
                    file_path = input("Enter file path to encrypt: ").strip()
                    password = getpass.getpass("Enter password: ")
                    if file_path and password:
                        self.encrypt_file(file_path, password)
                elif sub_choice == '4':
                    file_path = input("Enter encrypted file path: ").strip()
                    password = getpass.getpass("Enter password: ")
                    if file_path and password:
                        self.decrypt_file(file_path, password)
                elif sub_choice == '5':
                    file_path = input("Enter file path to hash: ").strip()
                    if file_path:
                        self.compute_file_hash(file_path)
                elif sub_choice == '6':
                    file_path = input("Enter file path to securely delete: ").strip()
                    try:
                        passes = int(input("Overwrite passes (default: 1): ") or "1")
                    except ValueError:
                        passes = 1
                    if file_path:
                        self.secure_delete(file_path, passes)
                elif sub_choice == '7':
                    self.list_listening_ports()
                elif sub_choice == '8':
                    self.show_firewall_status()
                elif sub_choice == '9':
                    self.run_quick_defender_scan()
                
                input("\nPress Enter to continue...")
                self.clear_screen()
            
            elif choice == '12':
                self.clear_screen()
                print("💾 BACKUP & RESTORE")
                print("=" * 50)
                source = input("Enter source path to backup: ").strip()
                backup_dir = input("Enter backup directory: ").strip()
                if source and backup_dir:
                    self.backup_files(source, backup_dir)
                input("\nPress Enter to continue...")
                self.clear_screen()
            
            elif choice == '9':
                self.clear_screen()
                self.system_optimizer()
                input("\nPress Enter to continue...")
                self.clear_screen()
            
            elif choice == '13':
                self.clear_screen()
                log_dir = input("Enter log directory (default: system default): ").strip()
                if log_dir:
                    self.analyze_logs(log_dir)
                else:
                    self.analyze_logs()
                input("\nPress Enter to continue...")
                self.clear_screen()
            
            elif choice == '10':
                self.clear_screen()
                self.startup_manager()
                input("\nPress Enter to continue...")
                self.clear_screen()
            
            elif choice == '8':
                self.clear_screen()
                print("🔧 DISK DEFRAGMENTATION")
                print("=" * 50)
                
                # Show admin status
                if self.is_windows:
                    if self.is_admin:
                        print("✅ Running with Administrator privileges")
                    else:
                        print("⚠️  Not running as Administrator - some features may be limited")
                        print("💡 For full defragmentation features, run as Administrator")
                
                print("\n1. Analyze disk fragmentation")
                print("2. Defragment disk")
                print("3. Show alternative methods")
                print("4. Return to main menu")
                sub_choice = input("Enter choice: ").strip()
                
                if sub_choice == '1':
                    if self.is_windows:
                        default_drive = "C:" if self.is_windows else "/"
                        drive = input(f"Enter drive (default: {default_drive}): ").strip() or default_drive
                        self.analyze_disk_fragmentation(drive)
                    else:
                        self.analyze_disk_fragmentation()
                elif sub_choice == '2':
                    if self.is_windows:
                        default_drive = "C:" if self.is_windows else "/"
                        drive = input(f"Enter drive (default: {default_drive}): ").strip() or default_drive
                        confirm = input(f"⚠️  Defragmenting {drive} may take a long time. Continue? (y/N): ").strip().lower()
                        if confirm == 'y':
                            self.defragment_disk(drive)
                        else:
                            print("Defragmentation cancelled")
                    else:
                        print("Linux defragmentation requires manual commands.")
                        print("Use the analysis option to get specific commands for your filesystem.")
                        self.defragment_disk()
                elif sub_choice == '3':
                    if self.is_windows:
                        default_drive = "C:" if self.is_windows else "/"
                        drive = input(f"Enter drive (default: {default_drive}): ").strip() or default_drive
                        self.show_defrag_alternatives(drive)
                    else:
                        self.show_defrag_alternatives()
                
                input("\nPress Enter to continue...")
                self.clear_screen()
            
            elif choice == '14':
                self.clear_screen()
                print("🔧 SYSTEM REPAIR TOOLS")
                print("=" * 50)
                
                # Show admin status
                if self.is_windows:
                    if self.is_admin:
                        print("✅ Running with Administrator privileges")
                    else:
                        print("⚠️  Not running as Administrator - repair tools require admin access")
                        print("💡 For full repair features, run as Administrator")
                
                print("\n1. SFC /scannow (System File Checker)")
                print("2. DISM Repair (Windows Image Repair)")
                print("3. Return to main menu")
                sub_choice = input("Enter choice: ").strip()
                
                if sub_choice == '1':
                    self.run_sfc_scannow()
                elif sub_choice == '2':
                    self.run_dism_repair()
                
                input("\nPress Enter to continue...")
                self.clear_screen()
            
            elif choice == '15':
                self.clear_screen()
                self.create_system_report()
                input("\nPress Enter to continue...")
                self.clear_screen()
            
            elif choice == '16':
                print("\n👋 Goodbye!")
                break
            
            else:
                print("❌ Invalid choice. Please try again.")
                time.sleep(1)
                self.clear_screen()

def main():
    """Main function with command line argument support"""
    parser = argparse.ArgumentParser(description='PC Helper Tools - System utilities')
    parser.add_argument('--info', action='store_true', help='Show system information and exit')
    parser.add_argument('--health', action='store_true', help='Run health check and exit')
    parser.add_argument('--report', action='store_true', help='Create system report and exit')
    parser.add_argument('--ping', type=str, help='Ping a host and exit')
    parser.add_argument('--scan', type=str, help='Scan ports on a host and exit')
    
    args = parser.parse_args()
    tools = PCHelperTools()
    
    if args.info:
        tools.get_system_info()
    elif args.health:
        tools.system_health_check()
    elif args.report:
        tools.create_system_report()
    elif args.ping:
        tools.ping_host(args.ping)
    elif args.scan:
        tools.network_scan(args.scan)
    else:
        tools.run()

if __name__ == "__main__":
    main()
