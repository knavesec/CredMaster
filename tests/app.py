from http.server import BaseHTTPRequestHandler, HTTPServer
import sys
from urllib.parse import urlparse, parse_qs


USERS = [
            ("user1@corp.local", "user1!"),
            ("user2@corp.local", "Uz3r2@"),
            ("user1@other.local", "otherPassword")
        ]

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Set response headers
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        # Check the path and respond accordingly
        if self.path == '/check':
            self.wfile.write(b'Endpoint /check reached!')
        elif self.path.startswith('/login'):
            # Parse the URL parameters
            params = parse_qs(urlparse(self.path).query)
            
            # Check if both 'username' and 'password' parameters are present
            if 'username' in params and 'password' in params:
                username = params['username'][0]
                password = params['password'][0]
                if (username, password) in USERS:
                    response = f'Greetings, {username}!'
                elif not username in [x[0] for x in USERS]:
                    response = f'Password is invalid'
                else:
                    response = 'Nope'
                self.wfile.write(response.encode('utf-8'))
            else:
                self.wfile.write(b'Missing username or password parameters!')
        else:
            self.wfile.write(b'Hello, this is a simple server!')

if __name__ == '__main__':
    port = 28514
    try:
        if len(sys.argv) == 2:
            port = int(sys.argv[1])
            assert port > 1024 and port < 65535
    except:
        pass
    # Specify the server address and port
    server_address = ('0.0.0.0', port)
    
    # Create an HTTP server with the specified handler
    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)

    print(f'Server is running on http://0.0.0.0:{port}')
    
    # Start the server
    httpd.serve_forever()
