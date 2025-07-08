from http.server import HTTPServer, BaseHTTPRequestHandler
from base64 import b64decode
import os
import argparse

class FileReceiverHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            raw_data = self.rfile.read(content_length)
            
            try:
                file_data = b64decode(raw_data, validate=True)
            except:
                file_data = raw_data
                filename = 'received_file.raw'
            
            with open(filename, 'wb') as f:
                f.write(file_data)
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"File saved as: " + filename.encode())
        except Exception as e:
            self.send_error(500, str(e))

def run_server(host='0.0.0.0', port=4444):
    server = HTTPServer((host, port), FileReceiverHandler)
    print(f"Server running on http://{host}:{port}")
    server.serve_forever()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind')
    parser.add_argument('--port', type=int, default=4444, help='Port to listen')
    args = parser.parse_args()
    
    run_server(args.host, args.port)