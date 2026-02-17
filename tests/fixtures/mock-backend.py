#!/usr/bin/env python3
"""
Simple mock backend for testing Zentinel inline OpenAPI validation.
Echoes back received requests as JSON.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sys

class MockBackendHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Custom log format
        sys.stderr.write(f"[BACKEND] {format % args}\n")

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else '{}'

        try:
            data = json.loads(body)
        except:
            data = {}

        # Echo back the request with a success response
        response = {
            "status": "success",
            "message": "User created successfully",
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "received": data
        }

        self.send_response(201)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response, indent=2).encode())

    def do_GET(self):
        # Return a list of users
        response = {
            "users": [
                {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "email": "user1@example.com",
                    "username": "user1",
                    "created_at": "2024-01-01T00:00:00Z"
                },
                {
                    "id": "550e8400-e29b-41d4-a716-446655440001",
                    "email": "user2@example.com",
                    "username": "user2",
                    "created_at": "2024-01-02T00:00:00Z"
                }
            ]
        }

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response, indent=2).encode())

def run_server(port=3001):
    server = HTTPServer(('127.0.0.1', port), MockBackendHandler)
    print(f"[BACKEND] Starting mock backend on http://127.0.0.1:{port}")
    print(f"[BACKEND] Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[BACKEND] Shutting down...")
        server.shutdown()

if __name__ == '__main__':
    run_server()
