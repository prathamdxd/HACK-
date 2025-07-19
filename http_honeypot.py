from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
from urllib.parse import urlparse, parse_qs

HOST = "0.0.0.0"
PORT = 8080

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler('http_audit.log'),
        logging.StreamHandler()
    ]
)


class FakeHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        client_ip = self.client_address[0]
        logging.info(f"GET request from {client_ip} - Path: {self.path}")
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"<h1>Welcome to Fake Web Server</h1>")

    def do_POST(self):
        client_ip = self.client_address[0]
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode()
        logging.info(f"POST request from {client_ip} - Data: {post_data}")
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"<h1>Login Successful (Not Really)</h1>")


def run_http_honeypot():
    server = HTTPServer((HOST, PORT), FakeHTTPHandler)
    logging.info(f"HTTP Honeypot running on {HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    run_http_honeypot()
