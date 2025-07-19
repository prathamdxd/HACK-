import logging
from logging.handlers import RotatingFileHandler
import socket
import paramiko
import threading
from pathlib import Path

# Configuration
SSH_BANNER = "SSH-2.0-OpenSSH_7.6p1"
HOST = "0.0.0.0"
PORT = 2222
USERNAME = "admin"  # Default username
PASSWORD = "password"  # Default password

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        RotatingFileHandler('ssh_audit.log', maxBytes=10000, backupCount=3),
        logging.StreamHandler()
    ]
)

# Fake filesystem
FAKE_FS = {
    '/': ['home', 'etc', 'readme.txt'],
    '/home': ['user1', 'user2'],
    '/etc': ['passwd', 'shadow']
}


class FakeShell:
    def __init__(self, channel, client_ip):
        self.channel = channel
        self.client_ip = client_ip
        self.cwd = '/'

    def run(self):
        self.channel.send("Welcome to Ubuntu 20.04 LTS (Fake SSH Server)\r\n")
        while True:
            self.channel.send(f"user@{self.client_ip}:{self.cwd}$ ")
            cmd = ""
            while True:
                char = self.channel.recv(1).decode()
                if char == '\r' or char == '\n':
                    break
                cmd += char

            if cmd == "exit":
                self.channel.send("Goodbye!\r\n")
                break
            elif cmd == "ls":
                files = FAKE_FS.get(self.cwd, [])
                self.channel.send("\r\n" + "\r\n".join(files) + "\r\n")
            elif cmd.startswith("cd "):
                new_dir = cmd[3:].strip()
                new_path = (self.cwd + '/' + new_dir).replace('//', '/')
                if new_path in FAKE_FS:
                    self.cwd = new_path
                    self.channel.send(f"Changed to {new_path}\r\n")
                else:
                    self.channel.send("Directory not found\r\n")
            else:
                self.channel.send(f"Command not found: {cmd}\r\n")


class SSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        logging.info(
            f"Login attempt: {username}:{password} from {self.client_ip}")
        if username == USERNAME and password == PASSWORD:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    # Add these two methods to fix PTY issues
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True  # Allow PTY allocation

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True  # Allow shell requests


def handle_connection(client_sock, client_ip):
    try:
        transport = paramiko.Transport(client_sock)
        transport.add_server_key(paramiko.RSAKey.generate(2048))
        transport.start_server(server=SSHServer(client_ip))

        channel = transport.accept(20)
        if channel:
            shell = FakeShell(channel, client_ip)
            shell.run()
            channel.close()
    except Exception as e:
        logging.error(f"Error: {e}")
    finally:
        client_sock.close()


def start_ssh_honeypot():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(100)
    logging.info(f"SSH Honeypot running on {HOST}:{PORT}")

    while True:
        client, addr = sock.accept()
        threading.Thread(target=handle_connection,
                         args=(client, addr[0])).start()


if __name__ == "__main__":
    start_ssh_honeypot()
