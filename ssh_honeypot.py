import logging
from logging.handlers import RotatingFileHandler
import socket
import paramiko
import threading
import time
import random
import re
from io import StringIO

# Configuration
SSH_BANNER = "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3"
HOST = "0.0.0.0"
PORT = 2222
USERNAME = "admin"
PASSWORD = "password"
COMMAND_TIMEOUT = 30
SESSION_DURATION_LIMIT = 600
MAX_LOGIN_ATTEMPTS = 5

# Enhanced logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler('ssh_audit.log', maxBytes=10 *
                            1024*1024, backupCount=5),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ssh_honeypot")

# More realistic fake filesystem
FAKE_FS = {
    '/': {
        'type': 'dir',
        'contents': ['bin', 'etc', 'home', 'tmp', 'usr', 'var'],
        'perms': 'drwxr-xr-x',
        'owner': 'root'
    },
    '/etc': {
        'type': 'dir',
        'contents': ['passwd', 'shadow', 'ssh', 'hosts'],
        'perms': 'drwxr-xr-x',
        'owner': 'root'
    },
    '/etc/passwd': {
        'type': 'file',
        'content': "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Admin User:/home/admin:/bin/bash",
        'perms': '-rw-r--r--',
        'owner': 'root'
    },
    '/etc/shadow': {
        'type': 'file',
        'content': "root:*:18295:0:99999:7:::\nadmin:$6$rounds=656000$V4M2X1XwYFZJkDf0$X5Jz7v8Qz3q9Q1w2E3r4T5y6U7i8O9p0A1S2D3F4G5H6J7K8L9Z0X1C2V3B4N5M:18295:0:99999:7:::",
        'perms': '-rw-r-----',
        'owner': 'root'
    },
    '/tmp': {
        'type': 'dir',
        'contents': [],
        'perms': 'drwxrwxrwt',
        'owner': 'root'
    }
}

# Enhanced malware patterns
MALWARE_PATTERNS = [
    r"(wget|curl)\s+(http|https|ftp)://",
    r"chmod\s+[+]x",
    r"(bash|sh)\s+-[ic]",
    r"python\d?\s+-c",
    r"perl\s+-e",
    r"rm\s+-rf",
    r"mkfifo",
    r"/dev/(tcp|udp)/",
    r"nc\s+.*(-l|-v|-p)",
    r"(exec|eval)\s+",
    r"echo\s+.*\s*>\s*/",
    r"\./.*\.(sh|py|pl)",
    r"sudo\s+.*(apt|yum|dnf)",
    r"useradd|adduser",
    r"passwd\s+.*--stdin",
    r"ssh-keygen\s+-t\s+rsa",
    r"cat\s+>/etc/crontab",
    r"chattr\s+[+]i"
]


class FakeShell:
    def __init__(self, channel, client_ip):
        self.channel = channel
        self.client_ip = client_ip
        self.cwd = '/'
        self.start_time = time.time()
        self.last_activity = time.time()
        self.session_active = True
        self.is_root = False
        self.username = USERNAME
        self.command_history = []

    def check_timeout(self):
        if time.time() - self.last_activity > COMMAND_TIMEOUT:
            logger.warning(f"Session timeout from {self.client_ip}")
            self.channel.send("\r\nSession timed out due to inactivity\r\n")
            return True
        if time.time() - self.start_time > SESSION_DURATION_LIMIT:
            logger.warning(
                f"Session duration limit reached from {self.client_ip}")
            self.channel.send("\r\nSession duration limit reached\r\n")
            return True
        return False

    def detect_malware(self, cmd):
        for pattern in MALWARE_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                logger.warning(
                    f"Malicious command detected from {self.client_ip}: {cmd}")
                return True
        return False

    def fake_sudo(self, cmd):
        if "sudo" in cmd and not self.is_root:
            self.channel.send(f"[sudo] password for {self.username}: ")
            password = ""
            while True:
                if self.channel.recv_ready():
                    char = self.channel.recv(1).decode()
                    if char in ('\r', '\n'):
                        break
                    password += char
                    self.channel.send("*")
                else:
                    time.sleep(0.1)
                    if self.check_timeout():
                        return False

            if password == PASSWORD:
                self.is_root = True
                logger.info(f"Successful sudo from {self.client_ip}")
                self.channel.send("\r\n")
                return True
            else:
                logger.warning(f"Failed sudo attempt from {self.client_ip}")
                self.channel.send("\r\nSorry, try again.\r\n")
                return False
        return True

    def handle_command(self, cmd):
        self.last_activity = time.time()
        self.command_history.append(cmd)

        if self.detect_malware(cmd):
            self.channel.send(
                "\r\nCommand contains suspicious patterns and was blocked\r\n")
            return

        if not self.fake_sudo(cmd):
            return

        cmd = cmd.replace("sudo", "").strip()

        if cmd == "exit":
            self.session_active = False
            self.channel.send("\r\nlogout\r\n")
        elif cmd == "whoami":
            self.channel.send(f"\r\n{self.username}\r\n")
        elif cmd == "id":
            self.handle_id()
        elif cmd in ("ls", "ls -la", "ls -l", "ll"):
            self.handle_ls(cmd)
        elif cmd.startswith("cd "):
            self.handle_cd(cmd)
        elif cmd.startswith("cat "):
            self.handle_cat(cmd)
        elif cmd.startswith("echo "):
            self.handle_echo(cmd)
        elif cmd == "pwd":
            self.channel.send(f"\r\n{self.cwd}\r\n")
        elif cmd in ("uname -a", "uname"):
            self.handle_uname()
        elif cmd in ("ps aux", "ps -ef"):
            self.handle_ps()
        elif cmd in ("ifconfig", "ip a", "ip addr"):
            self.handle_network()
        elif cmd in ("netstat -tuln", "netstat -an"):
            self.handle_netstat()
        elif cmd == "history":
            self.handle_history()
        elif cmd == "clear":
            self.channel.send("\x1b[H\x1b[J")
        elif cmd.startswith("wget ") or cmd.startswith("curl "):
            self.handle_download(cmd)
        elif cmd.startswith("rm "):
            self.handle_rm(cmd)
        elif cmd.startswith("chmod "):
            self.handle_chmod(cmd)
        elif cmd == "help":
            self.handle_help()
        elif cmd == "":
            pass
        else:
            self.channel.send(f"\r\n{cmd}: command not found\r\n")

    def handle_ls(self, cmd):
        long_format = "-l" in cmd or "ll" == cmd
        if self.cwd in FAKE_FS:
            contents = FAKE_FS[self.cwd]['contents']
            if long_format:
                output = StringIO()
                for item in contents:
                    path = f"{self.cwd}/{item}".replace("//", "/")
                    if path in FAKE_FS:
                        details = FAKE_FS[path]
                        output.write(
                            f"{details['perms']} 1 {details['owner']} {details['owner']} 4096 Jul 10 12:00 {item}\r\n")
                self.channel.send("\r\n" + output.getvalue())
            else:
                self.channel.send("\r\n" + "  ".join(contents) + "\r\n")
        else:
            self.channel.send(
                "\r\nls: cannot access directory: No such file or directory\r\n")

    def handle_cd(self, cmd):
        target = cmd[3:].strip()
        if target == "~":
            new_path = f"/home/{self.username}"
        elif target.startswith("/"):
            new_path = target
        else:
            new_path = f"{self.cwd}/{target}".replace("//", "/")

        if new_path in FAKE_FS and FAKE_FS[new_path]['type'] == 'dir':
            self.cwd = new_path
            self.channel.send("\r\n")
        else:
            self.channel.send(
                f"\r\ncd: {target}: No such file or directory\r\n")

    def handle_cat(self, cmd):
        target = cmd[4:].strip()
        path = f"{self.cwd}/{target}".replace("//", "/")

        if path in FAKE_FS and FAKE_FS[path]['type'] == 'file':
            self.channel.send("\r\n" + FAKE_FS[path]['content'] + "\r\n")
        else:
            self.channel.send(
                f"\r\ncat: {target}: No such file or directory\r\n")

    def handle_echo(self, cmd):
        text = cmd[5:]
        if text.strip().startswith("$(") or text.strip().startswith("`"):
            logger.warning(
                f"Command substitution attempt from {self.client_ip}: {cmd}")
            self.channel.send("\r\nCommand substitution not allowed\r\n")
        else:
            self.channel.send("\r\n" + text + "\r\n")

    def handle_ps(self):
        output = StringIO()
        output.write(
            "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\n")
        processes = [
            {"user": "root", "pid": 1, "name": "systemd", "cpu": "0.1", "mem": "0.5"},
            {"user": "root", "pid": 2, "name": "kthreadd",
                "cpu": "0.0", "mem": "0.0"},
            {"user": "root", "pid": 100, "name": "sshd", "cpu": "0.3", "mem": "1.2"},
            {"user": self.username, "pid": 101,
                "name": "bash", "cpu": "0.5", "mem": "0.8"}
        ]
        for proc in processes:
            output.write(
                f"{proc['user']:8} {proc['pid']:6} {proc['cpu']:4} {proc['mem']:4} 123456 65432 ?        S    12:00   0:00 {proc['name']}\r\n")
        self.channel.send("\r\n" + output.getvalue())

    def handle_network(self):
        self.channel.send(f"""
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.{random.randint(1, 254)}  netmask 255.255.255.0  broadcast 192.168.1.255
        ether 00:1{random.randint(10, 99)}:2{random.randint(10, 99)}:3{random.randint(10, 99)}:4{random.randint(10, 99)}:5{random.randint(10, 99)}
        RX packets {random.randint(1000, 9999)}  bytes {random.randint(1000000, 9999999)}
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets {random.randint(1000, 9999)}  bytes {random.randint(1000000, 9999999)}
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000
        RX packets 100  bytes 10000
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 100  bytes 10000
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
\r\n""")

    def handle_netstat(self):
        self.channel.send("""
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
tcp6       0      0 :::80                   :::*                    LISTEN     
udp        0      0 0.0.0.0:68              0.0.0.0:*                          
\r\n""")

    def handle_history(self):
        self.channel.send("\r\n".join(
            [f" {i+1}  {cmd}" for i, cmd in enumerate(self.command_history[-10:])]) + "\r\n")

    def handle_id(self):
        if self.is_root:
            self.channel.send("\r\nuid=0(root) gid=0(root) groups=0(root)\r\n")
        else:
            self.channel.send(
                f"\r\nuid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username})\r\n")

    def handle_uname(self):
        self.channel.send(
            "\r\nLinux fake-server 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux\r\n")

    def handle_download(self, cmd):
        logger.warning(f"Download attempt from {self.client_ip}: {cmd}")
        self.channel.send(
            "\r\nCommand blocked: direct downloads not allowed\r\n")

    def handle_rm(self, cmd):
        target = cmd[3:].strip()
        if target.startswith("-rf") or target.startswith("-fr"):
            logger.warning(
                f"Forceful deletion attempt from {self.client_ip}: {cmd}")
            self.channel.send("\r\nPermission denied\r\n")
        else:
            self.channel.send("\r\nrm: cannot remove: Permission denied\r\n")

    def handle_chmod(self, cmd):
        logger.warning(
            f"Permission change attempt from {self.client_ip}: {cmd}")
        self.channel.send(
            "\r\nchmod: changing permissions: Operation not permitted\r\n")

    def handle_help(self):
        self.channel.send("""
Available commands:
  ls, ll, ls -l    List directory contents
  cd <directory>   Change directory
  cat <file>       Display file contents
  echo <text>      Display text
  whoami           Show current user
  id               Show user and group info
  pwd              Print working directory
  ps aux           List processes
  ifconfig/ip a    Network information
  netstat -tuln    Network connections
  history          Show command history
  clear            Clear screen
  exit             End session
\r\n""")

    def run(self):
        try:
            welcome_msg = f"""
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 4.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of {time.strftime('%a %b %d %H:%M:%S %Z %Y')}

Last login: {time.strftime('%a %b %d %H:%M:%S %Y')} from {self.client_ip}
"""
            self.channel.send(welcome_msg)

            while self.session_active and not self.check_timeout():
                try:
                    prompt = f"\r\n{self.username}@{socket.gethostname()}:{self.cwd}# " if self.is_root else f"\r\n{self.username}@{socket.gethostname()}:{self.cwd}$ "
                    self.channel.send(prompt)

                    cmd = ""
                    while True:
                        if self.channel.recv_ready():
                            char = self.channel.recv(1).decode()
                            if char in ('\r', '\n'):
                                break
                            cmd += char
                        else:
                            time.sleep(0.1)
                            if self.check_timeout():
                                return

                    self.handle_command(cmd)
                except (socket.timeout, paramiko.SSHException) as e:
                    logger.error(
                        f"Error in session with {self.client_ip}: {e}")
                    break
        finally:
            duration = time.time() - self.start_time
            logger.info(
                f"Session ended with {self.client_ip} (Duration: {duration:.2f}s, Commands: {len(self.command_history)})")
            self.channel.close()


class SSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()
        self.login_attempts = 0
        self.last_attempt = 0
        self.username = None

    def check_auth_password(self, username, password):
        now = time.time()
        if now - self.last_attempt < 1:  # Rate limiting
            time.sleep(1)

        self.login_attempts += 1
        self.last_attempt = now
        self.username = username

        logger.info(
            f"Login attempt {self.login_attempts} from {self.client_ip}: {username}:{password}")

        if self.login_attempts >= MAX_LOGIN_ATTEMPTS:
            logger.warning(f"Too many login attempts from {self.client_ip}")
            return paramiko.AUTH_FAILED

        if username == USERNAME and password == PASSWORD:
            logger.info(
                f"Successful login from {self.client_ip} as {username}")
            return paramiko.AUTH_SUCCESSFUL

        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        logger.warning(
            f"Direct command execution attempt from {self.client_ip}: {command}")
        channel.send(f"Command execution not allowed: {command}\r\n")
        channel.send_close()
        return False


def handle_connection(client_sock, client_ip):
    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = SSH_BANNER

        # Generate host key if not exists
        host_key_path = "host_key"
        try:
            host_key = paramiko.RSAKey(filename=host_key_path)
        except:
            host_key = paramiko.RSAKey.generate(2048)
            host_key.write_private_key_file(host_key_path)
            logger.info("Generated new RSA host key")

        transport.add_server_key(host_key)

        server = SSHServer(client_ip)
        transport.start_server(server=server)

        channel = transport.accept(20)
        if channel:
            logger.info(f"New SSH session from {client_ip}")
            shell = FakeShell(channel, client_ip)
            if server.username:
                shell.username = server.username
            shell.run()
    except Exception as e:
        logger.error(f"Error handling connection from {client_ip}: {str(e)}")
    finally:
        try:
            client_sock.close()
        except:
            pass


def start_ssh_honeypot():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(100)

    logger.info(f"SSH Honeypot running on {HOST}:{PORT}")
    logger.info(f"Default credentials: {USERNAME}:{PASSWORD}")

    try:
        while True:
            client, addr = sock.accept()
            logger.info(f"New connection from {addr[0]}:{addr[1]}")
            threading.Thread(target=handle_connection, args=(
                client, addr[0]), daemon=True).start()
    except KeyboardInterrupt:
        logger.info("Shutting down honeypot...")
    finally:
        sock.close()


if __name__ == "__main__":
    start_ssh_honeypot()
