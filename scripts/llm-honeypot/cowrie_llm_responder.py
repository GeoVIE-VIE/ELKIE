#!/usr/bin/env python3
"""
Cowrie LLM Responder - High-Interaction SSH Honeypot with Local LLM

This creates an SSH honeypot that uses a local LLM (via Ollama) to generate
realistic responses to attacker commands, providing high-interaction
honeypot capabilities without API costs.

Designed for: Dual Xeon Platinum 8168 (48 cores, 96GB RAM)
"""

import asyncio
import asyncssh
import json
import logging
import os
import re
import signal
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from llm_client import HoneypotLLMClient, LLMConfig, get_client

# Configure logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("cowrie-llm")


class HoneypotConfig:
    """Configuration for the SSH honeypot."""

    def __init__(self):
        self.ssh_port = int(os.getenv("SSH_PORT", "8022"))
        self.telnet_port = int(os.getenv("TELNET_PORT", "8023"))
        self.host_key_path = os.getenv("HOST_KEY_PATH", "/app/ssh_host_key")
        self.log_path = Path(os.getenv("LOG_PATH", "/var/log/cowrie-llm"))

        # Fake system info
        self.hostname = os.getenv("FAKE_HOSTNAME", "ubuntu-server-01")
        self.os_name = "Ubuntu 22.04.3 LTS"
        self.kernel = "5.15.0-91-generic"

        # Credential database - common weak credentials that attackers try
        self.valid_credentials = self._load_credentials()

        # LLM settings
        self.llm_config = LLMConfig(
            ollama_host=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
            model=os.getenv("LLM_MODEL", "mistral:7b-instruct-v0.2-q4_K_M"),
            redis_host=os.getenv("REDIS_HOST", "redis"),
            max_tokens=int(os.getenv("LLM_MAX_TOKENS", "512")),
            temperature=float(os.getenv("LLM_TEMPERATURE", "0.7")),
        )

        # Elasticsearch for logging
        self.elasticsearch_host = os.getenv("ELASTICSEARCH_HOST", "")

    def _load_credentials(self) -> Dict[str, str]:
        """Load valid credentials for the honeypot."""
        # These are intentionally weak credentials that attackers commonly try
        default_creds = {
            "root": ["root", "toor", "password", "123456", "admin", ""],
            "admin": ["admin", "password", "123456", "admin123"],
            "user": ["user", "password", "123456"],
            "ubuntu": ["ubuntu", "password"],
            "pi": ["raspberry", "pi"],
            "oracle": ["oracle", "password"],
            "postgres": ["postgres", "password"],
            "mysql": ["mysql", "password"],
        }
        return default_creds


class SessionLogger:
    """Logs honeypot sessions in JSON format for Elasticsearch ingestion."""

    def __init__(self, log_path: Path):
        self.log_path = log_path
        self.log_path.mkdir(parents=True, exist_ok=True)
        self.session_file = self.log_path / "sessions.jsonl"
        self.command_file = self.log_path / "commands.jsonl"

    def log_session_start(self, session_data: Dict[str, Any]):
        """Log session start event."""
        event = {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": "session.start",
            "honeypot_type": "cowrie-llm",
            **session_data
        }
        self._write_event(self.session_file, event)
        logger.info(f"Session started: {session_data.get('session_id')} from {session_data.get('src_ip')}")

    def log_login_attempt(self, session_id: str, src_ip: str, username: str, password: str, success: bool):
        """Log authentication attempt."""
        event = {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": "login.attempt",
            "honeypot_type": "cowrie-llm",
            "session_id": session_id,
            "src_ip": src_ip,
            "username": username,
            "password": password,
            "success": success
        }
        self._write_event(self.session_file, event)
        status = "SUCCESS" if success else "FAILED"
        logger.info(f"Login {status}: {username}:{password} from {src_ip}")

    def log_command(self, session_id: str, src_ip: str, username: str,
                    command: str, response: str, source: str, latency_ms: int):
        """Log command execution."""
        event = {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": "command.input",
            "honeypot_type": "cowrie-llm",
            "session_id": session_id,
            "src_ip": src_ip,
            "username": username,
            "command": command,
            "response_source": source,
            "response_latency_ms": latency_ms,
            "response_length": len(response)
        }
        self._write_event(self.command_file, event)

        # Also log response separately for analysis
        response_event = {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": "command.output",
            "honeypot_type": "cowrie-llm",
            "session_id": session_id,
            "command": command,
            "response": response[:2000],  # Truncate long responses
        }
        self._write_event(self.command_file, response_event)

    def log_session_end(self, session_id: str, src_ip: str, duration_seconds: int, command_count: int):
        """Log session end event."""
        event = {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": "session.end",
            "honeypot_type": "cowrie-llm",
            "session_id": session_id,
            "src_ip": src_ip,
            "duration_seconds": duration_seconds,
            "command_count": command_count
        }
        self._write_event(self.session_file, event)
        logger.info(f"Session ended: {session_id}, duration: {duration_seconds}s, commands: {command_count}")

    def _write_event(self, filepath: Path, event: Dict[str, Any]):
        """Write event to JSONL file."""
        with open(filepath, "a") as f:
            f.write(json.dumps(event) + "\n")


class FakeFilesystem:
    """Simulated filesystem for the honeypot."""

    def __init__(self):
        self.cwd = "/root"
        # Simulated directory structure
        self.directories = {
            "/": ["bin", "boot", "dev", "etc", "home", "lib", "lib64", "media",
                  "mnt", "opt", "proc", "root", "run", "sbin", "srv", "sys",
                  "tmp", "usr", "var"],
            "/root": [".bashrc", ".bash_history", ".profile", ".ssh", "scripts"],
            "/root/.ssh": ["authorized_keys", "known_hosts"],
            "/home": ["ubuntu", "admin"],
            "/etc": ["passwd", "shadow", "group", "hosts", "hostname", "resolv.conf",
                    "ssh", "nginx", "apache2", "mysql", "cron.d"],
            "/var": ["log", "www", "lib", "cache", "tmp"],
            "/var/log": ["syslog", "auth.log", "kern.log", "dpkg.log", "apt"],
            "/var/www": ["html"],
            "/var/www/html": ["index.html", "info.php"],
            "/tmp": [],
        }

    def resolve_path(self, path: str) -> str:
        """Resolve relative path to absolute."""
        if path.startswith("/"):
            return os.path.normpath(path)
        return os.path.normpath(os.path.join(self.cwd, path))

    def list_directory(self, path: str = None) -> Optional[str]:
        """Generate ls output for a directory."""
        target = self.resolve_path(path) if path else self.cwd
        if target in self.directories:
            items = self.directories[target]
            return "  ".join(items) if items else ""
        return None

    def change_directory(self, path: str) -> tuple[bool, str]:
        """Change current directory."""
        new_path = self.resolve_path(path)
        if new_path in self.directories or new_path == "/":
            self.cwd = new_path
            return True, new_path
        return False, f"bash: cd: {path}: No such file or directory"


class HoneypotSSHServer(asyncssh.SSHServer):
    """SSH server that accepts connections and validates credentials."""

    def __init__(self, config: HoneypotConfig, session_logger: SessionLogger):
        self.config = config
        self.session_logger = session_logger
        self._session_id = str(uuid.uuid4())[:8]
        self._client_ip = None
        self._username = None
        self._authenticated = False

    def connection_made(self, conn):
        """Called when connection is established."""
        peername = conn.get_extra_info('peername')
        self._client_ip = peername[0] if peername else "unknown"
        logger.debug(f"Connection from {self._client_ip}")

    def connection_lost(self, exc):
        """Called when connection is lost."""
        if exc:
            logger.debug(f"Connection lost from {self._client_ip}: {exc}")

    def begin_auth(self, username: str) -> bool:
        """Called when authentication begins. Return True to require auth."""
        self._username = username
        return True

    def password_auth_supported(self) -> bool:
        """Password authentication is supported."""
        return True

    def validate_password(self, username: str, password: str) -> bool:
        """Validate username/password credentials."""
        valid_passwords = self.config.valid_credentials.get(username, [])
        success = password in valid_passwords

        self.session_logger.log_login_attempt(
            session_id=self._session_id,
            src_ip=self._client_ip,
            username=username,
            password=password,
            success=success
        )

        if success:
            self._authenticated = True
            self._username = username

        return success


class HoneypotShellSession:
    """Interactive shell session with LLM-powered responses."""

    def __init__(
        self,
        process: asyncssh.SSHServerProcess,
        config: HoneypotConfig,
        session_logger: SessionLogger,
        session_id: str,
        client_ip: str,
        username: str
    ):
        self.process = process
        self.config = config
        self.session_logger = session_logger
        self.session_id = session_id
        self.client_ip = client_ip
        self.username = username
        self.filesystem = FakeFilesystem()
        self.command_count = 0
        self.start_time = datetime.now()
        self.llm_client: Optional[HoneypotLLMClient] = None

    async def run(self):
        """Run the interactive shell session."""
        # Initialize LLM client
        self.llm_client = await get_client(self.config.llm_config)

        # Log session start
        self.session_logger.log_session_start({
            "session_id": self.session_id,
            "src_ip": self.client_ip,
            "username": self.username,
            "protocol": "ssh"
        })

        # Send welcome banner
        await self._send_banner()

        # Main command loop
        try:
            while True:
                prompt = self._get_prompt()
                self.process.stdout.write(prompt)

                try:
                    command = await asyncio.wait_for(
                        self._read_line(),
                        timeout=300  # 5 minute timeout
                    )
                except asyncio.TimeoutError:
                    self.process.stdout.write("\nConnection timed out.\n")
                    break

                if command is None:
                    break

                command = command.strip()
                if not command:
                    continue

                # Handle exit commands
                if command.lower() in ("exit", "logout", "quit"):
                    self.process.stdout.write("logout\n")
                    break

                # Process command
                response = await self._process_command(command)

                # Output response
                if response:
                    self.process.stdout.write(response)
                    if not response.endswith("\n"):
                        self.process.stdout.write("\n")

                self.command_count += 1

        except asyncssh.BreakReceived:
            pass
        except Exception as e:
            logger.error(f"Session error: {e}")
        finally:
            # Log session end
            duration = int((datetime.now() - self.start_time).total_seconds())
            self.session_logger.log_session_end(
                self.session_id,
                self.client_ip,
                duration,
                self.command_count
            )
            self.process.exit(0)

    async def _send_banner(self):
        """Send login banner."""
        banner = f"""Welcome to {self.config.os_name} ({self.config.kernel})

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Last login: {self._fake_last_login()} from {self._fake_previous_ip()}
"""
        self.process.stdout.write(banner)

    def _fake_last_login(self) -> str:
        """Generate fake last login time."""
        from datetime import timedelta
        import random
        fake_time = datetime.now() - timedelta(hours=random.randint(1, 48))
        return fake_time.strftime("%a %b %d %H:%M:%S %Y")

    def _fake_previous_ip(self) -> str:
        """Generate fake previous IP."""
        import random
        return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    def _get_prompt(self) -> str:
        """Generate shell prompt."""
        user_char = "#" if self.username == "root" else "$"
        return f"{self.username}@{self.config.hostname}:{self.filesystem.cwd}{user_char} "

    async def _read_line(self) -> Optional[str]:
        """Read a line of input from the client."""
        line = ""
        while True:
            try:
                data = await self.process.stdin.read(1)
                if not data:
                    return None

                char = data

                # Handle special characters
                if char == "\r" or char == "\n":
                    self.process.stdout.write("\n")
                    return line
                elif char == "\x03":  # Ctrl+C
                    self.process.stdout.write("^C\n")
                    return ""
                elif char == "\x04":  # Ctrl+D
                    return None
                elif char == "\x7f" or char == "\b":  # Backspace
                    if line:
                        line = line[:-1]
                        self.process.stdout.write("\b \b")
                else:
                    line += char
                    self.process.stdout.write(char)

            except Exception:
                return None

    async def _process_command(self, command: str) -> str:
        """Process a command and return the response."""

        # Handle built-in commands first (cd, etc.)
        builtin_response = self._handle_builtin(command)
        if builtin_response is not None:
            return builtin_response

        # Use LLM for complex commands
        result = await self.llm_client.generate_response(
            command=command,
            session_id=self.session_id,
            src_ip=self.client_ip,
            username=self.username
        )

        # Log the command
        self.session_logger.log_command(
            session_id=self.session_id,
            src_ip=self.client_ip,
            username=self.username,
            command=command,
            response=result.get("response", ""),
            source=result.get("source", "unknown"),
            latency_ms=result.get("latency_ms", 0)
        )

        return result.get("response", "")

    def _handle_builtin(self, command: str) -> Optional[str]:
        """Handle built-in shell commands."""
        parts = command.split()
        if not parts:
            return ""

        cmd = parts[0]

        # cd command
        if cmd == "cd":
            if len(parts) == 1:
                path = "/root" if self.username == "root" else f"/home/{self.username}"
            else:
                path = parts[1]

            success, result = self.filesystem.change_directory(path)
            if success:
                # Update LLM client context
                asyncio.create_task(
                    self.llm_client.update_session_cwd(self.session_id, result)
                )
                return ""
            return result

        # clear command
        if cmd == "clear":
            return "\033[2J\033[H"

        # history command
        if cmd == "history":
            return self._fake_history()

        return None

    def _fake_history(self) -> str:
        """Generate fake command history."""
        fake_commands = [
            "ls -la",
            "cd /var/log",
            "tail -f syslog",
            "systemctl status nginx",
            "df -h",
            "free -m",
            "top",
            "ps aux",
            "netstat -tulpn",
            "cat /etc/passwd",
        ]
        lines = []
        for i, cmd in enumerate(fake_commands, 1):
            lines.append(f"  {i}  {cmd}")
        return "\n".join(lines)


async def handle_client(process: asyncssh.SSHServerProcess):
    """Handle an SSH client connection."""
    # Get server info from connection
    server = process.get_extra_info('ssh_server')
    if not isinstance(server, HoneypotSSHServer):
        process.exit(1)
        return

    session = HoneypotShellSession(
        process=process,
        config=server.config,
        session_logger=server.session_logger,
        session_id=server._session_id,
        client_ip=server._client_ip,
        username=server._username or "root"
    )
    await session.run()


class SSHServerFactory:
    """Factory for creating SSH server instances."""

    def __init__(self, config: HoneypotConfig, session_logger: SessionLogger):
        self.config = config
        self.session_logger = session_logger

    def __call__(self):
        return HoneypotSSHServer(self.config, self.session_logger)


async def start_server(config: HoneypotConfig):
    """Start the SSH honeypot server."""
    session_logger = SessionLogger(config.log_path)

    # Generate or load host key
    host_key_path = Path(config.host_key_path)
    if not host_key_path.exists():
        logger.info("Generating new SSH host key...")
        host_key_path.parent.mkdir(parents=True, exist_ok=True)
        key = asyncssh.generate_private_key('ssh-rsa', 2048)
        host_key_path.write_bytes(key.export_private_key())

    server_factory = SSHServerFactory(config, session_logger)

    await asyncssh.create_server(
        server_factory,
        '',
        config.ssh_port,
        server_host_keys=[str(host_key_path)],
        process_factory=handle_client,
        encoding='utf-8',
    )

    logger.info(f"SSH Honeypot listening on port {config.ssh_port}")
    logger.info(f"Using LLM: {config.llm_config.model}")
    logger.info(f"Ollama host: {config.llm_config.ollama_host}")


async def main():
    """Main entry point."""
    config = HoneypotConfig()

    # Handle shutdown gracefully
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown()))

    await start_server(config)

    # Keep running
    while True:
        await asyncio.sleep(3600)


async def shutdown():
    """Graceful shutdown handler."""
    logger.info("Shutting down...")
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    asyncio.get_event_loop().stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Interrupted")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)
