"""
Cowrie LLM Command Handler Plugin

This integrates directly into Cowrie's command handling system,
only using LLM for commands Cowrie doesn't already handle.

Install: Copy to cowrie/commands/ in your T-Pot Cowrie container
"""

import os
import time
import json
import hashlib
from typing import Optional, Tuple
from urllib.request import urlopen, Request
from urllib.error import URLError

# Cowrie imports (available when running inside Cowrie)
try:
    from cowrie.shell.command import HoneyPotCommand
    from cowrie.core.config import CowrieConfig
    COWRIE_AVAILABLE = True
except ImportError:
    COWRIE_AVAILABLE = False
    # Stub for testing outside Cowrie
    class HoneyPotCommand:
        pass


class LLMCommandHandler:
    """
    Handles commands that Cowrie doesn't natively support by
    calling a local Ollama instance.

    Key design decisions:
    1. Only called for UNKNOWN commands (Cowrie handles known ones)
    2. Caches responses to ensure consistency
    3. Uses fast static responses where possible
    4. Adds artificial delay to mask LLM latency
    """

    # Ollama configuration
    OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    MODEL = os.getenv("LLM_MODEL", "mistral:7b-instruct-v0.2-q4_K_M")

    # Response cache (in-memory, persists across commands in session)
    _cache = {}

    # Commands that should NEVER go to LLM (Cowrie handles these well)
    COWRIE_NATIVE = {
        'ls', 'cat', 'cd', 'pwd', 'whoami', 'id', 'uname', 'hostname',
        'ps', 'netstat', 'ifconfig', 'wget', 'curl', 'echo', 'env',
        'exit', 'logout', 'su', 'sudo', 'chmod', 'chown', 'mkdir',
        'rm', 'cp', 'mv', 'touch', 'head', 'tail', 'grep', 'find',
        'ssh', 'scp', 'ping', 'nslookup', 'dig', 'adduser', 'useradd',
        'passwd', 'history', 'clear', 'date', 'uptime', 'free', 'df',
        'mount', 'umount', 'kill', 'killall', 'service', 'systemctl',
    }

    # Fast static responses (no LLM needed)
    STATIC_RESPONSES = {
        'arch': 'x86_64',
        'nproc': '4',
        'getconf _NPROCESSORS_ONLN': '4',
        'lscpu | grep "^CPU(s):"': 'CPU(s):                          4',
        'cat /proc/cpuinfo | grep processor | wc -l': '4',
        'which python': '/usr/bin/python',
        'which python3': '/usr/bin/python3',
        'which perl': '/usr/bin/perl',
        'which gcc': '/usr/bin/gcc',
        'which make': '/usr/bin/make',
        'type bash': 'bash is /bin/bash',
        'echo $SHELL': '/bin/bash',
        'echo $USER': '{username}',
        'echo $HOME': '{home}',
        'echo $TERM': 'xterm-256color',
        'printenv SHELL': '/bin/bash',
        'getent passwd root': 'root:x:0:0:root:/root:/bin/bash',
    }

    def __init__(self, protocol):
        """Initialize with Cowrie protocol reference."""
        self.protocol = protocol
        self.session_cache = {}  # Per-session consistency cache

    def should_handle(self, cmd: str) -> bool:
        """
        Determine if LLM should handle this command.
        Returns False for commands Cowrie handles natively.
        """
        base_cmd = cmd.split()[0] if cmd.split() else ''

        # Never intercept Cowrie-native commands
        if base_cmd in self.COWRIE_NATIVE:
            return False

        # Handle everything else
        return True

    def get_response(self, cmd: str, cwd: str, username: str) -> Tuple[str, str]:
        """
        Get response for command.

        Returns: (response_text, source)
        Source is one of: 'static', 'cache', 'llm', 'error'
        """
        # 1. Check static responses first (instant)
        static = self._check_static(cmd, username)
        if static:
            return static, 'static'

        # 2. Check session cache (for consistency)
        cache_key = self._cache_key(cmd, cwd)
        if cache_key in self.session_cache:
            return self.session_cache[cache_key], 'cache'

        # 3. Call LLM
        response = self._call_llm(cmd, cwd, username)
        if response:
            self.session_cache[cache_key] = response
            return response, 'llm'

        # 4. Fallback
        return f"bash: {cmd.split()[0]}: command not found", 'error'

    def _check_static(self, cmd: str, username: str) -> Optional[str]:
        """Check for static response match."""
        cmd_clean = cmd.strip()

        for pattern, response in self.STATIC_RESPONSES.items():
            if cmd_clean == pattern:
                return response.format(
                    username=username,
                    home=f'/home/{username}' if username != 'root' else '/root'
                )
        return None

    def _cache_key(self, cmd: str, cwd: str) -> str:
        """Generate cache key for command + context."""
        return hashlib.md5(f"{cmd}:{cwd}".encode()).hexdigest()

    def _call_llm(self, cmd: str, cwd: str, username: str) -> Optional[str]:
        """Call Ollama API for response generation."""

        system_prompt = f"""You are simulating a real Ubuntu 22.04 bash shell.
Output ONLY the exact command result - no markdown, no explanation.
Current directory: {cwd}
User: {username}
Be concise and realistic. For unknown commands, output appropriate errors."""

        user_prompt = f"$ {cmd}"

        payload = json.dumps({
            "model": self.MODEL,
            "prompt": user_prompt,
            "system": system_prompt,
            "stream": False,
            "options": {
                "temperature": 0.3,  # Low temperature for consistency
                "num_predict": 256,
                "stop": ["$", "#", "```"]
            }
        }).encode()

        try:
            req = Request(
                f"{self.OLLAMA_HOST}/api/generate",
                data=payload,
                headers={"Content-Type": "application/json"}
            )
            with urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
                response = data.get("response", "").strip()

                # Clean up common LLM artifacts
                response = self._clean_response(response, cmd)
                return response

        except URLError as e:
            # Log error but don't expose to attacker
            return None
        except Exception as e:
            return None

    def _clean_response(self, response: str, cmd: str) -> str:
        """Remove LLM artifacts from response."""
        # Remove markdown code blocks
        if response.startswith("```"):
            lines = response.split("\n")
            if lines[-1].strip() == "```":
                response = "\n".join(lines[1:-1])
            else:
                response = "\n".join(lines[1:])

        # Remove command echo
        if response.startswith(f"$ {cmd}"):
            response = response[len(f"$ {cmd}"):].lstrip("\n")

        # Remove trailing prompts
        for prompt in ["$ ", "# ", "root@"]:
            if response.rstrip().endswith(prompt):
                response = response.rstrip()[:-len(prompt)].rstrip()

        return response.strip()


# Cowrie command class for unknown commands
if COWRIE_AVAILABLE:
    class Command_llm_fallback(HoneyPotCommand):
        """
        Fallback command handler that uses LLM for unknown commands.

        This is registered as a catch-all in Cowrie's command system.
        """

        def call(self):
            """Execute the command via LLM."""
            cmd = " ".join(self.args) if self.args else ""
            full_cmd = f"{self.protocol.cmd} {cmd}".strip()

            handler = LLMCommandHandler(self.protocol)

            # Get current working directory and username
            cwd = self.protocol.cwd
            username = self.protocol.user.username

            # Get response
            response, source = handler.get_response(full_cmd, cwd, username)

            # Add slight delay to mask LLM latency variation
            # Real commands have some variance too
            import random
            time.sleep(random.uniform(0.05, 0.15))

            # Output response
            if response:
                self.write(response + "\n")

            # Log the interaction (Cowrie's standard logging)
            self.protocol.logDispatch(
                eventid='cowrie.command.llm',
                input=full_cmd,
                response_source=source
            )


# For testing outside Cowrie
if __name__ == "__main__":
    handler = LLMCommandHandler(None)

    test_commands = [
        ("echo $SHELL", "/root", "root"),
        ("docker ps", "/root", "root"),
        ("apt list --installed | head", "/root", "root"),
    ]

    for cmd, cwd, user in test_commands:
        response, source = handler.get_response(cmd, cwd, user)
        print(f"\n$ {cmd}")
        print(f"[source: {source}]")
        print(response)
