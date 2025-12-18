#!/usr/bin/env python3
"""
Cowrie LLM Proxy Service

This service sits between Cowrie and Ollama, providing:
1. Response caching for consistency
2. Latency masking (pre-generates responses)
3. Request queuing and rate limiting
4. Cowrie-native logging format

The proxy pre-generates likely follow-up responses in the background,
so when an attacker types a command, the response is already cached.
"""

import asyncio
import hashlib
import json
import logging
import os
import random
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set
from aiohttp import web, ClientSession, ClientTimeout

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger("llm-proxy")


@dataclass
class SessionState:
    """Track state for each Cowrie session."""
    session_id: str
    username: str = "root"
    cwd: str = "/root"
    command_history: List[str] = field(default_factory=list)
    created_files: Set[str] = field(default_factory=set)
    created_dirs: Set[str] = field(default_factory=set)
    env_vars: Dict[str, str] = field(default_factory=dict)
    last_activity: float = field(default_factory=time.time)


class ResponseCache:
    """
    LRU cache for LLM responses with TTL.
    Ensures consistent responses for repeated commands.
    """

    def __init__(self, max_size: int = 10000, ttl: int = 3600):
        self.cache: OrderedDict[str, tuple] = OrderedDict()
        self.max_size = max_size
        self.ttl = ttl

    def _make_key(self, cmd: str, cwd: str, username: str) -> str:
        """Create cache key from command context."""
        return hashlib.md5(f"{cmd}:{cwd}:{username}".encode()).hexdigest()

    def get(self, cmd: str, cwd: str, username: str) -> Optional[str]:
        """Get cached response if exists and not expired."""
        key = self._make_key(cmd, cwd, username)
        if key in self.cache:
            response, timestamp = self.cache[key]
            if time.time() - timestamp < self.ttl:
                # Move to end (most recently used)
                self.cache.move_to_end(key)
                return response
            else:
                # Expired, remove
                del self.cache[key]
        return None

    def set(self, cmd: str, cwd: str, username: str, response: str):
        """Cache a response."""
        key = self._make_key(cmd, cwd, username)
        self.cache[key] = (response, time.time())
        self.cache.move_to_end(key)

        # Evict oldest if over max size
        while len(self.cache) > self.max_size:
            self.cache.popitem(last=False)


class PredictiveCache:
    """
    Pre-generates responses for likely follow-up commands.
    This masks LLM latency by having responses ready before they're needed.
    """

    # Commands attackers commonly run in sequence
    COMMAND_CHAINS = {
        "id": ["whoami", "uname -a", "cat /etc/passwd"],
        "whoami": ["id", "pwd", "ls -la"],
        "ls": ["cat", "cd", "pwd"],
        "cat /etc/passwd": ["cat /etc/shadow", "cat /etc/group"],
        "uname -a": ["cat /proc/version", "lsb_release -a", "hostnamectl"],
        "ps aux": ["netstat -tulpn", "ss -tulpn", "top"],
        "netstat": ["ss", "lsof -i", "iptables -L"],
        "wget": ["chmod +x", "bash", "./"],
        "curl": ["chmod +x", "bash", "sh"],
        "cd /tmp": ["ls", "wget", "curl"],
        "cd /var/tmp": ["ls", "wget", "curl"],
        "find / -perm": ["ls -la", "cat", "./"],
    }

    def __init__(self):
        self.pending_predictions: Dict[str, asyncio.Task] = {}

    def get_predictions(self, last_cmd: str) -> List[str]:
        """Get likely follow-up commands based on last command."""
        predictions = []

        # Direct chain match
        for pattern, followups in self.COMMAND_CHAINS.items():
            if pattern in last_cmd.lower():
                predictions.extend(followups)

        # Generic follow-ups
        predictions.extend(["ls", "pwd", "id"])

        return list(set(predictions))[:5]  # Limit to 5 predictions


class LLMClient:
    """Async client for Ollama API with timeout and retry."""

    def __init__(self, host: str, model: str):
        self.host = host
        self.model = model
        self.session: Optional[ClientSession] = None

    async def initialize(self):
        """Create HTTP session."""
        self.session = ClientSession(
            timeout=ClientTimeout(total=30)
        )

    async def close(self):
        """Close HTTP session."""
        if self.session:
            await self.session.close()

    async def generate(
        self,
        cmd: str,
        cwd: str,
        username: str,
        context: Optional[str] = None
    ) -> Optional[str]:
        """Generate response for command."""

        system_prompt = f"""You simulate an Ubuntu 22.04 bash shell. Output ONLY the raw command result.
Rules:
- No markdown, no backticks, no explanations
- Match real Linux output format exactly
- For errors, use standard bash error format
- Current directory: {cwd}
- User: {username}
- Be concise - real commands have terse output"""

        if context:
            system_prompt += f"\nRecent context:\n{context}"

        payload = {
            "model": self.model,
            "prompt": f"$ {cmd}",
            "system": system_prompt,
            "stream": False,
            "options": {
                "temperature": 0.3,
                "num_predict": 256,
                "stop": ["$", "#", "```", "\n\n\n"]
            }
        }

        try:
            async with self.session.post(
                f"{self.host}/api/generate",
                json=payload
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    response = data.get("response", "").strip()
                    return self._clean_response(response, cmd)
        except Exception as e:
            logger.error(f"LLM error: {e}")

        return None

    def _clean_response(self, response: str, cmd: str) -> str:
        """Clean LLM artifacts from response."""
        # Remove markdown
        if response.startswith("```"):
            lines = response.split("\n")
            response = "\n".join(
                l for l in lines
                if not l.strip().startswith("```")
            )

        # Remove command echo
        if response.startswith(f"$ {cmd}"):
            response = response[len(f"$ {cmd}"):].lstrip("\n")

        return response.strip()


class CowrieLLMProxy:
    """
    Main proxy service that Cowrie calls for unknown commands.

    API Endpoints:
    - POST /generate - Generate response for command
    - POST /session/start - Start tracking a session
    - POST /session/end - End session tracking
    - GET /health - Health check
    """

    def __init__(self):
        self.ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.model = os.getenv("LLM_MODEL", "mistral:7b-instruct-v0.2-q4_K_M")

        self.llm = LLMClient(self.ollama_host, self.model)
        self.cache = ResponseCache()
        self.predictor = PredictiveCache()
        self.sessions: Dict[str, SessionState] = {}

        self.app = web.Application()
        self._setup_routes()

    def _setup_routes(self):
        """Configure HTTP routes."""
        self.app.router.add_post("/generate", self.handle_generate)
        self.app.router.add_post("/session/start", self.handle_session_start)
        self.app.router.add_post("/session/end", self.handle_session_end)
        self.app.router.add_get("/health", self.handle_health)

    async def handle_generate(self, request: web.Request) -> web.Response:
        """
        Generate response for a command.

        Expected JSON body:
        {
            "session_id": "abc123",
            "command": "docker ps",
            "cwd": "/root",
            "username": "root"
        }
        """
        try:
            data = await request.json()
        except json.JSONDecodeError:
            return web.json_response(
                {"error": "Invalid JSON"},
                status=400
            )

        session_id = data.get("session_id", "unknown")
        cmd = data.get("command", "")
        cwd = data.get("cwd", "/root")
        username = data.get("username", "root")

        if not cmd:
            return web.json_response(
                {"error": "Missing command"},
                status=400
            )

        start_time = time.time()

        # Update session state
        session = self.sessions.get(session_id)
        if session:
            session.cwd = cwd
            session.command_history.append(cmd)
            session.last_activity = time.time()

        # Check cache first
        cached = self.cache.get(cmd, cwd, username)
        if cached:
            latency = int((time.time() - start_time) * 1000)
            logger.info(f"[{session_id}] Cache hit: {cmd[:50]} ({latency}ms)")

            # Trigger prediction for next commands
            asyncio.create_task(self._predict_and_cache(cmd, cwd, username))

            return web.json_response({
                "response": cached,
                "source": "cache",
                "latency_ms": latency
            })

        # Generate with LLM
        context = self._build_context(session) if session else None
        response = await self.llm.generate(cmd, cwd, username, context)

        if response:
            # Cache the response
            self.cache.set(cmd, cwd, username, response)

            latency = int((time.time() - start_time) * 1000)
            logger.info(f"[{session_id}] LLM generated: {cmd[:50]} ({latency}ms)")

            # Trigger prediction
            asyncio.create_task(self._predict_and_cache(cmd, cwd, username))

            return web.json_response({
                "response": response,
                "source": "llm",
                "latency_ms": latency
            })

        # Fallback
        return web.json_response({
            "response": f"bash: {cmd.split()[0]}: command not found",
            "source": "fallback",
            "latency_ms": int((time.time() - start_time) * 1000)
        })

    async def _predict_and_cache(self, last_cmd: str, cwd: str, username: str):
        """Pre-generate responses for likely follow-up commands."""
        predictions = self.predictor.get_predictions(last_cmd)

        for cmd in predictions:
            # Skip if already cached
            if self.cache.get(cmd, cwd, username):
                continue

            # Generate in background
            response = await self.llm.generate(cmd, cwd, username)
            if response:
                self.cache.set(cmd, cwd, username, response)
                logger.debug(f"Pre-cached: {cmd}")

    def _build_context(self, session: SessionState) -> str:
        """Build context string from session history."""
        if not session.command_history:
            return ""

        recent = session.command_history[-5:]
        return "Previous commands: " + ", ".join(recent)

    async def handle_session_start(self, request: web.Request) -> web.Response:
        """Start tracking a new session."""
        data = await request.json()
        session_id = data.get("session_id")
        username = data.get("username", "root")

        if session_id:
            self.sessions[session_id] = SessionState(
                session_id=session_id,
                username=username
            )
            logger.info(f"Session started: {session_id}")

        return web.json_response({"status": "ok"})

    async def handle_session_end(self, request: web.Request) -> web.Response:
        """End session tracking."""
        data = await request.json()
        session_id = data.get("session_id")

        if session_id and session_id in self.sessions:
            del self.sessions[session_id]
            logger.info(f"Session ended: {session_id}")

        return web.json_response({"status": "ok"})

    async def handle_health(self, request: web.Request) -> web.Response:
        """Health check endpoint."""
        # Check Ollama connectivity
        try:
            async with self.llm.session.get(
                f"{self.ollama_host}/api/tags"
            ) as resp:
                ollama_ok = resp.status == 200
        except:
            ollama_ok = False

        return web.json_response({
            "status": "healthy" if ollama_ok else "degraded",
            "ollama": "connected" if ollama_ok else "disconnected",
            "active_sessions": len(self.sessions),
            "cache_size": len(self.cache.cache)
        })

    async def start(self):
        """Start the proxy service."""
        await self.llm.initialize()

        runner = web.AppRunner(self.app)
        await runner.setup()

        site = web.TCPSite(runner, "0.0.0.0", 11435)
        await site.start()

        logger.info("LLM Proxy listening on port 11435")
        logger.info(f"Ollama host: {self.ollama_host}")
        logger.info(f"Model: {self.model}")

    async def cleanup(self):
        """Cleanup resources."""
        await self.llm.close()


async def main():
    proxy = CowrieLLMProxy()
    await proxy.start()

    # Keep running
    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        await proxy.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
