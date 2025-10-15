from __future__ import annotations

import math
import random
import time
import uuid
from dataclasses import dataclass
from threading import Lock
from typing import Dict, List, Optional

from flask import Flask, render_template, request
from flask_socketio import SocketIO

import requests
import docker
import urllib.parse
import secrets
import socket
from docker import errors as docker_errors
import atexit
import signal
import logging




app = Flask(__name__)
# app.config["SECRET_KEY"] = "queue-webserver-secret"

# Ensure this matches your server's actual URL
BASE_URL = "https://hackersir-cmdi.devvillie.me"

# Update SocketIO initialization to include the correct CORS origins
socketio = SocketIO(app, async_mode="eventlet", cors_allowed_origins="*")

# Configure basic logging for diagnostics
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

MAX_ACTIVE_USERS = 50
SESSION_DURATION_SECONDS = 900
CADDY_API_URL = "http://localhost:2019"

global port_now
port_now = 10000
containers = {}
try:
    client = docker.from_env()
    # Best-effort connectivity check (won't crash if not available)
    try:
        client.ping()
    except Exception:
        logging.warning("Docker daemon ping failed; will attempt operations lazily.")
except Exception:
    logging.exception("Failed to initialize Docker client from environment.")
    client = None
IMAGE_NAME = "ctf-ping-vuln"


# Add a new configuration for the base URL
# BASE_URL = "https://hacker-cmdi.devvillie.me"  # Update this to the actual base URL of your server

@dataclass
class ActiveSession:
    user_id: str
    sid: str
    text: str
    started_at: float
    expires_at: float


@dataclass
class QueuedUser:
    user_id: str
    sid: str
    token: str
    enqueued_at: float


active_sessions: Dict[str, ActiveSession] = {}
waiting_queue: List[QueuedUser] = []
sid_to_user: Dict[str, str] = {}
_lock = Lock()
_supervisor_started = False


def _ensure_supervisor() -> None:
    global _supervisor_started
    with _lock:
        if not _supervisor_started:
            socketio.start_background_task(_session_supervisor)
            _supervisor_started = True

def stop_containers():
    global containers
    logging.info("Stopping all containers...")
    for container in list(containers.values()):
        try:
            container.stop(timeout=1)
            logging.info("Stopped container: %s", getattr(container, "name", "?"))
        except docker_errors.NotFound:
            pass
        except docker_errors.APIError as e:
            resp = getattr(e, "response", None)
            if not (resp is not None and getattr(resp, "status_code", None) == 404):
                logging.exception("Docker API error stopping container %s", getattr(container, 'name', '?'))
        except requests.exceptions.HTTPError as e:
            if e.response is None or e.response.status_code != 404:
                logging.exception("HTTP error stopping container %s", getattr(container, 'name', '?'))
        except Exception:
            logging.exception("Unexpected error while stopping container %s", getattr(container, 'name', '?'))
    containers.clear()
    logging.info("All containers stopped.")

def _wait_for_port(host: str, port: int, timeout: float = 8.0, interval: float = 0.2) -> bool:
    """Wait until a TCP port is accepting connections."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(interval)
    return False

def _wait_for_http(url: str, timeout: float = 15.0, interval: float = 0.3) -> bool:
    """Wait until an HTTP endpoint responds (any status code)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=1.5)
            # Any response means the server is accepting connections
            return True
        except requests.RequestException:
            time.sleep(interval)
    return False

def _find_next_free_port(start: int, end: int) -> int:
    """Find a free TCP port on localhost in [start, end]."""
    for p in range(start, end + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    # Fallback to start if nothing free (shouldn't happen with small pool)
    return start

def generate_ping_server(user_id: str) -> str:
    global port_now

    if client is None:
        raise RuntimeError("Docker is unavailable on the server.")

    secure_password = secrets.token_urlsafe(16)
    encoded_password = urllib.parse.quote(secure_password)

    # Pick a free port in the pool
    cur_port = _find_next_free_port(port_now, 10100)

    def _start_container(port: int):
        if client:
            return client.containers.run(
                IMAGE_NAME,
                detach=True,
                ports={'80/tcp': port},
                name=f"ctf_{port}",
                environment={"CMDI_PASSWORD": secure_password},
                auto_remove=True,
                mem_limit="100m",
                mem_reservation="75m",
            )
        else:
            raise RuntimeError("Client is None")

    try:
        try:
            container = _start_container(cur_port)
        except docker_errors.ImageNotFound:
            logging.exception("Docker image not found: %s", IMAGE_NAME)
            raise RuntimeError("Server image is not available. Please try again later.")
        except docker_errors.APIError:
            logging.exception("Docker API error while starting container on port %d", cur_port)
            raise RuntimeError("Failed to start the server. Please try again later.")
        except Exception:
            logging.exception("Unexpected error while starting container on port %d", cur_port)
            raise RuntimeError("Failed to start the server. Please try again later.")

        containers[user_id] = container
        url_local = f"http://127.0.0.1:{cur_port}/?password={encoded_password}"

        # Wait for TCP and HTTP readiness
        ready = _wait_for_port('127.0.0.1', cur_port, timeout=10.0) and _wait_for_http(url_local, timeout=12.0)
        if not ready:
            logging.warning("Container on port %d not ready, attempting one restart...", cur_port)
            try:
                container.restart(timeout=2)
                ready = _wait_for_port('127.0.0.1', cur_port, timeout=10.0) and _wait_for_http(url_local, timeout=12.0)
            except Exception:
                logging.exception("Error while restarting container on port %d", cur_port)
                ready = False

        # Verify running state
        try:
            container.reload()
            running = (container.status == "running")
        except Exception:
            logging.exception("Failed to reload container state on port %d", cur_port)
            running = False

        if not (ready and running):
            logging.error("Container failed to become ready on port %d", cur_port)
            try:
                container.stop(timeout=1)
            except Exception:
                logging.exception("Error while stopping unready container on port %d", cur_port)
            containers.pop(user_id, None)
            raise RuntimeError("Container failed to become ready. Please try again.")
    except Exception:
        # Ensure cleanup if container was created but not tracked
        containers.pop(user_id, None)
        raise

    full_url = f"{BASE_URL}/cmdi-{cur_port}/?password={encoded_password}"

    # Advance the global pointer (wrap after 10100)
    port_now = cur_port + 1
    if port_now > 10100:
        port_now = 10000

    return full_url


def _activate_user(
    user_id: str,
    sid: str,
    *,
    from_queue: bool = False,
    queue_token: Optional[str] = None,
) -> None:
    try:
        text = generate_ping_server(user_id)
    except Exception:
        logging.exception("Failed to start ping server for user_id=%s", user_id)
        socketio.emit(
            "session_update",
            {
                "status": "error",
                "message": "Failed to start the ping server. Please try again.",
            },
            to=sid,
        )
        return

    now = time.time()
    session = ActiveSession(
        user_id=user_id,
        sid=sid,
        text=text,
        started_at=now,
        expires_at=now + SESSION_DURATION_SECONDS,
    )
    active_sessions[user_id] = session
    socketio.emit(
        "session_update",
        {
            "status": "active",
            "text": text,
            "startedAt": session.started_at,
            "expiresAt": session.expires_at,
            "timeRemaining": int(session.expires_at - now),
            "message": "Your ping server is ready. Enjoy!",
            "source": "queue" if from_queue else "immediate",
            "token": queue_token,
        },
        to=sid,
    )


def _emit_queue_positions(now: Optional[float] = None) -> None:
    if now is None:
        now = time.time()
    waits = _calculate_queue_waits(now)
    for index, queued in enumerate(waiting_queue):
        wait_seconds = waits.get(queued.user_id, 0)
        socketio.emit(
            "queue_update",
            {
                "status": "waiting",
                "position": index + 1,
                "queueSize": len(waiting_queue),
                "token": queued.token,
                "waitSeconds": wait_seconds,
                "estimatedStartAt": now + wait_seconds,
            },
            to=queued.sid,
        )


def _session_supervisor() -> None:
    while True:
        socketio.sleep(1)
        now = time.time()
        expired_users: List[str] = []

        with _lock:
            # Update timers for active users
            for session in list(active_sessions.values()):
                remaining = int(session.expires_at - now)
                if remaining <= 0:
                    expired_users.append(session.user_id)
                else:
                    socketio.emit(
                        "timer_update",
                        {
                            "status": "active",
                            "timeRemaining": remaining,
                        },
                        to=session.sid,
                    )

            # Expire sessions whose time ran out
            for user_id in expired_users:
                session = active_sessions.pop(user_id, None)
                if session:
                    socketio.emit(
                        "session_update",
                        {
                            "status": "ended",
                            "message": "Session time has ended.",
                            "text": session.text,
                            "timeRemaining": 0,
                        },
                        to=session.sid,
                    )
                    if user_id in containers:
                        try:
                            containers[user_id].stop(timeout=1)
                        except docker_errors.NotFound:
                            pass
                        except docker_errors.APIError as e:
                            resp = getattr(e, "response", None)
                            if not (resp is not None and getattr(resp, "status_code", None) == 404):
                                logging.exception("Docker API error while stopping expired container for user_id=%s", user_id)
                        except requests.exceptions.HTTPError as e:
                            if e.response is None or e.response.status_code != 404:
                                logging.exception("HTTP error while stopping expired container for user_id=%s", user_id)
                        except Exception:
                            logging.exception("Unexpected error stopping expired container for user_id=%s", user_id)
                        finally:
                            containers.pop(user_id, None)

            # Promote queued users into open slots
            while waiting_queue and len(active_sessions) < MAX_ACTIVE_USERS:
                queued = waiting_queue.pop(0)
                _activate_user(
                    queued.user_id,
                    queued.sid,
                    from_queue=True,
                    queue_token=queued.token,
                )

            # Notify queued users about their latest position
            _emit_queue_positions(now)


def _remove_from_queue(user_id: str) -> Optional[QueuedUser]:
    for index, queued in enumerate(waiting_queue):
        if queued.user_id == user_id:
            removed = waiting_queue.pop(index)
            return removed
    return None


def _get_sid() -> str:
    sid = getattr(request, "sid", None)
    if not sid:
        raise RuntimeError("Socket.IO session id is unavailable for this request")
    return sid


def _calculate_queue_waits(now: Optional[float] = None) -> Dict[str, int]:
    if now is None:
        now = time.time()

    remaining_times: List[float] = [
        max(0.0, session.expires_at - now) for session in active_sessions.values()
    ]
    while len(remaining_times) < MAX_ACTIVE_USERS:
        remaining_times.append(0.0)

    remaining_times.sort()
    waits: Dict[str, int] = {}
    future_slots = remaining_times[:]

    for queued in waiting_queue:
        if future_slots:
            wait_seconds = future_slots.pop(0)
        else:
            wait_seconds = 0.0

        wait_int = max(0, int(math.ceil(wait_seconds)))
        waits[queued.user_id] = wait_int

        future_slots.append(wait_seconds + SESSION_DURATION_SECONDS)
        future_slots.sort()

    return waits


@app.route("/")
def index() -> str:
    return render_template("index.html")


@socketio.on("connect")
def handle_connect():
    _ensure_supervisor()
    sid = _get_sid()
    with _lock:
        user_id = str(uuid.uuid4())
        sid_to_user[sid] = user_id
    socketio.emit(
        "session_update",
        {
            "status": "connected",
            "message": "Connected. Click the button to request the ping server.",
        },
        to=sid,
    )


@socketio.on("disconnect")
def handle_disconnect(reason=None):
    sid = _get_sid()
    with _lock:
        user_id = sid_to_user.pop(sid, None)
        if not user_id:
            return

        # Remove from active sessions if present
        active = active_sessions.pop(user_id, None)
        if active:
            socketio.emit(
                "session_update",
                {
                    "status": "ended",
                    "message": "Disconnected. Session closed.",
                    "timeRemaining": 0,
                },
                to=active.sid,
            )
            if user_id in containers.keys():
                c = containers.pop(user_id, None)
                if c:
                    try:
                        c.stop(timeout=1)
                    except docker_errors.NotFound:
                        pass
                    except docker_errors.APIError as e:
                        resp = getattr(e, "response", None)
                        if not (resp is not None and getattr(resp, "status_code", None) == 404):
                            logging.exception("Docker API error while stopping container on disconnect for user_id=%s", user_id)
                    except requests.exceptions.HTTPError as e:
                        if e.response is None or e.response.status_code != 404:
                            logging.exception("HTTP error while stopping container on disconnect for user_id=%s", user_id)
                    except Exception:
                        logging.exception("Unexpected error stopping container on disconnect for user_id=%s", user_id)

        # Remove from queue if present
        removed = _remove_from_queue(user_id)
        if removed:
            socketio.emit(
                "session_update",
                {
                    "status": "ended",
                    "message": "You left the queue.",
                    "timeRemaining": 0,
                },
                to=removed.sid,
            )

        _emit_queue_positions()


@socketio.on("request_text")
def handle_request_text():
    sid = _get_sid()
    with _lock:
        user_id = sid_to_user.get(sid)
        if not user_id:
            return

        now = time.time()
        waits_lookup = _calculate_queue_waits(now)

        # Already active? refresh status
        if user_id in active_sessions:
            session = active_sessions[user_id]
            remaining = max(0, int(session.expires_at - time.time()))
            socketio.emit(
                "session_update",
                {
                    "status": "active",
                    "text": session.text,
                    "timeRemaining": remaining,
                    "message": "Your ping server is running",
                },
                to=sid,
            )
            return

        # Already queued? send position update
        for position, queued in enumerate(waiting_queue, start=1):
            if queued.user_id == user_id:
                socketio.emit(
                    "session_update",
                    {
                        "status": "queued",
                        "position": position,
                        "queueSize": len(waiting_queue),
                        "token": queued.token,
                        "waitSeconds": waits_lookup.get(user_id, 0),
                        "message": "Still waiting for a slot…",
                    },
                    to=sid,
                )
                return

        # Offer immediate slot if space available
        if len(active_sessions) < MAX_ACTIVE_USERS:
            _activate_user(user_id, sid, from_queue=False)
            return

        # Otherwise enqueue the user
        token = str(uuid.uuid4())
        queued_user = QueuedUser(
            user_id=user_id,
            sid=sid,
            token=token,
            enqueued_at=time.time(),
        )
        waiting_queue.append(queued_user)
        now = time.time()
        waits_lookup = _calculate_queue_waits(now)
        position = len(waiting_queue)
        socketio.emit(
            "session_update",
            {
                "status": "queued",
                "position": position,
                "queueSize": len(waiting_queue),
                "token": token,
                "waitSeconds": waits_lookup.get(user_id, 0),
                "message": "All slots are busy. You've been queued.",
            },
            to=sid,
        )
        _emit_queue_positions(now)


if __name__ == "__main__":
    # Ensure cleanup on exit and signals
    atexit.register(stop_containers)
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, lambda s, f: stop_containers())
        except Exception:
            logging.debug("Signal handler registration failed for %s", sig)
    _ensure_supervisor()
    socketio.run(app, host="0.0.0.0", port=81)
