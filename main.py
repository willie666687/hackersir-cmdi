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




app = Flask(__name__)
# app.config["SECRET_KEY"] = "queue-webserver-secret"

# Ensure this matches your server's actual URL
BASE_URL = "https://hackersir-cmdi.devvillie.me"

# Update SocketIO initialization to include the correct CORS origins
socketio = SocketIO(app, async_mode="eventlet", cors_allowed_origins="*")

MAX_ACTIVE_USERS = 5
SESSION_DURATION_SECONDS = 60
CADDY_API_URL = "http://localhost:2019"

global port_now
port_now = 10000
containers = {}
client = docker.from_env()
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
    print("\nStopping all containers...")
    for container in containers.values():
        try:
            port = int(container.name.split('_')[1])
            # remove_caddy_route(port)
            
            container.stop()
            print(f"Stopped container: {container.name}")
        except Exception as e:
            print(f"Error stopping container {container.name}: {e}")
    containers.clear()
    print("All containers stopped.")

def generate_ping_server(user_id: str) -> str:
    global port_now
    secure_password = secrets.token_urlsafe(16)
    container = client.containers.run(
        IMAGE_NAME,
        detach=True,
        ports={'80/tcp': port_now},
        name=f"ctf_{port_now}",
        environment={"CMDI_PASSWORD": secure_password},
        auto_remove=True,
        mem_limit="100m",
        mem_reservation="75m",
        cpu_percent=20
    )
    containers[user_id] = container

    encoded_password = urllib.parse.quote(secure_password)
    full_url = f"{BASE_URL}/cmdi-{port_now}/?password={encoded_password}"

    port_now += 1
    if port_now > 10010:
        port_now = 10000
    return full_url


def _activate_user(
    user_id: str,
    sid: str,
    *,
    from_queue: bool = False,
    queue_token: Optional[str] = None,
) -> None:
    text = generate_ping_server(user_id)
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
                        containers[user_id].stop()
                        del containers[user_id]

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
def handle_disconnect():
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
                containers[user_id].stop()
                del containers[user_id]

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
    _ensure_supervisor()
    socketio.run(app, host="0.0.0.0", port=81)
