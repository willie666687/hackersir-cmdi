const statusLabel = document.getElementById("status-label");
const statusMessage = document.getElementById("status-message");
const timerEl = document.getElementById("timer");
const queuePositionEl = document.getElementById("queue-position");
const queueTokenEl = document.getElementById("queue-token");
const queueWaitEl = document.getElementById("queue-wait");
const textOutput = document.getElementById("text-output");
const requestBtn = document.getElementById("request-btn");

const basePath = window.location.pathname.replace(/\/$/, "");
const socketPath = basePath ? `${basePath}/socket.io` : "/socket.io";

const socket = io("https://hackersir-cmdi.devvillie.me", {
  path: socketPath,
  transports: ["websocket"],
  reconnection: true,
  reconnectionAttempts: Infinity,
  reconnectionDelay: 1000,
});

function setStatus(state, message) {
  statusLabel.textContent = state;
  statusLabel.className = `badge ${state}`;
  statusMessage.textContent = message || "";
}

function updateQueueWait(seconds) {
  if (typeof seconds === "number" && Number.isFinite(seconds)) {
    queueWaitEl.textContent = `${seconds}s`;
  } else {
    queueWaitEl.textContent = "—";
  }
}

requestBtn.addEventListener("click", () => {
  socket.emit("request_text");
});

socket.on("connect", () => {
  setStatus("active", "Connected. Click the button to request text.");
});

socket.on("disconnect", () => {
  setStatus("ended", "Disconnected from server.");
  timerEl.textContent = "—";
  queuePositionEl.textContent = "—";
  queueTokenEl.textContent = "—";
  updateQueueWait(undefined);
});

socket.on("session_update", (payload = {}) => {
  const { status, text, message, timeRemaining, token, source, waitSeconds } = payload;

  if (status === "active") {
    setStatus("active", message || "Text is ready.");
    if (typeof timeRemaining === "number") {
      timerEl.textContent = `${timeRemaining}s`;
    }
    if (typeof text === "string" && text.length > 0) {
      textOutput.textContent = text;
      textOutput.href = text;
    }
    queuePositionEl.textContent = "—";
    queueTokenEl.textContent = source === "queue" ? token || "—" : "—";
    updateQueueWait(undefined);
  } else if (status === "queued") {
    setStatus("queued", message || "Waiting for a slot…");
    if (payload.position) {
      queuePositionEl.textContent = payload.position;
    }
    queueTokenEl.textContent = token || "—";
    updateQueueWait(waitSeconds);
    timerEl.textContent = "—";
  } else if (status === "ended") {
    setStatus("ended", message || "Session ended.");
    timerEl.textContent = "0s";
    queueTokenEl.textContent = "—";
    updateQueueWait(undefined);
  } else if (status === "connected") {
    setStatus("active", message || "Connected. Click the button to ask for text.");
    updateQueueWait(undefined);
  }

  if (payload.position) {
    queuePositionEl.textContent = payload.position;
  }
});

socket.on("timer_update", (payload = {}) => {
  if (typeof payload.timeRemaining === "number") {
    timerEl.textContent = `${payload.timeRemaining}s`;
  }
});

socket.on("queue_update", (payload = {}) => {
  if (typeof payload.position !== "undefined") {
    queuePositionEl.textContent = payload.position;
  }
  if (payload.token) {
    queueTokenEl.textContent = payload.token;
    setStatus("queued", "Waiting for a slot…");
  }
  updateQueueWait(payload.waitSeconds);
});
