// client.js
// Shared frontend helpers for the RNG game

// --- API Helper ---
async function api(path, method = "GET", body) {
  const opts = { 
    method, 
    headers: { "Content-Type": "application/json" } 
  };
  if (body) opts.body = JSON.stringify(body);

  const res = await fetch(path, opts);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || res.statusText);
  }
  return res.json();
}

// --- Auth Helpers ---
async function signup(username, password) {
  return api("/api/signup", "POST", { username, password });
}

async function login(username, password) {
  return api("/api/login", "POST", { username, password });
}

async function logout() {
  return api("/api/logout", "POST");
}

// --- Stats ---
async function getStats() {
  return api("/api/stats");
}

// --- RNG ---
async function openBox() {
  return api("/api/open-box", "POST");
}

// --- Leaderboard ---
async function getLeaderboard() {
  return api("/api/leaderboard");
}

// --- Trades ---
async function createTrade(itemName, targetUser) {
  return api("/api/trades", "POST", { itemName, targetUser });
}

async function getTrades() {
  return api("/api/trades");
}

async function acceptTrade(tradeId) {
  return api(`/api/trades/${tradeId}/accept`, "POST");
}

// --- Socket.io Chat ---
let socket;
function connectChat(username) {
  if (!io) {
    console.error("Socket.io client missing");
    return;
  }
  socket = io();

  socket.on("connect", () => {
    console.log("Connected to chat");
  });

  socket.on("chatMessage", (msg) => {
    const chatBox = document.getElementById("chatBox");
    if (chatBox) {
      const div = document.createElement("div");
      div.textContent = `${msg.user}: ${msg.text}`;
      chatBox.appendChild(div);
    }
  });

  // join with username
  socket.emit("join", { user: username });
}

function sendChatMessage(text) {
  if (socket) {
    socket.emit("chatMessage", { text });
  }
}
