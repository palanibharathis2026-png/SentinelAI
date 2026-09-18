// All calls go to /api, which Vite (dev) or nginx (Docker) forwards to the FastAPI backend.
import { getAuth, setAuth } from "./auth.js";

const BASE = import.meta.env.VITE_API_URL || "";

async function request(path, options = {}) {
  const token = getAuth()?.token;
  let res;
  try {
    res = await fetch(`${BASE}${path}`, {
      headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      ...options,
    });
  } catch {
    throw new Error("Can't reach the SentinelAI server. Check the internet connection, or ask the host for a fresh link.");
  }
  if (res.status === 502 || res.status === 504) {
    throw new Error("The SentinelAI server is not running right now. Ask the host to start it (start.bat).");
  }
  if (res.status === 401 && token) {
    // Expired, server restarted, or signed out by the SOC: back to the login page with the reason.
    let reason = "Your session ended. Please sign in again.";
    try {
      reason = (await res.clone().json()).detail || reason;
    } catch {
      /* not JSON */
    }
    try {
      sessionStorage.setItem("sentinel-flash", reason);
    } catch {
      /* storage blocked */
    }
    setAuth(null);
  }
  if (!res.ok) {
    let message = res.statusText;
    try {
      message = (await res.json()).detail || message;
    } catch {
      /* response was not JSON */
    }
    throw new Error(message);
  }
  return res.json();
}

const post = (path, body) => request(path, { method: "POST", body: JSON.stringify(body ?? {}) });

export const api = {
  health: () => request("/api/health"),
  stats: () => request("/api/stats"),
  alerts: (status = "open") => request(`/api/alerts?status=${status}`),
  events: (params = {}) => request(`/api/events?${new URLSearchParams(params)}`),
  event: (id) => request(`/api/events/${id}`),
  explain: (id, refresh = false) => post(`/api/events/${id}/explain?refresh=${refresh}`),
  setEventStatus: (id, status) =>
    request(`/api/events/${id}/status`, { method: "PATCH", body: JSON.stringify({ status }) }),
  users: () => request("/api/users"),
  user: (id) => request(`/api/users/${id}`),
  block: (id, reason) => post(`/api/users/${id}/block`, { reason }),
  unblock: (id) => post(`/api/users/${id}/unblock`),
  timeline: (hours = 72) => request(`/api/timeline?hours=${hours}`),
  scenarios: () => request("/api/scenarios"),
  simulate: (scenario, userId) => post("/api/simulate", { scenario, user_id: userId || null }),
  model: () => request("/api/model"),
  live: () => request("/api/live"),
  setLive: (enabled) => post("/api/live", { enabled }),
  reset: () => post("/api/reset"),
  map: (hours = 168) => request(`/api/map?hours=${hours}`),
  departments: () => request("/api/departments"),
  labOptions: () => request("/api/lab/options"),
  labScore: (body) => post("/api/lab/score", body),
  login: (username, password) => post("/api/auth/login", { username, password }),
  staffLogin: (username, password, city) => post("/api/auth/staff-login", { username, password, city: city || null }),
  staffMe: () => request("/api/staff/me"),
  staffHeartbeat: () => post("/api/staff/me/heartbeat"),
  staffActivity: (kind, system) => post("/api/staff/me/activity", { kind, system: system || null }),
  staffLogout: () => post("/api/staff/me/logout"),
  activeStaff: () => request("/api/staff/active"),
  forceSignout: (userId) => post(`/api/staff/${userId}/signout`),
  challenge: () => request("/api/staff/challenge"),
};
