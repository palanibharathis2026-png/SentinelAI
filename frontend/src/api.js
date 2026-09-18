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
  learning: () => request("/api/learning"),
  retrain: () => post("/api/learning/retrain"),
  modelCard: () => request("/api/model/card"),
  evaluation: () => request("/api/model/evaluation"),
  downloadModel: async (name) => {
    // Files need the login token too, so fetch them and save the result from the browser.
    const token = getAuth()?.token;
    const res = await fetch(`${BASE}/api/model/download/${name}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
    if (!res.ok) throw new Error("Download failed");
    const url = URL.createObjectURL(await res.blob());
    const a = Object.assign(document.createElement("a"), { href: url, download: name === "model" ? "sentinel_model.npz" : "model_card.json" });
    a.click();
    URL.revokeObjectURL(url);
  },
  onboardingOptions: () => request("/api/employees/options"),
  onboard: (body) => post("/api/employees", body),
  offboard: (id) => post(`/api/employees/${id}/offboard`),
  integrations: () => request("/api/integrations"),
  updateIntegration: (body) => request("/api/integrations", { method: "PUT", body: JSON.stringify(body) }),
  testIntegration: (channel) => post("/api/integrations/test", { channel }),
  useDemoReceiver: () => post("/api/integrations/demo-receiver"),
  createIngestKey: (label) => post("/api/integrations/keys", { label }),
  revokeIngestKey: (id) => request(`/api/integrations/keys/${id}`, { method: "DELETE" }),
  ingestSample: (source) => request(`/api/integrations/sample/${source}`),
  ingest: (source, payload) => post(`/api/ingest/${source}`, payload),
  exportEvents: async (format) => {
    const token = getAuth()?.token;
    const res = await fetch(`${BASE}/api/export/events?format=${format}&hours=168`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
    if (!res.ok) throw new Error("Export failed");
    const url = URL.createObjectURL(await res.blob());
    const name = { cef: "sentinelai-alerts.cef.log", jsonl: "sentinelai-alerts.jsonl", csv: "sentinelai-alerts.csv" }[format];
    Object.assign(document.createElement("a"), { href: url, download: name }).click();
    URL.revokeObjectURL(url);
  },
  live: () => request("/api/live"),
  setLive: (enabled) => post("/api/live", { enabled }),
  reset: () => post("/api/reset"),
  map: (hours = 168) => request(`/api/map?hours=${hours}`),
  departments: () => request("/api/departments"),
  labOptions: () => request("/api/lab/options"),
  labScore: (body) => post("/api/lab/score", body),
  login: (username, password) => post("/api/auth/login", { username, password }),
  adminSecondFactor: (challengeId, code) => post("/api/auth/admin-2fa", { challenge_id: challengeId, code }),
  adminEmailCode: (challengeId) => post("/api/auth/admin-email-code", { challenge_id: challengeId }),
  security: () => request("/api/security"),
  staffLogin: (username, password, extra = {}) => post("/api/auth/staff-login", { username, password, ...extra }),
  staffOtp: (challengeId, code) => post("/api/auth/staff-otp", { challenge_id: challengeId, code }),
  staffRequestAccess: (system) => post("/api/staff/me/request-access", { system }),
  staffChangeEmail: (email) => post("/api/staff/me/email", { email }),
  access: () => request("/api/access"),
  updateAccess: (userId, body) => request(`/api/access/${userId}`, { method: "PUT", body: JSON.stringify(body) }),
  unlockStaff: (userId) => post(`/api/access/${userId}/unlock`),
  decideRequest: (id, approve) => post(`/api/access/requests/${id}`, { approve }),
  setAdminEmail: (email) => request("/api/settings/mail", { method: "PUT", body: JSON.stringify({ admin_email: email }) }),
  verifyAdminEmail: (code) => post("/api/settings/mail/verify", { code }),
  testMail: () => post("/api/mail/test"),
  mail: (limit = 60) => request(`/api/mail?limit=${limit}`),
  staffMe: () => request("/api/staff/me"),
  staffHeartbeat: () => post("/api/staff/me/heartbeat"),
  staffActivity: (kind, system) => post("/api/staff/me/activity", { kind, system: system || null }),
  staffLogout: () => post("/api/staff/me/logout"),
  activeStaff: () => request("/api/staff/active"),
  forceSignout: (userId) => post(`/api/staff/${userId}/signout`),
  challenge: () => request("/api/staff/challenge"),
};
