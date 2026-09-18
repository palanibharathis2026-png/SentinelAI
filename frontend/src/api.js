// All calls go to /api, which Vite (dev) or nginx (Docker) forwards to the FastAPI backend.
const BASE = import.meta.env.VITE_API_URL || "";

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
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
};
