// Login state for this browser tab. sessionStorage (not localStorage) so an admin tab and a
// staff tab can be open side by side in the same browser during a demo.
const KEY = "sentinel-auth";
const EVENT = "sentinel-auth-change";
let memory = null;

export function getAuth() {
  try {
    const raw = sessionStorage.getItem(KEY);
    return raw ? JSON.parse(raw) : memory;
  } catch {
    return memory;
  }
}

export function setAuth(value) {
  memory = value;
  try {
    if (value) sessionStorage.setItem(KEY, JSON.stringify(value));
    else sessionStorage.removeItem(KEY);
  } catch {
    /* storage blocked: keep it in memory */
  }
  window.dispatchEvent(new Event(EVENT));
}

export function onAuthChange(handler) {
  window.addEventListener(EVENT, handler);
  return () => window.removeEventListener(EVENT, handler);
}
