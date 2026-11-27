/** In-memory browser session. Only the server authenticates and authorizes. */
const API = 'http://localhost:8000';
const AUTH_TIMEOUT = 10000;
const expiredMessage = 'Session expired or invalid. Sign in again.';
const networkMessage = 'Backend unavailable. Check the local FastAPI service.';

function initial(status = 'anonymous', notice = '') {
  return { status, notice, user: null, sessionVersion: 0, busy: false,
    result: null, events: [], alerts: [], eventsBusy: false, eventsError: '' };
}

function errorMessage(status) {
  if (status === 403) return 'Access forbidden.';
  if (status === 422) return 'Invalid request.';
  if (status === 502 || status === 503) return 'Service unavailable. Check FastAPI or local Ollama.';
  return 'Request failed.';
}

function validLogin(data) {
  return data && typeof data.access_token === 'string' && data.access_token.length <= 4096 &&
    /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(data.access_token) &&
    data.token_type === 'bearer' && Number.isInteger(data.expires_in) &&
    data.expires_in > 0 && data.expires_in <= 86400;
}

function validIdentity(data) {
  return data && typeof data.username === 'string' && data.username.length > 0 &&
    ['intern', 'manager'].includes(data.role);
}

export function createSessionController({ fetcher = (...args) => fetch(...args),
  now = () => Date.now(), schedule = setTimeout, cancel = clearTimeout } = {}) {
  let snapshot = initial();
  let generation = 0;
  let session = null; // JWT stays private in this closure, never in storage or the snapshot.
  let expiryTimer = null;
  let eventRequest = null;
  const pending = new Set();
  const listeners = new Set();

  function publish(next) {
    snapshot = next;
    for (const listener of listeners) listener();
  }
  function update(changes) { publish({ ...snapshot, ...changes }); }
  function reset(status = 'anonymous', notice = '') {
    generation += 1;
    session = null;
    if (expiryTimer !== null) cancel(expiryTimer);
    expiryTimer = null;
    for (const controller of pending) controller.abort();
    pending.clear();
    eventRequest = null;
    publish(initial(status, notice));
    return generation;
  }
  function checkExpiry() {
    if (session && now() >= session.deadline) reset('anonymous', expiredMessage);
    return session !== null;
  }
  function armExpiry(version) {
    if (version !== generation || !session) return;
    const remaining = session.deadline - now();
    if (remaining <= 0) { reset('anonymous', expiredMessage); return; }
    expiryTimer = schedule(() => armExpiry(version), remaining);
  }
  function current(version) { return version === generation && checkExpiry(); }

  // No ambient cookies, no redirects, no persisted HTTP cache. Only fixed API paths.
  async function request(path, { method = 'GET', token, body, controller, authTimeout = false } = {}) {
    const headers = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    pending.add(controller);
    const timer = authTimeout ? schedule(() => controller.abort(), AUTH_TIMEOUT) : null;
    try {
      const response = await fetcher(API + path, { method, headers, credentials: 'omit',
        cache: 'no-store', redirect: 'error', signal: controller.signal,
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
      // Never echo raw HTTP error bodies (they may contain sensitive input).
      const data = response.ok && response.status !== 204 ? await response.json() : null;
      if (controller.signal.aborted) throw new Error('Request aborted');
      return { status: response.status, ok: response.ok, data };
    } finally {
      pending.delete(controller);
      if (timer !== null) cancel(timer);
    }
  }

  async function login(username, password) {
    if (snapshot.status !== 'anonymous') return;
    const version = reset('authenticating');
    const controller = new AbortController();
    const started = now();
    let token = null;
    try {
      const response = await request('/api/auth/login', { method: 'POST',
        body: { username, password }, controller, authTimeout: true });
      if (version !== generation) return;
      if (!response.ok) {
        reset('anonymous', response.status === 401 ? 'Invalid credentials.' : errorMessage(response.status));
        return;
      }
      if (!validLogin(response.data)) throw new Error('Invalid login response');
      token = response.data.access_token;
      const deadline = started + response.data.expires_in * 1000;
      const identity = await request('/api/auth/me', { token, controller, authTimeout: true });
      if (version !== generation) return;
      if (!identity.ok || !validIdentity(identity.data) || now() >= deadline) {
        throw new Error('Identity not verified');
      }
      session = { token, deadline };
      publish({ ...initial('authenticated'), sessionVersion: version,
        user: { username: identity.data.username, role: identity.data.role } });
      armExpiry(version);
      void loadEvents();
    } catch {
      if (version !== generation) return;
      // A login may have succeeded while /me failed. Best effort revoke the
      // unadopted credential; no token is retained or trusted in the UI.
      if (token) {
        const cleanup = new AbortController();
        reset('signingOut', 'Identity could not be verified.');
        const cleanupVersion = generation;
        try { await request('/api/auth/logout', { method: 'POST', token, controller: cleanup, authTimeout: true }); }
        catch { /* orphan session expires server-side */ }
        if (cleanupVersion === generation) reset('anonymous', 'Identity could not be verified. Sign in again.');
      } else reset('anonymous', networkMessage);
    }
  }

  async function logout() {
    if (!checkExpiry()) return;
    const token = session.token;
    // Invalidate before sending logout: no old result can repopulate the UI.
    const version = reset('signingOut');
    let notice = 'Signed out.';
    try {
      const response = await request('/api/auth/logout', { method: 'POST', token,
        controller: new AbortController(), authTimeout: true });
      if (response.status !== 204) notice = 'Local session cleared. Server revocation not confirmed.';
    } catch { notice = 'Local session cleared. Server revocation not confirmed.'; }
    if (version === generation) reset('anonymous', notice);
  }

  async function loadEvents() {
    if (!checkExpiry()) return;
    const version = generation;
    const token = session.token;
    eventRequest?.abort();
    const controller = new AbortController();
    eventRequest = controller;
    update({ eventsBusy: true, eventsError: '' });
    try {
      const response = await request('/api/events', { token, controller });
      if (!current(version) || eventRequest !== controller) return;
      if (response.status === 401) { reset('anonymous', expiredMessage); return; }
      if (!response.ok || !Array.isArray(response.data?.events) || !Array.isArray(response.data?.alerts)) {
        update({ events: [], alerts: [], eventsError: errorMessage(response.status) });
        return;
      }
      update({ events: response.data.events, alerts: response.data.alerts });
    } catch {
      if (current(version) && eventRequest === controller) {
        update({ events: [], alerts: [], eventsError: networkMessage });
      }
    } finally {
      if (current(version) && eventRequest === controller) {
        eventRequest = null;
        update({ eventsBusy: false });
      }
    }
  }

  async function send(path, body) {
    if (!checkExpiry() || snapshot.busy) return;
    const version = generation;
    const token = session.token;
    const controller = new AbortController();
    update({ busy: true, result: null });
    try {
      const response = await request(path, { method: 'POST', token, body, controller });
      if (!current(version)) return;
      if (response.status === 401) { reset('anonymous', expiredMessage); return; }
      update({ result: response.ok ? response.data : { error: errorMessage(response.status) } });
    } catch {
      if (current(version)) update({ result: { error: networkMessage } });
    } finally {
      if (current(version)) {
        update({ busy: false });
        void loadEvents();
      }
    }
  }

  return {
    getSnapshot: () => snapshot,
    subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
    login, logout, loadEvents, checkExpiry,
    simulate: documentId => send('/api/simulate', { tool: 'read_document', arguments: { document_id: documentId } }),
    chat: prompt => send('/api/chat', { prompt }),
    dispose: () => reset(),
  };
}
