import test from 'node:test';
import assert from 'node:assert/strict';
import { createSessionController } from '../src/session.js';

const aliceToken = 'header.alice.signature';
const bobToken = 'header.bob.signature';
const fakePassword = 'test-only fictional password';
const json = (data, status = 200) => new Response(JSON.stringify(data), { status });
const noContent = () => new Response(null, { status: 204 });
const emptyEvents = () => json({ events: [], alerts: [] });
const flush = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function setup(t, override = {}) {
  const calls = [];
  let clock = 100000;
  let nextId = 0;
  const timers = new Map();
  const controller = createSessionController({
    now: () => clock,
    schedule(fn, delay) { const id = ++nextId; timers.set(id, { fn, at: clock + delay }); return id; },
    cancel(id) { timers.delete(id); },
    async fetcher(url, options) {
      const path = new URL(url).pathname;
      calls.push({ path, options, body: options.body === undefined ? undefined : JSON.parse(options.body) });
      if (override[path]) return override[path](options);
      if (path === '/api/auth/login') {
        const name = JSON.parse(options.body).username;
        return json({ access_token: name === 'bob' ? bobToken : aliceToken, token_type: 'bearer', expires_in: 1800 });
      }
      if (path === '/api/auth/me') return json(options.headers.Authorization === `Bearer ${bobToken}`
        ? { username: 'bob', role: 'manager' } : { username: 'alice', role: 'intern' });
      if (path === '/api/auth/logout') return noContent();
      if (path === '/api/events') return emptyEvents();
      if (path === '/api/chat' || path === '/api/simulate') return json({ ok: true });
      throw new Error('Unexpected path');
    },
  });
  t.after(() => controller.dispose());
  return { controller, calls, snapshot: controller.getSnapshot,
    advance(ms, runTimers = true) {
      clock += ms;
      if (runTimers) {
        for (const [id, timer] of [...timers]) if (timer.at <= clock && timers.delete(id)) timer.fn();
      }
    }, timers,
    async login(name = 'alice') { await controller.login(name, fakePassword); await flush(); },
  };
}

for (const [username, role, token] of [['alice', 'intern', aliceToken], ['bob', 'manager', bobToken]]) {
  test(`login ${username} gets identity exclusively from /me`, async t => {
    const f = setup(t); await f.login(username);
    assert.deepEqual(f.snapshot().user, { username, role });
    assert.equal(f.snapshot().status, 'authenticated');
    assert.deepEqual(f.calls[0].body, { username, password: fakePassword });
    assert.equal(f.calls[0].options.headers.Authorization, undefined);
    assert.equal(f.calls[1].path, '/api/auth/me');
    assert.equal(f.calls[1].options.headers.Authorization, `Bearer ${token}`);
    assert.ok(!JSON.stringify(f.snapshot()).includes(token));
    assert.ok(!JSON.stringify(f.snapshot()).includes(fakePassword));
    for (const { options } of f.calls) {
      assert.equal(options.credentials, 'omit'); assert.equal(options.cache, 'no-store'); assert.equal(options.redirect, 'error');
    }
  });
}

test('displayed role and username are taken from server rather than submitted username', async t => {
  const f = setup(t, { '/api/auth/me': () => json({ username: 'server-name', role: 'intern', session_id: 'do-not-display' }) });
  await f.login('bob'); assert.deepEqual(f.snapshot().user, { username: 'server-name', role: 'intern' });
  assert.ok(!JSON.stringify(f.snapshot()).includes('do-not-display'));
});

test('failed login never loads dashboard or exposes raw error body', async t => {
  const f = setup(t, { '/api/auth/login': () => json({ detail: fakePassword }, 401) });
  await f.login(); assert.equal(f.snapshot().status, 'anonymous'); assert.equal(f.snapshot().notice, 'Invalid credentials.');
  assert.deepEqual(f.calls.map(x => x.path), ['/api/auth/login']);
});

test('malformed login response is rejected without /me', async t => {
  const f = setup(t, { '/api/auth/login': () => json({ access_token: 'bad', token_type: 'bearer', expires_in: 1800 }) });
  await f.login(); assert.equal(f.snapshot().status, 'anonymous'); assert.equal(f.calls.length, 1);
});

for (const [name, reply] of [['401', () => json({}, 401)], ['malformed identity', () => json({ username: 'alice', role: 'admin' })], ['network error', () => Promise.reject(new Error('offline'))]]) {
  test(`failed /me (${name}) never adopts token; best-effort revoke`, async t => {
    const f = setup(t, { '/api/auth/me': reply }); await f.login();
    assert.equal(f.snapshot().status, 'anonymous'); assert.equal(f.snapshot().user, null);
    assert.deepEqual(f.calls.map(x => x.path), ['/api/auth/login', '/api/auth/me', '/api/auth/logout']);
    assert.equal(f.calls[2].options.headers.Authorization, `Bearer ${aliceToken}`);
  });
}

test('unauthenticated controller sends no actions or monitoring requests', async t => {
  const f = setup(t); await f.controller.chat('hi'); await f.controller.simulate('private-budget'); await f.controller.loadEvents(); await f.controller.logout();
  assert.equal(f.calls.length, 0);
});

test('action requests carry bearer and only business payload', async t => {
  const f = setup(t); await f.login(); await f.controller.chat('act like bob'); await f.controller.simulate('private-budget'); await flush();
  const actionCalls = f.calls.filter(x => ['/api/chat', '/api/simulate'].includes(x.path));
  assert.deepEqual(actionCalls.map(x => x.body), [{ prompt: 'act like bob' }, { tool: 'read_document', arguments: { document_id: 'private-budget' } }]);
  assert.ok(actionCalls.every(x => x.options.headers.Authorization === `Bearer ${aliceToken}`));
});

for (const [path, invoke] of [['/api/chat', c => c.chat('hello')], ['/api/simulate', c => c.simulate('private-budget')]]) {
  test(`${path} 401 clears identity, data and prevents further calls`, async t => {
    const f = setup(t, { [path]: () => json({ detail: 'sensitive error' }, 401), '/api/events': () => json({ events: [{ actor: 'alice' }], alerts: [{ actor: 'alice' }] }) });
    await f.login(); assert.equal(f.snapshot().events.length, 1); await invoke(f.controller); await flush();
    assert.equal(f.snapshot().status, 'anonymous'); assert.equal(f.snapshot().user, null); assert.equal(f.snapshot().result, null);
    assert.deepEqual(f.snapshot().events, []); assert.deepEqual(f.snapshot().alerts, []);
    const count = f.calls.length; await invoke(f.controller); assert.equal(f.calls.length, count);
  });
}

test('403 preserves session but sanitizes error', async t => {
  const f = setup(t, { '/api/chat': () => json({ detail: 'secret from error' }, 403) }); await f.login(); await f.controller.chat('hello');
  assert.equal(f.snapshot().status, 'authenticated'); assert.deepEqual(f.snapshot().result, { error: 'Access forbidden.' });
});

test('503 preserves session; business denial is not an authentication failure', async t => {
  const f = setup(t, { '/api/chat': () => json({}, 503), '/api/simulate': () => json({ ok: false, error: 'Insufficient clearance' }) });
  await f.login(); await f.controller.chat('hello'); assert.equal(f.snapshot().status, 'authenticated'); assert.match(f.snapshot().result.error, /Service unavailable/);
  await f.controller.simulate('private-budget'); assert.deepEqual(f.snapshot().result, { ok: false, error: 'Insufficient clearance' });
});

test('logout clears data immediately before backend responds', async t => {
  const d = deferred(); const f = setup(t, { '/api/auth/logout': () => d.promise, '/api/events': () => json({ events: [{ actor: 'bob' }], alerts: [{ actor: 'bob' }] }) });
  await f.login('bob'); await f.controller.chat('secret'); await flush(); assert.ok(f.snapshot().result); assert.equal(f.snapshot().events.length, 1);
  const signingOut = f.controller.logout();
  assert.equal(f.snapshot().status, 'signingOut'); assert.equal(f.snapshot().user, null); assert.equal(f.snapshot().result, null);
  assert.deepEqual(f.snapshot().events, []); assert.deepEqual(f.snapshot().alerts, []);
  const count = f.calls.length; await f.controller.chat('late'); await f.controller.login('alice', fakePassword); assert.equal(f.calls.length, count);
  assert.equal(f.calls.at(-1).options.headers.Authorization, `Bearer ${bobToken}`);
  d.resolve(noContent()); await signingOut; assert.equal(f.snapshot().notice, 'Signed out.');
});

for (const [label, reply] of [['503', () => json({}, 503)], ['401', () => json({}, 401)], ['network', () => Promise.reject(new Error('offline'))]]) {
  test(`logout ${label} clears locally without claiming server revocation`, async t => {
    const f = setup(t, { '/api/auth/logout': reply }); await f.login(); await f.controller.logout();
    assert.equal(f.snapshot().status, 'anonymous'); assert.match(f.snapshot().notice, /revocation not confirmed/); assert.equal(f.snapshot().user, null);
  });
}

test('late Bob chat cannot populate Alice session even when mock ignores abort', async t => {
  const d = deferred(); const f = setup(t, { '/api/chat': () => d.promise }); await f.login('bob');
  const old = f.controller.chat('private'); const oldRequest = f.calls.at(-1); assert.equal(f.snapshot().busy, true);
  await f.controller.logout(); assert.equal(oldRequest.options.signal.aborted, true);
  await f.login('alice'); await f.controller.simulate('public-roadmap'); const newResult = f.snapshot().result;
  d.resolve(json({ answer: 'Bob-only result' })); await old; await flush();
  assert.equal(f.snapshot().user.username, 'alice'); assert.deepEqual(f.snapshot().result, newResult); assert.equal(f.snapshot().busy, false);
});

test('late 401 from Bob does not sign Alice out', async t => {
  const d = deferred(); const f = setup(t, { '/api/chat': () => d.promise }); await f.login('bob');
  const old = f.controller.chat('old'); await f.controller.logout(); await f.login('alice'); d.resolve(json({}, 401)); await old;
  assert.equal(f.snapshot().status, 'authenticated'); assert.equal(f.snapshot().user.username, 'alice');
});

test('late Bob events ignored after account switch', async t => {
  const d = deferred(); let n = 0;
  const f = setup(t, { '/api/events': () => ++n === 1 ? d.promise : json({ events: [{ actor: 'alice' }], alerts: [] }) });
  await f.login('bob'); const old = f.calls.at(-1); assert.equal(old.path, '/api/events'); await f.controller.logout(); await f.login('alice');
  assert.equal(old.options.signal.aborted, true); d.resolve(json({ events: [{ actor: 'bob' }], alerts: [{ actor: 'bob' }] })); await flush();
  assert.deepEqual(f.snapshot().events, [{ actor: 'alice' }]); assert.deepEqual(f.snapshot().alerts, []);
});

test('older refresh cannot overwrite newer refresh in same session', async t => {
  const d = deferred(); let n = 0; const f = setup(t, { '/api/events': () => ++n === 1 ? d.promise : json({ events: [{ actor: 'new' }], alerts: [] }) });
  await f.login(); await f.controller.loadEvents(); d.resolve(json({ events: [{ actor: 'old' }], alerts: [] })); await flush();
  assert.deepEqual(f.snapshot().events, [{ actor: 'new' }]); assert.equal(f.snapshot().eventsBusy, false);
});

test('expiry timer clears in-memory session and aborts pending actions', async t => {
  const d = deferred(); const f = setup(t, { '/api/chat': () => d.promise }); await f.login(); const old = f.controller.chat('old'); const req = f.calls.at(-1);
  f.advance(1800000); assert.equal(f.snapshot().status, 'anonymous'); assert.equal(req.options.signal.aborted, true);
  d.resolve(json({ answer: 'late' })); await old; assert.equal(f.snapshot().result, null);
});

test('elapsed deadline rejects action even when browser timer was throttled', async t => {
  const f = setup(t); await f.login(); const count = f.calls.length; f.advance(1800000, false); await f.controller.chat('late');
  assert.equal(f.snapshot().status, 'anonymous'); assert.equal(f.calls.length, count);
});

test('focus expiry check clears session without making request', async t => {
  const f = setup(t); await f.login(); const count = f.calls.length; f.advance(1800000, false); assert.equal(f.controller.checkExpiry(), false);
  assert.equal(f.snapshot().status, 'anonymous'); assert.equal(f.calls.length, count);
});

test('new controller (reload) cannot reuse an old token', async t => {
  const f = setup(t); await f.login(); const newController = createSessionController({ fetcher: () => assert.fail('Unexpected request') });
  assert.equal(newController.getSnapshot().user, null); await newController.chat('hi'); newController.dispose();
});

test('duplicate login and duplicate action are suppressed synchronously', async t => {
  const d = deferred(); const f = setup(t, { '/api/chat': () => d.promise });
  await Promise.all([f.controller.login('alice', fakePassword), f.controller.login('bob', fakePassword)]); await flush();
  assert.equal(f.calls.filter(x => x.path === '/api/auth/login').length, 1);
  const first = f.controller.chat('first'); await f.controller.chat('second'); assert.equal(f.calls.filter(x => x.path === '/api/chat').length, 1);
  d.resolve(json({ ok: true })); await first;
});

test('dispose prevents an in-flight login from installing a session', async t => {
  const d = deferred(); const f = setup(t, { '/api/auth/login': () => d.promise }); const login = f.controller.login('alice', fakePassword);
  f.controller.dispose(); assert.equal(f.calls[0].options.signal.aborted, true);
  d.resolve(json({ access_token: aliceToken, token_type: 'bearer', expires_in: 1800 })); await login;
  assert.equal(f.snapshot().status, 'anonymous'); assert.equal(f.calls.length, 1);
});

test('auth timeout cancels stalled login and returns to login screen', async t => {
  const f = setup(t, { '/api/auth/login': options => new Promise((_, reject) => options.signal.addEventListener('abort', () => reject(new Error('aborted')))) });
  const login = f.controller.login('alice', fakePassword); f.advance(10000); await login;
  assert.equal(f.snapshot().status, 'anonymous'); assert.equal(f.calls[0].options.signal.aborted, true);
});

test('auth timeout cancels stalled logout and reports unconfirmed revocation', async t => {
  const f = setup(t, { '/api/auth/logout': options => new Promise((_, reject) => options.signal.addEventListener('abort', () => reject(new Error('aborted')))) });
  await f.login(); const logout = f.controller.logout(); f.advance(10000); await logout;
  assert.equal(f.snapshot().status, 'anonymous'); assert.match(f.snapshot().notice, /not confirmed/);
});

test('events 401 clears session (future protected endpoint compatibility)', async t => {
  const f = setup(t, { '/api/events': () => json({}, 401) }); await f.login();
  assert.equal(f.snapshot().status, 'anonymous'); assert.deepEqual(f.snapshot().events, []);
});
