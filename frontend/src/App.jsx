import React, { useEffect, useState, useSyncExternalStore } from 'react';
import { createSessionController } from './session.js';

function Login({ controller, state }) {
  const locked = state.status !== 'anonymous';
  function submit(event) {
    event.preventDefault();
    if (locked) return;
    const form = event.currentTarget;
    const values = new FormData(form);
    const username = values.get('username');
    const password = values.get('password');
    form.elements.password.value = '';
    void controller.login(username, password);
  }
  return (
    <section className="panel">
      <h2>1. Sign in to AgentGuard</h2>
      <p>Use your provisioned demo account. The server determines your role.</p>
      <form onSubmit={submit}>
        <label htmlFor="username">Username</label>
        <input id="username" name="username" autoComplete="username" required maxLength={64} disabled={locked} />
        <label htmlFor="password">Password</label>
        <input id="password" name="password" type="password" autoComplete="current-password" required maxLength={1024} disabled={locked} />
        <button type="submit" disabled={locked}>{state.status === 'authenticating' ? 'Signing in…' : state.status === 'signingOut' ? 'Signing out…' : 'Sign in'}</button>
      </form>
      {state.notice && <p role="status">{state.notice}</p>}
    </section>
  );
}

function Dashboard({ controller, state }) {
  const [documentId, setDocumentId] = useState('private-budget');
  const [prompt, setPrompt] = useState('Please summarize the public-injected document.');
  const { user, busy, result, events, alerts, eventsBusy, eventsError } = state;
  return (
    <>
      <section className="panel">
        <div className="row"><h2>1. Authenticated identity</h2><button className="secondary" onClick={() => void controller.logout()}>Logout</button></div>
        <p>Signed in as <strong>{user.username}</strong> — {user.role}</p>
        <small>Role verified by the backend. Reloading the page requires signing in again.</small>
      </section>
      <section className="cols">
        <div className="panel"><h2>2. Test security policy (no AI needed)</h2>
          <label htmlFor="document-id">Document ID</label>
          <select id="document-id" value={documentId} onChange={e => setDocumentId(e.target.value)}>
            <option value="private-budget">private-budget (restricted)</option>
            <option value="public-roadmap">public-roadmap (public)</option>
            <option value="public-injected">public-injected (untrusted text)</option>
          </select>
          <button disabled={busy} onClick={() => void controller.simulate(documentId)}>Simulate tool call</button>
        </div>
        <div className="panel"><h2>3. Try real Qwen3 agent</h2>
          <label htmlFor="prompt">Prompt to send to Ollama</label>
          <textarea id="prompt" value={prompt} onChange={e => setPrompt(e.target.value)} rows={4} maxLength={3000} />
          <button disabled={busy || !prompt.trim()} onClick={() => void controller.chat(prompt)}>Run local agent</button>
          <small>Requires Ollama with qwen3:1.7b. The model does not bypass AgentGuard's policy.</small>
        </div>
      </section>
      <section className="panel"><h2>Response</h2><pre aria-live="polite">{busy ? 'Request in progress…' : result ? JSON.stringify(result, null, 2) : 'Run a simulation or an agent request.'}</pre></section>
      <section className="panel"><div className="row"><h2>Security monitoring</h2><button className="secondary" disabled={eventsBusy} onClick={() => void controller.loadEvents()}>Refresh</button></div>
        <small>Global demo audit feed; per-role visibility is pending backend coordination.</small>
        {eventsError ? <p role="status">{eventsError}</p> : <p>{alerts.length ? 'Alerts: ' + alerts.map(a => a.actor + ' (' + a.count + ' blocked)').join(', ') : 'No repeated-denial alerts.'}</p>}
        <div className="scroll"><table><thead><tr><th>Actor</th><th>Tool</th><th>Target</th><th>Decision</th><th>Reason</th></tr></thead>
          <tbody>{events.map((e, i) => <tr key={i}><td>{e.actor}</td><td>{e.tool}</td><td>{e.target}</td><td>{e.allowed ? 'Allowed' : 'Blocked'}</td><td>{e.reason}</td></tr>)}</tbody>
        </table></div>
      </section>
    </>
  );
}

export default function App() {
  const [controller] = useState(() => createSessionController());
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot);
  useEffect(() => {
    const check = () => controller.checkExpiry();
    const leave = () => controller.dispose();
    window.addEventListener('focus', check);
    window.addEventListener('pagehide', leave);
    document.addEventListener('visibilitychange', check);
    return () => {
      window.removeEventListener('focus', check);
      window.removeEventListener('pagehide', leave);
      document.removeEventListener('visibilitychange', check);
      controller.dispose();
    };
  }, [controller]);

  return (
    <main>
      <header><span className="eyebrow">AI AGENT SECURITY LAB</span><h1>AgentGuard</h1><p>Inspect tool actions. Deny unauthorized access. Audit every decision.</p></header>
      {state.status === 'authenticated'
        ? <Dashboard key={state.sessionVersion} controller={controller} state={state} />
        : <Login controller={controller} state={state} />}
      <footer>University prototype. Do not use real confidential data.</footer>
    </main>
  );
}
