import { useEffect, useState } from 'react';

const API = 'http://localhost:8000';

export default function App() {
  const [actor, setActor] = useState('alice');
  const [documentId, setDocumentId] = useState('private-budget');
  const [prompt, setPrompt] = useState('Please summarize the public-injected document.');
  const [result, setResult] = useState(null);
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [busy, setBusy] = useState(false);

  async function loadEvents() {
    try {
      const response = await fetch(API + '/api/events');
      if (response.ok) {
        const data = await response.json();
        setEvents(data.events);
        setAlerts(data.alerts);
      }
    } catch { /* backend may not be running yet */ }
  }

  useEffect(() => { loadEvents(); }, []);

  async function send(path, data) {
    setBusy(true);
    setResult(null);
    try {
      const response = await fetch(API + path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      const body = await response.json();
      setResult(response.ok ? body : { error: body.detail || 'Request failed' });
    } catch {
      setResult({ error: 'Backend offline. Run uvicorn backend.main:app --reload.' });
    } finally {
      setBusy(false);
      loadEvents();
    }
  }

  return (
    <main>
      <header><span className="eyebrow">AI AGENT SECURITY LAB</span><h1>AgentGuard</h1><p>Inspect tool actions. Deny unauthorized access. Audit every decision.</p></header>
      <section className="panel">
        <h2>1. Choose demo identity</h2>
        <label>Actor (demo only — this is not authentication)</label>
        <select value={actor} onChange={e => setActor(e.target.value)}>
          <option value="alice">Alice — intern (public only)</option>
          <option value="bob">Bob — manager (public + restricted)</option>
        </select>
      </section>
      <section className="cols">
        <div className="panel"><h2>2. Test security policy (no AI needed)</h2>
          <label>Document ID</label>
          <select value={documentId} onChange={e => setDocumentId(e.target.value)}>
            <option value="private-budget">private-budget (restricted)</option>
            <option value="public-roadmap">public-roadmap (public)</option>
            <option value="public-injected">public-injected (untrusted text)</option>
          </select>
          <button disabled={busy} onClick={() => send('/api/simulate', { actor_id: actor, tool: 'read_document', arguments: { document_id: documentId } })}>Simulate tool call</button>
        </div>
        <div className="panel"><h2>3. Try real Qwen3 agent</h2>
          <label>Prompt to send to Ollama</label>
          <textarea value={prompt} onChange={e => setPrompt(e.target.value)} rows={4} />
          <button disabled={busy || !prompt.trim()} onClick={() => send('/api/chat', { actor_id: actor, prompt })}>Run local agent</button>
          <small>Requires Ollama with qwen3:1.7b. The model does not bypass AgentGuard's policy.</small>
        </div>
      </section>
      <section className="panel"><h2>Response</h2><pre>{result ? JSON.stringify(result, null, 2) : 'Run a simulation or an agent request.'}</pre></section>
      <section className="panel"><div className="row"><h2>Security monitoring</h2><button className="secondary" onClick={loadEvents}>Refresh</button></div>
        <p>{alerts.length ? 'Alerts: ' + alerts.map(a => a.actor + ' (' + a.count + ' blocked)').join(', ') : 'No repeated-denial alerts.'}</p>
        <div className="scroll"><table><thead><tr><th>Actor</th><th>Tool</th><th>Target</th><th>Decision</th><th>Reason</th></tr></thead>
          <tbody>{events.map((e, i) => <tr key={i}><td>{e.actor}</td><td>{e.tool}</td><td>{e.target}</td><td>{e.allowed ? 'Allowed' : 'Blocked'}</td><td>{e.reason}</td></tr>)}</tbody>
        </table></div>
      </section>
      <footer>University prototype. Do not use real confidential data.</footer>
    </main>
  );
}
