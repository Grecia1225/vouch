import { useState } from "react";
import { delJson, postJson } from "../api.js";

const LEVELS = [
  ["basic", "Basic: registered, date, version"],
  ["name", "Also show the file name"],
  ["technical", "Also show SHA-256 and transaction"],
];

// Owner-side controls for what a third party can see. More is revealed only when the owner chooses.
export default function SharePanel({ doc, onChanged, openPublicCertificate }) {
  const share = doc.share || {};
  const [level, setLevel] = useState(share.level || "basic");
  const [days, setDays] = useState(0);
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const active = share.token && !share.revoked && (!share.expiresAt || new Date(share.expiresAt) > new Date());
  const url = share.token ? `${window.location.origin}/v/${share.token}` : "";

  const save = async (regenerate = false) => {
    setBusy(true); setMsg("");
    try { await postJson(`/docs/${doc._id}/share`, { level, expiresInDays: days, regenerate }); setMsg("Link updated."); onChanged(); }
    catch (e) { setMsg(e.message); } finally { setBusy(false); }
  };
  const revoke = async () => {
    setBusy(true); setMsg("");
    try { await delJson(`/docs/${doc._id}/share`); setMsg("Link revoked. It no longer works."); onChanged(); }
    catch (e) { setMsg(e.message); } finally { setBusy(false); }
  };
  const copy = async () => { try { await navigator.clipboard.writeText(url); setMsg("Link copied."); } catch { setMsg("Copy the link manually."); } };

  return (
    <section className="card">
      <h2>Share: {doc.filename}</h2>
      <p className="muted">Anyone with the link can check a copy of this document. By default they see only that it is registered, and when.</p>
      <div className="form-grid">
        <label>What the viewer can see
          <select value={level} onChange={(e) => setLevel(e.target.value)}>
            {LEVELS.map(([k, label]) => <option key={k} value={k}>{label}</option>)}
          </select>
        </label>
        <label>Link expires
          <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
            <option value={0}>Never</option><option value={7}>In 7 days</option><option value={30}>In 30 days</option><option value={90}>In 90 days</option>
          </select>
        </label>
      </div>
      <p className="muted small-note">Never shown to a viewer at any level: your name or account, metadata, location, or hidden-content findings.</p>
      <div className="row top-gap">
        <button className="btn" disabled={busy} onClick={() => save(false)}>{active ? "Update link" : "Create link"}</button>
        {active && <button className="btn outline" onClick={copy}>Copy link</button>}
        {active && <button className="btn outline" disabled={busy} onClick={() => save(true)}>New link (old one stops working)</button>}
        {active && <button className="btn danger" disabled={busy} onClick={revoke}>Revoke</button>}
        <button className="btn outline" onClick={openPublicCertificate}>Public certificate (PDF)</button>
      </div>
      {active && <p><code>{url}</code></p>}
      {share.token && !active && <p className="error">This link is revoked or expired.</p>}
      {msg && <p className="muted">{msg}</p>}
    </section>
  );
}
