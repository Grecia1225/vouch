import { useEffect, useState } from "react";
import { getBlob, getJson, postForm } from "../api.js";
import { buildForm } from "../inputs.js";
import InputPicker from "../components/InputPicker.jsx";
import MetaReport from "../components/MetaReport.jsx";
import SharePanel from "../components/SharePanel.jsx";

const short = (h) => (h ? `${h.slice(0, 10)}...${h.slice(-6)}` : "");
const STATUS = {
  ok: ["ok-bg", "Notarized"],
  exists: ["warn-bg", "Already notarized"],
  error: ["bad-bg", "Failed"],
};

export default function Dashboard() {
  const [docs, setDocs] = useState([]);
  const [items, setItems] = useState([]);
  const [results, setResults] = useState(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState(null);
  const [cfg, setCfg] = useState({});
  const [shareFor, setShareFor] = useState(null);
  const [meta, setMeta] = useState(undefined); // undefined = hidden, null = none stored

  const load = () => getJson("/docs").then(setDocs).catch((e) => setMsg({ type: "error", text: e.message }));
  useEffect(() => { load(); getJson("/config").then(setCfg).catch(() => {}); }, []);

  const txLink = (tx) => cfg.explorerTxUrl
    ? <a href={cfg.explorerTxUrl + tx} target="_blank" rel="noreferrer"><code title={tx}>{short(tx)}</code></a>
    : <code title={tx}>{short(tx)}</code>;

  const newVersion = async (id, file) => {
    if (!file) return;
    setBusy(true); setMsg(null); setResults(null);
    try {
      const data = await postForm(`/docs/${id}/version`, buildForm([{ kind: "file", file, context: { source: "file" } }]));
      setResults(data.results);
      load();
    } catch (e) { setMsg({ type: "error", text: e.message }); } finally { setBusy(false); }
  };

  const notarize = async () => {
    setBusy(true); setMsg(null); setResults(null);
    try {
      const data = await postForm("/docs/notarize", buildForm(items));
      setResults(data.results);
      setItems([]);
      load();
    } catch (e) {
      setMsg({ type: "error", text: e.message });
    } finally {
      setBusy(false);
    }
  };

  const openBlob = async (path, filename, download) => {
    // open the tab immediately (inside the click) so popup blockers allow it
    const win = download ? null : window.open("", "_blank");
    try {
      const blob = await getBlob(path);
      const url = URL.createObjectURL(blob);
      if (download) {
        const a = document.createElement("a");
        a.href = url; a.download = filename; a.click();
      } else if (win) {
        win.location.href = url;
      }
    } catch (e) {
      if (win) win.close();
      setMsg({ type: "error", text: e.message });
    }
  };

  const showMeta = async (id) => {
    try { setMeta(await getJson(`/docs/${id}/metadata`)); } catch (e) { setMsg({ type: "error", text: e.message }); }
  };

  return (
    <>
      <section className="card">
        <h2>Notarize</h2>
        <p className="muted">Add one or many items: files, a live photo, a voice recording or a link. Only each item's fingerprint goes on the blockchain.</p>
        <InputPicker items={items} setItems={setItems} />
        <div className="row top-gap">
          <button className="btn" disabled={!items.length || busy} onClick={notarize}>
            {busy ? "Anchoring on chain..." : `Notarize ${items.length || ""} item${items.length === 1 ? "" : "s"}`}
          </button>
        </div>
        {msg && <p className={msg.type === "ok" ? "ok" : "error"}>{msg.text}</p>}
        {results && (
          <ul className="results">
            {results.map((r, i) => {
              const [cls, label] = STATUS[r.status] || STATUS.error;
              return (
                <li key={i}>
                  <span className={`badge ${cls}`}>{label}</span>
                  <span className="grow name">{r.name}</span>
                  <code title={r.doc ? r.doc.hash : r.hash}>{short(r.doc ? r.doc.hash : r.hash)}</code>
                  {r.error && <span className="error">{r.error}</span>}
                </li>
              );
            })}
          </ul>
        )}
      </section>

      <section className="card">
        <h2>My documents</h2>
        {docs.length === 0 ? (
          <p className="muted">Nothing notarized yet.</p>
        ) : (
          <div className="scroll">
            <table>
              <thead>
                <tr><th>File</th><th>Ver.</th><th>Via</th><th>SHA-256</th><th>Notarized (UTC)</th><th>Tx</th><th></th></tr>
              </thead>
              <tbody>
                {docs.map((d) => (
                  <tr key={d._id}>
                    <td>{d.filename}</td>
                    <td>v{d.version || 1}</td>
                    <td>{d.capture && d.capture.source ? d.capture.source : "file"}{d.capture && d.capture.location ? " + location" : ""}</td>
                    <td><code title={d.hash}>{short(d.hash)}</code></td>
                    <td>{new Date(d.notarizedAt).toUTCString().slice(5, 25)}</td>
                    <td>{txLink(d.txHash)}</td>
                    <td className="actions">
                      <button className="btn small" onClick={() => openBlob(`/docs/${d._id}/certificate`)}>Certificate</button>
                      <button className="btn small outline" onClick={() => openBlob(`/docs/${d._id}/download`, d.filename, true)}>Download</button>
                      <button className="btn small outline" onClick={() => showMeta(d._id)}>Metadata</button>
                      <button className="btn small outline" onClick={() => setShareFor(d._id)}>Share</button>
                      <label className="btn small outline">
                        New version
                        <input type="file" hidden onChange={(e) => { newVersion(d._id, e.target.files[0]); e.target.value = ""; }} />
                      </label>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {shareFor && docs.find((d) => d._id === shareFor) && (
        <SharePanel
          doc={docs.find((d) => d._id === shareFor)}
          onChanged={load}
          openPublicCertificate={() => openBlob(`/docs/${shareFor}/certificate?variant=public`)}
        />
      )}
      {meta !== undefined && <MetaReport r={meta} />}
    </>
  );
}
