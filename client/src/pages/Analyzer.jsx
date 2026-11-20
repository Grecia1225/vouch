import { useState } from "react";
import { Link } from "react-router-dom";
import { postForm, postFormBlob, getToken } from "../api.js";
import { buildForm } from "../inputs.js";
import InputPicker from "../components/InputPicker.jsx";
import MetaReport from "../components/MetaReport.jsx";

export default function Analyzer() {
  const [items, setItems] = useState([]);
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [ordered, setOrdered] = useState([]); // items in the order the server returns results (files, then links)

  const analyse = async () => {
    setBusy(true); setError(""); setResults(null);
    try {
      setOrdered([...items.filter((i) => i.kind === "file"), ...items.filter((i) => i.kind === "url")]);
      const data = await postForm("/metadata/analyze", buildForm(items));
      setResults(data.results);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const extract = async (index, candidate) => {
    const item = ordered[index];
    if (!getToken()) { setError("Log in to extract hidden data."); return; }
    if (!item || item.kind !== "file") { setError("Extraction works for uploaded or captured files."); return; }
    try {
      const blob = await postFormBlob("/stego/extract", buildForm([item], { candidateId: candidate.id }));
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `extracted-${candidate.id.replace(/[^a-z0-9]+/gi, "-")}.dat`;
      a.click();
    } catch (e) { setError(e.message); }
  };

  return (
    <>
      <section className="card">
        <h2>Metadata Analyser</h2>
        <p className="muted">
          Inspect who created a file, with what software, and when. Works with PDF, Word, Excel, PowerPoint, images and audio.
          Add files, take a photo, record your voice or paste a link. Everything is analysed in memory and not stored.
        </p>
        <InputPicker items={items} setItems={setItems} />
        <div className="row top-gap">
          <button className="btn" disabled={!items.length || busy} onClick={analyse}>{busy ? "Analysing..." : `Analyse ${items.length || ""} item${items.length === 1 ? "" : "s"}`}</button>
        </div>
        {error && <p className="error">{error}</p>}
      </section>

      {results && results.map((x, i) => (
        <div key={i}>
          <h3 className="result-title">{x.name}</h3>
          {x.error ? <section className="card"><p className="error">{x.error}</p></section> : <MetaReport r={x.report} onExtract={(c) => extract(i, c)} />}
        </div>
      ))}
      {results && (
        <p className="muted">
          Want permanent, verifiable proof of these files? <Link to={getToken() ? "/dashboard" : "/register"}>Notarize them with Vouch</Link>.
        </p>
      )}
    </>
  );
}
