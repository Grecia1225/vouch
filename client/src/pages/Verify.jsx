import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { getJson, postForm } from "../api.js";
import { buildForm, extractHash, extractToken } from "../inputs.js";
import InputPicker from "../components/InputPicker.jsx";
import QrScanner from "../components/QrScanner.jsx";

const when = (ts) => new Date(ts * 1000).toUTCString();

export default function Verify() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const [expectedHash, setExpectedHash] = useState(params.get("hash") || ""); // from a certificate QR
  const [lookup, setLookup] = useState(null);
  const [items, setItems] = useState([]);
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [showScan, setShowScan] = useState(false);

  useEffect(() => {
    setLookup(null);
    if (expectedHash) getJson(`/verify/${expectedHash}`).then(setLookup).catch((e) => setError(e.message));
  }, [expectedHash]);

  const onScan = (text) => {
    const tok = extractToken(text);
    setShowScan(false);
    if (tok) { navigate(`/v/${tok}`); return; } // certificate QR: open the minimal third-party view
    const h = extractHash(text);
    if (h) { setExpectedHash(h); setError(""); setResults(null); }
    else setError("That QR code is not a Vouch certificate.");
  };

  const verify = async () => {
    setBusy(true); setError(""); setResults(null);
    try {
      const data = await postForm("/verify", buildForm(items, { expectedHash: items.length === 1 ? expectedHash : "" }));
      setResults(data.results);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <section className="card">
        <h2>Verify documents</h2>
        <p className="muted">
          Add the file(s) to check: upload, camera, voice or a link. Vouch re-computes each SHA-256 and compares it with the blockchain. Nothing is stored. Prefer not to trust our server? <Link to="/independent">Check independently</Link>.
        </p>

        <div className="row">
          <button className="btn outline" onClick={() => setShowScan((s) => !s)}>{showScan ? "Close scanner" : "Scan certificate QR"}</button>
          {expectedHash && (
            <span className="chip">
              Certificate loaded: {expectedHash.slice(0, 10)}...
              <button className="link-btn" onClick={() => { setExpectedHash(""); setLookup(null); }}>clear</button>
            </span>
          )}
        </div>
        {showScan && <QrScanner onResult={onScan} />}

        {lookup && (
          <div className={lookup.found ? "banner ok-bg top-gap" : "banner warn-bg top-gap"}>
            {lookup.found
              ? <>Certificate fingerprint found on chain, registered {when(lookup.record.timestamp)}. Add the original file below to confirm it is unaltered.</>
              : <>This fingerprint is not on the blockchain.</>}
          </div>
        )}

        <div className="top-gap"><InputPicker items={items} setItems={setItems} /></div>
        {expectedHash && items.length > 1 && (
          <p className="muted">Tampering detection against a certificate works with one file at a time. With several items each is checked on its own.</p>
        )}
        <div className="row top-gap">
          <button className="btn" disabled={!items.length || busy} onClick={verify}>{busy ? "Checking..." : `Verify ${items.length || ""} item${items.length === 1 ? "" : "s"}`}</button>
        </div>
        {error && <p className="error">{error}</p>}
      </section>

      {results && results.map((r, i) => <Result key={i} r={r} />)}
    </>
  );
}

function Result({ r }) {
  const [versions, setVersions] = useState([]);
  useEffect(() => {
    if (r.status === "AUTHENTIC") getJson(`/verify/${r.hash}/history`).then((d) => setVersions(d.versions || [])).catch(() => {});
  }, [r.hash, r.status]);

  const view = {
    AUTHENTIC: { cls: "ok-bg", title: "AUTHENTIC", text: "This file matches a blockchain record exactly. It has not been altered since it was registered." },
    TAMPERED: { cls: "bad-bg", title: "TAMPERED", text: "This file does NOT match the registered fingerprint from the certificate. It has been altered or is a different file." },
    NOT_FOUND: { cls: "warn-bg", title: "NO RECORD FOUND", text: "No blockchain record matches this file. It was never notarized with Vouch, or it has been changed." },
    ERROR: { cls: "bad-bg", title: "COULD NOT CHECK", text: r.error },
  }[r.status];

  return (
    <section className={`card result ${view.cls}`}>
      <h2>{view.title}: {r.name}</h2>
      <p>{view.text}</p>
      {r.hash && (
        <details>
          <summary>Technical details</summary>
          <dl>
          <dt>Computed SHA-256</dt><dd><code>{r.hash}</code></dd>
          {r.expectedHash && (<><dt>Expected SHA-256</dt><dd><code>{r.expectedHash}</code></dd></>)}
          {r.record && (<><dt>Registered at (UTC)</dt><dd>{when(r.record.timestamp)}</dd></>)}
          {r.txHash && (<><dt>Transaction</dt><dd><code>{r.txHash}</code></dd></>)}
          {r.blockNumber && (<><dt>Block</dt><dd>{r.blockNumber}</dd></>)}
          {versions.length > 1 && (<><dt>Version history</dt><dd>{versions.map((v, i) => (<div key={v.hash}><code>{v.hash.slice(0, 16)}...</code> {new Date(v.timestamp * 1000).toISOString()}{i === 0 ? " (this file)" : ""}</div>))}</dd></>)}
          </dl>
        </details>
      )}
    </section>
  );
}
