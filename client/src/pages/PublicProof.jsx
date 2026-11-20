import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { getJson, postForm } from "../api.js";
import { buildForm } from "../inputs.js";
import InputPicker from "../components/InputPicker.jsx";

const when = (d) => new Date(d).toUTCString();

// The page a third party sees after opening a share link or scanning a certificate QR.
// It deliberately shows only what the owner chose to reveal.
export default function PublicProof() {
  const { token } = useParams();
  const [info, setInfo] = useState(null);
  const [invalid, setInvalid] = useState(false);
  const [items, setItems] = useState([]);
  const [out, setOut] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [cfg, setCfg] = useState({});

  useEffect(() => {
    getJson(`/p/${token}`).then(setInfo).catch(() => setInvalid(true));
    getJson("/config").then(setCfg).catch(() => {});
  }, [token]);

  const check = async () => {
    setBusy(true); setError(""); setOut(null);
    try { setOut(await postForm(`/p/${token}/check`, buildForm(items))); }
    catch (e) { setError(e.message); }
    finally { setBusy(false); }
  };

  if (invalid) return (
    <section className="card narrow">
      <h2>Link not valid</h2>
      <p className="muted">This link is not valid or has expired. Ask the document owner for a new one.</p>
      <Link to="/verify">Verify a document another way</Link>
    </section>
  );
  if (!info) return <p className="muted">Loading...</p>;

  return (
    <>
      <section className="card result ok-bg">
        <h2>REGISTERED DOCUMENT</h2>
        <p>This document was registered on a blockchain on {when(info.registeredAt)}.</p>
        <dl>
          {info.filename && (<><dt>Document</dt><dd>{info.filename}</dd></>)}
          <dt>Version</dt><dd>{info.version}</dd>
          <dt>Network</dt><dd>{info.network}</dd>
        </dl>
        {info.sha256 && (
          <details>
            <summary>Technical details (shared by the owner)</summary>
            <dl>
              <dt>SHA-256</dt><dd><code>{info.sha256}</code></dd>
              <dt>Transaction</dt>
              <dd>{cfg.explorerTxUrl ? <a href={cfg.explorerTxUrl + info.txHash} target="_blank" rel="noreferrer"><code>{info.txHash}</code></a> : <code>{info.txHash}</code>}</dd>
              <dt>Block</dt><dd>{info.blockNumber}</dd>
            </dl>
            <p><Link to="/independent">Check this without trusting Vouch</Link></p>
          </details>
        )}
      </section>

      <section className="card">
        <h2>Is your copy the same?</h2>
        <p className="muted">
          Add your copy of the document: upload it, photograph it, or paste a link. We compare it with the registered one.
          Your file is not stored.
        </p>
        <InputPicker items={items} setItems={setItems} tabs={["files", "camera", "link"]} />
        <div className="row top-gap">
          <button className="btn" disabled={!items.length || busy} onClick={check}>{busy ? "Checking..." : "Check my copy"}</button>
        </div>
        {error && <p className="error">{error}</p>}
      </section>

      {out && out.results.map((r, i) => <Verdict key={i} r={r} />)}

      <p className="muted small-note">
        Technical details such as the fingerprint and transaction are not shown unless the owner chooses to reveal them.
        A match shows the file is identical to the registered one. It does not show who wrote it or that its content is true.
      </p>
    </>
  );
}

function Verdict({ r }) {
  const v = {
    AUTHENTIC: ["ok-bg", "MATCHES", "Your copy is identical to the registered document."],
    OTHER_VERSION: ["warn-bg", "DIFFERENT VERSION", r.isLatest ? `This is version ${r.version} of the same document, which is the latest version.` : `This is version ${r.version} of the same document. The registered version is ${r.registeredVersion}.`],
    NO_MATCH: ["bad-bg", "DOES NOT MATCH", "Your copy is different from the registered document. It has been changed, or it is another file."],
    RECORD_UNAVAILABLE: ["warn-bg", "CANNOT CONFIRM", "The blockchain record could not be reached right now. Try again shortly."],
    ERROR: ["bad-bg", "COULD NOT CHECK", r.error],
  }[r.status] || ["warn-bg", "UNKNOWN", ""];
  return (
    <section className={`card result ${v[0]}`}>
      <h2>{v[1]}: {r.name}</h2>
      <p>{v[2]}</p>
    </section>
  );
}
