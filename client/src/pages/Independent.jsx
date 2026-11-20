import { useEffect, useState } from "react";
import { Fragment } from "react";
import { getJson } from "../api.js";
import InputPicker from "../components/InputPicker.jsx";
import { getChainId, isAddress, isHash, readHistory, readOwner, sha256Hex } from "../lib/vouchChain.js";

const when = (ts) => new Date(ts * 1000).toUTCString();

export default function Independent() {
  const [rpcUrl, setRpcUrl] = useState("");
  const [contract, setContract] = useState("");
  const [prefilled, setPrefilled] = useState(false);
  const [items, setItems] = useState([]);
  const [hashText, setHashText] = useState("");
  const [out, setOut] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  // Convenience only: the page works with values you type yourself
  useEffect(() => {
    getJson("/config").then((c) => { if (c.rpcUrl) setRpcUrl(c.rpcUrl); if (c.contract) setContract(c.contract); setPrefilled(true); }).catch(() => {});
  }, []);

  const check = async () => {
    setBusy(true); setError(""); setOut(null);
    try {
      if (!/^https?:\/\//i.test(rpcUrl)) throw new Error("Enter an RPC URL starting with http:// or https://");
      if (!isAddress(contract)) throw new Error("Enter the contract address (0x followed by 40 hex characters)");

      const targets = [];
      for (const it of items) targets.push({ name: it.file.name, hash: await sha256Hex(new Uint8Array(await it.file.arrayBuffer())), local: true });
      if (hashText.trim()) {
        if (!isHash(hashText.trim())) throw new Error("That is not a valid SHA-256 hash (64 hex characters)");
        targets.push({ name: "Hash you entered", hash: hashText.trim().toLowerCase(), local: false });
      }
      if (!targets.length) throw new Error("Add a file or enter a hash");

      const chainId = await getChainId(rpcUrl);
      const owner = await readOwner(rpcUrl, contract);
      const results = [];
      for (const t of targets) results.push({ ...t, history: await readHistory(rpcUrl, contract, t.hash) });
      setOut({ chainId, owner, results });
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <section className="card">
        <h2>Independent check</h2>
        <p className="muted">
          This page hashes your file inside your browser and reads the blockchain directly from the RPC node you choose.
          It does not send your file, or the result, to the Vouch server.
        </p>
        <div className="banner ok-bg">
          For a fully independent check, type the RPC URL and contract address yourself (for example from the block explorer)
          {prefilled ? " instead of using the prefilled values" : ""}.
        </div>
        <div className="top-gap form-grid">
          <label>RPC URL<input value={rpcUrl} onChange={(e) => setRpcUrl(e.target.value)} placeholder="https://rpc-amoy.polygon.technology" /></label>
          <label>Contract address<input value={contract} onChange={(e) => setContract(e.target.value.trim())} placeholder="0x..." /></label>
        </div>

        <div className="top-gap"><InputPicker items={items} setItems={setItems} tabs={["files", "camera", "voice"]} /></div>
        <label className="top-gap block">Or enter a SHA-256 hash
          <input value={hashText} onChange={(e) => setHashText(e.target.value)} placeholder="64 hex characters" />
        </label>
        <div className="row top-gap">
          <button className="btn" disabled={busy} onClick={check}>{busy ? "Reading blockchain..." : "Check on blockchain"}</button>
        </div>
        {error && <p className="error">{error}</p>}
      </section>

      {out && (
        <>
          <p className="muted">Network chain id {out.chainId}. Only this address can write records: <code>{out.owner}</code></p>
          {out.results.map((r, i) => {
            const rec = r.history[0];
            return (
              <section key={i} className={`card result ${rec ? "ok-bg" : "warn-bg"}`}>
                <h2>{rec ? "REGISTERED" : "NO RECORD"}: {r.name}</h2>
                <p>{rec
                  ? "These exact bytes were registered on the blockchain at the time below."
                  : "No record for this exact content. It was never registered, or it has changed by even one bit."}</p>
                <dl>
                  <dt>SHA-256</dt><dd><code>{r.hash}</code> {r.local ? "(computed in your browser)" : ""}</dd>
                  {rec && (<>
                    <dt>Registered at (UTC)</dt><dd>{when(rec.timestamp)}</dd>
                    <dt>Uploader</dt><dd>{rec.uploaderRef} (opaque reference)</dd>
                    <dt>Written by</dt><dd><code>{rec.notarizedBy}</code> {rec.notarizedBy.toLowerCase() === out.owner.toLowerCase() ? "(the contract owner)" : "(NOT the contract owner)"}</dd>
                  </>)}
                  {r.history.length > 1 && (<>
                    <dt>Version history</dt>
                    <dd>{r.history.map((h, j) => (<Fragment key={h.hash}><div><code>{h.hash.slice(0, 16)}...</code> {new Date(h.timestamp * 1000).toISOString()}{j === 0 ? " (this one)" : ""}</div></Fragment>))}</dd>
                  </>)}
                </dl>
              </section>
            );
          })}
          <p className="muted small-note">
            Registered proves the exact bytes existed at that time. It does not prove who wrote the file or that its content is true.
          </p>
        </>
      )}
    </>
  );
}
