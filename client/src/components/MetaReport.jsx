import { Fragment } from "react";

const LABELS = {
  title: "Title", subject: "Subject", author: "Author / creator", lastModifiedBy: "Last modified by", keywords: "Keywords",
  creatorTool: "Created with", producer: "Producer", application: "Application", company: "Company",
  created: "Created", modified: "Modified", revision: "Revision", copyright: "Copyright",
};
const fmt = (v) => {
  if (typeof v === "boolean") return v ? "Yes" : "No";
  if (typeof v === "string" && /^\d{4}-\d{2}-\d{2}T/.test(v)) return new Date(v).toUTCString();
  return String(v);
};
const nice = (k) => k.replace(/([A-Z])/g, " $1").replace(/^./, (c) => c.toUpperCase());

function KV({ title, rows }) {
  if (!rows.length) return null;
  return (
    <div className="kv-block">
      <h3>{title}</h3>
      <dl className="kv">
        {rows.map(([k, v]) => (<Fragment key={k}><dt>{k}</dt><dd>{v}</dd></Fragment>))}
      </dl>
    </div>
  );
}

const HIDDEN = {
  "none-found": ["ok-bg", "No evidence of hidden content found"],
  possible: ["warn-bg", "Possible anomaly in hidden-content checks"],
  likely: ["bad-bg", "Anomaly detected: hidden or unusual data found"],
  unknown: ["warn-bg", "Hidden-content checks could not run"],
};

function HiddenSection({ h, onExtract }) {
  if (!h) return null;
  const [cls, label] = HIDDEN[h.summary.level] || HIDDEN.unknown;
  return (
    <div className="kv-block">
      <h3>Hidden-content checks</h3>
      <div className={`banner ${cls}`}>{label}</div>
      <p className="muted">{h.summary.text}</p>
      {h.checks.length > 0 && (
        <ul className="findings">
          {h.checks.map((c, i) => (<li key={i}><span className={`dot ${c.level}`} /><span><strong>{c.title}.</strong> {c.detail}</span></li>))}
        </ul>
      )}
      {h.candidates.length > 0 && (
        <div className="scroll">
          <table>
            <thead><tr><th>Hidden item</th><th>Size</th><th>Entropy</th><th>Preview</th><th></th></tr></thead>
            <tbody>
              {h.candidates.map((c) => (
                <tr key={c.id}>
                  <td>{c.label}{c.detectedType ? ` (${c.detectedType})` : ""}</td>
                  <td>{c.sizeBytes} B</td>
                  <td>{c.entropy}</td>
                  <td><code>{c.text !== undefined ? c.text.slice(0, 120) : c.hex}</code></td>
                  <td>{onExtract && <button className="btn small outline" onClick={() => onExtract(c)}>Extract</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="muted small-note">Extracted data is saved as an inert .dat file. It may be malicious: never open or run it.</p>
        </div>
      )}
      <p className="muted small-note">Coverage: structure {h.coverage.structural ? "checked" : "not applicable"}; LSB analysis {h.coverage.lsb}; text {h.coverage.text}.</p>
      <p className="muted small-note">{h.limitations}</p>
    </div>
  );
}

export default function MetaReport({ r, onExtract }) {
  if (!r) return <p className="muted">No metadata snapshot stored for this document.</p>;
  const risk = {
    low: ["ok-bg", "No inconsistencies found"],
    medium: ["warn-bg", "Review suggested"],
    high: ["bad-bg", "Inconsistencies found"],
  }[r.riskLevel] || ["warn-bg", "Analysis complete"];

  const fileRows = [
    ["File name", r.file.name], ["Size", `${r.file.sizeBytes.toLocaleString()} bytes`],
    ["Detected type", r.file.detectedType], ["Extension matches content", r.file.extensionMatches ? "Yes" : "NO"],
    r.file.clientLastModified && ["File-system modified (your device)", fmt(r.file.clientLastModified)],
  ].filter(Boolean);
  const propRows = Object.entries(r.properties || {}).map(([k, v]) => [LABELS[k] || nice(k), fmt(v)]);
  const cap = r.capture;
  const srcLabel = { camera: "Live camera", voice: "Live voice recording", url: "Link", scan: "QR scan", file: "File upload" };
  const capRows = cap ? [
    ["Entered via", srcLabel[cap.source] || cap.source],
    cap.capturedAt && ["Captured at", fmt(cap.capturedAt)],
    cap.durationSec !== undefined && ["Duration", `${cap.durationSec} seconds`],
    cap.sourceUrl && ["Source link", cap.sourceUrl],
    cap.location && ["Location (browser-reported, unverified)", `${cap.location.latitude}, ${cap.location.longitude}${cap.location.accuracyMeters ? ` (accuracy about ${cap.location.accuracyMeters} m)` : ""}`],
  ].filter(Boolean) : [];
  const { gps, ...tech } = r.technical || {};
  const techRows = Object.entries(tech).map(([k, v]) => [nice(k), fmt(v)]);

  return (
    <section className="card">
      <div className={`banner ${risk[0]}`}>{risk[1]}</div>

      <h3>Findings</h3>
      {r.findings.length === 0 ? (
        <p className="muted">Nothing unusual detected.</p>
      ) : (
        <ul className="findings">
          {r.findings.map((f, i) => (<li key={i}><span className={`dot ${f.level}`} />{f.message}</li>))}
        </ul>
      )}

      <KV title="File" rows={fileRows} />
      {cap && cap.source !== "file" && <KV title="Capture context" rows={capRows} />}
      <KV title="Document properties" rows={propRows} />
      <KV title="Technical details" rows={techRows} />

      <HiddenSection h={r.hidden} onExtract={onExtract} />

      {gps && (
        <div className="kv-block">
          <h3>Location (GPS)</h3>
          <p className="muted">
            {gps.latitude}, {gps.longitude} -
            <a href={`https://www.openstreetmap.org/?mlat=${gps.latitude}&mlon=${gps.longitude}#map=15/${gps.latitude}/${gps.longitude}`} target="_blank" rel="noreferrer"> open map</a>
          </p>
        </div>
      )}

      {r.hashes && (
        <div className="kv-block">
          <h3>Hashes</h3>
          <dl className="kv">
            <dt>SHA-256</dt><dd><code>{r.hashes.sha256}</code></dd>
            <dt>SHA-1</dt><dd><code>{r.hashes.sha1}</code></dd>
            <dt>MD5</dt><dd><code>{r.hashes.md5}</code></dd>
          </dl>
        </div>
      )}
      <p className="muted small-note">{r.disclaimer}</p>
    </section>
  );
}
