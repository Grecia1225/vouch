import { useEffect, useRef, useState } from "react";
import { MAX_ITEMS, fmtSize, getLocation, newId } from "../inputs.js";

const TABS = [["files", "Files"], ["camera", "Camera"], ["voice", "Voice"], ["link", "Link"]];
const BADGE = { file: "FILE", camera: "CAMERA", voice: "VOICE", url: "LINK", scan: "SCAN" };

export default function InputPicker({ items, setItems, tabs }) {
  const visibleTabs = tabs ? TABS.filter(([k]) => tabs.includes(k)) : TABS;
  const [tab, setTab] = useState("files");
  const [withLocation, setWithLocation] = useState(false);
  const [notice, setNotice] = useState("");
  const [url, setUrl] = useState("");
  const [dragging, setDragging] = useState(false);

  const add = (newItems) => setItems((prev) => [...prev, ...newItems].slice(0, MAX_ITEMS));
  const remove = (id) => setItems((prev) => prev.filter((i) => i.id !== id));

  const addFiles = (list) => {
    setNotice("");
    add(Array.from(list).map((file) => ({ id: newId(), kind: "file", file, context: { source: "file" } })));
  };

  // Context stamped on live captures: time, and (only if the user opted in) browser-reported location
  const captureContext = async (source, extra = {}) => {
    const ctx = { source, capturedAt: new Date().toISOString(), ...extra };
    if (withLocation) {
      try { ctx.location = await getLocation(); setNotice(""); } catch (e) { setNotice(e.message + ". Saved without location."); }
    }
    return ctx;
  };
  const addCapture = async (file, source, extra) => {
    const context = await captureContext(source, extra);
    add([{ id: newId(), kind: "file", file, context }]);
  };

  const addUrl = () => {
    const u = url.trim();
    if (!/^https?:\/\//i.test(u)) { setNotice("Enter a link starting with http:// or https://"); return; }
    setNotice("");
    add([{ id: newId(), kind: "url", url: u, context: { source: "url", sourceUrl: u } }]);
    setUrl("");
  };

  return (
    <div className="picker">
      <div className="tabs">
        {visibleTabs.map(([k, label]) => (
          <button key={k} className={tab === k ? "tab on" : "tab"} onClick={() => setTab(k)}>{label}</button>
        ))}
      </div>

      {tab === "files" && (
        <label
          className={dragging ? "drop over" : "drop"}
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => { e.preventDefault(); setDragging(false); addFiles(e.dataTransfer.files); }}
        >
          <input type="file" multiple hidden onChange={(e) => { addFiles(e.target.files); e.target.value = ""; }} />
          <strong>Drag and drop files here</strong>
          <span>or click to browse (up to {MAX_ITEMS} at once)</span>
        </label>
      )}

      {tab === "camera" && <CameraCapture onCapture={(file) => addCapture(file, "camera")} />}
      {tab === "voice" && <VoiceRecorder onRecorded={(file, secs) => addCapture(file, "voice", { durationSec: secs })} />}

      {tab === "link" && (
        <div className="row">
          <input className="grow" placeholder="https://example.com/contract.pdf" value={url}
            onChange={(e) => setUrl(e.target.value)} onKeyDown={(e) => e.key === "Enter" && addUrl()} />
          <button className="btn" onClick={addUrl}>Add link</button>
        </div>
      )}

      {(tab === "camera" || tab === "voice") && (
        <label className="check">
          <input type="checkbox" checked={withLocation} onChange={(e) => setWithLocation(e.target.checked)} />
          Attach my location to captures (reported by your browser, stored with the record, not on the blockchain)
        </label>
      )}
      {notice && <p className="error">{notice}</p>}

      {items.length > 0 && (
        <ul className="items">
          {items.map((i) => (
            <li key={i.id}>
              <span className={`badge ${i.context.source}`}>{BADGE[i.context.source] || "FILE"}</span>
              <span className="grow name">{i.kind === "url" ? i.url : i.file.name}</span>
              {i.kind === "file" && <span className="muted">{fmtSize(i.file.size)}</span>}
              {i.context.durationSec !== undefined && <span className="muted">{i.context.durationSec}s</span>}
              {i.context.location && <span className="chip">location</span>}
              <button className="link-btn" onClick={() => remove(i.id)} aria-label="Remove">Remove</button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function CameraCapture({ onCapture }) {
  const videoRef = useRef(null);
  const streamRef = useRef(null);
  const [on, setOn] = useState(false);
  const [err, setErr] = useState("");

  const stop = () => {
    if (streamRef.current) streamRef.current.getTracks().forEach((t) => t.stop());
    streamRef.current = null;
    setOn(false);
  };
  useEffect(() => stop, []);
  useEffect(() => { if (on && videoRef.current) { videoRef.current.srcObject = streamRef.current; } }, [on]);

  const start = async () => {
    setErr("");
    if (!navigator.mediaDevices) { setErr("The live camera needs HTTPS or localhost. Use the phone camera button instead."); return; }
    try {
      streamRef.current = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: "environment" } }, audio: false });
      setOn(true);
    } catch (e) { setErr("Camera unavailable: " + e.message); }
  };
  const snap = () => {
    const v = videoRef.current;
    if (!v || !v.videoWidth) return;
    const c = document.createElement("canvas");
    c.width = v.videoWidth; c.height = v.videoHeight;
    c.getContext("2d").drawImage(v, 0, 0);
    c.toBlob((b) => onCapture(new File([b], `photo-${Date.now()}.jpg`, { type: "image/jpeg" })), "image/jpeg", 0.92);
  };

  return (
    <div className="capture">
      {on ? (
        <>
          <video ref={videoRef} autoPlay playsInline muted className="video" />
          <div className="row">
            <button className="btn" onClick={snap}>Capture photo</button>
            <button className="btn outline" onClick={stop}>Stop camera</button>
          </div>
        </>
      ) : (
        <div className="row">
          <button className="btn" onClick={start}>Start live camera</button>
          <label className="btn outline">
            Use phone camera app
            <input type="file" accept="image/*" capture="environment" hidden onChange={(e) => { Array.from(e.target.files).forEach((f) => onCapture(f)); e.target.value = ""; }} />
          </label>
        </div>
      )}
      {err && <p className="error">{err}</p>}
    </div>
  );
}

function VoiceRecorder({ onRecorded }) {
  const [rec, setRec] = useState(false);
  const [secs, setSecs] = useState(0);
  const [level, setLevel] = useState(0);
  const [err, setErr] = useState("");
  const r = useRef({});

  const start = async () => {
    setErr("");
    if (!navigator.mediaDevices || !window.MediaRecorder) { setErr("Voice recording needs a modern browser on HTTPS or localhost."); return; }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const mime = ["audio/webm;codecs=opus", "audio/webm", "audio/mp4", "audio/ogg"].find((t) => MediaRecorder.isTypeSupported(t)) || "";
      const mr = new MediaRecorder(stream, mime ? { mimeType: mime } : undefined);
      const chunks = [];
      const started = Date.now();
      mr.ondataavailable = (e) => e.data.size && chunks.push(e.data);
      mr.onstop = () => {
        stream.getTracks().forEach((t) => t.stop());
        cancelAnimationFrame(r.current.raf);
        clearInterval(r.current.timer);
        if (r.current.ctx) r.current.ctx.close();
        const type = mr.mimeType || mime || "audio/webm";
        const ext = type.includes("mp4") ? "m4a" : type.includes("ogg") ? "ogg" : "webm";
        onRecorded(new File([new Blob(chunks, { type })], `voice-${Date.now()}.${ext}`, { type }), Math.round((Date.now() - started) / 1000));
        setRec(false); setSecs(0); setLevel(0);
      };
      const AC = window.AudioContext || window.webkitAudioContext;
      if (AC) { // live level meter
        const ctx = new AC();
        const an = ctx.createAnalyser();
        an.fftSize = 256;
        ctx.createMediaStreamSource(stream).connect(an);
        const data = new Uint8Array(an.frequencyBinCount);
        const tick = () => {
          an.getByteTimeDomainData(data);
          let peak = 0;
          for (const v of data) peak = Math.max(peak, Math.abs(v - 128));
          setLevel(Math.min(100, peak * 1.6));
          r.current.raf = requestAnimationFrame(tick);
        };
        tick();
        r.current.ctx = ctx;
      }
      r.current.timer = setInterval(() => setSecs((s) => s + 1), 1000);
      r.current.mr = mr;
      mr.start();
      setRec(true);
    } catch (e) { setErr("Microphone unavailable: " + e.message); }
  };
  const stop = () => r.current.mr && r.current.mr.state !== "inactive" && r.current.mr.stop();
  useEffect(() => () => { if (r.current.mr && r.current.mr.state === "recording") r.current.mr.stop(); }, []);

  const mmss = `${String(Math.floor(secs / 60)).padStart(2, "0")}:${String(secs % 60).padStart(2, "0")}`;
  return (
    <div className="capture">
      <div className="row">
        {rec ? <button className="btn danger" onClick={stop}>Stop and save</button> : <button className="btn" onClick={start}>Start recording</button>}
        {rec && <><span className="rec-dot" /><strong>{mmss}</strong></>}
      </div>
      {rec && <div className="meter"><div style={{ width: `${level}%` }} /></div>}
      {err && <p className="error">{err}</p>}
    </div>
  );
}
