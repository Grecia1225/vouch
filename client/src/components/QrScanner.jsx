import { useEffect, useRef, useState } from "react";

// BarcodeDetector where the browser has it, jsQR (pure JS) everywhere else
function makeDetector() {
  try { return "BarcodeDetector" in window ? new window.BarcodeDetector({ formats: ["qr_code"] }) : null; } catch { return null; }
}
async function decodeCanvas(canvas, detector) {
  if (detector) {
    const codes = await detector.detect(canvas);
    return codes[0] ? codes[0].rawValue : null;
  }
  const { default: jsQR } = await import("jsqr");
  const img = canvas.getContext("2d", { willReadFrequently: true }).getImageData(0, 0, canvas.width, canvas.height);
  const res = jsQR(img.data, img.width, img.height);
  return res ? res.data : null;
}

export default function QrScanner({ onResult }) {
  const videoRef = useRef(null);
  const streamRef = useRef(null);
  const rafRef = useRef(0);
  const [on, setOn] = useState(false);
  const [err, setErr] = useState("");

  const stop = () => {
    cancelAnimationFrame(rafRef.current);
    if (streamRef.current) streamRef.current.getTracks().forEach((t) => t.stop());
    streamRef.current = null;
    setOn(false);
  };
  useEffect(() => stop, []);

  const start = async () => {
    setErr("");
    if (!navigator.mediaDevices) { setErr("The camera needs HTTPS or localhost. Upload a photo of the QR code instead."); return; }
    try {
      streamRef.current = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: "environment" } } });
      setOn(true);
    } catch (e) { setErr("Camera unavailable: " + e.message); }
  };

  useEffect(() => {
    if (!on) return undefined;
    const v = videoRef.current;
    v.srcObject = streamRef.current;
    v.play().catch(() => {});
    const detector = makeDetector();
    const canvas = document.createElement("canvas");
    let busy = false, last = 0;
    const loop = async (t) => {
      rafRef.current = requestAnimationFrame(loop);
      if (busy || t - last < 200 || !v.videoWidth) return;
      busy = true; last = t;
      canvas.width = v.videoWidth; canvas.height = v.videoHeight;
      canvas.getContext("2d", { willReadFrequently: true }).drawImage(v, 0, 0);
      try {
        const text = await decodeCanvas(canvas, detector);
        if (text) { stop(); onResult(text); }
      } catch { /* keep scanning */ }
      busy = false;
    };
    rafRef.current = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(rafRef.current);
  }, [on]);

  const fromImage = async (file) => {
    setErr("");
    try {
      const bmp = await createImageBitmap(file);
      const canvas = document.createElement("canvas");
      canvas.width = bmp.width; canvas.height = bmp.height;
      canvas.getContext("2d", { willReadFrequently: true }).drawImage(bmp, 0, 0);
      const text = await decodeCanvas(canvas, makeDetector());
      if (text) onResult(text); else setErr("No QR code found in that image");
    } catch { setErr("Could not read that image"); }
  };

  return (
    <div className="capture">
      {on ? (
        <>
          <video ref={videoRef} playsInline muted className="video" />
          <p className="muted">Point the camera at the QR code on a Vouch certificate...</p>
          <button className="btn outline" onClick={stop}>Cancel</button>
        </>
      ) : (
        <div className="row">
          <button className="btn" onClick={start}>Scan certificate QR</button>
          <label className="btn outline">
            Upload QR image
            <input type="file" accept="image/*" hidden onChange={(e) => { if (e.target.files[0]) fromImage(e.target.files[0]); e.target.value = ""; }} />
          </label>
        </div>
      )}
      {err && <p className="error">{err}</p>}
    </div>
  );
}
