const PDFDocument = require("pdfkit");
const QRCode = require("qrcode");

/** Builds the PDF proof certificate with a QR code pointing at the public verify page. */
async function buildCertificate({ doc, userName, verifyUrl, variant = "owner", level = "basic", network }) {
  const qr = await QRCode.toBuffer(verifyUrl, { width: 260, margin: 1 });
  return new Promise((resolve, reject) => {
    const pdf = new PDFDocument({ size: "A4", margin: 50 });
    const chunks = [];
    pdf.on("data", (c) => chunks.push(c));
    pdf.on("end", () => resolve(Buffer.concat(chunks)));
    pdf.on("error", reject);

    const navy = "#1F3A5F", teal = "#0E7C86", grey = "#55657A";
    const W = pdf.page.width, H = pdf.page.height;

    // Light background: a soft pale-blue to pale-mint wash, with a gentle band along the bottom
    const wash = pdf.linearGradient(0, 0, W, H);
    wash.stop(0, "#EAF4FA").stop(0.55, "#F2F8F6").stop(1, "#E6F3F1");
    pdf.rect(0, 0, W, H).fill(wash);
    pdf.rect(0, H - 110, W, 110).fill("#DCEFF0");

    // Diagonal "Vouch" watermark, drawn first so all text sits on top of it
    pdf.save();
    pdf.opacity(0.24);
    pdf.rotate(-35, { origin: [W / 2, H / 2] });
    pdf.font("Helvetica-Bold").fontSize(170).fillColor(navy);
    const markWidth = pdf.widthOfString("Vouch");
    pdf.text("Vouch", W / 2 - markWidth / 2, H / 2 - 64, { lineBreak: false });
    pdf.restore();

    pdf.rect(0, 0, W, 12).fill(teal);
    pdf.fillColor(navy).font("Helvetica-Bold").fontSize(28).text("Vouch", 50, 50);
    pdf.fillColor(grey).font("Helvetica").fontSize(11).text("Digital Notary - Proof of Registration", 50, 84);
    pdf.moveDown(2).fillColor(navy).font("Helvetica-Bold").fontSize(18).text("Certificate of Notarization");

    const row = (label, value, mono = false) => {
      pdf.moveDown(0.9).fillColor(grey).font("Helvetica-Bold").fontSize(9).text(label.toUpperCase());
      pdf.fillColor("#1B2A3A").font(mono ? "Courier" : "Helvetica").fontSize(mono ? 9.5 : 12).text(value, { width: 495 });
    };
    if (variant === "public") {
      // Third-party copy: only what a reader needs. No fingerprint, transaction, owner or location.
      row("Document", level === "basic" ? "Registered document (name withheld by the owner)" : doc.filename);
      row("Registered at (UTC)", new Date(doc.notarizedAt).toUTCString());
      row("Version", String(doc.version || 1));
      if (network) row("Network", network);
    } else {
      row("Document name", doc.filename);
      row("Registered by", userName);
      row("Registered at (UTC)", new Date(doc.notarizedAt).toUTCString());
      row("Transaction hash", doc.txHash, true);
      row("Block number", String(doc.blockNumber));
      if (doc.capture && doc.capture.source && doc.capture.source !== "file") {
        const src = { camera: "Live camera", voice: "Live voice recording", url: "Link", scan: "Scan" }[doc.capture.source] || doc.capture.source;
        row("Entered via", src + (doc.capture.capturedAt ? " at " + new Date(doc.capture.capturedAt).toUTCString() : ""));
      }
      if (doc.capture && doc.capture.location)
        row("Location (reported by browser, unverified)", `${doc.capture.location.latitude}, ${doc.capture.location.longitude}`);

    }
    const y = pdf.y + 25;
    pdf.image(qr, 50, y, { width: 130 });
    pdf.fillColor(navy).font("Helvetica-Bold").fontSize(12).text("Scan to verify", 200, y + 10);
    pdf.fillColor(grey).font("Helvetica").fontSize(10).text(verifyUrl, 200, y + 30, { width: 345 });
    pdf.text(variant === "public" ? "Open the link or scan the code, then add your copy of the file to check that it matches. The document itself is not stored in this certificate." : "Add the original file on the verify page to confirm it is unaltered.", 200, y + 62, { width: 345 });

    pdf.fillColor(grey).fontSize(8).text(
      "This certificate is tamper-evident proof that this exact file was registered on a blockchain at the stated time. " +
        "It does not by itself establish authorship, consent, truth of contents or statutory notarization.",
      50, 740, { width: 495 }
    );
    pdf.end();
  });
}
module.exports = { buildCertificate };
