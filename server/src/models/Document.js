const mongoose = require("mongoose");
const docSchema = new mongoose.Schema(
  {
    owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    filename: { type: String, required: true },
    mimeType: String,
    size: Number,
    hash: { type: String, required: true, unique: true }, // SHA-256 hex (lowercase)
    fileId: { type: mongoose.Schema.Types.ObjectId, required: true }, // GridFS id
    txHash: String,
    blockNumber: Number,
    notarizedAt: Date, // block timestamp
    share: { // capability link for third-party viewers (see services/privacy.js)
      token: { type: String, index: { unique: true, sparse: true } },
      level: { type: String, enum: ["basic", "name", "technical"], default: "basic" },
      expiresAt: Date,
      revoked: { type: Boolean, default: false },
    },
    version: { type: Number, default: 1 },
    previousHash: String, // SHA-256 of the version this one replaced
    capture: { type: mongoose.Schema.Types.Mixed }, // how the data was entered: source, time, self-reported location
    metadata: { type: mongoose.Schema.Types.Mixed }, // metadata snapshot at registration (GPS coordinates removed)
  },
  { timestamps: true }
);
module.exports = mongoose.model("Document", docSchema);
