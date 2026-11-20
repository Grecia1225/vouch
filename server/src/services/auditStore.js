const mongoose = require("mongoose");

const schema = new mongoose.Schema(
  {
    seq: { type: Number, required: true, unique: true },
    at: { type: String, required: true },
    actor: { type: String, default: null },
    action: { type: String, required: true },
    detail: { type: mongoose.Schema.Types.Mixed, default: {} },
    prevHash: { type: String, required: true },
    hash: { type: String, required: true },
  },
  { versionKey: false, minimize: false }
);
const AuditEvent = mongoose.models.AuditEvent || mongoose.model("AuditEvent", schema);

module.exports = {
  last: () => AuditEvent.findOne().sort({ seq: -1 }).lean(),
  append: (ev) => AuditEvent.create(ev),
  async *all() { for await (const d of AuditEvent.find().sort({ seq: 1 }).lean().cursor()) yield d; },
};
