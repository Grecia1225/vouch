const mongoose = require("mongoose");
const { mongoUri } = require("./config");

async function connectDB() {
  await mongoose.connect(mongoUri);
  console.log("MongoDB connected");
}
const getBucket = () =>
  new mongoose.mongo.GridFSBucket(mongoose.connection.db, { bucketName: "documents" });

module.exports = { connectDB, getBucket };
