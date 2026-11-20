const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("Vouch", () => {
  let vouch, owner, other;
  const hash = ethers.keccak256(ethers.toUtf8Bytes("sample document"));

  beforeEach(async () => {
    [owner, other] = await ethers.getSigners();
    const F = await ethers.getContractFactory("Vouch");
    vouch = await F.deploy();
    await vouch.waitForDeployment();
  });

  it("records a hash with timestamp and uploader ref", async () => {
    await vouch.notarize(hash, "user-1");
    const r = await vouch.verify(hash);
    expect(r.exists).to.equal(true);
    expect(r.uploaderRef).to.equal("user-1");
    expect(r.timestamp).to.be.gt(0);
    expect(await vouch.totalNotarized()).to.equal(1);
  });

  it("reports unknown hashes as not existing", async () => {
    const r = await vouch.verify(hash);
    expect(r.exists).to.equal(false);
  });

  it("rejects duplicate hashes", async () => {
    await vouch.notarize(hash, "a");
    await expect(vouch.notarize(hash, "b")).to.be.revertedWithCustomError(vouch, "AlreadyNotarized");
  });

  it("only the owner can notarize", async () => {
    await expect(vouch.connect(other).notarize(hash, "x")).to.be.revertedWithCustomError(vouch, "NotOwner");
  });

  describe("versions", () => {
    const h2 = ethers.keccak256(ethers.toUtf8Bytes("sample document v2"));
    const h3 = ethers.keccak256(ethers.toUtf8Bytes("sample document v3"));

    it("links a new version to an existing one", async () => {
      await vouch.notarize(hash, "u1");
      await vouch.notarizeVersion(h2, hash, "u1");
      expect(await vouch.previousOf(h2)).to.equal(hash);
      expect(await vouch.previousOf(hash)).to.equal(ethers.ZeroHash);
      expect(await vouch.totalNotarized()).to.equal(2);
    });

    it("builds a chain across several versions", async () => {
      await vouch.notarize(hash, "u1");
      await vouch.notarizeVersion(h2, hash, "u1");
      await vouch.notarizeVersion(h3, h2, "u1");
      expect(await vouch.previousOf(h3)).to.equal(h2);
    });

    it("rejects a version whose previous hash was never registered", async () => {
      await expect(vouch.notarizeVersion(h2, hash, "u1")).to.be.revertedWithCustomError(vouch, "PreviousNotFound");
    });

    it("cannot re-register an existing hash as a new version", async () => {
      await vouch.notarize(hash, "u1");
      await vouch.notarizeVersion(h2, hash, "u1");
      await expect(vouch.notarizeVersion(hash, h2, "u1")).to.be.revertedWithCustomError(vouch, "AlreadyNotarized");
    });

    it("only the owner can add versions", async () => {
      await vouch.notarize(hash, "u1");
      await expect(vouch.connect(other).notarizeVersion(h2, hash, "x")).to.be.revertedWithCustomError(vouch, "NotOwner");
    });
  });
});
