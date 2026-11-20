// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Vouch - on-chain registry of document fingerprints
/// @notice Stores SHA-256 hashes with a block timestamp, an opaque uploader reference and an
///         optional link to the previous version. Only hashes are stored: documents never go on-chain.
contract Vouch {
    struct Record {
        address notarizedBy;
        string uploaderRef; // opaque user id, NOT an email or name
        uint64 timestamp;   // block timestamp
        bool exists;
        bytes32 previous;   // hash of the previous version (0 for a first version)
    }

    address public owner;
    uint256 public totalNotarized;
    mapping(bytes32 => Record) private records;

    event DocumentNotarized(
        bytes32 indexed docHash,
        string uploaderRef,
        uint64 timestamp,
        address indexed notarizedBy
    );
    event VersionLinked(bytes32 indexed docHash, bytes32 indexed previousHash);

    error NotOwner();
    error EmptyHash();
    error AlreadyNotarized(bytes32 docHash);
    error PreviousNotFound(bytes32 previousHash);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /// @notice Register a first version of a document. Called by the Vouch backend (relayer).
    function notarize(bytes32 docHash, string calldata uploaderRef) external onlyOwner {
        _store(docHash, bytes32(0), uploaderRef);
    }

    /// @notice Register a new version that points at an already-registered previous version.
    ///         Because the previous hash must exist first, history can only grow forwards:
    ///         versions cannot be reordered, cycled or silently replaced.
    function notarizeVersion(bytes32 docHash, bytes32 previousHash, string calldata uploaderRef) external onlyOwner {
        if (!records[previousHash].exists) revert PreviousNotFound(previousHash);
        _store(docHash, previousHash, uploaderRef);
    }

    function _store(bytes32 docHash, bytes32 previousHash, string calldata uploaderRef) internal {
        if (docHash == bytes32(0)) revert EmptyHash();
        if (records[docHash].exists) revert AlreadyNotarized(docHash);

        records[docHash] = Record(msg.sender, uploaderRef, uint64(block.timestamp), true, previousHash);
        totalNotarized += 1;
        emit DocumentNotarized(docHash, uploaderRef, uint64(block.timestamp), msg.sender);
        if (previousHash != bytes32(0)) emit VersionLinked(docHash, previousHash);
    }

    /// @notice Public, free read. Anyone can verify a hash without trusting Vouch.
    function verify(bytes32 docHash)
        external
        view
        returns (bool exists, string memory uploaderRef, uint64 timestamp, address notarizedBy)
    {
        Record storage r = records[docHash];
        return (r.exists, r.uploaderRef, r.timestamp, r.notarizedBy);
    }

    /// @notice Hash of the version this one replaced (0x0 if it is a first version or unknown).
    function previousOf(bytes32 docHash) external view returns (bytes32) {
        return records[docHash].previous;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }
}
