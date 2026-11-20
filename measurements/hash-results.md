# Hash measurements (no blockchain needed)

Generated 2026-10-15T10:51:51.398Z on Intel(R) Xeon(R) Processor @ 2.10GHz (1 cores), Node v22.22.2. Numbers depend on the machine: re-run `node server/scripts/measure-hash.js` on yours and quote your own.

## SHA-256 speed
| File size | Time per hash | Throughput |
|---|---|---|
| 1 KB | 0.005 ms | 190.7 MB/s |
| 100 KB | 0.089 ms | 1098.3 MB/s |
| 1 MB | 0.758 ms | 1318.5 MB/s |
| 10 MB | 7.62 ms | 1312.4 MB/s |

The server's 10 MB upload limit means hashing is never the bottleneck: the blockchain write dominates.

## Avalanche effect (2000 random 4 KB files, 1 random bit flipped)
Bits of the 256-bit hash that changed: mean **127.98** (ideal 128), min 101, max 153, standard deviation 8.05.

## Tamper detection (2000 random files per attack)
| Modification | Trials | Detected | Detection rate |
|---|---|---|---|
| flip 1 bit | 2000 | 2000 | 100% |
| change 1 byte | 2000 | 2000 | 100% |
| delete 1 byte | 2000 | 2000 | 100% |
| append 1 byte | 2000 | 2000 | 100% |
| swap 2 bytes | 1992 | 1992 | 100% |

A modified file hashes differently, so the registered fingerprint no longer matches and verification reports it. (Hash collisions are computationally infeasible for SHA-256; this test shows the property holds in practice, it is not a proof.)
