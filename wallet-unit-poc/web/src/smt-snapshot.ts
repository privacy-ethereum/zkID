// Binary-format layer for the moica-revocation-smt snapshot (PR #22).
//
// Layout (BigEndian):
//   Header (52 bytes):
//     [0:2]   magic       uint16  0x534D ("SM")
//     [2:4]   version     uint16  1
//     [4:8]   nodeCount   uint32
//     [8:40]  rootHash    [32]byte
//     [40:44] depth       uint32
//     [44:52] crlNumber   uint64
//
//   Per node (variable — 97 or 129 bytes):
//     [0:1]   type        uint8   0=branch, 1=leaf
//     [1:33]  hash        [32]byte
//     Branch: [33:65] left, [65:97] right        (97 bytes total)
//     Leaf:   [33:65] key, [65:97] value,
//             [97:129] entryMark                 (129 bytes total)
//
// Upstream source: privacy-ethereum/moica-revocation-smt server/internal/snapshot/binary.go

import { bytesToHex } from "./bytes";

export const SNAPSHOT_MAGIC = 0x534d;
export const SNAPSHOT_VERSION = 1;
export const SNAPSHOT_HEADER_BYTES = 52;
const BRANCH_NODE_BYTES = 97;
const LEAF_NODE_BYTES = 129;

export interface SnapshotHeader {
  magic: number;
  version: number;
  /** Total node count (branches + leaves). */
  nodeCount: number;
  /** Root as a lowercase hex string with NO `0x` prefix (matches the Go
   *  `bigToHex` output that `smtFinalize` + `smtCreateProof` consume). */
  rootHex: string;
  depth: number;
  crlNumber: bigint;
  /** Offset in the source buffer where the node body begins. */
  bodyOffset: number;
}

export interface NodeChunk {
  /** View into the source buffer spanning exactly `nodes` whole nodes. */
  slice: Uint8Array;
  nodes: number;
  leaves: number;
}

export function parseSnapshotHeader(bytes: Uint8Array): SnapshotHeader {
  if (bytes.byteLength < SNAPSHOT_HEADER_BYTES) {
    throw new Error(
      `snapshot too short for header: ${bytes.byteLength} < ${SNAPSHOT_HEADER_BYTES}`,
    );
  }
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const magic = dv.getUint16(0, false);
  if (magic !== SNAPSHOT_MAGIC) {
    throw new Error(
      `snapshot bad magic: 0x${magic.toString(16).padStart(4, "0")} (expected 0x534D)`,
    );
  }
  const version = dv.getUint16(2, false);
  if (version !== SNAPSHOT_VERSION) {
    throw new Error(
      `snapshot unsupported version ${version} (expected ${SNAPSHOT_VERSION})`,
    );
  }
  const nodeCount = dv.getUint32(4, false);
  const rootHex = bytesToStrippedHex(bytes.subarray(8, 40));
  const depth = dv.getUint32(40, false);
  const crlNumber = dv.getBigUint64(44, false);
  return {
    magic,
    version,
    nodeCount,
    rootHex,
    depth,
    crlNumber,
    bodyOffset: SNAPSHOT_HEADER_BYTES,
  };
}

/** Walk the node body and yield node-aligned chunks of at most `chunkNodes`
 *  complete nodes. Each yielded `slice` is a view into the source buffer — no
 *  copy. Throws on truncated/invalid node bytes so a corrupt snapshot fails
 *  closed instead of silently feeding the wasm engine a partial tree. */
export function* iterateNodeChunks(
  bytes: Uint8Array,
  header: SnapshotHeader,
  chunkNodes: number,
): Generator<NodeChunk> {
  if (chunkNodes < 1) throw new Error("chunkNodes must be >= 1");
  const total = header.nodeCount;
  let consumed = 0;
  let offset = header.bodyOffset;

  while (consumed < total) {
    const chunkStart = offset;
    let chunkNodesCount = 0;
    let chunkLeafCount = 0;
    const target = Math.min(chunkNodes, total - consumed);

    while (chunkNodesCount < target) {
      if (offset + 33 > bytes.byteLength) {
        throw new Error(
          `snapshot truncated: need type+hash at offset ${offset}, have ${bytes.byteLength}`,
        );
      }
      const type = bytes[offset];
      const nodeSize =
        type === 1 ? LEAF_NODE_BYTES : type === 0 ? BRANCH_NODE_BYTES : -1;
      if (nodeSize < 0) {
        throw new Error(
          `snapshot bad node type ${type} at offset ${offset} (node ${consumed + chunkNodesCount})`,
        );
      }
      if (offset + nodeSize > bytes.byteLength) {
        throw new Error(
          `snapshot truncated: need ${nodeSize} bytes for node at offset ${offset}, have ${bytes.byteLength - offset}`,
        );
      }
      offset += nodeSize;
      chunkNodesCount++;
      if (type === 1) chunkLeafCount++;
    }

    yield {
      slice: bytes.subarray(chunkStart, offset),
      nodes: chunkNodesCount,
      leaves: chunkLeafCount,
    };
    consumed += chunkNodesCount;
  }

  if (offset !== bytes.byteLength) {
    throw new Error(
      `snapshot has ${bytes.byteLength - offset} trailing bytes after ${total} nodes`,
    );
  }
}

function bytesToStrippedHex(bytes: Uint8Array): string {
  // Match Go's big.Int.Text(16): strip leading zeros; "0" for zero.
  const stripped = bytesToHex(bytes).replace(/^0+/, "");
  return stripped === "" ? "0" : stripped;
}
