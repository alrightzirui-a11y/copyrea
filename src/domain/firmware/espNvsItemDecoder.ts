import { crc32 } from "node:zlib";
import { sha256Hex } from "../../kernel/sha256Hex.js";
import {
  readInt32At,
  readInt64At,
  readUint16At,
  readUint32At,
  readUint64At,
} from "../binaryContainer.js";
import type { EspNvsDataType, EspNvsEntry } from "./espNvs.js";

const CRC_SEED = 0xffff_ffff;
const MAX_BLOB_PREVIEW_BYTES = 128;

/** Compute ESP-IDF `esp_rom_crc32_le(0xffffffff, buf, len)`. */
export const espIdfCrc32 = (bytes: Uint8Array): number =>
  crc32(bytes, CRC_SEED) >>> 0;

/** Compute ESP-IDF NVS 32-byte item header CRC over `[0..4) || [8..32)`. */
export const computeNvsItemHeaderCrc = (slot32: Uint8Array): number => {
  const packed = Buffer.allocUnsafe(28);
  packed.set(slot32.subarray(0, 4), 0);
  packed.set(slot32.subarray(8, 32), 4);
  return espIdfCrc32(packed);
};

export const decodeCString16 = (bytes16: Uint8Array): string => {
  const nul = bytes16.indexOf(0);
  const slice = nul === -1 ? bytes16 : bytes16.subarray(0, nul);
  return Buffer.from(slice).toString("utf8");
};

export interface RawBlobChunk {
  readonly pageIndex: number;
  readonly pageSeqNo: number;
  readonly entryIndex: number;
  readonly fileOffset: number;
  readonly nsIndex: number;
  readonly key: string;
  readonly chunkIndex: number;
  readonly span: number;
  readonly payload: Buffer;
  readonly crcValid: boolean;
}

export interface RawBlobIndex {
  readonly pageIndex: number;
  readonly pageSeqNo: number;
  readonly entryIndex: number;
  readonly fileOffset: number;
  readonly nsIndex: number;
  readonly key: string;
  readonly totalSize: number;
  readonly chunkCount: number;
  readonly chunkStart: number;
  readonly headerCrcValid: boolean;
}

const decodePrimitiveValue = (
  typeCode: number,
  data8: Uint8Array,
): {
  readonly dataType: EspNvsDataType;
  readonly integerText: string;
} | null => {
  switch (typeCode) {
    case 0x01:
      return { dataType: "u8", integerText: String(data8[0]!) };
    case 0x11: {
      const v = data8[0]!;
      return { dataType: "i8", integerText: String(v > 127 ? v - 256 : v) };
    }
    case 0x02:
      return {
        dataType: "u16",
        integerText: String(readUint16At(data8, 0, true)),
      };
    case 0x12: {
      const u = readUint16At(data8, 0, true);
      return {
        dataType: "i16",
        integerText: String(u > 32767 ? u - 65536 : u),
      };
    }
    case 0x04:
      return {
        dataType: "u32",
        integerText: String(readUint32At(data8, 0, true)),
      };
    case 0x14:
      return {
        dataType: "i32",
        integerText: String(readInt32At(data8, 0, true)),
      };
    case 0x08:
      return {
        dataType: "u64",
        integerText: readUint64At(data8, 0, true).toString(10),
      };
    case 0x18:
      return {
        dataType: "i64",
        integerText: readInt64At(data8, 0, true).toString(10),
      };
    default:
      return null;
  }
};

export interface DecodedSingleSlotResult {
  readonly consumedSlots: number;
  readonly namespaceDef?: {
    readonly id: number;
    readonly name: string;
    readonly pageIndex: number;
    readonly entryIndex: number;
  };
  readonly immediateEntry?: Omit<EspNvsEntry, "namespace">;
  readonly blobChunk?: RawBlobChunk;
  readonly blobIndex?: RawBlobIndex;
  readonly crcMismatch?: boolean;
}

const buildImmediateVariableEntry = (options: {
  readonly pageIndex: number;
  readonly pageFileOffset: number;
  readonly entryIndex: number;
  readonly nsIndex: number;
  readonly typeCode: number;
  readonly span: number;
  readonly key: string;
  readonly payload: Buffer;
  readonly crcValid: boolean;
}): DecodedSingleSlotResult => {
  const {
    pageIndex,
    pageFileOffset,
    entryIndex,
    nsIndex,
    typeCode,
    span,
    key,
    payload,
    crcValid,
  } = options;
  if (typeCode === 0x21) {
    const nulIdx = payload.indexOf(0);
    const strBytes = nulIdx === -1 ? payload : payload.subarray(0, nulIdx);
    return {
      consumedSlots: span,
      immediateEntry: {
        page_index: pageIndex,
        entry_index: entryIndex,
        file_offset: pageFileOffset + 64 + entryIndex * 32,
        namespace_id: nsIndex,
        key,
        data_type: "sz",
        raw_type_code: typeCode,
        span,
        value_text: strBytes.toString("utf8"),
        value_integer: null,
        blob_size: null,
        blob_preview_hex: null,
        blob_sha256: null,
        crc_valid: crcValid,
        completeness: crcValid ? "complete" : "crc_mismatch",
      },
      ...(crcValid ? {} : { crcMismatch: true }),
    };
  }
  const preview = payload.subarray(0, MAX_BLOB_PREVIEW_BYTES).toString("hex");
  return {
    consumedSlots: span,
    immediateEntry: {
      page_index: pageIndex,
      entry_index: entryIndex,
      file_offset: pageFileOffset + 64 + entryIndex * 32,
      namespace_id: nsIndex,
      key,
      data_type: "blob_v1",
      raw_type_code: typeCode,
      span,
      value_text: null,
      value_integer: null,
      blob_size: payload.length,
      blob_preview_hex: preview,
      blob_sha256: sha256Hex(payload),
      crc_valid: crcValid,
      completeness: crcValid ? "complete" : "crc_mismatch",
    },
    ...(crcValid ? {} : { crcMismatch: true }),
  };
};

const decodeVariableSpanItem = (options: {
  readonly pageBytes: Buffer;
  readonly pageIndex: number;
  readonly pageSeqNo: number;
  readonly pageFileOffset: number;
  readonly entryIndex: number;
  readonly nsIndex: number;
  readonly typeCode: number;
  readonly span: number;
  readonly chunkIndex: number;
  readonly key: string;
  readonly data8: Uint8Array;
  readonly headerCrcValid: boolean;
}): DecodedSingleSlotResult => {
  const {
    pageBytes,
    pageIndex,
    pageSeqNo,
    pageFileOffset,
    entryIndex,
    nsIndex,
    typeCode,
    span,
    chunkIndex,
    key,
    data8,
    headerCrcValid,
  } = options;
  const declaredLen = readUint16At(data8, 0, true);
  const declaredDataCrc = readUint32At(data8, 4, true);
  const maxSpanBytes = (span - 1) * 32;
  const payloadStart = 64 + (entryIndex + 1) * 32;
  const availableBytes = Math.max(
    0,
    Math.min(maxSpanBytes, 4096 - payloadStart),
  );
  const sliceLen = Math.min(declaredLen, availableBytes);
  const payload = Buffer.from(
    pageBytes.subarray(payloadStart, payloadStart + sliceLen),
  );
  const dataCrcValid =
    sliceLen === declaredLen && espIdfCrc32(payload) === declaredDataCrc;
  const crcValid = headerCrcValid && dataCrcValid;

  if (typeCode === 0x42) {
    return {
      consumedSlots: span,
      blobChunk: {
        pageIndex,
        pageSeqNo,
        entryIndex,
        fileOffset: pageFileOffset + 64 + entryIndex * 32,
        nsIndex,
        key,
        chunkIndex,
        span,
        payload,
        crcValid,
      },
      ...(crcValid ? {} : { crcMismatch: true }),
    };
  }
  return buildImmediateVariableEntry({
    pageIndex,
    pageFileOffset,
    entryIndex,
    nsIndex,
    typeCode,
    span,
    key,
    payload,
    crcValid,
  });
};

/** Decode one written NVS entry starting at `entryIndex` (0..125). */
export const decodeWrittenNvsSlot = (options: {
  readonly pageBytes: Buffer;
  readonly pageIndex: number;
  readonly pageSeqNo: number;
  readonly pageFileOffset: number;
  readonly entryIndex: number;
}): DecodedSingleSlotResult => {
  const { pageBytes, pageIndex, pageSeqNo, pageFileOffset, entryIndex } =
    options;
  const slotOffset = 64 + entryIndex * 32;
  const slot = pageBytes.subarray(slotOffset, slotOffset + 32);
  const nsIndex = slot[0]!;
  const typeCode = slot[1]!;
  const rawSpan = slot[2]!;
  const span = Math.max(1, Math.min(126 - entryIndex, rawSpan));
  const chunkIndex = slot[3]!;
  const declaredHeaderCrc = readUint32At(slot, 4, true);
  const headerCrcValid = computeNvsItemHeaderCrc(slot) === declaredHeaderCrc;
  const key = decodeCString16(slot.subarray(8, 24));
  const data8 = slot.subarray(24, 32);

  if (nsIndex === 0 && typeCode === 0x01) {
    const nsId = data8[0]!;
    if (headerCrcValid && nsId >= 1 && nsId <= 254) {
      return {
        consumedSlots: 1,
        namespaceDef: { id: nsId, name: key, pageIndex, entryIndex },
      };
    }
    return { consumedSlots: 1, crcMismatch: !headerCrcValid };
  }

  if (nsIndex === 0) {
    return {
      consumedSlots: span,
      ...(headerCrcValid ? {} : { crcMismatch: true }),
    };
  }

  if (typeCode === 0x48) {
    return {
      consumedSlots: 1,
      blobIndex: {
        pageIndex,
        pageSeqNo,
        entryIndex,
        fileOffset: pageFileOffset + slotOffset,
        nsIndex,
        key,
        totalSize: readUint32At(data8, 0, true),
        chunkCount: data8[4]!,
        chunkStart: data8[5]!,
        headerCrcValid,
      },
      ...(headerCrcValid ? {} : { crcMismatch: true }),
    };
  }

  if (typeCode === 0x21 || typeCode === 0x41 || typeCode === 0x42) {
    return decodeVariableSpanItem({
      pageBytes,
      pageIndex,
      pageSeqNo,
      pageFileOffset,
      entryIndex,
      nsIndex,
      typeCode,
      span,
      chunkIndex,
      key,
      data8,
      headerCrcValid,
    });
  }

  const prim = decodePrimitiveValue(typeCode, data8);
  return {
    consumedSlots: 1,
    immediateEntry: {
      page_index: pageIndex,
      entry_index: entryIndex,
      file_offset: pageFileOffset + slotOffset,
      namespace_id: nsIndex,
      key,
      data_type: prim?.dataType ?? "unknown",
      raw_type_code: typeCode,
      span: 1,
      value_text: null,
      value_integer: prim?.integerText ?? null,
      blob_size: null,
      blob_preview_hex: null,
      blob_sha256: null,
      crc_valid: headerCrcValid,
      completeness: headerCrcValid ? "complete" : "crc_mismatch",
    },
    ...(headerCrcValid ? {} : { crcMismatch: true }),
  };
};

/** Reassemble v2 multi-chunk `BLOB_IDX` + `BLOB_DATA` items and surface orphan chunks. */
export const reassembleNvsV2Blobs = (
  indices: readonly RawBlobIndex[],
  chunks: readonly RawBlobChunk[],
): Omit<EspNvsEntry, "namespace">[] => {
  const usedChunkRefs = new Set<RawBlobChunk>();
  const out: Omit<EspNvsEntry, "namespace">[] = [];

  for (const idx of indices) {
    const endChunk = idx.chunkStart + idx.chunkCount;
    const matching: RawBlobChunk[] = [];
    let allPresent = idx.chunkCount > 0;
    let allCrcValid = idx.headerCrcValid;

    for (let c = idx.chunkStart; c < endChunk; c += 1) {
      const candidates = chunks
        .filter(
          (ch) =>
            ch.nsIndex === idx.nsIndex &&
            ch.key === idx.key &&
            ch.chunkIndex === c,
        )
        .sort((a, b) => b.pageSeqNo - a.pageSeqNo);
      const picked = candidates[0];
      if (picked === undefined) {
        allPresent = false;
      } else {
        usedChunkRefs.add(picked);
        matching.push(picked);
        if (!picked.crcValid) allCrcValid = false;
      }
    }

    const joined = Buffer.concat(matching.map((m) => m.payload));
    const complete = allPresent && joined.length === idx.totalSize;
    out.push({
      page_index: idx.pageIndex,
      entry_index: idx.entryIndex,
      file_offset: idx.fileOffset,
      namespace_id: idx.nsIndex,
      key: idx.key,
      data_type: "blob_v2",
      raw_type_code: 0x48,
      span: 1,
      value_text: null,
      value_integer: null,
      blob_size: joined.length,
      blob_preview_hex: joined.subarray(0, 128).toString("hex"),
      blob_sha256: sha256Hex(joined),
      crc_valid: allCrcValid,
      completeness: !allCrcValid
        ? "crc_mismatch"
        : complete
          ? "complete"
          : "missing_chunks",
    });
  }

  for (const ch of chunks) {
    if (usedChunkRefs.has(ch)) continue;
    out.push({
      page_index: ch.pageIndex,
      entry_index: ch.entryIndex,
      file_offset: ch.fileOffset,
      namespace_id: ch.nsIndex,
      key: ch.key,
      data_type: "blob_data_orphan",
      raw_type_code: 0x42,
      span: ch.span,
      value_text: null,
      value_integer: null,
      blob_size: ch.payload.length,
      blob_preview_hex: ch.payload.subarray(0, 128).toString("hex"),
      blob_sha256: sha256Hex(ch.payload),
      crc_valid: ch.crcValid,
      completeness: ch.crcValid ? "missing_chunks" : "crc_mismatch",
    });
  }
  return out;
};
