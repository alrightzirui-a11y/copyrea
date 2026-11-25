import { describe, expect, it } from "vitest";
import { espNvsReportSchema } from "./espNvs.js";
import { computeNvsItemHeaderCrc, espIdfCrc32 } from "./espNvsItemDecoder.js";
import { parseEspNvsPartition } from "./espNvsParser.js";

const initActivePage = (seqNo: number, versionByte = 0xfe): Buffer => {
  const page = Buffer.alloc(4096, 0xff);
  page.writeUInt32LE(0xffff_fffe, 0); // ACTIVE
  page.writeUInt32LE(seqNo, 4);
  page[8] = versionByte;
  const hdrCrc = espIdfCrc32(page.subarray(4, 28));
  page.writeUInt32LE(hdrCrc, 28);
  return page;
};

const setBitmapWritten = (page: Buffer, slot: number, span = 1): void => {
  for (let i = 0; i < span; i += 1) {
    const idx = slot + i;
    const byteIdx = 32 + (idx >>> 2);
    const shift = (idx & 3) * 2;
    // Clear bit 0 so 0b11 -> 0b10 (WRITTEN)
    page[byteIdx] = page[byteIdx]! & ~(1 << shift);
  }
};

const writeKey = (slot32: Buffer, key: string): void => {
  slot32.fill(0, 8, 24);
  Buffer.from(key, "utf8").copy(slot32, 8, 0, 15);
};

const writeNamespaceSlot = (
  page: Buffer,
  slotIdx: number,
  name: string,
  nsId: number,
): void => {
  const off = 64 + slotIdx * 32;
  const s = page.subarray(off, off + 32);
  s.fill(0xff);
  s[0] = 0;
  s[1] = 0x01;
  s[2] = 1;
  s[3] = 0xff;
  writeKey(s, name);
  s[24] = nsId;
  s.writeUInt32LE(computeNvsItemHeaderCrc(s), 4);
  setBitmapWritten(page, slotIdx, 1);
};

const writeU32Slot = (options: {
  readonly page: Buffer;
  readonly slotIdx: number;
  readonly nsId: number;
  readonly key: string;
  readonly val: number;
}): void => {
  const { page, slotIdx, nsId, key, val } = options;
  const off = 64 + slotIdx * 32;
  const s = page.subarray(off, off + 32);
  s.fill(0xff);
  s[0] = nsId;
  s[1] = 0x04;
  s[2] = 1;
  s[3] = 0xff;
  writeKey(s, key);
  s.writeUInt32LE(val >>> 0, 24);
  s.writeUInt32LE(computeNvsItemHeaderCrc(s), 4);
  setBitmapWritten(page, slotIdx, 1);
};

const writeVarSlot = (options: {
  readonly page: Buffer;
  readonly slotIdx: number;
  readonly nsId: number;
  readonly typeCode: number;
  readonly chunkIndex: number;
  readonly key: string;
  readonly payload: Buffer;
}): number => {
  const { page, slotIdx, nsId, typeCode, chunkIndex, key, payload } = options;
  const dataSlots = Math.max(1, Math.ceil(payload.length / 32));
  const span = 1 + dataSlots;
  const off = 64 + slotIdx * 32;
  const s = page.subarray(off, off + 32);
  s.fill(0xff);
  s[0] = nsId;
  s[1] = typeCode;
  s[2] = span;
  s[3] = chunkIndex;
  writeKey(s, key);
  s.writeUInt16LE(payload.length, 24);
  s.writeUInt16LE(0xffff, 26);
  s.writeUInt32LE(espIdfCrc32(payload), 28);
  s.writeUInt32LE(computeNvsItemHeaderCrc(s), 4);
  payload.copy(page, off + 32);
  setBitmapWritten(page, slotIdx, span);
  return span;
};

describe("parseEspNvsPartition", () => {
  it("decodes namespaces, primitives, UTF-8 strings, and multi-chunk v2 blobs across pages", () => {
    const p0 = initActivePage(1, 0xfe);
    writeNamespaceSlot(p0, 0, "wifi", 1);
    writeU32Slot({ page: p0, slotIdx: 1, nsId: 1, key: "channel", val: 6 });
    const ssidPayload = Buffer.from("factory-ap\0", "utf8");
    const used = writeVarSlot({
      page: p0,
      slotIdx: 2,
      nsId: 1,
      typeCode: 0x21,
      chunkIndex: 0xff,
      key: "ssid",
      payload: ssidPayload,
    });
    const chunk0 = Buffer.from("0123456789abcdef", "utf8");
    writeVarSlot({
      page: p0,
      slotIdx: 2 + used,
      nsId: 1,
      typeCode: 0x42,
      chunkIndex: 0,
      key: "cert_der",
      payload: chunk0,
    });

    const p1 = initActivePage(2, 0xfe);
    const chunk1 = Buffer.from("fedcba9876543210", "utf8");
    const c1Span = writeVarSlot({
      page: p1,
      slotIdx: 0,
      nsId: 1,
      typeCode: 0x42,
      chunkIndex: 1,
      key: "cert_der",
      payload: chunk1,
    });
    // Write BLOB_IDX (0x48)
    const idxOff = 64 + c1Span * 32;
    const idxSlot = p1.subarray(idxOff, idxOff + 32);
    idxSlot.fill(0xff);
    idxSlot[0] = 1;
    idxSlot[1] = 0x48;
    idxSlot[2] = 1;
    idxSlot[3] = 0xff;
    writeKey(idxSlot, "cert_der");
    idxSlot.writeUInt32LE(chunk0.length + chunk1.length, 24);
    idxSlot[28] = 2; // chunkCount
    idxSlot[29] = 0; // chunkStart
    idxSlot.writeUInt32LE(computeNvsItemHeaderCrc(idxSlot), 4);
    setBitmapWritten(p1, c1Span, 1);

    const p2 = Buffer.alloc(4096, 0xff); // EMPTY page
    const image = Buffer.concat([p0, p1, p2]);

    const res = parseEspNvsPartition({
      artifact: {
        path: "/tmp/nvs.bin",
        sha256: "a".repeat(64),
        bytes: image.length,
      },
      partitionOffset: 0,
      maxEntries: 100,
      sliceBytes: image,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(espNvsReportSchema.safeParse(res.value).success).toBe(true);
    expect(res.value.coverage.status).toBe("complete");
    expect(res.value.namespaces).toEqual([
      { namespace_id: 1, name: "wifi", page_index: 0, entry_index: 0 },
    ]);
    expect(res.value.entries).toHaveLength(3);
    expect(res.value.entries[0]).toMatchObject({
      namespace: "wifi",
      key: "channel",
      data_type: "u32",
      value_integer: "6",
      crc_valid: true,
    });
    expect(res.value.entries[1]).toMatchObject({
      namespace: "wifi",
      key: "ssid",
      data_type: "sz",
      value_text: "factory-ap",
      crc_valid: true,
    });
    expect(res.value.entries[2]).toMatchObject({
      namespace: "wifi",
      key: "cert_der",
      data_type: "blob_v2",
      blob_size: 32,
      blob_preview_hex: Buffer.concat([chunk0, chunk1]).toString("hex"),
      completeness: "complete",
      crc_valid: true,
    });
  });

  it("flags encrypted or corrupt pages as corrupt_or_encrypted with partial coverage", () => {
    const encrypted = Buffer.alloc(4096);
    for (let i = 0; i < encrypted.length; i += 1) {
      encrypted[i] = (i * 73 + 19) & 0xff;
    }
    const res = parseEspNvsPartition({
      artifact: {
        path: "/tmp/enc_nvs.bin",
        sha256: "b".repeat(64),
        bytes: 4096,
      },
      partitionOffset: 0,
      maxEntries: 64,
      sliceBytes: encrypted,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.value.pages[0]?.state).toBe("corrupt_or_encrypted");
    expect(res.value.corrupt_or_encrypted_page_count).toBe(1);
    expect(res.value.coverage.status).toBe("partial");
  });
});
