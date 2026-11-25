import { readUint16At, readUint32At } from "../binaryContainer.js";
import { formatHexCompact } from "./firmwareLiteralPoolRegions.js";

export interface RawPoolLoadCandidate {
  readonly insnOffset: number;
  readonly insnSize: number;
  readonly insnAddress: number;
  readonly mnemonic: "ldr" | "ldr.w" | "l32r";
  readonly targetRegister: string;
  readonly disassembly: string;
  readonly poolOffset: number;
  readonly poolAddress: number;
  readonly loadedValue: number;
}

export interface RawIsaScanResult {
  readonly candidates: readonly RawPoolLoadCandidate[];
  readonly outOfImageTargets: number;
}

const ARM_REGISTERS = [
  "r0",
  "r1",
  "r2",
  "r3",
  "r4",
  "r5",
  "r6",
  "r7",
  "r8",
  "r9",
  "r10",
  "r11",
  "r12",
  "sp",
  "lr",
  "pc",
] as const;

const A32_COND_SUFFIX = [
  "eq",
  "ne",
  "cs",
  "cc",
  "mi",
  "pl",
  "vs",
  "vc",
  "hi",
  "ls",
  "ge",
  "lt",
  "gt",
  "le",
  "",
] as const;

const resolvePoolSlot = (
  fileBytes: Uint8Array,
  baseAddress: number,
  poolAddrBig: bigint,
): { readonly poolOffset: number; readonly loadedValue: number } | null => {
  if ((poolAddrBig & 3n) !== 0n) return null;
  const relBig = poolAddrBig - BigInt(baseAddress >>> 0);
  if (relBig < 0n || relBig + 4n > BigInt(fileBytes.length)) return null;
  const poolOffset = Number(relBig);
  const loadedValue = readUint32At(fileBytes, poolOffset, true);
  if (loadedValue === undefined) return null;
  return { poolOffset, loadedValue };
};

const decodeThumb32LiteralLoad = (options: {
  readonly fileBytes: Uint8Array;
  readonly baseAddress: number;
  readonly off: number;
  readonly hw1: number;
  readonly hw2: number;
}): RawPoolLoadCandidate | "out_of_image" | null => {
  if (options.hw1 !== 0xf8df && options.hw1 !== 0xf85f) return null;
  const uAdd = options.hw1 === 0xf8df;
  const rt = (options.hw2 >>> 12) & 0x0f;
  const imm12 = options.hw2 & 0x0fff;
  const insnAddress = (options.baseAddress + options.off) >>> 0;
  const alignedPc = (BigInt(insnAddress) + 4n) & ~3n;
  const poolAddrBig = uAdd
    ? alignedPc + BigInt(imm12)
    : alignedPc - BigInt(imm12);
  const resolved = resolvePoolSlot(
    options.fileBytes,
    options.baseAddress,
    poolAddrBig,
  );
  if (resolved === null) return "out_of_image";
  const reg = ARM_REGISTERS[rt] ?? `r${String(rt)}`;
  const signedDisp = uAdd
    ? `#0x${imm12.toString(16)}`
    : `#-0x${imm12.toString(16)}`;
  return {
    insnOffset: options.off,
    insnSize: 4,
    insnAddress,
    mnemonic: "ldr.w",
    targetRegister: reg,
    disassembly: `ldr.w ${reg}, [pc, ${signedDisp}]`,
    poolOffset: resolved.poolOffset,
    poolAddress: Number(poolAddrBig),
    loadedValue: resolved.loadedValue,
  };
};

const decodeThumb16LiteralLoad = (options: {
  readonly fileBytes: Uint8Array;
  readonly baseAddress: number;
  readonly off: number;
  readonly hw1: number;
}): RawPoolLoadCandidate | "out_of_image" | null => {
  if ((options.hw1 & 0xf800) !== 0x4800) return null;
  const rt = (options.hw1 >>> 8) & 0x07;
  const immBytes = (options.hw1 & 0xff) * 4;
  const insnAddress = (options.baseAddress + options.off) >>> 0;
  const alignedPc = (BigInt(insnAddress) + 4n) & ~3n;
  const poolAddrBig = alignedPc + BigInt(immBytes);
  const resolved = resolvePoolSlot(
    options.fileBytes,
    options.baseAddress,
    poolAddrBig,
  );
  if (resolved === null) return "out_of_image";
  const reg = ARM_REGISTERS[rt] ?? `r${String(rt)}`;
  return {
    insnOffset: options.off,
    insnSize: 2,
    insnAddress,
    mnemonic: "ldr",
    targetRegister: reg,
    disassembly: `ldr ${reg}, [pc, #0x${immBytes.toString(16)}]`,
    poolOffset: resolved.poolOffset,
    poolAddress: Number(poolAddrBig),
    loadedValue: resolved.loadedValue,
  };
};

export const collectThumbCandidates = (
  fileBytes: Uint8Array,
  baseAddress: number,
  scanStart: number,
  scanEnd: number,
): RawIsaScanResult => {
  const candidates: RawPoolLoadCandidate[] = [];
  const forwardPoolOffsets = new Set<number>();
  // not-an-allowance: tally of PC-relative literal loads targeting outside image bounds
  let outOfImageTargets = 0;
  let off = scanStart;

  while (off + 2 <= scanEnd) {
    if (forwardPoolOffsets.has(off & ~3)) {
      off += 2;
      continue;
    }
    const hw1 = readUint16At(fileBytes, off, true);
    if (hw1 === undefined) break;

    if (hw1 >= 0xe800) {
      if (off + 4 > scanEnd) break;
      const hw2 = readUint16At(fileBytes, off + 2, true);
      if (hw2 === undefined) break;
      const decoded = decodeThumb32LiteralLoad({
        fileBytes,
        baseAddress,
        off,
        hw1,
        hw2,
      });
      if (decoded === "out_of_image") {
        outOfImageTargets += 1;
      } else if (decoded !== null) {
        if (decoded.poolOffset > off)
          forwardPoolOffsets.add(decoded.poolOffset);
        candidates.push(decoded);
      }
      off += 4;
      continue;
    }

    const decoded16 = decodeThumb16LiteralLoad({
      fileBytes,
      baseAddress,
      off,
      hw1,
    });
    if (decoded16 === "out_of_image") {
      outOfImageTargets += 1;
    } else if (decoded16 !== null) {
      if (decoded16.poolOffset > off) {
        forwardPoolOffsets.add(decoded16.poolOffset);
      }
      candidates.push(decoded16);
    }
    off += 2;
  }

  return { candidates, outOfImageTargets };
};

export const collectA32Candidates = (
  fileBytes: Uint8Array,
  baseAddress: number,
  scanStart: number,
  scanEnd: number,
): RawIsaScanResult => {
  const candidates: RawPoolLoadCandidate[] = [];
  const forwardPoolOffsets = new Set<number>();
  // not-an-allowance: tally of PC-relative literal loads targeting outside image bounds
  let outOfImageTargets = 0;

  for (let off = scanStart; off + 4 <= scanEnd; off += 4) {
    if (forwardPoolOffsets.has(off)) continue;
    const word = readUint32At(fileBytes, off, true);
    if (word === undefined) break;
    const cond = (word >>> 28) & 0x0f;
    if (cond === 0x0f || (word & 0x0f7f_0000) !== 0x051f_0000) continue;

    const uAdd = (word & 0x0080_0000) !== 0;
    const rd = (word >>> 12) & 0x0f;
    const imm12 = word & 0x0fff;
    const insnAddress = (baseAddress + off) >>> 0;
    const poolAddrBig =
      BigInt(insnAddress) + 8n + (uAdd ? BigInt(imm12) : -BigInt(imm12));
    const resolved = resolvePoolSlot(fileBytes, baseAddress, poolAddrBig);
    if (resolved === null) {
      outOfImageTargets += 1;
      continue;
    }
    if (resolved.poolOffset > off) forwardPoolOffsets.add(resolved.poolOffset);
    const reg = ARM_REGISTERS[rd] ?? `r${String(rd)}`;
    const condText = A32_COND_SUFFIX[cond] ?? "";
    const signedDisp = uAdd
      ? `#0x${imm12.toString(16)}`
      : `#-0x${imm12.toString(16)}`;
    candidates.push({
      insnOffset: off,
      insnSize: 4,
      insnAddress,
      mnemonic: "ldr",
      targetRegister: reg,
      disassembly: `ldr${condText} ${reg}, [pc, ${signedDisp}]`,
      poolOffset: resolved.poolOffset,
      poolAddress: Number(poolAddrBig),
      loadedValue: resolved.loadedValue,
    });
  }

  return { candidates, outOfImageTargets };
};

const isXtensaEntryAnchor = (
  fileBytes: Uint8Array,
  off: number,
  scanEnd: number,
): boolean =>
  (off & 3) === 0 &&
  off + 3 <= scanEnd &&
  fileBytes[off] === 0x36 &&
  (fileBytes[off + 1]! & 0x0f) === 0x01;

const skipZeroPaddingToAlign4 = (
  fileBytes: Uint8Array,
  startOff: number,
  scanEnd: number,
): number => {
  let cursor = startOff;
  while (cursor < scanEnd && (cursor & 3) !== 0 && fileBytes[cursor] === 0x00) {
    cursor += 1;
  }
  return cursor;
};

const stepXtensaInstruction = (
  fileBytes: Uint8Array,
  off: number,
  scanEnd: number,
): number | "stop" => {
  const b0 = fileBytes[off]!;
  const op0 = b0 & 0x0f;
  if (op0 >= 0x0e) return (off & ~3) + 4;
  if (op0 >= 0x08) {
    const b1 = fileBytes[off + 1]!;
    const isNarrowRet = (b0 === 0x0d || b0 === 0x1d) && b1 === 0xf0;
    return isNarrowRet
      ? skipZeroPaddingToAlign4(fileBytes, off + 2, scanEnd)
      : off + 2;
  }
  if (off + 3 > scanEnd) return "stop";
  const b1 = fileBytes[off + 1]!;
  const b2 = fileBytes[off + 2]!;
  if (b0 === 0x00 && b1 === 0x00 && b2 === 0x00) return (off & ~3) + 4;
  const nextAligned = (off & ~3) + 4;
  if (
    nextAligned > off &&
    nextAligned < off + 3 &&
    isXtensaEntryAnchor(fileBytes, nextAligned, scanEnd)
  ) {
    return nextAligned;
  }
  const isWideRet = (b0 === 0x80 || b0 === 0x90) && b1 === 0x00 && b2 === 0x00;
  return isWideRet
    ? skipZeroPaddingToAlign4(fileBytes, off + 3, scanEnd)
    : off + 3;
};

export const collectXtensaCandidates = (
  fileBytes: Uint8Array,
  baseAddress: number,
  scanStart: number,
  scanEnd: number,
): RawIsaScanResult => {
  const candidates: RawPoolLoadCandidate[] = [];
  // not-an-allowance: tally of L32R instructions targeting outside image bounds
  let outOfImageTargets = 0;
  let off = scanStart;

  while (off + 2 <= scanEnd) {
    const b0 = fileBytes[off]!;
    const op0 = b0 & 0x0f;
    if (op0 === 0x01 && off + 3 <= scanEnd) {
      const nextAligned = (off & ~3) + 4;
      const crossesEntry =
        nextAligned > off &&
        nextAligned < off + 3 &&
        isXtensaEntryAnchor(fileBytes, nextAligned, scanEnd);
      if (!crossesEntry) {
        const at = (b0 >>> 4) & 0x0f;
        const offset16 = fileBytes[off + 1]! | (fileBytes[off + 2]! << 8);
        const signedWords = offset16 - 0x1_0000;
        const insnAddress = (baseAddress + off) >>> 0;
        const alignedPc = (BigInt(insnAddress) + 3n) & ~3n;
        const poolAddrBig = alignedPc + BigInt(signedWords) * 4n;
        const resolved = resolvePoolSlot(fileBytes, baseAddress, poolAddrBig);
        if (resolved === null) {
          outOfImageTargets += 1;
        } else {
          const reg = `a${String(at)}`;
          const poolAddrNum = Number(poolAddrBig);
          candidates.push({
            insnOffset: off,
            insnSize: 3,
            insnAddress,
            mnemonic: "l32r",
            targetRegister: reg,
            disassembly: `l32r ${reg}, ${formatHexCompact(poolAddrNum)}`,
            poolOffset: resolved.poolOffset,
            poolAddress: poolAddrNum,
            loadedValue: resolved.loadedValue,
          });
        }
      }
    }
    const nextOff = stepXtensaInstruction(fileBytes, off, scanEnd);
    if (nextOff === "stop") break;
    off = nextOff;
  }

  return { candidates, outOfImageTargets };
};
