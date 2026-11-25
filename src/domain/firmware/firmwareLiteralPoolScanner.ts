import { BoundedListCollector } from "../boundedList.js";
import { malformedInput, type ParseFailureError } from "../parseFailure.js";
import { err, ok, type Result } from "../result.js";
import { compareUnicodeCodePoints } from "../unicodeCodePointOrder.js";
import {
  collectA32Candidates,
  collectThumbCandidates,
  collectXtensaCandidates,
  type RawPoolLoadCandidate,
} from "./firmwareLiteralPoolDecoders.js";
import {
  classifyLoadedConstant,
  formatHex32,
  formatHexCompact,
  type SvdPeripheralSpan,
} from "./firmwareLiteralPoolRegions.js";
import type {
  FirmwareLiteralPoolIsa,
  FirmwareLiteralPoolsReport,
  LiteralPoolAttributionBasis,
  LiteralPoolMmioSummary,
  LiteralPoolReference,
  LiteralPoolRegionKind,
} from "./firmwareLiteralPools.js";

export interface ScanFirmwareLiteralPoolsOptions {
  readonly artifact: {
    readonly path: string;
    readonly sha256: string;
    readonly bytes: number;
  };
  readonly fileBytes: Uint8Array;
  readonly isa: FirmwareLiteralPoolIsa;
  readonly baseAddressHex: string;
  readonly scanOffset: number;
  readonly maxScanBytes: number;
  readonly maxReferences: number;
  readonly svdSupplied: boolean;
  readonly svdPeripherals: readonly SvdPeripheralSpan[];
}

interface MmioAccumulator {
  readonly groupKey: string;
  readonly regionKind: LiteralPoolRegionKind;
  readonly basis: LiteralPoolAttributionBasis;
  readonly baseAddress: number;
  readonly svdPeripheral: string | null;
  readonly architecturalBlock: string | null;
  // not-an-allowance: observed count of literal-pool loads targeting this MMIO group
  referenceCount: number;
  readonly constants: Set<string>;
  readonly sampleInstructions: string[];
}

const SAMPLE_ADDRESS_DISPLAY_COUNT = 6;
const DISTINCT_CONSTANT_DISPLAY_COUNT = 16;

const parseHexBaseAddress = (
  rawHex: string,
  fileLength: number,
): Result<number, ParseFailureError<"malformed">> => {
  const parsed = Number.parseInt(rawHex.slice(2), 16);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > 0xffff_ffff) {
    return err(
      malformedInput(
        "firmware-literal-pools",
        `base_address ${rawHex} is outside the 32-bit unsigned address space.`,
      ),
    );
  }
  if (BigInt(parsed) + BigInt(fileLength) > 0x1_0000_0000n) {
    return err(
      malformedInput(
        "firmware-literal-pools",
        `Image of ${String(fileLength)} bytes at ${rawHex} wraps past 32-bit address space.`,
      ),
    );
  }
  return ok(parsed);
};

const checkIsaAlignment = (
  isa: FirmwareLiteralPoolIsa,
  baseAddress: number,
  scanOffset: number,
): ParseFailureError<"malformed"> | null => {
  if (
    isa === "arm-thumb" &&
    ((baseAddress & 1) !== 0 || (scanOffset & 1) !== 0)
  ) {
    return malformedInput(
      "firmware-literal-pools",
      "arm-thumb requires 2-byte aligned base_address and scan_offset.",
    );
  }
  if (
    isa === "arm-a32" &&
    ((baseAddress & 3) !== 0 || (scanOffset & 3) !== 0)
  ) {
    return malformedInput(
      "firmware-literal-pools",
      "arm-a32 requires 4-byte aligned base_address and scan_offset.",
    );
  }
  return null;
};

const overlapsPoolWord = (
  insnOffset: number,
  insnSize: number,
  poolOffsets: ReadonlySet<number>,
): boolean => {
  const firstAligned = insnOffset & ~3;
  const lastAligned = (insnOffset + insnSize - 1) & ~3;
  for (let slot = firstAligned; slot <= lastAligned; slot += 4) {
    if (poolOffsets.has(slot)) return true;
  }
  return false;
};

const filterPoolSlotOverlaps = (
  candidates: readonly RawPoolLoadCandidate[],
): {
  readonly retained: readonly RawPoolLoadCandidate[];
  readonly suppressedCount: number;
} => {
  const allTargets = new Set<number>(candidates.map((c) => c.poolOffset));
  const nonPoolSources = candidates.filter(
    (c) => !overlapsPoolWord(c.insnOffset, c.insnSize, allTargets),
  );
  const confirmedPoolSlots = new Set<number>(
    nonPoolSources.map((c) => c.poolOffset),
  );
  const retained = candidates.filter(
    (c) => !overlapsPoolWord(c.insnOffset, c.insnSize, confirmedPoolSlots),
  );
  return {
    retained,
    suppressedCount: candidates.length - retained.length,
  };
};

const recordMmioSummary = (
  groups: Map<string, MmioAccumulator>,
  reference: LiteralPoolReference,
  mmioBaseAddress: number,
): void => {
  const groupKey =
    reference.svd_peripheral !== null
      ? `svd:${reference.svd_peripheral}`
      : reference.architectural_block !== null
        ? `arch:${reference.architectural_block}`
        : `page:${formatHex32(mmioBaseAddress)}`;
  let acc = groups.get(groupKey);
  if (acc === undefined) {
    acc = {
      groupKey,
      regionKind: reference.region_kind,
      basis: reference.basis,
      baseAddress: mmioBaseAddress,
      svdPeripheral: reference.svd_peripheral,
      architecturalBlock: reference.architectural_block,
      referenceCount: 0,
      constants: new Set<string>(),
      sampleInstructions: [],
    };
    groups.set(groupKey, acc);
  }
  acc.referenceCount += 1;
  if (acc.constants.size < DISTINCT_CONSTANT_DISPLAY_COUNT) {
    acc.constants.add(reference.loaded_value);
  }
  if (acc.sampleInstructions.length < SAMPLE_ADDRESS_DISPLAY_COUNT) {
    acc.sampleInstructions.push(reference.instruction_address);
  }
};

const buildMmioSummaryList = (
  groups: ReadonlyMap<string, MmioAccumulator>,
): LiteralPoolMmioSummary[] =>
  [...groups.values()]
    .sort(
      (a, b) =>
        b.referenceCount - a.referenceCount ||
        compareUnicodeCodePoints(a.groupKey, b.groupKey),
    )
    .map((group) => ({
      group_key: group.groupKey,
      region_kind: group.regionKind,
      basis: group.basis,
      base_address: formatHex32(group.baseAddress),
      svd_peripheral: group.svdPeripheral,
      architectural_block: group.architecturalBlock,
      reference_count: group.referenceCount,
      distinct_constants: [...group.constants].sort(compareUnicodeCodePoints),
      sample_instruction_addresses: group.sampleInstructions,
    }));

const buildScanLimitations = (params: {
  readonly scanTruncated: boolean;
  readonly scannedBytes: number;
  readonly availableFromOffset: number;
  readonly scanOffset: number;
  readonly maxScanBytes: number;
  readonly retainedCount: number;
  readonly omittedCount: number;
  readonly maxReferences: number;
  readonly svdSupplied: boolean;
}): string[] => {
  const limitations = [
    "Linear instruction scanning without control-flow recovery may encounter inline non-pool data tables (such as switch jump tables or embedded strings); referenced 32-bit pool slots are suppressed from instruction decoding.",
  ];
  if (params.scanTruncated) {
    limitations.push(
      `Scanned ${String(params.scannedBytes)} of ${String(params.availableFromOffset)} available bytes from scan_offset ${String(params.scanOffset)} (bounded by max_scan_bytes = ${String(params.maxScanBytes)}).`,
    );
  }
  if (params.omittedCount > 0) {
    limitations.push(
      `Retained ${String(params.retainedCount)} literal-pool load references inline and omitted ${String(params.omittedCount)} (bounded by max_references = ${String(params.maxReferences)}); mmio_summary and counts cover all ${String(params.scannedBytes)} scanned bytes.`,
    );
  }
  if (!params.svdSupplied) {
    limitations.push(
      "No svd_xml profile was supplied; peripheral MMIO regions outside architectural Cortex-M PPB/SCS blocks are grouped by 4 KiB page under address_map_convention.",
    );
  }
  return limitations;
};

const runIsaCandidateScan = (
  isa: FirmwareLiteralPoolIsa,
  fileBytes: Uint8Array,
  baseAddress: number,
  range: { readonly start: number; readonly end: number },
) => {
  if (isa === "arm-thumb") {
    return collectThumbCandidates(
      fileBytes,
      baseAddress,
      range.start,
      range.end,
    );
  }
  if (isa === "arm-a32") {
    return collectA32Candidates(fileBytes, baseAddress, range.start, range.end);
  }
  return collectXtensaCandidates(
    fileBytes,
    baseAddress,
    range.start,
    range.end,
  );
};

const classifyAndCollectReferences = (params: {
  readonly retained: readonly RawPoolLoadCandidate[];
  readonly isa: FirmwareLiteralPoolIsa;
  readonly baseAddress: number;
  readonly fileByteLength: number;
  readonly maxReferences: number;
  readonly svdPeripherals: readonly SvdPeripheralSpan[];
}) => {
  const collector = new BoundedListCollector<LiteralPoolReference>(
    params.maxReferences,
  );
  const distinctSlots = new Set<number>();
  const mmioGroups = new Map<string, MmioAccumulator>();
  // not-an-allowance: tally of literal-pool loads classified as peripheral/PPB MMIO
  let mmioLoadCount = 0;
  // not-an-allowance: tally of literal-pool loads matched against supplied CMSIS-SVD
  let svdMatchedLoadCount = 0;

  for (const cand of params.retained) {
    distinctSlots.add(cand.poolOffset);
    const classified = classifyLoadedConstant({
      value: cand.loadedValue,
      isa: params.isa,
      baseAddress: params.baseAddress,
      fileBytes: params.fileByteLength,
      svdPeripherals: params.svdPeripherals,
    });
    const ref: LiteralPoolReference = {
      instruction_offset: cand.insnOffset,
      instruction_address: formatHexCompact(cand.insnAddress),
      mnemonic: cand.mnemonic,
      target_register: cand.targetRegister,
      disassembly: cand.disassembly,
      pool_offset: cand.poolOffset,
      pool_address: formatHexCompact(cand.poolAddress),
      loaded_value: formatHex32(cand.loadedValue),
      region_kind: classified.regionKind,
      basis: classified.basis,
      architectural_block: classified.architecturalBlock,
      svd_peripheral: classified.svdPeripheral,
      svd_register_offset: classified.svdRegisterOffset,
    };
    if (classified.svdPeripheral !== null) svdMatchedLoadCount += 1;
    if (classified.mmioBaseAddress !== null) {
      mmioLoadCount += 1;
      recordMmioSummary(mmioGroups, ref, classified.mmioBaseAddress);
    }
    collector.push(ref);
  }

  return {
    bounded: collector.toList(),
    distinctSlotCount: distinctSlots.size,
    mmioGroups,
    mmioLoadCount,
    svdMatchedLoadCount,
  };
};

/** Disassemble PC-relative literal-pool loads and classify loaded 32-bit MMIO constants. */
export const scanFirmwareLiteralPools = (
  options: ScanFirmwareLiteralPoolsOptions,
): Result<FirmwareLiteralPoolsReport, ParseFailureError<"malformed">> => {
  const baseResult = parseHexBaseAddress(
    options.baseAddressHex,
    options.fileBytes.length,
  );
  if (!baseResult.ok) return baseResult;
  const baseAddress = baseResult.value;

  const alignErr = checkIsaAlignment(
    options.isa,
    baseAddress,
    options.scanOffset,
  );
  if (alignErr !== null) return err(alignErr);

  const availableFromOffset = Math.max(
    0,
    options.fileBytes.length - options.scanOffset,
  );
  const scanStart = Math.min(options.scanOffset, options.fileBytes.length);
  const scanEnd = Math.min(
    options.fileBytes.length,
    scanStart + options.maxScanBytes,
  );
  const scannedBytes = scanEnd - scanStart;

  const rawScan = runIsaCandidateScan(
    options.isa,
    options.fileBytes,
    baseAddress,
    { start: scanStart, end: scanEnd },
  );
  const { retained, suppressedCount } = filterPoolSlotOverlaps(
    rawScan.candidates,
  );
  const collected = classifyAndCollectReferences({
    retained,
    isa: options.isa,
    baseAddress,
    fileByteLength: options.fileBytes.length,
    maxReferences: options.maxReferences,
    svdPeripherals: options.svdPeripherals,
  });

  const scanTruncated = scannedBytes < availableFromOffset;
  return ok({
    artifact: options.artifact,
    isa: options.isa,
    base_address: formatHexCompact(baseAddress),
    scan_range: { start: scanStart, end: scanEnd, scanned_bytes: scannedBytes },
    coverage: {
      status:
        scanTruncated || collected.bounded.omitted > 0 ? "partial" : "complete",
      available_from_offset_bytes: availableFromOffset,
      retained_references: collected.bounded.items.length,
      omitted_references: collected.bounded.omitted,
    },
    counts: {
      resolved_pool_loads: retained.length,
      distinct_pool_slots: collected.distinctSlotCount,
      mmio_pool_loads: collected.mmioLoadCount,
      out_of_image_pool_targets: rawScan.outOfImageTargets,
      suppressed_pool_slot_overlaps: suppressedCount,
    },
    svd_profile: {
      supplied: options.svdSupplied,
      peripheral_count: options.svdPeripherals.length,
      matched_load_count: collected.svdMatchedLoadCount,
    },
    mmio_summary: buildMmioSummaryList(collected.mmioGroups),
    references: [...collected.bounded.items],
    limitations: buildScanLimitations({
      scanTruncated,
      scannedBytes,
      availableFromOffset,
      scanOffset: options.scanOffset,
      maxScanBytes: options.maxScanBytes,
      retainedCount: collected.bounded.items.length,
      omittedCount: collected.bounded.omitted,
      maxReferences: options.maxReferences,
      svdSupplied: options.svdSupplied,
    }),
  });
};
