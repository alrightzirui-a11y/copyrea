import type { Element } from "@xmldom/xmldom";
import {
  decodeLimit,
  malformedInput,
  type ParseFailureError,
} from "../parseFailure.js";
import { err, ok, type Result } from "../result.js";
import {
  parseXmlDocumentWithinNodeLimit,
  xmlChildrenNamed,
  xmlFirstChildNamed,
} from "../xmlDocument.js";
import {
  MAX_LITERAL_POOL_SVD_XML_NODES,
  type FirmwareLiteralPoolIsa,
  type LiteralPoolAttributionBasis,
  type LiteralPoolRegionKind,
} from "./firmwareLiteralPools.js";

export interface SvdPeripheralSpan {
  readonly name: string;
  readonly baseAddress: number;
  readonly endAddress: number;
}

export type SvdPeripheralParseError =
  | ParseFailureError<"malformed">
  | ParseFailureError<"unsupported">
  | ParseFailureError<"limit">;

export interface ConstantClassification {
  readonly regionKind: LiteralPoolRegionKind;
  readonly basis: LiteralPoolAttributionBasis;
  readonly architecturalBlock: string | null;
  readonly svdPeripheral: string | null;
  readonly svdRegisterOffset: string | null;
  readonly mmioBaseAddress: number | null;
}

const DEFAULT_PERIPHERAL_SPAN_BYTES = 0x400;

export const formatHex32 = (value: number): string =>
  `0x${(value >>> 0).toString(16).padStart(8, "0")}`;

export const formatHexCompact = (value: number): string =>
  `0x${(value >>> 0).toString(16)}`;

const trimmedText = (element: Element | undefined): string | null => {
  if (element === undefined) return null;
  const text = (element.textContent ?? "").trim();
  return text.length > 0 ? `${text}` : null;
};

const parseUnsigned32 = (raw: string): number | null => {
  const normalized = raw.trim();
  const parsed = /^0x[0-9a-fA-F]+$/u.test(normalized)
    ? Number.parseInt(normalized.slice(2), 16)
    : /^[0-9]+$/u.test(normalized)
      ? Number.parseInt(normalized, 10)
      : Number.NaN;
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > 0xffff_ffff) {
    return null;
  }
  return parsed;
};

const extractAddressBlockEndOffset = (peripheralEl: Element): number | null => {
  let maxEnd = 0;
  for (const block of xmlChildrenNamed(peripheralEl, "addressBlock")) {
    const offsetText = trimmedText(xmlFirstChildNamed(block, "offset")) ?? "0";
    const sizeText = trimmedText(xmlFirstChildNamed(block, "size"));
    if (sizeText === null) continue;
    const blockOffset = parseUnsigned32(offsetText);
    const blockSize = parseUnsigned32(sizeText);
    if (blockOffset === null || blockSize === null || blockSize === 0) continue;
    const endOffset = blockOffset + blockSize;
    if (endOffset > maxEnd) maxEnd = endOffset;
  }
  return maxEnd > 0 ? maxEnd : null;
};

/** Parse CMSIS-SVD `<peripheral>` base addresses and `<addressBlock>` spans. */
export const parseSvdPeripheralSpans = (
  svdXml: string,
): Result<readonly SvdPeripheralSpan[], SvdPeripheralParseError> => {
  const docResult = parseXmlDocumentWithinNodeLimit(svdXml, {
    maximumNodes: MAX_LITERAL_POOL_SVD_XML_NODES,
    lineEndings: "normalize",
  });
  if (!docResult.ok) {
    const failure = docResult.error;
    if ("kind" in failure && failure.kind === "node-limit") {
      return err(
        decodeLimit(
          "cmsis-svd",
          `svd_xml exceeded the ${String(failure.maximum)}-node XML ceiling`,
          { name: "svd_xml", maximum: failure.maximum },
        ),
      );
    }
    return err(failure);
  }

  const root = docResult.value.documentElement;
  if (root === null || root.localName !== "device") {
    return err(
      malformedInput("cmsis-svd", "CMSIS-SVD root element must be <device>."),
    );
  }

  const peripheralsEl = xmlFirstChildNamed(root, "peripherals");
  if (peripheralsEl === undefined) return ok([]);

  const spanByName = new Map<string, number>();
  const rawEntries: {
    readonly name: string;
    readonly baseAddress: number;
    readonly derivedFrom: string | null;
    readonly explicitSpan: number | null;
  }[] = [];

  for (const periphEl of xmlChildrenNamed(peripheralsEl, "peripheral")) {
    const name = trimmedText(xmlFirstChildNamed(periphEl, "name"));
    const baseText = trimmedText(xmlFirstChildNamed(periphEl, "baseAddress"));
    if (name === null || baseText === null) continue;
    const baseAddress = parseUnsigned32(baseText);
    if (baseAddress === null) continue;
    const rawDerived = periphEl.getAttribute("derivedFrom") as string | null;
    const derivedAttr = (rawDerived ?? "").trim();
    const derivedFrom = derivedAttr.length > 0 ? derivedAttr : null;
    const explicitSpan = extractAddressBlockEndOffset(periphEl);
    if (explicitSpan !== null) spanByName.set(name, explicitSpan);
    rawEntries.push({ name, baseAddress, derivedFrom, explicitSpan });
  }

  const resolved: SvdPeripheralSpan[] = rawEntries.map((entry) => {
    const parentSpan =
      entry.derivedFrom !== null
        ? spanByName.get(entry.derivedFrom)
        : undefined;
    const inheritedSpan =
      entry.explicitSpan ?? parentSpan ?? DEFAULT_PERIPHERAL_SPAN_BYTES;
    return {
      name: entry.name,
      baseAddress: entry.baseAddress,
      endAddress: Math.min(0x1_0000_0000, entry.baseAddress + inheritedSpan),
    };
  });

  resolved.sort(
    (a, b) =>
      a.baseAddress - b.baseAddress ||
      a.endAddress - a.baseAddress - (b.endAddress - b.baseAddress),
  );
  return ok(resolved);
};

const CORTEX_M_EXACT_REGISTERS: ReadonlyMap<number, string> = new Map([
  [0xe000_ed08, "SCB.VTOR"],
  [0xe000_ed0c, "SCB.AIRCR"],
  [0xe000_ed88, "SCB.CPACR"],
]);

const CORTEX_M_PPB_RANGES: readonly {
  readonly start: number;
  readonly end: number;
  readonly name: string;
}[] = [
  { start: 0xe000_1000, end: 0xe000_1fff, name: "DWT" },
  { start: 0xe000_2000, end: 0xe000_2fff, name: "FPB" },
  { start: 0xe000_e010, end: 0xe000_e0ff, name: "SysTick" },
  { start: 0xe000_e100, end: 0xe000_ecff, name: "NVIC" },
  { start: 0xe000_ed00, end: 0xe000_ed8f, name: "SCB" },
  { start: 0xe000_ed90, end: 0xe000_edef, name: "MPU" },
  { start: 0xe000_ef00, end: 0xe000_efff, name: "SCS_FPU" },
];

const classifyCortexMPpbBlock = (value: number): string => {
  const exact = CORTEX_M_EXACT_REGISTERS.get(value);
  if (exact !== undefined) return exact;
  for (const range of CORTEX_M_PPB_RANGES) {
    if (value >= range.start && value <= range.end) return range.name;
  }
  return "PPB";
};

const findSvdMatch = (
  value: number,
  svdPeripherals: readonly SvdPeripheralSpan[],
): SvdPeripheralSpan | undefined => {
  for (const periph of svdPeripherals) {
    if (value >= periph.baseAddress && value < periph.endAddress) {
      return periph;
    }
  }
  return undefined;
};

const nonMmioClassification = (
  regionKind: LiteralPoolRegionKind,
  basis: LiteralPoolAttributionBasis,
): ConstantClassification => ({
  regionKind,
  basis,
  architecturalBlock: null,
  svdPeripheral: null,
  svdRegisterOffset: null,
  mmioBaseAddress: null,
});

const classifyArmMmioOrSram = (
  u32: number,
  svdMatch: SvdPeripheralSpan | undefined,
): ConstantClassification | null => {
  const svdPeripheral = svdMatch?.name ?? null;
  const svdRegisterOffset =
    svdMatch !== undefined
      ? formatHexCompact(u32 - svdMatch.baseAddress)
      : null;
  const fallbackPage = (u32 & 0xffff_f000) >>> 0;

  if (u32 >= 0xe000_0000 && u32 <= 0xe00f_ffff) {
    return {
      regionKind: "cortex_m_ppb_scs",
      basis:
        svdMatch !== undefined ? "explicit_profile" : "architecture_manual",
      architecturalBlock: classifyCortexMPpbBlock(u32),
      svdPeripheral,
      svdRegisterOffset,
      mmioBaseAddress: svdMatch?.baseAddress ?? fallbackPage,
    };
  }
  if ((u32 >= 0x4000_0000 && u32 <= 0x5fff_ffff) || svdMatch !== undefined) {
    return {
      regionKind: "cortex_m_peripheral",
      basis:
        svdMatch !== undefined ? "explicit_profile" : "address_map_convention",
      architecturalBlock: null,
      svdPeripheral,
      svdRegisterOffset,
      mmioBaseAddress: svdMatch?.baseAddress ?? fallbackPage,
    };
  }
  if (u32 >= 0x2000_0000 && u32 <= 0x3fff_ffff) {
    return nonMmioClassification("cortex_m_sram", "address_map_convention");
  }
  return null;
};

const classifyXtensaMmioOrSram = (
  u32: number,
  svdMatch: SvdPeripheralSpan | undefined,
): ConstantClassification | null => {
  const isEspPeriphBus =
    (u32 >= 0x3ff0_0000 && u32 <= 0x3ff7_ffff) ||
    (u32 >= 0x6000_0000 && u32 <= 0x600f_ffff);
  if (isEspPeriphBus || svdMatch !== undefined) {
    return {
      regionKind: "esp_peripheral",
      basis:
        svdMatch !== undefined ? "explicit_profile" : "address_map_convention",
      architecturalBlock: null,
      svdPeripheral: svdMatch?.name ?? null,
      svdRegisterOffset:
        svdMatch !== undefined
          ? formatHexCompact(u32 - svdMatch.baseAddress)
          : null,
      mmioBaseAddress: svdMatch?.baseAddress ?? (u32 & 0xffff_f000) >>> 0,
    };
  }
  if (u32 >= 0x3ff8_0000 && u32 <= 0x3fff_ffff) {
    return nonMmioClassification("esp_sram_rtc", "address_map_convention");
  }
  return null;
};

const isWithinMappedImage = (
  value: number,
  isa: FirmwareLiteralPoolIsa,
  baseAddress: number,
  fileBytes: number,
): boolean => {
  const candidate = isa === "arm-thumb" ? (value & ~1) >>> 0 : value >>> 0;
  const start = BigInt(baseAddress >>> 0);
  const end = start + BigInt(fileBytes);
  const target = BigInt(candidate);
  return target >= start && target < end;
};

/** Classify a 32-bit literal-pool constant by SVD profile and architectural memory map. */
export const classifyLoadedConstant = (options: {
  readonly value: number;
  readonly isa: FirmwareLiteralPoolIsa;
  readonly baseAddress: number;
  readonly fileBytes: number;
  readonly svdPeripherals: readonly SvdPeripheralSpan[];
}): ConstantClassification => {
  const u32 = options.value >>> 0;
  const svdMatch = findSvdMatch(u32, options.svdPeripherals);
  const archMatch =
    options.isa === "xtensa"
      ? classifyXtensaMmioOrSram(u32, svdMatch)
      : classifyArmMmioOrSram(u32, svdMatch);
  if (archMatch !== null) return archMatch;

  if (
    isWithinMappedImage(
      u32,
      options.isa,
      options.baseAddress,
      options.fileBytes,
    )
  ) {
    return nonMmioClassification("mapped_image", "observed_bounds");
  }
  return nonMmioClassification("other", "unclassified");
};
