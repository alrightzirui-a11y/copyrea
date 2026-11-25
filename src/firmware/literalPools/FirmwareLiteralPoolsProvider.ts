import { decodeLimit } from "../../domain/parseFailure.js";
import {
  isParseLimit,
  parseLimitConstraint,
} from "../../domain/parseFailureAnalysisError.js";
import {
  ArtifactResourceScope,
  artifactFilePrimaryFacts,
  assertArtifactReadActive,
  projectArtifactCloseFailure,
  projectStableArtifactFailure,
  readStableArtifact,
  type StableArtifactSnapshot,
} from "../../resources/index.js";
import type { ExecutionOptions } from "../../ports/AnalysisProvider.js";
import type { FirmwareLiteralPoolsPort } from "../../ports/binaryDiagnostics/FirmwareLiteralPoolsPort.js";
import {
  MAX_LITERAL_POOL_FILE_BYTES,
  MAX_LITERAL_POOL_SVD_XML_NODES,
  firmwareLiteralPoolBudgetLimit,
  type InspectFirmwareLiteralPoolsInput,
} from "../../domain/firmware/firmwareLiteralPools.js";
import { parseSvdPeripheralSpans } from "../../domain/firmware/firmwareLiteralPoolRegions.js";
import { scanFirmwareLiteralPools } from "../../domain/firmware/firmwareLiteralPoolScanner.js";
import { FIRMWARE_LITERAL_POOLS_PROVIDER } from "../../domain/investigationProviders.js";
import { err, ok } from "../../domain/result.js";
import { classifyProviderFailure } from "../../providers/classifyProviderFailure.js";
import { offlineArtifactFailureDialect } from "../../providers/offlineArtifactFailure.js";

const OPERATION = "inspect_firmware_literal_pools";

/** Portable ARM Thumb/Thumb-2/A32 and Xtensa L32R literal-pool decoder over one regular file. */
export class FirmwareLiteralPoolsProvider implements FirmwareLiteralPoolsPort {
  readonly identity = FIRMWARE_LITERAL_POOLS_PROVIDER;
  readonly #resources = new ArtifactResourceScope();

  async close(): Promise<void> {
    try {
      await this.#resources.close();
    } catch (cause: unknown) {
      throw projectArtifactCloseFailure(
        cause,
        FIRMWARE_LITERAL_POOLS_PROVIDER.id,
        OPERATION,
      );
    }
  }

  async inspect(
    input: InspectFirmwareLiteralPoolsInput,
    options?: ExecutionOptions,
  ) {
    let snapshot: StableArtifactSnapshot | undefined;
    try {
      return await this.#resources.run(async () => {
        assertArtifactReadActive(options?.signal);
        const svdResult =
          input.svd_xml === undefined
            ? ok([])
            : parseSvdPeripheralSpans(input.svd_xml);
        if (!svdResult.ok) throw svdResult.error;

        snapshot = await readStableArtifact(
          input.path,
          input.max_file_bytes,
          options?.signal,
          undefined,
          this.#resources,
        );
        assertArtifactReadActive(options?.signal);

        const parsed = scanFirmwareLiteralPools({
          artifact: {
            path: input.path,
            sha256: snapshot.sha256,
            bytes: snapshot.bytes.length,
          },
          fileBytes: snapshot.bytes,
          isa: input.isa,
          baseAddressHex: input.base_address,
          scanOffset: input.scan_offset,
          maxScanBytes: input.max_scan_bytes,
          maxReferences: input.max_references,
          svdSupplied: input.svd_xml !== undefined,
          svdPeripherals: svdResult.value,
        });
        if (!parsed.ok) throw parsed.error;
        return ok(parsed.value);
      });
    } catch (cause) {
      return err(literalPoolsFailure(cause, input, snapshot));
    }
  }
}

const fileSizeRemediation = (input: InspectFirmwareLiteralPoolsInput): string =>
  input.max_file_bytes >= MAX_LITERAL_POOL_FILE_BYTES
    ? `The image exceeds the ${String(MAX_LITERAL_POOL_FILE_BYTES)}-byte input ceiling this operation accepts; select a smaller firmware slice.`
    : `Raise max_file_bytes above ${String(input.max_file_bytes)} bytes within its ${String(MAX_LITERAL_POOL_FILE_BYTES)}-byte ceiling, or select a smaller firmware slice.`;

const literalPoolsFailure = (
  cause: unknown,
  input: InspectFirmwareLiteralPoolsInput,
  snapshot: StableArtifactSnapshot | undefined,
) => {
  const facts = artifactFilePrimaryFacts(cause);
  const primary = classifyProviderFailure(
    facts.cause,
    offlineArtifactFailureDialect(facts, {
      providerId: FIRMWARE_LITERAL_POOLS_PROVIDER.id,
      operation: OPERATION,
      path: input.path,
      description: "firmware literal pools",
      fallbackMessage: "Firmware literal-pool inspection failed.",
      recognise: (failure) => {
        if (isParseLimit(failure, "cmsis-svd")) {
          return parseLimitConstraint(OPERATION, "capacity", failure, {
            retryable: false,
            limit: firmwareLiteralPoolBudgetLimit(
              "svd_xml",
              MAX_LITERAL_POOL_SVD_XML_NODES,
            ),
            remediationAction: `Provide a trimmed CMSIS-SVD document within the ${String(MAX_LITERAL_POOL_SVD_XML_NODES)}-node XML ceiling.`,
          });
        }
        return undefined;
      },
      fileSize: (failure) =>
        parseLimitConstraint(
          OPERATION,
          "file-size",
          decodeLimit(
            "firmware-literal-pools",
            failure.message,
            { name: "max_file_bytes", maximum: input.max_file_bytes },
            { cause: failure },
          ),
          {
            retryable: false,
            limit: firmwareLiteralPoolBudgetLimit(
              "max_file_bytes",
              input.max_file_bytes,
            ),
            remediationAction: fileSizeRemediation(input),
          },
        ),
    }),
  );
  return projectStableArtifactFailure(
    cause,
    primary,
    input.path,
    FIRMWARE_LITERAL_POOLS_PROVIDER.id,
    OPERATION,
    snapshot,
  );
};
