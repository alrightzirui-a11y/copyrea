import { decodeLimit } from "../../domain/parseFailure.js";
import { parseLimitConstraint } from "../../domain/parseFailureAnalysisError.js";
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
import type { EspNvsPort } from "../../ports/binaryDiagnostics/EspNvsPort.js";
import {
  MAX_ESP_NVS_FILE_BYTES,
  espNvsBudgetLimit,
  type InspectEspNvsInput,
} from "../../domain/firmware/espNvs.js";
import { parseEspNvsPartition } from "../../domain/firmware/espNvsParser.js";
import { ESP_NVS_PROVIDER } from "../../domain/investigationProviders.js";
import { err, ok } from "../../domain/result.js";
import { classifyProviderFailure } from "../../providers/classifyProviderFailure.js";
import { offlineArtifactFailureDialect } from "../../providers/offlineArtifactFailure.js";

const OPERATION = "inspect_esp_nvs";

/** Portable ESP-IDF Non-Volatile Storage (NVS v1/v2) partition decoder. */
export class EspNvsProvider implements EspNvsPort {
  readonly identity = ESP_NVS_PROVIDER;
  readonly #resources = new ArtifactResourceScope();

  async close(): Promise<void> {
    try {
      await this.#resources.close();
    } catch (cause: unknown) {
      throw projectArtifactCloseFailure(cause, ESP_NVS_PROVIDER.id, OPERATION);
    }
  }

  async inspect(input: InspectEspNvsInput, options?: ExecutionOptions) {
    let snapshot: StableArtifactSnapshot | undefined;
    try {
      return await this.#resources.run(async () => {
        snapshot = await readStableArtifact(
          input.path,
          input.max_file_bytes,
          options?.signal,
          undefined,
          this.#resources,
        );
        assertArtifactReadActive(options?.signal);

        const sliceEnd =
          input.partition_bytes === undefined
            ? snapshot.bytes.length
            : Math.min(
                snapshot.bytes.length,
                input.partition_offset + input.partition_bytes,
              );
        const slice =
          input.partition_offset < snapshot.bytes.length
            ? snapshot.bytes.subarray(input.partition_offset, sliceEnd)
            : Buffer.alloc(0);

        const parsed = parseEspNvsPartition({
          artifact: {
            path: input.path,
            sha256: snapshot.sha256,
            bytes: snapshot.bytes.length,
          },
          partitionOffset: input.partition_offset,
          partitionBytes: input.partition_bytes,
          maxEntries: input.max_entries,
          sliceBytes: slice,
        });
        if (!parsed.ok) throw parsed.error;
        return ok(parsed.value);
      });
    } catch (cause) {
      return err(espNvsFailure(cause, input, snapshot));
    }
  }
}

const fileSizeRemediation = (input: InspectEspNvsInput): string =>
  input.max_file_bytes >= MAX_ESP_NVS_FILE_BYTES
    ? `The image exceeds the ${String(MAX_ESP_NVS_FILE_BYTES)}-byte input ceiling this operation accepts; carve the NVS partition first.`
    : `Raise max_file_bytes above ${String(input.max_file_bytes)} bytes within its ${String(MAX_ESP_NVS_FILE_BYTES)}-byte ceiling, or carve the NVS partition first.`;

const espNvsFailure = (
  cause: unknown,
  input: InspectEspNvsInput,
  snapshot: StableArtifactSnapshot | undefined,
) => {
  const facts = artifactFilePrimaryFacts(cause);
  const primary = classifyProviderFailure(
    facts.cause,
    offlineArtifactFailureDialect(facts, {
      providerId: ESP_NVS_PROVIDER.id,
      operation: OPERATION,
      path: input.path,
      description: "ESP-IDF NVS partition",
      fallbackMessage: "ESP-IDF NVS partition inspection failed.",
      fileSize: (failure) =>
        parseLimitConstraint(
          OPERATION,
          "file-size",
          decodeLimit(
            "esp-nvs",
            failure.message,
            { name: "max_file_bytes", maximum: input.max_file_bytes },
            { cause: failure },
          ),
          {
            retryable: false,
            limit: espNvsBudgetLimit(input.max_file_bytes),
            remediationAction: fileSizeRemediation(input),
          },
        ),
    }),
  );
  return projectStableArtifactFailure(
    cause,
    primary,
    input.path,
    ESP_NVS_PROVIDER.id,
    OPERATION,
    snapshot,
  );
};
