import type { ExecutionOptions } from "../../ports/AnalysisProvider.js";
import type { EspNvsPort } from "../../ports/binaryDiagnostics/EspNvsPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  espNvsReportSchema,
  inspectEspNvsInputSchema,
  type EspNvsReport,
  type InspectEspNvsInput,
} from "../../domain/firmware/espNvs.js";
import type { Result } from "../../domain/result.js";
import { executeArtifactInspection } from "../ArtifactInspectionExecution.js";

const OPERATION = "inspect_esp_nvs";

const validNvsReport = (
  report: EspNvsReport,
  input: InspectEspNvsInput,
): boolean => {
  if (report.artifact.path !== input.path) return false;
  if (report.partition_range.start !== input.partition_offset) return false;
  if (report.partition_range.end > report.artifact.bytes) return false;
  if (report.entries.length > input.max_entries) return false;
  return true;
};

/** Shared caller validation, output parsing, and Evidence provenance for CLI/MCP. */
export class EspNvsService {
  constructor(readonly provider: EspNvsPort) {}

  close(): Promise<void> {
    return this.provider.close?.() ?? Promise.resolve();
  }

  inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    return executeArtifactInspection(
      {
        operation: OPERATION,
        inputSchema: inspectEspNvsInputSchema,
        outputSchema: espNvsReportSchema,
        provider: this.provider,
        retainCompletedReport: true,
        invalidOutputMessage:
          "ESP-IDF NVS provider returned malformed output or mismatched artifact identity.",
        toParameters: (input) => input,
        validateReport: validNvsReport,
        buildEvidence: (value, identity, parameters) =>
          createEvidence(
            {
              path: value.artifact.path,
              format: "file",
              sha256: value.artifact.sha256,
            },
            identity,
            {
              operation: OPERATION,
              parameters,
              result: value,
              confidence: "observed",
              limitations: value.limitations,
              locations: [
                { kind: "artifact-path", path: value.artifact.path },
                {
                  kind: "file-offset-range",
                  start: value.partition_range.start,
                  end: value.partition_range.end,
                },
              ],
            },
          ),
      },
      rawInput,
      options,
    );
  }
}
