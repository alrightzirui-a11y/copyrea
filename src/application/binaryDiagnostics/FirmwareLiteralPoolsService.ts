import { sha256Hex } from "../../kernel/sha256Hex.js";
import type { ExecutionOptions } from "../../ports/AnalysisProvider.js";
import type { FirmwareLiteralPoolsPort } from "../../ports/binaryDiagnostics/FirmwareLiteralPoolsPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  firmwareLiteralPoolsReportSchema,
  inspectFirmwareLiteralPoolsInputSchema,
  type FirmwareLiteralPoolsReport,
  type InspectFirmwareLiteralPoolsInput,
} from "../../domain/firmware/firmwareLiteralPools.js";
import type { Result } from "../../domain/result.js";
import { executeArtifactInspection } from "../ArtifactInspectionExecution.js";

const OPERATION = "inspect_firmware_literal_pools";

const validLiteralPoolsReport = (
  report: FirmwareLiteralPoolsReport,
  input: InspectFirmwareLiteralPoolsInput,
): boolean => {
  if (report.artifact.path !== input.path) return false;
  if (report.isa !== input.isa) return false;
  if (report.references.length > input.max_references) return false;
  if (report.scan_range.scanned_bytes > input.max_scan_bytes) return false;
  if (report.scan_range.end > report.artifact.bytes) return false;
  return true;
};

/** Shared caller validation, output parsing, and Evidence provenance for CLI/MCP. */
export class FirmwareLiteralPoolsService {
  constructor(readonly provider: FirmwareLiteralPoolsPort) {}

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
        inputSchema: inspectFirmwareLiteralPoolsInputSchema,
        outputSchema: firmwareLiteralPoolsReportSchema,
        provider: this.provider,
        retainCompletedReport: true,
        invalidOutputMessage:
          "Firmware literal-pools provider returned malformed output or mismatched artifact identity.",
        toParameters: (input) => input,
        validateReport: validLiteralPoolsReport,
        buildEvidence: (value, identity, parameters) => {
          const { svd_xml, ...restParams } = parameters;
          const evidenceParams =
            svd_xml === undefined
              ? restParams
              : {
                  ...restParams,
                  svd_xml_sha256: sha256Hex(svd_xml),
                };
          return createEvidence(
            {
              path: value.artifact.path,
              format: "file",
              sha256: value.artifact.sha256,
            },
            identity,
            {
              operation: OPERATION,
              parameters: evidenceParams,
              result: value,
              confidence: "derived",
              limitations: value.limitations,
              locations: [
                { kind: "artifact-path", path: value.artifact.path },
                {
                  kind: "file-offset-range",
                  start: value.scan_range.start,
                  end: value.scan_range.end,
                },
              ],
            },
          );
        },
      },
      rawInput,
      options,
    );
  }
}
