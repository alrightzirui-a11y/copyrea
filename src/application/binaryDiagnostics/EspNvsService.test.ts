import { describe, expect, it } from "vitest";
import { EspNvsService } from "./EspNvsService.js";
import { ESP_NVS_PROVIDER } from "../../domain/investigationProviders.js";
import { decodeLimit } from "../../domain/parseFailure.js";
import { parseLimitConstraint } from "../../domain/parseFailureAnalysisError.js";
import { espNvsBudgetLimit } from "../../domain/firmware/espNvs.js";
import { err, ok } from "../../domain/result.js";
import type { EspNvsPort } from "../../ports/binaryDiagnostics/EspNvsPort.js";

describe("EspNvsService", () => {
  it("wraps NVS report in sha256-bound Evidence with partition file-offset-range", async () => {
    const mockPort: EspNvsPort = {
      identity: ESP_NVS_PROVIDER,
      inspect: async (input) =>
        ok({
          artifact: {
            path: input.path,
            sha256: "c".repeat(64),
            bytes: 65536,
          },
          partition_range: {
            start: 36864,
            end: 45056,
            page_count: 2,
            trailing_unaligned_bytes: 0,
          },
          coverage: {
            status: "complete",
            examined_pages: 2,
            retained_entries: 0,
            omitted_entries: 0,
          },
          pages: [],
          namespaces: [],
          entries: [],
          corrupt_entry_count: 0,
          corrupt_or_encrypted_page_count: 0,
          anomalies: [],
          limitations: [],
        }),
    };

    const service = new EspNvsService(mockPort);
    const res = await service.inspect({
      path: "/tmp/flash.bin",
      partition_offset: 36864,
      partition_bytes: 8192,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.value.operation).toBe("inspect_esp_nvs");
    expect(res.value.subject.identity).toMatchObject({
      kind: "file",
      sha256: "c".repeat(64),
    });
    expect(res.value.locations).toEqual([
      { kind: "artifact-path", path: "/tmp/flash.bin" },
      { kind: "file-offset-range", start: 36864, end: 45056 },
    ]);
  });

  it("propagates max_file_bytes refusals with control_kind: parameter", async () => {
    const mockPort: EspNvsPort = {
      identity: ESP_NVS_PROVIDER,
      inspect: async (input) =>
        err(
          parseLimitConstraint(
            "inspect_esp_nvs",
            "file-size",
            decodeLimit("esp-nvs", "File exceeds max_file_bytes", {
              name: "max_file_bytes",
              maximum: input.max_file_bytes,
            }),
            {
              retryable: false,
              limit: espNvsBudgetLimit(input.max_file_bytes),
              remediationAction: "Raise max_file_bytes.",
            },
          ),
        ),
    };
    const service = new EspNvsService(mockPort);
    const res = await service.inspect({
      path: "/tmp/big_flash.bin",
      max_file_bytes: 4096,
    });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.error.limit).toMatchObject({
      control_kind: "parameter",
      parameter: "max_file_bytes",
      effective_value: 4096,
    });
  });
});
