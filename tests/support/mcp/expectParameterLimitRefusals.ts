import type { Client } from "@modelcontextprotocol/client";
import { expect } from "vitest";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";

/** One per-call budget, the value that refuses the fixture, and its published range. */
export interface ExpectedParameterLimit {
  readonly resource: string;
  readonly value: number;
  readonly minimum: number;
  readonly maximum: number;
  readonly default_value: number;
  readonly unit: "bytes" | "count";
}

/**
 * Call `tool` once per budget with that budget set to `value` and assert the
 * refusal names it as a structured `details.limit` with the expected range.
 */
export const expectParameterLimitRefusals = async (
  client: Pick<Client, "callTool">,
  tool: string,
  path: string,
  expected: Readonly<Record<string, ExpectedParameterLimit>>,
): Promise<void> => {
  for (const [parameter, bounds] of Object.entries(expected)) {
    const response = await client.callTool({
      name: tool,
      arguments: { path, [parameter]: bounds.value },
    });
    const { error } = parseMcpToolError(response);
    expect(error, parameter).toMatchObject({
      code: "resource_constraint",
      retryable: false,
      details: {
        resource: bounds.resource,
        limit: {
          control_kind: "parameter",
          parameter,
          effective_value: bounds.value,
          unit: bounds.unit,
          minimum: bounds.minimum,
          maximum: bounds.maximum,
          default_value: bounds.default_value,
          applies_at: "next_call",
        },
      },
    });
  }
};
