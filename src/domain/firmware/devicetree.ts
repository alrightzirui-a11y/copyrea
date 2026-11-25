import { z } from "zod";
import type { AnalysisParameterLimit } from "../analysisSettings.js";
import { digestSchema } from "../digests.js";
import { absoluteLocalPathStringSchema } from "../localPath.js";
const uint = z.number().int().min(0).max(0xffffffff);
export const MAX_DEVICETREE_FILE_BYTES = 16777216;
export const DEVICETREE_PROPERTY_PREVIEW_BYTES = 256;

/** The per-call budgets `inspect_devicetree` accepts, shared by its schema and refusals. */
export const DEVICETREE_READ_BUDGETS = {
  max_file_bytes: {
    minimum: 40,
    maximum: MAX_DEVICETREE_FILE_BYTES,
    default_value: 4194304,
  },
  max_nodes: { minimum: 1, maximum: 65536, default_value: 8192 },
  max_properties: { minimum: 1, maximum: 262144, default_value: 32768 },
  max_depth: { minimum: 1, maximum: 256, default_value: 64 },
} as const;
export type DevicetreeReadBudget = keyof typeof DEVICETREE_READ_BUDGETS;

const budget = (name: DevicetreeReadBudget) => {
  const bounds = DEVICETREE_READ_BUDGETS[name];
  return z
    .number()
    .int()
    .min(bounds.minimum)
    .max(bounds.maximum)
    .default(bounds.default_value);
};

export const inspectDevicetreeInputSchema = z.strictObject({
  path: absoluteLocalPathStringSchema,
  max_file_bytes: budget("max_file_bytes"),
  max_nodes: budget("max_nodes"),
  max_properties: budget("max_properties"),
  max_depth: budget("max_depth"),
});

/**
 * The per-call control that stopped devicetree inspection, named by its
 * contract field; each adapter names the option that sets it. The schema owns
 * the same bounds, so the reported range is the one the next call accepts.
 */
export const devicetreeBudgetLimit = (
  parameter: DevicetreeReadBudget,
  effectiveValue: number,
): AnalysisParameterLimit => ({
  control_kind: "parameter",
  parameter,
  effective_value: effectiveValue,
  unit: parameter === "max_file_bytes" ? "bytes" : "count",
  ...DEVICETREE_READ_BUDGETS[parameter],
  applies_at: "next_call",
});
export const devicetreePropertySchema = z.strictObject({
  name: z.string(),
  offset: uint,
  bytes: uint,
  hex: z
    .string()
    .regex(/^[0-9a-f]*$/)
    .max(DEVICETREE_PROPERTY_PREVIEW_BYTES * 2),
  truncated: z.boolean(),
  derived: z.strictObject({
    confidence: z.literal("derived"),
    strings: z.array(z.string()).nullable(),
    cells: z.array(uint).nullable(),
    reg: z
      .array(
        z.strictObject({
          address: z.string().nullable(),
          size: z.string().nullable(),
        }),
      )
      .nullable(),
  }),
});
export const devicetreeNodeSchema = z.strictObject({
  path: z.string(),
  parent: z.string().nullable(),
  offset: uint,
  properties: z.array(devicetreePropertySchema),
});
export const devicetreeSchema = z
  .strictObject({
    artifact: z.strictObject({
      path: z.string(),
      sha256: digestSchema,
      bytes: uint,
    }),
    header: z.strictObject({
      magic: uint,
      totalsize: uint,
      off_dt_struct: uint,
      off_dt_strings: uint,
      off_mem_rsvmap: uint,
      version: uint,
      last_comp_version: uint,
      boot_cpuid_phys: uint,
      size_dt_strings: uint,
      size_dt_struct: uint.nullable(),
    }),
    reservations: z.array(
      z.strictObject({ offset: uint, address: z.string(), size: z.string() }),
    ),
    nodes: z.array(devicetreeNodeSchema),
    references: z.array(
      z.strictObject({
        source: z.string(),
        property: z.string(),
        phandle: uint,
        target: z.string().nullable(),
        confidence: z.literal("derived"),
      }),
    ),
    summary: z.strictObject({
      confidence: z.literal("derived"),
      compatible: z.array(z.string()).nullable(),
      model: z.string().nullable(),
      bootargs: z.string().nullable(),
      stdout_path: z.string().nullable(),
      aliases: z.array(
        z.strictObject({ name: z.string(), path: z.string().nullable() }),
      ),
    }),
    coverage: z.strictObject({
      status: z.literal("complete"),
      examined_nodes: uint,
      examined_properties: uint,
    }),
    limitations: z.array(z.string()),
  })
  .superRefine((report, context) => {
    const invalid = (path: (string | number)[], message: string) =>
      context.addIssue({ code: "custom", path, message });
    const { totalsize } = report.header;
    if (totalsize > report.artifact.bytes)
      return invalid(
        ["header", "totalsize"],
        "The Devicetree extent exceeds the selected artifact.",
      );
    if (report.coverage.examined_nodes !== report.nodes.length)
      return invalid(
        ["coverage", "examined_nodes"],
        "Examined node count disagrees with the listed nodes.",
      );

    const paths = new Set<string>();
    let properties = 0;
    for (const [index, node] of report.nodes.entries()) {
      if (paths.has(node.path))
        return invalid(
          ["nodes", index, "path"],
          "Duplicate Devicetree node path.",
        );
      if (node.parent !== null && !paths.has(node.parent))
        return invalid(
          ["nodes", index, "parent"],
          "The parent must precede its child in the recorded walk.",
        );
      if (node.offset >= totalsize)
        return invalid(
          ["nodes", index, "offset"],
          "The node starts outside the declared Devicetree extent.",
        );
      paths.add(node.path);
      properties += node.properties.length;
      for (const [propertyIndex, property] of node.properties.entries()) {
        if (property.offset > totalsize - property.bytes)
          return invalid(
            ["nodes", index, "properties", propertyIndex, "offset"],
            "The property range exceeds the declared Devicetree extent.",
          );
        const previewBytes = Math.min(
          property.bytes,
          DEVICETREE_PROPERTY_PREVIEW_BYTES,
        );
        if (property.hex.length !== previewBytes * 2)
          return invalid(
            ["nodes", index, "properties", propertyIndex, "hex"],
            "The property preview does not match its admitted byte count.",
          );
        if (property.truncated !== property.bytes > previewBytes)
          return invalid(
            ["nodes", index, "properties", propertyIndex, "truncated"],
            "The truncation flag disagrees with the property preview extent.",
          );
      }
    }
    if (report.coverage.examined_properties !== properties)
      return invalid(
        ["coverage", "examined_properties"],
        "Examined property count disagrees with the listed properties.",
      );
    const outside = report.reservations.findIndex(
      ({ offset }) => offset > totalsize - 16,
    );
    if (outside !== -1)
      invalid(
        ["reservations", outside, "offset"],
        "The reservation record exceeds the declared Devicetree extent.",
      );
  });
export type Devicetree = z.infer<typeof devicetreeSchema>;
export type InspectDevicetreeInput = z.infer<
  typeof inspectDevicetreeInputSchema
>;
