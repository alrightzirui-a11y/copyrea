import {
  isParseLimit,
  parseLimitConstraint,
} from "../../domain/parseFailureAnalysisError.js";
import {
  artifactFilePrimaryFacts,
  projectArtifactCloseFailure,
  projectStableArtifactFailure,
  ArtifactReaderFailure,
  type StableArtifactSnapshot,
  readStableArtifact,
  ArtifactResourceScope,
} from "../../resources/index.js";
import type { DevicetreePort } from "../../ports/binaryDiagnostics/DevicetreePort.js";
import type { ExecutionOptions } from "../../ports/AnalysisProvider.js";
import { AnalysisResourceConstraintError } from "../../domain/analysisErrorCore.js";
import {
  DEVICETREE_READ_BUDGETS,
  devicetreeBudgetLimit,
  type DevicetreeReadBudget,
  type InspectDevicetreeInput,
} from "../../domain/firmware/devicetree.js";
import { err, ok } from "../../domain/result.js";
import { DEVICETREE_PROVIDER } from "../../domain/investigationProviders.js";
import {
  DEVICETREE_DECODED_ALLOWANCE,
  DEVICETREE_DECODED_BYTES,
  DEVICETREE_FORMAT,
  parseDevicetree,
} from "../../domain/firmware/devicetreeParser.js";
import { fixedAllowanceOptions } from "../../domain/fixedAllowanceRemediation.js";
import { classifyProviderFailure } from "../../providers/classifyProviderFailure.js";
import { offlineArtifactFailureDialect } from "../../providers/offlineArtifactFailure.js";

const OPERATION = "inspect_devicetree";

const isReadBudget = (name: string): name is DevicetreeReadBudget =>
  Object.hasOwn(DEVICETREE_READ_BUDGETS, name);

/** The caller-selected budget that stopped inspection, as structured limit and prose. */
const budgetRefusal = (
  parameter: DevicetreeReadBudget,
  input: InspectDevicetreeInput,
) => {
  const selected = input[parameter];
  const { maximum } = DEVICETREE_READ_BUDGETS[parameter];
  return {
    retryable: false as const,
    limit: devicetreeBudgetLimit(parameter, selected),
    remediationAction:
      selected < maximum
        ? `Raise ${parameter} above ${String(selected)}, up to ${String(maximum)}, on the next call, or select a smaller DTB.`
        : `${parameter} is at this operation's maximum of ${String(maximum)}; select a smaller DTB.`,
  };
};

/** Portable parser over one bounded, identity-checked regular file. */
export class DevicetreeProvider implements DevicetreePort {
  readonly identity = DEVICETREE_PROVIDER;
  readonly #resources = new ArtifactResourceScope();

  async close(): Promise<void> {
    try {
      await this.#resources.close();
    } catch (cause: unknown) {
      throw projectArtifactCloseFailure(
        cause,
        DEVICETREE_PROVIDER.id,
        OPERATION,
      );
    }
  }

  async inspect(input: InspectDevicetreeInput, options?: ExecutionOptions) {
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
        const { report } = parseDevicetree(
          snapshot.bytes,
          {
            path: input.path,
            sha256: snapshot.sha256,
            bytes: snapshot.bytes.length,
          },
          input,
        );
        return ok(report);
      });
    } catch (cause) {
      return err(devicetreeFailure(cause, input, snapshot));
    }
  }
}

const devicetreeFailure = (
  cause: unknown,
  input: InspectDevicetreeInput,
  snapshot?: StableArtifactSnapshot,
) => {
  const facts = artifactFilePrimaryFacts(cause);
  return projectStableArtifactFailure(
    cause,
    classifyProviderFailure(
      facts.cause,
      offlineArtifactFailureDialect(facts, {
        operation: OPERATION,
        providerId: DEVICETREE_PROVIDER.id,
        path: input.path,
        description: "devicetree blob",
        fallbackMessage: "devicetree inspection failed.",
        recognise: (failure, origin) => {
          if (isParseLimit(failure, DEVICETREE_FORMAT)) {
            const { name } = failure.failure.limit;
            return isReadBudget(name)
              ? parseLimitConstraint(
                  OPERATION,
                  "capacity",
                  failure,
                  budgetRefusal(name, input),
                )
              : parseLimitConstraint(
                  OPERATION,
                  "memory",
                  failure,
                  fixedAllowanceOptions(
                    DEVICETREE_DECODED_ALLOWANCE,
                    "parser",
                    {
                      limit: DEVICETREE_DECODED_BYTES,
                      unit: "bytes",
                    },
                  ),
                );
          }
          if (
            origin === "owned-or-classified" &&
            failure instanceof ArtifactReaderFailure &&
            failure.reason === "limit"
          )
            return new AnalysisResourceConstraintError(
              OPERATION,
              failure.boundary ?? "memory",
              failure.message,
              { max_file_bytes: input.max_file_bytes },
              { cause: failure, ...budgetRefusal("max_file_bytes", input) },
            );
          return undefined;
        },
      }),
    ),
    input.path,
    DEVICETREE_PROVIDER.id,
    OPERATION,
    snapshot,
  );
};
