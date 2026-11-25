import { NUGET_NUPKG_PROVIDER_IDENTITY } from "./NugetNupkgProviderIdentity.js";
import {
  ArtifactReaderFailure,
  ArtifactResourceScope,
  artifactFilePrimaryFacts,
  projectArtifactCloseFailure,
  projectStableArtifactFailure,
  translateArtifactFailure,
  withStableArtifactHandle,
} from "../resources/index.js";
import {
  isParseLimit,
  parseLimitConstraint,
} from "../domain/parseFailureAnalysisError.js";
import { decodeLimit } from "../domain/parseFailure.js";
import { fixedCeilingConstraint } from "../domain/analysisErrorCore.js";
import { ArtifactOperationError } from "../domain/artifactOperationError.js";
import {
  NUGET_NUPKG_FORMAT,
  NUGET_NUPKG_READ_BUDGETS,
  nugetNupkgBudgetLimit,
  type InspectNugetNupkgInput,
  type NugetNupkgReadBudget,
} from "../domain/nuget/nupkg.js";
import { err, ok } from "../domain/result.js";
import { errorMessage } from "../kernel/errorMessage.js";
import { classifyProviderFailure } from "../providers/classifyProviderFailure.js";
import { offlineArtifactFailureDialect } from "../providers/offlineArtifactFailure.js";
import { parseNugetNupkg } from "./NugetNupkgParser.js";

const OPERATION = "inspect_nuget_nupkg";

const isReadBudget = (name: string): name is NugetNupkgReadBudget =>
  Object.hasOwn(NUGET_NUPKG_READ_BUDGETS, name);

/** The caller-selected budget that stopped inspection, as structured limit and prose. */
const budgetRefusal = (
  parameter: NugetNupkgReadBudget,
  input: InspectNugetNupkgInput,
) => {
  const selected = input[parameter];
  const { maximum } = NUGET_NUPKG_READ_BUDGETS[parameter];
  return {
    retryable: false as const,
    limit: nugetNupkgBudgetLimit(parameter, selected),
    remediationAction:
      selected >= maximum
        ? `${parameter} is at this operation's maximum of ${String(maximum)}; select a complete artifact within that bound.`
        : `Raise ${parameter} above ${String(selected)}, up to ${String(maximum)}, or select a smaller artifact. The budget applies on the next call; repeating the unchanged request does not raise it.`,
  };
};

const nupkgFailure = (
  cause: unknown,
  input: InspectNugetNupkgInput,
  identity?: { readonly sha256: string; readonly bytes: number },
) => {
  const facts = artifactFilePrimaryFacts(cause);
  const primary = classifyProviderFailure(
    facts.cause,
    offlineArtifactFailureDialect(facts, {
      providerId: NUGET_NUPKG_PROVIDER_IDENTITY.id,
      operation: OPERATION,
      path: input.path,
      description: "NuGet package",
      recognise: (failure, origin) => {
        if (isParseLimit(failure, NUGET_NUPKG_FORMAT)) {
          const { name } = failure.failure.limit;
          return parseLimitConstraint(
            OPERATION,
            name === "max_entries" ? "capacity" : "memory",
            failure,
            {
              path: input.path,
              retryable: false,
              ...(isReadBudget(name) ? budgetRefusal(name, input) : {}),
            },
          );
        }
        if (
          origin === "owned-or-classified" &&
          failure instanceof ArtifactReaderFailure
        ) {
          if (
            failure.reason === "limit" &&
            failure.fixedAllowance !== undefined
          )
            return fixedCeilingConstraint(
              OPERATION,
              failure.boundary ?? "memory",
              failure.message,
              failure.fixedAllowance,
              { cause: failure },
            );
          if (failure.reason === "limit" && failure.boundary === "file-size")
            return undefined;
          if (
            failure.reason !== "path" &&
            failure.reason !== "integrity" &&
            failure.reason !== "cancelled"
          )
            return translateArtifactFailure(OPERATION, input.path, failure);
        }
        return undefined;
      },
      fileSize: (failure) =>
        parseLimitConstraint(
          OPERATION,
          "file-size",
          decodeLimit(
            NUGET_NUPKG_FORMAT,
            failure.message,
            { name: "max_file_bytes", maximum: input.max_file_bytes },
            { cause: failure },
          ),
          budgetRefusal("max_file_bytes", input),
        ),
      unclassified: (failure) =>
        new ArtifactOperationError(
          OPERATION,
          "io",
          undefined,
          errorMessage(failure),
          { cause: failure },
        ),
    }),
  );
  return projectStableArtifactFailure(
    cause,
    primary,
    input.path,
    NUGET_NUPKG_PROVIDER_IDENTITY.id,
    OPERATION,
    identity,
  );
};

/** Portable parser over one bounded, identity-checked regular file. */
export class NugetNupkgProvider {
  readonly identity = NUGET_NUPKG_PROVIDER_IDENTITY;
  readonly #resources = new ArtifactResourceScope();

  async close(): Promise<void> {
    try {
      await this.#resources.close();
    } catch (cause: unknown) {
      throw projectArtifactCloseFailure(
        cause,
        NUGET_NUPKG_PROVIDER_IDENTITY.id,
        OPERATION,
      );
    }
  }

  async inspect(
    input: InspectNugetNupkgInput,
    options?: { readonly signal?: AbortSignal },
  ) {
    let identity:
      | { readonly sha256: string; readonly bytes: number }
      | undefined;
    try {
      return await this.#resources.run(async () =>
        withStableArtifactHandle(
          input.path,
          input.max_file_bytes,
          {
            retainBytes: () => 4,
            signal: options?.signal,
            resourceScope: this.#resources,
            onIdentity: (verified) => {
              identity = verified;
            },
          },
          async ({ prefix, size, sha256, readRange }) =>
            ok(
              await parseNugetNupkg(
                { prefix, size, readRange },
                { path: input.path, sha256, bytes: size },
                input,
                options?.signal,
              ),
            ),
        ),
      );
    } catch (cause) {
      return err(nupkgFailure(cause, input, identity));
    }
  }
}
