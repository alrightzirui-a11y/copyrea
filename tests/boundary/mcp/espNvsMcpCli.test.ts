import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { describe, expect, it, onTestFinished } from "vitest";
import { createCli } from "../../../src/cli.js";
import {
  computeNvsItemHeaderCrc,
  espIdfCrc32,
} from "../../../src/domain/firmware/espNvsItemDecoder.js";
import { silentLogger } from "../../../src/logger.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { createMcpSchemaValidation } from "../../fixtures/mcpSchemaValidation.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

describe("inspect_esp_nvs CLI and MCP parity", () => {
  it("decodes an NVS slice inside a flash dump with CLI and advertised MCP parity", async () => {
    const dir = await createTestTempDirectory("rea-esp-nvs-");
    const flashPath = join(dir, "esp32.bin");
    const prefix = Buffer.alloc(4096, 0xff);
    const page = Buffer.alloc(4096, 0xff);
    page.writeUInt32LE(0xffff_fffe, 0);
    page.writeUInt32LE(1, 4);
    page[8] = 0xfe;
    page.writeUInt32LE(espIdfCrc32(page.subarray(4, 28)), 28);

    // Slot 0: namespace "cfg" -> id 1
    const s0 = page.subarray(64, 96);
    s0.fill(0xff);
    s0[0] = 0;
    s0[1] = 0x01;
    s0[2] = 1;
    s0[3] = 0xff;
    s0.fill(0, 8, 24);
    Buffer.from("cfg", "utf8").copy(s0, 8);
    s0[24] = 1;
    s0.writeUInt32LE(computeNvsItemHeaderCrc(s0), 4);

    // Slot 1: u16 "baud" = 11520 => u32 "baud" = 115200
    const s1 = page.subarray(96, 128);
    s1.fill(0xff);
    s1[0] = 1;
    s1[1] = 0x04;
    s1[2] = 1;
    s1[3] = 0xff;
    s1.fill(0, 8, 24);
    Buffer.from("baud", "utf8").copy(s1, 8);
    s1.writeUInt32LE(115200, 24);
    s1.writeUInt32LE(computeNvsItemHeaderCrc(s1), 4);

    // Mark slots 0 and 1 WRITTEN (0b1010_1111 = 0xfa -> slot0 bits 1:0=10, slot1 bits 3:2=10 => 0xf0 | 0b1010 = 0xfa)
    page[32] = 0xfa;

    await writeFile(flashPath, Buffer.concat([prefix, page]));

    const session = createTestBinarySession(() => {
      throw new Error("No deep provider should start");
    });
    const server = createServer(
      { kind: "session", session },
      { environment: {}, logger: silentLogger },
    );
    const client = new Client(
      { name: "esp-nvs-test", version: "1" },
      { jsonSchemaValidator: createMcpSchemaValidation() },
    );
    onTestFinished(async () => {
      await client.close();
      await server.close();
      await session.close();
    });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const mcpRes = await client.callTool({
      name: "inspect_esp_nvs",
      arguments: {
        path: flashPath,
        partition_offset: 4096,
        partition_bytes: 4096,
      },
    });
    expect(mcpRes.isError).not.toBe(true);
    const mcpStructured = mcpRes.structuredContent as {
      normalized_result: {
        entries: {
          namespace: string | null;
          key: string;
          value_integer: string | null;
        }[];
      };
    };
    expect(mcpStructured.normalized_result.entries).toMatchObject([
      { namespace: "cfg", key: "baud", value_integer: "115200" },
    ]);

    let cliStdout = "";
    let cliExitCode = 0;
    await createCli({}).serve(
      [
        "inspect-esp-nvs",
        flashPath,
        "--partition-offset",
        "4096",
        "--partition-bytes",
        "4096",
        "--format",
        "json",
      ],
      {
        env: {},
        exit: (code) => {
          cliExitCode = code;
        },
        stdout: (chunk) => {
          cliStdout += chunk;
        },
      },
    );
    expect(cliExitCode).toBe(0);
    const cliParsed = JSON.parse(cliStdout) as {
      normalized_result: typeof mcpStructured.normalized_result;
    };
    expect(cliParsed.normalized_result).toEqual(
      mcpStructured.normalized_result,
    );
  });
});
