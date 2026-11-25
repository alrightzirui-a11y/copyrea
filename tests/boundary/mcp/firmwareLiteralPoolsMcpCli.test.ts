import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { describe, expect, it, onTestFinished } from "vitest";
import { createCli } from "../../../src/cli.js";
import { silentLogger } from "../../../src/logger.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { createMcpSchemaValidation } from "../../fixtures/mcpSchemaValidation.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const MINI_SVD = `<device>
  <name>STM32F103</name>
  <peripherals>
    <peripheral>
      <name>GPIOA</name>
      <baseAddress>0x40010800</baseAddress>
      <addressBlock>
        <offset>0x0</offset>
        <size>0x400</size>
        <usage>registers</usage>
      </addressBlock>
    </peripheral>
  </peripherals>
</device>`;

describe("inspect_firmware_literal_pools CLI and MCP parity", () => {
  it("disassembles Thumb literal-pool MMIO loads with CLI and advertised MCP parity", async () => {
    const dir = await createTestTempDirectory("rea-literal-pools-");
    const fwPath = join(dir, "stm32.bin");
    const image = Buffer.alloc(24, 0x00);
    // 0x00: `ldr r0, [pc, #0x08]` -> Align(0x08000004,4)+8 = 0x0800000c (off 0x0c) -> SCB.VTOR (0xe000ed08)
    image.writeUInt16LE(0x4802, 0x00);
    // 0x02: `ldr r1, [pc, #0x0c]` -> Align(0x08000006,4)+12 = 0x08000010 (off 0x10) -> GPIOA_ODR (0x4001080c)
    image.writeUInt16LE(0x4903, 0x02);
    for (let p = 0x04; p < 0x0c; p += 2) image.writeUInt16LE(0xbf00, p);
    image.writeUInt32LE(0xe000_ed08, 0x0c);
    image.writeUInt32LE(0x4001_080c, 0x10);
    await writeFile(fwPath, image);

    const session = createTestBinarySession(() => {
      throw new Error("No deep provider should start");
    });
    const server = createServer(
      { kind: "session", session },
      { environment: {}, logger: silentLogger },
    );
    const client = new Client(
      { name: "firmware-literal-pools-test", version: "1" },
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
      name: "inspect_firmware_literal_pools",
      arguments: {
        path: fwPath,
        isa: "arm-thumb",
        base_address: "0x08000000",
        svd_xml: MINI_SVD,
      },
    });
    expect(mcpRes.isError).not.toBe(true);
    const mcpStructured = mcpRes.structuredContent as {
      normalized_result: {
        references: {
          loaded_value: string;
          svd_peripheral: string | null;
          architectural_block: string | null;
        }[];
      };
    };
    expect(mcpStructured.normalized_result.references).toMatchObject([
      {
        loaded_value: "0xe000ed08",
        svd_peripheral: null,
        architectural_block: "SCB.VTOR",
      },
      {
        loaded_value: "0x4001080c",
        svd_peripheral: "GPIOA",
        architectural_block: null,
      },
    ]);

    let cliStdout = "";
    let cliExitCode = 0;
    await createCli({}).serve(
      [
        "inspect-firmware-literal-pools",
        fwPath,
        "--isa",
        "arm-thumb",
        "--base-address",
        "0x08000000",
        "--svd-xml",
        MINI_SVD,
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
