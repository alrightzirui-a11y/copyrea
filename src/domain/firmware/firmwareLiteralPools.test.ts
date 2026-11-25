import { describe, expect, it } from "vitest";
import { parseSvdPeripheralSpans } from "./firmwareLiteralPoolRegions.js";
import { scanFirmwareLiteralPools } from "./firmwareLiteralPoolScanner.js";

const SAMPLE_SVD = `<device>
  <name>STM32F4</name>
  <peripherals>
    <peripheral>
      <name>USART1</name>
      <baseAddress>0x40011000</baseAddress>
      <addressBlock>
        <offset>0x0</offset>
        <size>0x400</size>
        <usage>registers</usage>
      </addressBlock>
    </peripheral>
    <peripheral derivedFrom="USART1">
      <name>USART2</name>
      <baseAddress>0x40004400</baseAddress>
    </peripheral>
  </peripherals>
</device>`;

describe("firmwareLiteralPools domain scanner", () => {
  it("decodes Thumb-1 LDR and Thumb-2 LDR.W loads, attributes SCB.VTOR and SVD peripherals, and skips forward pool data words", () => {
    const buf = Buffer.alloc(32, 0x00);
    // 0x00 (0x08000000): Thumb-1 `ldr r0, [pc, #0x10]` -> Align(0x08000004,4)+0x10 = 0x08000014 (off 0x14)
    buf.writeUInt16LE(0x4804, 0x00);
    // 0x02 (0x08000002): Thumb-1 `nop` (`0xbf00`)
    buf.writeUInt16LE(0xbf00, 0x02);
    // 0x04 (0x08000004): Thumb-2 `ldr.w r4, [pc, #0x10]` -> Align(0x08000008,4)+0x10 = 0x08000018 (off 0x18)
    buf.writeUInt16LE(0xf8df, 0x04);
    buf.writeUInt16LE(0x4010, 0x06);
    // 0x08 (0x08000008): Thumb-1 `ldr r1, [pc, #0x10]` -> Align(0x0800000c,4)+0x10 = 0x0800001c (off 0x1c)
    buf.writeUInt16LE(0x4904, 0x08);
    // 0x0a..0x13: `nop` padding
    for (let p = 0x0a; p < 0x14; p += 2) buf.writeUInt16LE(0xbf00, p);
    // Pool slot 0x14: 0xE000ED08 (SCB.VTOR)
    buf.writeUInt32LE(0xe000_ed08, 0x14);
    // Pool slot 0x18: 0x40011004 (USART1 + 0x4)
    buf.writeUInt32LE(0x4001_1004, 0x18);
    // Pool slot 0x1c: 0x40004804 -> wait, USART2 is 0x40004400..0x40004800, so use 0x40004404!
    // Notice 0x40004804 low halfword `0x4804` looks like `ldr r0, [pc, #0x10]`, so let's put `0x40004800`?
    // Even better: 0x40004404 is inside USART2; let's test `0x40004801` or `0x40004404`!
    // Wait: `0x40004404` -> low halfword `0x4404`, high halfword `0x4000`. What about `0x48014404`? No, `0x40004800`.. let's use `0x4000440c`!
    buf.writeUInt32LE(0x4000_440c, 0x1c);

    const svd = parseSvdPeripheralSpans(SAMPLE_SVD);
    expect(svd.ok).toBe(true);
    if (!svd.ok) return;

    const res = scanFirmwareLiteralPools({
      artifact: {
        path: "/tmp/fw.bin",
        sha256: "a".repeat(64),
        bytes: buf.length,
      },
      fileBytes: buf,
      isa: "arm-thumb",
      baseAddressHex: "0x08000000",
      scanOffset: 0,
      maxScanBytes: 64,
      maxReferences: 16,
      svdSupplied: true,
      svdPeripherals: svd.value,
    });

    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.value.counts.resolved_pool_loads).toBe(3);
    expect(res.value.counts.mmio_pool_loads).toBe(3);
    expect(res.value.svd_profile.matched_load_count).toBe(2);
    expect(res.value.references[0]).toMatchObject({
      instruction_address: "0x8000000",
      mnemonic: "ldr",
      target_register: "r0",
      loaded_value: "0xe000ed08",
      region_kind: "cortex_m_ppb_scs",
      architectural_block: "SCB.VTOR",
    });
    expect(res.value.references[1]).toMatchObject({
      instruction_address: "0x8000004",
      mnemonic: "ldr.w",
      target_register: "r4",
      loaded_value: "0x40011004",
      region_kind: "cortex_m_peripheral",
      basis: "explicit_profile",
      svd_peripheral: "USART1",
      svd_register_offset: "0x4",
    });
    expect(res.value.references[2]).toMatchObject({
      instruction_address: "0x8000008",
      svd_peripheral: "USART2",
      svd_register_offset: "0xc",
    });
  });

  it("decodes ARM A32 conditional LDR literal and Xtensa L32R across 16-bit narrow framing while suppressing pool-slot overlaps", () => {
    // ARM A32: 0x00 `ldreq r2, [pc, #0x0]` -> PC+8 = 0x08 -> loads 0x40020010
    const a32 = Buffer.alloc(12, 0x00);
    a32.writeUInt32LE(0x059f_2000, 0x00);
    a32.writeUInt32LE(0xe1a0_0000, 0x04); // nop
    a32.writeUInt32LE(0x4002_0010, 0x08);

    const a32Res = scanFirmwareLiteralPools({
      artifact: {
        path: "/tmp/a32.bin",
        sha256: "b".repeat(64),
        bytes: a32.length,
      },
      fileBytes: a32,
      isa: "arm-a32",
      baseAddressHex: "0x00000000",
      scanOffset: 0,
      maxScanBytes: 64,
      maxReferences: 16,
      svdSupplied: false,
      svdPeripherals: [],
    });
    expect(a32Res.ok).toBe(true);
    if (!a32Res.ok) return;
    expect(a32Res.value.references).toHaveLength(1);
    expect(a32Res.value.references[0]).toMatchObject({
      disassembly: "ldreq r2, [pc, #0x0]",
      loaded_value: "0x40020010",
      region_kind: "cortex_m_peripheral",
    });

    // Xtensa:
    // 0x00..0x04: pre-function literal pool slot 0 (0x400d0000): 0x3ff44004 (ESP32 GPIO_OUT_REG)
    // 0x04..0x08: pre-function literal pool slot 1 (0x400d0004): crafted ESP32 address 0x3fffff01 whose low 3 bytes `01 ff ff`
    //             look like `l32r a0, -1` targeting 0x400d0000! Must be suppressed because real code at 0x0d loads slot 0x04!
    // 0x08..0x0a: 16-bit narrow `mov.n a2, a3` (`0x0d, 0x23`)
    // 0x0a..0x0d: 24-bit `l32r a4, 0x400d0000`: insnAddr=0x400d000a -> Align(PC+3,4)=0x400d000c -> delta=-12=-3 words -> offset16=0xfffd
    // 0x0d..0x10: 24-bit `l32r a5, 0x400d0004`: insnAddr=0x400d000d -> Align(PC+3,4)=0x400d0010 -> delta=-12=-3 words -> offset16=0xfffd
    const xtensa = Buffer.alloc(16, 0x00);
    xtensa.writeUInt32LE(0x3ff4_4004, 0x00);
    xtensa.writeUInt32LE(0x3fff_ff01, 0x04);
    xtensa[0x08] = 0x0d;
    xtensa[0x09] = 0x23;
    xtensa[0x0a] = 0x41; // at=a4, op0=1
    xtensa[0x0b] = 0xfd;
    xtensa[0x0c] = 0xff;
    xtensa[0x0d] = 0x51; // at=a5, op0=1
    xtensa[0x0e] = 0xfd;
    xtensa[0x0f] = 0xff;

    const xtRes = scanFirmwareLiteralPools({
      artifact: {
        path: "/tmp/esp32_irom.bin",
        sha256: "c".repeat(64),
        bytes: xtensa.length,
      },
      fileBytes: xtensa,
      isa: "xtensa",
      baseAddressHex: "0x400d0000",
      scanOffset: 0,
      maxScanBytes: 64,
      maxReferences: 1,
      svdSupplied: false,
      svdPeripherals: [],
    });
    expect(xtRes.ok).toBe(true);
    if (!xtRes.ok) return;
    expect(xtRes.value.counts.suppressed_pool_slot_overlaps).toBe(1);
    expect(xtRes.value.counts.resolved_pool_loads).toBe(2);
    expect(xtRes.value.coverage).toMatchObject({
      status: "partial",
      retained_references: 1,
      omitted_references: 1,
    });
    expect(xtRes.value.references[0]).toMatchObject({
      instruction_address: "0x400d000a",
      mnemonic: "l32r",
      target_register: "a4",
      pool_address: "0x400d0000",
      loaded_value: "0x3ff44004",
      region_kind: "esp_peripheral",
    });
  });
});
