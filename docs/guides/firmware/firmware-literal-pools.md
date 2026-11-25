# Firmware literal-pool MMIO disassembly

Fixed-width 16-, 24-, and 32-bit embedded instruction sets—ARM Thumb/Thumb-2, ARM A32, and Espressif Xtensa LX106/LX6/LX7—cannot encode arbitrary 32-bit peripheral MMIO addresses (`0x40000000..0x5FFFFFFF`, `0xE000E000`, `0x3FF00000..0x3FF7FFFF`) inside a single immediate instruction. Compilers emit PC-relative literal-pool loads (`LDR Rt, [PC, #imm]`, `LDR.W Rt, [PC, #+-imm12]`, `L32R ar, slot`) that fetch 32-bit constants embedded in `.text` or `.irom0.text`.

`inspect_firmware_literal_pools` (`rea inspect-firmware-literal-pools`) disassembles those PC-relative loads directly from a local firmware image or carved code slice at a caller-selected `base_address` without requiring an external disassembler or executing target code.

## Supported instruction encodings

| `isa`       | Decoded PC-relative load instructions                                                                    | Alignment & framing                                                                                                                            |
| ----------- | -------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `arm-thumb` | 16-bit Thumb `LDR Rt, [PC, #imm8*4]` and 32-bit Thumb-2 `LDR.W Rt, [PC, #+-imm12]` at `Align(PC + 4, 4)` | 2-byte aligned `base_address` and `scan_offset`; steps 2 bytes for 16-bit instructions and 4 bytes for Thumb-2 prefixes (`>= 0xE800`).         |
| `arm-a32`   | Conditional and unconditional 32-bit `LDR<c> Rd, [PC, #+-imm12]` at `(PC + 8) +- imm12`                  | 4-byte aligned `base_address` and `scan_offset`.                                                                                               |
| `xtensa`    | 24-bit `L32R ar, offset16` at `Align(PC + 3, 4) + (offset16 - 0x10000) * 4`                              | Mixed 16-bit narrow (`op0` in `0x8..0xD`) and 24-bit instruction framing; suppresses backward pool-slot data words from false `L32R` decoding. |

## CLI and MCP usage

```bash
rea inspect-firmware-literal-pools /path/to/stm32_app.bin \
  --isa arm-thumb \
  --base-address 0x08000000
```

Supply `--svd-xml` (or `svd_xml` in MCP) to attribute loaded peripheral addresses to named CMSIS-SVD `<peripheral>` blocks (`<baseAddress>`, `<addressBlock>`, and `derivedFrom` spans):

```json
{
  "path": "/path/to/stm32_app.bin",
  "isa": "arm-thumb",
  "base_address": "0x08000000",
  "scan_offset": 512,
  "max_scan_bytes": 262144,
  "svd_xml": "<device>...</device>"
}
```

## Provenance and attribution basis

Every resolved literal-pool load distinguishes how its target region was established:

- `explicit_profile`: matched a `<peripheral>` span in caller-supplied `svd_xml` (`svd_peripheral` and `svd_register_offset` populated; Evidence records `svd_xml_sha256` without duplicating the full XML payload).
- `architecture_manual`: matched an architecturally fixed ARMv6-M/v7-M/v8-M Private Peripheral Bus / System Control Space block (`SCB.VTOR`, `SCB.AIRCR`, `SCB.CPACR`, `SCB`, `SysTick`, `NVIC`, `MPU`, `DWT`, `FPB`).
- `address_map_convention`: matched standard Cortex-M peripheral (`0x40000000..0x5FFFFFFF`), Cortex-M SRAM (`0x20000000..0x3FFFFFFF`), Espressif peripheral (`0x3FF00000..0x3FF7FFFF` / `0x60000000..0x600FFFFF`), or Espressif SRAM/RTC (`0x3FF80000..0x3FFFFFFF`) ranges.
- `observed_bounds`: pointed back into `[base_address, base_address + file_bytes)` (clearing Thumb bit 0 for `arm-thumb`).
- `unclassified`: constant did not match a known MMIO range or mapped image span.

## Limits and limitations

- Linear instruction scanning without control-flow recovery can traverse inline non-pool data tables (such as switch jump tables or embedded strings); referenced 32-bit pool words inside the image are suppressed from instruction decoding (`counts.suppressed_pool_slot_overlaps`).
- `max_scan_bytes` (default `1048576`, maximum `16777216`) bounds scanned instruction bytes from `scan_offset`; `max_references` (default `512`, maximum `4096`) bounds inline `references` while `mmio_summary` and `counts` reflect every scanned byte (`coverage.status: "partial"` when truncated).
- `max_file_bytes` (default `33554432`, maximum `67108864`) and `svd_xml` (`200000` XML nodes) report typed `details.limit` (`control_kind: "parameter"`) on refusal.
