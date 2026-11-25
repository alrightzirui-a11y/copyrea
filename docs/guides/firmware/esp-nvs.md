# ESP-IDF Non-Volatile Storage (NVS) partitions

`inspect_esp_nvs` (`rea inspect-esp-nvs`) decodes ESP-IDF v1 and v2 Non-Volatile
Storage (NVS) flash partitions directly from either a carved `nvs.bin` file or a
4096-byte aligned slice of a raw ESP32/ESP8266 SPI flash dump without executing
target code.

## When to use it

When `inspect_artifact` on an `esp-flash-image` dump reports a `data/nvs`
partition (typically at `0x9000`), use `inspect_esp_nvs` to inspect its
persisted configuration state:

- Verify 4096-byte NVS page headers (`empty`, `active`, `full`, `freeing`, or
  `corrupt_or_encrypted`), sequence numbers, v1/v2 format markers, and 2-bit
  slot state bitmaps (`empty`, `written`, `erased`).
- Reconstruct namespace tables (`ns_index = 0`), primitive integer settings
  (`u8`..`u64`, `i8`..`i64`), UTF-8 strings (`sz`), v1 single-page blobs, and v2
  multi-chunk `BLOB_IDX` + `BLOB_DATA` payloads with SHA-256 digests and bounded
  hex previews.
- Verify ESP-IDF `esp_rom_crc32_le(0xFFFFFFFF, ...)` checksums on every page
  header, 32-byte item header, and variable-length payload.

## CLI and MCP usage

```bash
# Standalone carved NVS partition
rea inspect-esp-nvs partitions/nvs.bin

# Directly inside a full ESP32 flash dump (offset 0x9000 = 36864, size 0x6000 = 24576)
rea inspect-esp-nvs esp32_flash.bin --partition-offset 36864 --partition-bytes 24576
```

## Provenance and limitations

- Stored keys and values are preserved verbatim as local artifact observations.
- XTS-AES encrypted NVS partitions are not decrypted; encrypted pages fail
  header CRC32 verification and are reported as `state: "corrupt_or_encrypted"`
  with `coverage.status: "partial"`.
- Orphan `BLOB_DATA` chunks without a matching `BLOB_IDX` record are surfaced
  with `data_type: "blob_data_orphan"` and `completeness: "missing_chunks"`.
