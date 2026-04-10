# nDPI Seeded Vulnerability Report

**Library:** nDPI (ntop Network Deep Packet Inspection Library)
**Branch:** dev
**Purpose:** Fuzzer evaluation — intentionally introduced vulnerabilities for sanitizer-guided fuzzing research.
**Date:** 2026-04-09

> **Note:** These bugs are NOT present in the upstream nDPI codebase.
> They were introduced deliberately to evaluate custom fuzzer effectiveness.

---

## Summary Table

| # | CWE | Type | File (modified line) | Sanitizer | Trigger Input |
|---|-----|------|----------------------|-----------|---------------|
| 1 | CWE-121 | Stack buffer overflow | `src/lib/ndpi_community_id.c:325` | ASan stack-buffer-overflow | IPv6 flow, l4\_proto=TCP, hash\_buf\_len≥32 |
| 2 | CWE-122 | Heap buffer overflow (off-by-one) | `src/lib/ndpi_analyze.c:509` | ASan heap-buffer-overflow | ndpi\_inc\_bin with slot\_id == num\_bins |
| 3 | CWE-121 | Stack buffer overflow (off-by-one) | `src/lib/ndpi_utils.c:5163` | ASan stack-buffer-overflow | src\_len ≥ dst\_len (e.g., haystack ≥ 256 bytes) |
| 4 | CWE-122 | Heap buffer overflow (post-increment) | `src/lib/ndpi_analyze.c:134` | ASan heap-buffer-overflow | num\_values\_array\_len=1, add ≥2 values |
| 5 | CWE-125 | Stack buffer over-read | `src/lib/ndpi_utils.c:4643` | ASan stack-buffer-overflow | input size > 1024 bytes |

---

## Bug 1 — IPv6 Community ID Stack Buffer Overflow

**File:** `src/lib/ndpi_community_id.c`, line 325
**Harness:** `fuzz/fuzz_community_id.cpp`
**Sanitizer:** ASan stack-buffer-overflow
**Seed:** `fuzz/corpus/fuzz_community_id_seed/seed_ipv6_tcp`

### Change

```diff
- u_int8_t comm_buf[40] = { 0 };
+ u_int8_t comm_buf[30] = { 0 };
```

### Description

`ndpi_flowv6_flow_hash` assembles a byte buffer that is hashed to produce the community ID. For an IPv6 flow, the buffer must hold: 2 bytes (seed) + 16 bytes (src IPv6) + 16 bytes (dst IPv6) = 34 bytes written before the finalize call, which appends a further 6 bytes (l4\_proto, pad, src\_port, dst\_port), for a total of 40 bytes. The original declaration `comm_buf[40]` sized the buffer correctly. Reducing it to 30 means that `ndpi_community_id_buf_copy` writes past the array starting when the second IPv6 address is copied (at offset 18, writing through offset 33 — 4 bytes past the 30-byte boundary). The subsequent `ndpi_community_id_finalize_and_compute_hash` writes 6 more bytes even further past the end. This is a classic stack buffer overflow triggered by any IPv6 flow with a transport-layer protocol (TCP, UDP, SCTP, or ICMPv6).

### Trigger Input

```
\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01
\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02
\x40\x00\x00\x50\x00\x50\x00\x06\x01
```

41 bytes total. FuzzedDataProvider reads from the back: byte 40 (`is_ipv6=1`), byte 39 (`l4_proto=6` TCP), bytes 37–38 (`src_port=80`), bytes 35–36 (`dst_port=80`), byte 34 (`icmp_type=0`), byte 33 (`icmp_code=0`), byte 32 (`hash_buf_len=64`). The remaining 32 front bytes become the two IPv6 addresses consumed via `ConsumeBytes(16)` twice.

### Reproduction

```bash
# Using the seed file directly:
./fuzz_community_id fuzz/corpus/fuzz_community_id_seed/seed_ipv6_tcp

# Or with explicit bytes:
printf '\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x40\x00\x00\x50\x00\x50\x00\x06\x01' | ./fuzz_community_id
```

---

## Bug 2 — ndpi\_inc\_bin Heap Buffer Overflow (Off-by-One)

**File:** `src/lib/ndpi_analyze.c`, line 509
**Harness:** `fuzz/fuzz_alg_bins.cpp`
**Sanitizer:** ASan heap-buffer-overflow
**Seed:** `fuzz/corpus/fuzz_alg_bins_seed/seed_oob`

### Change

```diff
- if(slot_id >= b->num_bins) slot_id = b->num_bins - 1;
+ if(slot_id > b->num_bins) slot_id = b->num_bins - 1;
```

### Description

`ndpi_inc_bin` accepts a `slot_id` parameter and is supposed to clamp it to the valid index range `[0, num_bins - 1]`. The original guard used `>=` to catch the case where `slot_id == num_bins` (one past the end). Changing the comparison to `>` allows `slot_id == num_bins` to pass unclamped. The subsequent write `b->u.bins8[slot_id]` (or the equivalent for 16/32/64-bit families) then writes exactly one element past the end of the heap-allocated array, producing a one-element heap buffer overflow. The overflow is deterministically triggered by passing `slot_id` equal to the bin count used during initialization.

### Trigger Input

A 2048-byte seed with `num_bins=1` (2-byte LE value at end), `family=ndpi_bin_family8` (0), `num_iteration=1`, and `slot_id=1` (equal to `num_bins`). The fuzzer minimum-size guard requires at least 2048 bytes of input.

```
<2048 bytes: 'A' repeated except specific bytes at tail>
Byte 2047 = 0x01  (num_bins low byte  → num_bins = 1)
Byte 2046 = 0x00  (num_bins high byte)
Byte 2045 = 0x00  (family = ndpi_bin_family8)
Byte 2044 = 0x01  (num_iteration = 1)
Byte 2043 = 0x01  (slot_id low byte  → slot_id = 1 = num_bins)
Byte 2042 = 0x00  (slot_id high byte)
Bytes 2034-2041   (val = 1, u_int64_t LE)
```

### Reproduction

```bash
./fuzz_alg_bins fuzz/corpus/fuzz_alg_bins_seed/seed_oob
```

---

## Bug 3 — ndpi\_strlcpy Stack Buffer Overflow (Off-by-One)

**File:** `src/lib/ndpi_utils.c`, line 5163
**Harness:** `fuzz/fuzz_alg_memmem.cpp`
**Sanitizer:** ASan stack-buffer-overflow
**Seed:** `fuzz/corpus/fuzz_alg_memmem_seed/seed_strlcpy`

### Change

```diff
- size_t copy_len = ndpi_min(src_len, dst_len - 1);
+ size_t copy_len = ndpi_min(src_len, dst_len);
```

### Description

`ndpi_strlcpy` is meant to copy at most `dst_len - 1` bytes and always null-terminate the destination. The `- 1` reserves one byte in the destination for the null terminator. Removing this reservation means that when `src_len >= dst_len`, `copy_len` equals `dst_len` exactly. The subsequent `memmove(dst, src, dst_len)` fills the entire buffer, and then `dst[dst_len] = '\0'` writes one byte past the end. The fuzzer harness calls `ndpi_strlcpy(dst, h, sizeof(dst), h_len)` with `dst` as a 256-byte stack array; any input providing a haystack of ≥256 bytes triggers the off-by-one write to `dst[256]`.

### Trigger Input

```
<512 bytes of 0xFF> <512 bytes of 0xAA> <6 bytes: 0x01 0x01 0x01 0x01 0x01 0x01>
```

Total 1030 bytes. The 512-byte haystack (all `0xFF`) gives `h_len=512`. The last 6 bytes (back-consumed) include the strlcpy branch selector byte `0x01` (true), causing `ndpi_strlcpy(dst[256], h, 256, 512)` to be called. With the bug, `copy_len=256`, then `dst[256]='\0'` writes one byte past the 256-element stack buffer.

### Reproduction

```bash
./fuzz_alg_memmem fuzz/corpus/fuzz_alg_memmem_seed/seed_strlcpy
```

---

## Bug 4 — ndpi\_data\_add\_value Heap Buffer Overflow (Post-Increment)

**File:** `src/lib/ndpi_analyze.c`, line 134
**Harness:** `fuzz/fuzz_alg_hw_rsi_outliers_da.cpp`
**Sanitizer:** ASan heap-buffer-overflow
**Seed:** `fuzz/corpus/fuzz_alg_hw_rsi_outliers_da_seed/seed_da_oob`

### Change

```diff
- if(++s->next_value_insert_index == s->num_values_array_len)
+ if(s->next_value_insert_index++ == s->num_values_array_len)
```

### Description

`ndpi_data_add_value` writes each incoming value into a circular ring buffer of length `num_values_array_len`, advancing `next_value_insert_index` and wrapping it to zero when it reaches the end. The original pre-increment (`++index`) increments before the comparison, so when `index` would become `num_values_array_len` the wrap triggers immediately. The post-increment change evaluates the old value in the comparison: when `index` is `num_values_array_len - 1` the condition (`old == len`) is false, so the index is left at `num_values_array_len` without wrapping. On the very next call the write `s->values[num_values_array_len]` accesses one element past the end of the heap allocation before the wrap correction fires. For a ring buffer of length 1, the overflow occurs on the second call to `ndpi_data_add_value`.

### Trigger Input

A 1024-byte seed designed so that FuzzedDataProvider (reading from the back) decodes:

```
Byte 1023 = 0x02          (num_values = 2)
Bytes 1022-1019 = values[0] = 1 (u_int32_t LE)
Bytes 1018-1015 = values2[0] = 0
Bytes 1014-1011 = values[1] = 2
Bytes 1010-1007 = values2[1] = 0
Bytes 1006-1005 = num_periods = 0
Byte  1004      = additive_seasonal = 0
Bytes 1003-996  = alpha = 0.0 (double)
Bytes 995-988   = beta  = 0.0
Bytes 987-980   = gamma = 0.0
Bytes 979-976   = significance = 0.0 (float)
Byte  975       = num_learning_values = 1
Byte  974       = max_series_len low  = 1  → max_series_len = 1
Byte  973       = max_series_len high = 0
Byte  972       = ConsumeBool = 1 (true → first path: alloc then loop)
```

`ndpi_alloc_data_analysis(1)` allocates a 1-element `values[]`. Then `ndpi_data_add_value` is called twice: the first call writes `values[0]` (valid) and leaves `next_value_insert_index = 1`; the second call writes `values[1]` — one past the end — before resetting to zero.

### Reproduction

```bash
./fuzz_alg_hw_rsi_outliers_da fuzz/corpus/fuzz_alg_hw_rsi_outliers_da_seed/seed_da_oob
```

---

## Bug 5 — ndpi\_bin2hex Stack Buffer Over-Read

**File:** `src/lib/ndpi_utils.c`, line 4643
**Harness:** `fuzz/fuzz_alg_crc32_md5.c`
**Sanitizer:** ASan stack-buffer-overflow (read)
**Seed:** `fuzz/corpus/fuzz_alg_crc32_md5_seed/seed_bin2hex`

### Change

```diff
- if (out_len < (in_len*2)) {
+ if (out_len < in_len) {
```

### Description

`ndpi_bin2hex` converts a binary buffer to its hexadecimal ASCII representation, writing two output bytes per input byte. The guard `out_len < in_len*2` ensures the output buffer can hold the full hex expansion. Changing the check to `out_len < in_len` only verifies that the output buffer is larger than the raw input — it is unaware that hex expansion doubles the size. When the input is larger than `out_len / 2` but smaller than `out_len`, the check passes and the function fills the 2048-byte stack output buffer and returns `j = in_len * 2`. The caller then passes this inflated length to `ndpi_hex2bin(out2, sizeof(out2), out, len)`, which iterates over `out[0 .. len-1]` = `out[0 .. 2*in_len-1]`. For `in_len = 1025`, this reads `out[2048]` and `out[2049]` — two bytes past the end of the 2048-element stack buffer — causing a stack buffer over-read detected by ASan.

### Trigger Input

```
<1025 bytes of 0xFF>
```

Any 1025-byte input satisfies `in_len = 1025 < out_len = 2048` (so the buggy guard passes) while also satisfying `in_len * 2 = 2050 > out_len` (the overflow condition). The `0xFF` bytes produce a non-trivial hex sequence that exercises the full loop.

### Reproduction

```bash
python3 -c "import sys; sys.stdout.buffer.write(bytes([0xFF]*1025))" | ./fuzz_alg_crc32_md5
# Or with the seed file:
./fuzz_alg_crc32_md5 fuzz/corpus/fuzz_alg_crc32_md5_seed/seed_bin2hex
```

---

## Build Instructions

All harnesses use the libFuzzer interface and must be compiled with Clang:

```bash
cd /path/to/nDPI

# Compile a specific harness (replace NAME with the target):
clang++ -std=c++11 \
  -I src/include \
  -I src/lib/third_party/include \
  -fsanitize=address,undefined \
  -fno-sanitize-recover=all \
  -fsanitize=fuzzer \
  -g -O1 \
  fuzz/NAME_fuzzer.cpp src/lib/*.c \
  -o NAME_fuzzer

# Run with the seed corpus:
./NAME_fuzzer fuzz/corpus/NAME_seed/ -max_total_time=60

# Reproduce with a known trigger:
./NAME_fuzzer fuzz/corpus/NAME_seed/seed_file
```

Available harnesses:

| Harness | Targets |
|---------|---------|
| `fuzz_community_id` | Bug 1 |
| `fuzz_alg_bins` | Bug 2 |
| `fuzz_alg_memmem` | Bug 3 |
| `fuzz_alg_hw_rsi_outliers_da` | Bug 4 |
| `fuzz_alg_crc32_md5` | Bug 5 |

---

## Expected Sanitizer Output

### Bug 1 — Stack buffer overflow (ndpi\_flowv6\_flow\_hash)
```
==XXXXX==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x... pc 0x...
WRITE of size 1 at offset 30 in frame <ndpi_flowv6_flow_hash>
  object 'comm_buf' of size 30
```

### Bug 2 — Heap buffer overflow (ndpi\_inc\_bin)
```
==XXXXX==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
WRITE of size 1 at 0x... thread T0
    #0 ndpi_inc_bin src/lib/ndpi_analyze.c:512
```

### Bug 3 — Stack buffer overflow (ndpi\_strlcpy)
```
==XXXXX==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x...
WRITE of size 1 at offset 256 in frame <LLVMFuzzerTestOneInput>
  object 'dst' of size 256
```

### Bug 4 — Heap buffer overflow (ndpi\_data\_add\_value)
```
==XXXXX==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
WRITE of size 8 at 0x... thread T0
    #0 ndpi_data_add_value src/lib/ndpi_analyze.c:132
```

### Bug 5 — Stack buffer over-read (ndpi\_hex2bin via ndpi\_bin2hex)
```
==XXXXX==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x...
READ of size 1 at offset 2048 in frame <LLVMFuzzerTestOneInput>
  object 'out' of size 2048
```

---

## Build System Integration

### CMakeLists.txt

```cmake
add_fuzzer(fuzz_community_id)
add_fuzzer(fuzz_alg_bins)
add_fuzzer(fuzz_alg_memmem)
add_fuzzer(fuzz_alg_hw_rsi_outliers_da)
add_fuzzer(fuzz_alg_crc32_md5)
```

### Makefile (OSS-Fuzz)

```makefile
all: \
  $(OUT)/fuzz_community_id \
  $(OUT)/fuzz_community_id_seed_corpus.zip \
  $(OUT)/fuzz_community_id.options \
  $(OUT)/fuzz_alg_bins \
  $(OUT)/fuzz_alg_bins_seed_corpus.zip \
  $(OUT)/fuzz_alg_bins.options \
  $(OUT)/fuzz_alg_memmem \
  $(OUT)/fuzz_alg_memmem_seed_corpus.zip \
  $(OUT)/fuzz_alg_memmem.options \
  $(OUT)/fuzz_alg_hw_rsi_outliers_da \
  $(OUT)/fuzz_alg_hw_rsi_outliers_da_seed_corpus.zip \
  $(OUT)/fuzz_alg_hw_rsi_outliers_da.options \
  $(OUT)/fuzz_alg_crc32_md5 \
  $(OUT)/fuzz_alg_crc32_md5_seed_corpus.zip \
  $(OUT)/fuzz_alg_crc32_md5.options
```

---

## Changelog

### 2026-04-09 — Initial bug injection

Added 5 intentional vulnerabilities across 3 source files, created 5 seed corpus directories, and documented all bugs in this report.

| Harness | Seed file | Seed bytes |
|---------|-----------|------------|
| `fuzz_community_id` | `seed_ipv6_tcp` | 41 bytes |
| `fuzz_alg_bins` | `seed_oob` | 2048 bytes |
| `fuzz_alg_memmem` | `seed_strlcpy` | 1030 bytes |
| `fuzz_alg_hw_rsi_outliers_da` | `seed_da_oob` | 1024 bytes |
| `fuzz_alg_crc32_md5` | `seed_bin2hex` | 1025 bytes |

---

*This report documents intentional research vulnerabilities.
The upstream nDPI library does not contain these bugs.*
