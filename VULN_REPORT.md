# nDPI Seeded Vulnerability Report

**Library:** nDPI (ntop Network Deep Packet Inspection Library)
**Branch:** dev
**Purpose:** Fuzzer evaluation — intentionally introduced vulnerabilities for sanitizer-guided fuzzing research.
**Date:** 2026-04-11 (updated; original 2026-04-09)

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
| 6 | CWE-190 | Signed integer overflow | `src/lib/ndpi_analyze.c:145` | UBSan signed-integer-overflow | value > sqrt(INT64\_MAX) ≈ 3,037,000,499 |
| 7 | CWE-415 | Double-free | `src/lib/ndpi_analyze.c:1216` | ASan heap-double-free | num\_values ≥ num\_periods+2 to trigger HW transition then hw\_free |
| 8 | CWE-121 | Stack buffer overflow (off-by-one) | `src/lib/ndpi_utils.c:4933` | ASan stack-buffer-overflow | haystack ≥ 2048 bytes with all bytes ≥ 0x80 |
| 9 | CWE-401 | Memory leak | `src/lib/ndpi_analyze.c:974` | LSan memory-leak | any valid ndpi\_cluster\_bins call |
| 10 | CWE-190 | Shift exponent overflow | `src/lib/third_party/src/hll/hll.c:85` | UBSan shift-base-exponent | bits = 31 |
| 11 | CWE-122 | Heap buffer overflow (off-by-one) | `src/lib/ndpi_analyze.c:2011` | ASan heap-buffer-overflow | element with bit N set where N = log2(num\_hashes\*1024) |
| 12 | CWE-908 | Use of uninitialized memory | `src/lib/ndpi_analyze.c:996` | MSan uninitialized-value | num\_learning\_values ≥ 2, add ≥ 2 RSI values |
| 13 | CWE-369 | Divide by zero | `src/lib/ndpi_analyze.c:581,587` | UBSan integer-divide-by-zero | ndpi\_bin\_family8 bin with all-zero values |
| 14 | CWE-416 | Use-after-free | `src/lib/ndpi_analyze.c:967` | ASan heap-use-after-free | any ndpi\_cluster\_bins call with centroids=NULL |
| 15 | CWE-122 | Heap buffer overflow (undersized realloc) | `src/lib/ndpi_serializer.c:283` | ASan heap-buffer-overflow | serializer buffer extension with any min\_len ≥ 2 |

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

## Bug 6 — ndpi\_data\_add\_value Signed Integer Overflow

**File:** `src/lib/ndpi_analyze.c`, line 145
**Harness:** `fuzz/fuzz_alg_hw_rsi_outliers_da.cpp`
**Sanitizer:** UBSan signed-integer-overflow
**Seed:** `fuzz/corpus/fuzz_alg_hw_rsi_outliers_da_seed/seed_signed_overflow`

### Change

```diff
- s->stddev.sum_square_total += (u_int64_t)value * (u_int64_t)value;
+ s->stddev.sum_square_total += (int64_t)value * (int64_t)value;
```

### Description

`ndpi_data_add_value` accumulates `value²` into `sum_square_total` to support an online standard-deviation calculation. The original cast `(u_int64_t)value * (u_int64_t)value` keeps the multiplication in unsigned 64-bit space, where wrapping is defined. Changing the casts to `int64_t` makes the multiplication signed. When `value > sqrt(INT64_MAX) ≈ 3,037,000,499`, the product exceeds `INT64_MAX = 9,223,372,036,854,775,807`, which is undefined behavior under C's signed-integer rules. For `value = 0xFFFFFFFF = 4,294,967,295`, the product is approximately `1.844×10¹⁹`, well past the signed 64-bit limit. UBSan catches this at the `*` operator before the result is stored.

### Trigger Input

1024-byte seed. FuzzedDataProvider reads from the back:
```
Byte 1023 = 0x01          (num_values = 1)
Bytes 1022-1019 = 0xFFFFFFFF  (values[0] = 4294967295)
...
Byte 983  = 0x00          (num_learning_values = 0, RSI disabled)
Bytes 982-981 = 0x0001    (max_series_len = 1)
Byte 980  = 0x01          (ConsumeBool → ndpi_alloc_data_analysis path)
```

### Reproduction

```bash
./fuzz_alg_hw_rsi_outliers_da fuzz/corpus/fuzz_alg_hw_rsi_outliers_da_seed/seed_signed_overflow
```

---

## Bug 7 — ndpi\_hw\_add\_value Double-Free (Missing NULL after free)

**File:** `src/lib/ndpi_analyze.c`, line 1216
**Harness:** `fuzz/fuzz_alg_hw_rsi_outliers_da.cpp`
**Sanitizer:** ASan heap-double-free
**Seed:** `fuzz/corpus/fuzz_alg_hw_rsi_outliers_da_seed/seed_double_free`

### Change

```diff
  ndpi_free(hw->y);
- hw->y = NULL;
```

### Description

`ndpi_hw_add_value` implements Holt-Winters triple exponential smoothing. During the initial learning phase (`num_values < num_season_periods`), incoming values are stored in `hw->y[]`. When `num_values` first reaches `num_season_periods` (transition point), the seasonal indices are computed from `hw->y`, and then `hw->y` is freed — it is no longer needed for the online update phase. The original code nulled `hw->y` immediately after freeing to prevent any subsequent access. Without this null assignment, `hw->y` holds a dangling pointer. When `ndpi_hw_free()` is subsequently called by the harness (`if(rc_hw == 0) ndpi_hw_free(&hw)`), it checks `if(hw->y)` — the dangling pointer is non-NULL — and frees it a second time. ASan detects this as `heap-double-free`.

### Trigger Input

1024-byte seed. FuzzedDataProvider (from back):
```
Byte 1023 = 0x03          (num_values = 3)
Bytes 1022-1015           (values[0..2] = 1, 0, 1)
Bytes 998-997 = 0x0001    (num_periods = 1 → num_season_periods = 2)
```
With `num_periods=1`, the transition fires on the 3rd call to `ndpi_hw_add_value`. Then `ndpi_hw_free` double-frees `hw->y`.

### Reproduction

```bash
./fuzz_alg_hw_rsi_outliers_da fuzz/corpus/fuzz_alg_hw_rsi_outliers_da_seed/seed_double_free
```

---

## Bug 8 — ndpi\_str\_to\_utf8 Stack Buffer Overflow (Off-by-One)

**File:** `src/lib/ndpi_utils.c`, line 4933
**Harness:** `fuzz/fuzz_alg_strnstr.cpp`
**Sanitizer:** ASan stack-buffer-overflow
**Seed:** `fuzz/corpus/fuzz_alg_strnstr_seed/seed_utf8_overflow`

### Change

```diff
- if(out_len < ((in_len*2)+1)) {
+ if(out_len < (in_len*2)) {
```

### Description

`ndpi_str_to_utf8` converts a byte string to a UTF-8 representation. ASCII bytes (< 0x80) pass through as one byte; high bytes (≥ 0x80) are expanded to two UTF-8 bytes (`0xC0 | (b>>6)` and `0x80 | (b&0x3F)`). The output buffer therefore needs `in_len*2 + 1` bytes in the worst case (all high bytes, plus a null terminator). The original guard enforced this: `if(out_len < (in_len*2)+1)` rejects inputs that would overflow. Removing the `+1` allows `out_len == in_len*2` to pass. When all `in_len` bytes are ≥ 0x80, the write index `j` reaches exactly `in_len*2 = out_len`, and `out[j] = '\0'` writes one byte past the end of the stack buffer. The harness declares `out[4096]` and passes `sizeof(out) = 4096` as `out_len`; a 2048-byte haystack of 0xFF bytes triggers the off-by-one write to `out[4096]`.

### Trigger Input

```
<4096 bytes of 0xFF>
```

`ConsumeRandomLengthString` in the harness constructs a haystack of up to 2048 high bytes from this input. `ndpi_str_to_utf8` expands them to 4096 output bytes and then writes `out[4096]`.

### Reproduction

```bash
python3 -c "import sys; sys.stdout.buffer.write(bytes([0xFF]*4096))" | ./fuzz_alg_strnstr
# Or:
./fuzz_alg_strnstr fuzz/corpus/fuzz_alg_strnstr_seed/seed_utf8_overflow
```

---

## Bug 9 — ndpi\_cluster\_bins Memory Leak (bin\_score never freed)

**File:** `src/lib/ndpi_analyze.c`, line 974
**Harness:** `fuzz/fuzz_alg_bins.cpp`
**Sanitizer:** LSan memory-leak
**Seed:** `fuzz/corpus/fuzz_alg_bins_seed/seed_cluster_leak_uaf`

### Change

```diff
- ndpi_free(bin_score);
+ /* ndpi_free(bin_score); */
```

### Description

`ndpi_cluster_bins` allocates a `float` scoring array `bin_score` at the start and relies on a single `ndpi_free(bin_score)` call at the end of the function to release it. Commenting out this free means `bin_score` is never reclaimed on any return path, including the normal success return and early allocation-failure returns. LSan reports the allocation site as a direct memory leak. The leaked size is `num_bins * sizeof(float)` bytes per call. Because `bin_score` is allocated on every invocation (line 788), the leak is unconditional whenever `ndpi_cluster_bins` executes.

### Trigger Input

Any 2048-byte seed that causes `ndpi_cluster_bins` to be called (i.e., `bins` and `cluster_ids` allocations succeed). See `seed_cluster_leak_uaf`.

### Reproduction

```bash
./fuzz_alg_bins fuzz/corpus/fuzz_alg_bins_seed/seed_cluster_leak_uaf
```

---

## Bug 10 — hll\_init Signed Shift Overflow

**File:** `src/lib/third_party/src/hll/hll.c`, lines 79 and 85
**Harness:** `fuzz/fuzz_alg_hll.cpp`
**Sanitizer:** UBSan shift-base-exponent
**Seed:** `fuzz/corpus/fuzz_alg_hll_seed/seed_shift_overflow`

### Change

```diff
- if(bits < 4 || bits > 20) {
+ if(bits < 4 || bits > 31) {

- hll->size = (size_t)1 << bits;
+ hll->size = 1 << bits;
```

### Description

`hll_init` uses `bits` to determine the number of HyperLogLog registers: `hll->size = 1 << bits`. The original code cast the literal `1` to `size_t` (64-bit unsigned on x86-64) before the shift, making the result well-defined for any `bits ≤ 63`. It also validated `bits ≤ 20` to cap memory usage. Removing the `(size_t)` cast keeps the literal as `int` (32-bit signed). Shifting a signed `int` by 31 bits (`1 << 31`) shifts a 1-bit value into the sign bit, which is undefined behavior under the C standard. UBSan's `shift-base-exponent` check fires at this expression. Relaxing the guard from `bits > 20` to `bits > 31` allows the value `bits = 31` to reach the shift.

### Trigger Input

2048-byte seed. FuzzedDataProvider reads from the back:
```
Byte 2047 = 0x1F    (bits = 31)
```
`ndpi_hll_init(hll, 31)` passes the relaxed guard and reaches `1 << 31`.

### Reproduction

```bash
./fuzz_alg_hll fuzz/corpus/fuzz_alg_hll_seed/seed_shift_overflow
```

---

## Bug 11 — ndpi\_cm\_sketch\_add Heap Buffer Overflow (Missing -1 Bitmask)

**File:** `src/lib/ndpi_analyze.c`, line 2011
**Harness:** `fuzz/fuzz_ds_cmsketch.cpp`
**Sanitizer:** ASan heap-buffer-overflow
**Seed:** `fuzz/corpus/fuzz_ds_cmsketch_seed/seed_cmsketch_oob`

### Change

```diff
- sketch->num_hash_buckets = ndpi_nearest_power_of_two(sketch->num_hash_buckets)-1,
+ sketch->num_hash_buckets = ndpi_nearest_power_of_two(sketch->num_hash_buckets),
```

### Description

The Count-Min Sketch uses `num_hash_buckets` as a bitmask for fast modular reduction: `hashval = ndpi_simple_hash(element, idx) & num_hash_buckets`. A correct power-of-two bitmask must be `2^k - 1` (all lower bits set). The original code correctly computed `ndpi_nearest_power_of_two(N) - 1`. Removing the `-1` leaves `num_hash_buckets = 2^k` (a power of two, not a bitmask). The bitwise AND `element & 2^k` now yields either `0` or `2^k`. The backing array `sketch->tables` has exactly `num_hashes * NDPI_COUNT_MIN_SKETCH_NUM_BUCKETS = 2^k` entries (indices `0` to `2^k - 1`). When the AND produces `2^k`, `sketch->tables[2^k]` writes one element past the end of the heap allocation. For `num_hashes = 2`, `2^k = 2048`; element `0x00000800` (bit 11 set) triggers `tables[2048]` out-of-bounds.

### Trigger Input

1024-byte seed. FuzzedDataProvider (from back):
```
Bytes 1023-1022 = 0x0002    (num_hashes = 2 → tables size = 2048, num_hash_buckets = 2048)
Byte  1021      = 0x01      (num_iteration = 1)
Byte  1020      = 0x00      (num_lookup = 0)
Bytes 1019-1016 = 0x00000800  (element with bit 11 set → 0x00000800 & 2048 = 2048 → OOB)
```

### Reproduction

```bash
./fuzz_ds_cmsketch fuzz/corpus/fuzz_ds_cmsketch_seed/seed_cmsketch_oob
```

---

## Bug 12 — ndpi\_alloc\_rsi Uninitialized Memory Read (calloc → malloc)

**File:** `src/lib/ndpi_analyze.c`, line 996
**Harness:** `fuzz/fuzz_alg_hw_rsi_outliers_da.cpp`
**Sanitizer:** MSan uninitialized-value
**Seed:** `fuzz/corpus/fuzz_alg_hw_rsi_outliers_da_seed/seed_rsi_uninit`

### Change

```diff
- s->gains = (u_int32_t*)ndpi_calloc(num_learning_values, sizeof(u_int32_t));
+ s->gains = (u_int32_t*)ndpi_malloc(num_learning_values * sizeof(u_int32_t));
```

### Description

`ndpi_alloc_rsi` allocates two arrays — `gains` and `losses` — used by the RSI rolling-window computation. The original code used `ndpi_calloc` which zero-initializes both arrays. The change replaces `gains` allocation with `ndpi_malloc`, leaving all `num_learning_values` elements uninitialized. In `ndpi_rsi_add_value`, after the first call (which sets `s->empty = 0`), the second call reaches the branch at line 1032: `s->total_gains -= s->gains[s->next_index]`. For `next_index = 1`, `s->gains[1]` has never been written (the first call only wrote `s->gains[0]`), so reading it is a use of uninitialized memory. MSan detects the read.

### Trigger Input

1024-byte seed. FuzzedDataProvider (from back):
```
Byte 1023 = 0x02    (num_values = 2)
Bytes 1022-1015     (values[0]=1, values2[0]=0)
Bytes 1014-1007     (values[1]=2, values2[1]=0)
Byte  975  = 0x02   (num_learning_values = 2 → RSI initialized)
```
Two calls to `ndpi_rsi_add_value` with `values[0]=1` then `values[1]=2`. The second call reads the uninitialized `gains[1]`.

### Reproduction

```bash
./fuzz_alg_hw_rsi_outliers_da fuzz/corpus/fuzz_alg_hw_rsi_outliers_da_seed/seed_rsi_uninit
```

---

## Bug 13 — ndpi\_normalize\_bin Integer Divide-by-Zero

**File:** `src/lib/ndpi_analyze.c`, lines 581 and 587
**Harness:** `fuzz/fuzz_alg_bins.cpp`
**Sanitizer:** UBSan integer-divide-by-zero
**Seed:** `fuzz/corpus/fuzz_alg_bins_seed/seed_normalize_divzero`

### Change

```diff
- if(!b || b->is_empty) return;
+ if(!b) return;

- if(tot > 0) {
+ if(tot >= 0) {
```

### Description

`ndpi_normalize_bin` converts each bin slot to a percentage of the total. Two safety checks guard it: (1) `b->is_empty` prevents normalization of empty bins, and (2) `if(tot > 0)` prevents division by zero when all bin values are zero. The first change removes the `is_empty` check. The second change replaces `tot > 0` with `tot >= 0`; since `tot` is `u_int32_t`, `tot >= 0` is always true, effectively removing the zero guard. After `ndpi_reset_bin(b)` sets all bin values to zero and `b->is_empty = 1`, a subsequent call to `ndpi_normalize_bin(b)` now passes both disabled checks, computes `tot = 0`, and executes `b->u.bins8[i] = (b->u.bins8[i]*100) / 0` — integer division by zero. The harness calls `ndpi_reset_bin(b)` at line 51 and then `ndpi_normalize_bin(b)` at line 63.

### Trigger Input

2048-byte seed (minimum for `fuzz_alg_bins`). FuzzedDataProvider (from back):
```
Bytes 2047-2046 = 0x0001    (num_bins = 1)
Byte  2045      = 0x00      (family = ndpi_bin_family8)
Byte  2044      = 0x00      (num_iteration = 0 → no inc_bin calls)
```
With `num_iteration = 0`, no `ndpi_inc_bin` calls are made. `ndpi_reset_bin(b)` zeros all bins and sets `is_empty = 1`. `ndpi_normalize_bin(b)` then divides by zero.

### Reproduction

```bash
./fuzz_alg_bins fuzz/corpus/fuzz_alg_bins_seed/seed_normalize_divzero
```

---

## Bug 14 — ndpi\_cluster\_bins Heap Use-After-Free

**File:** `src/lib/ndpi_analyze.c`, lines 967–970
**Harness:** `fuzz/fuzz_alg_bins.cpp`
**Sanitizer:** ASan heap-use-after-free
**Seed:** `fuzz/corpus/fuzz_alg_bins_seed/seed_cluster_leak_uaf`

### Change

```diff
  if(alloc_centroids) {
+   ndpi_free(centroids);
+
    for(i=0; i<num_clusters; i++)
      ndpi_free_bin(&centroids[i]);
-
-   ndpi_free(centroids);
  }
```

### Description

When `ndpi_cluster_bins` allocates the `centroids` array internally (`centroids == NULL` on entry, so `alloc_centroids = 1`), it is responsible for freeing both the container array and each element's internal bin data. The original code freed the element internals first (loop calling `ndpi_free_bin`), then freed the container. The change inverts this order: the container is freed first with `ndpi_free(centroids)`, and then the loop accesses `centroids[i]` to call `ndpi_free_bin`. Each iteration of `for(i=0; i<num_clusters; i++) ndpi_free_bin(&centroids[i])` reads a `struct ndpi_bin` from freed heap memory — a classic use-after-free. ASan detects the first read of `centroids[0]` in `ndpi_free_bin`.

### Trigger Input

Same seed as Bug 9: any input that reaches `ndpi_cluster_bins` with `centroids = NULL` (the harness always passes `NULL`). See `seed_cluster_leak_uaf`.

### Reproduction

```bash
./fuzz_alg_bins fuzz/corpus/fuzz_alg_bins_seed/seed_cluster_leak_uaf
```

---

## Bug 15 — ndpi\_extend\_serializer\_buffer Heap Buffer Overflow (Undersized Realloc)

**File:** `src/lib/ndpi_serializer.c`, line 283
**Harness:** `fuzz/fuzz_serialization.cpp`
**Sanitizer:** ASan heap-buffer-overflow
**Seed:** `fuzz/corpus/fuzz_serialization_seed/seed_extend_overflow`

### Change

```diff
- new_size = buffer->size + min_len;
+ new_size = buffer->size + (min_len / 2);
```

### Description

`ndpi_extend_serializer_buffer` is called whenever the serializer's write buffer lacks room for the next field. `min_len` specifies the minimum number of additional bytes needed. The original code grew the buffer by at least `min_len` bytes. The change halves the increment: `min_len / 2`. The caller checks only whether `ndpi_extend_serializer_buffer` returned an error code (< 0); it does not verify that the new buffer size is actually sufficient. The reallocated buffer may be `min_len / 2` bytes shorter than required. Subsequent serialization writes that fill the missing bytes walk past the end of the heap allocation. For any call where `min_len >= 2` (i.e., nearly every extension), the allocated buffer is undersized by at least 1 byte, and the write that triggered the extension overflows the new allocation.

### Trigger Input

256 bytes of random data. The serializer allocates a small buffer on `ndpi_init_serializer_ll(..., small_size)` and then attempts to serialize multiple fields. The first field that exceeds the initial buffer triggers `ndpi_extend_serializer_buffer` with `min_len > 1`, allocating an undersized buffer. The next write overflows it.

### Reproduction

```bash
./fuzz_serialization fuzz/corpus/fuzz_serialization_seed/seed_extend_overflow
```

---

## Expected Sanitizer Output (Bugs 6–15)

### Bug 6 — UBSan signed integer overflow (ndpi\_data\_add\_value)
```
src/lib/ndpi_analyze.c:145:3: runtime error: signed integer overflow:
  3221225472 * 3221225472 cannot be represented in type 'long'
```

### Bug 7 — ASan double-free (ndpi\_hw\_add\_value)
```
==XXXXX==ERROR: AddressSanitizer: heap-double-free on address 0x...
    #0 ndpi_hw_free src/lib/ndpi_analyze.c:1165
```

### Bug 8 — ASan stack-buffer-overflow (ndpi\_str\_to\_utf8)
```
==XXXXX==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x...
WRITE of size 1 at offset 4096 in frame <LLVMFuzzerTestOneInput>
  object 'out' of size 4096
```

### Bug 9 — LSan memory leak (ndpi\_cluster\_bins)
```
==XXXXX==ERROR: LeakSanitizer: detected memory leaks
Direct leak of N byte(s) in 1 object(s) allocated from:
    #0 ndpi_cluster_bins src/lib/ndpi_analyze.c:788
```

### Bug 10 — UBSan shift overflow (hll\_init)
```
src/lib/third_party/src/hll/hll.c:85:16: runtime error: left shift of 1 by 31 places
  cannot be represented in type 'int'
```

### Bug 11 — ASan heap-buffer-overflow (ndpi\_cm\_sketch\_add)
```
==XXXXX==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
WRITE of size 4 at 0x... thread T0
    #0 ndpi_cm_sketch_add src/lib/ndpi_analyze.c:2044
```

### Bug 12 — MSan uninitialized-value (ndpi\_rsi\_add\_value)
```
==XXXXX==ERROR: MemorySanitizer: use-of-uninitialized-value
    #0 ndpi_rsi_add_value src/lib/ndpi_analyze.c:1032
```

### Bug 13 — UBSan integer divide-by-zero (ndpi\_normalize\_bin)
```
src/lib/ndpi_analyze.c:589:21: runtime error: division by zero
```

### Bug 14 — ASan heap-use-after-free (ndpi\_cluster\_bins)
```
==XXXXX==ERROR: AddressSanitizer: heap-use-after-free on address 0x...
READ of size N at 0x... thread T0
    #0 ndpi_free_bin src/lib/ndpi_analyze.c:420
    #1 ndpi_cluster_bins src/lib/ndpi_analyze.c:969
```

### Bug 15 — ASan heap-buffer-overflow (ndpi\_extend\_serializer\_buffer)
```
==XXXXX==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
WRITE of size N at 0x... thread T0
    #0 ndpi_serialize_... src/lib/ndpi_serializer.c:...
```

---

## Build System Integration (Bugs 6–15)

### Additional harnesses (use existing targets)

```cmake
# Already present — no new harnesses needed
add_fuzzer(fuzz_alg_hw_rsi_outliers_da)  # Bugs 6, 7, 12
add_fuzzer(fuzz_alg_bins)                 # Bugs 9, 13, 14
add_fuzzer(fuzz_alg_strnstr)              # Bug 8
add_fuzzer(fuzz_alg_hll)                  # Bug 10
add_fuzzer(fuzz_ds_cmsketch)              # Bug 11
add_fuzzer(fuzz_serialization)            # Bug 15
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

### 2026-04-11 — Extended bug injection (bugs 6–15)

Added 10 additional vulnerabilities across 4 source files using 6 existing harnesses. New sanitizer types introduced: UBSan (signed-integer-overflow, shift-base-exponent, integer-divide-by-zero), MSan (uninitialized-value), LSan (memory-leak), and ASan (double-free, use-after-free).

| Harness | Seed file | Seed bytes | Bug |
|---------|-----------|------------|-----|
| `fuzz_alg_hw_rsi_outliers_da` | `seed_signed_overflow` | 1024 bytes | 6 |
| `fuzz_alg_hw_rsi_outliers_da` | `seed_double_free` | 1024 bytes | 7 |
| `fuzz_alg_strnstr` | `seed_utf8_overflow` | 4096 bytes | 8 |
| `fuzz_alg_bins` | `seed_cluster_leak_uaf` | 2048 bytes | 9, 14 |
| `fuzz_alg_hll` | `seed_shift_overflow` | 2048 bytes | 10 |
| `fuzz_ds_cmsketch` | `seed_cmsketch_oob` | 1024 bytes | 11 |
| `fuzz_alg_hw_rsi_outliers_da` | `seed_rsi_uninit` | 1024 bytes | 12 |
| `fuzz_alg_bins` | `seed_normalize_divzero` | 2048 bytes | 13 |
| `fuzz_serialization` | `seed_extend_overflow` | 256 bytes | 15 |

---

*This report documents intentional research vulnerabilities.
The upstream nDPI library does not contain these bugs.*
