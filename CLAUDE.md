# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is nDPI

nDPI is an open-source LGPLv3 library for **deep packet inspection (DPI)**. It classifies network traffic into 364+ protocols by analyzing packet payloads using protocol dissectors, IP/port heuristics, TLS certificates, and behavioral analysis. It is maintained by ntop.org and targets 100 Gbit+ classification speeds.

## Build

nDPI uses autotools. The standard build sequence:

```bash
./autogen.sh && ./configure
make
```

Library-only build (no examples or tests):
```bash
./autogen.sh && ./configure --with-only-libndpi
make
```

Useful configure flags:
- `--with-sanitizer` — ASAN + UBSan + LeakSan
- `--with-thread-sanitizer` — ThreadSanitizer
- `--enable-debug-build` — debug symbols
- `--with-pcre2` — PCRE2 regex support
- `--with-maxminddb` — GeoIP support
- `--enable-fuzztargets` — build fuzz targets

On Windows, use `windows/nDPI.sln` with Visual Studio, or build via MSYS2/MinGW-w64.

## Testing

```bash
make check                  # run all tests
./tests/do.sh               # PCAP regression tests (diff-based)
./tests/do-unit.sh          # unit tests
./tests/do-dga.sh           # DGA detection tests
```

Useful environment variables for test runs:
- `NDPI_FORCE_PARALLEL_CONFIGS=1` — run test configs in parallel (recommended)
- `NDPI_FAIL_FAST=1` — stop on first failure
- `NDPI_FORCE_UPDATING_UTESTS_RESULTS=1` — regenerate expected test output
- `NDPI_TESTS_VALGRIND=1` — run under Valgrind

## Code Validation

The CI enforces `-Werror` (all warnings are errors). To validate symbol hygiene (no raw malloc/free — must use nDPI wrappers):
```bash
./utils/check_symbols.sh
```

CodeQL analysis runs automatically via `.github/workflows/codeql.yml` on pushes/PRs.

## Architecture

### Core Library (`src/lib/`)

- **`ndpi_main.c`** — central detection engine (~13K lines); initializes protocol defaults, routes packets to dissectors, manages detection state
- **`ndpi_utils.c`** — utility functions (string, hash, IP, etc.)
- **`ndpi_analyze.c`** — flow-level statistical analysis
- **`ndpi_classify.c`** — classification logic after dissection
- **`ndpi_serializer.c`** — serializes flow metadata to JSON or binary (TLV) format
- **`ndpi_config.c`** — runtime configuration management

### Protocol Dissectors (`src/lib/protocols/`)

259 individual `.c` files, one per protocol family (e.g., `tls.c`, `http.c`, `quic.c`, `dns.c`). Each dissector:
1. Inspects packet payload
2. Updates flow state in the `ndpi_flow_struct`
3. Calls `ndpi_set_detected_protocol()` when confident

### Public API (`src/include/`)

- `ndpi_api.h` — public-facing API
- `ndpi_typedefs.h` — all type definitions including `ndpi_flow_struct` (per-flow state)
- `ndpi_private.h` — internal API, dissector registration
- `ndpi_protocol_ids.h` — enum of all 364+ protocol IDs

### Plugin System (`src/lib/plugins/`)

Runtime-loadable dissectors. Load at runtime:
```bash
./example/ndpiReader --plugins-dir src/lib/plugins/
```

### Main CLI Tool (`example/ndpiReader.c`)

The primary tool for PCAP analysis and live capture. Used extensively in tests.

## Adding a New Protocol

1. Add protocol ID to `src/include/ndpi_protocol_ids.h`
2. Create dissector `src/lib/protocols/<proto>.c`
3. Add per-flow state fields to `ndpi_flow_struct` in `src/include/ndpi_typedefs.h`
4. Declare the search function in `src/include/ndpi_private.h`
5. Register default ports in `ndpi_init_protocol_defaults()` in `ndpi_main.c`
6. Add PCAP-based regression tests in `tests/`
7. Document in `doc/protocols.rst`
8. Update `windows/nDPI.sln` if adding new source files

## Memory Management

Raw `malloc`/`free`/`strdup` are **not allowed** in library code. Use nDPI's wrappers (`ndpi_malloc`, `ndpi_free`, `ndpi_strdup`, etc.) so that callers can hook memory allocation. `check_symbols.sh` enforces this.

## Branch & CI

Active development is on the `dev` branch. GitHub Actions (`.github/workflows/`) tests across Ubuntu 22.04/24.04 and macOS, multiple GCC/Clang versions, with fuzzing via OSS-Fuzz/ClusterFuzz.
