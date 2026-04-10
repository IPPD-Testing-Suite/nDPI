# [REPLACE: Library Name] Seeded Vulnerability Report

**Library:** [REPLACE: Library Name and Version]
**Branch:** [REPLACE: branch name, e.g., 2.0-bugs]
**Purpose:** Fuzzer evaluation — intentionally introduced vulnerabilities for sanitizer-guided fuzzing research.
**Date:** [REPLACE: YYYY-MM-DD]

> **Note:** These bugs are NOT present in the upstream [REPLACE: Library Name] codebase.
> They were introduced deliberately to evaluate custom fuzzer effectiveness.

---

## Summary Table

| # | CWE | Type | File (modified line) | Sanitizer | Trigger Input |
|---|-----|------|----------------------|-----------|---------------|
| 1 | CWE-[REPLACE] | [REPLACE: type] | `[REPLACE: file.hpp:NNN]` | [REPLACE: sanitizer] | `[REPLACE: trigger]` |
| 2 | CWE-[REPLACE] | [REPLACE: type] | `[REPLACE: file.hpp:NNN]` | [REPLACE: sanitizer] | `[REPLACE: trigger]` |
| 3 | CWE-[REPLACE] | [REPLACE: type] | `[REPLACE: file.hpp:NNN]` | [REPLACE: sanitizer] | `[REPLACE: trigger]` |
| 4 | CWE-[REPLACE] | [REPLACE: type] | `[REPLACE: file.hpp:NNN]` | [REPLACE: sanitizer] | `[REPLACE: trigger]` |
| 5 | CWE-[REPLACE] | [REPLACE: type] | `[REPLACE: file.hpp:NNN]` | [REPLACE: sanitizer] | `[REPLACE: trigger]` |

---

## Bug 1 — [REPLACE: Short Name]

**File:** `[REPLACE: src/path/to/File.hpp]`, line [REPLACE: NNN]
**Harness:** `extras/fuzzing/[REPLACE: name]_fuzzer.cpp`
**Sanitizer:** [REPLACE: ASan stack-buffer-overflow | ASan heap-buffer-overflow | UBSan signed-integer-overflow | ASan stack-overflow]

### Change

```diff
- [REPLACE: original line(s)]
+ [REPLACE: modified line(s)]
```

### Description

[REPLACE: Explain what the original code did, what the change breaks, and why this creates
a memory safety or UB vulnerability. Include relevant variable names, types, and loop
conditions. 3–6 sentences.]

### Trigger Input

```
[REPLACE: exact input string or bytes that trigger the bug]
```

[REPLACE: Explain why this specific input triggers the bug — e.g., "17 digit characters;
the 17th write goes to index 16 of a 16-element array."]

### Reproduction

```bash
echo -n '[REPLACE: trigger]' | ./[REPLACE: name]_fuzzer
# Or for binary input:
# printf '\xNN\xNN...' | ./[REPLACE: name]_fuzzer
```

---

## Bug 2 — [REPLACE: Short Name]

**File:** `[REPLACE: src/path/to/File.hpp]`, line [REPLACE: NNN]
**Harness:** `extras/fuzzing/[REPLACE: name]_fuzzer.cpp`
**Sanitizer:** [REPLACE: ASan stack-buffer-overflow | ASan heap-buffer-overflow | UBSan signed-integer-overflow | ASan stack-overflow]

### Change

```diff
- [REPLACE: original line(s)]
+ [REPLACE: modified line(s)]
```

### Description

[REPLACE]

### Trigger Input

```
[REPLACE]
```

[REPLACE: explanation]

### Reproduction

```bash
echo -n '[REPLACE: trigger]' | ./[REPLACE: name]_fuzzer
```

---

## Bug 3 — [REPLACE: Short Name]

**File:** `[REPLACE: src/path/to/File.hpp]`, lines [REPLACE: NNN–MMM] (deleted)
**Harness:** `extras/fuzzing/[REPLACE: name]_fuzzer.cpp`
**Sanitizer:** [REPLACE: ASan stack-buffer-overflow | ASan heap-buffer-overflow | UBSan signed-integer-overflow | ASan stack-overflow]

### Change

```diff
[REPLACE: show deleted lines with leading -]
```

### Description

[REPLACE]

### Trigger Input

```
[REPLACE]
```

[REPLACE: explanation]

### Reproduction

```bash
echo -n '[REPLACE: trigger]' | ./[REPLACE: name]_fuzzer
```

---

## Bug 4 — [REPLACE: Short Name]

**File:** `[REPLACE: src/path/to/File.hpp]`, lines [REPLACE: NNN–MMM] (deleted)
**Harness:** `extras/fuzzing/[REPLACE: name]_fuzzer.cpp`
**Sanitizer:** [REPLACE: ASan stack-buffer-overflow | ASan heap-buffer-overflow | UBSan signed-integer-overflow | ASan stack-overflow]

### Change

```diff
[REPLACE: show deleted lines with leading -]
```

### Description

[REPLACE]

### Trigger Input

```
[REPLACE]
```

[REPLACE: explanation]

### Reproduction

```bash
echo -n '[REPLACE: trigger]' | ./[REPLACE: name]_fuzzer
```

---

## Bug 5 — [REPLACE: Short Name]

**File:** `[REPLACE: src/path/to/File.hpp]`, line [REPLACE: NNN]
**Harness:** `extras/fuzzing/[REPLACE: name]_fuzzer.cpp`
**Sanitizer:** [REPLACE: ASan stack-buffer-overflow | ASan heap-buffer-overflow | UBSan signed-integer-overflow | ASan stack-overflow]

### Change

```diff
- [REPLACE: original line(s)]
+ [REPLACE: modified line(s)]
```

### Description

[REPLACE]

### Trigger Input

```
[REPLACE]
```

[REPLACE: explanation]

### Reproduction

```bash
echo -n '[REPLACE: trigger]' | ./[REPLACE: name]_fuzzer
```

---

## Build Instructions

All harnesses use the libFuzzer interface and must be compiled with Clang:

```bash
cd /path/to/[REPLACE: library]

# Compile a specific harness (replace NAME with the target):
clang++ -std=c++11 \
  -I src \
  -fsanitize=address,undefined \
  -fno-sanitize-recover=all \
  -fsanitize=fuzzer \
  -g -O1 \
  extras/fuzzing/NAME_fuzzer.cpp \
  -o NAME_fuzzer

# Run with the seed corpus:
./NAME_fuzzer extras/fuzzing/NAME_corpus/ extras/fuzzing/NAME_seed_corpus/ -max_total_time=60

# Reproduce with a known trigger:
echo -n 'TRIGGER_INPUT' | ./NAME_fuzzer
```

Available harnesses:

| Harness | Targets |
|---------|---------|
| `[REPLACE: name1]_fuzzer` | Bug 1 |
| `[REPLACE: name2]_fuzzer` | Bug 2 |
| `[REPLACE: name3]_fuzzer` | Bug 3 |
| `[REPLACE: name4]_fuzzer` | Bug 4 |
| `[REPLACE: name5]_fuzzer` | Bug 5 |

---

## Expected Sanitizer Output

### Bug 1 — [REPLACE: type]
```
[REPLACE: paste expected sanitizer output here]
```

### Bug 2 — [REPLACE: type]
```
[REPLACE]
```

### Bug 3 — [REPLACE: type]
```
[REPLACE]
```

### Bug 4 — [REPLACE: type]
```
[REPLACE]
```

### Bug 5 — [REPLACE: type]
```
[REPLACE]
```

---

## Build System Integration

### CMakeLists.txt

```cmake
add_fuzzer([REPLACE: name1])
add_fuzzer([REPLACE: name2])
add_fuzzer([REPLACE: name3])
add_fuzzer([REPLACE: name4])
add_fuzzer([REPLACE: name5])
```

### Makefile (OSS-Fuzz)

```makefile
all: \
  $(OUT)/[REPLACE: name1]_fuzzer \
  $(OUT)/[REPLACE: name1]_fuzzer_seed_corpus.zip \
  $(OUT)/[REPLACE: name1]_fuzzer.options \
  $(OUT)/[REPLACE: name2]_fuzzer \
  $(OUT)/[REPLACE: name2]_fuzzer_seed_corpus.zip \
  $(OUT)/[REPLACE: name2]_fuzzer.options \
  $(OUT)/[REPLACE: name3]_fuzzer \
  $(OUT)/[REPLACE: name3]_fuzzer_seed_corpus.zip \
  $(OUT)/[REPLACE: name3]_fuzzer.options \
  $(OUT)/[REPLACE: name4]_fuzzer \
  $(OUT)/[REPLACE: name4]_fuzzer_seed_corpus.zip \
  $(OUT)/[REPLACE: name4]_fuzzer.options \
  $(OUT)/[REPLACE: name5]_fuzzer \
  $(OUT)/[REPLACE: name5]_fuzzer_seed_corpus.zip \
  $(OUT)/[REPLACE: name5]_fuzzer.options
```

---

## Changelog

### [REPLACE: YYYY-MM-DD] — Initial bug injection

[REPLACE: describe what was changed, e.g. "Added 5 intentional vulnerabilities and harnesses."]

### [REPLACE: YYYY-MM-DD] — Connected harnesses

[REPLACE: e.g., "Added corpus directories and seed corpora; updated CMakeLists.txt and Makefile."]

### [REPLACE: YYYY-MM-DD] — Replaced biased seeds with unbiased seeds

| Harness | Old seed (biased) | New seed (unbiased) | Seed bytes |
|---------|-------------------|---------------------|------------|
| `[REPLACE: name1]` | [REPLACE] | [REPLACE] | [REPLACE hex] |
| `[REPLACE: name2]` | [REPLACE] | [REPLACE] | [REPLACE hex] |
| `[REPLACE: name3]` | [REPLACE] | [REPLACE] | [REPLACE hex] |
| `[REPLACE: name4]` | [REPLACE] | [REPLACE] | [REPLACE hex] |
| `[REPLACE: name5]` | [REPLACE] | [REPLACE] | [REPLACE hex] |

---

*This report documents intentional research vulnerabilities.
The upstream [REPLACE: Library Name] library does not contain these bugs.*
