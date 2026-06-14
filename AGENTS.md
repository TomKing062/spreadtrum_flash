# spd_dump — Spreadtrum/Unisoc firmware dumper & flasher

Firmware dumping, flashing, and partition management tool for Spreadtrum/Unisoc
mobile SoCs (SC6531, ums9621, etc.). Communicates with devices in BROM/FDL1/FDL2
stages over USB via libusb or the official SPRD U2S Diag driver.

## Project

- **Stack:** C99 (C + minimal C++ for Windows driver wrapper), libusb-1.0, libxml2, libiconv
- **Entry point:** `spd_dump.c:134` — `main()`
- **Cross-platform:** Linux (incl. Android/Termux), Windows (MSVC / Visual Studio)
- **Build system:** Makefile (Linux) + Visual Studio `.sln`/`.vcxproj` (Windows)
- **Repo:** [TomKing062/spreadtrum_flash](https://github.com/TomKing062/spreadtrum_flash)

## Commands

| Command | What it does |
|---|---|
| `make` | Build `spd_dump` binary (C99, libusb + libxml2 via pkg-config) |
| `make MUSL_BUILD=1` | Static musl build (set `USER_PKG_CONFIG_PATH` for cross) |
| `make MYDEBUG=1` | Build with `_MYDEBUG` preprocessor flag |
| `make clean` | Remove binary + GITVER.h |

**Windows:** Open `spd_dump.sln` in Visual Studio, build `Release|Win32` or `Release|x64`.

**Dependencies:** `libusb-1.0`, `libxml2`, `libiconv` (Linux) — prebuilt in `Lib/` for Windows.

**No test suite.** No linter config — `.editorconfig` enforces formatting.

## Architecture

| Module | File(s) | Role |
|---|---|---|
| **Main / CLI** | `spd_dump.c` | Entry point, argument parsing, command dispatch, interactive REPL (`FDL2>` prompt) |
| **Core library** | `common.c` + `common.h` | USB I/O (`spdio_t`), BSL protocol encode/decode, HDLC framing, CRC16/CRC32, partition read/write/erase, PAC file handling, DM-verity toggle, A/B slot management, NAND support |
| **Protocol defs** | `spd_cmd.h` | BSL command opcodes, constants, HDLC markers, memory maps |
| **Windows driver wrapper** | `Wrapper.cpp` / `Wrapper.h` | SPRD U2S Diag driver COM-style interop via C++ class wrapper |
| **Windows logging** | `BMPlatform.cpp` / `BMPlatform.h` | `ISpLog` logging platform (file + serial log) for Windows |
| **Libraries** | `Lib/` | Prebuilt 3rd-party: `libusb-1.0.dll/.lib`, `libxml2_{Win32,x64}.lib`, `libiconv_{Win32,x64}.lib` |
| **Obfuscation** | `obf/` | VMProtect obfuscation tooling (not part of build) |
| **Version** | `GITVER.h` | Auto-generated via Makefile (`git rev-list HEAD --count` + `git rev-parse HEAD`) |

**Key data types:**
- `spdio_t` — I/O context (wraps `libusb_device_handle` or Windows `ClassHandle`)
- `partition_t` — partition table info
- `DA_INFO_T` — Download Agent info

**Protocol layers:** physical (USB bulk/control) → HDLC framing (0x7E flag, byte-stuffing) → CRC16 → BSL command/response.

## Conventions

- **Language:** C99 (`-std=c99 -pedantic`) with OS-specific C++ for Windows wrappers.
- **Indentation:** tabs for C/C++ (`.editorconfig`), 4-space for everything else.
- **Naming:** `snake_case` for functions/variables, `UPPER_CASE` for macros and enums.
- **Error handling:** `ERR_EXIT(...)` macro prints to stderr and exits; no return-code propagation.
- **Debug output:** `DBG_LOG(...)` wraps `fprintf(stderr, ...)`.
- **Platform branching:** `#if _WIN32` / `#else` / `#if USE_LIBUSB` — prefer compile-time dispatch.
- **Endianness:** LE throughout (`WRITE16_LE`, `WRITE32_LE` macros).
- **Memory:** Manual malloc/free on buffers; `spdio_free()` for I/O contexts.
- **No dynamic linking on Linux:** libusb + libxml2 linked at compile time via pkg-config.

## Notes

<!-- Quick-add space for future observations -->
