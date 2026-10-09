# Target Architecture & Classification Matrix

This reference catalogs the 7 canonical reversing target classes, their binary signatures, execution runtimes, and decompilation targets.

---

## 1. Native Unmanaged Binaries (ELF, PE, Mach-O)

### Signatures & Headers
- **ELF (Linux / BSD / Android Native):**
  - Magic: `\x7fELF` (Offset 0x00).
  - Class: 1 = 32-bit, 2 = 64-bit (Offset 0x04).
  - Endianness: 1 = Little-endian, 2 = Big-endian (Offset 0x05).
  - Machine Architecture: `0x03` = x86, `0x3E` = x86_64, `0x28` = ARM, `0xB7` = AArch64, `0xF3` = RISC-V.
- **PE / COFF (Windows):**
  - DOS Header: `MZ` (`0x4D 0x5A` at Offset 0x00).
  - PE Pointer: `e_lfanew` at Offset 0x3C points to PE Signature `PE\0\0` (`0x50 0x45 0x00 0x00`).
  - COFF Machine: `0x014C` = i386, `0x8664` = AMD64, `0xAA64` = ARM64.
- **Mach-O (macOS / iOS Native):**
  - 32-bit: `0xFEEDFACE` (Little-endian: `0xCEFAEDFE`).
  - 64-bit: `0xFEEDFACF` (Little-endian: `0xCFFAEDFE`).
  - Universal / Fat Binary: `0xCAFEBABE`.

### Calling Conventions
- **System V AMD64 (Linux / macOS x86_64):**
  - Arguments: `RDI`, `RSI`, `RDX`, `RCX`, `R8`, `R9`. Stack for remaining arguments in reverse order.
  - Return: `RAX` (64-bit), `RDX:RAX` (128-bit).
  - Callee-Saved: `RBX`, `RSP`, `RBP`, `R12`, `R13`, `R14`, `R15`.
- **Microsoft x64 (Windows x86_64):**
  - Arguments: `RCX`, `RDX`, `R8`, `R9`. Shadow space: 32 bytes allocated by caller on stack.
  - Return: `RAX`.
  - Callee-Saved: `RBX`, `RBP`, `RDI`, `RSI`, `RSP`, `R12`–`R15`.
- **ARM64 (AAPCS64):**
  - Arguments: `X0`–`X7`. Return: `X0` (or `X0`–`X1`). Link Register: `X30` (`LR`).

---

## 2. Managed .NET Assemblies (CIL / MSIL)

### Signatures & Structure
- Standard PE32/PE32+ container.
- Optional Header `DataDirectory[14]` (CLR Runtime Header) contains non-zero VirtualAddress and Size.
- CLI Metadata Header: Magic `0x424A5342` (`BSJB`).
- Metadata Streams:
  - `#~` or `#-`: Compressed metadata tables (Module, TypeRef, TypeDef, MethodDef, Param).
  - `#Strings`: UTF-8 identifiers.
  - `#US`: User-defined string literals.
  - `#Blob`: Signatures, binary constants.

### Decompilation Toolchain
- **Headless CLI:** `ilspycmd -p -o ./decompiled_cs target.dll`
- **Dynamic Deobfuscation:** `de4dot target.exe -o cleaned.exe`
- **Interactive:** `dnSpyEx`, `ILSpy`.

---

## 3. Mobile Dalvik / ART Runtimes (APK / DEX)

### Signatures & Structure
- **APK:** Standard ZIP format (`PK\x03\x04`). Contains `AndroidManifest.xml`, `classes.dex` (or `classes2.dex`, etc.), `lib/<arch>/*.so`.
- **DEX File:** Magic `dex\n035\0` to `dex\n039\0`. Header size 0x70 bytes.

### Decompilation Toolchain
- **Jadx CLI:** `jadx --deobf --show-bad-code -d ./out_jadx target.apk`
- **Resource Decompilation:** `apktool d target.apk -o ./out_apktool`
- **Dynamic Instrumentation:** `frida -U -f com.example.app -l hook.js`

---

## 4. WebAssembly (WASM)

### Signatures & Structure
- Magic: `\x00asm` (`0x00 0x61 0x73 0x6D`).
- Version: `\x01\x00\x00\x00` (Version 1).
- Section IDs: 1 (Type), 2 (Import), 3 (Function), 4 (Table), 5 (Memory), 6 (Global), 7 (Export), 10 (Code), 11 (Data).

### Decompilation Toolchain
- **WABT (WebAssembly Binary Toolkit):**
  - Disassemble to WAT: `wasm2wat target.wasm -o target.wat`
  - Decompile to C: `wasm2c target.wasm -o target.c`
- **Ghidra / IDA:** WASM loader modules.

---

## 5. Frontend & Dynamic Script Runtimes (JS / Node)

### Characteristics
- Obfuscated Webpack/Rollup bundles, V8 bytecode (`.jsc`), Electron ASAR archives.
- Anti-analysis patterns: String array rotation, control flow flattening, dead code injection, `debugger;` loops.

### Deobfuscation Toolchain
- **Unpacking ASAR:** `npx asar@3.2.0 extract app.asar ./decompiled_asar`
- **SourceMap Recovery:** `npx restore-sourcemap@0.2.2 -i bundle.js.map -o ./src`
- **AST Deobfuscation:** Babel plugins targeting string decoder routines.

---

## 6. Stripped Go & Rust Binaries

### Go Binary Characteristics
- Absence of standard libc imports (Go bundles its own runtime and syscall wrappers).
- Go PC-Line Table (`pclntab`): Located in `.gopclntab` or within `.rodata`. Magic values: `0xFFFFFFFB`, `0xFFFFFFFA`, `0xFFFFFFF0`.
- Function symbols, file names, and line numbers are reconstructible from `pclntab`.
- Tool: `gore-sym -d -t target > symbols.json`

### Rust Binary Characteristics
- Mangled symbols using `_R` (v0 mangling) or `_ZN` (legacy C++ style).
- Panic formatting strings in `.rodata`: `"assertion failed: "` followed by source path (`"src/main.rs:42:13"`).
- Demangling: `rustfilt < mangled_symbol`

---

## 7. Wire & Storage Protocols

### Signatures & Structure
- **PCAP:** Magic `0xA1B2C3D4` (Microsecond, same endian) or `0xD4C3B2A1` (Swapped).
- **PCAPNG:** Magic `0x0A0D0D0A` (Section Header Block).

### Toolchain
- **tshark payload carving:**
  ```bash
  tshark -r capture.pcap -Y "tcp.payload" -T fields -e tcp.payload > payloads.hex
  ```
- **Kaitai Struct (.ksy):** Formal declarative parsing into Python/C++ dissecting classes.
