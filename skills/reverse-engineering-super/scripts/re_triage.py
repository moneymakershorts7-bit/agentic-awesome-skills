#!/usr/bin/env python3
"""
Reverse Engineering Super-Skill (re-super) Deterministic Triage Engine
Analyzes unknown binaries/artifacts, computes entropy, identifies format,
architecture, runtime/compiler, packers, and generates optimal RE pipeline recipes.
"""

import os
import sys
import math
import struct
import json
import re
from typing import Dict, Any, List, Tuple, Optional

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy

def calculate_chunk_entropy(data: bytes, chunk_size: int = 4096) -> List[Tuple[int, float]]:
    entropies = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        entropies.append((i, calculate_entropy(chunk)))
    return entropies

class BinaryTriager:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.size = os.path.getsize(filepath)
        with open(filepath, "rb") as f:
            self.header = f.read(16384)
            f.seek(0)
            self.full_data = f.read() if self.size < 50 * 1024 * 1024 else None

        self.overall_entropy = calculate_entropy(self.full_data if self.full_data else self.header)
        self.format = "UNKNOWN"
        self.subformat = "UNKNOWN"
        self.arch = "UNKNOWN"
        self.bits = 0
        self.endianness = "UNKNOWN"
        self.compiler_runtime = "UNKNOWN"
        self.packers = []
        self.sections: List[Dict[str, Any]] = []
        self.indicators: List[str] = []
        self.tool_recommendations: Dict[str, Any] = {}

    def triage(self) -> Dict[str, Any]:
        self._detect_format()
        if self.format in ["ELF", "PE", "Mach-O", "Mach-O_Universal", "DOTNET_PE", "UNKNOWN"]:
            self._detect_runtime_and_compiler()
            self._detect_packers()
        self._generate_recipes()
        
        return {
            "metadata": {
                "file": self.filename,
                "size_bytes": self.size,
                "overall_entropy": round(self.overall_entropy, 4),
                "is_likely_packed": self.overall_entropy > 7.15 or len(self.packers) > 0,
            },
            "classification": {
                "format": self.format,
                "subformat": self.subformat,
                "architecture": self.arch,
                "bits": self.bits,
                "endian": self.endianness,
                "compiler_runtime": self.compiler_runtime,
                "detected_packers": self.packers,
                "key_indicators": self.indicators,
            },
            "sections": self.sections[:10],
            "recommendations": self.tool_recommendations
        }

    def _detect_format(self):
        h = self.header
        if len(h) < 4:
            self.format = "RAW_OR_EMPTY"
            return

        # ELF
        if h[:4] == b"\x7fELF":
            self.format = "ELF"
            self.bits = 32 if h[4] == 1 else (64 if h[4] == 2 else 0)
            self.endianness = "little" if h[5] == 1 else ("big" if h[5] == 2 else "unknown")
            e_machine = struct.unpack("<H" if self.endianness == "little" else ">H", h[18:20])[0]
            machine_map = {
                0x03: "x86",
                0x3e: "x86_64",
                0x28: "ARM",
                0xb7: "AArch64",
                0x08: "MIPS",
                0xf3: "RISC-V",
                0x14: "PowerPC"
            }
            self.arch = machine_map.get(e_machine, f"machine_0x{e_machine:x}")
            self.subformat = "ELF_EXEC_OR_DYN"
            self._parse_elf_sections()
            return

        # PE / COFF
        if h[:2] == b"MZ":
            self.format = "PE"
            if len(h) >= 0x40:
                e_lfanew = struct.unpack("<I", h[0x3c:0x40])[0]
                if e_lfanew + 4 <= len(h) and h[e_lfanew:e_lfanew+4] == b"PE\x00\x00":
                    self._parse_pe(e_lfanew)
                    return
            self.format = "MS-DOS_MZ"
            self.arch = "x86_16"
            return

        # Mach-O
        if h[:4] in [b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe"]: # 32-bit
            self.format = "Mach-O"
            self.bits = 32
            self.endianness = "big" if h[:4] == b"\xfe\xed\xfa\xce" else "little"
            cputype = struct.unpack(">I" if self.endianness == "big" else "<I", h[4:8])[0]
            self.arch = "x86" if cputype == 7 else ("ARM" if cputype == 12 else f"cpu_0x{cputype:x}")
            return
        if h[:4] in [b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"]: # 64-bit
            self.format = "Mach-O"
            self.bits = 64
            self.endianness = "big" if h[:4] == b"\xfe\xed\xfa\xcf" else "little"
            cputype = struct.unpack(">I" if self.endianness == "big" else "<I", h[4:8])[0]
            self.arch = "x86_64" if cputype == (7 | 0x01000000) else ("AArch64" if cputype == (12 | 0x01000000) else f"cpu_0x{cputype:x}")
            return
        if h[:4] in [b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"]: # Universal Fat or Java Class
            # Check if universal Mach-O fat binary
            if len(h) >= 8:
                count = struct.unpack(">I" if h[:4] == b"\xca\xfe\xba\xbe" else "<I", h[4:8])[0]
                if count < 20: # Likely Fat Mach-O
                    self.format = "Mach-O_Universal"
                    self.subformat = f"Fat_binary_{count}_archs"
                    self.arch = "Universal"
                    return
            self.format = "JVM_Class"
            self.subformat = "Java_Bytecode"
            self.arch = "JVM"
            return

        # WebAssembly
        if h[:4] == b"\x00asm":
            self.format = "WASM"
            version = struct.unpack("<I", h[4:8])[0] if len(h) >= 8 else 1
            self.subformat = f"WASM_v{version}"
            self.arch = "WebAssembly"
            self.bits = 32
            return

        # Android DEX
        if h[:4] == b"dex\n":
            self.format = "DEX"
            version = h[4:7].decode("ascii", errors="ignore")
            self.subformat = f"Dalvik_v{version}"
            self.arch = "Dalvik"
            return

        # ZIP / APK / JAR / docx
        if h[:4] == b"PK\x03\x04":
            self.format = "ZIP_CONTAINER"
            data_sample = self.full_data if self.full_data else self.header
            if b"classes.dex" in data_sample or b"AndroidManifest.xml" in data_sample:
                self.format = "APK"
                self.subformat = "Android_Package"
                self.arch = "Dalvik/Native"
            elif b"META-INF/MANIFEST.MF" in data_sample:
                self.format = "JAR"
                self.subformat = "Java_Archive"
                self.arch = "JVM"
            return

        # PCAP / PCAPNG
        if h[:4] in [b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"]:
            self.format = "PCAP"
            self.subformat = "Classic_PCAP"
            self.arch = "Network_Wire"
            return
        if h[:4] == b"\x0a\x0d\x0d\x0a":
            self.format = "PCAPNG"
            self.subformat = "NextGen_PCAP"
            self.arch = "Network_Wire"
            return

        # Text / Scripting (Python, Shell, JS)
        if h[:2] == b"#!" or any(h.startswith(x) for x in [b"(function", b"const ", b"var ", b"let ", b"import ", b"def "]):
            text_head = h[:1024].decode("utf-8", errors="ignore")
            if "python" in text_head or "import " in text_head or "def " in text_head:
                self.format = "PYTHON_SRC"
                self.subformat = "Python_Source"
                self.arch = "Python_VM"
                self.compiler_runtime = "CPython"
                return
            elif "function" in text_head or "const " in text_head or "require(" in text_head:
                self.format = "JAVASCRIPT"
                self.subformat = "JS/Node"
                self.arch = "V8/SpiderMonkey"
                self.compiler_runtime = "Node/V8"
                return
            elif "#!/bin/sh" in text_head or "#!/bin/bash" in text_head:
                self.format = "SHELL_SCRIPT"
                self.subformat = "Bash/POSIX"
                self.arch = "Shell"
                self.compiler_runtime = "Bash"
                return

    def _parse_elf_sections(self):
        if not self.full_data:
            return
        try:
            is_64 = self.bits == 64
            endian = "<" if self.endianness == "little" else ">"
            if is_64:
                e_shoff = struct.unpack(f"{endian}Q", self.full_data[40:48])[0]
                e_shentsize = struct.unpack(f"{endian}H", self.full_data[58:60])[0]
                e_shnum = struct.unpack(f"{endian}H", self.full_data[60:62])[0]
                e_shstrndx = struct.unpack(f"{endian}H", self.full_data[62:64])[0]
            else:
                e_shoff = struct.unpack(f"{endian}I", self.full_data[32:36])[0]
                e_shentsize = struct.unpack(f"{endian}H", self.full_data[46:48])[0]
                e_shnum = struct.unpack(f"{endian}H", self.full_data[48:50])[0]
                e_shstrndx = struct.unpack(f"{endian}H", self.full_data[50:52])[0]

            if e_shoff == 0 or e_shnum == 0 or e_shstrndx >= e_shnum:
                return

            str_header_offset = e_shoff + e_shstrndx * e_shentsize
            if is_64:
                sh_offset = struct.unpack(f"{endian}Q", self.full_data[str_header_offset+24:str_header_offset+32])[0]
                sh_size = struct.unpack(f"{endian}Q", self.full_data[str_header_offset+32:str_header_offset+40])[0]
            else:
                sh_offset = struct.unpack(f"{endian}I", self.full_data[str_header_offset+16:str_header_offset+20])[0]
                sh_size = struct.unpack(f"{endian}I", self.full_data[str_header_offset+20:str_header_offset+24])[0]

            strtab = self.full_data[sh_offset:sh_offset+sh_size]

            for i in range(e_shnum):
                hdr = self.full_data[e_shoff + i * e_shentsize: e_shoff + (i+1) * e_shentsize]
                if is_64:
                    sh_name_idx, sh_type, sh_flags, sh_addr, sh_offset_sec, sh_size_sec = struct.unpack(f"{endian}IIQQQQ", hdr[:40])
                else:
                    sh_name_idx, sh_type, sh_flags, sh_addr, sh_offset_sec, sh_size_sec = struct.unpack(f"{endian}IIIIII", hdr[:24])

                name = ""
                if sh_name_idx < len(strtab):
                    end = strtab.find(b"\x00", sh_name_idx)
                    name = strtab[sh_name_idx:end].decode("ascii", errors="ignore")

                sec_data = self.full_data[sh_offset_sec:sh_offset_sec + sh_size_sec]
                sec_ent = calculate_entropy(sec_data) if sec_data else 0.0
                self.sections.append({
                    "name": name or f"sec_{i}",
                    "size": sh_size_sec,
                    "entropy": round(sec_ent, 4),
                    "flags": hex(sh_flags)
                })
        except Exception:
            pass

    def _parse_pe(self, pe_offset: int):
        endian = "<"
        h = self.header
        coff_offset = pe_offset + 4
        machine = struct.unpack(f"{endian}H", h[coff_offset:coff_offset+2])[0]
        num_sections = struct.unpack(f"{endian}H", h[coff_offset+2:coff_offset+4])[0]
        opt_hdr_size = struct.unpack(f"{endian}H", h[coff_offset+16:coff_offset+18])[0]

        arch_map = {0x14c: ("x86", 32), 0x8664: ("x86_64", 64), 0xaa64: ("AArch64", 64), 0x1c0: ("ARM", 32)}
        self.arch, self.bits = arch_map.get(machine, (f"pe_0x{machine:x}", 32))
        self.endianness = "little"

        opt_offset = coff_offset + 20
        if opt_hdr_size > 0:
            magic = struct.unpack(f"{endian}H", h[opt_offset:opt_offset+2])[0]
            is_pe32_plus = (magic == 0x20b)
            self.subformat = "PE32+" if is_pe32_plus else "PE32"

            # Check CLR Header in DataDirectory[14]
            # PE32: DataDirectories start at opt_offset + 96
            # PE32+: DataDirectories start at opt_offset + 112
            dd_offset = opt_offset + (112 if is_pe32_plus else 96)
            clr_dd_offset = dd_offset + 14 * 8
            if clr_dd_offset + 8 <= len(h):
                clr_rva, clr_size = struct.unpack(f"{endian}II", h[clr_dd_offset:clr_dd_offset+8])
                if clr_rva > 0 and clr_size > 0:
                    self.format = "DOTNET_PE"
                    self.subformat = "Managed_CIL_Assembly"
                    self.compiler_runtime = ".NET / CLR"
                    self.indicators.append("CLR_Runtime_Header_Present")

        # Parse section headers
        sec_offset = opt_offset + opt_hdr_size
        for i in range(num_sections):
            if sec_offset + 40 > len(h):
                break
            sec_hdr = h[sec_offset:sec_offset+40]
            name = sec_hdr[:8].rstrip(b"\x00").decode("ascii", errors="ignore")
            vsize, vaddr, raw_size, raw_offset = struct.unpack("<IIII", sec_hdr[8:24])
            
            sec_ent = 0.0
            if self.full_data and raw_offset + raw_size <= len(self.full_data):
                sec_ent = calculate_entropy(self.full_data[raw_offset:raw_offset+raw_size])
            self.sections.append({
                "name": name,
                "virtual_size": vsize,
                "raw_size": raw_size,
                "entropy": round(sec_ent, 4)
            })
            sec_offset += 40

    def _detect_runtime_and_compiler(self):
        sample = self.full_data if self.full_data else self.header

        # Go detection
        if b"go.buildid" in sample or b"runtime.gopanic" in sample or b"runtime.main" in sample:
            self.compiler_runtime = "Go (Golang)"
            self.indicators.append("Go_Runtime_Signatures")
            if any(magic in sample for magic in [b"\xfb\xff\xff\xff", b"\xfa\xff\xff\xff", b"\xf0\xff\xff\xff"]):
                self.indicators.append("pclntab_structure_detected")
            m = re.search(rb"go1\.([0-9]+(?:\.[0-9]+)?)", sample)
            if m:
                self.indicators.append(f"Go_Version_{m.group(0).decode()}")
            return

        # Rust detection
        if b"rust_begin_unwind" in sample or b"library/std/src" in sample or b"core::fmt" in sample or b"/rustc/" in sample or b"library/alloc" in sample:
            self.compiler_runtime = "Rust"
            self.indicators.append("Rust_Runtime_Signatures")
            m = re.search(rb"rustc/([0-9a-f]{40})", sample)
            if m:
                self.indicators.append(f"rustc_commit_{m.group(1)[:10].decode()}")
            return

        # .NET detection (if not already set)
        if self.format == "DOTNET_PE" or b"_CorExeMain" in sample or b"mscoree.dll" in sample:
            self.compiler_runtime = ".NET / CLR (C#/F#/VB)"
            self.indicators.append(".NET_Metadata_Signatures")
            return

        # GCC / Clang
        if b"GCC: (" in sample:
            m = re.search(rb"GCC: \([^)]+\) [0-9.]+", sample)
            self.compiler_runtime = m.group(0).decode(errors="ignore") if m else "GCC"
            return
        if b"clang version" in sample:
            m = re.search(rb"clang version [0-9.]+", sample)
            self.compiler_runtime = m.group(0).decode(errors="ignore") if m else "Clang"
            return

        # MSVC Rich Header
        if b"Rich" in sample and b"DanS" in sample:
            self.compiler_runtime = "Microsoft Visual C++ (MSVC)"
            self.indicators.append("MSVC_Rich_Header_Detected")
            return

        # Native GLIBC (standard Linux C/C++)
        if b"GLIBC_" in sample:
            self.compiler_runtime = "C/C++ (glibc dynamic link)"
            self.indicators.append("GNU_C_Runtime_Linkage")
            return

    def _detect_packers(self):
        sample = self.full_data if self.full_data else self.header
        
        # UPX
        if b"UPX0" in sample or b"UPX1" in sample or b"UPX!" in sample:
            self.packers.append("UPX (Ultimate Packer for eXecutables)")

        # PyInstaller
        if b"pyi-windows-msvc" in sample or b"MEI\x0c\x0b\x0a\x0b" in sample or b"_pyi_" in sample:
            self.packers.append("PyInstaller (Packaged Python)")

        # ConfuserEx (.NET)
        if b"ConfuserEx" in sample or b"Confuser.Core" in sample:
            self.packers.append("ConfuserEx (.NET Obfuscator)")

        # SmartAssembly (.NET)
        if b"SmartAssembly" in sample or b"PoweredBySmartAssembly" in sample:
            self.packers.append("SmartAssembly (.NET Obfuscator)")

        # High Entropy Warning
        for sec in self.sections:
            if sec.get("entropy", 0.0) >= 7.2:
                self.indicators.append(f"High_Entropy_Section_{sec['name']}_{sec['entropy']}")

    def _generate_recipes(self):
        f = self.format
        cr = self.compiler_runtime

        if f == "ELF":
            if "Go" in cr:
                self.tool_recommendations = {
                    "primary_static": "Ghidra Headless / r2ghidra + GoReSym",
                    "dynamic_engine": "Frida (JS Interceptor) / GDB + pwndbg",
                    "context_slicing_strategy": "Export GoReSym symbols.json -> focus on main.* and package logic; filter out runtime.* and reflect.*",
                    "cli_recipe": [
                        f"# 1. Recover Go symbols\nGoReSym -d {self.filepath} > symbols.json",
                        f"# 2. Fast function inspection\nr2 -qc 'afl~main.' {self.filepath}",
                        f"# 3. Ghidra headless decompilation\nanalyzeHeadless ./ghidra_proj Proj -import {self.filepath} -postScript ExportMain.java"
                    ]
                }
            elif "Rust" in cr:
                self.tool_recommendations = {
                    "primary_static": "Ghidra + rust-demangle / IDA Pro + Rust plugin",
                    "dynamic_engine": "GDB + pwndbg (step through non-inlined routines)",
                    "context_slicing_strategy": "Grep panic strings (core::panicking) to locate error bounds and struct layouts; slice tokio state machine xrefs",
                    "cli_recipe": [
                        f"# 1. Extract panic strings & demangle\nstrings {self.filepath} | grep -E 'src/|panic' | head -n 30",
                        f"# 2. Decompile entry and demangle with rustfilt\nr2 -qc 'aaa; afl' {self.filepath} | rustfilt | grep -v 'core::'"
                    ]
                }
            else:
                self.tool_recommendations = {
                    "primary_static": "Ghidra Headless / radare2 (r2ghidra)",
                    "dynamic_engine": "GDB + pwndbg / Frida",
                    "symbolic_execution": "Angr (CFGEmulated + explore find=target avoid=fail)",
                    "context_slicing_strategy": "Extract strings xrefs -> identify caller functions -> AST slice cyclomatic complexity > 3; max 1500 tokens/func",
                    "cli_recipe": [
                        f"# 1. Recon sections and security features\nrabin2 -I -z {self.filepath}",
                        f"# 2. Interactive decompile of main\nr2 -qc 'aaa; pdf @ main' {self.filepath}",
                        f"# 3. Symbolic execution template\npython3 -c 'import angr; p=angr.Project(\"{self.filepath}\"); print(p.arch)'"
                    ]
                }
        elif f == "PE" or f == "MS-DOS_MZ":
            self.tool_recommendations = {
                "primary_static": "Ghidra Headless / IDA Pro (idapro_mcp) / radare2",
                "dynamic_engine": "x64dbg / Frida / Qiling Emulation",
                "context_slicing_strategy": "Parse Import Address Table (IAT) -> trace crypto/network APIs -> slice caller basic blocks",
                "cli_recipe": [
                    f"# 1. Header & IAT Recon\nrabin2 -i -z {self.filepath}",
                    f"# 2. Scan for packers\ndiec {self.filepath} 2>/dev/null || r2 -qc 'iS' {self.filepath}"
                ]
            }
        elif f == "DOTNET_PE":
            self.tool_recommendations = {
                "primary_static": "ILSpy (ilspycmd) / dnSpyEx / dnlib",
                "deobfuscator": "de4dot",
                "context_slicing_strategy": "IL-first examination: decompiled C# loses async state machines and anti-tamper. Dump IL instructions of Main and Crypto modules",
                "cli_recipe": [
                    f"# 1. Detect & Clean Obfuscation\nde4dot {self.filepath} -o clean_{self.filename}",
                    f"# 2. Headless C# Decompilation with ILSpy CLI\nilspycmd clean_{self.filename} -p -o ./decompiled_sources",
                    f"# 3. Monitored dnSpy MCP inspection\n# Call dnspy_inspect_il / dnspy_decompile"
                ]
            }
        elif f == "APK":
            self.tool_recommendations = {
                "primary_static": "Jadx (jadx -d out) + apktool",
                "dynamic_engine": "Frida (Java.perform, SSL pinning bypass)",
                "context_slicing_strategy": "Filter AndroidManifest.xml exported components -> Jadx decompiles target Activity/Service -> locate JNI native calls -> inspect lib/*.so in Ghidra",
                "cli_recipe": [
                    f"# 1. Decode resources and smali\napktool d {self.filepath} -o apk_res",
                    f"# 2. Fast Java decompilation\njadx -d apk_src {self.filepath}",
                    f"# 3. Enumerate exported components\npython3 manifest_summary.py apk_res/AndroidManifest.xml"
                ]
            }
        elif f == "DEX":
            self.tool_recommendations = {
                "primary_static": "Jadx / baksmali",
                "cli_recipe": [
                    f"jadx -d dex_src {self.filepath}",
                    f"baksmali d {self.filepath} -o smali_out"
                ]
            }
        elif f == "WASM":
            self.tool_recommendations = {
                "primary_static": "wasm2c / wasm-decompile / Ghidra WASM plugin",
                "context_slicing_strategy": "Convert WASM to C AST via wasm2c -> focus on exported functions and memory table imports",
                "cli_recipe": [
                    f"wasm2wat {self.filepath} -o target.wat",
                    f"wasm-decompile {self.filepath} -o target.dcmp"
                ]
            }
        elif f in ["PCAP", "PCAPNG"]:
            self.tool_recommendations = {
                "primary_static": "tshark / Kaitai Struct / Wireshark dissector",
                "dynamic_engine": "Python Scapy replay / blackboxprotobuf",
                "context_slicing_strategy": "Frame alignment: extract invariant header bytes, length fields, opcode magic, TLV layouts",
                "cli_recipe": [
                    f"tshark -r {self.filepath} -c 20 -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Protocol -e frame.len",
                    f"tshark -r {self.filepath} -T fields -e tcp.payload | head -n 30"
                ]
            }
        elif f == "JAVASCRIPT":
            self.tool_recommendations = {
                "primary_static": "AST Deobfuscator (Babel/Terser) / js-beautify",
                "dynamic_engine": "Chrome DevTools CDP / jshookmcp / Node sandbox",
                "context_slicing_strategy": "Observe XHR initiator -> hook crypto parameters -> slice AST scope enclosing signature generator",
                "cli_recipe": [
                    f"npx prettier@3.3.3 --write {self.filepath}",
                    f"# Trace in Node: node --inspect-brk {self.filepath}"
                ]
            }
        else:
            self.tool_recommendations = {
                "primary_static": "radare2 / Ghidra / binwalk",
                "cli_recipe": [
                    f"binwalk -E {self.filepath}",
                    f"strings -n 8 {self.filepath} | head -n 50"
                ]
            }

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <binary_or_file_path>")
        sys.exit(1)
    target = sys.argv[1]
    if not os.path.exists(target):
        print(f"[-] Error: file not found: {target}")
        sys.exit(1)
    
    triager = BinaryTriager(target)
    result = triager.triage()
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
