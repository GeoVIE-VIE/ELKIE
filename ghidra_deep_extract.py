# -*- coding: utf-8 -*-
# Ghidra headless postscript -- DEEP extraction with decompiled C code
# Run via: analyzeHeadless ... -postscript ghidra_deep_extract.py
#
# Decompiles top 20 functions by size and outputs readable C code.

import json
import os

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.symbol import SymbolType

def run():
    program = currentProgram
    fm = program.getFunctionManager()
    mem = program.getMemory()

    # Set up decompiler
    decomp = DecompInterface()
    decomp.openProgram(program)

    result = {
        "program_name": program.getName(),
        "language": str(program.getLanguage().getLanguageID()),
        "executable_format": program.getExecutableFormat(),
        "num_functions": fm.getFunctionCount(),
        "decompiled_functions": [],
        "suspicious_apis": [],
        "sections": [],
    }

    # --- Decompile top 20 functions by size ---
    funcs = []
    func_iter = fm.getFunctions(True)
    while func_iter.hasNext():
        f = func_iter.next()
        body = f.getBody()
        size = body.getNumAddresses() if body else 0
        if not f.isThunk() and size > 10:
            funcs.append((f, size))

    funcs.sort(key=lambda x: -x[1])

    for f, size in funcs[:20]:
        try:
            decomp_result = decomp.decompileFunction(f, 30, None)
            if decomp_result and decomp_result.decompileCompleted():
                c_code = decomp_result.getDecompiledFunction().getC()
                # Truncate very long functions
                if len(c_code) > 3000:
                    c_code = c_code[:3000] + "\n// ... truncated ..."

                result["decompiled_functions"].append({
                    "name": f.getName(),
                    "address": str(f.getEntryPoint()),
                    "size": int(size),
                    "param_count": f.getParameterCount(),
                    "c_code": c_code,
                })
        except Exception as e:
            result["decompiled_functions"].append({
                "name": f.getName(),
                "address": str(f.getEntryPoint()),
                "size": int(size),
                "c_code": "// decompilation failed: " + str(e),
            })

    # --- Suspicious APIs ---
    suspicious_apis = [
        "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
        "NtUnmapViewOfSection", "SetWindowsHookEx", "CreateProcess",
        "ShellExecute", "WinExec", "URLDownloadToFile", "InternetOpen",
        "WSAStartup", "connect", "send", "recv", "socket", "bind", "listen",
        "RegSetValueEx", "CreateService", "CryptEncrypt", "CryptDecrypt",
        "IsDebuggerPresent", "GetProcAddress", "LoadLibrary", "VirtualProtect",
        "OpenProcess", "ReadProcessMemory", "TerminateProcess",
        "execve", "fork", "ptrace", "mprotect", "mmap", "dlopen", "system",
        "popen", "unlink", "chmod", "chown", "setuid",
    ]

    sym_table = program.getSymbolTable()
    found = set()
    sym_iter = sym_table.getExternalSymbols()
    while sym_iter.hasNext():
        sym = sym_iter.next()
        for api in suspicious_apis:
            if api.lower() == sym.getName().lower():
                found.add(sym.getName())
    result["suspicious_apis"] = list(found)

    # --- Sections ---
    for block in mem.getBlocks():
        result["sections"].append({
            "name": block.getName(),
            "start": str(block.getStart()),
            "size": int(block.getSize()),
            "permissions": "%s%s%s" % (
                "R" if block.isRead() else "-",
                "W" if block.isWrite() else "-",
                "X" if block.isExecute() else "-",
            ),
        })

    # --- Write output ---
    sha256 = os.environ.get("SA_SHA256", program.getName())
    output_path = "/home/nalyzer/results/%s_ghidra_deep.json" % sha256
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print("Deep Ghidra extraction: %s" % output_path)
    print("  Decompiled: %d functions" % len(result["decompiled_functions"]))

run()
