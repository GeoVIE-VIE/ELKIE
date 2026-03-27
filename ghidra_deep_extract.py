# -*- coding: utf-8 -*-
# Ghidra headless postscript -- extract ALL non-thunk functions with metadata
# Run via: analyzeHeadless ... -postscript ghidra_deep_extract.py
#
# Two-tier output:
#   - function_index: ALL functions with metadata (name, size, APIs called, xrefs) for LLM triage
#   - decompiled_functions: decompiled C code for each function (LLM picks which to analyze)

import json
import os

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.symbol import SymbolType, RefType

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
        "function_index": [],       # lightweight metadata for ALL functions (triage pass)
        "decompiled_functions": [],  # full C code for all non-thunk functions
        "suspicious_apis": [],
        "sections": [],
    }

    # --- Suspicious API list ---
    suspicious_api_names = {
        "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
        "NtUnmapViewOfSection", "SetWindowsHookEx", "CreateProcess",
        "ShellExecute", "WinExec", "URLDownloadToFile", "InternetOpen",
        "WSAStartup", "connect", "send", "recv", "socket", "bind", "listen",
        "RegSetValueEx", "CreateService", "CryptEncrypt", "CryptDecrypt",
        "IsDebuggerPresent", "GetProcAddress", "LoadLibrary", "VirtualProtect",
        "OpenProcess", "ReadProcessMemory", "TerminateProcess",
        "execve", "fork", "ptrace", "mprotect", "mmap", "dlopen", "system",
        "popen", "unlink", "chmod", "chown", "setuid", "setgid", "chroot",
        "kill", "signal", "ioctl", "prctl", "mount", "umount",
        "getenv", "setenv", "syslog", "openlog",
    }
    suspicious_lower = {a.lower() for a in suspicious_api_names}

    # --- Collect ALL non-thunk functions ---
    all_funcs = []
    func_iter = fm.getFunctions(True)
    while func_iter.hasNext():
        f = func_iter.next()
        if f.isThunk():
            continue
        body = f.getBody()
        size = body.getNumAddresses() if body else 0
        if size < 4:
            continue  # skip trivial stubs
        all_funcs.append((f, size))

    all_funcs.sort(key=lambda x: -x[1])

    # --- Build function index + decompile ---
    for f, size in all_funcs:
        entry = f.getEntryPoint()

        # Get called functions (outgoing references)
        called = []
        called_refs = f.getCalledFunctions(None)
        if called_refs:
            for target in called_refs:
                called.append(target.getName())

        # Get callers (incoming references)
        callers = []
        calling_refs = f.getCallingFunctions(None)
        if calling_refs:
            for caller in calling_refs:
                callers.append(caller.getName())

        # Flag suspicious API calls within this function
        suspicious_calls = [c for c in called if c.lower() in suspicious_lower]

        # Build lightweight index entry (for triage pass — no C code)
        index_entry = {
            "name": f.getName(),
            "address": str(entry),
            "size": int(size),
            "param_count": f.getParameterCount(),
            "calls": called[:30],
            "called_by": callers[:15],
            "suspicious_calls": suspicious_calls,
        }
        result["function_index"].append(index_entry)

        # Decompile (for deep pass)
        try:
            decomp_result = decomp.decompileFunction(f, 30, None)
            if decomp_result and decomp_result.decompileCompleted():
                c_code = decomp_result.getDecompiledFunction().getC()
                # Truncate very long functions
                if len(c_code) > 4000:
                    c_code = c_code[:4000] + "\n// ... truncated ..."

                result["decompiled_functions"].append({
                    "name": f.getName(),
                    "address": str(entry),
                    "size": int(size),
                    "param_count": f.getParameterCount(),
                    "suspicious_calls": suspicious_calls,
                    "c_code": c_code,
                })
            else:
                result["decompiled_functions"].append({
                    "name": f.getName(),
                    "address": str(entry),
                    "size": int(size),
                    "c_code": "// decompilation failed",
                })
        except Exception as e:
            result["decompiled_functions"].append({
                "name": f.getName(),
                "address": str(entry),
                "size": int(size),
                "c_code": "// decompilation error: " + str(e),
            })

    # --- Suspicious APIs (from external symbols) ---
    sym_table = program.getSymbolTable()
    found = set()
    sym_iter = sym_table.getExternalSymbols()
    while sym_iter.hasNext():
        sym = sym_iter.next()
        if sym.getName().lower() in suspicious_lower:
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
    print("  Total functions (non-thunk): %d" % len(all_funcs))
    print("  Decompiled: %d" % len(result["decompiled_functions"]))
    print("  Function index entries: %d" % len(result["function_index"]))

run()
