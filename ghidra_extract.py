# Ghidra headless postscript — extracts analysis data to JSON
# Run via: analyzeHeadless ... -postscript ghidra_extract.py
#
# This is a Ghidra Python (Jython) script, not standard Python.
# It uses Ghidra's API: currentProgram, FlatProgramAPI, etc.

import json
import os

from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.listing import CodeUnit

def run():
    program = currentProgram
    listing = program.getListing()
    fm = program.getFunctionManager()
    sym_table = program.getSymbolTable()
    mem = program.getMemory()

    result = {
        "program_name": program.getName(),
        "language": str(program.getLanguage().getLanguageID()),
        "compiler": str(program.getCompilerSpec().getCompilerSpecID()),
        "image_base": str(program.getImageBase()),
        "executable_format": program.getExecutableFormat(),
        "num_functions": fm.getFunctionCount(),
        "functions": [],
        "imports": [],
        "exports": [],
        "strings_decompiled": [],
        "sections": [],
        "entry_points": [],
        "suspicious_apis": [],
    }

    # --- Functions (top 50 by size) ---
    funcs = []
    func_iter = fm.getFunctions(True)
    while func_iter.hasNext():
        f = func_iter.next()
        body = f.getBody()
        size = body.getNumAddresses() if body else 0
        funcs.append({
            "name": f.getName(),
            "address": str(f.getEntryPoint()),
            "size": int(size),
            "is_thunk": f.isThunk(),
            "calling_convention": str(f.getCallingConventionName()),
            "param_count": f.getParameterCount(),
        })

    # Sort by size descending, take top 50
    funcs.sort(key=lambda x: -x["size"])
    result["functions"] = funcs[:50]

    # --- Imports ---
    imports = []
    sym_iter = sym_table.getExternalSymbols()
    while sym_iter.hasNext():
        sym = sym_iter.next()
        imports.append({
            "name": sym.getName(),
            "namespace": str(sym.getParentNamespace()),
        })
    result["imports"] = imports[:200]

    # --- Exports ---
    sym_iter = sym_table.getSymbolIterator()
    while sym_iter.hasNext():
        sym = sym_iter.next()
        if sym.isExternalEntryPoint():
            result["exports"].append({
                "name": sym.getName(),
                "address": str(sym.getAddress()),
            })
    result["exports"] = result["exports"][:50]

    # --- Entry points ---
    sym_iter = sym_table.getSymbolIterator()
    while sym_iter.hasNext():
        sym = sym_iter.next()
        if sym.getSymbolType() == SymbolType.FUNCTION and sym.isPrimary():
            if sym.getName() in ("main", "_start", "entry", "WinMain", "DllEntryPoint", "_init"):
                result["entry_points"].append({
                    "name": sym.getName(),
                    "address": str(sym.getAddress()),
                })

    # --- Memory sections ---
    blocks = mem.getBlocks()
    for block in blocks:
        result["sections"].append({
            "name": block.getName(),
            "start": str(block.getStart()),
            "size": int(block.getSize()),
            "permissions": "%s%s%s" % (
                "R" if block.isRead() else "-",
                "W" if block.isWrite() else "-",
                "X" if block.isExecute() else "-",
            ),
            "initialized": block.isInitialized(),
        })

    # --- Suspicious API calls ---
    suspicious_apis = [
        "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
        "NtUnmapViewOfSection", "RtlCreateUserThread", "QueueUserAPC",
        "SetWindowsHookEx", "CreateProcess", "ShellExecute", "WinExec",
        "URLDownloadToFile", "InternetOpen", "HttpSendRequest",
        "WSAStartup", "connect", "send", "recv", "socket", "bind", "listen",
        "RegSetValueEx", "RegCreateKeyEx", "CreateService", "StartService",
        "CryptEncrypt", "CryptDecrypt", "CryptGenKey",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "GetProcAddress", "LoadLibrary", "GetModuleHandle",
        "VirtualProtect", "VirtualAlloc", "HeapCreate",
        "OpenProcess", "ReadProcessMemory", "TerminateProcess",
        # Linux
        "execve", "fork", "ptrace", "mprotect", "mmap", "dlopen", "system",
        "popen", "unlink", "chmod", "chown", "setuid", "setgid",
    ]

    found_apis = set()
    for imp in imports:
        name = imp["name"]
        for api in suspicious_apis:
            if api.lower() == name.lower():
                found_apis.add(name)

    result["suspicious_apis"] = list(found_apis)

    # --- Write output ---
    sha256 = os.environ.get("SA_SHA256", program.getName())
    output_path = "/home/nalyzer/results/%s_ghidra.json" % sha256
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print("Ghidra extraction complete: %s" % output_path)
    print("  Functions: %d, Imports: %d, Suspicious APIs: %d" % (
        result["num_functions"], len(result["imports"]), len(result["suspicious_apis"])))

run()
