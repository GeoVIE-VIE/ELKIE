# -*- coding: utf-8 -*-
"""Ghidra Headless Script - Starts an embedded HTTP server exposing MCP-compatible endpoints.
Replaces the GUI-only GhidraMCPPlugin for headless operation.

Usage with analyzeHeadless:
  analyzeHeadless /tmp/project session -import <sample> \
    -postscript ghidra_mcp_server.py -analysisTimeoutPerFile 240 \
    -scriptTimeout 0

The script blocks (serving HTTP) until killed or the timeout is reached.
Set MCP_SERVER_PORT env var to change port (default 8080).
Set MCP_SERVER_TIMEOUT env var for auto-shutdown in seconds (default 600).
"""
# @category MCP

import os
import json
import threading
import time

# Ghidra imports (available in Jython context)
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor

# Python 2 (Jython) HTTP server
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
import urlparse

PORT = int(os.environ.get("MCP_SERVER_PORT", "8080"))
TIMEOUT = int(os.environ.get("MCP_SERVER_TIMEOUT", "600"))

monitor = ConsoleTaskMonitor()

# Set up decompiler once
decomp = DecompInterface()
decomp.setOptions(DecompileOptions())
decomp.openProgram(currentProgram)

def get_functions(offset=0, limit=100):
    fm = currentProgram.getFunctionManager()
    funcs = list(fm.getFunctions(True))
    return [f.getName() for f in funcs[offset:offset+limit]]

def get_imports(offset=0, limit=100):
    sm = currentProgram.getSymbolTable()
    results = []
    for sym in sm.getExternalSymbols():
        results.append("%s::%s" % (sym.getParentNamespace().getName(), sym.getName()))
    return results[offset:offset+limit]

def get_exports(offset=0, limit=100):
    sm = currentProgram.getSymbolTable()
    results = []
    for sym in sm.getDefinedSymbols():
        if sym.isExternalEntryPoint():
            results.append(sym.getName())
    return results[offset:offset+limit]

def get_segments(offset=0, limit=100):
    mem = currentProgram.getMemory()
    results = []
    for block in mem.getBlocks():
        results.append("%s: %s-%s (%d bytes) [%s%s%s]" % (
            block.getName(), block.getStart(), block.getEnd(), block.getSize(),
            "R" if block.isRead() else "-",
            "W" if block.isWrite() else "-",
            "X" if block.isExecute() else "-",
        ))
    return results[offset:offset+limit]

def decompile_function_by_name(name):
    fm = currentProgram.getFunctionManager()
    for func in fm.getFunctions(True):
        if func.getName() == name:
            result = decomp.decompileFunction(func, 60, monitor)
            if result and result.decompileCompleted():
                return result.getDecompiledFunction().getC()
            return "Decompilation failed for %s" % name
    return "Function '%s' not found" % name

def decompile_function_by_addr(addr_str):
    addr_str = addr_str.strip()
    af = currentProgram.getAddressFactory()
    try:
        addr = af.getAddress(addr_str)
    except:
        return "Invalid address: %s" % addr_str
    fm = currentProgram.getFunctionManager()
    func = fm.getFunctionContaining(addr)
    if not func:
        return "No function at address %s" % addr_str
    result = decomp.decompileFunction(func, 60, monitor)
    if result and result.decompileCompleted():
        return result.getDecompiledFunction().getC()
    return "Decompilation failed at %s" % addr_str

def disassemble_function_by_addr(addr_str):
    addr_str = addr_str.strip()
    af = currentProgram.getAddressFactory()
    try:
        addr = af.getAddress(addr_str)
    except:
        return ["Invalid address: %s" % addr_str]
    fm = currentProgram.getFunctionManager()
    func = fm.getFunctionContaining(addr)
    if not func:
        return ["No function at address %s" % addr_str]
    listing = currentProgram.getListing()
    results = []
    body = func.getBody()
    inst_iter = listing.getInstructions(body, True)
    while inst_iter.hasNext():
        inst = inst_iter.next()
        comment = inst.getComment(0) or ""
        line = "%s: %s" % (inst.getAddress(), inst.toString())
        if comment:
            line += " ; %s" % comment
        results.append(line)
    return results

def search_functions(query, offset=0, limit=100):
    fm = currentProgram.getFunctionManager()
    results = []
    query_lower = query.lower()
    for func in fm.getFunctions(True):
        if query_lower in func.getName().lower():
            results.append(func.getName())
    return results[offset:offset+limit]

def get_strings(offset=0, limit=500, filter_str=None):
    from ghidra.program.util import DefinedDataIterator
    results = []
    count = 0
    for data in DefinedDataIterator.definedStrings(currentProgram):
        val = data.getDefaultValueRepresentation()
        if filter_str and filter_str.lower() not in val.lower():
            continue
        if count >= offset:
            results.append("%s: %s" % (data.getAddress(), val))
        count += 1
        if len(results) >= limit:
            break
    return results

def get_xrefs_to(addr_str, offset=0, limit=100):
    af = currentProgram.getAddressFactory()
    try:
        addr = af.getAddress(addr_str.strip())
    except:
        return ["Invalid address: %s" % addr_str]
    refs = currentProgram.getReferenceManager().getReferencesTo(addr)
    results = []
    for ref in refs:
        results.append("%s -> %s (%s)" % (ref.getFromAddress(), ref.getToAddress(), ref.getReferenceType()))
    return results[offset:offset+limit]

def get_xrefs_from(addr_str, offset=0, limit=100):
    af = currentProgram.getAddressFactory()
    try:
        addr = af.getAddress(addr_str.strip())
    except:
        return ["Invalid address: %s" % addr_str]
    refs = currentProgram.getReferenceManager().getReferencesFrom(addr)
    results = []
    for ref in refs:
        results.append("%s -> %s (%s)" % (ref.getFromAddress(), ref.getToAddress(), ref.getReferenceType()))
    return results[offset:offset+limit]

def get_function_xrefs(name, offset=0, limit=100):
    fm = currentProgram.getFunctionManager()
    for func in fm.getFunctions(True):
        if func.getName() == name:
            entry = func.getEntryPoint()
            return get_xrefs_to(str(entry), offset, limit)
    return ["Function '%s' not found" % name]

def get_data_items(offset=0, limit=100):
    listing = currentProgram.getListing()
    results = []
    data_iter = listing.getDefinedData(True)
    count = 0
    while data_iter.hasNext():
        data = data_iter.next()
        if count >= offset:
            results.append("%s: %s = %s" % (data.getAddress(), data.getDataType().getName(), data.getDefaultValueRepresentation()))
        count += 1
        if len(results) >= limit:
            break
    return results

def get_namespaces(offset=0, limit=100):
    sm = currentProgram.getSymbolTable()
    results = []
    for ns in sm.getClassNamespaces():
        results.append(ns.getName(True))
    return results[offset:offset+limit]


class MCPHandler(BaseHTTPRequestHandler):
    """HTTP request handler mapping GhidraMCP endpoints."""

    def log_message(self, format, *args):
        pass  # Suppress request logging

    def _send(self, body, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        if isinstance(body, list):
            self.wfile.write("\n".join(str(x) for x in body).encode("utf-8"))
        else:
            self.wfile.write(str(body).encode("utf-8"))

    def _params(self):
        parsed = urlparse.urlparse(self.path)
        return urlparse.parse_qs(parsed.query)

    def _int_param(self, params, key, default):
        vals = params.get(key, [str(default)])
        try:
            return int(vals[0])
        except:
            return default

    def do_GET(self):
        parsed = urlparse.urlparse(self.path)
        path = parsed.path.rstrip("/")
        params = self._params()

        try:
            if path == "/methods":
                self._send(get_functions(
                    self._int_param(params, "offset", 0),
                    self._int_param(params, "limit", 100)))
            elif path == "/imports":
                self._send(get_imports(
                    self._int_param(params, "offset", 0),
                    self._int_param(params, "limit", 100)))
            elif path == "/exports":
                self._send(get_exports(
                    self._int_param(params, "offset", 0),
                    self._int_param(params, "limit", 100)))
            elif path == "/segments":
                self._send(get_segments(
                    self._int_param(params, "offset", 0),
                    self._int_param(params, "limit", 100)))
            elif path == "/strings":
                self._send(get_strings(
                    self._int_param(params, "offset", 0),
                    self._int_param(params, "limit", 500),
                    params.get("filter", [None])[0]))
            elif path == "/decompile_function":
                addr = params.get("address", [""])[0]
                self._send(decompile_function_by_addr(addr))
            elif path == "/disassemble_function":
                addr = params.get("address", [""])[0]
                self._send(disassemble_function_by_addr(addr))
            elif path == "/searchFunctions":
                query = params.get("query", [""])[0]
                self._send(search_functions(query,
                    self._int_param(params, "offset", 0),
                    self._int_param(params, "limit", 100)))
            elif path == "/xrefs_to":
                addr = params.get("address", [""])[0]
                self._send(get_xrefs_to(addr,
                    self._int_param(params, "offset", 0),
                    self._int_param(params, "limit", 100)))
            elif path == "/xrefs_from":
                addr = params.get("address", [""])[0]
                self._send(get_xrefs_from(addr,
                    self._int_param(params, "offset", 0),
                    self._int_param(params, "limit", 100)))
            elif path == "/function_xrefs":
                name = params.get("name", [""])[0]
                self._send(get_function_xrefs(name,
                    self._int_param(params, "offset", 0),
                    self._int_param(params, "limit", 100)))
            elif path == "/data":
                self._send(get_data_items(
                    self._int_param(params, "offset", 0),
                    self._int_param(params, "limit", 100)))
            elif path == "/namespaces":
                self._send(get_namespaces(
                    self._int_param(params, "offset", 0),
                    self._int_param(params, "limit", 100)))
            elif path == "/list_functions":
                self._send(get_functions(0, 10000))
            elif path == "/health":
                self._send("ok")
            else:
                self._send("Unknown endpoint: %s" % path, 404)
        except Exception as e:
            self._send("Error: %s" % str(e), 500)

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8") if content_len else ""
        parsed = urlparse.urlparse(self.path)
        path = parsed.path.rstrip("/")

        try:
            if path == "/decompile":
                self._send(decompile_function_by_name(body.strip()))
            else:
                self._send("Unknown POST endpoint: %s" % path, 404)
        except Exception as e:
            self._send("Error: %s" % str(e), 500)


# Start HTTP server in a background thread
server = HTTPServer(("0.0.0.0", PORT), MCPHandler)
server_thread = threading.Thread(target=server.serve_forever)
server_thread.daemon = True
server_thread.start()

println("GhidraMCP HTTP server started on port %d (timeout=%ds)" % (PORT, TIMEOUT))

# Block until timeout - analyzeHeadless keeps the program open while script runs
start_time = time.time()
try:
    while time.time() - start_time < TIMEOUT:
        time.sleep(1)
except KeyboardInterrupt:
    pass

println("GhidraMCP server shutting down after %ds" % (time.time() - start_time))
server.shutdown()
