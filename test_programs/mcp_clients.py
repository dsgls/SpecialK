#!/usr/bin/env python3
"""Live checks for Special K's MCP server (docs/superpowers/specs/
2026-09-24-mcp-multi-client-design.md, §8): multiple clients, worker-pool
concurrency, cancellation, channel eviction, connection limits, sk_read_many
and pointer-chain addresses.

Needs a game running with the MCP server enabled and its token available
(see --token-file). Talks newline-delimited JSON-RPC 2.0 directly to the
server -- no bridge involved -- so check 4 evicts a connected bridge; see
its warning.

Python 3, standard library only.
"""

import argparse
import json
import os
import re
import socket
import sys
import threading
import time
from pathlib import Path

PROTOCOL_VERSION = "2025-06-18"
DEFAULT_CONNECT  = "127.0.0.1:27772"
PATTERN          = "de ad be ef ca fe ba be 13 37"


class Conn:
    """One TCP connection to the server. A reader thread parses newline-
    delimited JSON as it arrives and files each message by id (responses) or
    into a shared queue (notifications), so callers can wait for a specific
    response while other lines -- out-of-order responses, pushed
    notifications -- keep flowing. Every wait takes a timeout; none can hang.
    """

    def __init__(self, host, port, connect_timeout=5.0):
        self.sock = socket.create_connection((host, port), timeout=connect_timeout)
        self.sock.settimeout(None)
        self._rfile = self.sock.makefile("r", encoding="utf-8", newline="\n")
        self._cond = threading.Condition()
        self._responses = {}   # id key (json.dumps of id) -> list of response dicts
        self._notifications = []
        self._closed = False
        self._next_id = 1
        self._thread = threading.Thread(target=self._read_loop, daemon=True)
        self._thread.start()

    def _read_loop(self):
        try:
            for line in self._rfile:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(msg, dict):
                    continue
                with self._cond:
                    if "id" in msg and ("result" in msg or "error" in msg):
                        key = json.dumps(msg["id"])
                        self._responses.setdefault(key, []).append(msg)
                    else:
                        self._notifications.append(msg)
                    self._cond.notify_all()
        except OSError:
            pass
        finally:
            with self._cond:
                self._closed = True
                self._cond.notify_all()

    def _send(self, msg):
        self.sock.sendall((json.dumps(msg) + "\n").encode("utf-8"))

    def request(self, method, params, id_=None):
        """Sends a request and returns the id used; does not wait."""
        if id_ is None:
            id_ = self._next_id
            self._next_id += 1
        self._send({"jsonrpc": "2.0", "id": id_, "method": method, "params": params})
        return id_

    def notify(self, method, params):
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def wait_response(self, id_, timeout):
        """The next response for id_, or None on timeout or a closed socket."""
        key = json.dumps(id_)
        deadline = time.monotonic() + timeout
        with self._cond:
            while True:
                pending = self._responses.get(key)
                if pending:
                    return pending.pop(0)
                if self._closed:
                    return None
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._cond.wait(remaining)

    def peek_response(self, id_):
        """A response for id_ already received, without waiting for one."""
        return self.wait_response(id_, 0)

    def wait_notification(self, method, timeout):
        """The next queued notification with this method, or None."""
        deadline = time.monotonic() + timeout
        with self._cond:
            while True:
                for i, note in enumerate(self._notifications):
                    if note.get("method") == method:
                        return self._notifications.pop(i)
                if self._closed:
                    return None
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._cond.wait(remaining)

    def wait_closed(self, timeout):
        """True if the server closed the connection within timeout."""
        deadline = time.monotonic() + timeout
        with self._cond:
            while not self._closed:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._cond.wait(remaining)
            return True

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def connect(ctx):
    return Conn(ctx["host"], ctx["port"])


def raw_initialize(conn, token, channel=None, name="mcp_clients_check"):
    params = {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities":    {},
        "clientInfo":      {"name": name, "version": "1.0"},
        "token":           token,
    }
    if channel is not None:
        params["channel"] = channel

    id_ = conn.request("initialize", params)
    return conn.wait_response(id_, 10.0)


def initialize(conn, token, channel=None, name="mcp_clients_check"):
    """initialize + notifications/initialized; raises on refusal or timeout."""
    resp = raw_initialize(conn, token, channel=channel, name=name)
    if resp is None:
        raise TimeoutError("no response to initialize")
    if "error" in resp:
        raise RuntimeError(f"initialize was refused: {resp['error']}")

    conn.notify("notifications/initialized", {})
    return resp["result"]


def tool_payload(resp):
    """A tools/call response's own result: (dict, False) on success, or
    (message, True) on a tool error -- the server does not JSON-encode a
    tool error's text, so it is returned as a plain string."""
    result   = resp["result"]
    text     = result["content"][0]["text"]
    is_error = bool(result.get("isError", False))

    if is_error:
        return text, True

    return json.loads(text), False


def call_tool(conn, name, arguments, timeout=15.0, id_=None):
    id_  = conn.request("tools/call", {"name": name, "arguments": arguments}, id_=id_)
    resp = conn.wait_response(id_, timeout)

    if resp is None:
        raise TimeoutError(f"no response to tools/call {name} within {timeout}s")
    if "error" in resp:
        raise RuntimeError(f"tools/call {name} got a protocol error: {resp['error']}")

    return tool_payload(resp)


#
# Checks
#

def check_coexistence(ctx):
    a, b = connect(ctx), connect(ctx)
    try:
        initialize(a, ctx["token"])
        initialize(b, ctx["token"])

        for round_no in range(2):
            for label, conn in (("A", a), ("B", b)):
                id_ = conn.request("ping", {})
                resp = conn.wait_response(id_, 5.0)
                if resp is None or "result" not in resp:
                    return "FAIL", f"client {label} did not answer ping (round {round_no + 1})"

            if round_no == 0:
                time.sleep(1.0)

        return "PASS", "two plain clients both answered ping twice"
    finally:
        a.close()
        b.close()


def check_concurrency(ctx):
    a, b = connect(ctx), connect(ctx)
    try:
        initialize(a, ctx["token"])
        initialize(b, ctx["token"])

        id_a = a.request("tools/call",
                          {"name": "sk_pattern_scan", "arguments": {"all": True, "pattern": PATTERN}})
        id_b = b.request("tools/call", {"name": "sk_process_info", "arguments": {}})

        arrival, resp_of = {}, {}
        lock = threading.Lock()

        def waiter(label, conn, id_):
            resp = conn.wait_response(id_, 120.0)
            with lock:
                arrival[label] = time.monotonic()
                resp_of[label] = resp

        threads = [threading.Thread(target=waiter, args=args)
                   for args in (("A", a, id_a), ("B", b, id_b))]
        for t in threads:
            t.start()
        for t in threads:
            t.join(125.0)

        if resp_of.get("A") is None:
            return "FAIL", "sk_pattern_scan (all: true) did not answer within 120 s"
        if resp_of.get("B") is None:
            return "FAIL", "sk_process_info did not answer within 120 s"

        payload_a, is_error_a = tool_payload(resp_of["A"])
        if is_error_a:
            return "FAIL", f"sk_pattern_scan returned an error: {payload_a}"

        detail = f"bytes_scanned={payload_a.get('bytes_scanned')} elapsed_ms={payload_a.get('elapsed_ms')}"

        if arrival["A"] <= arrival["B"]:
            return "SKIP", f"the scan finished before process_info; {detail}"

        payload_b, is_error_b = tool_payload(resp_of["B"])
        if is_error_b:
            return "FAIL", f"sk_process_info returned an error: {payload_b}"

        return "PASS", f"sk_process_info answered while the scan was still running; {detail}"
    finally:
        a.close()
        b.close()


def check_cancellation(ctx):
    a, c, b = connect(ctx), connect(ctx), connect(ctx)
    try:
        initialize(a, ctx["token"])
        initialize(c, ctx["token"])
        initialize(b, ctx["token"])

        ids = []
        for conn, label in ((a, "a"), (c, "c")):
            for i in range(2):
                id_ = f"{label}{i + 1}"
                conn.request("tools/call",
                             {"name": "sk_pattern_scan", "arguments": {"all": True, "pattern": PATTERN}},
                             id_=id_)
                ids.append((conn, id_))

        time.sleep(0.2)

        for conn, id_ in ids:
            if conn.peek_response(id_) is not None:
                return "SKIP", f"scan {id_} finished before its cancel was sent"

        cancel_time = time.monotonic()
        for conn, id_ in ids:
            conn.notify("notifications/cancelled", {"requestId": id_})

        info_id = b.request("tools/call", {"name": "sk_process_info", "arguments": {}})
        resp = b.wait_response(info_id, 1.0)
        if resp is None:
            return "FAIL", "sk_process_info did not answer within 1 s of the cancels"

        payload, is_error = tool_payload(resp)
        if is_error:
            return "FAIL", f"sk_process_info returned an error: {payload}"

        deadline = cancel_time + 5.0
        for conn, id_ in ids:
            remaining = deadline - time.monotonic()
            if remaining > 0:
                late = conn.wait_response(id_, remaining)
                if late is not None:
                    return "FAIL", f"cancelled call {id_} still received a response"

        return "PASS", "sk_process_info answered promptly and no cancelled call got a response"
    finally:
        a.close()
        c.close()
        b.close()


def check_eviction(ctx, state):
    print("WARNING: check 4 evicts a live bridge connection; run with the "
          "bridge stopped for deterministic results.")

    c1, c2, c3 = connect(ctx), connect(ctx), connect(ctx)
    ok = False

    try:
        r1 = initialize(c1, ctx["token"], channel=True)
        if not r1.get("channel"):
            return "FAIL", "C1 did not receive the channel"

        r2 = initialize(c2, ctx["token"], channel=True)
        if not r2.get("channel"):
            return "FAIL", "C2 did not receive the channel"

        evicted = c1.wait_notification("notifications/specialk/evicted", 5.0)
        if evicted is None:
            return "FAIL", "C1 did not receive notifications/specialk/evicted"
        if evicted.get("params", {}).get("reason") != "another channel client connected":
            return "FAIL", f"unexpected evicted params: {evicted.get('params')}"
        if not c1.wait_closed(5.0):
            return "FAIL", "C1's connection was not closed after eviction"

        r3 = initialize(c3, ctx["token"], channel="if_free")
        if r3.get("channel", False):
            return "FAIL", "C3 got the channel via if_free while C2 still holds it"

        claim_resp = c3.wait_response(c3.request("specialk/claim_channel", {}), 5.0)
        if claim_resp is None or claim_resp.get("result", {}).get("channel") is not False:
            return "FAIL", f"C3's claim_channel while C2 holds it returned {claim_resp}"

        c2.close()

        deadline = time.monotonic() + 5.0
        got_channel = False
        while time.monotonic() < deadline and not got_channel:
            claim_resp = c3.wait_response(c3.request("specialk/claim_channel", {}), 1.0)
            if claim_resp is not None and claim_resp.get("result", {}).get("channel") is True:
                got_channel = True
            else:
                time.sleep(0.2)

        if not got_channel:
            return "FAIL", "C3 did not get the channel after C2 disconnected"

        state["c3"] = c3
        ok = True
        return "PASS", "evicted notice, closure, if_free and claim_channel all matched the spec"
    finally:
        c1.close()
        if not ok:
            c2.close()
            c3.close()


def check_limits(ctx, state):
    c3 = state.get("c3")
    if c3 is None:
        return "SKIP", "check 4 did not hand off a channel-holding connection"

    plains = []
    tenth = None
    try:
        for i in range(8):
            conn = connect(ctx)
            result = initialize(conn, ctx["token"])
            if result.get("channel", False):
                return "FAIL", f"plain client {i + 1} unexpectedly got the channel"
            plains.append(conn)

        ninth = connect(ctx)
        resp = raw_initialize(ninth, ctx["token"])
        try:
            if resp is None or "error" not in resp:
                return "FAIL", f"9th plain initialize was not refused: {resp}"
            if resp["error"].get("message") != "client limit reached":
                return "FAIL", f"unexpected refusal: {resp['error']}"
            ninth.wait_closed(5.0)
        finally:
            ninth.close()

        tenth = connect(ctx)
        result10 = initialize(tenth, ctx["token"], channel=True)
        if not result10.get("channel", False):
            return "FAIL", "a channel claim was refused despite the client limit"

        if c3.wait_notification("notifications/specialk/evicted", 5.0) is None:
            return "FAIL", "C3 was not evicted by the new channel claim"
        if not c3.wait_closed(5.0):
            return "FAIL", "C3's connection was not closed after eviction"

        return "PASS", "8 plain clients, a refused 9th, and a channel claim that evicted C3"
    finally:
        for conn in plains:
            conn.close()
        if tenth is not None:
            tenth.close()
        c3.close()


def check_batch_reads(ctx):
    conn = connect(ctx)
    try:
        initialize(conn, ctx["token"])

        info, is_error = call_tool(conn, "sk_process_info", {})
        if is_error:
            return "FAIL", f"sk_process_info returned an error: {info}"

        exe = info.get("exe")
        if not exe:
            return "FAIL", "sk_process_info did not return exe"

        payload, is_error = call_tool(conn, "sk_read_many", {
            "reads": [
                {"address": f"{exe}+0x0", "type": "hex", "count": 2},
                {"address": "0x10",       "type": "u32"},
            ]
        })
        if is_error:
            return "FAIL", f"sk_read_many returned an error: {payload}"

        results = payload.get("results")
        if not isinstance(results, list) or len(results) != 2:
            return "FAIL", f"expected 2 results, got {results!r}"

        good, bad = results

        values = good.get("values")
        if not values or values[0].lower() != "4d5a":
            return "FAIL", f"expected the exe's MZ header, got {good!r}"

        if "error" not in bad or bad.get("address") != "0x10":
            return "FAIL", f"expected a slot error echoing 0x10, got {bad!r}"

        return "PASS", "sk_read_many returned one value and one error, in order"
    finally:
        conn.close()


def check_pointer_chains(ctx):
    conn = connect(ctx)
    try:
        initialize(conn, ctx["token"])

        info, is_error = call_tool(conn, "sk_process_info", {})
        if is_error:
            return "FAIL", f"sk_process_info returned an error: {info}"

        exe      = info.get("exe")
        bitness  = info.get("bitness", 64)
        ptr_size = 4 if bitness == 32 else 8
        mask     = (1 << bitness) - 1

        regions, is_error = call_tool(conn, "sk_list_regions", {"module": exe, "protect": "r"})
        if is_error:
            return "FAIL", f"sk_list_regions returned an error: {regions}"

        candidate = None

        for region in regions.get("regions", []):
            if "w" in region.get("protect", ""):
                continue   # Read-only regions only: a writable value could change mid-check.

            base  = int(region["base"], 16)
            size  = int(region["size"])
            count = min(64, size // ptr_size)

            if count <= 0:
                continue

            try:
                read_payload, read_is_error = call_tool(
                    conn, "sk_read_memory",
                    {"address": region["base"], "type": "ptr", "count": count})
            except RuntimeError:
                continue

            if read_is_error:
                continue

            for i, value in enumerate(read_payload.get("values", [])):
                symbol = value.get("symbol")
                if not symbol:
                    continue

                m = re.search(r"\+0x([0-9a-fA-F]+)$", symbol)
                if not m or int(m.group(1), 16) < 0x10:
                    continue

                candidate = (base + i * ptr_size, int(value["address"], 16))
                break

            if candidate is not None:
                break

        if candidate is None:
            return "SKIP", "no pointer with a symbolized target at offset >= 0x10 was found"

        x_addr, v_addr = candidate
        x_hex = f"0x{x_addr:x}"

        sym, is_error = call_tool(conn, "sk_symbolize_address", {"address": f"[{x_hex}]"})
        if is_error or int(sym["address"], 16) != v_addr:
            return "FAIL", f"[{x_hex}] resolved to {sym!r}, expected 0x{v_addr:x}"

        expected_plus = (v_addr + 8) & mask
        sym8, is_error = call_tool(conn, "sk_symbolize_address", {"address": f"[{x_hex}]+0x8"})
        if is_error or int(sym8["address"], 16) != expected_plus:
            return "FAIL", f"[{x_hex}]+0x8 resolved to {sym8!r}, expected 0x{expected_plus:x}"

        expected_minus = (v_addr - 8) & mask
        symm8, is_error = call_tool(conn, "sk_symbolize_address", {"address": f"[{x_hex}]-0x8"})
        if is_error or int(symm8["address"], 16) != expected_minus:
            return "FAIL", f"[{x_hex}]-0x8 resolved to {symm8!r}, expected 0x{expected_minus:x}"

        bad_text, is_error = call_tool(conn, "sk_symbolize_address", {"address": "[0x10]"})
        if (not is_error) or "level 1" not in bad_text:
            return "FAIL", f"[0x10] should fail naming level 1, got {bad_text!r}"

        return "PASS", f"pointer chains at {x_hex} resolved consistently with sk_symbolize_address"
    finally:
        conn.close()


CHECKS = [
    (1, "Coexistence",        lambda ctx, state: check_coexistence(ctx)),
    (2, "Concurrency",        lambda ctx, state: check_concurrency(ctx)),
    (3, "Cancellation",       lambda ctx, state: check_cancellation(ctx)),
    (4, "Eviction and if_free", check_eviction),
    (5, "Limits",             check_limits),
    (6, "Batch reads",        lambda ctx, state: check_batch_reads(ctx)),
    (7, "Pointer chains",     lambda ctx, state: check_pointer_chains(ctx)),
]


def default_token_path():
    xdg  = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else (Path.home() / ".config")

    return base / "specialk-mcp-bridge" / "token"


def load_token(path):
    text = path.read_text(encoding="utf-8").strip()

    if not text:
        raise ValueError(f"token file {path} is empty")

    return text


def main(argv):
    parser = argparse.ArgumentParser(
        description="Live checks for Special K's MCP server: multiple clients, "
                     "worker-pool concurrency, cancellation, channel eviction, "
                     "connection limits, sk_read_many and pointer-chain addresses.")
    parser.add_argument("--connect", default=DEFAULT_CONNECT,
                         help=f"host:port of the Special K MCP server (default {DEFAULT_CONNECT})")
    parser.add_argument("--token-file", default=None,
                         help="path to the MCP token (default $XDG_CONFIG_HOME/specialk-mcp-bridge/token, "
                              "falling back to ~/.config/specialk-mcp-bridge/token)")
    args = parser.parse_args(argv)

    host, _, port_text = args.connect.rpartition(":")
    if not host or not port_text.isdigit():
        print(f"error: --connect must be host:port, got '{args.connect}'", file=sys.stderr)
        return 1

    port = int(port_text)
    token_path = Path(args.token_file) if args.token_file else default_token_path()

    try:
        token = load_token(token_path)
    except OSError as e:
        print(f"error: could not read token file {token_path}: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    try:
        socket.create_connection((host, port), timeout=5.0).close()
    except OSError as e:
        print(f"error: could not connect to {host}:{port}: {e}", file=sys.stderr)
        return 1

    ctx = {"host": host, "port": port, "token": token}
    state = {}
    failed = False

    for number, name, fn in CHECKS:
        try:
            status, detail = fn(ctx, state)
        except Exception as e:
            status, detail = "FAIL", f"unhandled exception: {e!r}"

        print(f"{status} {number}. {name}: {detail}")

        if status == "FAIL":
            failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
