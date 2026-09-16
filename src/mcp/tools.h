/**
 * This file is part of Special K.
 *
 * Special K is free software : you can redistribute it
 * and/or modify it under the terms of the GNU General Public License
 * as published by The Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Special K is distributed in the hope that it will be useful,
 *
 * But WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Special K.
 *
 *   If not, see <http://www.gnu.org/licenses/>.
 *
**/

#ifndef __SK__MCP_TOOLS_H__
#define __SK__MCP_TOOLS_H__

//
// Tool registry, shared by the server core and the tool implementations.
//   Private to src/mcp; it is not installed under include/.
//

#include <SpecialK/mcp/chat.h>
#include <SpecialK/mcp/server.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include <json/json.hpp>

// Thrown by a handler to fail the call with a message the client sees.
//   The dispatcher turns it into a tool result with isError: true.
struct SK_MCP_ToolError {
  std::string message;
};

// Thrown by SK_MCP_CheckCancelled.  Deliberately not an SK_MCP_ToolError:
//   scan and read loops catch ToolError to skip vanished regions, and a
//   cancel must never be mistaken for one.
struct SK_MCP_Cancelled { };

struct SK_MCP_Tool {
  const char*    name;
  const char*    description;
  nlohmann::json input_schema;

  // Runs on a worker thread, possibly alongside other calls to any tool.
  std::function <nlohmann::json (const nlohmann::json& args)>
                 handler;
};

// Only legal before the listener starts; the registry is read-only afterwards.
void SK_MCP_RegisterTool         (SK_MCP_Tool&& tool);

const std::vector <SK_MCP_Tool>&
     SK_MCP_Tools                (void);

// src/mcp/tools_process.cpp
void SK_MCP_RegisterProcessTools (void);
// src/mcp/tools_memory.cpp
void SK_MCP_RegisterMemoryTools  (void);
// src/mcp/tools_symbols.cpp
void SK_MCP_RegisterSymbolTools  (void);
// src/mcp/tools_scan.cpp
void SK_MCP_RegisterScanTools    (void);
// src/mcp/tools_exec.cpp
void SK_MCP_RegisterExecTools    (void);
// src/mcp/chat.cpp
void SK_MCP_RegisterChatTools    (void);

void SK_MCP_Notify               (const char* method, const nlohmann::json& params);

// Releases the value scan sessions of client; one a call is still using is
//   released by that call when it exits.  Called on the listener thread after
//   every job of that client has been cancelled, while workers may still be
//   running them.  Defined in src/mcp/tools_scan.cpp.
void SK_MCP_OnClientDisconnected (uint64_t client);

// Throws SK_MCP_Cancelled once the calling job has been cancelled.  A
//   no-op outside a job.
void     SK_MCP_CheckCancelled  (void);
// Whether the calling job has been cancelled; false outside a job.
bool     SK_MCP_IsCancelled     (void);
// The connection id of the client whose call is running on this thread,
//   or 0 outside a job.
uint64_t SK_MCP_CurrentClientId (void);

// The server's stop event, or nullptr before the listener has started.
HANDLE SK_MCP_StopEvent          (void);


//
// Shared helpers: src/mcp/address.cpp
//
//   Thread-agnostic and lock-free; everything here throws SK_MCP_ToolError
//     and nothing else.
//

struct SK_MCP_Module {
  HMODULE      handle;
  uintptr_t    base;
  size_t       size;
  std::string  name;    // File name with extension, as sk_list_modules reports it
  std::wstring path;
};

// Snapshot of the loaded modules, in enumeration order (the exe first).
std::vector <SK_MCP_Module>
     SK_MCP_EnumModules      (void);

// Case-insensitive, extension first and only then the stem; the first match
//   in enumeration order wins.
std::optional <SK_MCP_Module>
     SK_MCP_FindModule       (const std::string& name);

// The module whose image range contains addr.
std::optional <SK_MCP_Module>
     SK_MCP_ModuleForAddress (uintptr_t addr);

// "0x..." hex, bare hex, "module+offset", or a pointer chain such as
//   "[[game.exe+0x10]+0x20]+8"; decimal is never accepted.
//
//     address := lead (('+' | '-') hex)*     hex: bare or 0x-prefixed
//     lead    := '[' address ']' | 0x hex | bare
//
//   "[x]" reads a uintptr_t at x.  A bare lead runs to the first '+' outside
//   brackets (or the enclosing ']'); followed by '+' it is a module name,
//   otherwise it must be bare hex, so "1000+10" names a module "1000" and
//   "game.exe-8" is an error.  Offsets wrap.  At most 16 nested brackets and
//   1024 characters.
uintptr_t      SK_MCP_ParseAddress  (const std::string& text);
std::string    SK_MCP_FormatAddress (uintptr_t addr);   // "0x..." lowercase
nlohmann::json SK_MCP_Symbolize     (uintptr_t addr);   // "module+0x..." or null

// Snapshot forms, for a tool that parses or symbolizes many addresses in one
//   call: enumerate once with SK_MCP_EnumModules and pass the result in.  The
//   one-argument forms above enumerate on every call.  The returned pointer
//   points into modules and is only valid while it lives.
const SK_MCP_Module*
     SK_MCP_ModuleForAddress ( uintptr_t addr,
                               const std::vector <SK_MCP_Module>& modules );
nlohmann::json
     SK_MCP_Symbolize        ( uintptr_t addr,
                               const std::vector <SK_MCP_Module>& modules );
uintptr_t
     SK_MCP_ParseAddress     ( const std::string&                 text,
                               const std::vector <SK_MCP_Module>& modules );
std::optional <SK_MCP_Module>
     SK_MCP_FindModule       ( const std::string&                 name,
                               const std::vector <SK_MCP_Module>& modules );

// Every page in [addr, addr + len) must be committed, not PAGE_NOACCESS and
//   not PAGE_GUARD, or the call throws before touching memory.  The copy runs
//   under __try/__except and a fault throws with the exception code.
void SK_MCP_SafeRead  (uintptr_t addr,       void* dst, size_t len);
// Widens page protections for the duration of the copy and restores them on
//   every path.  A multi-page write is not atomic.
void SK_MCP_SafeWrite (uintptr_t addr, const void* src, size_t len);

// The base protection, with PAGE_GUARD, PAGE_NOCACHE and PAGE_WRITECOMBINE
//   masked off, as "rwx" / "r-x" / "---".
std::string SK_MCP_ProtectString (DWORD protect);

// Whether the whole of [addr, addr + len) sits in one readable committed
//   region, without touching it.  out receives the region info for addr.
bool SK_MCP_IsReadableRange ( uintptr_t addr, size_t len,
                              MEMORY_BASIC_INFORMATION* out = nullptr );

// The optional "protect" and "region_type" arguments shared by sk_list_regions
//   and the scan tools.
struct SK_MCP_RegionFilter {
  std::string protect;        // Required letters from "rwx"; empty = any
  bool        image   = true,
              priv    = true,
              mapped  = true;
  bool Matches (const MEMORY_BASIC_INFORMATION& mbi) const;
};
// Reads optional "protect" and "region_type" from args; throws ToolError.
SK_MCP_RegionFilter SK_MCP_ParseRegionFilter (const nlohmann::json& args);

// Replaces every byte sequence that is not valid UTF-8 -- truncated, overlong,
//   a surrogate or past U+10FFFF -- with U+FFFD, resyncing one byte at a time.
//   Text pulled out of process memory is not guaranteed to be text at all, and
//   nlohmann throws when it dumps a string that is not valid UTF-8.
std::string           SK_MCP_SanitizeUTF8 (const std::string& in);

// A JSON number or a numeric string ("3.0", "3", "1e-3").  The string form is
//   accepted because the integer and ptr types take strings, which makes
//   quoting a float an easy mistake; a whole number like 3 is a float value
//   like any other and needs no decimal point.
double                SK_MCP_ParseFloatValue (const nlohmann::json& v);

std::string           SK_MCP_BytesToHex (const void* data, size_t len);
std::vector <uint8_t> SK_MCP_HexToBytes (const std::string& hex);


//
// Presenting-thread job queue: src/mcp/render_queue.cpp
//

// Runs fn on the presenting thread and waits up to timeout_ms.  Throws
//   SK_MCP_ToolError on timeout or server stop; an exception thrown by fn is
//   captured and rethrown here.
//
// fn must capture everything it needs BY VALUE and return its result by
//   value: a job that times out may still run later, after the caller's frame
//   is gone.  Nothing fn touches may live on the caller's stack.
nlohmann::json
SK_MCP_RunOnRenderThread ( std::function <nlohmann::json (void)> fn,
                           DWORD                                 timeout_ms );


//
// Chat transcript: src/mcp/chat.cpp
//
//   The reader half the MCP Chat widget uses is public, in
//     <SpecialK/mcp/chat.h>; the writer half is here.  The transcript lock is
//     held only around container access, never across SK_MCP_Notify.
//

// Appends a claude / note / system entry.  seq is the user seq a claude entry
//   answers, else 0.
void     SK_MCP_Chat_Append      ( SK_MCP_ChatRole    role,
                                   const std::string& text,
                                   uint64_t           seq = 0 );

// Allocates a seq, records it in the reply pairing ring and pushes the channel
//   notification carrying text.  debug marks an sk_debug_notify seq, which
//   carries no transcript entry and is never paired or warned about.
uint64_t SK_MCP_Chat_Notify      (const std::string& text, bool debug = false);

// Appends a System entry.  Called by server.cpp where it logs the event, never
//   while the notification-queue lock is held.
void     SK_MCP_Chat_OnServerEvent (const char* what);

#endif /* __SK__MCP_TOOLS_H__ */
