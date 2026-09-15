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

#ifndef __SK__MCP_SERVER_H__
#define __SK__MCP_SERVER_H__

#include <string>

//
// Model Context Protocol server: a line-delimited JSON-RPC 2.0 listener that
//   exposes this process to several local clients at once.  At most one of
//   them, the channel client (normally the bridge), receives notifications.
//
//  Nothing here pulls in nlohmann/json; the tool registry lives in
//    src/mcp/tools.h and is private to the implementation.
//

// Registers the tools and starts the listener if config.mcp.enabled.
void        SK_MCP_Init              (void);

// Runs queued MCP jobs.  Called once per frame from the presenting thread;
//   costs one atomic load when nothing is queued, and does not need the
//   server to be running.
void        SK_MCP_DrainRenderJobs   (void);

// Process teardown: signals stop and closes the sockets, never waits.
void        SK_MCP_Shutdown          (void);

// Idempotent; false on failure, with the reason in SK_MCP_LastError.
bool        SK_MCP_Start             (void);

// Idempotent; signals stop and waits up to 5 seconds for the listener.
void        SK_MCP_Stop              (void);

bool        SK_MCP_IsRunning         (void);
// Whether an authenticated channel client is connected.
bool        SK_MCP_IsClientConnected (void);
// Authenticated clients other than the channel client.
int         SK_MCP_OtherClientCount  (void);

// "" when the last start attempt succeeded.
const char* SK_MCP_LastError         (void);

// Thread-safe.  params_json must be a JSON object; the notification is queued
//   and delivered to the channel client, or to the next one to take the channel.
void        SK_MCP_Notify            (const char* method, const char* params_json);

// Fills token with 32 lowercase hex characters from the system RNG, the same
//   way SK_MCP_Start fills an empty config.mcp.token.  False if the RNG fails.
bool        SK_MCP_GenerateToken     (std::wstring& token);

// SK_WideCharToUTF8 pads its result with NULs; this trims to the text.
std::string SK_MCP_ToUTF8            (const std::wstring& in);

#endif /* __SK__MCP_SERVER_H__ */
