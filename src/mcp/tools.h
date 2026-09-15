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

#include <SpecialK/mcp/server.h>

#include <functional>
#include <string>
#include <vector>

#include <json/json.hpp>

// Thrown by a handler to fail the call with a message the client sees.
//   The dispatcher turns it into a tool result with isError: true.
struct SK_MCP_ToolError {
  std::string message;
};

struct SK_MCP_Tool {
  const char*    name;
  const char*    description;
  nlohmann::json input_schema;

  std::function <nlohmann::json (const nlohmann::json& args)>
                 handler;
};

// Only legal before the listener starts; the registry is read-only afterwards.
void SK_MCP_RegisterTool         (SK_MCP_Tool&& tool);

const std::vector <SK_MCP_Tool>&
     SK_MCP_Tools                (void);

// src/mcp/tools_process.cpp
void SK_MCP_RegisterProcessTools (void);

void SK_MCP_Notify               (const char* method, const nlohmann::json& params);

#endif /* __SK__MCP_TOOLS_H__ */
