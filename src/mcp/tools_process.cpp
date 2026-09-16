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

#include <SpecialK/stdafx.h>

#include "tools.h"

#include <algorithm>
#include <cctype>
#include <vector>

using json = nlohmann::json;

static std::string
SK_MCP_ToLower (std::string str)
{
  std::transform ( str.cbegin (), str.cend (), str.begin (),
    [](unsigned char c) { return (char)std::tolower (c); } );

  return str;
}


static json
SK_MCP_ProcessInfo (const json& /*args*/)
{
  wchar_t wszPath [MAX_PATH + 1] = { };

  GetModuleFileNameW (nullptr, wszPath, MAX_PATH);

  // Unsynchronised by design: the presenting thread owns visible, and a stale
  //   value is harmless.  Null before the widgets initialise.
  const bool chat_open =
    SK_ImGui_Widgets->mcp_chat != nullptr &&
    SK_ImGui_Widgets->mcp_chat->isVisible ();

  return {
    { "pid",        (int)GetCurrentProcessId ()          },
    { "exe",        SK_MCP_ToUTF8 (SK_GetHostApp ())  },
    { "path",       SK_MCP_ToUTF8 (wszPath)           },
    { "bitness",    (int)SK_GetBitness ()                 },
    { "sk_version", SK_MCP_ToUTF8 (SK_GetVersionStrW ()) },
    { "chat_open",  chat_open                             }
  };
}

static json
SK_MCP_ListModules (const json& args)
{
  bool        has_filter = false;
  std::string filter_lower;

  if (args.is_object ())
  {
    const auto filter_it =
      args.find ("filter");

    if (filter_it != args.cend ())
    {
      if (! filter_it->is_string ())
        throw SK_MCP_ToolError { "filter must be a string" };

      has_filter   = true;
      filter_lower = SK_MCP_ToLower (filter_it->get <std::string> ());
    }
  }

  json modules =
    json::array ();

  for (const auto& mod : SK_MCP_EnumModules ())
  {
    if (has_filter)
    {
      if (SK_MCP_ToLower (mod.name).find (filter_lower) == std::string::npos)
        continue;
    }

    modules.push_back ({
      { "name", mod.name                        },
      { "base", SK_MCP_FormatAddress (mod.base) },
      { "size", (uint64_t)mod.size              },
      { "path", SK_MCP_ToUTF8 (mod.path)        }
    });
  }

  return { { "modules", modules } };
}

static json
SK_MCP_DebugNotify (const json& args)
{
  if ( (! args.is_object ())               ||
       (! args.contains ("content"))       ||
       (! args.at        ("content").is_string ()) )
  {
    throw SK_MCP_ToolError { "content is required and must be a string" };
  }

  const std::string content =
    args.at ("content").get <std::string> ();

  // Shares the chat's seq counter and pairing ring, but appends no transcript
  //   entry and is never paired with a reply.
  SK_MCP_Chat_Notify (content, true);

  return { { "queued", true } };
}


void
SK_MCP_RegisterProcessTools (void)
{
  SK_MCP_RegisterTool ({
    "sk_process_info",
    "Returns identifying information about the host process Special K is injected into.",
    {
      { "type",                 "object"      },
      { "properties",           json::object () },
      { "additionalProperties", false          }
    },
    SK_MCP_ProcessInfo
  });

  SK_MCP_RegisterTool ({
    "sk_list_modules",
    "Lists the modules loaded in the host process, optionally filtered by a case-insensitive substring of the module name.",
    {
      { "type",                 "object" },
      { "properties",
        { { "filter", { { "type", "string" } } } }
      },
      { "additionalProperties", false    }
    },
    SK_MCP_ListModules
  });

  SK_MCP_RegisterTool ({
    "sk_debug_notify",
    "Debug: pushes a channel notification as the in-game chat will in a later phase.",
    {
      { "type",                 "object"    },
      { "properties",
        { { "content", { { "type", "string" } } } }
      },
      { "required",             { "content" } },
      { "additionalProperties", false        }
    },
    SK_MCP_DebugNotify
  });
}
