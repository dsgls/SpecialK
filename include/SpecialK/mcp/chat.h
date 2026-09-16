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

#ifndef __SK__MCP_CHAT_H__
#define __SK__MCP_CHAT_H__

#include <cstdint>
#include <string>
#include <vector>

//
// In-game chat transcript, shared by the MCP server and the MCP Chat widget.
//
//   The widget is the only reader outside src/mcp, so this header carries just
//     what it needs; the writer half the tools use stays in src/mcp/tools.h.
//     Nothing here pulls in nlohmann/json.
//
//   The transcript is appended from the presenting thread (the widget), the
//     listener thread (the chat tools and the client events) and the control
//     panel thread (server start and stop).  Everything below is thread-safe.
//

enum class SK_MCP_ChatRole { User, Claude, Note, System };

struct SK_MCP_ChatEntry {
  SK_MCP_ChatRole role;
  std::string     text;     // UTF-8
  SYSTEMTIME      time;     // Local time at append
  uint64_t        seq;      // User: the seq sent; Claude: the seq answered; else 0
  uint64_t        index;    // Position in the transcript since process start, 1-based
};

// Appends a user entry and pushes it to Claude.  Returns its seq.
uint64_t SK_MCP_Chat_Submit     (const std::string& text);

// Copy of the last n entries, oldest first.
std::vector <SK_MCP_ChatEntry>
         SK_MCP_Chat_Tail       (size_t n);

// Incremented on every append; lets a reader skip the copy when nothing
//   changed.  A plain 64-bit load tears on 32-bit, hence LONG.
LONG     SK_MCP_Chat_Generation (void);

// Transcript size, for the tools' entries / total fields.
size_t   SK_MCP_Chat_Count      (void);

#endif /* __SK__MCP_CHAT_H__ */
