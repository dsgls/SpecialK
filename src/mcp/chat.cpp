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
#include <cstdio>
#include <deque>
#include <string>
#include <vector>

using json = nlohmann::json;

#define SK_MCP_LOG_SRC L" MCP-Srv "

// Oldest entries are dropped past this; the pairing ring below is what keeps
//   a late reply to a dropped message pairable.
static constexpr size_t SK_MCP_ChatMaxEntries  = 500;
static constexpr size_t SK_MCP_ChatMaxPairings = 256;

// One record per channel notification pushed, so a reply can be matched to the
//   message it answers after the transcript has forgotten it.
struct SK_MCP_ChatPairing {
  uint64_t seq;
  bool     answered;
  bool     debug;     // sk_debug_notify: no transcript entry, never warned about
};

// Everything below is guarded by _mcp_chat_lock, except the generation counter.
static SK_Thread_HybridSpinlock        _mcp_chat_lock;
static std::deque <SK_MCP_ChatEntry>   _mcp_chat_entries;
static std::deque <SK_MCP_ChatPairing> _mcp_chat_pairings;
static uint64_t                        _mcp_chat_last_index = 0;
static uint64_t                        _mcp_chat_last_seq   = 0;

// Incremented on every append.  A plain 64-bit load tears on 32-bit, so this is
//   a LONG maintained with the interlocked primitives.
static volatile LONG                   _mcp_chat_generation = 0;


// _mcp_chat_lock must be held.
static void
SK_MCP_Chat_AppendLocked ( SK_MCP_ChatRole    role,
                           const std::string& text,
                           uint64_t           seq )
{
  SK_MCP_ChatEntry entry = { };

  entry.role  = role;
  entry.text  = text;
  entry.seq   = seq;
  entry.index = ++_mcp_chat_last_index;

  GetLocalTime (&entry.time);

  _mcp_chat_entries.push_back (entry);

  while (_mcp_chat_entries.size () > SK_MCP_ChatMaxEntries)
         _mcp_chat_entries.pop_front ();

  InterlockedIncrement (&_mcp_chat_generation);
}

// _mcp_chat_lock must be held.  Allocates the next seq and records it.
static uint64_t
SK_MCP_Chat_PushPairingLocked (bool debug)
{
  const uint64_t seq =
    ++_mcp_chat_last_seq;

  _mcp_chat_pairings.push_back ({ seq, false, debug });

  while (_mcp_chat_pairings.size () > SK_MCP_ChatMaxPairings)
         _mcp_chat_pairings.pop_front ();

  return seq;
}

// No lock is held here; SK_MCP_Notify takes the server's queue lock.
//
//   The sanitize is not optional: nlohmann throws when dump () meets invalid
//     UTF-8, and this runs on the presenting thread for a widget submission,
//     where there is nothing to catch it.
static void
SK_MCP_Chat_SendChannel (uint64_t seq, const std::string& text)
{
  const json params = {
    { "content", SK_MCP_SanitizeUTF8 (text) },
    { "meta",    { { "seq",  std::to_string (seq)              },
                   { "game", SK_MCP_ToUTF8  (SK_GetHostApp ()) } } }
  };

  SK_MCP_Notify ("notifications/claude/channel", params);
}


uint64_t
SK_MCP_Chat_Submit (const std::string& text)
{
  // The widget is the one source of chat text that is not already JSON, so
  //   this is where it becomes valid UTF-8; the transcript and the channel
  //   notification then carry the same string.
  const std::string sanitized =
    SK_MCP_SanitizeUTF8 (text);

  uint64_t seq = 0;

  {
    std::scoped_lock lock (_mcp_chat_lock);

    seq =
      SK_MCP_Chat_PushPairingLocked (false);

    SK_MCP_Chat_AppendLocked (SK_MCP_ChatRole::User, sanitized, seq);
  }

  SK_MCP_Chat_SendChannel (seq, sanitized);

  return seq;
}

uint64_t
SK_MCP_Chat_Notify (const std::string& text, bool debug)
{
  uint64_t seq = 0;

  {
    std::scoped_lock lock (_mcp_chat_lock);

    seq =
      SK_MCP_Chat_PushPairingLocked (debug);
  }

  SK_MCP_Chat_SendChannel (seq, text);

  return seq;
}

void
SK_MCP_Chat_Append (SK_MCP_ChatRole role, const std::string& text, uint64_t seq)
{
  std::scoped_lock lock (_mcp_chat_lock);

  SK_MCP_Chat_AppendLocked (role, text, seq);
}

void
SK_MCP_Chat_OnServerEvent (const char* what)
{
  if (what == nullptr)
    return;

  SK_MCP_Chat_Append (SK_MCP_ChatRole::System, what);
}

std::vector <SK_MCP_ChatEntry>
SK_MCP_Chat_Tail (size_t n)
{
  std::scoped_lock lock (_mcp_chat_lock);

  const size_t count =
    std::min (n, _mcp_chat_entries.size ());

  return
    std::vector <SK_MCP_ChatEntry> (
      _mcp_chat_entries.cend () - (ptrdiff_t)count,
      _mcp_chat_entries.cend () );
}

LONG
SK_MCP_Chat_Generation (void)
{
  return
    ReadAcquire (&_mcp_chat_generation);
}

size_t
SK_MCP_Chat_Count (void)
{
  std::scoped_lock lock (_mcp_chat_lock);

  return
    _mcp_chat_entries.size ();
}


//
// Tools
//

static std::string
SK_MCP_Chat_RequireText (const json& args)
{
  if ( (! args.is_object ())          ||
       (! args.contains ("text"))     ||
       (! args.at ("text").is_string ()) )
  {
    throw SK_MCP_ToolError { "text is required and must be a string" };
  }

  std::string text =
    args.at ("text").get <std::string> ();

  if (text.empty ())
    throw SK_MCP_ToolError { "text must not be empty" };

  return text;
}

// The wire form of meta.seq is a string; a number is accepted as a convenience.
static bool
SK_MCP_Chat_ParseSeq (const json& args, uint64_t& seq)
{
  seq = 0;

  if (! args.is_object ())
    return false;

  const auto seq_it =
    args.find ("seq");

  if (seq_it == args.cend () || seq_it->is_null ())
    return false;

  if (seq_it->is_string ())
  {
    const std::string text =
      seq_it->get <std::string> ();

    if ( text.empty () ||
         text.cend () != std::find_if ( text.cbegin (), text.cend (),
           [](char c) { return 0 == isdigit ((unsigned char)c); } ) )
    {
      throw SK_MCP_ToolError { "seq must be a decimal message sequence number" };
    }

    seq = _strtoui64 (text.c_str (), nullptr, 10);

    return true;
  }

  if (seq_it->is_number_unsigned ())
  {
    seq = seq_it->get <uint64_t> ();

    return true;
  }

  // A signed integer here is necessarily negative; nlohmann parses every
  //   non-negative integer literal as unsigned.
  throw SK_MCP_ToolError { "seq must be a decimal message sequence number" };
}

static json
SK_MCP_ChatRespond (const json& args)
{
  const std::string text =
    SK_MCP_Chat_RequireText (args);

  uint64_t seq = 0;

  const bool has_seq =
    SK_MCP_Chat_ParseSeq (args, seq);

  std::string warning;
  size_t      entries = 0;

  {
    std::scoped_lock lock (_mcp_chat_lock);

    if (has_seq)
    {
      const auto pairing =
        std::find_if ( _mcp_chat_pairings.begin (), _mcp_chat_pairings.end (),
          [seq](const SK_MCP_ChatPairing& record) { return record.seq == seq; } );

      if (pairing == _mcp_chat_pairings.end ())
      {
        warning =
          "seq " + std::to_string (seq) + " unknown";
      }

      // A debug seq carries no transcript entry, so it is never paired.
      else if (! pairing->debug)
      {
        if (pairing->answered)
        {
          warning =
            "seq " + std::to_string (seq) + " already answered";
        }

        pairing->answered = true;
      }
    }

    SK_MCP_Chat_AppendLocked (SK_MCP_ChatRole::Claude, text, seq);

    entries =
      _mcp_chat_entries.size ();
  }

  if (! warning.empty ())
  {
    SK_LOG0 ( ( L"sk_chat_respond: %hs", warning.c_str () ), SK_MCP_LOG_SRC );
  }

  json result = {
    { "ok",      true               },
    { "entries", (uint64_t)entries  }
  };

  if (! warning.empty ())
    result ["warning"] = warning;

  return result;
}

static json
SK_MCP_ChatNotify (const json& args)
{
  const std::string text =
    SK_MCP_Chat_RequireText (args);

  SK_MCP_Chat_Append (SK_MCP_ChatRole::Note, text);

  return {
    { "ok",      true                          },
    { "entries", (uint64_t)SK_MCP_Chat_Count () }
  };
}

static const char*
SK_MCP_Chat_RoleName (SK_MCP_ChatRole role)
{
  switch (role)
  {
    case SK_MCP_ChatRole::User:   return "user";
    case SK_MCP_ChatRole::Claude: return "claude";
    case SK_MCP_ChatRole::Note:   return "note";
    default:                      return "system";
  }
}

static json
SK_MCP_ChatHistory (const json& args)
{
  size_t count = 20;

  if (args.is_object ())
  {
    const auto count_it =
      args.find ("count");

    if (count_it != args.cend ())
    {
      if (! count_it->is_number_integer ())
        throw SK_MCP_ToolError { "count must be a whole number" };

      if (! count_it->is_number_unsigned ())
        throw SK_MCP_ToolError { "count must not be negative" };

      count =
        (size_t)std::min ( count_it->get <uint64_t> (),
                             (uint64_t)SK_MCP_ChatMaxEntries );
    }
  }

  std::vector <SK_MCP_ChatEntry> tail;
  size_t                         total = 0;

  {
    std::scoped_lock lock (_mcp_chat_lock);

    total =
      _mcp_chat_entries.size ();

    const size_t taken =
      std::min (count, total);

    tail.assign ( _mcp_chat_entries.cend () - (ptrdiff_t)taken,
                  _mcp_chat_entries.cend () );
  }

  json entries =
    json::array ();

  for (const auto& entry : tail)
  {
    char szTime [32] = { };

    snprintf ( szTime, sizeof (szTime), "%04u-%02u-%02u %02u:%02u:%02u",
                 entry.time.wYear, entry.time.wMonth,  entry.time.wDay,
                 entry.time.wHour, entry.time.wMinute, entry.time.wSecond );

    entries.push_back ({
      { "index", entry.index                       },
      { "role",  SK_MCP_Chat_RoleName (entry.role) },
      { "text",  SK_MCP_SanitizeUTF8  (entry.text) },
      { "time",  szTime                            },
      { "seq",   entry.seq                         }
    });
  }

  return {
    { "total",     (uint64_t)total          },
    { "truncated", tail.size () < total     },
    { "entries",   entries                  }
  };
}


void
SK_MCP_RegisterChatTools (void)
{
  SK_MCP_RegisterTool ({
    "sk_chat_respond",
    "Reply to the in-game chat. Every channel event from Special K is a message "
    "typed in-game and gets exactly one sk_chat_respond; pass the event's meta.seq as seq.",
    {
      { "type",                 "object" },
      { "properties",
        { { "text", { { "type", "string" } } },
          { "seq",  { { "type", json::array ({ "string", "number" }) } } } }
      },
      { "required",             { "text" } },
      { "additionalProperties", false     }
    },
    SK_MCP_ChatRespond
  });

  SK_MCP_RegisterTool ({
    "sk_chat_notify",
    "Post a progress line to the in-game chat during long work; not a reply.",
    {
      { "type",                 "object" },
      { "properties",
        { { "text", { { "type", "string" } } } }
      },
      { "required",             { "text" } },
      { "additionalProperties", false     }
    },
    SK_MCP_ChatNotify
  });

  SK_MCP_RegisterTool ({
    "sk_chat_history",
    "Last N in-game chat entries, oldest first, for a fresh session to catch up.",
    {
      { "type",                 "object" },
      { "properties",
        { { "count", { { "type", "number" } } } }
      },
      { "additionalProperties", false    }
    },
    SK_MCP_ChatHistory
  });
}
