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

//
// stdafx.h pulls in Windows.h without WIN32_LEAN_AND_MEAN, which drags in the
//   winsock.h that blocks WinSock2.h.  WinSock2.h therefore has to come first,
//   and this translation unit is built with the precompiled header disabled.
//
#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <SpecialK/stdafx.h>

#pragma comment (lib, "ws2_32.lib")   // not in AdditionalDependencies
#pragma comment (lib, "bcrypt.lib")

#include <SpecialK/mcp/server.h>

#include "tools.h"

#include <bcrypt.h>

#include <algorithm>
#include <condition_variable>
#include <deque>
#include <map>
#include <memory>
#include <mutex>

using json = nlohmann::json;

#define SK_MCP_LOG_SRC L" MCP-Srv "

// A line longer than this is a protocol violation and drops the connection.
static constexpr size_t SK_MCP_MaxLineLength =  1024 * 1024;
static constexpr size_t SK_MCP_MaxQueueDepth =  256;

// A tool result larger than this would push the response line past the
//   bridge's 1 MiB cap and drop the connection, so it is refused instead.
static constexpr size_t SK_MCP_MaxResultBytes =  768 * 1024;

// Authenticated or not.  The two beyond 8 plain clients plus the channel
//   client leave room for a channel claim, which is never refused for lack of
//   room because it evicts the old channel client.
static constexpr size_t    SK_MCP_MaxConnections   = 10;
static constexpr size_t    SK_MCP_MaxPlainClients  = 8;
static constexpr ULONGLONG SK_MCP_AuthTimeoutMs    = 10000;
static constexpr ULONGLONG SK_MCP_DrainTimeoutMs   = 2000;
// Unsent output beyond this means the peer has stopped reading.
static constexpr size_t    SK_MCP_MaxOutboundBytes = 16 * 1024 * 1024;
// Per client per loop iteration, so a peer that keeps its pipe full cannot
//   hold the listener.
static constexpr size_t    SK_MCP_ReadBudgetBytes  = 64 * 1024;

static constexpr size_t    SK_MCP_WorkerCount      = 4;
static constexpr int       SK_MCP_MaxCallsInFlight = 16;
// Per client, so one client never holds more than half the workers.
static constexpr size_t    SK_MCP_MaxCallsRunning  = 2;

// Frozen by the wire protocol; the bridge keeps the same list.
static constexpr const char* SK_MCP_ProtocolVersions [] = {
  "2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"
};
static constexpr const char* SK_MCP_DefaultProtocolVersion = "2025-06-18";


// One tools/call.  Workers and the listener share it; only cancelled changes
//   after it has been queued.
struct SK_MCP_Job {
  uint64_t      client    = 0;
  json          id;
  std::string   id_key;           // id.dump (), what notifications/cancelled matches
  json          params;
  volatile LONG cancelled = FALSE;
};

using SK_MCP_JobPtr = std::shared_ptr <SK_MCP_Job>;

struct SK_MCP_ClientJobs {
  std::deque  <SK_MCP_JobPtr> queued;
  std::vector <SK_MCP_JobPtr> running;
};

struct SK_MCP_Completion {
  SK_MCP_JobPtr job;
  std::string   line;             // Empty when the call was cancelled
};

// Owned by the listener thread; nothing else touches it.
struct SK_MCP_Client {
  uint64_t    id            = 0;
  size_t      slot          = 0;      // Index into _mcp_client_socks
  SOCKET      sock          = INVALID_SOCKET;
  WSAEVENT    event         = WSA_INVALID_EVENT;
  std::string input;
  std::string output;
  size_t      output_sent   = 0;      // Prefix of output already sent
  bool        authenticated = false;
  bool        channel       = false;
  bool        closing       = false;  // Drains output, then closes; input is discarded
  bool        dead          = false;  // Closed at the end of this loop iteration
  bool        drained       = false;  // Closing and all output sent: close gracefully
  bool        read_more     = false;  // The read budget ran out; data may be waiting
  bool        write_blocked = false;  // Waiting for FD_WRITE
  ULONGLONG   accept_tick   = 0;
  ULONGLONG   closing_tick  = 0;
  int         in_flight     = 0;      // Calls queued or running
};

static std::vector <SK_MCP_Tool> _mcp_tools;

static SK_Thread_HybridSpinlock  _mcp_queue_lock;
static std::deque <std::string>  _mcp_queue;   // Serialized notification lines

// Listener thread only.  Client ids come from a counter that is never reset,
//   so a late completion can never be matched to a newer client.
static std::vector <std::unique_ptr <SK_MCP_Client>> _mcp_clients;
static uint64_t                                      _mcp_next_client_id = 1;

// The running count per client lives here rather than on SK_MCP_Client, so
//   a worker can free its slot and pick the next job without the listener.
static SK_Thread_HybridSpinlock                      _mcp_jobs_lock;
static std::condition_variable_any                   _mcp_jobs_cv;
static std::map <uint64_t, SK_MCP_ClientJobs>        _mcp_jobs;   // Empty entries are erased
static uint64_t                                      _mcp_jobs_last_served = 0;
static bool                                          _mcp_workers_stop     = false;

static HANDLE                                        _mcp_workers [SK_MCP_WorkerCount] = { };
static DWORD                                         _mcp_worker_count = 0;

static SK_Thread_HybridSpinlock                      _mcp_done_lock;
static std::deque <SK_MCP_Completion>                _mcp_done;

static thread_local SK_MCP_Job*                      _mcp_current_job = nullptr;

static          HANDLE _mcp_thread         = nullptr;
static volatile LONG   _mcp_running        = FALSE;
static volatile LONG   _mcp_has_channel    = FALSE;
static volatile LONG   _mcp_other_clients  = 0;
// Fixed storage: the control panel reads this pointer from another thread
//   every frame while the listener may be writing it.
static char            _mcp_last_error [256] = { };

static WSAEVENT _mcp_ev_stop   = WSA_INVALID_EVENT;
static WSAEVENT _mcp_ev_notify = WSA_INVALID_EVENT;
static WSAEVENT _mcp_ev_accept = WSA_INVALID_EVENT;
static WSAEVENT _mcp_ev_done   = WSA_INVALID_EVENT;   // Manual-reset, like the others

// Also closed by SK_MCP_Shutdown, out from under the listener.  Whoever swaps a
//   socket out with SK_MCP_TakeSocket owns its close.
static volatile SOCKET _mcp_listen_sock = INVALID_SOCKET;
static volatile SOCKET _mcp_client_socks [SK_MCP_MaxConnections] = {
  INVALID_SOCKET, INVALID_SOCKET, INVALID_SOCKET, INVALID_SOCKET, INVALID_SOCKET,
  INVALID_SOCKET, INVALID_SOCKET, INVALID_SOCKET, INVALID_SOCKET, INVALID_SOCKET
};

static_assert (sizeof (SOCKET) == sizeof (PVOID));

// The x86 InterlockedExchangePointer takes a non-volatile PVOID*.
static PVOID*
SK_MCP_SocketSlot (volatile SOCKET* slot)
{
  return
    reinterpret_cast <PVOID *> (const_cast <SOCKET *> (slot));
}

static SOCKET
SK_MCP_TakeSocket (volatile SOCKET* slot)
{
  return
    reinterpret_cast <SOCKET> (
      InterlockedExchangePointer ( SK_MCP_SocketSlot (slot),
                                   reinterpret_cast <PVOID> (INVALID_SOCKET) )
    );
}

static void
SK_MCP_StoreSocket (volatile SOCKET* slot, SOCKET sock)
{
  InterlockedExchangePointer ( SK_MCP_SocketSlot (slot),
                               reinterpret_cast <PVOID> (sock) );
}


static const char*
SK_MCP_WSAErrorName (int err)
{
  switch (err)
  {
    case WSAEACCES:       return "WSAEACCES";
    case WSAEADDRINUSE:   return "WSAEADDRINUSE";
    case WSAEADDRNOTAVAIL:return "WSAEADDRNOTAVAIL";
    case WSAECONNABORTED: return "WSAECONNABORTED";
    case WSAECONNRESET:   return "WSAECONNRESET";
    case WSAEFAULT:       return "WSAEFAULT";
    case WSAEINVAL:       return "WSAEINVAL";
    case WSAEMFILE:       return "WSAEMFILE";
    case WSAENETDOWN:     return "WSAENETDOWN";
    case WSAENOBUFS:      return "WSAENOBUFS";
    case WSAENOTSOCK:     return "WSAENOTSOCK";
    case WSANOTINITIALISED:
                          return "WSANOTINITIALISED";
    case WSAEWOULDBLOCK:  return "WSAEWOULDBLOCK";
    default:              return "WSAError";
  }
}

// e.g. "bind failed: WSAEADDRINUSE (10048)"
static std::string
SK_MCP_WSAErrorString (const char* what, int err)
{
  char szError [128] = { };

  snprintf ( szError, sizeof (szError), "%s: %s (%d)",
               what, SK_MCP_WSAErrorName (err), err );

  return szError;
}

static void
SK_MCP_SetLastError (const std::string& error)
{
  strncpy_s (_mcp_last_error, error.c_str (), _TRUNCATE);

  if (! error.empty ())
  {
    SK_LOG0 ( ( L"%hs", error.c_str () ), SK_MCP_LOG_SRC );
  }
}


HANDLE
SK_MCP_StopEvent (void)
{
  return
    (_mcp_ev_stop == WSA_INVALID_EVENT) ? nullptr
                                        : _mcp_ev_stop;
}

void
SK_MCP_RegisterTool (SK_MCP_Tool&& tool)
{
  _mcp_tools.emplace_back (std::move (tool));
}

const std::vector <SK_MCP_Tool>&
SK_MCP_Tools (void)
{
  return _mcp_tools;
}

void
SK_MCP_CheckCancelled (void)
{
  const SK_MCP_Job* job =
    _mcp_current_job;

  if (job != nullptr && ReadAcquire (&job->cancelled) != FALSE)
    throw SK_MCP_Cancelled { };
}

bool
SK_MCP_IsCancelled (void)
{
  const SK_MCP_Job* job =
    _mcp_current_job;

  return
    job != nullptr && ReadAcquire (&job->cancelled) != FALSE;
}

uint64_t
SK_MCP_CurrentClientId (void)
{
  const SK_MCP_Job* job =
    _mcp_current_job;

  return
    (job != nullptr) ? job->client
                     : 0;
}


bool
SK_MCP_GenerateToken (std::wstring& token)
{
  uint8_t bytes [16] = { };

  if (! BCRYPT_SUCCESS (
           BCryptGenRandom ( nullptr, bytes, sizeof (bytes),
                               BCRYPT_USE_SYSTEM_PREFERRED_RNG ) ) )
  {
    return false;
  }

  static constexpr wchar_t wszHexDigits [] = L"0123456789abcdef";

  std::wstring generated;
               generated.reserve (32);

  for (auto byte : bytes)
  {
    generated += wszHexDigits [(byte >> 4) & 0xF];
    generated += wszHexDigits [ byte       & 0xF];
  }

  token = generated;

  return true;
}

std::string
SK_MCP_ToUTF8 (const std::wstring& in)
{
  std::string out =
    SK_WideCharToUTF8 (in);

  out.resize (strlen (out.c_str ()));

  return out;
}


// Equal-length memcmp, so a mismatched token costs what a match costs.
static bool
SK_MCP_TokenMatches (const std::string& presented)
{
  const std::string expected =
    SK_MCP_ToUTF8 (config.mcp.token);

  // No configured token authenticates nobody; an empty presented token
  //   would otherwise match on a zero-length compare.
  if (expected.empty ())
    return false;

  if (expected.size () != presented.size ())
    return false;

  return
    0 == memcmp (expected.data (), presented.data (), expected.size ());
}


void
SK_MCP_Notify (const char* method, const char* params_json)
{
  if (method == nullptr)
    return;

  json params =
    json::parse (params_json != nullptr ? params_json : "{}", nullptr, false);

  if (params.is_discarded ())
      params = json::object ();

  SK_MCP_Notify (method, params);
}

void
SK_MCP_Notify (const char* method, const json& params)
{
  if (method == nullptr)
    return;

  const json notification = {
    { "jsonrpc", "2.0"   },
    { "method",  method  },
    { "params",  params  }
  };

  const std::string line =
    notification.dump () + "\n";

  {
    std::scoped_lock lock (_mcp_queue_lock);

    while (_mcp_queue.size () >= SK_MCP_MaxQueueDepth)
           _mcp_queue.pop_front ();

    _mcp_queue.push_back (line);

    // Signalling under the same lock SK_MCP_CloseEvents takes keeps the handle
    //   alive across the call; the listener's drain never holds it while sending.
    if (_mcp_ev_notify != WSA_INVALID_EVENT)
      WSASetEvent (_mcp_ev_notify);
  }
}


static std::string
SK_MCP_ResponseLine (const json& id, const json& result)
{
  const json response = {
    { "jsonrpc", "2.0"  },
    { "id",      id     },
    { "result",  result }
  };

  return
    response.dump () + "\n";
}

static std::string
SK_MCP_ErrorLine (const json& id, int code, const char* message)
{
  const json response = {
    { "jsonrpc", "2.0" },
    { "id",      id    },
    { "error",   { { "code", code }, { "message", message } } }
  };

  return
    response.dump () + "\n";
}

static json
SK_MCP_MakeToolResult (const std::string& text, bool is_error)
{
  json content =
    json::array ();

  content.push_back ({ { "type", "text" }, { "text", text } });

  return {
    { "content", content  },
    { "isError", is_error }
  };
}

static json
SK_MCP_HandleInitialize (const json& params, bool channel)
{
  std::string version = SK_MCP_DefaultProtocolVersion;

  if (params.is_object ())
  {
    const auto requested =
      params.find ("protocolVersion");

    if (requested != params.cend () && requested->is_string ())
    {
      const std::string requested_version =
        requested->get <std::string> ();

      for (auto supported : SK_MCP_ProtocolVersions)
      {
        if (requested_version == supported)
        {
          version = requested_version;
          break;
        }
      }
    }
  }

  return {
    { "protocolVersion", version               },
    { "capabilities",    { { "tools", json::object () } } },
    { "serverInfo",      { { "name",    "Special K"          },
                           { "version", SK_GetVersionStrA () } } },
    { "channel",         channel               }
  };
}

static json
SK_MCP_HandleToolsList (void)
{
  json tools =
    json::array ();

  for (const auto& tool : SK_MCP_Tools ())
  {
    tools.push_back ({
      { "name",        tool.name         },
      { "description", tool.description  },
      { "inputSchema", tool.input_schema }
    });
  }

  return { { "tools", tools } };
}

static json
SK_MCP_DispatchToolCall (const json& params)
{
  std::string name;

  if (params.is_object ())
  {
    const auto tool_name =
      params.find ("name");

    if (tool_name != params.cend () && tool_name->is_string ())
      name = tool_name->get <std::string> ();
  }

  json args =
    json::object ();

  if (params.is_object ())
  {
    const auto arguments =
      params.find ("arguments");

    if (arguments != params.cend () && arguments->is_object ())
      args = *arguments;
  }

  for (const auto& tool : SK_MCP_Tools ())
  {
    if (name == tool.name)
    {
      // No catch (...): the project builds with /EHa, and a catch-all would
      //   swallow access violations that belong to SK's crash handler.
      //   SK_MCP_Cancelled passes through to the worker.
      try
      {
        return
          SK_MCP_MakeToolResult (tool.handler (args).dump (), false);
      }

      catch (const SK_MCP_ToolError& e)
      {
        return
          SK_MCP_MakeToolResult (e.message, true);
      }

      catch (const std::exception& e)
      {
        return
          SK_MCP_MakeToolResult (e.what (), true);
      }
    }
  }

  return
    SK_MCP_MakeToolResult ("Unknown tool: " + name, true);
}

static json
SK_MCP_HandleToolsCall (const json& params)
{
  json result =
    SK_MCP_DispatchToolCall (params);

  // Measuring means serializing, which allocates a second copy of a result
  //   that is already large.
  try
  {
    // Measured after the handler's JSON has been escaped into the text item,
    //   which can nearly double backslash-heavy output.
    const size_t bytes =
      result.dump ().length ();

    if (bytes > SK_MCP_MaxResultBytes)
    {
      char szError [128] = { };

      snprintf ( szError, sizeof (szError),
                   "result too large (%zu bytes); narrow the request", bytes );

      return
        SK_MCP_MakeToolResult (szError, true);
    }
  }

  catch (const std::exception&)
  {
    return
      SK_MCP_MakeToolResult ("result too large; narrow the request", true);
  }

  return result;
}


//
// Worker pool
//

// The oldest queued job of the next client after the one served last that has
//   a job queued and a running slot free.  Caller holds _mcp_jobs_lock.
static SK_MCP_JobPtr
SK_MCP_PickJob (void)
{
  auto it =
    _mcp_jobs.upper_bound (_mcp_jobs_last_served);

  for (size_t i = 0; i < _mcp_jobs.size (); ++i, ++it)
  {
    if (it == _mcp_jobs.end ())
        it  = _mcp_jobs.begin ();

    auto& jobs = it->second;

    if (jobs.queued.empty () || jobs.running.size () >= SK_MCP_MaxCallsRunning)
      continue;

    SK_MCP_JobPtr job =
      jobs.queued.front ();

    jobs.queued.pop_front ();
    jobs.running.push_back (job);

    _mcp_jobs_last_served = it->first;

    return job;
  }

  return nullptr;
}

// The response line, or "" when the call was cancelled.
static std::string
SK_MCP_RunJob (SK_MCP_Job& job)
{
  std::string line;

  _mcp_current_job = &job;

  try
  {
    line =
      SK_MCP_ResponseLine (job.id, SK_MCP_HandleToolsCall (job.params));
  }

  catch (const SK_MCP_Cancelled&)
  {
  }

  catch (const std::exception&)
  {
    line =
      SK_MCP_ResponseLine ( job.id,
        SK_MCP_MakeToolResult ("could not serialize the result", true) );
  }

  _mcp_current_job = nullptr;

  return line;
}

static DWORD
WINAPI
SK_MCP_WorkerThread (LPVOID)
{
  for (;;)
  {
    SK_MCP_JobPtr job;

    {
      std::unique_lock lock (_mcp_jobs_lock);

      _mcp_jobs_cv.wait (lock, [&]
      {
        if (_mcp_workers_stop)
          return true;

        job = SK_MCP_PickJob ();

        return job != nullptr;
      });

      // Stop leaves queued jobs behind; the listener has cancelled them all.
      if (job == nullptr)
        break;
    }

    std::string line =
      SK_MCP_RunJob (*job);

    {
      std::scoped_lock lock (_mcp_jobs_lock);

      auto it =
        _mcp_jobs.find (job->client);

      if (it != _mcp_jobs.end ())
      {
        std::erase (it->second.running, job);

        if (it->second.running.empty () && it->second.queued.empty ())
          _mcp_jobs.erase (it);
      }
    }

    // A freed running slot may make another client's queued job runnable.
    _mcp_jobs_cv.notify_all ();

    {
      std::scoped_lock lock (_mcp_done_lock);

      _mcp_done.push_back ({ job, std::move (line) });

      WSASetEvent (_mcp_ev_done);
    }
  }

  return 0;
}

static void
SK_MCP_StopWorkers (void)
{
  {
    std::scoped_lock lock (_mcp_jobs_lock);

    _mcp_workers_stop = true;
  }

  _mcp_jobs_cv.notify_all ();

  // No timeout: a worker stuck in sk_call_function keeps the listener alive,
  //   which is what makes SK_MCP_Start refuse to restart over it.
  if (_mcp_worker_count > 0)
    WaitForMultipleObjects (_mcp_worker_count, _mcp_workers, TRUE, INFINITE);

  for (DWORD i = 0; i < _mcp_worker_count; ++i)
  {
    CloseHandle (_mcp_workers [i]);
                 _mcp_workers [i] = nullptr;
  }

  _mcp_worker_count = 0;

  {
    std::scoped_lock lock (_mcp_jobs_lock);

    _mcp_jobs.clear ();
  }

  {
    std::scoped_lock lock (_mcp_done_lock);

    _mcp_done.clear ();
  }
}

static bool
SK_MCP_StartWorkers (void)
{
  static constexpr const wchar_t* wszNames [SK_MCP_WorkerCount] = {
    L"[SK] MCP Worker 1", L"[SK] MCP Worker 2",
    L"[SK] MCP Worker 3", L"[SK] MCP Worker 4"
  };

  {
    std::scoped_lock lock (_mcp_jobs_lock);

    _mcp_workers_stop = false;
  }

  for (auto wszName : wszNames)
  {
    HANDLE hThread =
      SK_Thread_CreateEx (SK_MCP_WorkerThread, wszName);

    if (hThread == nullptr || hThread == INVALID_HANDLE_VALUE)
    {
      SK_MCP_StopWorkers ();

      return false;
    }

    _mcp_workers [_mcp_worker_count++] = hThread;
  }

  return true;
}

// Sets the cancel flag on the client's jobs whose request id matches id_key,
//   or on all of them when id_key is null, and removes the queued ones.
//   Returns how many queued jobs were removed.
static int
SK_MCP_CancelJobs (uint64_t client, const std::string* id_key)
{
  std::scoped_lock lock (_mcp_jobs_lock);

  auto it =
    _mcp_jobs.find (client);

  if (it == _mcp_jobs.end ())
    return 0;

  auto matches = [&](const SK_MCP_JobPtr& job)
  {
    return
      id_key == nullptr || job->id_key == *id_key;
  };

  int removed = 0;

  auto& queued = it->second.queued;

  for (auto job = queued.begin (); job != queued.end (); )
  {
    if (matches (*job))
    {
      InterlockedExchange (&(*job)->cancelled, TRUE);

      job = queued.erase (job);
      ++removed;
    }

    else
      ++job;
  }

  for (auto& job : it->second.running)
  {
    if (matches (job))
      InterlockedExchange (&job->cancelled, TRUE);
  }

  if (it->second.running.empty () && queued.empty ())
    _mcp_jobs.erase (it);

  return removed;
}

static void
SK_MCP_CancelAllJobs (void)
{
  std::scoped_lock lock (_mcp_jobs_lock);

  for (auto& entry : _mcp_jobs)
  {
    for (auto& job : entry.second.queued)  InterlockedExchange (&job->cancelled, TRUE);
    for (auto& job : entry.second.running) InterlockedExchange (&job->cancelled, TRUE);

    entry.second.queued.clear ();
  }
}


//
// Client I/O, all on the listener thread
//

static size_t
SK_MCP_Unsent (const SK_MCP_Client& client)
{
  return
    client.output.size () - client.output_sent;
}

// Writes as much as send accepts, without ever waiting.
static void
SK_MCP_WriteClient (SK_MCP_Client& client)
{
  while ( (! client.dead)          &&
          (! client.write_blocked) && SK_MCP_Unsent (client) > 0 )
  {
    const int result =
      send ( client.sock, client.output.data () + client.output_sent,
               static_cast <int> (std::min (SK_MCP_Unsent (client), size_t { 1024 * 1024 })), 0 );

    if (result > 0)
    {
      client.output_sent += static_cast <size_t> (result);
      continue;
    }

    if (result == SOCKET_ERROR && WSAGetLastError () == WSAEWOULDBLOCK)
      client.write_blocked = true;
    else
      client.dead          = true;
  }

  if (SK_MCP_Unsent (client) == 0)
  {
    client.output.clear ();
    client.output_sent = 0;
  }
}

static void
SK_MCP_Send (SK_MCP_Client& client, const std::string& line)
{
  if (client.dead)
    return;

  if (client.output_sent > 0 && client.output_sent >= client.output.size () / 2)
  {
    client.output.erase (0, client.output_sent);
    client.output_sent = 0;
  }

  client.output += line;

  if (SK_MCP_Unsent (client) > SK_MCP_MaxOutboundBytes)
  {
    SK_LOG0 ( ( L"Client %llu has more than 16 MiB of unsent output; closing it",
                  client.id ), SK_MCP_LOG_SRC );

    client.dead = true;

    return;
  }

  SK_MCP_WriteClient (client);
}

// Sends the response or error line first, then drains and closes; any later
//   input is discarded and the client's calls are cancelled.
static void
SK_MCP_BeginClose (SK_MCP_Client& client)
{
  if (client.closing)
    return;

  client.closing      = true;
  client.closing_tick = GetTickCount64 ();
  client.input.clear ();

  client.in_flight -=
    SK_MCP_CancelJobs (client.id, nullptr);
}

static void
SK_MCP_Refuse (SK_MCP_Client& client, const char* reason)
{
  SK_LOG0 ( ( L"Refused client %llu: %hs", client.id, reason ), SK_MCP_LOG_SRC );

  SK_MCP_BeginClose (client);
}

static void
SK_MCP_FlushQueue (SK_MCP_Client& client)
{
  std::deque <std::string> pending;

  {
    std::scoped_lock lock (_mcp_queue_lock);

    pending.swap (_mcp_queue);
  }

  for (const auto& line : pending)
    SK_MCP_Send (client, line);
}

static void
SK_MCP_DropChannel (SK_MCP_Client& client)
{
  client.channel = false;

  SK_LOG0 ( ( L"Channel client %llu disconnected", client.id ), SK_MCP_LOG_SRC );
}

// The live channel client, if any.  A holder that died earlier in this
//   iteration gives the channel up here, so a claim never sees two holders.
static SK_MCP_Client*
SK_MCP_ChannelClient (void)
{
  for (auto& client : _mcp_clients)
  {
    if (! client->channel)
      continue;

    if (client->dead)
    {
      SK_MCP_DropChannel (*client);
      continue;
    }

    return client.get ();
  }

  return nullptr;
}

static size_t
SK_MCP_PlainClientCount (void)
{
  return static_cast <size_t> (
    std::count_if ( _mcp_clients.cbegin (), _mcp_clients.cend (),
      [](const auto& client)
      {
        return client->authenticated && (! client->channel) &&
          (! client->closing)        && (! client->dead);
      }
    ) );
}

static void
SK_MCP_TakeChannel (SK_MCP_Client& client)
{
  client.channel = true;

  SK_LOG0 ( ( L"Client %llu holds the channel", client.id ), SK_MCP_LOG_SRC );
}

static void
SK_MCP_Evict (SK_MCP_Client& holder)
{
  static const std::string evicted =
    json ({
      { "jsonrpc", "2.0"                            },
      { "method",  "notifications/specialk/evicted" },
      { "params",  { { "reason", "another channel client connected" } } }
    }).dump () + "\n";

  // Anything already queued for it stays ahead of the notice.
  holder.channel = false;

  SK_MCP_Send       (holder, evicted);
  SK_MCP_BeginClose (holder);

  SK_LOG0 ( ( L"Client %llu evicted: another channel client connected",
                holder.id ), SK_MCP_LOG_SRC );
}

// Authenticates client with its first message.  False once it has been
//   refused.  took_channel is set when it became the channel client.
static bool
SK_MCP_Authenticate ( SK_MCP_Client&     client,
                      const std::string& method,
                      const json&        id,
                      const json&        params,
                      bool&              took_channel )
{
  std::string presented;

  if (params.is_object ())
  {
    const auto token = params.find ("token");

    if (token != params.cend () && token->is_string ())
      presented = token->get <std::string> ();
  }

  if (method != "initialize" || (! SK_MCP_TokenMatches (presented)))
  {
    SK_MCP_Send   (client, SK_MCP_ErrorLine (id, -32000, "unauthorized"));
    SK_MCP_Refuse (client, "unauthorized");

    return false;
  }

  bool claim   = false,
       if_free = false;

  const auto channel =
    params.find ("channel");

  if (channel != params.cend ())
  {
    if      (channel->is_boolean ())                          claim   = channel->get <bool> ();
    else if (channel->is_string  () && *channel == "if_free") if_free = true;
    else
    {
      SK_MCP_Send   (client, SK_MCP_ErrorLine (id, -32602, "channel must be true, false or \"if_free\""));
      SK_MCP_Refuse (client, "invalid channel value");

      return false;
    }
  }

  SK_MCP_Client* holder =
    SK_MCP_ChannelClient ();

  const bool as_channel =
    claim || (if_free && holder == nullptr);

  if ((! as_channel) && SK_MCP_PlainClientCount () >= SK_MCP_MaxPlainClients)
  {
    SK_MCP_Send   (client, SK_MCP_ErrorLine (id, -32000, "client limit reached"));
    SK_MCP_Refuse (client, "client limit reached");

    return false;
  }

  client.authenticated = true;

  if (as_channel)
  {
    if (holder != nullptr)
      SK_MCP_Evict (*holder);

    SK_MCP_TakeChannel (client);

    took_channel = true;
  }

  else
  {
    SK_LOG0 ( ( L"Client %llu authenticated as a plain client", client.id ),
                SK_MCP_LOG_SRC );
  }

  return true;
}

static void
SK_MCP_QueueCall (SK_MCP_Client& client, const json& id, const json& params)
{
  if (client.in_flight >= SK_MCP_MaxCallsInFlight)
  {
    SK_MCP_Send ( client,
      SK_MCP_ResponseLine ( id,
        SK_MCP_MakeToolResult ("too many calls in flight (16); wait for some to finish", true)
      )
    );

    return;
  }

  auto job =
    std::make_shared <SK_MCP_Job> ();

  job->client = client.id;
  job->id     = id;
  job->id_key = id.dump ();
  job->params = params;

  {
    std::scoped_lock lock (_mcp_jobs_lock);

    _mcp_jobs [client.id].queued.push_back (job);
  }

  _mcp_jobs_cv.notify_all ();

  ++client.in_flight;
}

static void
SK_MCP_HandleCancelled (SK_MCP_Client& client, const json& params)
{
  if ((! params.is_object ()) || (! params.contains ("requestId")))
    return;

  const std::string id_key =
    params.at ("requestId").dump ();

  client.in_flight -=
    SK_MCP_CancelJobs (client.id, &id_key);
}

static void
SK_MCP_HandleLine (SK_MCP_Client& client, const std::string& line)
{
  const json message =
    json::parse (line, nullptr, false);

  if (message.is_discarded () || (! message.is_object ()))
  {
    SK_MCP_Send (client, SK_MCP_ErrorLine (json (nullptr), -32700, "Parse error"));

    // An unauthenticated peer does not get to retry.
    if (! client.authenticated)
      SK_MCP_Refuse (client, "parse error before authenticating");

    return;
  }

  const auto method_it = message.find ("method");
  const auto id_it     = message.find ("id");

  const json  id     = (id_it != message.cend ()) ? *id_it : json (nullptr);
  std::string method;

  if (method_it != message.cend () && method_it->is_string ())
    method = method_it->get <std::string> ();

  const json params =
    message.contains ("params") ? message.at ("params")
                                : json::object ();

  bool took_channel = false;

  // Every connection authenticates in its first message.
  if (! client.authenticated)
  {
    if (! SK_MCP_Authenticate (client, method, id, params, took_channel))
      return;
  }

  // Other notifications are accepted and ignored.
  if (id_it == message.cend ())
  {
    if (method == "notifications/cancelled")
      SK_MCP_HandleCancelled (client, params);
  }

  else if (method == "initialize")
    SK_MCP_Send (client, SK_MCP_ResponseLine (id, SK_MCP_HandleInitialize (params, client.channel)));

  else if (method == "ping")
    SK_MCP_Send (client, SK_MCP_ResponseLine (id, json::object ()));

  else if (method == "tools/list")
    SK_MCP_Send (client, SK_MCP_ResponseLine (id, SK_MCP_HandleToolsList ()));

  else if (method == "tools/call")
    SK_MCP_QueueCall (client, id, params);

  else if (method == "specialk/claim_channel")
  {
    // Never evicts.
    if ((! client.channel) && SK_MCP_ChannelClient () == nullptr)
    {
      SK_MCP_TakeChannel (client);

      took_channel = true;
    }

    SK_MCP_Send (client, SK_MCP_ResponseLine (id, { { "channel", client.channel } }));
  }

  else
    SK_MCP_Send (client, SK_MCP_ErrorLine (id, -32601, "Method not found"));

  // Queued notifications follow the response that granted the channel.
  if (took_channel)
    SK_MCP_FlushQueue (client);
}

// Consumes every complete line in the input buffer.
static void
SK_MCP_DispatchBuffered (SK_MCP_Client& client)
{
  size_t newline;

  while ( (! client.closing) && (! client.dead) &&
          (newline = client.input.find ('\n')) != std::string::npos )
  {
    std::string line =
      client.input.substr (0, newline);

    client.input.erase (0, newline + 1);

    if ((! line.empty ()) && line.back () == '\r')
      line.pop_back ();

    if (line.empty ())
      continue;

    SK_MCP_HandleLine (client, line);
  }

  if (client.closing || client.dead)
  {
    client.input.clear ();
    return;
  }

  if (client.input.size () > SK_MCP_MaxLineLength)
  {
    SK_LOG0 ( ( L"Client %llu sent a line longer than 1 MiB", client.id ),
                SK_MCP_LOG_SRC );

    client.dead = true;
  }
}

// Reads up to SK_MCP_ReadBudgetBytes.  A closing client's input is read and
//   discarded, for the reason SK_MCP_CloseClient gives.
static void
SK_MCP_ReadClient (SK_MCP_Client& client)
{
  char   data [8192];
  size_t budget = SK_MCP_ReadBudgetBytes;

  client.read_more = false;

  while (! client.dead)
  {
    if (budget == 0)
    {
      client.read_more = true;
      break;
    }

    const int result =
      recv (client.sock, data, static_cast <int> (std::min (sizeof (data), budget)), 0);

    if (result > 0)
    {
      budget -= static_cast <size_t> (result);

      if (client.closing)
        continue;

      client.input.append (data, static_cast <size_t> (result));

      // Dispatching inside the drain keeps the buffer down to one unterminated
      //   line plus the chunk just read, so the 1 MiB cap cannot be outrun.
      SK_MCP_DispatchBuffered (client);

      continue;
    }

    // 0 is an orderly shutdown.
    if (result == 0 || WSAGetLastError () != WSAEWOULDBLOCK)
      client.dead = true;

    break;
  }
}

static void
SK_MCP_ServiceClient (SK_MCP_Client& client)
{
  WSANETWORKEVENTS network_events = { };

  if (SOCKET_ERROR == WSAEnumNetworkEvents (client.sock, client.event, &network_events))
  {
    client.dead = true;
    return;
  }

  if (network_events.lNetworkEvents & FD_WRITE)
    client.write_blocked = false;

  if ((network_events.lNetworkEvents & FD_READ) || client.read_more)
    SK_MCP_ReadClient (client);

  if (network_events.lNetworkEvents & FD_CLOSE)
    client.dead = true;

  SK_MCP_WriteClient (client);
}

// Cancels its jobs, releases its scan sessions and closes the socket, in that
//   order: a scan that finishes after this sees its cancel flag set.
static void
SK_MCP_CloseClient (SK_MCP_Client& client)
{
  SK_MCP_CancelJobs (client.id, nullptr);

  if (client.authenticated)
    SK_MCP_OnClientDisconnected (client.id);

  const SOCKET sock =
    SK_MCP_TakeSocket (&_mcp_client_socks [client.slot]);

  if (sock != INVALID_SOCKET)
  {
    if (client.drained)
    {
      // Unread input goes first, or the close would reset the connection and
      //   could destroy output the peer has not read yet.
      char   data [8192];
      size_t budget = SK_MCP_ReadBudgetBytes;

      while (budget > 0)
      {
        const int result =
          recv (sock, data, static_cast <int> (sizeof (data)), 0);

        if (result <= 0)
          break;

        budget -= std::min (budget, static_cast <size_t> (result));
      }

      shutdown (sock, SD_SEND);
    }

    closesocket (sock);
  }

  WSACloseEvent (client.event);

  client.sock  = INVALID_SOCKET;
  client.event = WSA_INVALID_EVENT;

  SK_LOG0 ( ( L"Client %llu disconnected", client.id ), SK_MCP_LOG_SRC );

  if (client.channel)
    SK_MCP_DropChannel (client);
}

static void
SK_MCP_AcceptClient (SOCKET accepted)
{
  if (_mcp_clients.size () >= SK_MCP_MaxConnections)
  {
    SK_LOG0 ( ( L"Refused a connection: %zu connections are open",
                  _mcp_clients.size () ), SK_MCP_LOG_SRC );

    closesocket (accepted);

    return;
  }

  const BOOL keepalive = TRUE;

  setsockopt ( accepted, SOL_SOCKET, SO_KEEPALIVE,
                 reinterpret_cast <const char *> (&keepalive), sizeof (keepalive) );

  const WSAEVENT event =
    WSACreateEvent ();

  // The accepted socket inherits the listener's event selection until this.
  if ( event == WSA_INVALID_EVENT ||
       SOCKET_ERROR == WSAEventSelect (accepted, event, FD_READ | FD_WRITE | FD_CLOSE) )
  {
    SK_LOG0 ( ( L"Refused a connection: %hs",
                  SK_MCP_WSAErrorString ("WSAEventSelect failed", WSAGetLastError ()).c_str () ),
                SK_MCP_LOG_SRC );

    closesocket (accepted);

    if (event != WSA_INVALID_EVENT)
      WSACloseEvent (event);

    return;
  }

  bool used [SK_MCP_MaxConnections] = { };

  for (const auto& client : _mcp_clients)
    used [client->slot] = true;

  const size_t slot =
    static_cast <size_t> (std::find (std::begin (used), std::end (used), false) - std::begin (used));

  auto client =
    std::make_unique <SK_MCP_Client> ();

  client->id          = _mcp_next_client_id++;
  client->slot        = slot;
  client->sock        = accepted;
  client->event       = event;
  client->accept_tick = GetTickCount64 ();

  SK_MCP_StoreSocket (&_mcp_client_socks [slot], accepted);

  SK_LOG0 ( ( L"Client %llu connected", client->id ), SK_MCP_LOG_SRC );

  _mcp_clients.emplace_back (std::move (client));
}

// False on a listener error, which stops the server.
static bool
SK_MCP_AcceptClients (void)
{
  WSANETWORKEVENTS network_events = { };

  if (SOCKET_ERROR == WSAEnumNetworkEvents (_mcp_listen_sock, _mcp_ev_accept, &network_events))
  {
    SK_MCP_SetLastError (
      SK_MCP_WSAErrorString ("WSAEnumNetworkEvents failed", WSAGetLastError ())
    );

    return false;
  }

  if (! (network_events.lNetworkEvents & FD_ACCEPT))
    return true;

  for (;;)
  {
    const SOCKET accepted =
      accept (_mcp_listen_sock, nullptr, nullptr);

    if (accepted == INVALID_SOCKET)
    {
      const int err =
        WSAGetLastError ();

      if (err != WSAEWOULDBLOCK)
      {
        SK_LOG0 ( ( L"%hs", SK_MCP_WSAErrorString ("accept failed", err).c_str () ),
                    SK_MCP_LOG_SRC );
      }

      return true;
    }

    SK_MCP_AcceptClient (accepted);
  }
}

static void
SK_MCP_DrainCompletions (void)
{
  // Reset before draining, so a completion pushed meanwhile signals again.
  WSAResetEvent (_mcp_ev_done);

  std::deque <SK_MCP_Completion> done;

  {
    std::scoped_lock lock (_mcp_done_lock);

    done.swap (_mcp_done);
  }

  for (auto& completion : done)
  {
    const auto client =
      std::find_if ( _mcp_clients.begin (), _mcp_clients.end (),
        [&](const auto& c) { return c->id == completion.job->client; } );

    // A result for a client that has gone is dropped.
    if (client == _mcp_clients.end ())
      continue;

    --(*client)->in_flight;

    if ( (*client)->closing || completion.line.empty () ||
         ReadAcquire (&completion.job->cancelled) != FALSE )
    {
      continue;
    }

    SK_MCP_Send (**client, completion.line);
  }
}

static void
SK_MCP_FlushNotifications (void)
{
  // A notification pushed after the reset signals again.
  WSAResetEvent (_mcp_ev_notify);

  // Without a channel client the entries wait for one.
  if (SK_MCP_Client* channel = SK_MCP_ChannelClient ())
    SK_MCP_FlushQueue (*channel);
}

static void
SK_MCP_ExpireDeadlines (void)
{
  const ULONGLONG now =
    GetTickCount64 ();

  for (auto& client : _mcp_clients)
  {
    if (client->dead)
      continue;

    if (client->closing)
    {
      if (SK_MCP_Unsent (*client) == 0)
      {
        client->drained = true;
        client->dead    = true;
      }

      else if (now - client->closing_tick >= SK_MCP_DrainTimeoutMs)
      {
        SK_LOG0 ( ( L"Client %llu did not drain its output within 2 s",
                      client->id ), SK_MCP_LOG_SRC );

        client->dead = true;
      }
    }

    else if ( (! client->authenticated) &&
              now - client->accept_tick >= SK_MCP_AuthTimeoutMs )
    {
      SK_LOG0 ( ( L"Refused client %llu: did not authenticate within 10 s",
                    client->id ), SK_MCP_LOG_SRC );

      client->dead = true;
    }
  }
}

// WSA_INFINITE when nothing is due.
static DWORD
SK_MCP_WaitTimeout (void)
{
  const ULONGLONG now =
    GetTickCount64 ();

  ULONGLONG due = ULLONG_MAX;

  for (const auto& client : _mcp_clients)
  {
    if (client->read_more)
      return 0;

    if (client->closing)
      due = std::min (due, client->closing_tick + SK_MCP_DrainTimeoutMs);

    else if (! client->authenticated)
      due = std::min (due, client->accept_tick  + SK_MCP_AuthTimeoutMs);
  }

  if (due == ULLONG_MAX)
    return WSA_INFINITE;

  if (due <= now)
    return 0;

  return
    static_cast <DWORD> (due - now);
}

static void
SK_MCP_SweepClients (void)
{
  for (auto& client : _mcp_clients)
  {
    if (client->dead)
      SK_MCP_CloseClient (*client);
  }

  std::erase_if (_mcp_clients, [](const auto& client) { return client->dead; });

  InterlockedExchange (&_mcp_has_channel,
    std::any_of ( _mcp_clients.cbegin (), _mcp_clients.cend (),
                    [](const auto& client) { return client->channel; } ) ? TRUE
                                                                         : FALSE);

  InterlockedExchange (&_mcp_other_clients,
    static_cast <LONG> (SK_MCP_PlainClientCount ()));
}

static DWORD
WINAPI
SK_MCP_ListenerThread (LPVOID)
{
  while (true)
  {
    WSAEVENT events [4 + SK_MCP_MaxConnections] = {
      _mcp_ev_stop, _mcp_ev_notify, _mcp_ev_accept, _mcp_ev_done
    };

    DWORD count = 4;

    for (const auto& client : _mcp_clients)
      events [count++] = client->event;

    const DWORD dwWait =
      WSAWaitForMultipleEvents (count, events, FALSE, SK_MCP_WaitTimeout (), FALSE);

    if (dwWait == WSA_WAIT_EVENT_0)   // stop
      break;

    if ( dwWait != WSA_WAIT_TIMEOUT &&
        (dwWait <  WSA_WAIT_EVENT_0 || dwWait >= WSA_WAIT_EVENT_0 + count) )
    {
      SK_MCP_SetLastError (
        SK_MCP_WSAErrorString ("WSAWaitForMultipleEvents failed", WSAGetLastError ())
      );

      break;
    }

    // The wait reports only the lowest signalled event, so every source is
    //   serviced on every pass; a busy low slot cannot starve a higher one.
    if (! SK_MCP_AcceptClients ())
      break;

    SK_MCP_DrainCompletions   ();
    SK_MCP_FlushNotifications ();

    // Indexed: nothing here adds clients.
    for (size_t i = 0; i < _mcp_clients.size (); ++i)
    {
      if (! _mcp_clients [i]->dead)
        SK_MCP_ServiceClient (*_mcp_clients [i]);
    }

    SK_MCP_ExpireDeadlines ();
    SK_MCP_SweepClients    ();
  }

  SK_MCP_CancelAllJobs ();

  for (auto& client : _mcp_clients)
    SK_MCP_CloseClient (*client);

  _mcp_clients.clear ();

  InterlockedExchange (&_mcp_has_channel,   FALSE);
  InterlockedExchange (&_mcp_other_clients, 0);

  SK_MCP_StopWorkers ();

  const SOCKET listen_sock =
    SK_MCP_TakeSocket (&_mcp_listen_sock);

  if (listen_sock != INVALID_SOCKET)
    closesocket (listen_sock);

  InterlockedExchange (&_mcp_running, FALSE);

  SK_LOG0 ( ( L"MCP server stopped" ), SK_MCP_LOG_SRC );

  return 0;
}


static bool
SK_MCP_CreateEvents (void)
{
  WSAEVENT* pEvents [] = {
    &_mcp_ev_stop, &_mcp_ev_notify, &_mcp_ev_accept, &_mcp_ev_done
  };

  for (auto* pEvent : pEvents)
  {
    if (*pEvent == WSA_INVALID_EVENT)
        *pEvent  = WSACreateEvent ();

    if (*pEvent == WSA_INVALID_EVENT)
      return false;
  }

  WSAResetEvent (_mcp_ev_stop);
  WSAResetEvent (_mcp_ev_accept);
  WSAResetEvent (_mcp_ev_done);

  return true;
}

static void
SK_MCP_CloseEvents (void)
{
  WSAEVENT* pEvents [] = {
    &_mcp_ev_stop, &_mcp_ev_notify, &_mcp_ev_accept, &_mcp_ev_done
  };

  // SK_MCP_Notify signals _mcp_ev_notify under this lock.
  std::scoped_lock lock (_mcp_queue_lock);

  for (auto* pEvent : pEvents)
  {
    if (*pEvent != WSA_INVALID_EVENT)
    {
      WSACloseEvent (*pEvent);
                     *pEvent = WSA_INVALID_EVENT;
    }
  }
}

bool
SK_MCP_IsRunning (void)
{
  return
    ReadAcquire (&_mcp_running) != FALSE;
}

bool
SK_MCP_IsClientConnected (void)
{
  return
    ReadAcquire (&_mcp_has_channel) != FALSE;
}

int
SK_MCP_OtherClientCount (void)
{
  return
    ReadAcquire (&_mcp_other_clients);
}

const char*
SK_MCP_LastError (void)
{
  return
    _mcp_last_error;
}

// SK_MCP_Start, SK_MCP_Stop and SK_MCP_Shutdown assume a single caller: the
//   control panel thread, plus process teardown for Shutdown.  They are not
//   serialized against one another, so two threads calling them at once would
//   race over the events, the thread handle and the sockets.
bool
SK_MCP_Start (void)
{
  if (SK_MCP_IsRunning ())
    return true;

  // A listener that failed to exit during SK_MCP_Stop still owns the events.
  if (_mcp_thread != nullptr)
  {
    if (WAIT_OBJECT_0 != WaitForSingleObject (_mcp_thread, 0))
    {
      SK_MCP_SetLastError ("the previous listener thread has not exited");

      return false;
    }

    CloseHandle (_mcp_thread);
                 _mcp_thread = nullptr;
  }

  static bool winsock_started = false;

  if (! winsock_started)
  {
    WSADATA wsa_data = { };

    const int result =
      WSAStartup (MAKEWORD (2, 2), &wsa_data);

    if (result != 0)
    {
      SK_MCP_SetLastError (SK_MCP_WSAErrorString ("WSAStartup failed", result));

      return false;
    }

    // Never WSACleanup: the game may be using Winsock as well.
    winsock_started = true;
  }

  if (config.mcp.token.empty ())
  {
    std::wstring token;

    if (! SK_MCP_GenerateToken (token))
    {
      SK_MCP_SetLastError ("BCryptGenRandom failed, no token generated");

      return false;
    }

    config.mcp.token = token;
    config.utility.save_async ();
  }

  if (! SK_MCP_CreateEvents ())
  {
    SK_MCP_SetLastError (SK_MCP_WSAErrorString ("WSACreateEvent failed", WSAGetLastError ()));
    SK_MCP_CloseEvents  ();

    return false;
  }

  if (config.mcp.port < 1 || config.mcp.port > 65535)
  {
    char szPort [64] = { };

    snprintf (szPort, sizeof (szPort), "port %d is out of range (1..65535)",
                                         config.mcp.port);

    SK_MCP_SetLastError (szPort);

    SK_MCP_CloseEvents ();

    return false;
  }

  const SOCKET listener =
    socket (AF_INET, SOCK_STREAM, 0);

  if (listener == INVALID_SOCKET)
  {
    SK_MCP_SetLastError (SK_MCP_WSAErrorString ("socket failed", WSAGetLastError ()));
    SK_MCP_CloseEvents  ();

    return false;
  }

  sockaddr_in addr     = { };
              addr.sin_family = AF_INET;
              addr.sin_port   = htons (static_cast <u_short> (config.mcp.port));

  if (1 != InetPtonW (AF_INET, config.mcp.bind_address.c_str (), &addr.sin_addr))
  {
    SK_MCP_SetLastError ("invalid bind address");

    closesocket        (listener);
    SK_MCP_CloseEvents ();

    return false;
  }

  // No SO_REUSEADDR: a stale bind means another instance is still listening.
  if (SOCKET_ERROR == bind (listener, reinterpret_cast <sockaddr *> (&addr), sizeof (addr)))
  {
    SK_MCP_SetLastError (SK_MCP_WSAErrorString ("bind failed", WSAGetLastError ()));

    closesocket        (listener);
    SK_MCP_CloseEvents ();

    return false;
  }

  if (config.mcp.bind_address != L"127.0.0.1")
  {
    SK_LOG0 ( ( L"MCP server is bound to %ws; anything that can reach this "
                L"address can use the token", config.mcp.bind_address.c_str () ),
                SK_MCP_LOG_SRC );
  }

  if (SOCKET_ERROR == listen (listener, 8))
  {
    SK_MCP_SetLastError (SK_MCP_WSAErrorString ("listen failed", WSAGetLastError ()));

    closesocket        (listener);
    SK_MCP_CloseEvents ();

    return false;
  }

  if (SOCKET_ERROR == WSAEventSelect (listener, _mcp_ev_accept, FD_ACCEPT))
  {
    SK_MCP_SetLastError (SK_MCP_WSAErrorString ("WSAEventSelect failed", WSAGetLastError ()));

    closesocket        (listener);
    SK_MCP_CloseEvents ();

    return false;
  }

  // The listener joins them before it exits.
  if (! SK_MCP_StartWorkers ())
  {
    SK_MCP_SetLastError ("could not create the worker threads");

    closesocket        (listener);
    SK_MCP_CloseEvents ();

    return false;
  }

  _mcp_listen_sock = listener;

  InterlockedExchange (&_mcp_running, TRUE);

  _mcp_thread =
    SK_Thread_CreateEx (SK_MCP_ListenerThread, L"[SK] MCP Server");

  if (_mcp_thread == nullptr || _mcp_thread == INVALID_HANDLE_VALUE)
  {
    InterlockedExchange (&_mcp_running, FALSE);

    _mcp_thread      = nullptr;
    _mcp_listen_sock = INVALID_SOCKET;

    SK_MCP_SetLastError ("could not create the listener thread");

    SK_MCP_StopWorkers ();
    closesocket        (listener);
    SK_MCP_CloseEvents ();

    return false;
  }

  *_mcp_last_error = '\0';

  SK_LOG0 ( ( L"MCP server listening on %ws:%d", config.mcp.bind_address.c_str (),
                                                 config.mcp.port ), SK_MCP_LOG_SRC );

  return true;
}

// Single-caller, like SK_MCP_Start.
void
SK_MCP_Stop (void)
{
  if (_mcp_thread == nullptr)
  {
    InterlockedExchange (&_mcp_running, FALSE);

    return;
  }

  if (_mcp_ev_stop != WSA_INVALID_EVENT)
      WSASetEvent (_mcp_ev_stop);

  if (WAIT_OBJECT_0 != WaitForSingleObject (_mcp_thread, 5000UL))
  {
    // Leave the events allocated; the thread may still be using them.
    SK_LOG0 ( ( L"MCP listener thread did not exit within 5 seconds" ), SK_MCP_LOG_SRC );

    InterlockedExchange (&_mcp_running, FALSE);

    return;
  }

  CloseHandle (_mcp_thread);
               _mcp_thread = nullptr;

  SK_MCP_CloseEvents ();

  InterlockedExchange (&_mcp_running, FALSE);
}

// Single-caller, like SK_MCP_Start.  The render job queue is deliberately
//   untouched: it outlives the server and costs nothing when idle.
void
SK_MCP_Shutdown (void)
{
  // SK_ShutdownCore runs under the loader lock, so this never waits.
  if (_mcp_ev_stop != WSA_INVALID_EVENT)
      WSASetEvent (_mcp_ev_stop);

  for (auto& slot : _mcp_client_socks)
  {
    const SOCKET client_sock =
      SK_MCP_TakeSocket (&slot);

    if (client_sock != INVALID_SOCKET)
      closesocket (client_sock);
  }

  const SOCKET listen_sock =
    SK_MCP_TakeSocket (&_mcp_listen_sock);

  if (listen_sock != INVALID_SOCKET)
    closesocket (listen_sock);

  InterlockedExchange (&_mcp_has_channel,   FALSE);
  InterlockedExchange (&_mcp_other_clients, 0);
  InterlockedExchange (&_mcp_running,       FALSE);
}

void
SK_MCP_Init (void)
{
  // The registry is read-only once the listener is running.
  SK_MCP_RegisterProcessTools ();
  SK_MCP_RegisterMemoryTools  ();
  SK_MCP_RegisterSymbolTools  ();
  SK_MCP_RegisterScanTools    ();
  SK_MCP_RegisterExecTools    ();

  if (config.mcp.enabled)
    SK_MCP_Start ();
}
