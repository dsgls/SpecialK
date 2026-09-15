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

#include <deque>
#include <mutex>

using json = nlohmann::json;

#define SK_MCP_LOG_SRC L" MCP-Srv "

// A line longer than this is a protocol violation and drops the connection.
static constexpr size_t SK_MCP_MaxLineLength =  1024 * 1024;
static constexpr size_t SK_MCP_MaxQueueDepth =  256;

// Frozen by the wire protocol; the bridge keeps the same list.
static constexpr const char* SK_MCP_ProtocolVersions [] = {
  "2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"
};
static constexpr const char* SK_MCP_DefaultProtocolVersion = "2025-06-18";


struct SK_MCP_ClientState {
  SOCKET      sock          = INVALID_SOCKET;
  std::string buffer;
  bool        authenticated = false;
  bool        read_pending  = false;
};

static std::vector <SK_MCP_Tool> _mcp_tools;

static SK_Thread_HybridSpinlock  _mcp_queue_lock;
static std::deque <std::string>  _mcp_queue;   // Serialized notification lines

static          HANDLE _mcp_thread        = nullptr;
static volatile LONG   _mcp_running       = FALSE;
static volatile LONG   _mcp_has_client    = FALSE;
// Fixed storage: the control panel reads this pointer from another thread
//   every frame while the listener may be writing it.
static char            _mcp_last_error [256] = { };

static WSAEVENT _mcp_ev_stop   = WSA_INVALID_EVENT;
static WSAEVENT _mcp_ev_notify = WSA_INVALID_EVENT;
static WSAEVENT _mcp_ev_accept = WSA_INVALID_EVENT;
static WSAEVENT _mcp_ev_client = WSA_INVALID_EVENT;
static WSAEVENT _mcp_ev_dummy  = WSA_INVALID_EVENT;   // Never signalled

// Also read by SK_MCP_Shutdown, which closes them out from under the listener.
static volatile SOCKET _mcp_listen_sock = INVALID_SOCKET;
static volatile SOCKET _mcp_client_sock = INVALID_SOCKET;


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


static json
SK_MCP_MakeResponse (const json& id, const json& result)
{
  return {
    { "jsonrpc", "2.0"  },
    { "id",      id     },
    { "result",  result }
  };
}

static json
SK_MCP_MakeError (const json& id, int code, const char* message)
{
  return {
    { "jsonrpc", "2.0" },
    { "id",      id    },
    { "error",   { { "code", code }, { "message", message } } }
  };
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
SK_MCP_HandleInitialize (const json& params)
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
                           { "version", SK_GetVersionStrA () } } }
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
SK_MCP_HandleToolsCall (const json& params)
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

// Builds the response line (empty for a notification).  Returns false when the
//   connection must be closed once that line, if any, has been sent.
static bool
SK_MCP_HandleLine ( const std::string&   line,
                    SK_MCP_ClientState&  client,
                    std::string&         response )
{
  response.clear ();

  const json message =
    json::parse (line, nullptr, false);

  if (message.is_discarded () || (! message.is_object ()))
  {
    response =
      SK_MCP_MakeError (json (nullptr), -32700, "Parse error").dump () + "\n";

    // An unauthenticated peer does not get to retry.
    return client.authenticated;
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

  // Every connection authenticates in its first message.
  if (! client.authenticated)
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
      response =
        SK_MCP_MakeError (id, -32000, "unauthorized").dump () + "\n";

      return false;
    }

    client.authenticated = true;
  }

  // Notifications are accepted and ignored.
  if (id_it == message.cend ())
    return true;

  json result;

  if      (method == "initialize") result = SK_MCP_HandleInitialize (params);
  else if (method == "ping")       result = json::object ();
  else if (method == "tools/list") result = SK_MCP_HandleToolsList ();
  else if (method == "tools/call") result = SK_MCP_HandleToolsCall (params);
  else
  {
    response =
      SK_MCP_MakeError (id, -32601, "Method not found").dump () + "\n";

    return true;
  }

  response =
    SK_MCP_MakeResponse (id, result).dump () + "\n";

  return true;
}


// Sends the whole buffer, pumping the client event while the socket is full.
//   False means the connection has been lost or a stop was requested.
static bool
SK_MCP_SendAll (SK_MCP_ClientState& client, const std::string& data)
{
  size_t sent = 0;

  while (sent < data.size ())
  {
    const int result =
      send ( client.sock, data.data () + sent,
               static_cast <int> (data.size () - sent), 0 );

    if (result > 0)
    {
      sent += static_cast <size_t> (result);
      continue;
    }

    if (result == SOCKET_ERROR && WSAGetLastError () == WSAEWOULDBLOCK)
    {
      WSAEVENT events [2] = { _mcp_ev_stop, _mcp_ev_client };

      const DWORD dwWait =
        WSAWaitForMultipleEvents (2, events, FALSE, WSA_INFINITE, FALSE);

      if (dwWait != WSA_WAIT_EVENT_0 + 1)
        return false;

      WSANETWORKEVENTS network_events = { };

      if (SOCKET_ERROR == WSAEnumNetworkEvents (client.sock, _mcp_ev_client, &network_events))
        return false;

      // WSAEnumNetworkEvents consumed the read notification, so remember it;
      //   the caller drains the socket once this response is out.
      if (network_events.lNetworkEvents & FD_READ)
        client.read_pending = true;

      if (network_events.lNetworkEvents & FD_CLOSE)
        return false;

      continue;
    }

    return false;
  }

  return true;
}

// Moves the queue into a local and sends it with no lock held.
static bool
SK_MCP_FlushQueue (SK_MCP_ClientState& client)
{
  if (client.sock == INVALID_SOCKET)
    return true;

  std::deque <std::string> pending;

  {
    std::scoped_lock lock (_mcp_queue_lock);

    pending.swap (_mcp_queue);
  }

  while (! pending.empty ())
  {
    if (! SK_MCP_SendAll (client, pending.front ()))
    {
      // A send failure discards the remainder and closes the client.
      return false;
    }

    pending.pop_front ();
  }

  return true;
}

static void
SK_MCP_CloseClient (SK_MCP_ClientState& client, WSAEVENT* events)
{
  if (client.sock != INVALID_SOCKET)
  {
    closesocket (client.sock);

    SK_LOG0 ( ( L"Client disconnected" ), SK_MCP_LOG_SRC );
  }

  client.sock          = INVALID_SOCKET;
  client.authenticated = false;
  client.read_pending  = false;
  client.buffer.clear ();

  _mcp_client_sock = INVALID_SOCKET;
  events [3]       = _mcp_ev_dummy;

  InterlockedExchange (&_mcp_has_client, FALSE);
}

// Consumes every complete line in the buffer, answering one at a time.
//   False means the connection must be closed.
static bool
SK_MCP_DispatchBuffered (SK_MCP_ClientState& client)
{
  size_t newline;

  while ((newline = client.buffer.find ('\n')) != std::string::npos)
  {
    std::string line =
      client.buffer.substr (0, newline);

    client.buffer.erase (0, newline + 1);

    if ((! line.empty ()) && line.back () == '\r')
      line.pop_back ();

    if (line.empty ())
      continue;

    std::string response;

    const bool was_authenticated =
      client.authenticated;

    const bool keep_alive =
      SK_MCP_HandleLine (line, client, response);

    if (! response.empty ())
    {
      if (! SK_MCP_SendAll (client, response))
        return false;
    }

    if (! keep_alive)
      return false;

    // Queued notifications go out once the initialize response is written,
    //   and before any later request from this client is served.
    if (client.authenticated && (! was_authenticated))
    {
      if (! SK_MCP_FlushQueue (client))
        return false;
    }
  }

  if (client.buffer.size () > SK_MCP_MaxLineLength)
  {
    SK_LOG0 ( ( L"Client sent a line longer than 1 MiB" ), SK_MCP_LOG_SRC );

    return false;
  }

  return true;
}

static bool
SK_MCP_ReadClient (SK_MCP_ClientState& client)
{
  char  data [8192];
  bool  more = true;

  while (more)
  {
    const int result =
      recv (client.sock, data, sizeof (data), 0);

    if (result > 0)
    {
      client.buffer.append (data, static_cast <size_t> (result));

      // Dispatching inside the drain keeps the buffer down to one unterminated
      //   line plus the chunk just read, so the 1 MiB cap cannot be outrun.
      if (! SK_MCP_DispatchBuffered (client))
        return false;

      continue;
    }

    if (result == 0)   // Orderly shutdown
      return false;

    if (WSAGetLastError () != WSAEWOULDBLOCK)
      return false;

    more = false;
  }

  return true;
}

static void
SK_MCP_AcceptClient (SK_MCP_ClientState& client, WSAEVENT* events)
{
  const SOCKET accepted =
    accept (_mcp_listen_sock, nullptr, nullptr);

  if (accepted == INVALID_SOCKET)
    return;

  // One client at a time; the newcomer replaces the incumbent without notice.
  if (client.sock != INVALID_SOCKET)
    SK_MCP_CloseClient (client, events);

  if (SOCKET_ERROR == WSAEventSelect (accepted, _mcp_ev_client, FD_READ | FD_WRITE | FD_CLOSE))
  {
    closesocket (accepted);
    return;
  }

  client.sock          = accepted;
  client.authenticated = false;
  client.read_pending  = false;
  client.buffer.clear ();

  _mcp_client_sock = accepted;
  events [3]       = _mcp_ev_client;

  InterlockedExchange (&_mcp_has_client, TRUE);

  SK_LOG0 ( ( L"Client connected" ), SK_MCP_LOG_SRC );
}

static DWORD
WINAPI
SK_MCP_ListenerThread (LPVOID)
{
  SK_MCP_ClientState client;

  WSAEVENT events [4] = {
    _mcp_ev_stop, _mcp_ev_notify, _mcp_ev_accept, _mcp_ev_dummy
  };

  bool stopping = false;

  while (! stopping)
  {
    const DWORD dwWait =
      WSAWaitForMultipleEvents (4, events, FALSE, WSA_INFINITE, FALSE);

    if (dwWait < WSA_WAIT_EVENT_0 || dwWait >= WSA_WAIT_EVENT_0 + 4)
    {
      SK_MCP_SetLastError (
        SK_MCP_WSAErrorString ("WSAWaitForMultipleEvents failed", WSAGetLastError ())
      );

      break;
    }

    switch (dwWait - WSA_WAIT_EVENT_0)
    {
      case 0:   // stop
        stopping = true;
        break;

      case 1:   // notify
      {
        WSAResetEvent (_mcp_ev_notify);

        // A peer that has not authenticated gets nothing; the entries stay
        //   queued for the flush that follows its initialize response.
        if (client.sock != INVALID_SOCKET && client.authenticated)
        {
          if (! SK_MCP_FlushQueue (client))
                SK_MCP_CloseClient (client, events);
        }
      } break;

      case 2:   // accept
      {
        WSANETWORKEVENTS network_events = { };

        if (SOCKET_ERROR == WSAEnumNetworkEvents (_mcp_listen_sock, _mcp_ev_accept, &network_events))
        {
          SK_MCP_SetLastError (
            SK_MCP_WSAErrorString ("WSAEnumNetworkEvents failed", WSAGetLastError ())
          );

          stopping = true;
          break;
        }

        if (network_events.lNetworkEvents & FD_ACCEPT)
          SK_MCP_AcceptClient (client, events);
      } break;

      case 3:   // client
      {
        WSANETWORKEVENTS network_events = { };

        if (SOCKET_ERROR == WSAEnumNetworkEvents (client.sock, _mcp_ev_client, &network_events))
        {
          SK_MCP_CloseClient (client, events);
          break;
        }

        if (network_events.lNetworkEvents & FD_READ)
          client.read_pending = true;

        if (client.read_pending)
        {
          client.read_pending = false;

          if (! SK_MCP_ReadClient (client))
          {
            SK_MCP_CloseClient (client, events);
            break;
          }
        }

        if (network_events.lNetworkEvents & FD_CLOSE)
          SK_MCP_CloseClient (client, events);
      } break;
    }

    // A send may have consumed a read notification while it waited.
    while (client.sock != INVALID_SOCKET && client.read_pending)
    {
      client.read_pending = false;

      if (! SK_MCP_ReadClient (client))
            SK_MCP_CloseClient (client, events);
    }
  }

  SK_MCP_CloseClient (client, events);

  if (_mcp_listen_sock != INVALID_SOCKET)
  {
    closesocket (_mcp_listen_sock);
                 _mcp_listen_sock = INVALID_SOCKET;
  }

  InterlockedExchange (&_mcp_running, FALSE);

  SK_LOG0 ( ( L"MCP server stopped" ), SK_MCP_LOG_SRC );

  return 0;
}


static bool
SK_MCP_CreateEvents (void)
{
  WSAEVENT* pEvents [] = {
    &_mcp_ev_stop, &_mcp_ev_notify, &_mcp_ev_accept, &_mcp_ev_client, &_mcp_ev_dummy
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
  WSAResetEvent (_mcp_ev_client);
  WSAResetEvent (_mcp_ev_dummy);

  return true;
}

static void
SK_MCP_CloseEvents (void)
{
  WSAEVENT* pEvents [] = {
    &_mcp_ev_stop, &_mcp_ev_notify, &_mcp_ev_accept, &_mcp_ev_client, &_mcp_ev_dummy
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
    ReadAcquire (&_mcp_has_client) != FALSE;
}

const char*
SK_MCP_LastError (void)
{
  return
    _mcp_last_error;
}

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

  if (SOCKET_ERROR == listen (listener, 1))
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

    closesocket        (listener);
    SK_MCP_CloseEvents ();

    return false;
  }

  *_mcp_last_error = '\0';

  SK_LOG0 ( ( L"MCP server listening on %ws:%d", config.mcp.bind_address.c_str (),
                                                 config.mcp.port ), SK_MCP_LOG_SRC );

  return true;
}

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

void
SK_MCP_Shutdown (void)
{
  // SK_ShutdownCore runs under the loader lock, so this never waits.
  if (_mcp_ev_stop != WSA_INVALID_EVENT)
      WSASetEvent (_mcp_ev_stop);

  const SOCKET client_sock = _mcp_client_sock;
  const SOCKET listen_sock = _mcp_listen_sock;

  _mcp_client_sock = INVALID_SOCKET;
  _mcp_listen_sock = INVALID_SOCKET;

  if (client_sock != INVALID_SOCKET) closesocket (client_sock);
  if (listen_sock != INVALID_SOCKET) closesocket (listen_sock);

  InterlockedExchange (&_mcp_has_client, FALSE);
  InterlockedExchange (&_mcp_running,    FALSE);
}

void
SK_MCP_Init (void)
{
  // The registry is read-only once the listener is running.
  SK_MCP_RegisterProcessTools ();

  if (config.mcp.enabled)
    SK_MCP_Start ();
}
