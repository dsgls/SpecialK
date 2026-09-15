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
#include <SpecialK/control_panel/mcp.h>
#include <SpecialK/mcp/server.h>

using namespace SK::ControlPanel;

bool
SK::ControlPanel::MCP::Draw (void)
{
  bool ret = false;

  if (ImGui::CollapsingHeader ("MCP Server"))
  {
    ret = true;

    if (ImGui::IsItemHovered ())
    {
      ImGui::SetTooltip (
        "Serves this process to Claude Code over the Special K MCP bridge. "
        "Off by default; do not enable in processes you do not intend to expose."
      );
    }

    ImGui::TreePush ("");

    bool changed =
      ImGui::Checkbox ("Enable MCP server", &config.mcp.enabled);

    if (changed)
    {
      if (config.mcp.enabled)
        SK_MCP_Start ();
      else
        SK_MCP_Stop  ();

      config.utility.save_async ();
    }

    ImGui::SameLine ();

    bool running   = SK_MCP_IsRunning         ();
    bool connected = SK_MCP_IsClientConnected ();

    const char* last_error =
      SK_MCP_LastError ();

    if (running && connected)
    {
      ImGui::TextColored (ImVec4 (0.1f, 1.0f, 0.1f, 1.0f), "Client connected");
    }

    else if (running)
    {
      ImGui::TextColored (ImVec4 (1.0f, 1.0f, 0.0f, 1.0f), "Listening");
    }

    else if (last_error != nullptr && last_error [0] != '\0')
    {
      ImGui::TextColored (ImVec4 (1.0f, 0.0f, 0.0f, 1.0f), "Failed: %s", last_error);
    }

    else
    {
      ImGui::TextColored (ImVec4 (0.6f, 0.6f, 0.6f, 1.0f), "Stopped");
    }

    int port =
      config.mcp.port;

    if (running)
      ImGui::BeginDisabled ();

    if (ImGui::InputInt ("Port", &port))
    {
      port = std::clamp (port, 1024, 65535);

      if (port != config.mcp.port)
      {
        config.mcp.port = port;
        config.utility.save_async ();
      }
    }

    if (running)
      ImGui::EndDisabled ();

    ImGui::SameLine ();

    std::string bind_address =
      SK_MCP_ToUTF8 (config.mcp.bind_address);

    ImGui::Text ("Bind  %s", bind_address.c_str ());

    std::string token =
      SK_MCP_ToUTF8 (config.mcp.token);

    ImGui::Text ("Token ");
    ImGui::SameLine ();

    if (token.empty ())
    {
      ImGui::TextColored (ImVec4 (0.6f, 0.6f, 0.6f, 1.0f), "(generated on first enable)");
    }

    else
    {
      std::string masked =
        token.size () >= 8 ? (token.substr (0, 4) + "..." + token.substr (token.size () - 4, 4))
                            :  token;

      ImGui::Text ("%s", masked.c_str ());

      ImGui::SameLine ();

      if (ImGui::Button ("Copy"))
      {
        ImGui::SetClipboardText (token.c_str ());
      }

      ImGui::SameLine ();

      if (running)
        ImGui::BeginDisabled ();

      if (ImGui::Button ("Regenerate"))
      {
        config.mcp.token = L"";

        std::wstring new_token;

        if (SK_MCP_GenerateToken (new_token))
        {
          config.mcp.token = new_token;
        }

        config.utility.save_async ();
      }

      if (running)
        ImGui::EndDisabled ();
    }

    ImGui::TreePop ();
  }

  return ret;
}
