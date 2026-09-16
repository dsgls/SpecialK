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

#include <SpecialK/mcp/chat.h>
#include <SpecialK/mcp/server.h>

#include <unordered_set>

//
// Chat with the Claude Code session on the other end of the MCP server.
//
//   Click-through is off so the input line can take the mouse and the
//     keyboard while the control panel is closed, which also means the widget
//     swallows mouse input under its rectangle while visible.  It therefore
//     defaults to hidden and is meant to be toggled by keybind.
//
//   No docking anchor: a docked widget is re-pinned to its edge every frame,
//     which undoes drags and cancels the corner resize grips.
//
class SKWG_MCPChat : public SK_Widget
{
public:
  SKWG_MCPChat (void) noexcept : SK_Widget ("MCP Chat")
  {
    SK_ImGui_Widgets->mcp_chat = this;

    setResizable    (true).setAutoFit      (false).setMovable (true).
    setClickThrough (false).setBorder      (true).
    setMinSize      ({ 320.0f, 200.0f }).
    setVisible      (false).setActive      (false);
  }

  void draw (void) override
  {
    // The base class only pushes the saved position and size to ImGui for
    //   widgets visible at startup; this one is normally shown later.  An
    //     unsaved position lands in the lower-right corner.
    if (ImGui::IsWindowAppearing ())
    {
      const auto& io =
        ImGui::GetIO ();

      const ImVec2 wnd_size = getSize ();
            ImVec2 wnd_pos  = getPos  ();

      if (wnd_pos.x == 0.0f && wnd_pos.y == 0.0f)
      {
        wnd_pos = ImVec2 ( io.DisplaySize.x - wnd_size.x - 16.0f,
                           io.DisplaySize.y - wnd_size.y - 16.0f );
      }

      ImGui::SetWindowSize (wnd_size, ImGuiCond_FirstUseEver);
      ImGui::SetWindowPos  (wnd_pos,  ImGuiCond_FirstUseEver);
    }

    const bool running   = SK_MCP_IsRunning         ();
    const bool connected = SK_MCP_IsClientConnected ();

    const char* last_error =
      SK_MCP_LastError ();

    if (running && connected)
    {
      ImGui::TextColored (ImVec4 (0.1f, 1.0f, 0.1f, 1.0f), "Bridge connected");
    }

    else if (running)
    {
      ImGui::TextColored (ImVec4 (1.0f, 1.0f, 0.0f, 1.0f), "Listening, no bridge");
    }

    else if (last_error != nullptr && last_error [0] != '\0')
    {
      ImGui::TextColored (ImVec4 (1.0f, 0.0f, 0.0f, 1.0f), "Failed: %s", last_error);
    }

    else
    {
      ImGui::TextColored (ImVec4 (0.6f, 0.6f, 0.6f, 1.0f), "Server stopped");
    }

    ImGui::Separator ();

    // One load per idle frame; a copy of the transcript only when it grew.
    const LONG generation =
      SK_MCP_Chat_Generation ();

    if (generation != last_generation_)
    {
      last_generation_ = generation;
      transcript_      = SK_MCP_Chat_Tail (500);

      user_seqs_.clear ();

      for ( const auto& entry : transcript_ )
      {
        if (entry.role == SK_MCP_ChatRole::User && entry.seq != 0)
          user_seqs_.emplace (entry.seq);
      }

      // Only follow the tail if the user had not scrolled up.
      scroll_to_bottom_ = at_bottom_;
    }

    const float input_height =
      ImGui::GetFrameHeightWithSpacing ();

    // A negative height reserves the input row; 0 would take the whole region.
    if (ImGui::BeginChild ("###MCP_Chat_Transcript",
                             ImVec2 (0.0f, -input_height), false))
    {
      for ( const auto& entry : transcript_ )
      {
        ImVec4 color;

        switch (entry.role)
        {
          case SK_MCP_ChatRole::User:
            color = ImVec4 (1.00f, 1.00f, 1.00f, 1.0f);
            break;
          case SK_MCP_ChatRole::Claude:
            color = ImVec4 (0.55f, 0.75f, 1.00f, 1.0f);
            break;
          case SK_MCP_ChatRole::Note:
            color = ImVec4 (0.60f, 0.60f, 0.60f, 1.0f);
            break;
          default: // System
            color = ImVec4 (0.40f, 0.40f, 0.40f, 1.0f);
            break;
        }

        char szTime [16] = { };

        snprintf ( szTime, sizeof (szTime), "[%02u:%02u:%02u] ",
                     static_cast <unsigned int> (entry.time.wHour),
                     static_cast <unsigned int> (entry.time.wMinute),
                     static_cast <unsigned int> (entry.time.wSecond) );

        // A reply to a message still in view is drawn as a continuation of it.
        const char* szReply =
          ( entry.role == SK_MCP_ChatRole::Claude && entry.seq != 0 &&
            user_seqs_.count (entry.seq) != 0 ) ? "↳ "
                                                : "";

        ImGui::PushStyleColor (ImGuiCol_Text, color);
        ImGui::TextWrapped    ("%s%s%s", szTime, szReply, entry.text.c_str ());
        ImGui::PopStyleColor  ();
      }

      if (scroll_to_bottom_)
      {
        ImGui::SetScrollHereY (1.0f);
        scroll_to_bottom_ = false;
      }

      at_bottom_ =
        (ImGui::GetScrollY () >= ImGui::GetScrollMaxY ());
    }

    ImGui::EndChild ();

    const float button_width =
      ImGui::CalcTextSize ("Send").x + ImGui::GetStyle ().FramePadding.x * 2.0f;

    // draw_base pushes a half-width item default, so the row width is explicit.
    ImGui::SetNextItemWidth (
      std::max ( 1.0f, ImGui::GetContentRegionAvail ().x - button_width -
                                       ImGui::GetStyle ().ItemSpacing.x )
    );

    bool submit =
      ImGui::InputText ( "###MCP_Chat_Input", input_, sizeof (input_),
                           ImGuiInputTextFlags_EnterReturnsTrue );

    if (focus_input_)
    {
      focus_input_ = false;

      ImGui::SetKeyboardFocusHere (-1);
    }

    ImGui::SameLine ();

    if (ImGui::Button ("Send"))
      submit = true;

    if (submit)
    {
      std::string text (input_);

      const size_t first = text.find_first_not_of (" \t\r\n");
      const size_t last  = text.find_last_not_of  (" \t\r\n");

      text = (first == std::string::npos) ? std::string ()
                                          : text.substr (first, last - first + 1);

      *input_ = '\0';

      // Only a line that was actually sent is worth taking the keyboard back for.
      if (! text.empty ())
      {
        SK_MCP_Chat_Submit (text);

        focus_input_ = true;
      }
    }
  }

private:
  std::vector <SK_MCP_ChatEntry> transcript_;
  std::unordered_set <uint64_t>  user_seqs_;

  LONG last_generation_  = -1;    // Force the first refresh
  bool at_bottom_        = true;
  bool scroll_to_bottom_ = false;
  bool focus_input_      = false;

  char input_ [4096]     = { };
};

SK_LazyGlobal <SKWG_MCPChat> __mcp_chat__;

void SK_Widget_InitMCPChat (void)
{
  SK_RunOnce (__mcp_chat__.getPtr ());
}
