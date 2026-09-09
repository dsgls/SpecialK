// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
//
// Copyright 2020 Andon "Kaldaien" Coleman
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
//

#include <SpecialK/stdafx.h>
#include <SpecialK/plugin/plugin_mgr.h>

// RVAs relative to the runtime image base; the exe is ASLR-capable, so the
// preferred base 0x00400000 is never assumed.
static constexpr uintptr_t SK_DXHR_RVA_PacifistIntact = 0x00A10C98;
static constexpr uintptr_t SK_DXHR_RVA_FoxiestIntact  = 0x00A10C99;
static constexpr uintptr_t SK_DXHR_RVA_AlarmsExempt   = 0x018ACB85;
static constexpr uintptr_t SK_DXHR_RVA_BreakPacifist  = 0x003D8090;
static constexpr uintptr_t SK_DXHR_RVA_BreakFoxiest   = 0x003D80A0;
static constexpr uintptr_t SK_DXHR_RVA_ResetRunState  = 0x003D8000;
static constexpr uintptr_t SK_DXHR_RVA_SaveChunkRead  = 0x003D82F0;

using Achievement_ResetRunState_pfn = void (__cdecl *)(void);
using Achievement_SaveChunkRead_pfn = bool (__cdecl *)(void *cursor, void *userdata);

static Achievement_ResetRunState_pfn
       Achievement_ResetRunState_Original = nullptr;
static Achievement_SaveChunkRead_pfn
       Achievement_SaveChunkRead_Original = nullptr;

// 1 = new game, 2 = restored from a save.
static constexpr LONG SK_DXHR_Event_NewGame  = 1;
static constexpr LONG SK_DXHR_Event_Restored = 2;

static bool SK_DXHR_NotifyPacifist = true;
static bool SK_DXHR_NotifyFoxiest  = true;
static bool SK_DXHR_NotifyOnLoad   = true;

static struct {
  bool             supported        = false;

  volatile LONG    pendingEvent     = 0;

  bool             seeded           = false;
  uint8_t          prevPacifist     = 1;
  uint8_t          prevFoxiest      = 1;

  // Last polled values, for the control panel.
  uint8_t          lastPacifist     = 1;
  uint8_t          lastFoxiest      = 1;
  uint8_t          lastAlarmsExempt = 0;

  volatile uint8_t *pPacifist       = nullptr;
  volatile uint8_t *pFoxiest        = nullptr;
  volatile uint8_t *pAlarmsExempt   = nullptr;

  struct {
    void init (void)
    {
      notify_pacifist =
        _CreateConfigParameterBool ( L"DXHR.PlugIn",
                                     L"NotifyPacifist", SK_DXHR_NotifyPacifist,
                                       L"Notify when Pacifist is broken" );
      notify_foxiest =
        _CreateConfigParameterBool ( L"DXHR.PlugIn",
                                     L"NotifyFoxiest",  SK_DXHR_NotifyFoxiest,
                                       L"Notify when Foxiest of the Hounds is broken" );
      notify_on_load =
        _CreateConfigParameterBool ( L"DXHR.PlugIn",
                                     L"NotifyOnLoad",   SK_DXHR_NotifyOnLoad,
                                       L"Summarise conditions after new game / restore" );
    }

    sk::ParameterBool* notify_pacifist = nullptr;
    sk::ParameterBool* notify_foxiest  = nullptr;
    sk::ParameterBool* notify_on_load  = nullptr;
  } ini_params;
} SK_DXHR;

static void
SK_DXHR_PutAddr (uint8_t *pDst, const uint8_t *pAddr)
{
  const uint32_t addr =
    static_cast <uint32_t> (reinterpret_cast <uintptr_t> (pAddr));

  pDst [0] = static_cast <uint8_t> ( addr        & 0xFF);
  pDst [1] = static_cast <uint8_t> ((addr >>  8) & 0xFF);
  pDst [2] = static_cast <uint8_t> ((addr >> 16) & 0xFF);
  pDst [3] = static_cast <uint8_t> ((addr >> 24) & 0xFF);
}

// Confirms the analysed build and, because the compared bytes embed relocated
// absolute addresses, that the computed image base is right.
static bool
SK_DXHR_CheckBuild (uint8_t *base)
{
  uint8_t *const pPacifistByte = base + SK_DXHR_RVA_PacifistIntact;
  uint8_t *const pFoxiestByte  = base + SK_DXHR_RVA_FoxiestIntact;
  uint8_t *const pExemptByte   = base + SK_DXHR_RVA_AlarmsExempt;
  uint8_t *const pBreakPacifist = base + SK_DXHR_RVA_BreakPacifist;
  uint8_t *const pBreakFoxiest = base + SK_DXHR_RVA_BreakFoxiest;
  uint8_t *const pResetRun     = base + SK_DXHR_RVA_ResetRunState;
  uint8_t *const pSaveChunk    = base + SK_DXHR_RVA_SaveChunkRead;

  if (! ( SK_ValidatePointer (pPacifistByte,  true) &&
          SK_ValidatePointer (pFoxiestByte,   true) &&
          SK_ValidatePointer (pExemptByte,    true) &&
          SK_ValidatePointer (pBreakPacifist, true) &&
          SK_ValidatePointer (pBreakPacifist + 7,  true) &&
          SK_ValidatePointer (pBreakFoxiest,  true) &&
          SK_ValidatePointer (pBreakFoxiest  + 16, true) &&
          SK_ValidatePointer (pResetRun,      true) &&
          SK_ValidatePointer (pResetRun      + 6,  true) &&
          SK_ValidatePointer (pSaveChunk,     true) &&
          SK_ValidatePointer (pSaveChunk     + 15, true) ) )
  {
    return false;
  }

  //   mov byte ptr [g_achPacifistIntact], 0
  //   ret
  uint8_t expect_break_pacifist [8] =
    { 0xC6, 0x05, 0, 0, 0, 0, 0x00, 0xC3 };
  SK_DXHR_PutAddr (&expect_break_pacifist [2], pPacifistByte);

  //   cmp byte ptr [g_achAlarmsExempt], 0
  //   jnz +7
  //   mov byte ptr [g_achFoxiestIntact], 0
  //   ret
  uint8_t expect_break_foxiest [17] =
    { 0x80, 0x3D, 0, 0, 0, 0, 0x00, 0x75, 0x07,
      0xC6, 0x05, 0, 0, 0, 0, 0x00, 0xC3 };
  SK_DXHR_PutAddr (&expect_break_foxiest  [2], pExemptByte);
  SK_DXHR_PutAddr (&expect_break_foxiest [11], pFoxiestByte);

  // First 7 bytes only: the rest of the prologue embeds addresses.
  //   xor eax,eax; push 0x40; mov cl,1; push eax
  static constexpr uint8_t expect_reset_run [7] =
    { 0x33, 0xC0, 0x6A, 0x40, 0xB1, 0x01, 0x50 };

  static constexpr uint8_t expect_save_chunk [16] =
    { 0x8B, 0x44, 0x24, 0x04, 0x8B, 0x08, 0x83, 0xC1,
      0x08, 0x83, 0xEC, 0x08, 0x3B, 0x48, 0x04, 0x76 };

  return
    0 == memcmp (pBreakPacifist, expect_break_pacifist, sizeof (expect_break_pacifist)) &&
    0 == memcmp (pBreakFoxiest,  expect_break_foxiest,  sizeof (expect_break_foxiest))  &&
    0 == memcmp (pResetRun,      expect_reset_run,      sizeof (expect_reset_run))      &&
    0 == memcmp (pSaveChunk,     expect_save_chunk,     sizeof (expect_save_chunk));
}

// The event is signalled both before and after the original runs: the original
// writes the condition bytes partway through, so a poll landing inside it must
// see an event rather than classify the new values as a break.
static void __cdecl
SK_DXHR_ResetRunState_Detour (void)
{
  InterlockedExchange (&SK_DXHR.pendingEvent, SK_DXHR_Event_NewGame);

  Achievement_ResetRunState_Original ();

  InterlockedExchange (&SK_DXHR.pendingEvent, SK_DXHR_Event_NewGame);
}

static bool __cdecl
SK_DXHR_SaveChunkRead_Detour (void *cursor, void *userdata)
{
  InterlockedExchange (&SK_DXHR.pendingEvent, SK_DXHR_Event_Restored);

  const bool bRet =
    Achievement_SaveChunkRead_Original (cursor, userdata);

  InterlockedExchange (&SK_DXHR.pendingEvent, SK_DXHR_Event_Restored);

  return bRet;
}

static constexpr DWORD SK_DXHR_ToastFlags =
  SK_ImGui_Toast::UseDuration | SK_ImGui_Toast::ShowCaption |
  SK_ImGui_Toast::ShowTitle   | SK_ImGui_Toast::ShowNewest;

static constexpr char SK_DXHR_ToastTitle [] =
  "Deus Ex: Human Revolution";

void __stdcall
SK_DXHR_EndFrame (void)
{
  uint8_t pacifist     = *SK_DXHR.pPacifist;
  uint8_t foxiest      = *SK_DXHR.pFoxiest;
  uint8_t alarmsExempt = *SK_DXHR.pAlarmsExempt;

  SK_DXHR.lastPacifist     = pacifist;
  SK_DXHR.lastFoxiest      = foxiest;
  SK_DXHR.lastAlarmsExempt = alarmsExempt;

  const LONG event =
    InterlockedExchange (&SK_DXHR.pendingEvent, 0);

  if (event != 0)
  {
    // The bytes above may have been read while the game was still writing
    // them; the event proves a write happened, so take the values again.
    pacifist     = *SK_DXHR.pPacifist;
    foxiest      = *SK_DXHR.pFoxiest;
    alarmsExempt = *SK_DXHR.pAlarmsExempt;

    SK_DXHR.lastPacifist     = pacifist;
    SK_DXHR.lastFoxiest      = foxiest;
    SK_DXHR.lastAlarmsExempt = alarmsExempt;

    if (SK_DXHR_NotifyOnLoad)
    {
      std::string caption;

      if (event == SK_DXHR_Event_NewGame)
      {
        caption = "New game - Pacifist: intact - Foxiest: intact";
      }

      else
      {
        caption =
          std::string ("Pacifist: ") + (pacifist != 0 ? "intact" : "broken") +
                      " - Foxiest: " + (foxiest  != 0 ? "intact" : "broken");
      }

      SK_ImGui_CreateNotification (
        "DXHR.Loaded", SK_ImGui_Toast::Info,
          caption.c_str (), SK_DXHR_ToastTitle,
            6000, SK_DXHR_ToastFlags
      );
    }

    SK_DXHR.prevPacifist = pacifist;
    SK_DXHR.prevFoxiest  = foxiest;
    SK_DXHR.seeded       = true;

    return;
  }

  if (! SK_DXHR.seeded)
  {
    SK_DXHR.prevPacifist = pacifist;
    SK_DXHR.prevFoxiest  = foxiest;
    SK_DXHR.seeded       = true;

    return;
  }

  if (SK_DXHR.prevPacifist != 0 && pacifist == 0 && SK_DXHR_NotifyPacifist)
  {
    SK_ImGui_CreateNotification (
      "DXHR.Pacifist", SK_ImGui_Toast::Warning,
        "Pacifist broken", SK_DXHR_ToastTitle,
          10000, SK_DXHR_ToastFlags
    );
  }

  if (SK_DXHR.prevFoxiest != 0 && foxiest == 0 && SK_DXHR_NotifyFoxiest)
  {
    SK_ImGui_CreateNotification (
      "DXHR.Foxiest", SK_ImGui_Toast::Warning,
        "Foxiest of the Hounds broken", SK_DXHR_ToastTitle,
          10000, SK_DXHR_ToastFlags
    );
  }

  SK_DXHR.prevPacifist = pacifist;
  SK_DXHR.prevFoxiest  = foxiest;
}

bool
SK_DXHR_PlugInCfg (void)
{
  if (ImGui::CollapsingHeader ("Deus Ex: Human Revolution", ImGuiTreeNodeFlags_DefaultOpen))
  {
    ImGui::TreePush ("");

    if (! SK_DXHR.supported)
    {
      ImGui::TextUnformatted ("Unsupported DXHRDC.exe build; achievement tracking disabled.");
      ImGui::TreePop         ();

      return true;
    }

    static const ImVec4 color_intact  (0.10f, 0.90f, 0.10f, 1.00f);
    static const ImVec4 color_broken  (0.95f, 0.20f, 0.20f, 1.00f);

    ImGui::TextUnformatted ("Achievement conditions");

    bool bChanged = false;

    auto _DrawStatus = [&](uint8_t intact)
    {
      ImGui::SameLine ();

      if (! SK_DXHR.seeded) ImGui::TextDisabled  (                "Unknown");
      else if (intact != 0) ImGui::TextColored   (color_intact,   "Intact");
      else                  ImGui::TextColored   (color_broken,   "Broken");
    };

    bChanged |=
      ImGui::Checkbox ("Notify when Pacifist is broken###SK_DXHR_NotifyPacifist",
                        &SK_DXHR_NotifyPacifist);

    if (ImGui::IsItemHovered ())
      ImGui::SetTooltip ("Broken by any counted NPC death, whoever caused it; "
                         "bosses and non-lethal takedowns do not count.");

    _DrawStatus (SK_DXHR.lastPacifist);

    bChanged |=
      ImGui::Checkbox ("Notify when Foxiest of the Hounds is broken###SK_DXHR_NotifyFoxiest",
                        &SK_DXHR_NotifyFoxiest);

    if (ImGui::IsItemHovered ())
      ImGui::SetTooltip ("Broken by any raised alarm while alarms are not script-exempt.");

    _DrawStatus (SK_DXHR.lastFoxiest);

    if (SK_DXHR.lastAlarmsExempt != 0)
    {
      ImGui::SameLine    ();
      ImGui::TextDisabled ("(alarms currently exempt)");
    }

    bChanged |=
      ImGui::Checkbox ("Summarise conditions after new game / restore###SK_DXHR_NotifyOnLoad",
                        &SK_DXHR_NotifyOnLoad);

    if (ImGui::IsItemHovered ())
      ImGui::SetTooltip ("Shows both conditions after a new game starts or saved state is restored.");

    if (bChanged)
    {
      SK_DXHR.ini_params.notify_pacifist->store (SK_DXHR_NotifyPacifist);
      SK_DXHR.ini_params.notify_foxiest->store  (SK_DXHR_NotifyFoxiest);
      SK_DXHR.ini_params.notify_on_load->store  (SK_DXHR_NotifyOnLoad);

      SK_GetDLLConfig ()->write (
        SK_GetDLLConfig ()->get_filename ()
      );
    }

    ImGui::TreePop ();
  }

  return true;
}

void
SK_DXHR_InitPlugin (void)
{
  SK_RunOnce (
  {
    SK_DXHR.ini_params.init ();

    uint8_t *base =
      reinterpret_cast <uint8_t *> (SK_GetModuleHandle (nullptr));

    SK_DXHR.supported =
      (base != nullptr) && SK_DXHR_CheckBuild (base);

    if (! SK_DXHR.supported)
    {
      SK_LOG0 ( (L"Unsupported DXHRDC.exe build; achievement tracking disabled"),
                 L" DXHRDC " );
    }

    plugin_mgr->config_fns.insert (SK_DXHR_PlugInCfg);

    if (SK_DXHR.supported)
    {
      SK_DXHR.pPacifist     = base + SK_DXHR_RVA_PacifistIntact;
      SK_DXHR.pFoxiest      = base + SK_DXHR_RVA_FoxiestIntact;
      SK_DXHR.pAlarmsExempt = base + SK_DXHR_RVA_AlarmsExempt;

      const MH_STATUS status_reset =
        SK_CreateFuncHook (      L"Achievement_ResetRunState",
                                    base + SK_DXHR_RVA_ResetRunState,
                                      SK_DXHR_ResetRunState_Detour,
           static_cast_p2p <void> (&Achievement_ResetRunState_Original) );

      const MH_STATUS status_chunk =
        SK_CreateFuncHook (      L"Achievement_SaveChunkRead",
                                    base + SK_DXHR_RVA_SaveChunkRead,
                                      SK_DXHR_SaveChunkRead_Detour,
           static_cast_p2p <void> (&Achievement_SaveChunkRead_Original) );

      if (status_reset != MH_OK || status_chunk != MH_OK)
      {
        SK_DXHR.supported = false;

        SK_LOG0 ( (L"Unsupported DXHRDC.exe build; achievement tracking disabled"),
                   L" DXHRDC " );
      }

      else
      {
        MH_QueueEnableHook (base + SK_DXHR_RVA_ResetRunState);
        MH_QueueEnableHook (base + SK_DXHR_RVA_SaveChunkRead);

        SK_ApplyQueuedHooks ();

        plugin_mgr->end_frame_fns.insert (SK_DXHR_EndFrame);
      }
    }
  });
}
