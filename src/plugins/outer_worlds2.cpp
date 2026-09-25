// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
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
#include <SpecialK/plugin/pattern_scan.h>

#ifdef _M_AMD64

// The Outer Worlds 2 (TheOuterWorlds2-Win64-Shipping.exe, UE5). Every address
// is resolved by pattern; the reverse engineering is in the outerworlds2-re
// repository (NOTES.md).

static constexpr float SK_OW2_MaxSensitivity = 4.0f;

// UIndianaGameUserSettings (gus = *(*GEngine + 0x2a0)) field offsets.
static constexpr uintptr_t SK_OW2_Engine_GameUserSettings = 0x2a0;
static constexpr uintptr_t SK_OW2_GUS_ControllerSens      = 0x2f8;
static constexpr uintptr_t SK_OW2_GUS_ControllerADSSens   = 0x310;

// UGameInstance (gi = *GGameInstance) -> USaveGameManager (mgr = *(gi + 0x2d8))
// field offsets.
static constexpr uintptr_t SK_OW2_GameInstance_SaveMgr          = 0x2d8;
static constexpr uintptr_t SK_OW2_SaveMgr_MaxOverwriteableSaves = 0xb18;

using SK_OW2_SetSensitivity_pfn = void (*)(void *gus, float value);

// FVector2D* (UPlayerMovementComponent *mc, FVector2D *out, const FVector2D *stick, float dt);
// declared with opaque pointer types; dt is the only non-pointer argument.
using SK_OW2_ProcessLookStick_pfn =
  void* (*)(void *mc, void *out, const void *stick, float dt);

enum SK_OW2_PatternId {
  SK_OW2_Pat_GEngine,
  SK_OW2_Pat_GGameInstance,
  SK_OW2_Pat_ProcessLookStick,
  SK_OW2_Pat_SetControllerSens,
  SK_OW2_Pat_SetControllerADSSens,
  SK_OW2_Pat_L1,
  SK_OW2_Pat_B1,

  // Searched only in [B1 match, B1 match + SK_OW2_B1_Window).
  SK_OW2_Pat_B2,
  SK_OW2_Pat_B4,
  SK_OW2_Pat_S,
  SK_OW2_Pat_B3,

  SK_OW2_Pat_Count,
  SK_OW2_Pat_TopLevelCount = SK_OW2_Pat_B2
};

static constexpr size_t SK_OW2_B1_Window = 0x200;

static constexpr struct {
  const char *name;
  const char *ida;
} SK_OW2_PatternDefs [SK_OW2_Pat_Count] = {
  { "GEngine",                     "48 8B 05 ?? ?? ?? ?? 41 8A E8 44 8A F2"                                                                                                   },
  { "GGameInstance",               "48 8B 05 ?? ?? ?? ?? 45 33 F6 44 8B 89 E4 04 00 00 48 8B D9 4C 8B 80 D8 02 00 00"                                                         },
  { "ProcessLookStick",            "48 8B C4 48 89 58 08 48 89 70 10 57 48 81 EC C0 00 00 00 41 0F 10 08 48 8B F2 48 8B D9"                                                   },
  { "SetControllerSensitivity",    "48 83 EC 28 0F 2E 89 F8 02 00 00 0F 85"                                                                                                   },
  { "SetControllerADSSensitivity", "48 83 EC 28 0F 2E 89 10 03 00 00 0F 85"                                                                                                   },
  { "L1",                          "66 0F 51 C1 66 0F 5A F0 0F 2F 75 00 73 08 0F 57 E4 0F 57 ED EB 78"                                                                        },
  { "B1",                          "0F 28 D7 F3 0F 7F 81 A0 19 00 00 E8 ?? ?? ?? ?? 48 8D 54 24 20 48 8B CB E8 ?? ?? ?? ?? 48 8D 54 24 20 48 8B CB E8 ?? ?? ?? ?? 48 8B 8B 98 11 00 00" },
  { "B2",                          "F3 44 0F 58 E1 72 ?? F3 0F 58 BB 50 19 00 00 F3 0F 10 8B 18 15 00 00"                                                                     },
  { "B4",                          "E8 ?? ?? ?? ?? 48 8B BF 10 1E 00 00 44 0F 28 D0"                                                                                          },
  { "S",                           "F3 0F 10 8B 30 15 00 00 F3 44 0F 5C E3 F3 0F 59 9B 84 19 00 00"                                                                           },
  { "B3",                          "F3 0F 10 8B 10 15 00 00 48 8B 83 08 01 00 00 F2 45 0F 59 C9"                                                                              },
};

// Apply in this order, undo in reverse: S must be in place whenever B3 is.
enum SK_OW2_SiteId {
  SK_OW2_Site_L1,
  SK_OW2_Site_B1a,
  SK_OW2_Site_B1b,
  SK_OW2_Site_B1c,
  SK_OW2_Site_B2,
  SK_OW2_Site_B4,
  SK_OW2_Site_S,
  SK_OW2_Site_B3,

  SK_OW2_Site_Count
};

static constexpr uint8_t SK_OW2_Orig_L1  [] = { 0xF0, 0x0F, 0x2F, 0x75, 0x00, 0x73, 0x08, 0x0F };
static constexpr uint8_t SK_OW2_Orig_B1a [] = { 0xE8, 0xE3, 0x5D, 0x6E, 0x02 };
static constexpr uint8_t SK_OW2_Orig_B1b [] = { 0xE8, 0xFA, 0x66, 0x6E, 0x02 };
static constexpr uint8_t SK_OW2_Orig_B1c [] = { 0xE8, 0x49, 0x66, 0x6E, 0x02 };
static constexpr uint8_t SK_OW2_Orig_B2  [] = { 0x72, 0x78 };
static constexpr uint8_t SK_OW2_Orig_B4  [] = { 0x44, 0x0F, 0x28, 0xD0 };
static constexpr uint8_t SK_OW2_Orig_S   [] = { 0xF3, 0x0F, 0x59, 0x9B, 0x84, 0x19, 0x00, 0x00 };
static constexpr uint8_t SK_OW2_Orig_B3  [] = {
  0xF3, 0x0F, 0x10, 0x8B, 0x10, 0x15, 0x00, 0x00, 0x48, 0x8B, 0x83, 0x08, 0x01, 0x00, 0x00,
  0xF2, 0x45, 0x0F, 0x59, 0xC9, 0xF2, 0x45, 0x0F, 0x59, 0xED, 0xF3, 0x44, 0x0F, 0x59, 0xA0,
  0xC8, 0x00, 0x00, 0x00, 0x0F, 0x5A, 0xC9, 0xF2, 0x45, 0x0F, 0x58, 0xCD, 0x66, 0x41, 0x0F,
  0x51, 0xC1, 0xF2, 0x0F, 0x5D, 0x05, 0x55, 0x0F, 0xBB, 0x04, 0xE8, 0x52, 0xE3, 0xA9, 0xFF
};

// L1: jmp over the deadzone clamp (the leading modrm and trailing 0F stay).
// B1a-c: nop the three curve / acceleration / angular deadzone calls.
// B2: jb -> jmp skips the yaw ramp. B4: xmm8 (1.0) replaces the ADS multiplier.
// S: store the ADS blend weight (xmm3) to [rsp+0x20] for B3.
static constexpr uint8_t SK_OW2_Repl_L1  [] = { 0xF0, 0xE9, 0x81, 0x00, 0x00, 0x00, 0x90, 0x0F };
static constexpr uint8_t SK_OW2_Repl_Nop [] = { 0x0F, 0x1F, 0x44, 0x00, 0x00 };
static constexpr uint8_t SK_OW2_Repl_B2  [] = { 0xEB, 0x78 };
static constexpr uint8_t SK_OW2_Repl_B4  [] = { 0x45, 0x0F, 0x28, 0xD0 };
static constexpr uint8_t SK_OW2_Repl_S   [] = { 0xF3, 0x0F, 0x11, 0x5C, 0x24, 0x20, 0x66, 0x90 };

// B3: rate scalar = CustomTimeDilation * lerp (hip, ADS sensitivity, s), with
// unit stick magnitude. The absolute address of gus+0x2f8 (&M) is filled in
// at runtime by SK_OW2_BuildB3.
static constexpr size_t  SK_OW2_B3_AddrOffset   = 18;
static constexpr size_t  SK_OW2_B3_ADSDispOffset = 30;
static constexpr uint8_t SK_OW2_Repl_B3_Template [] = {
  0x48, 0x8B, 0x83, 0x08, 0x01, 0x00, 0x00,             // mov   rax, [rbx+0x108]
  0xF3, 0x44, 0x0F, 0x10, 0xA0, 0xC8, 0x00, 0x00, 0x00, // movss xmm12, [rax+0xc8]
  0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,                   // mov   rax, &M
  0xF3, 0x0F, 0x10, 0x48, 0x18,                         // movss xmm1, [rax+0x18]
  0xF3, 0x0F, 0x5C, 0x08,                               // subss xmm1, [rax]
  0xF3, 0x0F, 0x59, 0x4C, 0x24, 0x20,                   // mulss xmm1, [rsp+0x20]
  0xF3, 0x0F, 0x58, 0x08,                               // addss xmm1, [rax]
  0xF3, 0x44, 0x0F, 0x59, 0xE1,                         // mulss xmm12, xmm1
  0xF3, 0x41, 0x0F, 0x5A, 0xC0,                         // cvtss2sd xmm0, xmm8
  0x0F, 0x1F, 0x44, 0x00, 0x00                          // nop
};

static_assert (sizeof (SK_OW2_Repl_B3_Template) == 60 &&
               sizeof (SK_OW2_Repl_B3_Template) == sizeof (SK_OW2_Orig_B3),
               "B3 replacement must cover the original exactly" );
static_assert (SK_OW2_Repl_B3_Template [SK_OW2_B3_ADSDispOffset] ==
                 SK_OW2_GUS_ControllerADSSens - SK_OW2_GUS_ControllerSens,
               "B3 reads ADS sensitivity relative to &M" );
static_assert (sizeof (SK_OW2_Repl_L1)  == sizeof (SK_OW2_Orig_L1)  &&
               sizeof (SK_OW2_Repl_Nop) == sizeof (SK_OW2_Orig_B1a) &&
               sizeof (SK_OW2_Repl_Nop) == sizeof (SK_OW2_Orig_B1b) &&
               sizeof (SK_OW2_Repl_Nop) == sizeof (SK_OW2_Orig_B1c) &&
               sizeof (SK_OW2_Repl_B2)  == sizeof (SK_OW2_Orig_B2)  &&
               sizeof (SK_OW2_Repl_B4)  == sizeof (SK_OW2_Orig_B4)  &&
               sizeof (SK_OW2_Repl_S)   == sizeof (SK_OW2_Orig_S),
               "Each replacement must cover its original exactly" );

// replacement is nullptr for B3, which is built per gus.
static constexpr struct {
  const char       *name;
  SK_OW2_PatternId  anchor;
  size_t            offset;
  const uint8_t    *original;
  const uint8_t    *replacement;
  size_t            size;
} SK_OW2_SiteDefs [SK_OW2_Site_Count] = {
  { "L1",  SK_OW2_Pat_L1, 0x07, SK_OW2_Orig_L1,  SK_OW2_Repl_L1,  sizeof (SK_OW2_Orig_L1)  },
  { "B1a", SK_OW2_Pat_B1, 0x0b, SK_OW2_Orig_B1a, SK_OW2_Repl_Nop, sizeof (SK_OW2_Orig_B1a) },
  { "B1b", SK_OW2_Pat_B1, 0x18, SK_OW2_Orig_B1b, SK_OW2_Repl_Nop, sizeof (SK_OW2_Orig_B1b) },
  { "B1c", SK_OW2_Pat_B1, 0x25, SK_OW2_Orig_B1c, SK_OW2_Repl_Nop, sizeof (SK_OW2_Orig_B1c) },
  { "B2",  SK_OW2_Pat_B2, 0x05, SK_OW2_Orig_B2,  SK_OW2_Repl_B2,  sizeof (SK_OW2_Orig_B2)  },
  { "B4",  SK_OW2_Pat_B4, 0x0c, SK_OW2_Orig_B4,  SK_OW2_Repl_B4,  sizeof (SK_OW2_Orig_B4)  },
  { "S",   SK_OW2_Pat_S,  0x0d, SK_OW2_Orig_S,   SK_OW2_Repl_S,   sizeof (SK_OW2_Orig_S)   },
  { "B3",  SK_OW2_Pat_B3, 0x00, SK_OW2_Orig_B3,  nullptr,         sizeof (SK_OW2_Orig_B3)  },
};

// Shared between the render thread (UI) and the game thread; each value is
// read and written whole, so no locking.
static struct {
  bool  bypass_input     = false;
  bool  override_sens    = false;
  float view_sensitivity = 1.0f;
  float ads_sensitivity  = 1.0f;
  bool  raise_save_limit = false;

  // Not shown in the panel: latches true the first time the save limit is
  // actually raised, so a later build that ships 9999 as its own default
  // does not get silently lowered for users who never used this feature.
  bool  save_limit_was_raised = false;
} SK_OW2_Config;

static struct {
  // Written once by the scan worker before the release store to resolved;
  // readers must ReadAcquire (&resolved) first.
  volatile LONG  resolved              = 0;

  bool           sensitivity_supported = false;
  volatile LONG  bypass_supported      = FALSE; // Cleared by the game thread if a patch batch fails
  bool           save_limit_supported  = false;

  // Bypass state, written only by the game thread (detour); the panel reads
  // bypass_applied with ReadAcquire.
  volatile LONG  bypass_applied        = FALSE;
  uint8_t       *bypass_gus            = nullptr; // gus baked into the applied B3

  uint8_t      **pGEngine              = nullptr; // UEngine**
  uint8_t      **pGGameInstance        = nullptr; // UGameInstance**
  uint8_t       *pProcessLookStick     = nullptr;

  SK_OW2_SetSensitivity_pfn
                 SetControllerSensitivity    = nullptr;
  SK_OW2_SetSensitivity_pfn
                 SetControllerADSSensitivity = nullptr;

  SK_OW2_ProcessLookStick_pfn
                 ProcessLookStick_Original   = nullptr;

  // Verified to hold SK_OW2_SiteDefs [i].original at resolve time.
  uint8_t       *sites [SK_OW2_Site_Count] = { };

  struct {
    void init (void)
    {
      bypass_input =
        _CreateConfigParameterBool  ( L"OuterWorlds2.PlugIn",
                                      L"BypassInputProcessing", SK_OW2_Config.bypass_input,
                                        L"Bypass the game's controller input processing" );
      override_sens =
        _CreateConfigParameterBool  ( L"OuterWorlds2.PlugIn",
                                      L"OverrideSensitivity",   SK_OW2_Config.override_sens,
                                        L"Enforce the view / ADS controller sensitivity below" );
      view_sensitivity =
        _CreateConfigParameterFloat ( L"OuterWorlds2.PlugIn",
                                      L"ViewSensitivity",       SK_OW2_Config.view_sensitivity,
                                        L"Controller view sensitivity, 0.0-4.0" );
      ads_sensitivity =
        _CreateConfigParameterFloat ( L"OuterWorlds2.PlugIn",
                                      L"ADSSensitivity",        SK_OW2_Config.ads_sensitivity,
                                        L"Controller ADS sensitivity, 0.0-4.0" );
      raise_save_limit =
        _CreateConfigParameterBool  ( L"OuterWorlds2.PlugIn",
                                      L"RaiseSaveLimit",        SK_OW2_Config.raise_save_limit,
                                        L"Raise the manual save limit to 9999" );
      save_limit_was_raised =
        _CreateConfigParameterBool  ( L"OuterWorlds2.PlugIn",
                                      L"SaveLimitWasRaised",    SK_OW2_Config.save_limit_was_raised,
                                        L"Internal: whether the save limit has ever been raised" );
    }

    void store (void)
    {
      bypass_input->store          (SK_OW2_Config.bypass_input);
      override_sens->store         (SK_OW2_Config.override_sens);
      view_sensitivity->store      (SK_OW2_Config.view_sensitivity);
      ads_sensitivity->store       (SK_OW2_Config.ads_sensitivity);
      raise_save_limit->store      (SK_OW2_Config.raise_save_limit);
      save_limit_was_raised->store (SK_OW2_Config.save_limit_was_raised);
    }

    sk::ParameterBool*  bypass_input          = nullptr;
    sk::ParameterBool*  override_sens         = nullptr;
    sk::ParameterFloat* view_sensitivity      = nullptr;
    sk::ParameterFloat* ads_sensitivity       = nullptr;
    sk::ParameterBool*  raise_save_limit      = nullptr;
    sk::ParameterBool*  save_limit_was_raised = nullptr;
  } ini_params;
} SK_OW2;

// A NaN would make the override call the setter every frame: the setter's
// compare is unordered and never stores it.
static float
SK_OW2_SanitizeSensitivity (float value)
{
  if (! std::isfinite (value))
    return 1.0f;

  return
    std::clamp (value, 0.0f, SK_OW2_MaxSensitivity);
}

// gus = *(*GEngine + 0x2a0); null until GEngine and the game user settings
// object both exist. Called from both the game thread (detour) and the
// render thread (panel); GEngine/gus themselves never move once created.
static uint8_t *
SK_OW2_GetGUS (void)
{
  if (SK_OW2.pGEngine == nullptr || *SK_OW2.pGEngine == nullptr)
    return nullptr;

  return
    *reinterpret_cast <uint8_t **> (*SK_OW2.pGEngine + SK_OW2_Engine_GameUserSettings);
}

// Panel-only read of the game's current sensitivity, wrapped in SEH: at exit
// the engine can tear gus down while the control panel is still drawing on
// the render thread. No C++ objects here needing unwinding (C2712).
static bool
SK_OW2_ReadGameSens (float& view, float& ads)
{
  __try
  {
    uint8_t *gus =
      SK_OW2_GetGUS ();

    if (gus == nullptr)
      return false;

    view = *reinterpret_cast <float *> (gus + SK_OW2_GUS_ControllerSens);
    ads  = *reinterpret_cast <float *> (gus + SK_OW2_GUS_ControllerADSSens);

    return true;
  }

  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    return false;
  }
}

static void
SK_OW2_BuildB3 (uint8_t *gus, uint8_t (&out) [sizeof (SK_OW2_Repl_B3_Template)])
{
  const uint8_t *sens =
    gus + SK_OW2_GUS_ControllerSens;

  memcpy (out, SK_OW2_Repl_B3_Template, sizeof (out));
  memcpy (out + SK_OW2_B3_AddrOffset, &sens, sizeof (sens));
}

// Writes every site from its current state to the other (original <->
// replacement), with B3 built for gus. Game thread only, from the detour: the
// game thread is the only one executing these sites and it is outside all of
// them, so no thread suspension or atomic write is needed.
static bool
SK_OW2_RunBypassBatch (bool apply, uint8_t *gus)
{
  uint8_t b3 [sizeof (SK_OW2_Repl_B3_Template)];
  SK_OW2_BuildB3 (gus, b3);

  const uint8_t *from [SK_OW2_Site_Count];
  const uint8_t *to   [SK_OW2_Site_Count];
  bool           skip [SK_OW2_Site_Count] = { };

  for (int i = 0; i < SK_OW2_Site_Count; ++i)
  {
    const auto&    def         = SK_OW2_SiteDefs [i];
    const uint8_t *replacement =
      def.replacement != nullptr ? def.replacement : b3;

    from [i] = apply ? def.original : replacement;
    to   [i] = apply ? replacement  : def.original;

    // Check every site before writing any, so a mismatch leaves code untouched.
    if (0 == memcmp (SK_OW2.sites [i], to [i], def.size))
      skip [i] = true;

    else if (0 != memcmp (SK_OW2.sites [i], from [i], def.size))
    {
      SK_LOG0 ( (L"Input bypass %hs aborted: unexpected bytes at site %hs; bypass disabled",
                   apply ? "apply" : "undo", def.name),
                 L" OW2 " );

      return false;
    }
  }

  // Apply in site order, undo in reverse (S must be in place whenever B3 is).
  int order   [SK_OW2_Site_Count];
  int written [SK_OW2_Site_Count];
  int count = 0;

  for (int i = 0; i < SK_OW2_Site_Count; ++i)
    order [i] = apply ? i : SK_OW2_Site_Count - 1 - i;

  auto _Write = [](int site, const uint8_t *bytes) -> bool
  {
    const size_t size = SK_OW2_SiteDefs [site].size;

    if (! SK_InjectMemory (SK_OW2.sites [site], bytes, size, PAGE_EXECUTE_READWRITE))
      return false;

    FlushInstructionCache (GetCurrentProcess (), SK_OW2.sites [site], size);

    return true;
  };

  for (const int site : order)
  {
    if (skip [site])
      continue;

    if (! _Write (site, to [site]))
    {
      SK_LOG0 ( (L"Input bypass %hs failed writing site %hs; rolling back, bypass disabled",
                   apply ? "apply" : "undo", SK_OW2_SiteDefs [site].name),
                 L" OW2 " );

      while (count > 0)
      {
        const int prev = written [--count];

        _Write (prev, from [prev]);
      }

      return false;
    }

    written [count++] = site;
  }

  return true;
}

// Bypass state machine; game thread only. desired is a single snapshot of
// the setting taken by the caller, used for the whole batch.
static void
SK_OW2_UpdateBypass (bool desired, uint8_t *gus)
{
  const bool applied =
    ReadAcquire (&SK_OW2.bypass_applied) != 0;

  // Steady state: nothing to do.
  if (desired == applied && ((! applied) || gus == SK_OW2.bypass_gus))
    return;

  // Undo also covers a changed gus: the applied B3 embeds the old address.
  if (applied)
  {
    if (! SK_OW2_RunBypassBatch (false, SK_OW2.bypass_gus))
    {
      WriteRelease (&SK_OW2.bypass_supported, FALSE);
      return;
    }

    SK_OW2.bypass_gus = nullptr;
    WriteRelease (&SK_OW2.bypass_applied, FALSE);
  }

  if (desired)
  {
    if (! SK_OW2_RunBypassBatch (true, gus))
    {
      WriteRelease (&SK_OW2.bypass_supported, FALSE);
      return;
    }

    SK_OW2.bypass_gus = gus;
    WriteRelease (&SK_OW2.bypass_applied, TRUE);
  }
}

// Runs on the game thread once per gameplay frame; ProcessLookStick has one
// caller, after PlayerInput processing has returned, so none of the L1 /
// B-site patch locations are on the stack here.
static void *
SK_OW2_ProcessLookStick_Detour (void *mc, void *out, const void *stick, float dt)
{
  uint8_t *gus =
    SK_OW2_GetGUS ();

  if (gus != nullptr)
  {
    if (ReadAcquire (&SK_OW2.bypass_supported))
      SK_OW2_UpdateBypass (SK_OW2_Config.bypass_input, gus);

    if (SK_OW2.sensitivity_supported && SK_OW2_Config.override_sens)
    {
      float *view =
        reinterpret_cast <float *> (gus + SK_OW2_GUS_ControllerSens);
      float *ads =
        reinterpret_cast <float *> (gus + SK_OW2_GUS_ControllerADSSens);

      if (*view != SK_OW2_Config.view_sensitivity)
        SK_OW2.SetControllerSensitivity    (gus, SK_OW2_Config.view_sensitivity);

      if (*ads != SK_OW2_Config.ads_sensitivity)
        SK_OW2.SetControllerADSSensitivity (gus, SK_OW2_Config.ads_sensitivity);
    }
  }

  return
    SK_OW2.ProcessLookStick_Original (mc, out, stick, dt);
}

static DWORD WINAPI
SK_OW2_ResolveThread (LPVOID)
{
  const LARGE_INTEGER start =
    SK_QueryPerf ();

  // SK_PatternScan_ScanRange's dispatch table holds one bit per pattern in a
  // pass, so each pass here must stay within 16 patterns.
  static_assert (                   SK_OW2_Pat_TopLevelCount <= 16 &&
                  SK_OW2_Pat_Count - SK_OW2_Pat_TopLevelCount <= 16,
                  "first_byte holds one bit per pattern in a pass" );

  SK_PatternScan_Pattern pats [SK_OW2_Pat_Count];

  bool parsed = true;

  for (int i = 0; i < SK_OW2_Pat_Count; ++i)
    parsed &= SK_PatternScan_ParsePattern (SK_OW2_PatternDefs [i].ida, pats [i]);

  SK_ReleaseAssert (parsed);

  uint8_t *base =
    reinterpret_cast <uint8_t *> (SK_GetModuleHandle (nullptr));

  uint8_t *text      = nullptr;
  size_t   text_size = 0;

  bool scanned =
    parsed && base != nullptr && SK_PatternScan_FindText (base, text, text_size);

  if (scanned)
  {
    const uint8_t *text_end = text + text_size;

    scanned =
      SK_PatternScan_ScanRange (text, text_end, text_end, pats, SK_OW2_Pat_TopLevelCount);

    const SK_PatternScan_Pattern& b1 = pats [SK_OW2_Pat_B1];

    if (scanned && b1.match != nullptr && ! b1.duplicate)
    {
      scanned =
        SK_PatternScan_ScanRange ( b1.match,
                                   std::min (b1.match + SK_OW2_B1_Window, text_end), text_end,
                                     &pats [SK_OW2_Pat_TopLevelCount],
                                            SK_OW2_Pat_Count - SK_OW2_Pat_TopLevelCount );
    }
  }

  if (! scanned)
  {
    SK_LOG0 ( (L"Could not scan the executable's .text section; all features disabled"),
               L" OW2 " );
  }

  // A partial scan cannot rule out duplicates, so it resolves nothing.
  auto _Found = [&](int id) -> const uint8_t *
  {
    return
      (! scanned) || pats [id].duplicate ? nullptr
                                         : pats [id].match;
  };

  for (int i = 0; scanned && i < SK_OW2_Pat_Count; ++i)
  {
    if (pats [i].duplicate)
    {
      SK_LOG0 ( (L"Pattern %hs matched more than once", SK_OW2_PatternDefs [i].name),
                 L" OW2 " );
    }
  }

  if (_Found (SK_OW2_Pat_GEngine) != nullptr)
    SK_OW2.pGEngine = reinterpret_cast <uint8_t **> (SK_PatternScan_RipTarget (_Found (SK_OW2_Pat_GEngine), 3, 7));

  if (_Found (SK_OW2_Pat_GGameInstance) != nullptr)
    SK_OW2.pGGameInstance = reinterpret_cast <uint8_t **> (SK_PatternScan_RipTarget (_Found (SK_OW2_Pat_GGameInstance), 3, 7));

  SK_OW2.pProcessLookStick =
    const_cast <uint8_t *> (_Found (SK_OW2_Pat_ProcessLookStick));

  SK_OW2.SetControllerSensitivity =
    reinterpret_cast <SK_OW2_SetSensitivity_pfn> (_Found (SK_OW2_Pat_SetControllerSens));
  SK_OW2.SetControllerADSSensitivity =
    reinterpret_cast <SK_OW2_SetSensitivity_pfn> (_Found (SK_OW2_Pat_SetControllerADSSens));

  std::string missing_sites;

  for (int i = 0; i < SK_OW2_Site_Count; ++i)
  {
    const auto&    def    = SK_OW2_SiteDefs [i];
    const uint8_t *anchor = _Found (def.anchor);

    if (anchor != nullptr && 0 == memcmp (anchor + def.offset, def.original, def.size))
      SK_OW2.sites [i] = const_cast <uint8_t *> (anchor + def.offset);

    else
      missing_sites += std::string (missing_sites.empty () ? "" : ", ") + def.name;
  }

  auto _Missing = [&](std::initializer_list <int> ids, std::string extra = "") -> std::string
  {
    std::string list;

    for (const int id : ids)
    {
      if (_Found (id) == nullptr)
        list += std::string (list.empty () ? "" : ", ") + SK_OW2_PatternDefs [id].name;
    }

    if (! extra.empty ())
      list += std::string (list.empty () ? "" : ", ") + extra;

    return list;
  };

  const std::string missing_sens =
    _Missing ({ SK_OW2_Pat_GEngine, SK_OW2_Pat_ProcessLookStick,
                SK_OW2_Pat_SetControllerSens, SK_OW2_Pat_SetControllerADSSens });
  const std::string missing_bypass =
    _Missing ({ SK_OW2_Pat_GEngine, SK_OW2_Pat_ProcessLookStick },
                missing_sites.empty () ? "" : "patch sites (" + missing_sites + ")");
  const std::string missing_save =
    _Missing ({ SK_OW2_Pat_GGameInstance });

  SK_OW2.sensitivity_supported = missing_sens.empty   ();
  SK_OW2.bypass_supported      = missing_bypass.empty ();
  SK_OW2.save_limit_supported  = missing_save.empty   ();

  if (! SK_OW2.sensitivity_supported)
  {
    SK_LOG0 ( (L"Sensitivity override unsupported, missing: %hs", missing_sens.c_str ()),
               L" OW2 " );
  }

  if (! SK_OW2.bypass_supported)
  {
    SK_LOG0 ( (L"Input processing bypass unsupported, missing: %hs", missing_bypass.c_str ()),
               L" OW2 " );
  }

  if (! SK_OW2.save_limit_supported)
  {
    SK_LOG0 ( (L"Save limit unsupported, missing: %hs", missing_save.c_str ()),
               L" OW2 " );
  }

  if (SK_OW2.sensitivity_supported || SK_OW2.bypass_supported)
  {
    // The patterns above are scanned before this overwrites the entry.
    const MH_STATUS status =
      SK_CreateFuncHook (      L"OW2_ProcessLookStick",
                                  SK_OW2.pProcessLookStick,
                                    SK_OW2_ProcessLookStick_Detour,
         static_cast_p2p <void> (&SK_OW2.ProcessLookStick_Original) );

    if (status == MH_OK)
    {
      MH_QueueEnableHook (SK_OW2.pProcessLookStick);

      // A no-op until SK_InitFinishCallback calls SK_EnableApplyQueuedHooks;
      // the detour goes live there, still before any gameplay frame.
      SK_ApplyQueuedHooks ();
    }

    else
    {
      SK_OW2.sensitivity_supported = false;
      SK_OW2.bypass_supported      = false;

      SK_LOG0 ( (L"Could not hook ProcessLookStick (Status: \"%hs\"); sensitivity "
                  L"override and input bypass disabled", MH_StatusToString (status)),
                 L" OW2 " );
    }
  }

  const double scan_ms =
    1000.0 * static_cast <double> (SK_QueryPerf ().QuadPart - start.QuadPart)
           / static_cast <double> (SK_PerfFreq);

  SK_LOG0 ( (L"Resolved in %.1f ms (%.1f MiB .text): sensitivity=%hs, bypass=%hs, save limit=%hs",
               scan_ms, static_cast <double> (text_size) / (1024.0 * 1024.0),
               SK_OW2.sensitivity_supported ? "yes" : "no",
               SK_OW2.bypass_supported      ? "yes" : "no",
               SK_OW2.save_limit_supported  ? "yes" : "no"),
             L" OW2 " );

  WriteRelease (&SK_OW2.resolved, 1);

  SK_Thread_CloseSelf ();

  return 0;
}

static constexpr int32_t SK_OW2_SaveLimit_Raised       = 9999;
static constexpr int32_t SK_OW2_SaveLimit_Default      = 100; // The game's own default.
static constexpr int32_t SK_OW2_SaveLimit_MinPlausible = 1;
static constexpr int32_t SK_OW2_SaveLimit_MaxPlausible = 100000;

// One-slot record of the value overwritten the last time the limit was
// raised. Render thread only (EndFrame), so no locking.
static struct {
  uint8_t *mgr   = nullptr; // nullptr = empty
  int32_t  value = 0;
} SK_OW2_SaveLimitSlot;

// Render thread only; latches the fault log below to one line.
static bool SK_OW2_SaveLimitFaultLogged = false;

// mgr may be concurrently freed or replaced by the game (e.g. a save/load
// swaps the manager), so the read and the write both go through SEH. No C++
// objects here needing unwinding (C2712). did_raise is set when this call
// wrote 9999 from the raise side; the caller persists that outside the SEH.
static bool
SK_OW2_ApplySaveLimit (uint8_t *gi, bool raise, bool allow_default_fallback, bool& did_raise)
{
  did_raise = false;

  __try
  {
    uint8_t *mgr =
      *reinterpret_cast <uint8_t **> (gi + SK_OW2_GameInstance_SaveMgr);

    if (mgr == nullptr)
      return true;

    auto *pv =
      reinterpret_cast <int32_t *> (mgr + SK_OW2_SaveMgr_MaxOverwriteableSaves);
    const int32_t v = *pv;

    auto& slot = SK_OW2_SaveLimitSlot;

    if (raise)
    {
      // Already raised, or implausible; leave it alone. Once written, v reads
      // back as 9999 next call, so this only ever fires once per mgr.
      if (v != SK_OW2_SaveLimit_Raised &&
          v >= SK_OW2_SaveLimit_MinPlausible && v <= SK_OW2_SaveLimit_MaxPlausible)
      {
        slot.mgr   = mgr;
        slot.value = v;
        *pv        = SK_OW2_SaveLimit_Raised;
        did_raise  = true;
      }
    }

    else
    {
      if (slot.mgr == mgr && v == SK_OW2_SaveLimit_Raised)
      {
        *pv      = slot.value;
        slot.mgr = nullptr;
      }

      else if (slot.mgr != nullptr && slot.mgr != mgr)
      {
        slot.mgr = nullptr;
      }

      // No recorded value (e.g. the game persisted 9999 through its Config
      // property across a restart): fall back to the game's own default, but
      // only for users who have raised the limit before (allow_default_fallback);
      // otherwise a game build that ships 9999 as its own default would get
      // silently lowered. Self-corrects after one write, same as the raise
      // side above.
      else if (allow_default_fallback && slot.mgr == nullptr && v == SK_OW2_SaveLimit_Raised)
      {
        *pv = SK_OW2_SaveLimit_Default;
      }
    }

    return true;
  }

  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    return false;
  }
}

void __stdcall
SK_OW2_EndFrame (void)
{
  if (! (ReadAcquire (&SK_OW2.resolved) && SK_OW2.save_limit_supported))
    return;

  // GGameInstance itself never moves once created (like GEngine; see
  // SK_OW2_GetGUS), so this deref needs no SEH.
  uint8_t *gi =
    (SK_OW2.pGGameInstance != nullptr) ? *SK_OW2.pGGameInstance : nullptr;

  if (gi == nullptr)
    return;

  bool did_raise = false;

  const bool ok =
    SK_OW2_ApplySaveLimit ( gi, SK_OW2_Config.raise_save_limit,
                                 SK_OW2_Config.save_limit_was_raised, did_raise );

  if (! ok)
  {
    if (! SK_OW2_SaveLimitFaultLogged)
    {
      SK_LOG0 ( (L"Save limit read/write faulted"), L" OW2 " );
      SK_OW2_SaveLimitFaultLogged = true;
    }

    return;
  }

  if (did_raise && ! SK_OW2_Config.save_limit_was_raised)
  {
    SK_OW2_Config.save_limit_was_raised = true;

    SK_OW2.ini_params.store ();
    config.utility.save_async_if (true);
  }
}

bool
SK_OW2_PlugInCfg (void)
{
  if (ImGui::CollapsingHeader ("The Outer Worlds 2", ImGuiTreeNodeFlags_DefaultOpen))
  {
    ImGui::TreePush ("");

    const bool resolved =
      ReadAcquire (&SK_OW2.resolved) != 0;

    auto& cfg = SK_OW2_Config;

    // Scan / support status beside the previous item.
    auto _Unavailable = [&](bool supported)
    {
      if (! resolved)
      {
        ImGui::SameLine     ();
        ImGui::TextDisabled ("Scanning game...");
      }

      else if (! supported)
      {
        ImGui::SameLine     ();
        ImGui::TextDisabled ("Unsupported game build");
      }
    };

    auto _Tooltip = [](const char *text)
    {
      if (ImGui::IsItemHovered (ImGuiHoveredFlags_AllowWhenDisabled))
        ImGui::SetTooltip ("%s", text);
    };

    bool toggled = false;

    // Input processing bypass
    const bool bypass_supported =
      ReadAcquire (&SK_OW2.bypass_supported) != 0;
    const bool bypass_off =
      (! resolved) || (! bypass_supported);

    ImGui::BeginDisabled (bypass_off);
    toggled |=
      ImGui::Checkbox ("Bypass controller input processing###SK_OW2_Bypass", &cfg.bypass_input);
    _Tooltip ( "Removes the game's stick deadzones, response curves, acceleration, yaw ramp, "
               "angular deadzone and weapon ADS stick multiplier.\n\n"
               "Keeps the sprint turn multiplier, the pitch multiplier setting and aim assist." );
    ImGui::EndDisabled ();
    _Unavailable (bypass_supported);

    if (! bypass_off)
    {
      // The patches follow the checkbox on the next gameplay frame.
      const bool applied =
        ReadAcquire (&SK_OW2.bypass_applied) != 0;

      const char *status =
        applied ? (cfg.bypass_input ? "Active"
                                    : "Removing at next gameplay frame")
                : (cfg.bypass_input ? "Waiting for gameplay"
                                    : nullptr);

      if (status != nullptr)
      {
        ImGui::SameLine     ();
        ImGui::TextDisabled ("%s", status);
      }
    }

    // Sensitivity override
    const bool sens_off =
      (! resolved) || (! SK_OW2.sensitivity_supported);

    ImGui::BeginDisabled (sens_off);
    toggled |=
      ImGui::Checkbox ("Override sensitivity###SK_OW2_OverrideSens", &cfg.override_sens);
    ImGui::EndDisabled ();
    _Unavailable (SK_OW2.sensitivity_supported);

    ImGui::BeginDisabled (sens_off);
    {
      static constexpr const char *slider_tip =
        "With bypass on, 100% = 120 deg/s yaw at full stick.\n\n"
        "With bypass off the game maps it as 0.5 + 1.5 x value, so the same "
        "percentage is a different speed.";

      auto _Slider = [&](const char *label, float& value)
      {
        float pct = value * 100.0f;

        if (ImGui::SliderFloat ( label, &pct, 0.0f, SK_OW2_MaxSensitivity * 100.0f,
                                   "%.0f%%", ImGuiSliderFlags_AlwaysClamp ))
        {
          value = SK_OW2_SanitizeSensitivity (pct / 100.0f);
        }

        // The live value follows the drag; persist once it ends.
        if (ImGui::IsItemDeactivatedAfterEdit ())
        {
          SK_OW2.ini_params.store ();
          config.utility.save_async_if (true);
        }

        _Tooltip (slider_tip);
      };

      ImGui::TreePush ("");
      _Slider ("View###SK_OW2_ViewSens", cfg.view_sensitivity);
      _Slider ("ADS###SK_OW2_ADSSens",   cfg.ads_sensitivity);

      float game_view = 0.0f;
      float game_ads  = 0.0f;

      if (resolved && SK_OW2_ReadGameSens (game_view, game_ads))
      {
        ImGui::TextDisabled ( "Game's current values: View %.0f%%, ADS %.0f%%",
                               game_view * 100.0f, game_ads * 100.0f );
      }

      else
        ImGui::TextDisabled ("Game's current values: n/a");

      ImGui::TreePop  ();
    }
    ImGui::EndDisabled ();

    // Save limit
    const bool save_off =
      (! resolved) || (! SK_OW2.save_limit_supported);

    ImGui::BeginDisabled (save_off);
    toggled |=
      ImGui::Checkbox ("Raise manual save limit to 9999###SK_OW2_SaveLimit", &cfg.raise_save_limit);
    _Tooltip ("Takes effect the next time the save menu opens.");
    ImGui::EndDisabled ();
    _Unavailable (SK_OW2.save_limit_supported);

    if (toggled)
    {
      SK_OW2.ini_params.store ();
      config.utility.save_async_if (true);
    }

    ImGui::TreePop ();
  }

  return true;
}

void
SK_OW2_InitPlugin (void)
{
  SK_RunOnce (
  {
    SK_OW2.ini_params.init ();

    SK_OW2_Config.view_sensitivity =
      SK_OW2_SanitizeSensitivity (SK_OW2_Config.view_sensitivity);
    SK_OW2_Config.ads_sensitivity =
      SK_OW2_SanitizeSensitivity (SK_OW2_Config.ads_sensitivity);

    SK_OW2.ini_params.store ();

    plugin_mgr->config_fns.insert    (SK_OW2_PlugInCfg);
    plugin_mgr->end_frame_fns.insert (SK_OW2_EndFrame);

    SK_Thread_CreateEx (SK_OW2_ResolveThread, L"[SK] OW2 Pattern Scan");
  });
}

#endif
