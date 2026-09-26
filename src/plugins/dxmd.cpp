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

// Deus Ex: Mankind Divided (DXMD.exe / DXMD_real.exe, Dawn engine, Nixxes PC
// port). Every address is resolved by pattern; the reverse engineering is in
// the dxmd-re repository (NOTES.md).

static constexpr float SK_DXMD_MaxSensitivity = 3.0f;

// uint8_t NxXInput_ConvertAxis (void *dev, uint8_t *pad, int axis, int16_t x, int16_t y);
using SK_DXMD_ConvertAxis_pfn =
  uint8_t (*)(void *dev, uint8_t *pad, int axis, int16_t x, int16_t y);

// void *ZNavigationInputScheme_Update (uint8_t *self, void *ctx);
using SK_DXMD_NavUpdate_pfn =
  void* (*)(uint8_t *self, void *ctx);

// void *ZInputControlStick_Update (uint8_t *self, void *ctx);
using SK_DXMD_StickUpdate_pfn =
  void* (*)(uint8_t *self, void *ctx);

// float *ZPlayerAimingSystem_ProcessLookInput (uint8_t *self, float *out, void *unused,
//                                               float stickX, float stickY, void *params,
//                                               bool xFromGamepad, bool yFromGamepad);
using SK_DXMD_ProcessLookInput_pfn =
  float* (*)(uint8_t *self, float *out, void *unused, float stickX, float stickY,
             void *params, bool xFromGamepad, bool yFromGamepad);

enum SK_DXMD_PatternId {
  SK_DXMD_Pat_N_R,             // Anchor; ConvertAxis is derived from this match (see below).
  SK_DXMD_Pat_NavUpdate,
  SK_DXMD_Pat_StickUpdate,
  SK_DXMD_Pat_ProcessLookInput,
  SK_DXMD_Pat_RateFilterFlag,

  SK_DXMD_Pat_Count
};

static constexpr struct {
  const char *name;
  const char *ida;
} SK_DXMD_PatternDefs [SK_DXMD_Pat_Count] = {
  { "N_R",              "44 38 42 73 0F 84 ?? ?? ?? ?? 45 0F BF C1"                                                                                        },
  { "NavUpdate",        "40 55 53 56 57 48 8D 6C 24 C1 48 81 EC 98 00 00 00 48 8B 41 E8 48 8B F1 0F 29 B4 24 80 00 00 00 48 83 C1 E8"                     },
  { "StickUpdate",      "48 8B C4 55 53 56 48 8D 68 A1 48 81 EC D0 00 00 00 83 79 18 00 0F 29 70 D8"                                                      },
  { "ProcessLookInput", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 41 56 48 83 EC 60 33 C0 0F 29 74 24 50 0F 29 7C 24 40 48 89 02 89 42 08 48 8B FA" },
  { "RateFilterFlag",   "80 3D ?? ?? ?? ?? 00 0F 85 8D 00 00 00 80 BC 24 A0 00 00 00 00"                                                                  },
};

// ConvertAxis has no distinctive entry bytes of its own; it sits at a fixed
// offset before its caller's N_R comparison. The prologue is checked so a
// pattern-table mismatch counts as not found rather than hooking garbage.
static constexpr ptrdiff_t SK_DXMD_ConvertAxis_Offset = -0x38;
static constexpr uint8_t   SK_DXMD_ConvertAxis_Prologue [] =
  { 0x40, 0x55, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x30, 0x45, 0x85, 0xC0 };

// Shared between the render thread (UI) and the game thread; each value is
// read and written whole, so no locking.
static struct {
  bool  bypass_input     = false;
  bool  override_sens    = false;
  float view_sensitivity = 1.0f;
  float ads_sensitivity  = 1.0f;
} SK_DXMD_Config;

static struct {
  // Written once by the scan worker before the release store to resolved;
  // the panel ReadAcquires resolved first; detours read the flags plain and
  // see false until the worker stores them last.
  volatile LONG resolved              = 0;

  bool          sensitivity_supported = false;
  bool          bypass_supported      = false;

  uint8_t      *pConvertAxis          = nullptr;
  uint8_t      *pNavUpdate            = nullptr;
  uint8_t      *pStickUpdate          = nullptr;
  uint8_t      *pProcessLookInput     = nullptr;
  uint8_t      *g_DisableLookRateFilters = nullptr; // Byte global; RateFilterFlag target.

  SK_DXMD_ConvertAxis_pfn
                ConvertAxis_Original      = nullptr;
  SK_DXMD_NavUpdate_pfn
                NavUpdate_Original        = nullptr;
  SK_DXMD_StickUpdate_pfn
                StickUpdate_Original      = nullptr;
  SK_DXMD_ProcessLookInput_pfn
                ProcessLookInput_Original = nullptr;

  // The game's own gamepad sensitivity, copied by the ProcessLookInput detour
  // (game thread) for the panel (render thread), which never reads game memory.
  bool          game_sens_seen        = false;
  float         game_sens_x           = 0.0f;
  float         game_sens_y           = 0.0f;

  struct {
    void init (void)
    {
      bypass_input =
        _CreateConfigParameterBool  ( L"DXMD.PlugIn",
                                      L"BypassInputProcessing", SK_DXMD_Config.bypass_input,
                                        L"Bypass the game's controller input processing" );
      override_sens =
        _CreateConfigParameterBool  ( L"DXMD.PlugIn",
                                      L"OverrideSensitivity",   SK_DXMD_Config.override_sens,
                                        L"Enforce the view / ADS controller sensitivity below" );
      view_sensitivity =
        _CreateConfigParameterFloat ( L"DXMD.PlugIn",
                                      L"ViewSensitivity",       SK_DXMD_Config.view_sensitivity,
                                        L"Controller view sensitivity, 0.0-3.0" );
      ads_sensitivity =
        _CreateConfigParameterFloat ( L"DXMD.PlugIn",
                                      L"ADSSensitivity",        SK_DXMD_Config.ads_sensitivity,
                                        L"Controller ADS sensitivity, 0.0-3.0" );
    }

    void store (void)
    {
      bypass_input->store     (SK_DXMD_Config.bypass_input);
      override_sens->store    (SK_DXMD_Config.override_sens);
      view_sensitivity->store (SK_DXMD_Config.view_sensitivity);
      ads_sensitivity->store  (SK_DXMD_Config.ads_sensitivity);
    }

    sk::ParameterBool*  bypass_input     = nullptr;
    sk::ParameterBool*  override_sens    = nullptr;
    sk::ParameterFloat* view_sensitivity = nullptr;
    sk::ParameterFloat* ads_sensitivity  = nullptr;
  } ini_params;
} SK_DXMD;

// A NaN would make the slider math propagate NaN into the panel every frame.
static float
SK_DXMD_SanitizeSensitivity (float value)
{
  if (! std::isfinite (value))
    return 1.0f;

  return
    std::clamp (value, 0.0f, SK_DXMD_MaxSensitivity);
}

// Game object offsets (dxmd-re NOTES.md).
static constexpr ptrdiff_t SK_DXMD_Pad_LeftDeadzoneFlag  = 0x72;  // uint8_t; non-zero applies the XInput deadzone
static constexpr ptrdiff_t SK_DXMD_Pad_RightDeadzoneFlag = 0x73;

static constexpr ptrdiff_t SK_DXMD_Nav_OutputX           = 0xe0;  // int32 analog ID; look = 0 / 1
static constexpr ptrdiff_t SK_DXMD_Nav_OutputY           = 0xe4;
static constexpr ptrdiff_t SK_DXMD_Nav_CurveRefs         = 0xe8;  // Two 0x10-byte entity refs; an all-zero ref is skipped
static constexpr size_t    SK_DXMD_Nav_CurveRefsSize     = 0x20;
static constexpr ptrdiff_t SK_DXMD_Nav_RightDeadzoneType = 0x11c; // int32

static constexpr ptrdiff_t SK_DXMD_Stick_Stick           = 0x18;  // int32; 0 left, 1 right
static constexpr ptrdiff_t SK_DXMD_Stick_DirOutputs      = 0x1c;  // int32 x4 directional output IDs
static constexpr ptrdiff_t SK_DXMD_Stick_OutputX         = 0x2c;
static constexpr ptrdiff_t SK_DXMD_Stick_OutputY         = 0x30;
static constexpr ptrdiff_t SK_DXMD_Stick_Directional     = 0x34;  // int32; 0 = X/Y outputs
static constexpr ptrdiff_t SK_DXMD_Stick_Curve           = 0x40;  // Response curve entity or null
static constexpr ptrdiff_t SK_DXMD_Stick_DeadzoneType    = 0x48;  // int32

static constexpr ptrdiff_t SK_DXMD_Aim_SensY             = 0x08;  // float gamepad sensitivity; menu range 0.75-1.75
static constexpr ptrdiff_t SK_DXMD_Aim_SensX             = 0x0c;
static constexpr ptrdiff_t SK_DXMD_Aim_Owner             = 0x118; // Start of the aim-flag query

static constexpr int32_t   SK_DXMD_DeadzoneType_None     = 1;

// Aim-flag query: owner->vtbl [0x348 / 8] returns r; the character is at
// r + 8 and its state machine at character + 0xa0, whose vtbl [0x90 / 8] is
// HasFlag (sm, flag).
static constexpr size_t    SK_DXMD_Owner_GetR_Slot       = 0x348 / 8;
static constexpr ptrdiff_t SK_DXMD_R_Character           = 0x08;
static constexpr ptrdiff_t SK_DXMD_Char_StateMachine     = 0xa0;
static constexpr size_t    SK_DXMD_SM_HasFlag_Slot       = 0x90 / 8;

static constexpr int       SK_DXMD_Flag_GoingToIronSight = 0x43;
static constexpr int       SK_DXMD_Flag_IronSight        = 0x44;
static constexpr int       SK_DXMD_Flag_InCover          = 0x51;
static constexpr int       SK_DXMD_Flag_CoverAim         = 0x71;

template <typename T>
static T&
SK_DXMD_Field (uint8_t *base, ptrdiff_t offset)
{
  return
    *reinterpret_cast <T *> (base + offset);
}

static bool
SK_DXMD_BypassActive (void)
{
  return
    SK_DXMD_Config.bypass_input && SK_DXMD.bypass_supported;
}

static bool
SK_DXMD_SensitivityActive (void)
{
  return
    SK_DXMD_Config.override_sens && SK_DXMD.sensitivity_supported;
}

static bool
SK_DXMD_HasFlag (uint8_t *sm, int flag)
{
  using HasFlag_pfn = uint32_t (*)(uint8_t *sm, int flag);

  const HasFlag_pfn has_flag =
    (*reinterpret_cast <HasFlag_pfn **> (sm)) [SK_DXMD_SM_HasFlag_Slot];

  return
    (has_flag (sm, flag) & 0xff) != 0;
}

// Mirrors the game's base-speed tree: in cover, aiming = aiming from cover;
// otherwise iron sight or going to it. HasFlag does not null-check the state
// machine (the game makes the same call unguarded), so the whole query runs
// under SEH and a fault reads as not aiming. No C++ objects here needing
// unwinding (C2712).
static bool
SK_DXMD_IsAiming (uint8_t *self)
{
  __try
  {
    uint8_t *owner =
      SK_DXMD_Field <uint8_t *> (self, SK_DXMD_Aim_Owner);

    if (owner == nullptr)
      return false;

    using GetR_pfn = uint8_t* (*)(uint8_t *owner);

    const GetR_pfn get_r =
      (*reinterpret_cast <GetR_pfn **> (owner)) [SK_DXMD_Owner_GetR_Slot];

    uint8_t *r =
      get_r (owner);

    if (r == nullptr)
      return false;

    uint8_t *character =
      SK_DXMD_Field <uint8_t *> (r, SK_DXMD_R_Character);

    if (character == nullptr)
      return false;

    uint8_t *sm = character + SK_DXMD_Char_StateMachine;

    if (SK_DXMD_HasFlag (sm, SK_DXMD_Flag_InCover))
      return SK_DXMD_HasFlag (sm, SK_DXMD_Flag_CoverAim);

    return
      SK_DXMD_HasFlag (sm, SK_DXMD_Flag_GoingToIronSight) ||
      SK_DXMD_HasFlag (sm, SK_DXMD_Flag_IronSight);
  }

  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    return false;
  }
}

// Layer 0: with the pad's per-stick flag clear, ConvertAxis returns v / 32767
// instead of applying the XInput radial deadzone. The game re-copies the flag
// from a global config every poll, so it is cleared only for the call.
static uint8_t
SK_DXMD_ConvertAxis_Detour (void *dev, uint8_t *pad, int axis, int16_t x, int16_t y)
{
  const ptrdiff_t flag_offset =
    axis == 2 ? SK_DXMD_Pad_LeftDeadzoneFlag  :
    axis == 3 ? SK_DXMD_Pad_RightDeadzoneFlag : 0;

  if (flag_offset == 0 || (! SK_DXMD_BypassActive ()))
  {
    return
      SK_DXMD.ConvertAxis_Original (dev, pad, axis, x, y);
  }

  uint8_t&      flag  = SK_DXMD_Field <uint8_t> (pad, flag_offset);
  const uint8_t saved = flag;

  flag = 0;

  const uint8_t ret =
    SK_DXMD.ConvertAxis_Original (dev, pad, axis, x, y);

  if (flag == 0)
      flag = saved;

  return ret;
}

// The gameplay look scheme (outputs to analogs 0 / 1) runs with no right-stick
// deadzone and no magnitude curves. The left-stick deadzone type only blends
// the two curves, so it is left alone.
static void *
SK_DXMD_NavUpdate_Detour (uint8_t *self, void *ctx)
{
  if ( SK_DXMD_Field <int32_t> (self, SK_DXMD_Nav_OutputX) != 0 ||
       SK_DXMD_Field <int32_t> (self, SK_DXMD_Nav_OutputY) != 1 ||
       (! SK_DXMD_BypassActive ()) )
  {
    return
      SK_DXMD.NavUpdate_Original (self, ctx);
  }

  static constexpr uint8_t zero_refs [SK_DXMD_Nav_CurveRefsSize] = { };

  int32_t& dz_type = SK_DXMD_Field <int32_t> (self, SK_DXMD_Nav_RightDeadzoneType);
  uint8_t* refs    = self + SK_DXMD_Nav_CurveRefs;

  const int32_t saved_dz_type = dz_type;
  uint8_t       saved_refs [SK_DXMD_Nav_CurveRefsSize];

  memcpy (saved_refs, refs, SK_DXMD_Nav_CurveRefsSize);

  dz_type = SK_DXMD_DeadzoneType_None;
  memset (refs, 0, SK_DXMD_Nav_CurveRefsSize);

  void *ret =
    SK_DXMD.NavUpdate_Original (self, ctx);

  if (0 == memcmp (refs, zero_refs, SK_DXMD_Nav_CurveRefsSize))
    memcpy (refs, saved_refs, SK_DXMD_Nav_CurveRefsSize);

  if (dz_type == SK_DXMD_DeadzoneType_None)
      dz_type = saved_dz_type;

  return ret;
}

// Runs for hundreds of instances per frame, nested inside NavUpdate; only the
// gameplay look and movement mappers lose their curve and deadzone. The left
// X/Y mappers (menu navigation) and right-stick UI mappers are left alone.
static void *
SK_DXMD_StickUpdate_Detour (uint8_t *self, void *ctx)
{
  if (! SK_DXMD_BypassActive ())
  {
    return
      SK_DXMD.StickUpdate_Original (self, ctx);
  }

  auto _Int = [self](ptrdiff_t offset) -> int32_t
  {
    return
      SK_DXMD_Field <int32_t> (self, offset);
  };

  const int32_t stick = _Int (SK_DXMD_Stick_Stick);

  const bool look =
    stick == 1 && _Int (SK_DXMD_Stick_OutputX)     == 0 &&
                  _Int (SK_DXMD_Stick_OutputY)     == 1 &&
                  _Int (SK_DXMD_Stick_Directional) == 0;

  const bool move =
    stick == 0 && _Int (SK_DXMD_Stick_Directional)      != 0 &&
                  _Int (SK_DXMD_Stick_DirOutputs + 0x0) == 2 &&
                  _Int (SK_DXMD_Stick_DirOutputs + 0x4) == 3 &&
                  _Int (SK_DXMD_Stick_DirOutputs + 0x8) == 4 &&
                  _Int (SK_DXMD_Stick_DirOutputs + 0xc) == 5;

  if (! (look || move))
  {
    return
      SK_DXMD.StickUpdate_Original (self, ctx);
  }

  void*&   curve   = SK_DXMD_Field <void *>  (self, SK_DXMD_Stick_Curve);
  int32_t& dz_type = SK_DXMD_Field <int32_t> (self, SK_DXMD_Stick_DeadzoneType);

  void          *saved_curve   = curve;
  const int32_t  saved_dz_type = dz_type;

  dz_type = SK_DXMD_DeadzoneType_None;
  curve   = nullptr;

  void *ret =
    SK_DXMD.StickUpdate_Original (self, ctx);

  if (curve == nullptr)
      curve = saved_curve;

  if (dz_type == SK_DXMD_DeadzoneType_None)
      dz_type = saved_dz_type;

  return ret;
}

// Player look. With bypass on, g_DisableLookRateFilters skips the per-axis
// rate-of-change filters (look acceleration) for this call; the game never
// writes the flag itself. The override swaps in View or ADS for the game's
// sensitivity fields, which are read only here, so ADS scales the game's own
// aiming base speed just as View scales the hip one.
static float *
SK_DXMD_ProcessLookInput_Detour ( uint8_t *self, float *out, void *unused,
                                   float stickX, float stickY, void *params,
                                   bool xFromGamepad, bool yFromGamepad )
{
  float& sens_x = SK_DXMD_Field <float> (self, SK_DXMD_Aim_SensX);
  float& sens_y = SK_DXMD_Field <float> (self, SK_DXMD_Aim_SensY);

  SK_DXMD.game_sens_x    = sens_x;
  SK_DXMD.game_sens_y    = sens_y;
  SK_DXMD.game_sens_seen = true;

  const bool bypass =
    SK_DXMD_BypassActive ();
  const bool override_sens =
    SK_DXMD_SensitivityActive ();

  uint8_t* rate_filters       = SK_DXMD.g_DisableLookRateFilters;
  uint8_t  saved_rate_filters = 0;

  if (bypass)
  {
    saved_rate_filters = *rate_filters;
    *rate_filters      = 1;
  }

  const float saved_sens_x = sens_x;
  const float saved_sens_y = sens_y;
  float       sens         = 0.0f;

  if (override_sens)
  {
    sens =
      SK_DXMD_IsAiming (self) ? SK_DXMD_Config.ads_sensitivity
                              : SK_DXMD_Config.view_sensitivity;

    sens_x = sens;
    sens_y = sens;
  }

  float *ret =
    SK_DXMD.ProcessLookInput_Original ( self, out, unused, stickX, stickY, params,
                                         xFromGamepad, yFromGamepad );

  if (override_sens)
  {
    if (sens_x == sens) sens_x = saved_sens_x;
    if (sens_y == sens) sens_y = saved_sens_y;
  }

  if (bypass && *rate_filters == 1)
    *rate_filters = saved_rate_filters;

  return ret;
}

static DWORD WINAPI
SK_DXMD_ResolveThread (LPVOID)
{
  const LARGE_INTEGER start =
    SK_QueryPerf ();

  // SK_PatternScan_ScanRange's dispatch table holds one bit per pattern in a
  // pass, so this single pass must stay within 16 patterns.
  static_assert (SK_DXMD_Pat_Count <= 16, "first_byte holds one bit per pattern in a pass");

  SK_PatternScan_Pattern pats [SK_DXMD_Pat_Count];

  bool parsed = true;

  for (int i = 0; i < SK_DXMD_Pat_Count; ++i)
    parsed &= SK_PatternScan_ParsePattern (SK_DXMD_PatternDefs [i].ida, pats [i]);

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
      SK_PatternScan_ScanRange (text, text_end, text_end, pats, SK_DXMD_Pat_Count);
  }

  if (! scanned)
  {
    SK_LOG0 ( (L"Could not scan the executable's .text section; all features disabled"),
               L" DXMD " );
  }

  // A partial scan cannot rule out duplicates, so it resolves nothing.
  auto _Found = [&](int id) -> const uint8_t *
  {
    return
      (! scanned) || pats [id].duplicate ? nullptr
                                         : pats [id].match;
  };

  for (int i = 0; scanned && i < SK_DXMD_Pat_Count; ++i)
  {
    if (pats [i].duplicate)
    {
      SK_LOG0 ( (L"Pattern %hs matched more than once", SK_DXMD_PatternDefs [i].name),
                 L" DXMD " );
    }
  }

  const uint8_t *n_r = _Found (SK_DXMD_Pat_N_R);

  const uint8_t *convert_axis = nullptr;

  if (n_r != nullptr)
  {
    const uint8_t *candidate = n_r + SK_DXMD_ConvertAxis_Offset;

    if (0 == memcmp (candidate, SK_DXMD_ConvertAxis_Prologue, sizeof (SK_DXMD_ConvertAxis_Prologue)))
      convert_axis = candidate;
  }

  SK_DXMD.pConvertAxis      = const_cast <uint8_t *> (convert_axis);
  SK_DXMD.pNavUpdate        = const_cast <uint8_t *> (_Found (SK_DXMD_Pat_NavUpdate));
  SK_DXMD.pStickUpdate      = const_cast <uint8_t *> (_Found (SK_DXMD_Pat_StickUpdate));
  SK_DXMD.pProcessLookInput = const_cast <uint8_t *> (_Found (SK_DXMD_Pat_ProcessLookInput));

  const uint8_t *rate_filter_flag =
    _Found (SK_DXMD_Pat_RateFilterFlag);

  SK_DXMD.g_DisableLookRateFilters =
    (rate_filter_flag != nullptr) ? SK_PatternScan_RipTarget (rate_filter_flag, 2, 7)
                                  : nullptr;

  auto _Append = [](std::string& list, const char *name)
  {
    list += (list.empty () ? "" : ", ") + std::string (name);
  };

  std::string missing_sens;

  if (SK_DXMD.pProcessLookInput == nullptr)
    _Append (missing_sens, "ProcessLookInput");

  std::string missing_bypass;

  if (SK_DXMD.pConvertAxis             == nullptr) _Append (missing_bypass, "ConvertAxis");
  if (SK_DXMD.pNavUpdate               == nullptr) _Append (missing_bypass, "NavUpdate");
  if (SK_DXMD.pStickUpdate             == nullptr) _Append (missing_bypass, "StickUpdate");
  if (SK_DXMD.pProcessLookInput        == nullptr) _Append (missing_bypass, "ProcessLookInput");
  if (SK_DXMD.g_DisableLookRateFilters == nullptr) _Append (missing_bypass, "RateFilterFlag");

  bool sens_ok = missing_sens.empty   ();
  bool byp_ok  = missing_bypass.empty ();

  if (! sens_ok)
    SK_LOG0 ( (L"Sensitivity override unsupported, missing: %hs", missing_sens.c_str ()), L" DXMD " );

  if (! byp_ok)
    SK_LOG0 ( (L"Input processing bypass unsupported, missing: %hs", missing_bypass.c_str ()), L" DXMD " );

  // Hooks are created only after every pattern above is resolved.
  MH_STATUS status_look = MH_UNKNOWN;

  if (sens_ok || byp_ok)
  {
    status_look =
      SK_CreateFuncHook (      L"DXMD_ProcessLookInput",
                                  SK_DXMD.pProcessLookInput,
                                    SK_DXMD_ProcessLookInput_Detour,
         static_cast_p2p <void> (&SK_DXMD.ProcessLookInput_Original) );

    if (status_look != MH_OK)
    {
      sens_ok = false;
      byp_ok  = false;

      SK_LOG0 ( (L"Could not hook ProcessLookInput (Status: \"%hs\"); sensitivity override "
                  L"and input bypass disabled", MH_StatusToString (status_look)),
                 L" DXMD " );
    }
  }

  if (byp_ok)
  {
    const MH_STATUS status_convert =
      SK_CreateFuncHook (      L"DXMD_ConvertAxis",
                                  SK_DXMD.pConvertAxis,
                                    SK_DXMD_ConvertAxis_Detour,
         static_cast_p2p <void> (&SK_DXMD.ConvertAxis_Original) );

    const MH_STATUS status_nav =
      SK_CreateFuncHook (      L"DXMD_NavUpdate",
                                  SK_DXMD.pNavUpdate,
                                    SK_DXMD_NavUpdate_Detour,
         static_cast_p2p <void> (&SK_DXMD.NavUpdate_Original) );

    const MH_STATUS status_stick =
      SK_CreateFuncHook (      L"DXMD_StickUpdate",
                                  SK_DXMD.pStickUpdate,
                                    SK_DXMD_StickUpdate_Detour,
         static_cast_p2p <void> (&SK_DXMD.StickUpdate_Original) );

    if (status_convert != MH_OK || status_nav != MH_OK || status_stick != MH_OK)
    {
      byp_ok = false;

      SK_LOG0 ( (L"Could not hook the bypass entry points (ConvertAxis: \"%hs\", NavUpdate: \"%hs\", "
                  L"StickUpdate: \"%hs\"); input bypass disabled",
                   MH_StatusToString (status_convert), MH_StatusToString (status_nav),
                   MH_StatusToString (status_stick)),
                 L" DXMD " );
    }
  }

  if (sens_ok)
    MH_QueueEnableHook (SK_DXMD.pProcessLookInput);

  if (byp_ok)
  {
    if (! sens_ok)
      MH_QueueEnableHook (SK_DXMD.pProcessLookInput);

    MH_QueueEnableHook (SK_DXMD.pConvertAxis);
    MH_QueueEnableHook (SK_DXMD.pNavUpdate);
    MH_QueueEnableHook (SK_DXMD.pStickUpdate);
  }

  if (sens_ok || byp_ok)
  {
    // A no-op until SK_InitFinishCallback calls SK_EnableApplyQueuedHooks;
    // the detours go live there, still before any gameplay frame.
    SK_ApplyQueuedHooks ();
  }

  SK_DXMD.sensitivity_supported = sens_ok;
  SK_DXMD.bypass_supported      = byp_ok;

  const double scan_ms =
    1000.0 * static_cast <double> (SK_QueryPerf ().QuadPart - start.QuadPart)
           / static_cast <double> (SK_PerfFreq);

  SK_LOG0 ( (L"Resolved in %.1f ms (%.1f MiB .text): sensitivity=%hs, bypass=%hs",
               scan_ms, static_cast <double> (text_size) / (1024.0 * 1024.0),
               SK_DXMD.sensitivity_supported ? "yes" : "no",
               SK_DXMD.bypass_supported      ? "yes" : "no"),
             L" DXMD " );

  WriteRelease (&SK_DXMD.resolved, 1);

  SK_Thread_CloseSelf ();

  return 0;
}

bool
SK_DXMD_PlugInCfg (void)
{
  if (ImGui::CollapsingHeader ("Deus Ex: Mankind Divided", ImGuiTreeNodeFlags_DefaultOpen))
  {
    ImGui::TreePush ("");

    const bool resolved =
      ReadAcquire (&SK_DXMD.resolved) != 0;

    auto& cfg = SK_DXMD_Config;

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
    const bool bypass_off =
      (! resolved) || (! SK_DXMD.bypass_supported);

    ImGui::BeginDisabled (bypass_off);
    toggled |=
      ImGui::Checkbox ("Bypass controller input processing###SK_DXMD_Bypass", &cfg.bypass_input);
    _Tooltip ( "Removes the Nixxes and engine stick deadzones (both sticks), the look response "
               "curve and look acceleration.\n\n"
               "Keeps the game's state-based turn speed (hip / cover / aiming), the weapon aim "
               "factor and aim assist; pair it with SK's stick deadzone." );
    ImGui::EndDisabled ();
    _Unavailable (SK_DXMD.bypass_supported);

    // Sensitivity override
    const bool sens_off =
      (! resolved) || (! SK_DXMD.sensitivity_supported);

    ImGui::BeginDisabled (sens_off);
    toggled |=
      ImGui::Checkbox ("Override sensitivity###SK_DXMD_OverrideSens", &cfg.override_sens);
    _Tooltip ( "Replaces the game's controller sensitivity with the View value, or the ADS "
               "value while aiming down sights or aiming from cover." );
    ImGui::EndDisabled ();
    _Unavailable (SK_DXMD.sensitivity_supported);

    ImGui::BeginDisabled (sens_off);
    {
      static constexpr const char *slider_tip =
        "With bypass on, 100% View = 360 deg/s yaw and 240 deg/s pitch at full stick "
        "(288 / 192 in cover); 100% ADS = 180 / 120 deg/s x the weapon's aim factor.\n\n"
        "Without bypass, the curve and acceleration make the effective speed lower and "
        "non-linear.";

      auto _Slider = [&](const char *label, float& value)
      {
        float pct = value * 100.0f;

        if (ImGui::SliderFloat ( label, &pct, 0.0f, SK_DXMD_MaxSensitivity * 100.0f,
                                   "%.0f%%", ImGuiSliderFlags_AlwaysClamp ))
        {
          value = SK_DXMD_SanitizeSensitivity (pct / 100.0f);
        }

        // The live value follows the drag; persist once it ends.
        if (ImGui::IsItemDeactivatedAfterEdit ())
        {
          SK_DXMD.ini_params.store ();
          config.utility.save_async_if (true);
        }

        _Tooltip (slider_tip);
      };

      ImGui::TreePush ("");
      _Slider ("View###SK_DXMD_ViewSens", cfg.view_sensitivity);
      _Slider ("ADS###SK_DXMD_ADSSens",   cfg.ads_sensitivity);

      // Copied by the ProcessLookInput detour; n/a until the first gameplay frame.
      if (SK_DXMD.game_sens_seen)
      {
        ImGui::TextDisabled ( "Game's current values: X %.0f%%, Y %.0f%%",
                               SK_DXMD.game_sens_x * 100.0f, SK_DXMD.game_sens_y * 100.0f );
      }

      else
        ImGui::TextDisabled ("Game's current values: n/a");

      ImGui::TreePop ();
    }
    ImGui::EndDisabled ();

    if (toggled)
    {
      SK_DXMD.ini_params.store ();
      config.utility.save_async_if (true);
    }

    ImGui::TreePop ();
  }

  return true;
}

void
SK_DXMD_InitPlugin (void)
{
  SK_RunOnce (
  {
    SK_DXMD.ini_params.init ();

    SK_DXMD_Config.view_sensitivity =
      SK_DXMD_SanitizeSensitivity (SK_DXMD_Config.view_sensitivity);
    SK_DXMD_Config.ads_sensitivity =
      SK_DXMD_SanitizeSensitivity (SK_DXMD_Config.ads_sensitivity);

    SK_DXMD.ini_params.store ();

    plugin_mgr->config_fns.insert (SK_DXMD_PlugInCfg);

    SK_Thread_CreateEx (SK_DXMD_ResolveThread, L"[SK] DXMD Pattern Scan");
  });
}

#endif
