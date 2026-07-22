// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
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
#include <SpecialK/input/game_input.h>

#include <imgui/font_awesome.h>

#ifdef  __SK_SUBSYSTEM__
#undef  __SK_SUBSYSTEM__
#endif
#define __SK_SUBSYSTEM__ L"Input Mgr."

#define SK_LOG_INPUT_CALL { static int  calls  = 0;             \
  { SK_LOG0 ( (L"[!] > Call #%lu: %hs", calls++, __FUNCTION__), \
               L"Input Mgr." ); } }

///////////////////////////////////////////////////////
//
// GameInput.dll  (SK_GI)
//
///////////////////////////////////////////////////////

extern SK_LazyGlobal <sk_input_api_context_s> SK_GameInput_Backend;

#define SK_GAMEINPUT_READ(type)  SK_GameInput_Backend->markRead   (type);
#define SK_GAMEINPUT_WRITE(type) SK_GameInput_Backend->markWrite  (type);
#define SK_GAMEINPUT_VIEW(type)  SK_GameInput_Backend->markViewed (type);
#define SK_GAMEINPUT_HIDE(type)  SK_GameInput_Backend->markHidden (type);

#define GI_VIRTUAL_HOOK(_Base,_Index,_Name,_Override,_Original,_Type) {       \
  void** _vftable = *(void***)*(_Base);                                       \
                                                                              \
  if ((_Original) == nullptr) {                                               \
    SK_CreateVFTableHook2 ( L##_Name,                                         \
                              _vftable,                                       \
                                (_Index),                                     \
                                  (_Override),                                \
                                    (LPVOID *)&(_Original));                  \
                                                                              \
    /* The queued enable is silently dropped while the global apply flag  */  \
    /* is off (early init); enable directly so one-shot call sites are    */  \
    /* intercepted from the first call.                                   */  \
    if ((_Original) != nullptr)                                               \
      SK_EnableHook (_vftable [_Index]);                                      \
  }                                                                           \
}

bool SK_GameInput_EmulatedPlayStation = false;

using GameInputCreate_pfn = HRESULT (WINAPI *)(IGameInput**);
      GameInputCreate_pfn
      GameInputCreate_Original = nullptr;

      GameInputCreate_pfn
      GameInputCreate_Redist_Original = nullptr;

static IGameInputDevice *s_virtual_gameinput_device = nullptr;

HRESULT
STDMETHODCALLTYPE
SK_IWrapGameInput::QueryInterface (REFIID riid, void **ppvObject) noexcept
{
  if (ppvObject == nullptr)
  {
    return E_POINTER;
  }

  if ( riid == __uuidof (IUnknown)   ||
       riid == __uuidof (IGameInput) )
  {
    auto _GetVersion = [](REFIID riid) ->
    UINT
    {
      if (riid == __uuidof (IGameInput))  return 0;

      return 0;
    };

    UINT required_ver =
      _GetVersion (riid);

    if (ver_ < required_ver)
    {
      IUnknown* pPromoted = nullptr;

      if ( FAILED (
             pReal->QueryInterface ( riid,
                           (void **)&pPromoted )
                  ) || pPromoted == nullptr
         )
      {
        return E_NOINTERFACE;
      }

      ver_ =
        SK_COM_PromoteInterface (&pReal, pPromoted) ?
                                       required_ver : ver_;
    }

    else
    {
      AddRef ();
    }

    *ppvObject = this;

    return S_OK;
  }

  if (! pReal)
    return E_NOTIMPL;

  HRESULT hr =
    pReal->QueryInterface (riid, ppvObject);

  static
    concurrency::concurrent_unordered_set <std::wstring> reported_guids;

  wchar_t                wszGUID [41] = { };
  StringFromGUID2 (riid, wszGUID, 40);

  bool once =
    reported_guids.count (wszGUID) > 0;

  if (! once)
  {
    reported_guids.insert (wszGUID);

    SK_LOG0 ( ( L"QueryInterface on wrapped IGameInput for Mystery UUID: %s",
                    wszGUID ), L"Game Input" );
  }

  return hr;
};

ULONG
STDMETHODCALLTYPE
SK_IWrapGameInput::AddRef (void) noexcept
{
  InterlockedIncrement (&refs_);

  return
    pReal != nullptr ? pReal->AddRef () : 1;
};

ULONG
STDMETHODCALLTYPE
SK_IWrapGameInput::Release (void) noexcept
{
  ULONG xrefs =
    InterlockedDecrement (&refs_),
         refs = pReal != nullptr ? pReal->Release () : 1;

  if (xrefs == 0)
  {
    if (refs != 0)
    {
      SK_LOG0 ( ( L"Inconsistent reference count for IGameInput; expected=%d, actual=%d",
                  xrefs, refs ),
                  L"Game Input" );
    }

    else
      delete this;
  }

  return
    refs;
};

uint64_t
STDMETHODCALLTYPE
SK_IWrapGameInput::GetCurrentTimestamp (void) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal != nullptr ? pReal->GetCurrentTimestamp () : SK_QueryPerf ().QuadPart;
}

static concurrency::concurrent_unordered_map <IGameInputDevice*,concurrency::concurrent_unordered_map <GameInputKind,SK_ComPtr<IGameInputReading>>> _current_readings;

using IGameInputReading_GetGamepadState_pfn = bool (STDMETHODCALLTYPE *)(IGameInputReading*,GameInputGamepadState*) noexcept;

IGameInputReading_GetGamepadState_pfn IGameInputReading_GetGamepadState_Original = nullptr;

// Guards installation of the GetGamepadState shaping hook across all FOUR
//   install sites (GetCurrentReading, GetNextReading, GetPreviousReading, and
//   GetTemporalReading). A per-site SK_RunOnce is not enough: multiple threads
//   can race through different sites' null checks on a title's first-ever
//   poll, each passing GI_VIRTUAL_HOOK's non-atomic (_Original == nullptr)
//   guard, and the loser hits MinHook's ALREADY_CREATED path, which removes and
//   recreates the hook with a use-after-free window on the freed trampoline.
//   This single atomic makes the install exactly-once across all sites.
static volatile LONG s_GameInputReadingHooked = FALSE;

// Shapes native GameInput gamepad sticks through SK's shared deadzone/response-
//   curve pipeline. Every real IGameInputReading (from GetCurrentReading,
//   GetNextReading, GetPreviousReading, GetTemporalReading, or a callback)
//   shares one vtable, so this single hook covers every acquisition path.
//
// Hot path: pure math, config reads, and the same per-call activity marks the
//   other input backends make. Safe on any game thread -- no locks, no
//   allocation, no logging. Idempotent per call because the original
//   re-materializes state from the reading's immutable snapshot.
bool
STDMETHODCALLTYPE
IGameInputReading_GetGamepadState_Override (IGameInputReading *This, GameInputGamepadState *state) noexcept
{
  bool bRet =
    IGameInputReading_GetGamepadState_Original (This, state);

  if (bRet)
  {
    // Xbox Mode's wrapper marks this activity at acquisition -- skip marking
    //   here so the two sites do not double-count.
    const bool mark_activity =
      (! config.input.gamepad.xinput.emulate);

    if (mark_activity)
      SK_GAMEINPUT_READ (sk_input_dev_type::Gamepad);

    // Shape or zero, never both -- no point curving values we then discard.
    if (SK_ImGui_WantGamepadCapture ())
    {
      if (mark_activity)
        SK_GAMEINPUT_HIDE (sk_input_dev_type::Gamepad);

      ZeroMemory (state, sizeof (GameInputGamepadState));
    }

    else
    {
      if (mark_activity)
        SK_GAMEINPUT_VIEW (sk_input_dev_type::Gamepad);

      SK_XInput_ShapeSticks (state->leftThumbstickX,  state->leftThumbstickY,
                             state->rightThumbstickX, state->rightThumbstickY);
    }
  }

  return bRet;
}

// Installs the GetGamepadState shaping hook on a real IGameInputReading's
//   vtable. Callers must only pass a non-null real reading (never SK's
//   SK_IWrapGameInputReading or SK_IPlayStationGameInputReading).
static void
SK_GameInput_InstallReadingHook (IGameInputReading **ppReading)
{
  if (InterlockedCompareExchange (&s_GameInputReadingHooked, TRUE, FALSE) == FALSE)
  {
    GI_VIRTUAL_HOOK ( ppReading, 22,
                        "IGameInputReading::GetGamepadState",
                         IGameInputReading_GetGamepadState_Override,
                         IGameInputReading_GetGamepadState_Original,
                         IGameInputReading_GetGamepadState_pfn );

    SK_ApplyQueuedHooks ();

    // Hook creation can fail (e.g. non-executable vtable target); the
    //   trampoline stays null in that case. Release the guard so a later
    //   reading retries instead of leaving shaping silently disabled.
    if (IGameInputReading_GetGamepadState_Original == nullptr)
      InterlockedExchange (&s_GameInputReadingHooked, FALSE);
  }
}

using IGameInput_GetCurrentReading_pfn       = HRESULT (STDMETHODCALLTYPE *)(IGameInput*,GameInputKind,IGameInputDevice*,IGameInputReading**)                                       noexcept;
using IGameInput_GetNextReading_pfn          = HRESULT (STDMETHODCALLTYPE *)(IGameInput*,IGameInputReading*,GameInputKind,IGameInputDevice*,IGameInputReading**)                    noexcept;
using IGameInput_GetPreviousReading_pfn      = HRESULT (STDMETHODCALLTYPE *)(IGameInput*,IGameInputReading*,GameInputKind,IGameInputDevice*,IGameInputReading**)                    noexcept;
using IGameInput_GetTemporalReading_pfn      = HRESULT (STDMETHODCALLTYPE *)(IGameInput*,uint64_t,IGameInputDevice*,IGameInputReading**)                                            noexcept;
using IGameInput_RegisterReadingCallback_pfn = HRESULT (STDMETHODCALLTYPE *)(IGameInput*,IGameInputDevice*,GameInputKind,float,void*,GameInputReadingCallback,GameInputCallbackToken*) noexcept;

IGameInput_GetCurrentReading_pfn       IGameInput_GetCurrentReading_Original       = nullptr;
IGameInput_GetNextReading_pfn          IGameInput_GetNextReading_Original          = nullptr;
IGameInput_GetPreviousReading_pfn      IGameInput_GetPreviousReading_Original      = nullptr;
IGameInput_GetTemporalReading_pfn      IGameInput_GetTemporalReading_Original      = nullptr;
IGameInput_RegisterReadingCallback_pfn IGameInput_RegisterReadingCallback_Original = nullptr;

// The four polled acquisition methods on the real IGameInput. Each is a thin
//   forwarder that installs the shaping hook on the reading it returns; once
//   IGameInputReading_GetGamepadState_Original is non-null the install is a
//   single atomic read that falls straight through.
HRESULT
STDMETHODCALLTYPE
IGameInput_GetCurrentReading_Override (IGameInput *This, GameInputKind inputKind,
                                       IGameInputDevice *device, IGameInputReading **reading) noexcept
{
  SK_LOG_FIRST_CALL

  HRESULT hr =
    IGameInput_GetCurrentReading_Original (This, inputKind, device, reading);

  if (SUCCEEDED (hr) && reading != nullptr && *reading != nullptr)
    SK_GameInput_InstallReadingHook (reading);

  return hr;
}

HRESULT
STDMETHODCALLTYPE
IGameInput_GetNextReading_Override (IGameInput *This, IGameInputReading *referenceReading,
                                    GameInputKind inputKind, IGameInputDevice *device,
                                    IGameInputReading **reading) noexcept
{
  SK_LOG_FIRST_CALL

  HRESULT hr =
    IGameInput_GetNextReading_Original (This, referenceReading, inputKind, device, reading);

  if (SUCCEEDED (hr) && reading != nullptr && *reading != nullptr)
    SK_GameInput_InstallReadingHook (reading);

  return hr;
}

HRESULT
STDMETHODCALLTYPE
IGameInput_GetPreviousReading_Override (IGameInput *This, IGameInputReading *referenceReading,
                                        GameInputKind inputKind, IGameInputDevice *device,
                                        IGameInputReading **reading) noexcept
{
  SK_LOG_FIRST_CALL

  HRESULT hr =
    IGameInput_GetPreviousReading_Original (This, referenceReading, inputKind, device, reading);

  if (SUCCEEDED (hr) && reading != nullptr && *reading != nullptr)
    SK_GameInput_InstallReadingHook (reading);

  return hr;
}

HRESULT
STDMETHODCALLTYPE
IGameInput_GetTemporalReading_Override (IGameInput *This, uint64_t timestamp,
                                        IGameInputDevice *device, IGameInputReading **reading) noexcept
{
  SK_LOG_FIRST_CALL

  HRESULT hr =
    IGameInput_GetTemporalReading_Original (This, timestamp, device, reading);

  if (SUCCEEDED (hr) && reading != nullptr && *reading != nullptr)
    SK_GameInput_InstallReadingHook (reading);

  return hr;
}

struct SK_GameInputReadingCallbackShim {
  GameInputReadingCallback fn;
  void                    *context;
};

// Interposed between the game's reading callback and GameInput. The reading
//   reaches here before the game's callback body runs, so the game's very
//   first GetGamepadState inside that callback is already shaped.
void
CALLBACK
SK_GameInput_ReadingCallbackThunk ( GameInputCallbackToken callbackToken, void *context,
                                    IGameInputReading *reading, bool hasOverrunOccurred )
{
  auto *shim =
    static_cast <SK_GameInputReadingCallbackShim *> (context);

  if (reading != nullptr)
    SK_GameInput_InstallReadingHook (&reading);

  shim->fn (callbackToken, shim->context, reading, hasOverrunOccurred);
}

// A title that reads exclusively through RegisterReadingCallback never acquires
//   a reading by a polled method, so nothing else installs the shaping hook.
//   Interpose a thunk only when we still need a reading.
HRESULT
STDMETHODCALLTYPE
IGameInput_RegisterReadingCallback_Override (IGameInput *This, IGameInputDevice *device,
                                             GameInputKind inputKind, float analogThreshold,
                                             void *context, GameInputReadingCallback callbackFunc,
                                             GameInputCallbackToken *callbackToken) noexcept
{
  SK_LOG_FIRST_CALL

  // Hook already installed -> this registration has nothing to teach us.
  //   Forward untouched: no thunk, no allocation, no per-delivery cost.
  if (IGameInputReading_GetGamepadState_Original != nullptr || callbackFunc == nullptr)
  {
    return
      IGameInput_RegisterReadingCallback_Original ( This, device, inputKind, analogThreshold,
                                                      context, callbackFunc, callbackToken );
  }

  // Shim lifetime: allocated once, freed only on registration failure. Freeing
  //   on unregistration would need an UnregisterCallback hook and open a
  //   use-after-free window against a callback in flight on a thread we do not
  //   control. In practice this is one ~16-byte allocation per process.
  auto *shim =
    new SK_GameInputReadingCallbackShim { callbackFunc, context };

  HRESULT hr =
    IGameInput_RegisterReadingCallback_Original ( This, device, inputKind, analogThreshold,
                                                  shim, SK_GameInput_ReadingCallbackThunk,
                                                    callbackToken );

  if (FAILED (hr))  // nothing can be in flight yet
    delete shim;

  return hr;
}

// Refuses vtables that live in SpecialK's own module. In Xbox Mode the system
//   GameInput.dll hands our inner SK_IWrapGameInput back to the outer create
//   detour, and hooking our own C++ vtable would be self-recursion.
static bool
SK_GameInput_IsOwnVFTable (void *pObj)
{
  void  **vftable = *(void ***)pObj;
  HMODULE hModVFT =  nullptr;

  GetModuleHandleExW ( GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                         (LPCWSTR)vftable [0], &hModVFT );

  return
    hModVFT == SK_GetDLL ();
}

// Guards the dispatch-hook install exactly-once across both create detours,
//   following s_GameInputReadingHooked: release the guard if any trampoline is
//   still null after SK_ApplyQueuedHooks so a later create retries instead of
//   leaving shaping silently disabled.
static volatile LONG s_GameInputDispatchHooked = FALSE;

// Installs SK's dispatch hooks on the real IGameInput's vtable. Both create
//   detours call this on the object GameInputCreate handed back; one shared
//   GameInputRedist.dll implementation is reachable through both DLLs, so a
//   single install covers Xbox Mode and the default path alike.
static void
SK_GameInput_InstallDispatchHooks (IGameInput **ppGameInput)
{
  if (SK_GameInput_IsOwnVFTable (*ppGameInput))
    return;

  if (InterlockedCompareExchange (&s_GameInputDispatchHooked, TRUE, FALSE) == FALSE)
  {
    GI_VIRTUAL_HOOK ( ppGameInput, 4,
                        "IGameInput::GetCurrentReading",
                         IGameInput_GetCurrentReading_Override,
                         IGameInput_GetCurrentReading_Original,
                         IGameInput_GetCurrentReading_pfn );
    GI_VIRTUAL_HOOK ( ppGameInput, 5,
                        "IGameInput::GetNextReading",
                         IGameInput_GetNextReading_Override,
                         IGameInput_GetNextReading_Original,
                         IGameInput_GetNextReading_pfn );
    GI_VIRTUAL_HOOK ( ppGameInput, 6,
                        "IGameInput::GetPreviousReading",
                         IGameInput_GetPreviousReading_Override,
                         IGameInput_GetPreviousReading_Original,
                         IGameInput_GetPreviousReading_pfn );
    GI_VIRTUAL_HOOK ( ppGameInput, 7,
                        "IGameInput::GetTemporalReading",
                         IGameInput_GetTemporalReading_Override,
                         IGameInput_GetTemporalReading_Original,
                         IGameInput_GetTemporalReading_pfn );
    GI_VIRTUAL_HOOK ( ppGameInput, 8,
                        "IGameInput::RegisterReadingCallback",
                         IGameInput_RegisterReadingCallback_Override,
                         IGameInput_RegisterReadingCallback_Original,
                         IGameInput_RegisterReadingCallback_pfn );

    SK_ApplyQueuedHooks ();

    if ( IGameInput_GetCurrentReading_Original        == nullptr ||
         IGameInput_GetNextReading_Original           == nullptr ||
         IGameInput_GetPreviousReading_Original       == nullptr ||
         IGameInput_GetTemporalReading_Original       == nullptr ||
         IGameInput_RegisterReadingCallback_Original  == nullptr )
      InterlockedExchange (&s_GameInputDispatchHooked, FALSE);
  }
}

HRESULT
STDMETHODCALLTYPE
SK_IWrapGameInput::GetCurrentReading (_In_          GameInputKind      inputKind,
                                      _In_opt_     IGameInputDevice   *device,
                                      _COM_Outptr_ IGameInputReading **reading) noexcept
{
  SK_LOG_FIRST_CALL

  bool capture_input = false;

  // Always poll XInput 0 so we can detect native Xbox activity
  SK_XInput_PollController (0);

  if (device == s_virtual_gameinput_device)
  {
    static SK_IPlayStationGameInputReading virtual_current_reading (0);
    *reading =       (IGameInputReading *)&virtual_current_reading;
    return S_OK;
  }

  switch (inputKind)
  {
    case GameInputKindKeyboard:
      if (SK_ImGui_WantKeyboardCapture ())
      {
        capture_input = true;
      }
      break;

    case GameInputKindMouse:
    case GameInputKindTouch:
      if (SK_ImGui_WantMouseCapture ())
      {
        capture_input = true;
      }
      break;

    case GameInputKindGamepad:
    case GameInputKindController:
    case GameInputKindControllerSwitch:
    case GameInputKindControllerButton:
    case GameInputKindControllerAxis:
    case GameInputKindRawDeviceReport:
    case GameInputKindUiNavigation:
      if (SK_ImGui_WantGamepadCapture ())
      {
        capture_input = true;
      }
      break;

    default:
      break;
  }

  if (! capture_input)
  {
    HRESULT hr =
      pReal->GetCurrentReading (inputKind, device, reading);

    if (reading != nullptr)
    {
      _current_readings [device][inputKind] = *reading;
    }

    return hr;
  }

  else
  {
    if (reading != nullptr && _current_readings.count (device) &&
                                    _current_readings [device].count (inputKind) &&
                                    _current_readings [device]       [inputKind].p != nullptr) {
                                    _current_readings [device]       [inputKind].p->AddRef ();
                         *reading = _current_readings [device]       [inputKind];
       return S_OK;
     }

    else if (reading != nullptr && pReal != nullptr)
    {
      HRESULT hr =
        pReal->GetCurrentReading (inputKind, device, reading);
        _current_readings[device][inputKind] =      *reading;
      return  hr;
    }
  }

  return
    pReal != nullptr ? pReal->GetCurrentReading (inputKind, device, reading) : E_NOTIMPL;
}

using IGameInputDevice_SetHapticMotorState_pfn = HRESULT (STDMETHODCALLTYPE *)(IGameInputDevice*,uint32_t,GameInputHapticFeedbackParams const*) noexcept;
using IGameInputDevice_SetRumbleState_pfn      = void    (STDMETHODCALLTYPE *)(IGameInputDevice*,GameInputRumbleParams const*)                  noexcept;

IGameInputDevice_SetHapticMotorState_pfn IGameInputDevice_SetHapticMotorState_Original = nullptr;
IGameInputDevice_SetRumbleState_pfn      IGameInputDevice_SetRumbleState_Original      = nullptr;

HRESULT
STDMETHODCALLTYPE
IGameInputDevice_SetHapticMotorState_Override (IGameInputDevice *This, uint32_t motorIndex, GameInputHapticFeedbackParams const* params) noexcept
{
  SK_LOG_FIRST_CALL

  if (params != nullptr)
  {
    auto params_ = *params;

    if (config.input.gamepad.disable_rumble || SK_ImGui_WantGamepadCapture ())
    {
      params_ = {};
    }

    return
      IGameInputDevice_SetHapticMotorState_Original (This, motorIndex, &params_);
  }

  return
      IGameInputDevice_SetHapticMotorState_Original (This, motorIndex, nullptr);
} 

void
STDMETHODCALLTYPE
IGameInputDevice_SetRumbleState_Override (IGameInputDevice *This, GameInputRumbleParams const *params) noexcept
{
  SK_LOG_FIRST_CALL

  auto params_ = params != nullptr ? *params : GameInputRumbleParams {};

  //if (params_.leftTrigger > 0.0f || params_.rightTrigger > 0.0f)
  //{
  //  SK_RunOnce (SK_ImGui_Warning (L"Game uses Impulse Triggers!"));
  //}

  if (config.input.gamepad.disable_rumble || SK_ImGui_WantGamepadCapture ())
  {
    params_.highFrequency = params_.lowFrequency = 0.0f;
    params_.leftTrigger   = params_.rightTrigger = 0.0f;
  }

  // Do not rumble on Xbox controllers while a virtual controller is substituting
  if (config.input.gamepad.xinput.emulate && SK_HID_GetActivePlayStationDevice (true))
  {
    return;
  }

  return
    IGameInputDevice_SetRumbleState_Original (This, &params_);
}

// SK-owned readings never cross into the real implementation. Classifies a
//   game-supplied referenceReading by vtable pointer (each SK reading class
//   has exactly one, taken from a static exemplar, so the per-call cost is
//   two pointer compares): SK's PlayStation virtual reading has no real
//   counterpart -- callers answer GAMEINPUT_E_READING_NOT_FOUND; a wrapped
//   reading is unwrapped in place so its inner real reading forwards.
static bool
SK_GameInput_SanitizeReferenceReading (IGameInputReading *&referenceReading)
{
  if (referenceReading == nullptr)
    return true;

  static SK_IPlayStationGameInputReading exemplar_virtual (0);
  static SK_IWrapGameInputReading        exemplar_wrapped (nullptr);

  void *vftable =
    *(void **)referenceReading;

  if (vftable == *(void **)&exemplar_virtual)
    return false;

  if (vftable == *(void **)&exemplar_wrapped)
  {
    referenceReading =
      ((SK_IWrapGameInputReading *)referenceReading)->GetRealReading ();
  }

  return true;
}

HRESULT
STDMETHODCALLTYPE
SK_IWrapGameInput::GetNextReading (_In_         IGameInputReading  *referenceReading,
                                   _In_          GameInputKind      inputKind,
                                   _In_opt_     IGameInputDevice   *device,
                                   _COM_Outptr_ IGameInputReading **reading) noexcept
{
  SK_LOG_FIRST_CALL

  bool capture_input = false;

  if (device != nullptr && device != s_virtual_gameinput_device)
  {
    SK_RunOnce (
      GI_VIRTUAL_HOOK ( IID_PPV_ARGS_Helper (&device), 9,
                          "IGameInputDevice::SetHapticMotorState",
                           IGameInputDevice_SetHapticMotorState_Override,
                           IGameInputDevice_SetHapticMotorState_Original,
                           IGameInputDevice_SetHapticMotorState_pfn );
      GI_VIRTUAL_HOOK ( IID_PPV_ARGS_Helper (&device), 10,
                          "IGameInputDevice::SetRumbleState",
                           IGameInputDevice_SetRumbleState_Override,
                           IGameInputDevice_SetRumbleState_Original,
                           IGameInputDevice_SetRumbleState_pfn );

      SK_ApplyQueuedHooks ();
     );
  }

  switch (inputKind)
  {
    case GameInputKindKeyboard:
      SK_GAMEINPUT_READ (sk_input_dev_type::Keyboard);
      if (SK_ImGui_WantKeyboardCapture ())
      { SK_GAMEINPUT_HIDE (sk_input_dev_type::Keyboard);
        capture_input = true;
      } else
      { SK_GAMEINPUT_VIEW (sk_input_dev_type::Keyboard); }
      break;

    case GameInputKindMouse:
    case GameInputKindTouch:
      SK_GAMEINPUT_READ (sk_input_dev_type::Mouse);
      if (SK_ImGui_WantMouseCapture ())
      { SK_GAMEINPUT_HIDE (sk_input_dev_type::Mouse);
        capture_input = true;
      } else
      { SK_GAMEINPUT_VIEW (sk_input_dev_type::Mouse); }
      break;

    case GameInputKindGamepad:
    case GameInputKindController:
    case GameInputKindControllerSwitch:
    case GameInputKindControllerButton:
    case GameInputKindControllerAxis:
    case GameInputKindRawDeviceReport:
    case GameInputKindUiNavigation:
    {
      // 1 frame delay before blocking, so we have time to neutralize input readings
      static concurrency::concurrent_unordered_map <IGameInputDevice*,
             concurrency::concurrent_unordered_map <GameInputKind, bool>>
                 capture_last_frame;
      const bool capture_this_frame = SK_ImGui_WantGamepadCapture ();
      SK_GAMEINPUT_READ (sk_input_dev_type::Gamepad);
      if (capture_this_frame && capture_last_frame [device][inputKind])
      { SK_GAMEINPUT_HIDE (sk_input_dev_type::Gamepad);
        capture_input = true;
      } else
      { SK_GAMEINPUT_VIEW (sk_input_dev_type::Gamepad); }
      capture_last_frame [device][inputKind] = capture_this_frame;
    } break;

    default:
      break;
  }

  if (capture_input)
  {
    if (reading != nullptr)
       *reading  = nullptr;
    return GAMEINPUT_E_READING_NOT_FOUND;
  }

  if (device == s_virtual_gameinput_device)
  {
    // The virtual pad emulates only gamepad readings; report no history for
    //   every other kind rather than fall through to the forwarding paths
    //   below with the SK-owned device.
    if (inputKind != GameInputKindGamepad)
    {
      if (reading != nullptr)
         *reading  = nullptr;
      return GAMEINPUT_E_READING_NOT_FOUND;
    }

    static SK_IPlayStationGameInputReading virtual_next_reading (0);
    static UINT64                          last_virtual_active = 0;
           UINT64                          virtual_active      = 0;

    if (! SK_HID_PlayStationControllers.empty ())
    {
      if (config.input.gamepad.xinput.emulate && (! config.input.gamepad.xinput.blackout_api))
      {
        if ( const auto *pNewestInputDevice =
               SK_HID_GetActivePlayStationDevice (true) )
        {
          SK_GameInput_EmulatedPlayStation = true;

          virtual_active =
            ReadULong64Acquire (&pNewestInputDevice->xinput.last_active);
        }

        else
        {
          SK_GameInput_EmulatedPlayStation = false;
        }
      }
    }

    if (std::exchange (last_virtual_active, virtual_active) != virtual_active)
    {
      if (reading != nullptr)
         *reading = (IGameInputReading *)&virtual_next_reading;
      return S_OK;
    }

    if (reading != nullptr)
       *reading  = nullptr;
    return GAMEINPUT_E_READING_NOT_FOUND;
  }

  // A reading acquired from SK's virtual pad chains here when the title
  //   passes device = nullptr or a real device; never forward it.
  if (! SK_GameInput_SanitizeReferenceReading (referenceReading))
  {
    if (reading != nullptr)
       *reading  = nullptr;
    return GAMEINPUT_E_READING_NOT_FOUND;
  }

  const GameInputDeviceInfo* info =
    device != nullptr        ?
    device->GetDeviceInfo () : nullptr;

  if (info != nullptr)
  {
    SK_RunOnce (
    {
      SK_LOGi0 (L"GameInputDevice: VID=%x",                   info->vendorId);
      SK_LOGi0 (L"GameInputDevice: PID=%x",                   info->productId);
      SK_LOGi0 (L"GameInputDevice: Revision=%u",              info->revisionNumber);
      SK_LOGi0 (L"GameInputDevice: Id=%d",                    info->deviceId);
      SK_LOGi0 (L"GameInputDevice: RootId=%x",                info->deviceRootId);
      SK_LOGi0 (L"GameInputDevice: DeviceFamily=%x",          info->deviceFamily);
      SK_LOGi0 (L"GameInputDevice: Usage={%x,%x}",            info->usage.id, info->usage.page);
      SK_LOGi0 (L"GameInputDevice: Interface=%d",             info->interfaceNumber);
      SK_LOGi0 (L"GameInputDevice: Collection=%d",            info->collectionNumber);
      SK_LOGi0 (L"GameInputDevice: HW Version="
                               "%01d.%01d.%01d.%01d",         info->hardwareVersion.major, info->hardwareVersion.minor,
                                                              info->hardwareVersion.build, info->hardwareVersion.revision);
      SK_LOGi0 (L"GameInputDevice: FW Version="
                               "%01d.%01d.%01d.%01d",         info->firmwareVersion.major, info->firmwareVersion.minor,
                                                              info->firmwareVersion.build, info->firmwareVersion.revision);
      SK_LOGi0 (L"GameInputDevice: Capabilities=%x",          info->capabilities);
      SK_LOGi0 (L"GameInputDevice: SupportedInput=%x",        info->supportedInput);
      SK_LOGi0 (L"GameInputDevice: SupportedRumbleMotors=%x", info->supportedRumbleMotors);
      SK_LOGi0 (L"GameInputDevice: SupportedSystemButtons=%x",info->supportedSystemButtons);
    });
  }

  if (inputKind == GameInputKindGamepad)
  {
    IGameInputReading *reading_ = nullptr;

    HRESULT hr =
      pReal->GetNextReading (referenceReading, inputKind, device, &reading_);

    if (SUCCEEDED (hr) && reading_ != nullptr)
    {
      if (reading != nullptr)
      {  *reading  = (IGameInputReading *)new (std::nothrow) SK_IWrapGameInputReading (reading_);
        _current_readings [device][inputKind] = *reading;

        SK_GameInput_EmulatedPlayStation = false;
      }

      else
      {
        reading_->Release ();
      }
    }

    return hr;
  }

  return
    pReal->GetNextReading (referenceReading, inputKind, device, reading);
}

HRESULT
STDMETHODCALLTYPE
SK_IWrapGameInput::GetPreviousReading (_In_         IGameInputReading  *referenceReading,
                                       _In_          GameInputKind      inputKind,
                                       _In_opt_     IGameInputDevice   *device,
                                       _COM_Outptr_ IGameInputReading **reading) noexcept
{
  SK_LOG_FIRST_CALL

  bool capture_input = false;
  static concurrency::concurrent_unordered_map <IGameInputDevice*,concurrency::concurrent_unordered_map <GameInputKind,SK_ComPtr<IGameInputReading>>> readings;

  // SK's emulation keeps no reading history -- answer for the virtual device
  //   here; forwarding it (and the SK-owned referenceReading paired with it)
  //   into the real implementation would dereference foreign objects.
  if (device == s_virtual_gameinput_device)
  {
    if (reading != nullptr)
       *reading  = nullptr;
    return GAMEINPUT_E_READING_NOT_FOUND;
  }

  // The title may also chain an SK-owned reading with device = nullptr or a
  //   real device; never forward it.
  if (! SK_GameInput_SanitizeReferenceReading (referenceReading))
  {
    if (reading != nullptr)
       *reading  = nullptr;
    return GAMEINPUT_E_READING_NOT_FOUND;
  }

  switch (inputKind)
  {
    case GameInputKindKeyboard:
      if (SK_ImGui_WantKeyboardCapture ())
      {
        capture_input = true;
      }
      break;

    case GameInputKindMouse:
    case GameInputKindTouch:
      if (SK_ImGui_WantMouseCapture ())
      {
        capture_input = true;
      }
      break;

    case GameInputKindGamepad:
    case GameInputKindController:
    case GameInputKindControllerSwitch:
    case GameInputKindControllerButton:
    case GameInputKindControllerAxis:
    case GameInputKindRawDeviceReport:
    case GameInputKindUiNavigation:
      if (SK_ImGui_WantGamepadCapture ())
      {
        capture_input = true;
      }
      break;

    default:
      break;
  }

  if (! capture_input)
  {
    HRESULT hr =
      pReal->GetPreviousReading (referenceReading, inputKind, device, reading);

    if (reading != nullptr)
      readings [device][inputKind] = *reading;

    return hr;
  }

  else
  {
    if (reading != nullptr && readings.count (device) &&
                              readings       [device].count (inputKind) &&
                              readings       [device]       [inputKind].p != nullptr) {
                              readings       [device]       [inputKind].p->AddRef ();
                   *reading = readings       [device]       [inputKind];
    }

    else if (SUCCEEDED (pReal->GetPreviousReading (referenceReading, inputKind, device, reading)))
    {
      if (reading != nullptr)
      {
        readings [device][inputKind] = *reading;
      }
    }

    return S_OK;
  }
}

HRESULT
STDMETHODCALLTYPE
SK_IWrapGameInput::GetTemporalReading (_In_         uint64_t            timestamp,
                                       _In_         IGameInputDevice   *device,
                                       _COM_Outptr_ IGameInputReading **reading) noexcept
{
  SK_LOG_FIRST_CALL

  // Mirrors GetCurrentReading: the static reading reads live state when
  //   polled, the closest answer SK's history-less emulation has for any
  //   timestamp. Never forward the SK-owned device to the real implementation.
  if (device == s_virtual_gameinput_device)
  {
    static SK_IPlayStationGameInputReading virtual_temporal_reading (0);
    *reading =       (IGameInputReading *)&virtual_temporal_reading;
    return S_OK;
  }

  HRESULT hr =
    pReal->GetTemporalReading (timestamp, device, reading);

  return hr;
}

HRESULT
STDMETHODCALLTYPE
SK_IWrapGameInput::RegisterReadingCallback (_In_opt_                         IGameInputDevice          *device,
                                            _In_                              GameInputKind             inputKind,
                                            _In_                              float                     analogThreshold,
                                            _In_opt_                          void                     *context,
                                            _In_                              GameInputReadingCallback  callbackFunc,
                                            _Out_opt_ _Result_zeroonfailure_  GameInputCallbackToken   *callbackToken) noexcept
{
  SK_LOG_FIRST_CALL

  // Register against any device instead of SK's virtual one -- the real
  //   implementation dereferences the device at registration time. The token
  //   stays real, so StopCallback/UnregisterCallback work; the virtual pad's
  //   input arrives via the polled paths only (SK's emulation has no callback
  //   delivery).
  if (device == s_virtual_gameinput_device)
      device  = nullptr;

  return
    pReal == nullptr ? S_OK :
    pReal->RegisterReadingCallback (device, inputKind, analogThreshold, context, callbackFunc, callbackToken);
}

HRESULT
STDMETHODCALLTYPE
SK_IWrapGameInput::RegisterDeviceCallback (_In_opt_                        IGameInputDevice         *device,
                                           _In_                             GameInputKind            inputKind,
                                           _In_                             GameInputDeviceStatus    statusFilter,
                                           _In_                             GameInputEnumerationKind enumerationKind,
                                           _In_opt_                         void                    *context,
                                           _In_                             GameInputDeviceCallback  callbackFunc,
                                           _Out_opt_ _Result_zeroonfailure_ GameInputCallbackToken  *callbackToken) noexcept
{
  SK_LOG_FIRST_CALL

  SK_LOGi1 ( L"RegisterDeviceCallback: inputKind=%d, statusFilter=%x, enumerationKind=%d",
                                       inputKind,    statusFilter,    enumerationKind );

  // Widen an SK-virtual-device filter to any device -- the real implementation
  //   dereferences the filter device, and a real token must come back so
  //   StopCallback/UnregisterCallback work.
  if (device == s_virtual_gameinput_device)
      device  = nullptr;

  HRESULT hr =
    pReal == nullptr ? S_OK : pReal->RegisterDeviceCallback (device, inputKind, statusFilter, enumerationKind, context, callbackFunc, callbackToken);

  if (SUCCEEDED (hr) && inputKind == GameInputKindGamepad && (statusFilter & GameInputDeviceConnected) != 0 && (config.input.gamepad.xinput.emulate || ! SK_XInput_PollController (0)))
  {
    // TODO: Implement hotplug
    if (s_virtual_gameinput_device == nullptr)
        s_virtual_gameinput_device = (IGameInputDevice *)new (std::nothrow) SK_IGameInputDevice (nullptr);

    callbackFunc (callbackToken != nullptr ? *callbackToken : 0, context, s_virtual_gameinput_device, SK_QueryPerf ().QuadPart, GameInputDeviceConnected, GameInputDeviceConnected);
  }

  return hr;
}

HRESULT
STDMETHODCALLTYPE
SK_IWrapGameInput::RegisterSystemButtonCallback (_In_opt_                         IGameInputDevice               *device,
                                                 _In_                              GameInputSystemButtons         buttonFilter,
                                                 _In_opt_                          void                          *context,
                                                 _In_                              GameInputSystemButtonCallback  callbackFunc,
                                                 _Out_opt_ _Result_zeroonfailure_  GameInputCallbackToken        *callbackToken) noexcept
{
  SK_LOG_FIRST_CALL

  // Same guard as RegisterDeviceCallback: never hand the SK-owned filter
  //   device to the real implementation.
  if (device == s_virtual_gameinput_device)
      device  = nullptr;

  return
    pReal == nullptr ? S_OK :
    pReal->RegisterSystemButtonCallback (device, buttonFilter, context, callbackFunc, callbackToken);
}

HRESULT
STDMETHODCALLTYPE
SK_IWrapGameInput::RegisterKeyboardLayoutCallback (_In_opt_                         IGameInputDevice                 *device,
                                                   _In_opt_                          void                            *context,
                                                   _In_                              GameInputKeyboardLayoutCallback  callbackFunc,
                                                   _Out_opt_ _Result_zeroonfailure_  GameInputCallbackToken          *callbackToken) noexcept
{
  SK_LOG_FIRST_CALL

  // Same guard as RegisterDeviceCallback: never hand the SK-owned filter
  //   device to the real implementation.
  if (device == s_virtual_gameinput_device)
      device  = nullptr;

  return
    pReal == nullptr ? S_OK :
    pReal->RegisterKeyboardLayoutCallback (device, context, callbackFunc, callbackToken);
}

void
STDMETHODCALLTYPE
SK_IWrapGameInput::StopCallback (_In_ GameInputCallbackToken callbackToken) noexcept
{
  SK_LOG_FIRST_CALL

  if (pReal != nullptr)
      pReal->StopCallback (callbackToken);
}

bool
STDMETHODCALLTYPE
SK_IWrapGameInput::UnregisterCallback (_In_ GameInputCallbackToken callbackToken,
                                       _In_ uint64_t               timeoutInMicroseconds) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal == nullptr ? true :
    pReal->UnregisterCallback (callbackToken, timeoutInMicroseconds);
}

HRESULT
STDMETHODCALLTYPE
SK_IWrapGameInput::CreateDispatcher (_COM_Outptr_ IGameInputDispatcher **dispatcher) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal == nullptr ? S_OK :
    pReal->CreateDispatcher (dispatcher);
}

HRESULT
STDMETHODCALLTYPE
SK_IWrapGameInput::CreateAggregateDevice (_In_          GameInputKind     inputKind,
                                          _COM_Outptr_ IGameInputDevice **device) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal == nullptr ? S_OK :
    pReal->CreateAggregateDevice (inputKind, device);
}

HRESULT
STDMETHODCALLTYPE
SK_IWrapGameInput::FindDeviceFromId (_In_         APP_LOCAL_DEVICE_ID const  *value,
                                     _COM_Outptr_ IGameInputDevice          **device) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal == nullptr ? S_OK :
    pReal->FindDeviceFromId (value, device);
}

HRESULT
STDMETHODCALLTYPE
SK_IWrapGameInput::FindDeviceFromObject (_In_         IUnknown          *value,
                                         _COM_Outptr_ IGameInputDevice **device) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal == nullptr ? S_OK :
    pReal->FindDeviceFromObject (value, device);
}

HRESULT
STDMETHODCALLTYPE
SK_IWrapGameInput::FindDeviceFromPlatformHandle (_In_         HANDLE             value,
                                                 _COM_Outptr_ IGameInputDevice **device) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal == nullptr ? S_OK :
    pReal->FindDeviceFromPlatformHandle (value, device);
}

HRESULT
STDMETHODCALLTYPE
SK_IWrapGameInput::FindDeviceFromPlatformString (_In_         LPCWSTR            value,
                                                 _COM_Outptr_ IGameInputDevice **device) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal == nullptr ? S_OK :
    pReal->FindDeviceFromPlatformString (value, device);
}

HRESULT
STDMETHODCALLTYPE
SK_IWrapGameInput::EnableOemDeviceSupport (_In_ uint16_t vendorId,
                                           _In_ uint16_t productId,
                                           _In_ uint8_t interfaceNumber,
                                           _In_ uint8_t collectionNumber) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal == nullptr ? S_OK :
    pReal->EnableOemDeviceSupport (vendorId, productId, interfaceNumber, collectionNumber);
}

void
STDMETHODCALLTYPE
SK_IWrapGameInput::SetFocusPolicy (_In_ GameInputFocusPolicy policy) noexcept
{
  SK_LOG_FIRST_CALL

  if (pReal != nullptr)
      pReal->SetFocusPolicy (policy);
}


HRESULT
WINAPI
GameInputCreate_Detour (IGameInput** gameInput)
{
  SK_LOG_FIRST_CALL

  IGameInput* pReal = nullptr;

  HRESULT hr =
    GameInputCreate_Original (&pReal);

  if (SUCCEEDED (hr) && pReal != nullptr)
    SK_GameInput_InstallDispatchHooks (&pReal);

  if (SUCCEEDED (hr) || config.input.gamepad.xinput.emulate)
  {
    // Turn on XInput emulation by default on first-run for Unreal Engine.
    //
    //   -> Their GameInput integration is extremely simple and SK is fully compatible.
    //
    if (config.system.first_run && (! SK_XInput_PollController (0)))
    {
      SK_RunOnce (if (! SK_ImGui_HasPlayStationController  ())
                        SK_HID_SetupPlayStationControllers ());

      if (SK_ImGui_HasPlayStationController () && StrStrIW (SK_GetFullyQualifiedApp (), L"Binaries\\Win"))
      {
        SK_LOGi0 (L"Enabling Xbox Mode because Unreal Engine is using GameInput...");

        config.input.gamepad.xinput.emulate = true;
      }
    }

    if (config.input.gamepad.xinput.emulate)
    {
      if (gameInput != nullptr)
         *gameInput = (IGameInput *)new SK_IWrapGameInput (pReal);
      else                          new SK_IWrapGameInput (pReal);

      return S_OK;
    }
  }

  if (gameInput != nullptr && 
        nullptr != pReal)
     *gameInput  = pReal;

  return hr;
}

HRESULT
WINAPI
GameInputCreate_Redist_Detour (IGameInput** gameInput)
{
  SK_LOG_FIRST_CALL

  IGameInput* pReal = nullptr;

  HRESULT hr =
    GameInputCreate_Redist_Original (&pReal);

  if (SUCCEEDED (hr) && pReal != nullptr)
    SK_GameInput_InstallDispatchHooks (&pReal);

  if (SUCCEEDED (hr) || config.input.gamepad.xinput.emulate)
  {
    // Turn on XInput emulation by default on first-run for Unreal Engine.
    //
    //   -> Their GameInput integration is extremely simple and SK is fully compatible.
    //
    if (config.system.first_run && (! SK_XInput_PollController (0)))
    {
      SK_RunOnce (if (! SK_ImGui_HasPlayStationController  ())
                        SK_HID_SetupPlayStationControllers ());

      if (SK_ImGui_HasPlayStationController () && StrStrIW (SK_GetFullyQualifiedApp (), L"Binaries\\Win"))
      {
        SK_LOGi0 (L"Enabling Xbox Mode because Unreal Engine is using GameInput...");

        config.input.gamepad.xinput.emulate = true;
      }
    }

    if (config.input.gamepad.xinput.emulate)
    {
      if (gameInput != nullptr)
         *gameInput = (IGameInput *)new SK_IWrapGameInput (pReal);
      else                          new SK_IWrapGameInput (pReal);

      return S_OK;
    }
  }

  if (gameInput != nullptr && 
        nullptr != pReal)
     *gameInput  = pReal;

  return hr;
}


#pragma warning (disable: 4100)

HRESULT
__stdcall
SK_IGameInputDevice::QueryInterface (REFIID riid, void **ppvObject) noexcept
{
  if (ppvObject == nullptr)
  {
    return E_POINTER;
  }

  if ( riid == __uuidof (IUnknown) ||
       riid == __uuidof (IGameInputDevice) )
  {
    AddRef ();

    *ppvObject = this;

    return S_OK;
  }

  static
    concurrency::concurrent_unordered_set <std::wstring> reported_guids;

  wchar_t                wszGUID [41] = { };
  StringFromGUID2 (riid, wszGUID, 40);

  bool once =
    reported_guids.count (wszGUID) > 0;

  if (! once)
  {
    reported_guids.insert (wszGUID);

    SK_LOG0 ( ( L"QueryInterface on wrapped IGameInputDevice for Mystery UUID: %s",
                    wszGUID ), L"Game Input" );
  }

  return E_NOINTERFACE;
}

ULONG
__stdcall
SK_IGameInputDevice::AddRef (void) noexcept
{
  return InterlockedIncrement (&refs_);
}

ULONG
__stdcall
SK_IGameInputDevice::Release (void) noexcept
{
  return InterlockedDecrement (&refs_);
}

GameInputDeviceInfo const*
__stdcall
SK_IGameInputDevice::GetDeviceInfo (void) noexcept
{
  SK_LOG_FIRST_CALL

  if (this != s_virtual_gameinput_device)
  {
    return
      pReal->GetDeviceInfo ();
  }

  static GameInputDeviceInfo dev_info = {};

  dev_info.infoSize = sizeof (GameInputDeviceInfo);

  // Traditional Xbox 360 Controller
#if 0
  dev_info.controllerAxisCount   = 6;
  dev_info.controllerButtonCount = 13;

  dev_info.deviceId        = {1};
  dev_info.deviceRootId    = {1};

  dev_info.capabilities    = GameInputDeviceCapabilityPowerOff | GameInputDeviceCapabilityWireless;

  dev_info.vendorId        = 0x45e;
  dev_info.productId       = 0x28e;

  dev_info.deviceFamily    = GameInputFamilyXbox360;
  dev_info.usage.id        = 5;
  dev_info.usage.page      = 1;

  dev_info.interfaceNumber = 0;

  dev_info.supportedInput         = GameInputKindControllerAxis | GameInputKindControllerButton |
                                    GameInputKindGamepad        | GameInputKindUiNavigation;
  dev_info.supportedRumbleMotors  = GameInputRumbleLowFrequency | GameInputRumbleHighFrequency;
  dev_info.supportedSystemButtons = GameInputSystemButtonGuide;
#else
  // Xbox One
  dev_info.controllerAxisCount   =  6;
  dev_info.controllerButtonCount = 13;

  dev_info.deviceId        = {1};
  dev_info.deviceRootId    = {1};

  dev_info.capabilities    = GameInputDeviceCapabilitySynchronization | GameInputDeviceCapabilityPowerOff |
                             GameInputDeviceCapabilityWireless;

  dev_info.vendorId        = 0x45e;
  dev_info.productId       = 0xb12;

  dev_info.deviceFamily    = GameInputFamilyXboxOne;
  dev_info.usage.id        = 5;
  dev_info.usage.page      = 1;

  dev_info.interfaceNumber = 0;

  dev_info.supportedInput         = GameInputKindRawDeviceReport  | GameInputKindControllerAxis |
                                    GameInputKindControllerButton | GameInputKindGamepad        | GameInputKindUiNavigation;
  dev_info.supportedRumbleMotors  = GameInputRumbleLowFrequency   | GameInputRumbleHighFrequency|
                                    GameInputRumbleLeftTrigger    | GameInputRumbleRightTrigger;
  dev_info.supportedSystemButtons = GameInputSystemButtonGuide    | GameInputSystemButtonShare;
#endif

  return &dev_info;
}

GameInputDeviceStatus
__stdcall
SK_IGameInputDevice::GetDeviceStatus (void) noexcept
{
  SK_LOG_FIRST_CALL

  GameInputDeviceStatus ret = GameInputDeviceNoStatus;

  if (SK_ImGui_HasPlayStationController ())
  {
    ret |= GameInputDeviceConnected | GameInputDeviceInputEnabled | GameInputDeviceOutputEnabled;
  }

  return ret;
}

void
__stdcall
SK_IGameInputDevice::GetBatteryState (GameInputBatteryState *state) noexcept
{
  SK_LOG_FIRST_CALL
}

HRESULT
__stdcall
SK_IGameInputDevice::CreateForceFeedbackEffect (uint32_t motorIndex,
                                                GameInputForceFeedbackParams const *params,
                                               IGameInputForceFeedbackEffect       **effect) noexcept
{
  SK_LOG_FIRST_CALL

  return E_NOTIMPL;
}

bool
__stdcall
SK_IGameInputDevice::IsForceFeedbackMotorPoweredOn (uint32_t motorIndex) noexcept
{
  SK_LOG_FIRST_CALL

  return false;
}

void
__stdcall
SK_IGameInputDevice::SetForceFeedbackMotorGain (uint32_t motorIndex, float masterGain) noexcept
{
  SK_LOG_FIRST_CALL
}

HRESULT
__stdcall
SK_IGameInputDevice::SetHapticMotorState (uint32_t motorIndex,
                                          GameInputHapticFeedbackParams const *params) noexcept
{
  SK_LOG_FIRST_CALL

  // ...

  return S_OK;
}

void
__stdcall
SK_IGameInputDevice::SetRumbleState (GameInputRumbleParams const *params) noexcept
{
  SK_LOG_FIRST_CALL

  if (config.input.gamepad.disable_rumble)
  {
    SK_XInput_ZeroHaptics (0);
    return;
  }

  if (! params)
  {
    if (! SK_ImGui_WantGamepadCapture ())
    {
      if (config.input.gamepad.xinput.emulate && (! config.input.gamepad.xinput.blackout_api))
      {
        SK_XInput_ZeroHaptics (0);
      }
    }

    return;
  }

  GameInputRumbleParams params_ = *params;

  if (config.input.gamepad.xinput.emulate && (! config.input.gamepad.xinput.blackout_api) && (! SK_ImGui_WantGamepadCapture ()))
  {
    if (SK_HID_PlayStationDevice *pNewestInputDevice = nullptr; (pNewestInputDevice = SK_HID_GetActivePlayStationDevice (true)) != nullptr)
    {
      SK_GameInput_EmulatedPlayStation = true;

      pNewestInputDevice->setVibration (
        static_cast <USHORT> (std::min (65535UL, static_cast <ULONG> (std::clamp (params_.lowFrequency,  0.0f, 1.0f) * 65536.0f))),
        static_cast <USHORT> (std::min (65535UL, static_cast <ULONG> (std::clamp (params_.highFrequency, 0.0f, 1.0f) * 65536.0f))),
        static_cast <USHORT> (std::min (65535UL, static_cast <ULONG> (std::clamp (params_.leftTrigger,   0.0f, 1.0f) * 65536.0f))),
        static_cast <USHORT> (std::min (65535UL, static_cast <ULONG> (std::clamp (params_.rightTrigger,  0.0f, 1.0f) * 65536.0f))),
                                        65535ui16
      );

      pNewestInputDevice->write_output_report ();

      return;
    }
  }

  SK_GameInput_EmulatedPlayStation = false;
}

void
__stdcall
SK_IGameInputDevice::SetInputSynchronizationState (bool enabled) noexcept
{
  SK_LOG_FIRST_CALL
}

void
__stdcall
SK_IGameInputDevice::SendInputSynchronizationHint (void) noexcept
{
  SK_LOG_FIRST_CALL
}

void
__stdcall
SK_IGameInputDevice::PowerOff (void) noexcept
{
  SK_LOG_FIRST_CALL

  // ...
}
                                                                               
HRESULT
__stdcall
SK_IGameInputDevice::CreateRawDeviceReport (uint32_t                     reportId,
                                            GameInputRawDeviceReportKind reportKind,
                                           IGameInputRawDeviceReport   **report) noexcept
{
  SK_LOG_FIRST_CALL

  return E_NOTIMPL;
}

HRESULT
__stdcall
SK_IGameInputDevice::GetRawDeviceFeature (uint32_t                   reportId,
                                         IGameInputRawDeviceReport **report) noexcept
{
  SK_LOG_FIRST_CALL

  return E_NOTIMPL;
}

HRESULT
__stdcall
SK_IGameInputDevice::SetRawDeviceFeature (IGameInputRawDeviceReport *report) noexcept
{
  SK_LOG_FIRST_CALL

  return E_NOTIMPL;
}

HRESULT
__stdcall
SK_IGameInputDevice::SendRawDeviceOutput (IGameInputRawDeviceReport *report) noexcept
{
  SK_LOG_FIRST_CALL

  return E_NOTIMPL;
}

HRESULT
__stdcall
SK_IGameInputDevice::SendRawDeviceOutputWithResponse (IGameInputRawDeviceReport   *requestReport,
                                                      IGameInputRawDeviceReport **responseReport)  noexcept
{
  SK_LOG_FIRST_CALL

  return E_NOTIMPL;
}

HRESULT
__stdcall
SK_IGameInputDevice::ExecuteRawDeviceIoControl (uint32_t    controlCode,
                                                size_t      inputBufferSize,
                                                void const *inputBuffer,
                                                size_t      outputBufferSize,
                                                void       *outputBuffer,
                                                size_t     *outputSize) noexcept
{
  SK_LOG_FIRST_CALL

  return E_NOTIMPL;
}

bool
__stdcall
SK_IGameInputDevice::AcquireExclusiveRawDeviceAccess (uint64_t timeoutInMicroseconds) noexcept
{
  SK_LOG_FIRST_CALL

  return true;
}

void
__stdcall
SK_IGameInputDevice::ReleaseExclusiveRawDeviceAccess(void) noexcept
{
  SK_LOG_FIRST_CALL
}


HRESULT
STDMETHODCALLTYPE
SK_IWrapGameInputReading::QueryInterface (REFIID riid, void **ppvObject) noexcept
{
  if (ppvObject == nullptr)
  {
    return E_POINTER;
  }

  if ( riid == __uuidof (IUnknown) ||
       riid == __uuidof (IGameInputReading) )
  {
    auto _GetVersion = [](REFIID riid) ->
    UINT
    {
      if (riid == __uuidof (IGameInputReading))  return 0;

      return 0;
    };

    UINT required_ver =
      _GetVersion (riid);

    if (ver_ < required_ver)
    {
      IUnknown* pPromoted = nullptr;

      if ( FAILED (
             pReal->QueryInterface ( riid,
                           (void **)&pPromoted )
                  ) || pPromoted == nullptr
         )
      {
        return E_NOINTERFACE;
      }

      ver_ =
        SK_COM_PromoteInterface (&pReal, pPromoted) ?
                                       required_ver : ver_;
    }

    else
    {
      AddRef ();
    }

    *ppvObject = this;

    return S_OK;
  }

  HRESULT hr =
    pReal->QueryInterface (riid, ppvObject);

  static
    concurrency::concurrent_unordered_set <std::wstring> reported_guids;

  wchar_t                wszGUID [41] = { };
  StringFromGUID2 (riid, wszGUID, 40);

  bool once =
    reported_guids.count (wszGUID) > 0;

  if (! once)
  {
    reported_guids.insert (wszGUID);

    SK_LOG0 ( ( L"QueryInterface on wrapped IGameInputReading for Mystery UUID: %s",
                    wszGUID ), L"Game Input" );
  }

  return hr;
}

ULONG
STDMETHODCALLTYPE
SK_IWrapGameInputReading::AddRef (void) noexcept
{
  InterlockedIncrement (&refs_);

  return
    pReal->AddRef ();
}

ULONG
STDMETHODCALLTYPE
SK_IWrapGameInputReading::Release (void) noexcept
{
  ULONG xrefs =
    InterlockedDecrement (&refs_),
         refs = pReal->Release ();

  if (xrefs == 0)
  {
    if (refs != 0)
    {
      SK_LOG0 ( ( L"Inconsistent reference count for IGameInputReading; expected=%d, actual=%d",
                  xrefs, refs ),
                  L"Game Input" );
    }

    else
      delete this;
  }

  return
    refs;
}

GameInputKind
STDMETHODCALLTYPE
SK_IWrapGameInputReading::GetInputKind (void) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal->GetInputKind ();
}

uint64_t
STDMETHODCALLTYPE
SK_IWrapGameInputReading::GetSequenceNumber (GameInputKind inputKind) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal->GetSequenceNumber (inputKind);
}

uint64_t
STDMETHODCALLTYPE
SK_IWrapGameInputReading::GetTimestamp (void) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal->GetTimestamp ();
}

void
STDMETHODCALLTYPE
SK_IWrapGameInputReading::GetDevice (IGameInputDevice **device) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal->GetDevice (device);
}

bool
STDMETHODCALLTYPE
SK_IWrapGameInputReading::GetRawReport (IGameInputRawDeviceReport **report) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal->GetRawReport (report);
}

uint32_t
STDMETHODCALLTYPE
SK_IWrapGameInputReading::GetControllerAxisCount (void) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal->GetControllerAxisCount ();
}

uint32_t
STDMETHODCALLTYPE
SK_IWrapGameInputReading::GetControllerAxisState (uint32_t stateArrayCount,
                                                  float   *stateArray) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal->GetControllerAxisState (stateArrayCount, stateArray);
}

uint32_t
STDMETHODCALLTYPE
SK_IWrapGameInputReading::GetControllerButtonCount (void) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal->GetControllerButtonCount ();
}

uint32_t
STDMETHODCALLTYPE
SK_IWrapGameInputReading::GetControllerButtonState (uint32_t stateArrayCount,
                                                    bool    *stateArray) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal->GetControllerButtonState (stateArrayCount, stateArray);
}

uint32_t
STDMETHODCALLTYPE
SK_IWrapGameInputReading::GetControllerSwitchCount (void) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal->GetControllerSwitchCount ();
}

uint32_t
STDMETHODCALLTYPE
SK_IWrapGameInputReading::GetControllerSwitchState (uint32_t                    stateArrayCount,
                                                    GameInputSwitchPosition    *stateArray) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal->GetControllerSwitchState (stateArrayCount, stateArray);
}

uint32_t
STDMETHODCALLTYPE
SK_IWrapGameInputReading::GetKeyCount (void) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal->GetKeyCount ();
}

uint32_t
STDMETHODCALLTYPE
SK_IWrapGameInputReading::GetKeyState (uint32_t           stateArrayCount,
                                       GameInputKeyState *stateArray) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal->GetKeyState (stateArrayCount, stateArray);
}

bool
STDMETHODCALLTYPE
SK_IWrapGameInputReading::GetMouseState (GameInputMouseState *state) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal->GetMouseState (state);
}

uint32_t
STDMETHODCALLTYPE
SK_IWrapGameInputReading::GetTouchCount (void) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal->GetTouchCount ();
}

uint32_t
STDMETHODCALLTYPE
SK_IWrapGameInputReading::GetTouchState (uint32_t             stateArrayCount,
                                         GameInputTouchState *stateArray) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal->GetTouchState (stateArrayCount, stateArray);
}

bool
STDMETHODCALLTYPE
SK_IWrapGameInputReading::GetMotionState (GameInputMotionState *state) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal->GetMotionState (state);
}

bool
STDMETHODCALLTYPE
SK_IWrapGameInputReading::GetArcadeStickState (GameInputArcadeStickState* state) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal->GetArcadeStickState (state);
}

bool
STDMETHODCALLTYPE
SK_IWrapGameInputReading::GetFlightStickState (GameInputFlightStickState *state) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal->GetFlightStickState (state);
}

bool
STDMETHODCALLTYPE
SK_IWrapGameInputReading::GetGamepadState (GameInputGamepadState *state) noexcept
{
  SK_LOG_FIRST_CALL

  // Pure forwarder: pReal is the real reading, so this call lands in
  //   IGameInputReading_GetGamepadState_Override, which already zeroes on
  //   capture. The zero below is redundant but idempotent -- kept as
  //   belt-and-braces so Xbox Mode behavior is unaffected.
  if (pReal->GetGamepadState (state))
  {
    if (SK_ImGui_WantGamepadCapture ())
    {
      ZeroMemory (state, sizeof (GameInputGamepadState));
    }

    return true;
  }

  return false;
}

bool
STDMETHODCALLTYPE
SK_IWrapGameInputReading::GetRacingWheelState (GameInputRacingWheelState *state) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal->GetRacingWheelState (state);
}

bool
STDMETHODCALLTYPE
SK_IWrapGameInputReading::GetUiNavigationState (GameInputUiNavigationState *state) noexcept
{
  SK_LOG_FIRST_CALL

  return
    pReal->GetUiNavigationState (state);
}

static volatile LONG s_hooked_system = FALSE;
static volatile LONG s_hooked_redist = FALSE;

// Installs the GameInputCreate export hook for a single module. The
//   caller-supplied guard makes the inline and worker-thread paths mutually
//     exclusive, so the export is never hooked twice.
static void
SK_GameInput_HookCreate ( const wchar_t       *wszModule,
                          GameInputCreate_pfn  pDetour,
                          GameInputCreate_pfn *ppOriginal,
                          volatile LONG       *pHooked )
{
  if (! InterlockedCompareExchange (pHooked, TRUE, FALSE))
  {
    void *pfnTarget = nullptr;

    SK_CreateDLLHook2 (      wszModule,
                              "GameInputCreate",
                               pDetour,
      static_cast_p2p <void> (ppOriginal),
                              &pfnTarget );

    // SK_ApplyQueuedHooks is a silent no-op while the global apply flag is
    //   off (early init) -- enable directly so the title's one-shot
    //   GameInputCreate call cannot slip through unhooked.
    if (pfnTarget != nullptr)
      SK_EnableHook (pfnTarget);
  }
}

// Covers titles that called GameInputCreate before SK attached (global
//   injection attaches around window creation, long after a top-of-main
//   create): the export hook arms too late to ever fire, but the
//   implementation is a process-wide singleton, so acquiring our own
//   instance and patching its dispatch vtable also covers the object the
//   title already holds. Runs on a worker thread because SK_Input_Init can
//   run under the loader lock and GameInputCreate may LoadLibrary the
//   redist internally.
static void
SK_GameInput_HookExistingInstance (GameInputCreate_pfn pfnCreate)
{
  static volatile LONG s_hooked_existing = FALSE;

  if (pfnCreate == nullptr)
    return;

  if (InterlockedCompareExchange (&s_hooked_existing, TRUE, FALSE))
    return;

  SK_Thread_CreateEx ([](LPVOID user)->DWORD
  {
    auto pfnGameInputCreate =
      reinterpret_cast <GameInputCreate_pfn> (user);

    IGameInput *pGameInput = nullptr;

    if ( SUCCEEDED (pfnGameInputCreate (&pGameInput)) &&
                                         pGameInput != nullptr )
    {
      SK_GameInput_InstallDispatchHooks (&pGameInput);

      // A callback-only title that registered before SK attached never
      //   passes through the dispatch overrides, so nothing else would
      //   install the reading-shaping hook. Acquire readings ourselves
      //   until one arrives.
      while ((! ReadAcquire (&__SK_DLL_Ending)) &&
               IGameInputReading_GetGamepadState_Original == nullptr)
      {
        SK_ComPtr <IGameInputReading> pReading;

        if ( SUCCEEDED (
               pGameInput->GetCurrentReading (GameInputKindGamepad, nullptr, &pReading.p)
             )        &&               pReading != nullptr )
        {
          SK_GameInput_InstallReadingHook (&pReading.p);
        }

        if (IGameInputReading_GetGamepadState_Original == nullptr)
          SK_SleepEx (250UL, FALSE);
      }

      pGameInput->Release ();
    }

    SK_Thread_CloseSelf ();

    return 0;
  }, L"[SK] GameInput Late Hook Thread", (LPVOID)pfnCreate);
}

void
SK_Input_HookGameInput (void)
{
  if (! config.input.gamepad.hook_game_input)
    return;

  // Already loaded -> hook inline. No LoadLibrary means no loader-lock
  //   hazard, and this arms the hook before the app can call GameInputCreate.
  if (GetModuleHandleW (L"GameInput.dll") != nullptr)
  {
    SK_GameInput_HookCreate ( L"GameInput.dll", GameInputCreate_Detour,
                             &GameInputCreate_Original, &s_hooked_system );

    // The title may have called GameInputCreate before SK attached; hook
    //   the singleton it is already holding.
    SK_GameInput_HookExistingInstance (GameInputCreate_Original);
  }

  if (GetModuleHandleW (L"GameInputRedist.dll") != nullptr)
  {
    SK_GameInput_HookCreate ( L"GameInputRedist.dll", GameInputCreate_Redist_Detour,
                             &GameInputCreate_Redist_Original, &s_hooked_redist );

    SK_GameInput_HookExistingInstance (GameInputCreate_Redist_Original);
  }

  // Only Xbox Mode force-loads a missing DLL, and SK_LoadLibraryW can run
  //   under the loader lock from SK_Input_Init -- defer that to a worker.
  if (config.input.gamepad.xinput.emulate)
  {
    if (GetModuleHandleW (L"GameInput.dll") == nullptr)
    {
      static HANDLE hGameInputInitThread =
      SK_Thread_CreateEx ([](LPVOID)->DWORD
      {
        SK_PROFILE_FIRST_CALL

        SK_LoadLibraryW (L"GameInput.dll");
        SK_GameInput_HookCreate ( L"GameInput.dll", GameInputCreate_Detour,
                                 &GameInputCreate_Original, &s_hooked_system );

        SK_Thread_CloseSelf ();
        return 0;
      }, L"[SK] GameInput.dll Init Thread");
    }

    if (GetModuleHandleW (L"GameInputRedist.dll") == nullptr)
    {
      static HANDLE hGameInputRedistInitThread =
      SK_Thread_CreateEx ([](LPVOID)->DWORD
      {
        SK_PROFILE_FIRST_CALL

        SK_LoadLibraryW (L"GameInputRedist.dll");
        SK_GameInput_HookCreate ( L"GameInputRedist.dll", GameInputCreate_Redist_Detour,
                                 &GameInputCreate_Redist_Original, &s_hooked_redist );

        SK_Thread_CloseSelf ();
        return 0;
      }, L"[SK] GameInputRedist.dll Init Thread");
    }
  }
}



HRESULT
STDMETHODCALLTYPE
SK_IPlayStationGameInputReading::QueryInterface (REFIID riid, void **ppvObject) noexcept
{
  if (ppvObject == nullptr)
  {
    return E_POINTER;
  }

  if ( riid == __uuidof (IUnknown) ||
       riid == __uuidof (IGameInputReading) )
  {
    AddRef ();

    *ppvObject = this;

    return S_OK;
  }

  static
    concurrency::concurrent_unordered_set <std::wstring> reported_guids;

  wchar_t                wszGUID [41] = { };
  StringFromGUID2 (riid, wszGUID, 40);

  bool once =
    reported_guids.count (wszGUID) > 0;

  if (! once)
  {
    reported_guids.insert (wszGUID);

    SK_LOG0 ( ( L"QueryInterface on PlayStation IGameInputReading for Mystery UUID: %s",
                    wszGUID ), L"Game Input" );
  }

  return E_NOINTERFACE;
}

ULONG
STDMETHODCALLTYPE
SK_IPlayStationGameInputReading::AddRef (void) noexcept
{
  InterlockedIncrement (&refs_);

  return refs_;
}

ULONG
STDMETHODCALLTYPE
SK_IPlayStationGameInputReading::Release (void) noexcept
{
  InterlockedDecrement (&refs_);

  return refs_;
}

GameInputKind
STDMETHODCALLTYPE
SK_IPlayStationGameInputReading::GetInputKind (void) noexcept
{
  SK_LOG_FIRST_CALL

  return GameInputKindGamepad;
}

uint64_t
STDMETHODCALLTYPE
SK_IPlayStationGameInputReading::GetSequenceNumber (GameInputKind inputKind) noexcept
{
  SK_LOG_FIRST_CALL

  SK_RunOnce (SK_LOGi0 (L"Stub"));

  return 0;
    //pReal->GetSequenceNumber (inputKind);
}

uint64_t
STDMETHODCALLTYPE
SK_IPlayStationGameInputReading::GetTimestamp (void) noexcept
{
  SK_LOG_FIRST_CALL

  //
  // Obviously this is implemented wrong, it should be accessing a history buffer
  //   of previous readings, not iterating through all PlayStation controllers and
  //     finding the one with the newest input.
  //
  //  * This entire class should be encapsulating a single reading, not merely
  //      providing the data from the newest sampled input available (!!)
  //
  static volatile UINT64 last_timestamp = 0;

  if (config.input.gamepad.xinput.emulate && (! config.input.gamepad.xinput.blackout_api))
  {
          UINT64      timestamp = ReadULong64Acquire (&last_timestamp);
    const UINT64 orig_timestamp                           { timestamp };

    if (! SK_HID_PlayStationControllers.empty ())
    {
      for (const auto& controller : SK_HID_PlayStationControllers)
      {
        if (controller.bConnected)
        {
          timestamp =
            std::max (timestamp, ReadULong64Acquire (&controller.xinput.last_active));
        }
      }
    }

    if (timestamp > orig_timestamp)
    {
      InterlockedCompareExchange (
        &last_timestamp, timestamp,
                    orig_timestamp
      );
    }
  }

  return
    ReadULong64Acquire (&last_timestamp);
}

void
STDMETHODCALLTYPE
SK_IPlayStationGameInputReading::GetDevice (IGameInputDevice **device) noexcept
{
  SK_LOG_FIRST_CALL

  SK_ReleaseAssert (s_virtual_gameinput_device != nullptr);

  if (device != nullptr &&
               s_virtual_gameinput_device != nullptr)
  {            s_virtual_gameinput_device->AddRef ();
     *device = s_virtual_gameinput_device;
  }
}

bool
STDMETHODCALLTYPE
SK_IPlayStationGameInputReading::GetRawReport (IGameInputRawDeviceReport **report) noexcept
{
  SK_LOG_FIRST_CALL

  SK_RunOnce (SK_LOGi0 (L"Stub"));

  return false;
}

uint32_t
STDMETHODCALLTYPE
SK_IPlayStationGameInputReading::GetControllerAxisCount (void) noexcept
{
  SK_LOG_FIRST_CALL

  return 6;
}

uint32_t
STDMETHODCALLTYPE
SK_IPlayStationGameInputReading::GetControllerAxisState (uint32_t stateArrayCount,
                                                  float   *stateArray) noexcept
{
  SK_LOG_FIRST_CALL

  SK_RunOnce (SK_LOGi0 (L"Stub"));

  return 0;
    //pReal->GetControllerAxisState (stateArrayCount, stateArray);
}

uint32_t
STDMETHODCALLTYPE
SK_IPlayStationGameInputReading::GetControllerButtonCount (void) noexcept
{
  SK_LOG_FIRST_CALL

  return 13;
}

uint32_t
STDMETHODCALLTYPE
SK_IPlayStationGameInputReading::GetControllerButtonState (uint32_t stateArrayCount,
                                                           bool    *stateArray) noexcept
{
  SK_LOG_FIRST_CALL

  SK_RunOnce (SK_LOGi0 (L"Stub"));

  return 0;
}

uint32_t
STDMETHODCALLTYPE
SK_IPlayStationGameInputReading::GetControllerSwitchCount (void) noexcept
{
  SK_LOG_FIRST_CALL

  SK_RunOnce (SK_LOGi0 (L"Stub"));

  return 0;
}

uint32_t
STDMETHODCALLTYPE
SK_IPlayStationGameInputReading::GetControllerSwitchState (uint32_t                 stateArrayCount,
                                                           GameInputSwitchPosition *stateArray) noexcept
{
  SK_LOG_FIRST_CALL

  SK_RunOnce (SK_LOGi0 (L"Stub"));

  return 0;
}

uint32_t
STDMETHODCALLTYPE
SK_IPlayStationGameInputReading::GetKeyCount (void) noexcept
{
  SK_LOG_FIRST_CALL

  return 0;
}

uint32_t
STDMETHODCALLTYPE
SK_IPlayStationGameInputReading::GetKeyState (uint32_t           stateArrayCount,
                                              GameInputKeyState *stateArray) noexcept
{
  SK_LOG_FIRST_CALL

  return 0;
}

bool
STDMETHODCALLTYPE
SK_IPlayStationGameInputReading::GetMouseState (GameInputMouseState *state) noexcept
{
  SK_LOG_FIRST_CALL

  return false;
}

uint32_t
STDMETHODCALLTYPE
SK_IPlayStationGameInputReading::GetTouchCount (void) noexcept
{
  SK_LOG_FIRST_CALL

  SK_RunOnce (SK_LOGi0 (L"Stub"));

  return 0;
}

uint32_t
STDMETHODCALLTYPE
SK_IPlayStationGameInputReading::GetTouchState (uint32_t             stateArrayCount,
                                                GameInputTouchState *stateArray) noexcept
{
  SK_LOG_FIRST_CALL

  SK_RunOnce (SK_LOGi0 (L"Stub"));

  return 0;
}

bool
STDMETHODCALLTYPE
SK_IPlayStationGameInputReading::GetMotionState (GameInputMotionState *state) noexcept
{
  SK_LOG_FIRST_CALL

  return false;
}

bool
STDMETHODCALLTYPE
SK_IPlayStationGameInputReading::GetArcadeStickState (GameInputArcadeStickState* state) noexcept
{
  SK_LOG_FIRST_CALL

  return false;
}

bool
STDMETHODCALLTYPE
SK_IPlayStationGameInputReading::GetFlightStickState (GameInputFlightStickState *state) noexcept
{
  SK_LOG_FIRST_CALL

  return false;
}

bool
STDMETHODCALLTYPE
SK_IPlayStationGameInputReading::GetGamepadState (GameInputGamepadState *state) noexcept
{
  SK_LOG_FIRST_CALL

  ZeroMemory (state, sizeof (GameInputGamepadState));

  SK_GameInput_EmulatedPlayStation = false;

  if (! SK_HID_PlayStationControllers.empty ())
  {
    XINPUT_STATE                    _state = {};
    SK_ImGui_PollGamepad_EndFrame (&_state);

    if (config.input.gamepad.xinput.emulate && (! config.input.gamepad.xinput.blackout_api))
    {
      auto pNewestInputDevice = SK_HID_GetActivePlayStationDevice (true);
      if ( pNewestInputDevice != nullptr )
      {
        if (! SK_ImGui_WantGamepadCapture ())
        {
          // SK's own reading/vtable, unaffected by the GetGamepadState hook.
          //   These sticks arrive pre-shaped from playstation.cpp's HID
          //   pipeline -- do not re-shape.
          auto latest_state =
            pNewestInputDevice->xinput.getLatestState ();

          SK_XInput_ApplyRemapping (&latest_state);

          state->leftThumbstickX =
            static_cast <float> (latest_state.Gamepad.sThumbLX) / 32767;
          state->leftThumbstickY =
            static_cast <float> (latest_state.Gamepad.sThumbLY) / 32767;

          state->rightThumbstickX =
            static_cast <float> (latest_state.Gamepad.sThumbRX) / 32767;
          state->rightThumbstickY =
            static_cast <float> (latest_state.Gamepad.sThumbRY) / 32767;

          state->leftTrigger =
            static_cast <float> (latest_state.Gamepad.bLeftTrigger ) / 255;
          state->rightTrigger =
            static_cast <float> (latest_state.Gamepad.bRightTrigger) / 255;

          state->buttons |= (latest_state.Gamepad.wButtons & XINPUT_GAMEPAD_A) != 0 ? GameInputGamepadA : GameInputGamepadNone;
          state->buttons |= (latest_state.Gamepad.wButtons & XINPUT_GAMEPAD_B) != 0 ? GameInputGamepadB : GameInputGamepadNone;
          state->buttons |= (latest_state.Gamepad.wButtons & XINPUT_GAMEPAD_X) != 0 ? GameInputGamepadX : GameInputGamepadNone;
          state->buttons |= (latest_state.Gamepad.wButtons & XINPUT_GAMEPAD_Y) != 0 ? GameInputGamepadY : GameInputGamepadNone;

          state->buttons |= (latest_state.Gamepad.wButtons & XINPUT_GAMEPAD_START) != 0 ? GameInputGamepadMenu : GameInputGamepadNone;
          state->buttons |= (latest_state.Gamepad.wButtons & XINPUT_GAMEPAD_BACK)  != 0 ? GameInputGamepadView : GameInputGamepadNone;

          state->buttons |= (latest_state.Gamepad.wButtons & XINPUT_GAMEPAD_DPAD_UP)    != 0 ? GameInputGamepadDPadUp    : GameInputGamepadNone;
          state->buttons |= (latest_state.Gamepad.wButtons & XINPUT_GAMEPAD_DPAD_DOWN)  != 0 ? GameInputGamepadDPadDown  : GameInputGamepadNone;
          state->buttons |= (latest_state.Gamepad.wButtons & XINPUT_GAMEPAD_DPAD_LEFT)  != 0 ? GameInputGamepadDPadLeft  : GameInputGamepadNone;
          state->buttons |= (latest_state.Gamepad.wButtons & XINPUT_GAMEPAD_DPAD_RIGHT) != 0 ? GameInputGamepadDPadRight : GameInputGamepadNone;

          state->buttons |= (latest_state.Gamepad.wButtons & XINPUT_GAMEPAD_LEFT_SHOULDER)  != 0 ? GameInputGamepadLeftShoulder  : GameInputGamepadNone;
          state->buttons |= (latest_state.Gamepad.wButtons & XINPUT_GAMEPAD_RIGHT_SHOULDER) != 0 ? GameInputGamepadRightShoulder : GameInputGamepadNone;

          state->buttons |= (latest_state.Gamepad.wButtons & XINPUT_GAMEPAD_LEFT_THUMB)  != 0 ? GameInputGamepadLeftThumbstick  : GameInputGamepadNone;
          state->buttons |= (latest_state.Gamepad.wButtons & XINPUT_GAMEPAD_RIGHT_THUMB) != 0 ? GameInputGamepadRightThumbstick : GameInputGamepadNone;

          SK_GameInput_EmulatedPlayStation = true;
        }
      }
    }
  }

  return true;
}

bool
STDMETHODCALLTYPE
SK_IPlayStationGameInputReading::GetRacingWheelState (GameInputRacingWheelState *state) noexcept
{
  SK_LOG_FIRST_CALL

  return false;
}

bool
STDMETHODCALLTYPE
SK_IPlayStationGameInputReading::GetUiNavigationState (GameInputUiNavigationState *state) noexcept
{
  SK_LOG_FIRST_CALL

  SK_RunOnce (SK_LOGi0 (L"Stub"));

  return false;
}


HRESULT
WINAPI
GameInputCreate_BypassSystemDLL (IGameInput** gameInput)
{
  SK_LOG_FIRST_CALL

  return
    GameInputCreate_Detour (gameInput);
}