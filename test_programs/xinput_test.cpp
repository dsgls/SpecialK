// Throwaway diagnostic: exercises only the XInput read path so an operator
// can eyeball whether Special K's stick-shaping (SK_XInput_ShapeSticks) is
// applied. Touches XInputGetState and nothing else -- see
// common/sk_test_harness.h for the shared display API.
#include <windows.h>

#include "common/sk_test_harness.h"

namespace {

  // Minimal mirror of the real XINPUT_GAMEPAD/XINPUT_STATE layout (natural
  // alignment already matches the SDK's -- no #pragma pack needed).
  // Declared locally instead of #include <Xinput.h> so this TU can never
  // pick up an implicit xinput.lib autolink; XInputGetState is resolved
  // dynamically below and must come from XInput1_4.dll specifically.
  struct SK_XINPUT_GAMEPAD {
    WORD  wButtons;
    BYTE  bLeftTrigger;
    BYTE  bRightTrigger;
    SHORT sThumbLX;
    SHORT sThumbLY;
    SHORT sThumbRX;
    SHORT sThumbRY;
  };

  struct SK_XINPUT_STATE {
    DWORD              dwPacketNumber;
    SK_XINPUT_GAMEPAD  Gamepad;
  };

  using PFN_XInputGetState = DWORD (WINAPI*)(DWORD, SK_XINPUT_STATE*);

  constexpr float kThumbRange   = 32767.0f;  // sThumbL/RX/Y full-scale divisor
  constexpr float kTriggerRange = 255.0f;    // bLeft/RightTrigger full-scale divisor

  // Thumbstick min (-32768) / 32767 overshoots -1 by a hair; clamp per spec.
  float NormalizeThumb(SHORT raw) {
    const float v = static_cast<float>(raw) / kThumbRange;
    return v < -1.0f ? -1.0f : (v > 1.0f ? 1.0f : v);
  }

  float NormalizeTrigger(BYTE raw) {
    return static_cast<float>(raw) / kTriggerRange;
  }

}  // namespace

int main() {
  // SK's XInput detour is installed on XInput1_4.dll specifically
  // (src/input/xinput_core.cpp), so resolve that module explicitly instead
  // of linking xinput.lib, whose version-selection could land on a
  // different DLL (e.g. xinput1_3/9_1_0) and never reach the hook.
  const HMODULE xinput_module = LoadLibraryW(L"XInput1_4.dll");
  if (!xinput_module)
    return 1;

  const auto XInputGetState_ = reinterpret_cast<PFN_XInputGetState>(
    GetProcAddress(xinput_module, "XInputGetState"));
  if (!XInputGetState_)
    return 1;

  const char* labels[] = { "xinput" };
  if (!sk_test::Init(L"SK XInput Read-Path Test", 1, labels))
    return 1;

  while (sk_test::PumpMessages()) {
    SK_XINPUT_STATE state  = {};
    const DWORD     result = XInputGetState_(0, &state);

    sk_test::StickSample sample = {};
    sample.have_data = (result == ERROR_SUCCESS);

    if (sample.have_data) {
      sample.lx       = NormalizeThumb(state.Gamepad.sThumbLX);
      sample.ly       = NormalizeThumb(state.Gamepad.sThumbLY);
      sample.rx       = NormalizeThumb(state.Gamepad.sThumbRX);
      sample.ry       = NormalizeThumb(state.Gamepad.sThumbRY);
      sample.lt       = NormalizeTrigger(state.Gamepad.bLeftTrigger);
      sample.rt       = NormalizeTrigger(state.Gamepad.bRightTrigger);
      sample.sequence = state.dwPacketNumber;
    }

    sk_test::Submit(0, sample);
    sk_test::Render();
  }

  sk_test::Shutdown();
  return 0;
}
