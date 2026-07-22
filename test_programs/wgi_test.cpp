// wgi_test.cpp -- Windows.Gaming.Input (WGI) read-path diagnostic.
//
// Every frame, reads Gamepad::GetCurrentReading() via C++/WinRT and submits
// it to the shared harness (see common/sk_test_harness.h). C++/WinRT calls
// the same IGamepad COM vtable slot SK hooks
// (WGI_Gamepad_GetCurrentReading_Override, src/input/windows.gaming.input.cpp),
// so both of SK's shaping paths are exercised through this one call site:
//   - focused: WGI is polled directly and SK shapes the WGI reading in place
//     (windows.gaming.input.cpp:533, SK_XInput_ShapeSticks on the WGI values).
//   - unfocused, with SK's background render enabled: WGI can't poll while
//     the window isn't foreground, so SK falls back to reading XInput and
//     shapes that instead (windows.gaming.input.cpp:446-508).
// Both are the same override function branching on focus state -- this
// program does not special-case focus itself, it just keeps calling
// GetCurrentReading() every frame regardless, so the operator can watch the
// switch happen live by alt-tabbing.
//
// c++20 deviation: this repo otherwise targets /std:c++17, but C++/WinRT's
// generated headers use coroutine machinery, and under /std:c++17 this
// toolchain (VS2026 / MSVC 14.51) falls back to the removed
// <experimental/coroutine> and hard-errors. /std:c++20 pulls in the
// standard <coroutine> header instead, so this program (and, in its build,
// the harness translation unit compiled alongside it) is built with
// /std:c++20. This deviation is scoped to wgi_test only.

#include "common/sk_test_harness.h"

#include <winrt/base.h>
// Pulled explicitly (rather than relying on it transitively): the WGI header
// only forward-declares IVectorView's "auto"-return consume_* members, and
// without this include their definitions (in the .1.h below it) aren't
// visible yet, so calling Size()/GetAt() on Gamepad::Gamepads() fails to
// compile (C3779, "function that returns 'auto' cannot be used before it is
// defined").
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Gaming.Input.h>

#include <windows.h>
#include <cstdint>

using winrt::Windows::Gaming::Input::Gamepad;
using winrt::Windows::Gaming::Input::GamepadReading;

namespace {

  const char* kChannelLabels[] = { "wgi" };

  // Polls the first enumerated gamepad, if any, into a fresh sample. Wrapped
  // in try/catch because projected WinRT calls throw winrt::hresult_error on
  // failure (e.g. the WGI runtime being unavailable); treated the same as
  // "no reading" rather than tearing down the harness.
  sk_test::StickSample ReadWgi(uint32_t& sequence) {
    sk_test::StickSample sample{};

    try {
      auto pads = Gamepad::Gamepads();
      if (pads.Size() == 0)
        return sample;  // no gamepad connected (yet); have_data stays false

      Gamepad        pad = pads.GetAt(0);
      GamepadReading r   = pad.GetCurrentReading();

      // WGI reports sticks (-1..1) and triggers (0..1) as double; the
      // harness (and SK's own stick-shaping) works in float, so narrow at
      // this read boundary rather than carrying doubles through.
      sample.lx = static_cast<float>(r.LeftThumbstickX);
      sample.ly = static_cast<float>(r.LeftThumbstickY);
      sample.rx = static_cast<float>(r.RightThumbstickX);
      sample.ry = static_cast<float>(r.RightThumbstickY);
      sample.lt = static_cast<float>(r.LeftTrigger);
      sample.rt = static_cast<float>(r.RightTrigger);

      // A plain incrementing counter rather than bits of r.Timestamp: the
      // timestamp is a QPC tick count with no fixed period, so it doesn't
      // read as a "packet number" the way XInput's dwPacketNumber does; a
      // per-call counter is simpler and equally sufficient to show a
      // reading changed since the last frame.
      sample.sequence  = ++sequence;
      sample.have_data = true;
    } catch (const winrt::hresult_error&) {
      sample = sk_test::StickSample{};  // no reading this frame
    }

    return sample;
  }

} // anonymous namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
  try {
    // Under SK injection the thread's COM apartment state at startup isn't
    // guaranteed; init_apartment() throws hresult_error (e.g.
    // RPC_E_CHANGED_MODE) if it was already set to an incompatible model.
    winrt::init_apartment();
  } catch (const winrt::hresult_error&) {
    return 1;
  }

  if (!sk_test::Init(L"SK WGI Test", 1, kChannelLabels))
    return 1;

  uint32_t sequence = 0;

  while (sk_test::PumpMessages()) {
    sk_test::Submit(0, ReadWgi(sequence));
    sk_test::Render();
  }

  sk_test::Shutdown();
  return 0;
}
