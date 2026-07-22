// Exercises the four POLLED GameInput read paths -- GetCurrentReading,
// GetNextReading, GetPreviousReading, GetTemporalReading -- side by side so
// an operator can confirm SK's stick-shaping lands exactly once and all four
// agree. See .superpowers/sdd/task-3-brief.md for the design.
//
// GameInput.dll is resolved dynamically (LoadLibrary + GetProcAddress, no
// import lib) so SK's GameInputCreate hook -- which hands back the
// SK_IWrapGameInput wrapper -- is in force when SK is injected, and so the
// DLL choice (system vs redist) is a runtime pick rather than a link-time one.
//
// STARTUP ORDER: GameInputCreate runs at the very top of main(), before
// sk_test::Init. SK arms its GameInputCreate hook inline as soon as its DLL
// is loaded, so this program is exactly the early-acquisition case that hook
// must survive -- a regression here means the hook-arming fix broke.

#include "common/sk_test_harness.h"

#include <windows.h>
#include <GameInput.h>

#include <cstdio>
#include <cstring>
#include <cstdint>

namespace {

  // Copies a reading's gamepad state into a StickSample; have_data stays
  // false (the struct's zero-init default) if the reading is null or isn't
  // actually a gamepad.
  sk_test::StickSample ReadingToSample(IGameInputReading* reading) {
    sk_test::StickSample sample{};
    if (!reading)
      return sample;

    GameInputGamepadState gp{};
    if (!reading->GetGamepadState(&gp))
      return sample;

    sample.lx = gp.leftThumbstickX;
    sample.ly = gp.leftThumbstickY;
    sample.rx = gp.rightThumbstickX;
    sample.ry = gp.rightThumbstickY;
    sample.lt = gp.leftTrigger;
    sample.rt = gp.rightTrigger;
    // GetSequenceNumber is GameInput's own per-kind reading counter, not a
    // counter we invent -- it lets the operator read the channels' true
    // relative order directly off-screen (current highest, previous one
    // behind, next catching up to current, temporal near current).
    sample.sequence  = static_cast<uint32_t>(reading->GetSequenceNumber(GameInputKindGamepad));
    sample.have_data = true;
    return sample;
  }

  // Guards g_device: RegisterDeviceCallback below delivers already-connected
  // devices synchronously on the calling thread (GameInputBlockingEnumeration),
  // but hotplug arrivals land later on a GameInput worker thread, while the
  // render loop reads the pointer every frame on the main thread.
  CRITICAL_SECTION  g_deviceCs;
  IGameInputDevice* g_device = nullptr;

  // Stores the first gamepad device it is ever given, AddRef'd so it outlives
  // the callback; later (hotplug) devices are ignored -- one steady device is
  // enough to exercise the four polled read paths side by side.
  void CALLBACK OnDevice(GameInputCallbackToken /*callbackToken*/,
                          void* /*context*/,
                          IGameInputDevice* device,
                          uint64_t /*timestamp*/,
                          GameInputDeviceStatus /*currentStatus*/,
                          GameInputDeviceStatus /*previousStatus*/) {
    EnterCriticalSection(&g_deviceCs);
    if (!g_device && device) {
      g_device = device;
      g_device->AddRef();
    }
    LeaveCriticalSection(&g_deviceCs);
  }

} // namespace

int main(int argc, char** argv) {
  const wchar_t* dll_name = (argc > 1 && std::strcmp(argv[1], "redist") == 0)
    ? L"GameInputRedist.dll" : L"GameInput.dll";

  const HMODULE gi_module = LoadLibraryW(dll_name);
  if (!gi_module) {
    std::printf("LoadLibraryW failed for the GameInput DLL.\n");
    return 1;
  }

  const auto pGameInputCreate =
    reinterpret_cast<decltype(&GameInputCreate)>(GetProcAddress(gi_module, "GameInputCreate"));
  if (!pGameInputCreate) {
    std::printf("GetProcAddress(GameInputCreate) failed.\n");
    FreeLibrary(gi_module);
    return 1;
  }

  IGameInput* gi = nullptr;
  if (FAILED(pGameInputCreate(&gi)) || !gi) {
    std::printf("GameInputCreate failed.\n");
    FreeLibrary(gi_module);
    return 1;
  }

  InitializeCriticalSection(&g_deviceCs);

  // Blocking enumeration delivers every already-connected gamepad to OnDevice
  // before this call returns, so g_device is populated (if a pad is present)
  // before sk_test::Init even brings up the window.
  GameInputCallbackToken device_token = GAMEINPUT_INVALID_CALLBACK_TOKEN_VALUE;
  const HRESULT device_cb_hr =
    gi->RegisterDeviceCallback(nullptr, GameInputKindGamepad, GameInputDeviceConnected,
                               GameInputBlockingEnumeration, nullptr, OnDevice, &device_token);

  const char* const kLabels[] = { "current", "next", "previous", "temporal" };
  if (!sk_test::Init(L"GameInput Poll Test", 4, kLabels)) {
    std::printf("sk_test::Init failed.\n");
    // Symmetric with the shutdown drain below: stop the device callback and
    // block (bounded) until any invocation in flight finishes before tearing
    // down the critical section it locks. Only if registration succeeded --
    // otherwise device_token was never valid and there is nothing to drain.
    if (SUCCEEDED(device_cb_hr)) {
      gi->StopCallback(device_token);
      for (int attempt = 0; attempt < 5; ++attempt)
        if (gi->UnregisterCallback(device_token, /*timeoutInMicroseconds=*/ 5'000'000))
          break;
    }
    if (g_device)
      g_device->Release();
    DeleteCriticalSection(&g_deviceCs);
    gi->Release();
    FreeLibrary(gi_module);
    return 1;
  }

  // walker is seeded from the first successful GetCurrentReading (see the
  // `if (!walker)` branch below) -- the one documented departure from "one
  // method only" for the polled channels, since GetNextReading needs a
  // reference to walk forward from and GetCurrentReading is the only way to
  // obtain a first one. After that, "next" only ever advances via
  // GetNextReading itself.
  IGameInputReading* walker = nullptr;

  while (sk_test::PumpMessages()) {
    EnterCriticalSection(&g_deviceCs);
    IGameInputDevice* device = g_device;
    LeaveCriticalSection(&g_deviceCs);

    if (!device) {
      // No device enumerated yet -- every channel is honestly empty. Do not
      // poll at all: a null device collides with an upstream SK bug and would
      // never exercise SK's Xbox-Mode virtual device anyway.
      for (int c = 0; c < 4; ++c)
        sk_test::Submit(c, sk_test::StickSample{});
      sk_test::Render();
      continue;
    }

    IGameInputReading* cur = nullptr;
    if (FAILED(gi->GetCurrentReading(GameInputKindGamepad, device, &cur))) {
      // No reading this frame -- every channel is honestly empty; walker (if
      // any) is left untouched for the next frame's drain.
      for (int c = 0; c < 4; ++c)
        sk_test::Submit(c, sk_test::StickSample{});
      sk_test::Render();
      continue;
    }

    sk_test::Submit(0, ReadingToSample(cur)); // current

    if (!walker) {
      // Seed was lost or never succeeded (e.g. no reading at startup) --
      // reseed from this frame's current so the drain below has a reference
      // to walk forward from starting next frame.
      walker = cur;
      walker->AddRef();
      sk_test::Submit(1, sk_test::StickSample{});
    } else {
      // Drain the walker forward to newest using GetNextReading alone.
      // GetNextReading(current) directly would return
      // GAMEINPUT_E_READING_NOT_FOUND -- current is already newest -- so
      // catching up requires walking forward from a retained stale reading.
      IGameInputReading* nx = nullptr;
      while (SUCCEEDED(gi->GetNextReading(walker, GameInputKindGamepad, device, &nx))) {
        walker->Release();
        walker = nx;
        nx = nullptr;
      }
      sk_test::Submit(1, ReadingToSample(walker)); // next
    }

    IGameInputReading* prev = nullptr;
    if (SUCCEEDED(gi->GetPreviousReading(cur, GameInputKindGamepad, device, &prev))) {
      sk_test::Submit(2, ReadingToSample(prev)); // previous
      prev->Release();
    } else {
      sk_test::Submit(2, sk_test::StickSample{});
    }

    IGameInputReading* tmp = nullptr;
    if (SUCCEEDED(gi->GetTemporalReading(gi->GetCurrentTimestamp(), device, &tmp))) {
      sk_test::Submit(3, ReadingToSample(tmp)); // temporal
      tmp->Release();
    } else {
      sk_test::Submit(3, sk_test::StickSample{});
    }

    cur->Release(); // every reading obtained this frame is released except the retained walker

    sk_test::Render();
  }

  if (walker)
    walker->Release();

  // Stop first so no new callback starts, then Unregister to block until any
  // callback already in flight finishes -- only after that is it safe to
  // release g_device and destroy the critical section it locks. Only if
  // registration succeeded -- otherwise device_token was never valid.
  if (SUCCEEDED(device_cb_hr)) {
    gi->StopCallback(device_token);
    bool device_cb_unregistered = false;
    for (int attempt = 0; !device_cb_unregistered && attempt < 5; ++attempt)
      device_cb_unregistered = gi->UnregisterCallback(device_token, /*timeoutInMicroseconds=*/ 5'000'000);
  }

  if (g_device)
    g_device->Release();
  DeleteCriticalSection(&g_deviceCs);

  sk_test::Shutdown();
  gi->Release();
  FreeLibrary(gi_module);
  return 0;
}
