// Diagnostic program exercising the GameInput CALLBACK-only read path.
//
// PURITY INVARIANT: this program calls RegisterReadingCallback and nothing
// else that acquires a reading -- no GetCurrentReading/GetNextReading/
// GetPreviousReading/GetTemporalReading, no GetCurrentTimestamp, ever. Those
// polled entry points are exactly what makes SK install its reading-shaping
// hook; calling any of them here would make the callback-only path this
// program exists to probe look shaped even though it never went through the
// hook install site, proving the RegisterReadingCallback install site works
// rather than the polled one. RegisterDeviceCallback is exempt: a device
// connection callback is not a reading acquisition, so enumerating a device
// through it does not weaken the invariant.
//
// Isolation invariant (like the shared harness): only this file touches
// GameInput.h; the harness stays input-free.
//
// STARTUP ORDER: GameInputCreate runs at the very top of main(), before
// sk_test::Init, for the same reason as gameinput_poll_test -- SK arms its
// GameInputCreate hook inline as soon as its DLL is loaded, so this program
// is exactly the early-acquisition case that hook must survive.
#include "common/sk_test_harness.h"

#include <windows.h>
#include <GameInput.h>

#include <cstring>

namespace {

  // Guards g_latest/g_haveData/g_sequence: the GameInput runtime delivers
  // OnReading() on its own worker thread while the main thread reads the
  // snapshot once per frame in the render loop below. Without the lock the
  // two threads could race on the same memory (e.g. main thread observing a
  // torn struct with some fields from the old reading and some from the new
  // one), so every access on either side is wrapped in the same section.
  CRITICAL_SECTION     g_cs;
  GameInputGamepadState g_latest    = {};
  bool                  g_haveData  = false;
  uint32_t              g_sequence  = 0;

  void CALLBACK OnReading(GameInputCallbackToken /*callbackToken*/,
                           void* /*context*/,
                           IGameInputReading* reading,
                           bool /*hasOverrunOccurred*/) {
    // reading is a borrowed reference for the duration of this callback --
    // the GameInput runtime owns it and releases it after we return, so we
    // must not Release() it ourselves.
    GameInputGamepadState state;
    if (reading != nullptr && reading->GetGamepadState(&state)) {
      EnterCriticalSection(&g_cs);
      g_latest = state;
      g_haveData = true;
      ++g_sequence;
      LeaveCriticalSection(&g_cs);
    }
  }

  // Guards g_device: RegisterDeviceCallback below delivers already-connected
  // devices synchronously on the calling thread (GameInputBlockingEnumeration),
  // but hotplug arrivals land later on a GameInput worker thread, while main()
  // reads the pointer once, right before installing the reading callback.
  CRITICAL_SECTION  g_deviceCs;
  IGameInputDevice* g_device = nullptr;

  // Stores the first gamepad device it is ever given, AddRef'd so it outlives
  // the callback; later (hotplug) devices are ignored -- one steady device is
  // enough to drive the reading callback under test.
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

}  // namespace

int main(int argc, char** argv) {
  // §6 intro: resolve GameInputCreate dynamically (no import lib) so that
  // when SK is injected, its export/IAT redirection of GameInputCreate is
  // what actually answers this call instead of the real DLL export.
  const bool useRedist = argc > 1 && std::strcmp(argv[1], "redist") == 0;
  const wchar_t* dllName = useRedist ? L"GameInputRedist.dll" : L"GameInput.dll";

  HMODULE hGameInput = LoadLibraryW(dllName);
  if (hGameInput == nullptr)
    return 1;

  auto pGameInputCreate = (decltype(&GameInputCreate))GetProcAddress(hGameInput, "GameInputCreate");
  if (pGameInputCreate == nullptr) {
    FreeLibrary(hGameInput);
    return 1;
  }

  IGameInput* gi = nullptr;
  if (FAILED(pGameInputCreate(&gi)) || gi == nullptr) {
    FreeLibrary(hGameInput);
    return 1;
  }

  InitializeCriticalSection(&g_deviceCs);

  // Blocking enumeration delivers every already-connected gamepad to OnDevice
  // before this call returns, so g_device is populated (if a pad is present)
  // before sk_test::Init even brings up the window.
  GameInputCallbackToken deviceToken = GAMEINPUT_INVALID_CALLBACK_TOKEN_VALUE;
  const HRESULT deviceCbHr =
    gi->RegisterDeviceCallback(nullptr, GameInputKindGamepad, GameInputDeviceConnected,
                               GameInputBlockingEnumeration, nullptr, OnDevice, &deviceToken);

  static const char* kChannelLabels[] = { "callback" };
  if (!sk_test::Init(L"GameInput Callback Test", 1, kChannelLabels)) {
    // Symmetric with the shutdown drain below: stop the device callback and
    // block (bounded) until any invocation in flight finishes before tearing
    // down the critical section it locks. Only if registration succeeded --
    // otherwise deviceToken was never valid and there is nothing to drain.
    if (SUCCEEDED(deviceCbHr)) {
      gi->StopCallback(deviceToken);
      for (int attempt = 0; attempt < 5; ++attempt)
        if (gi->UnregisterCallback(deviceToken, /*timeoutInMicroseconds=*/ 5'000'000))
          break;
    }
    if (g_device)
      g_device->Release();
    DeleteCriticalSection(&g_deviceCs);
    gi->Release();
    FreeLibrary(hGameInput);
    return 1;
  }

  InitializeCriticalSection(&g_cs);

  EnterCriticalSection(&g_deviceCs);
  IGameInputDevice* device = g_device;
  LeaveCriticalSection(&g_deviceCs);

  GameInputCallbackToken token = GAMEINPUT_INVALID_CALLBACK_TOKEN_VALUE;
  const HRESULT hr = gi->RegisterReadingCallback(device, GameInputKindGamepad, 0.0f, nullptr, OnReading, &token);
  if (FAILED(hr)) {
    sk_test::Shutdown();
    DeleteCriticalSection(&g_cs);
    if (SUCCEEDED(deviceCbHr)) {
      gi->StopCallback(deviceToken);
      for (int attempt = 0; attempt < 5; ++attempt)
        if (gi->UnregisterCallback(deviceToken, /*timeoutInMicroseconds=*/ 5'000'000))
          break;
    }
    if (g_device)
      g_device->Release();
    DeleteCriticalSection(&g_deviceCs);
    gi->Release();
    return 1;
  }

  bool running = true;
  while (running) {
    running = sk_test::PumpMessages();

    sk_test::StickSample sample = {};
    EnterCriticalSection(&g_cs);
    sample.have_data = g_haveData;
    if (g_haveData) {
      // Passthrough: shows whatever GetGamepadState returns. Unhooked, that
      // is raw and linear; under SK, RegisterReadingCallback is interposed
      // by a thunk that installs the GetGamepadState shaping hook before
      // this callback runs, so these values already carry SK's shaping.
      sample.lx = g_latest.leftThumbstickX;
      sample.ly = g_latest.leftThumbstickY;
      sample.rx = g_latest.rightThumbstickX;
      sample.ry = g_latest.rightThumbstickY;
      sample.lt = g_latest.leftTrigger;
      sample.rt = g_latest.rightTrigger;
      sample.sequence = g_sequence;
    }
    LeaveCriticalSection(&g_cs);

    sk_test::Submit(0, sample);
    sk_test::Render();
  }

  // Stop first so no new callback starts, then Unregister to block until any
  // callback already in flight finishes -- only after that is it safe to
  // release gi and destroy the critical section the callback locks.
  // UnregisterCallback returns false if its timeout elapses while a callback
  // invocation is still in progress; retry (bounded) until it reports the
  // callback truly drained, since destroying g_cs/gi while OnReading might
  // still be running on a GameInput worker thread is undefined behavior.
  gi->StopCallback(token);
  bool unregistered = false;
  for (int attempt = 0; !unregistered && attempt < 5; ++attempt)
    unregistered = gi->UnregisterCallback(token, /*timeoutInMicroseconds=*/ 5'000'000);

  sk_test::Shutdown();
  DeleteCriticalSection(&g_cs);

  // Same drain, same reasoning, for the device callback registered at
  // startup, before releasing g_device and destroying the CS it locks. Only
  // if registration succeeded -- otherwise deviceToken was never valid.
  if (SUCCEEDED(deviceCbHr)) {
    gi->StopCallback(deviceToken);
    bool device_unregistered = false;
    for (int attempt = 0; !device_unregistered && attempt < 5; ++attempt)
      device_unregistered = gi->UnregisterCallback(deviceToken, /*timeoutInMicroseconds=*/ 5'000'000);
  }

  if (g_device)
    g_device->Release();
  DeleteCriticalSection(&g_deviceCs);

  gi->Release();
  return 0;
}
