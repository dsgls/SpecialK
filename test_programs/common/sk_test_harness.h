// Shared D3D11 + Direct2D + DirectWrite render harness for the input read-path
// test programs under test_programs/.
//
// Isolation invariant: this header (and its .cpp) is input-free. It must never
// include XInput.h, GameInput.h, or any WinRT / Windows.Gaming.Input header, and
// must never read a gamepad itself. Callers normalize samples and Submit() them;
// the harness only renders. This keeps each test program's input hook coverage
// (XInput / GameInput / WGI) isolated to that program's own code.
#pragma once

#include <cstdint>

namespace sk_test {

  struct StickSample {
    float    lx, ly, rx, ry;   // normalized to -1..1 by the caller
    float    lt, rt;           // triggers, 0..1
    uint32_t sequence;         // packet/reading counter, monotonic
    bool     have_data;        // false -> "no reading / no device", drawn honestly
  };

  // channel_labels: array of channel_count short ASCII labels (e.g. {"current","next",...}).
  bool Init(const wchar_t* window_title,
            int channel_count,
            const char* const* channel_labels);

  bool PumpMessages();                          // pumps the message queue; false on WM_QUIT
  void Submit(int channel, const StickSample&); // caller fills one channel per frame
  void Render();                                // draws all channels + graph, then Presents
  void Shutdown();

  bool IsForeground();  // true if our window has focus; for the WGI background procedure

}
