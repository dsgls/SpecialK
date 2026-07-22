// Implementation of the shared render harness. See sk_test_harness.h for the
// public API and the isolation invariant: no input/gamepad header, ever, here.
//
// Render path is swap-effect-agnostic: D2D draws into a private offscreen
// texture whose render target is created once, then each frame that texture is
// CopyResource'd onto swapchain backbuffer 0 before Present. This survives the
// flip model (buffer 0 rotates) and Special K's flip-model override (which hands
// GetBuffer a typeless, D2D-incompatible texture) alike -- neither can invalidate
// a render target that never touches the swapchain. The window is borderless
// fullscreen at native resolution so 1 backbuffer pixel == 1 display pixel (no
// post-scaling) and Special K's ImGui overlay has the whole screen to work with.
#include "sk_test_harness.h"

#include <windows.h>
#include <d3d11.h>
#include <d2d1.h>
#include <dwrite.h>
#include <dxgi.h>

#include <cmath>
#include <cwchar>
#include <string>
#include <vector>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "dwrite.lib")
#pragma comment(lib, "user32.lib")   // window class + message pump (RegisterClassExW/PeekMessageW/...)

namespace sk_test {

namespace {

  // ~5 s of history at 60 fps for the channel-0 magnitude graph.
  constexpr int kGraphCapacity = 300;

  // Layout is authored against a 1080p reference and scaled by
  // backbufferHeight/1080 so the readout stays a consistent physical size (and
  // readable) at any native resolution. Constants below are the 1080p values.
  constexpr float kReferenceHeight     = 1080.0f;
  constexpr float kLogicalMargin       =   10.0f;
  constexpr float kLogicalBlockHeight  =  100.0f;  // vertical space per channel's numeric block
  constexpr float kLogicalGraphHeight  =  260.0f;
  constexpr float kLogicalContentWidth =  620.0f;  // width of the left-hand readout column
  constexpr float kLogicalFontSize     =   14.0f;

  HWND                 g_hwnd          = nullptr;
  ID3D11Device*        g_device        = nullptr;
  ID3D11DeviceContext* g_context       = nullptr;
  IDXGISwapChain*      g_swapchain     = nullptr;
  ID3D11Texture2D*     g_offscreen     = nullptr;  // D2D target; copied to backbuffer each frame
  ID2D1Factory*        g_d2dFactory    = nullptr;
  ID2D1RenderTarget*   g_d2dRT         = nullptr;  // bound to g_offscreen, never the swapchain
  IDWriteFactory*      g_dwriteFactory = nullptr;
  IDWriteTextFormat*   g_textFormat    = nullptr;

  ID2D1SolidColorBrush* g_brushText  = nullptr;
  ID2D1SolidColorBrush* g_brushFrame = nullptr;
  ID2D1SolidColorBrush* g_brushLeft  = nullptr;  // left-stick magnitude polyline
  ID2D1SolidColorBrush* g_brushRight = nullptr;  // right-stick magnitude polyline

  // Resolution-derived layout, filled in by Init() once the backbuffer size is
  // known. g_scale multiplies stroke widths and the logical constants above.
  float g_scale        = 1.0f;
  float g_margin       = kLogicalMargin;
  float g_blockHeight  = kLogicalBlockHeight;
  float g_graphHeight  = kLogicalGraphHeight;
  float g_contentWidth = kLogicalContentWidth;

  // True only once every Init() step has succeeded; Render() gates on this
  // rather than g_d2dRT so a partial-failure Init() never leaves it able to
  // dereference an unset g_textFormat/brush.
  bool g_ready = false;

  std::vector<StickSample>  g_channels;
  std::vector<std::wstring> g_labels;

  // Ring buffers for the channel-0 magnitude graph; g_ringWrite is the next
  // slot to write, g_ringFilled saturates at kGraphCapacity once wrapped.
  float g_ringLeft[kGraphCapacity]  = {};
  float g_ringRight[kGraphCapacity] = {};
  int   g_ringWrite  = 0;
  int   g_ringFilled = 0;

  // Opt into per-monitor DPI awareness so an uninjected run renders at true
  // native resolution instead of being DPI-virtualized (post-scaled) by Windows.
  // Under Special K this is a harmless no-op -- SK already sets it. Resolved
  // dynamically so the harness builds regardless of the SDK's default WINVER;
  // (HANDLE)-4 is DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2.
  void EnablePerMonitorDpiAwareness() {
    if (HMODULE user32 = GetModuleHandleW(L"user32.dll")) {
      using SetCtx_pfn = BOOL (WINAPI*)(HANDLE);
      if (auto set_ctx = reinterpret_cast<SetCtx_pfn>(
                           GetProcAddress(user32, "SetProcessDpiAwarenessContext"))) {
        set_ctx(reinterpret_cast<HANDLE>(static_cast<INT_PTR>(-4)));
      }
    }
  }

  // channel_labels entries are short ASCII; a byte-widening copy is sufficient.
  std::wstring ToWide(const char* s) {
    std::wstring w;
    for (const char* p = s; *p; ++p)
      w.push_back(static_cast<wchar_t>(static_cast<unsigned char>(*p)));
    return w;
  }

  LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    if (msg == WM_DESTROY) {
      PostQuitMessage(0);
      return 0;
    }
    // Borderless fullscreen has no close button, so Esc is the quit path.
    if (msg == WM_KEYDOWN && wparam == VK_ESCAPE) {
      PostQuitMessage(0);
      return 0;
    }
    // No WM_ACTIVATE / kill-focus early-out: windowed Present must keep
    // running unfocused so IsForeground() reflects reality for callers
    // (e.g. the WGI background-input procedure) rather than a paused view.
    return DefWindowProcW(hwnd, msg, wparam, lparam);
  }

  void PushGraphSample(float left_mag, float right_mag) {
    g_ringLeft[g_ringWrite]  = left_mag;
    g_ringRight[g_ringWrite] = right_mag;
    g_ringWrite = (g_ringWrite + 1) % kGraphCapacity;
    if (g_ringFilled < kGraphCapacity)
      ++g_ringFilled;
  }

  void DrawGraph(const D2D1_RECT_F& rect) {
    g_d2dRT->DrawRectangle(rect, g_brushFrame, 1.0f * g_scale);

    if (g_ringFilled < 2)
      return;

    const float w      = rect.right - rect.left;
    const float h      = rect.bottom - rect.top;
    const int   oldest = (g_ringWrite - g_ringFilled + kGraphCapacity) % kGraphCapacity;

    // Ring buffer holds raw magnitudes; the 0..1 frame maps directly since
    // stick magnitude is already normalized by the caller.
    auto plot_point = [&](int sample_index, float value) -> D2D1_POINT_2F {
      const float clamped = value < 0.0f ? 0.0f : (value > 1.0f ? 1.0f : value);
      const float x = rect.left + w * (static_cast<float>(sample_index) / static_cast<float>(kGraphCapacity - 1));
      const float y = rect.bottom - clamped * h;
      return D2D1::Point2F(x, y);
    };

    D2D1_POINT_2F prev_left  = plot_point(0, g_ringLeft[oldest]);
    D2D1_POINT_2F prev_right = plot_point(0, g_ringRight[oldest]);

    for (int j = 1; j < g_ringFilled; ++j) {
      const int idx = (oldest + j) % kGraphCapacity;

      const D2D1_POINT_2F cur_left  = plot_point(j, g_ringLeft[idx]);
      const D2D1_POINT_2F cur_right = plot_point(j, g_ringRight[idx]);

      g_d2dRT->DrawLine(prev_left,  cur_left,  g_brushLeft,  1.5f * g_scale);
      g_d2dRT->DrawLine(prev_right, cur_right, g_brushRight, 1.5f * g_scale);

      prev_left  = cur_left;
      prev_right = cur_right;
    }
  }

  std::wstring FormatChannelBlock(const std::wstring& label, const StickSample& s) {
    wchar_t buf[512];

    if (!s.have_data) {
      std::swprintf(buf, 512, L"%ls\nno reading / no device", label.c_str());
      return buf;
    }

    const float lmag = std::sqrt(s.lx * s.lx + s.ly * s.ly);
    const float rmag = std::sqrt(s.rx * s.rx + s.ry * s.ry);

    std::swprintf(buf, 512,
      L"%ls\nLX %.3f LY %.3f RX %.3f RY %.3f\nLT %.3f RT %.3f\nLmag %.3f RMag %.3f\nseq %u",
      label.c_str(), s.lx, s.ly, s.rx, s.ry, s.lt, s.rt, lmag, rmag,
      static_cast<unsigned int>(s.sequence));

    return buf;
  }

} // anonymous namespace

bool Init(const wchar_t* window_title, int channel_count, const char* const* channel_labels) {
  if (channel_count <= 0 || channel_labels == nullptr)
    return false;

  EnablePerMonitorDpiAwareness();

  g_channels.assign(static_cast<size_t>(channel_count), StickSample{});
  g_labels.resize(static_cast<size_t>(channel_count));
  for (int i = 0; i < channel_count; ++i)
    g_labels[static_cast<size_t>(i)] = ToWide(channel_labels[i]);

  const HINSTANCE hinstance = GetModuleHandleW(nullptr);

  WNDCLASSEXW wc     = { sizeof(wc) };
  wc.lpfnWndProc     = WndProc;
  wc.hInstance       = hinstance;
  wc.hCursor         = LoadCursorW(nullptr, IDC_ARROW);
  wc.lpszClassName   = L"SKTestHarnessWindowClass";
  if (!RegisterClassExW(&wc))
    return false;

  // Borderless window covering the primary monitor at its native resolution.
  // Not topmost: alt-tabbing to another app (the WGI background procedure)
  // must bring that app forward while this window keeps rendering behind it.
  MONITORINFO mi = { sizeof(mi) };
  GetMonitorInfoW(MonitorFromPoint(POINT{ 0, 0 }, MONITOR_DEFAULTTOPRIMARY), &mi);
  const int mon_x = mi.rcMonitor.left;
  const int mon_y = mi.rcMonitor.top;
  const int mon_w = mi.rcMonitor.right  - mi.rcMonitor.left;
  const int mon_h = mi.rcMonitor.bottom - mi.rcMonitor.top;

  g_hwnd = CreateWindowExW(0, wc.lpszClassName, window_title, WS_POPUP,
                            mon_x, mon_y, mon_w, mon_h,
                            nullptr, nullptr, hinstance, nullptr);
  if (!g_hwnd)
    return false;

  ShowWindow(g_hwnd, SW_SHOW);
  UpdateWindow(g_hwnd);

  DXGI_SWAP_CHAIN_DESC sc_desc = {};
  sc_desc.BufferDesc.Width     = static_cast<UINT>(mon_w);
  sc_desc.BufferDesc.Height    = static_cast<UINT>(mon_h);
  sc_desc.BufferDesc.Format    = DXGI_FORMAT_B8G8R8A8_UNORM;
  sc_desc.SampleDesc.Count     = 1;
  sc_desc.BufferUsage          = DXGI_USAGE_RENDER_TARGET_OUTPUT;
  sc_desc.BufferCount          = 2;
  sc_desc.OutputWindow         = g_hwnd;
  sc_desc.Windowed             = TRUE;
  // Flip model, like a normal modern D3D app. The render path never binds a
  // render target to the backbuffer (see file header), so buffer rotation costs
  // us nothing, and SK sees an already-flip swapchain -- its override stays off.
  sc_desc.SwapEffect           = DXGI_SWAP_EFFECT_FLIP_DISCARD;

  const D3D_FEATURE_LEVEL levels[]     = { D3D_FEATURE_LEVEL_11_0 };
  D3D_FEATURE_LEVEL       obtained_level{};

  HRESULT hr = D3D11CreateDeviceAndSwapChain(
    nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
    levels, 1, D3D11_SDK_VERSION, &sc_desc, &g_swapchain, &g_device, &obtained_level, &g_context);
  if (FAILED(hr))
    return false;

  // Size everything from the swapchain's *actual* backbuffer, so an SK
  // resolution override can't desync the offscreen texture (CopyResource
  // requires matching dimensions) or the layout scale.
  DXGI_SWAP_CHAIN_DESC actual_desc = {};
  g_swapchain->GetDesc(&actual_desc);
  const UINT bb_w = actual_desc.BufferDesc.Width;
  const UINT bb_h = actual_desc.BufferDesc.Height;

  g_scale        = static_cast<float>(bb_h) / kReferenceHeight;
  g_margin       = kLogicalMargin       * g_scale;
  g_blockHeight  = kLogicalBlockHeight  * g_scale;
  g_graphHeight  = kLogicalGraphHeight  * g_scale;
  g_contentWidth = kLogicalContentWidth * g_scale;

  // Offscreen D2D target: typed BGRA (D2D-compatible), render-target bindable.
  // Same B8G8R8A8 family as the backbuffer, so the per-frame CopyResource is a
  // legal copy whether the backbuffer comes back typed (native / SK override
  // off) or typeless (SK override on).
  D3D11_TEXTURE2D_DESC tex_desc = {};
  tex_desc.Width            = bb_w;
  tex_desc.Height           = bb_h;
  tex_desc.MipLevels        = 1;
  tex_desc.ArraySize        = 1;
  tex_desc.Format           = DXGI_FORMAT_B8G8R8A8_UNORM;
  tex_desc.SampleDesc.Count = 1;
  tex_desc.Usage            = D3D11_USAGE_DEFAULT;
  tex_desc.BindFlags        = D3D11_BIND_RENDER_TARGET;

  hr = g_device->CreateTexture2D(&tex_desc, nullptr, &g_offscreen);
  if (FAILED(hr))
    return false;

  IDXGISurface* offscreen_surface = nullptr;
  hr = g_offscreen->QueryInterface(__uuidof(IDXGISurface), reinterpret_cast<void**>(&offscreen_surface));
  if (FAILED(hr))
    return false;

  hr = D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, &g_d2dFactory);
  if (FAILED(hr)) {
    offscreen_surface->Release();
    return false;
  }

  const D2D1_RENDER_TARGET_PROPERTIES rt_props = D2D1::RenderTargetProperties(
    D2D1_RENDER_TARGET_TYPE_DEFAULT,
    D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_PREMULTIPLIED));

  // Created once on the stable offscreen surface, so it never goes stale.
  hr = g_d2dFactory->CreateDxgiSurfaceRenderTarget(offscreen_surface, &rt_props, &g_d2dRT);
  offscreen_surface->Release();
  if (FAILED(hr))
    return false;

  hr = DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory),
                            reinterpret_cast<IUnknown**>(&g_dwriteFactory));
  if (FAILED(hr))
    return false;

  hr = g_dwriteFactory->CreateTextFormat(L"Consolas", nullptr, DWRITE_FONT_WEIGHT_NORMAL,
                                          DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL,
                                          kLogicalFontSize * g_scale, L"en-us", &g_textFormat);
  if (FAILED(hr))
    return false;

  g_textFormat->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
  g_textFormat->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);

  if (FAILED(g_d2dRT->CreateSolidColorBrush(D2D1::ColorF(1.0f, 1.0f, 1.0f),    &g_brushText)))
    return false;
  if (FAILED(g_d2dRT->CreateSolidColorBrush(D2D1::ColorF(0.5f, 0.5f, 0.5f),    &g_brushFrame)))
    return false;
  if (FAILED(g_d2dRT->CreateSolidColorBrush(D2D1::ColorF(0.30f, 0.85f, 0.35f), &g_brushLeft)))
    return false;
  if (FAILED(g_d2dRT->CreateSolidColorBrush(D2D1::ColorF(0.30f, 0.55f, 1.00f), &g_brushRight)))
    return false;

  g_ready = true;
  return true;
}

bool PumpMessages() {
  MSG msg;
  while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
    if (msg.message == WM_QUIT)
      return false;
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }
  return true;
}

void Submit(int channel, const StickSample& sample) {
  if (channel < 0 || static_cast<size_t>(channel) >= g_channels.size())
    return;
  g_channels[static_cast<size_t>(channel)] = sample;
}

void Render() {
  if (!g_ready)
    return;

  // Exactly one graph push per rendered frame, sourced from channel 0 (the
  // primary/"live" channel every program under test drives). A missing
  // reading pushes 0 rather than repeating a stale magnitude.
  if (!g_channels.empty()) {
    const StickSample& primary = g_channels[0];
    const float lmag = primary.have_data ? std::sqrt(primary.lx * primary.lx + primary.ly * primary.ly) : 0.0f;
    const float rmag = primary.have_data ? std::sqrt(primary.rx * primary.rx + primary.ry * primary.ry) : 0.0f;
    PushGraphSample(lmag, rmag);
  }

  g_d2dRT->BeginDraw();
  g_d2dRT->Clear(D2D1::ColorF(0.06f, 0.06f, 0.09f));

  for (size_t i = 0; i < g_channels.size(); ++i) {
    const float top = g_margin + static_cast<float>(i) * g_blockHeight;
    const D2D1_RECT_F block_rect = D2D1::RectF(
      g_margin, top, g_margin + g_contentWidth, top + g_blockHeight);

    const std::wstring text = FormatChannelBlock(g_labels[i], g_channels[i]);
    g_d2dRT->DrawText(text.c_str(), static_cast<UINT32>(text.size()), g_textFormat, block_rect, g_brushText);
  }

  const float graph_top = g_margin + static_cast<float>(g_channels.size()) * g_blockHeight + g_margin;
  const D2D1_RECT_F graph_rect = D2D1::RectF(
    g_margin, graph_top, g_margin + g_contentWidth, graph_top + g_graphHeight);

  DrawGraph(graph_rect);

  g_d2dRT->EndDraw();

  // Publish the frame: copy the offscreen target onto backbuffer 0, then
  // present. Requesting ID3D11Texture2D is the GUID SK's GetBuffer wrapper
  // expects, so no wrapper warning and no D2D-on-swapchain involvement.
  ID3D11Texture2D* backbuffer = nullptr;
  if (SUCCEEDED(g_swapchain->GetBuffer(0, __uuidof(ID3D11Texture2D), reinterpret_cast<void**>(&backbuffer)))) {
    g_context->CopyResource(backbuffer, g_offscreen);
    backbuffer->Release();
  }

  g_swapchain->Present(1, 0);
}

void Shutdown() {
  g_ready = false;

  if (g_brushRight)    { g_brushRight->Release();    g_brushRight    = nullptr; }
  if (g_brushLeft)     { g_brushLeft->Release();      g_brushLeft     = nullptr; }
  if (g_brushFrame)    { g_brushFrame->Release();     g_brushFrame    = nullptr; }
  if (g_brushText)     { g_brushText->Release();      g_brushText     = nullptr; }
  if (g_textFormat)    { g_textFormat->Release();     g_textFormat    = nullptr; }
  if (g_dwriteFactory) { g_dwriteFactory->Release();  g_dwriteFactory = nullptr; }
  if (g_d2dRT)         { g_d2dRT->Release();          g_d2dRT         = nullptr; }
  if (g_d2dFactory)    { g_d2dFactory->Release();     g_d2dFactory    = nullptr; }
  if (g_offscreen)     { g_offscreen->Release();      g_offscreen     = nullptr; }
  if (g_swapchain)     { g_swapchain->Release();      g_swapchain     = nullptr; }
  if (g_context)       { g_context->Release();        g_context       = nullptr; }
  if (g_device)        { g_device->Release();         g_device        = nullptr; }

  if (g_hwnd) {
    DestroyWindow(g_hwnd);
    g_hwnd = nullptr;
  }

  g_channels.clear();
  g_labels.clear();
  g_ringWrite  = 0;
  g_ringFilled = 0;
}

bool IsForeground() {
  return g_hwnd != nullptr && GetForegroundWindow() == g_hwnd;
}

} // namespace sk_test
