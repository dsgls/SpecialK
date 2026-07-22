# Input read-path test programs

Four throwaway diagnostic executables that verify Special K's stick-shaping
pipeline (`SK_XInput_ShapeSticks`) is applied exactly once -- no stacking, no
gaps -- across every read path a game can use to get a gamepad reading, plus
a raw-linearity sweep confirming the underlying API injects no hidden
deadzone/curve of its own. Not part of `SpecialK.sln`; build with
`build.bat`, not MSBuild.

Verification here is **visual**: the operator eyeballs each program's
numeric readout and magnitude-vs-time graph against SK's own ImGui stick
readout, side by side. There is no programmatic ground truth, no CSV
logging, no automation.

## Programs

| Program                    | API under test                                     | Expected result |
|-----------------------------|-----------------------------------------------------|------------------|
| `xinput_test`               | `XInputGetState` on `XInput1_4.dll`                  | sticks shaped |
| `gameinput_poll_test`       | `GetCurrentReading` + next + previous + temporal     | all four channels shaped and agreeing |
| `gameinput_callback_test`   | `RegisterReadingCallback` only (kept pure)           | sticks shaped |
| `wgi_test`                  | `Gamepad::GetCurrentReading`, focused + background   | sticks shaped |

Notes on what is and isn't a separate binary:
- **PlayStation-emulated input** is not a separate build -- run the same
  four programs with a DualSense connected instead of an Xbox pad.
- **WGI focused vs. background** is one binary (`wgi_test`); which path runs
  is selected at runtime by the window's focus state.
- **`GameInput.dll` vs `GameInputRedist.dll`** is a command-line switch on
  the two GameInput programs (`argv[1] == "redist"` selects the redist
  DLL), not extra binaries -- see "Running" below.

Shared rendering code lives in `common/sk_test_harness.{h,cpp}`. It is
input-free by design (never includes `XInput.h`, `GameInput.h`, or any
WinRT/Windows.Gaming.Input header, never reads a gamepad itself) so that
each program's input-hook coverage stays isolated to its own code; callers
normalize samples into `sk_test::StickSample` and `Submit()` them, the
harness only draws.

## Building

```
test_programs\build.bat
```

Run it from a shell with the toolchain available or just double-click it --
it calls `vcvars64.bat` itself (VS2022+/`VC\Auxiliary\Build\vcvars64.bat`
for x64). All four `.exe`s land flat in `test_programs\`, next to the
`.cpp` files. `build.bat` prints a per-program OK/FAIL/SKIP line and an
overall pass/fail at the end; a non-zero exit means at least one program
did not build.

Three programs compile at `/std:c++17`; `wgi_test` compiles at
**`/std:c++20`** -- C++/WinRT's generated headers need `<coroutine>`, and
under c++17 this toolchain falls back to the removed
`<experimental/coroutine>` and hard-errors. The deviation is scoped to
`wgi_test`'s own build step.

`build.bat` probes the SDK include path for `GameInput.h` before attempting
`gameinput_poll_test` / `gameinput_callback_test`, and skips those two with
a loud warning (instead of a wall of missing-header compiler errors) if an
older SDK without it is active; `xinput_test` and `wgi_test` still build.

## Running

Each program is a standalone `.exe`, no arguments needed except for the two
GameInput programs:

```
xinput_test.exe
gameinput_poll_test.exe            REM GameInput.dll (system)
gameinput_poll_test.exe redist     REM GameInputRedist.dll
gameinput_callback_test.exe        REM GameInput.dll (system)
gameinput_callback_test.exe redist REM GameInputRedist.dll
wgi_test.exe
```

Each opens a borderless-fullscreen D3D11/Direct2D window at the primary
monitor's native resolution, showing one numeric block per channel (sticks,
triggers, magnitude, sequence number) and a ~5 s magnitude-vs-time graph for
channel 0 in a left-hand column; the readout scales with resolution so it
stays readable, leaving the rest of the screen for SK's ImGui overlay. Press
**Esc** to quit. Rendering runs at native resolution (no Windows post-scaling)
and continues while the window is unfocused, which the WGI background
procedure below needs.

Both GameInput programs enumerate a gamepad via a blocking
`RegisterDeviceCallback` call right after `GameInputCreate`, before the window
even opens; with no controller connected they show "no reading / no device"
for their whole run rather than polling a null device.

## Injecting Special K

These programs create their own D3D11 device/swapchain, so SK's normal
swapchain-hook attach path works. SK resolves its role from the loaded DLL's
filename (`src/SpecialK.cpp:1125`) and calls `SK_Input_Init` at DLL attach.
XInput's hook is armed on a worker thread spawned there
(`src/input/xinput_core.cpp:3547`), typically not scheduled until tens of
milliseconds after `main()` has already started -- harmless for a per-frame
API, since a hook that lands late still catches the next `XInputGetState`
call.

`GameInputCreate` is called exactly once, at startup, so a late hook could
never take effect for the rest of the run -- unlike XInput, there is no next
call to catch. `SK_Input_Init` closes that gap by calling
`SK_Input_HookGameInput` (`src/input/game_input.cpp:1900`) synchronously: it
hooks the `GameInputCreate` export inline, with no worker thread and no
scheduling delay, the moment the module is already loaded; the `LoadLibrary`
trace (`src/diagnostics/load_library.cpp:516,519`) does the same the instant a
title loads `GameInput.dll`/`GameInputRedist.dll` dynamically. Both GameInput
programs acquire `IGameInput` at the very top of `main()`, before creating a
window -- the earliest a title can call `GameInputCreate` -- which is
deliberately the race this hook-arming design must survive.

To arm SK against a test program (manual step -- this reaches into your own
build output, so it isn't automated by `build.bat`):

1. Build SK (`build-claude.bat` or the normal build scripts).
2. Copy the freshly built `SpecialK64.dll` next to the test `.exe`s and
   rename the copy to `dxgi.dll`.
3. Launch the test `.exe`. SK takes `DLL_ROLE::DXGI` and hooks input
   immediately; once the program creates its D3D11 device, SK's control
   panel (Insert key by default) becomes available for the side-by-side
   comparison.

Optional `SpecialK.ini` beside the exes: to exercise the WGI background
procedure, enable background rendering by setting, under `[Window.System]`:

```
RenderInBackground=true
```

(This is the "Continue Rendering" checkbox under Window Management in SK's
control panel -- setting it directly in the INI avoids needing focus to
reach the checkbox first.)

## Manual verification procedure

For each program: inject SK (copy `dxgi.dll` as above), run it, and check:

**SK actually intercepted the API.** For the GameInput programs, confirm
`SpecialK.log` contains `First Call: GameInputCreate_Detour`. Without it, SK
never saw GameInput at all and every other result below is meaningless --
raw sticks would mean "not hooked", not "not shaped".

**Shape-applied-once / no stacking.** Move the stick; each program's values
should match SK's own ImGui stick readout -- same deadzone edge, same
curve. For `gameinput_poll_test`, all four columns (current/next/previous/
temporal) should agree with each other and with SK's readout.
`gameinput_callback_test` should agree too: the reading-vtable hook shapes
every acquisition path alike, callback included, so there is no raw/linear
case left to expect there.

**Capture-zeroing** (`SK_ImGui_WantGamepadCapture`). Open SK's control
panel and give it gamepad focus; every hooked path's readout, including
`gameinput_callback_test`'s, should drop to zero -- the reading-vtable hook
zeroes the whole `GameInputGamepadState` regardless of acquisition path.

**WGI background fallback** (`wgi_test` only). Enable `RenderInBackground`
(above), alt-tab away so the window loses focus, and confirm the readout
keeps updating -- via SK's XInput fallback -- and stays shaped.

**`GameInput.dll` vs `GameInputRedist.dll`.** Run each GameInput program
once per DLL (the `redist` argv switch); both runs should come up
shaped/hooked identically. A vtable-ownership probe found `GameInput.dll` is
a pass-through: it forwards `GameInputCreate` to `GameInputRedist.dll` and
hands back the redist object unwrapped, so both DLL choices resolve to the
same `IGameInput` vtable and the same installed hook -- there is one
implementation on this system, reachable two ways, not two independent ones.

**Raw-linearity sweep.** Set SK's own shaping to neutral (no deadzone,
linear/unity curve) and slowly sweep the stick corner-to-center. The graph
should be a straight, deadzone-free ramp with linear values -- confirming
the underlying API injects no hidden deadzone or curve of its own. Run this
on `xinput_test`, `gameinput_poll_test`, and `wgi_test`. GameInput is the
one worth the closest look: per the GDK, deadzone shaping is documented as
the application's responsibility, but `GameInput.dll`'s internals aren't
verifiable from source, so this sweep is the only check available.

## Known limitations

- Visual verification only -- no numeric ground truth, no automated
  pass/fail.
- `gameinput_poll_test` proves shaping-once per *delivery path*
  (current/next/previous/temporal), not per-*install-site* isolation: the
  next-reading walker's seed and the previous/temporal references all
  derive from `GetCurrentReading`. Fork-issues item 24's code review
  already establishes the shared install helper and that the four hook
  install sites are byte-identical calls, so this program does not need to
  re-prove that.
- PlayStation-emulated coverage depends on having a DualSense to plug in --
  there is no synthetic pad substitute.
- **Gamepad kind only.** A title reading the same pad through
  `GetControllerAxisState` or `GetRawReport` gets neither shaping nor
  capture-zeroing; none of these programs exercise those kinds.
- **First-acquisition-frame.** Capture-zeroing needs the reading-vtable hook
  installed, which needs one reading already acquired; a title in capture
  during its very first `IGameInputReading` acquisition sees one unzeroed
  frame.
