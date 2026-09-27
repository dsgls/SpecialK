# Fork issues — upstreaming review findings

Findings from the 2026-07-22 review of `main@upstream..main` (XInput deadzone/curve
pipeline + build fixes), numbered for stable reference. Item 4 (commit messages
describing changes that don't exist) was fixed directly in that session by rewriting
the messages of `wrstuyopurly` and `pvpzlnzxoonu`, and is not listed. Line numbers
refer to the branch tip at review time.

Update 2026-09-27: `pvpzlnzxoonu` was rewritten to hold the complete XInput
pipeline (item 1 applied there; it now builds on its own) and `mvvzqwrsnswv` holds
only the GameInput/WGI half. Items 5, 6, 8, 13, 14, 15, 17, 18 and 19 were applied
in `pvpzlnzxoonu`; the valid deadzone range was tightened to 0-16384 at the same
time. Item 7 was found to be wrong and is withdrawn.

## Blockers

### 1. `#if 0` silently disables the shipped DeadzonePercent feature — resolved: (c), removed in full
`src/input/xinput_core.cpp:4061-4097`. The pipeline commit wraps the entire percent-
deadzone + log10 response logic in `#if 0` with `(void)` casts in the `#else`.
`Input.XInput / DeadzonePercent` defaults to 5.0 and upstream applies it to both the
native slot-0 path (xinput_core.cpp:556, 917) and the PlayStation HID→XInput report
(playstation.cpp:2658), so every existing user's default stick response changes
(5% deadzone and log boost gone; drift returns on worn pads). The INI key, its
ConfigEntry description, the Xbox-Mode slider (cfg_input.cpp:2343-2351), and the
`deadzone_percent` parameter all remain live-looking but inert.
Decision 2026-07-22: (c) — DeadzonePercent removed in full: the INI key, its
ConfigEntry description, the Xbox-Mode slider, the `deadzone_percent` parameter,
the `#if 0` block, and the dead `unit` variable are all gone. The shared
`SK_XInput_ShapeSticks` pipeline supersedes the feature; stacking DeadzonePercent's
own deadzone+log10 response on top of the pipeline's deadzone/curve stages would
make the combined response nonlinear.
The removal is behavior-visible for upstream users (the key ships with default
5.0), so the PR description must say so; see item 7 for why not the CHANGELOG.
Considered and rejected: (a) keep the legacy path active when the new pipeline is
neutral — still stacks two response curves on top of each other; (b) migrate
DeadzonePercent into the input deadzone on load — same nonlinearity concern.
Provenance (found 2026-07-22): the disable was deliberate — curves-design §1 cites
a since-squashed commit titled "Disable deadzone addition feature and hardcoded
non-configurable exp curve", whose rationale was lost in a history rewrite. That
pointed at (c), the option chosen.

### 2. vcxproj/toolset changes break upstream CI and VS 2022 contributors
`SpecialK.vcxproj` + `libSKinHook.vcxproj` + `DirectXTex_Desktop_2015.vcxproj` +
`libzma.vcxproj` (commit `swstmpswvynw`). All 24 configurations moved to `v145`
(VS 2026 only; upstream CI runs `windows-2022` = v143 → MSB8020 everywhere); the two
"Release (clang)" configs now build with MSVC while still defining `SK_BUILT_BY_CLANG`;
30 hardcoded `C:\Program Files (x86)\Windows Kits\10\...\10.0.26100.0\ucrt` include/lib
paths; 16 empty `<VCToolsVersion></VCToolsVersion>` husks; `$(IncludePath);$(IncludePath)`
duplicates, `;;` artifacts, and three elements that drop `%(AdditionalIncludeDirectories)`
inheritance. All projects already use floating `WindowsTargetPlatformVersion=10.0`, so
the SDK hardcoding was never the right fix.
**Remedy**: drop every vcxproj change from the upstream PR (keep locally if needed).

### 3. Personal/workflow files must not go upstream
`.gitattributes` (`* text=auto` on a mixed-EOL repo → renormalization churn for all
contributors; EOL policy is the maintainer's own decision), `CLAUDE.md` (machine-
specific; also states "Platform Toolset: v145 (VS 2022)" — v145 is VS 2026),
`build-claude.bat` (hardcoded VS 2026 path), `docs/superpowers/` (4 AI planning/spec
docs with agent instructions and jj commands; one spec describes a superseded design).
Note the docs ride inside the feature commit `wzuzomvsstnv`, so removing them requires
rewriting that commit, not just dropping one.

## Majors

### 5. Non-neutral pipeline circularizes diagonals — resolved: keep as intentional, commented
`src/input/xinput_core.cpp:3998, 4051`. `r = min(1, (u-c)/(1-c))` caps output
magnitude at 32767: square-gate corners (32767, 32767) (norm ≈ 46340) become
(23169, 23169), and real Xbox pads lose their ~5-20% diagonal calibration
overshoot. Decision 2026-07-22: keep this behavior — output is intentionally
normalized to the circular gate (removes per-pad calibration slop; only affects
per-axis readers in the overshoot band; radially-clamping games see no change).
Update 2026-09-27: `SK_XInput_ShapeStickOutput` carries the "deliberately
clamped" comment and the commit message states the behavior change. Remaining: the
PR description should repeat it. The local design docs contradict the decision
(curves-design §3.4 promises "extrapolate monotonically … preserving the diagonal";
pipeline-design line 170 calls the clamp "same diagonal handling as today", which
is false vs the old code). They stay out of the PR (item 3) but should be corrected
if kept.
Considered and rejected: ratio-preservation via `out01 / min(u, 1.0f)` (creates
a curve-dead raw tail with a slope kink at the circle — the old upstream code's
own artifact); curve extrapolation per curves-design §3.4 (viable and smooth,
but the clamp's simplicity and cross-pad consistency were preferred).

### 6. No validation of the new INI parameters; degenerate values peg the stick — resolved
`src/config.cpp:5577ff`, `src/input/xinput_core.cpp:3963-3981`.
`StickCurveSigmoidSteepness=0` → `lo == hi` → NaN → `std::min(1.0f, NaN)` returns
1.0f → full deflection for any input above c. Power ≤ 0 pegs output; Expo > 1 is
non-monotonic; `InputDeadzone ≥ 32767` → dead stick / div-by-zero on diagonals;
`DeadzoneElimination ≥ 32767` pegs everything. The safety comment at
xinput_core.cpp:3995-3997 is false: this ImGui fork only clamps Ctrl+Click entry
with `ImGuiSliderFlags_AlwaysClamp` (none of the new sliders pass it), and load
clamps nothing.
Resolution 2026-09-27: the valid ranges are `SK_Stick*_Min/Max` constants in
xinput.h. `SK_XInput_GetStickShaping` (the only reader) clamps every value,
`SK_XInput_SanitizeStickShapingConfig` writes the clamped values back to config
after INI load, and every slider passes `ImGuiSliderFlags_AlwaysClamp`. The
magnitude curve pins u >= 1 to 1, and Sigmoid steepness >= 1 keeps `hi > lo`. The
deadzone range is 0-16384 (`SK_StickDeadzone_Max`), half the raw range, because
finer slider control matters more than deadzones nobody needs.

### 7. No CHANGELOG entry or version bump — withdrawn
Checked 2026-09-27: none of the fifteen most recently merged upstream PRs (including
an eight-file config rename, #346) touched `CHANGELOG.txt` or `DLL_VERSION.H`. The
maintainer writes both himself, so the PR must not. The INI keys and the
DeadzonePercent removal go in the commit message and PR description instead.
Also noted: the maintainer leaves no written review on PRs; he merges or ignores.

## Minors

### 8. '≈' (U+2248) doesn't render in the UI font — resolved
`src/control_panel/cfg_input.cpp:1749, 1759`. `SK_ImGui_GetGlyphRangesDefaultEx`
(include/imgui/imgui_user.inl:43-54) omits Mathematical Operators, so the tooltip
glyph falls back to '?'. Em-dashes render but have no precedent in src/ string
literals. Resolution 2026-09-27: tooltip reads "Set it just above the game's own
deadzone"; slider labels are "Controller (Left)" etc.; no non-ASCII remains.

### 9. Slot scope vs preview truthfulness
Shaping applies only at post-remap `dwUserIndex == 0` (xinput_core.cpp:545, 906),
but the preview follows `ui_slot`, and with `auto_slot_assign` (xinput_core.cpp:
464-465) slot-0 reads are redirected before the gate, so shaping never applies while
the preview shows a curve. Extend to all slots, or state "player 1" in the UI and
make the preview poll slot 0.

### 10. PlayStation-emulation users get no live calibration dot
`SK_XInput_PollController` reads SK's private `XInput_SK64.dll` and only sees real
XInput devices; PS pads shaped via playstation.cpp:2658 draw no dot in the preview.
Fall back to the HID device's raw magnitude, or note the limitation.

### 11. Windows.Gaming.Input fallback delivers unshaped sticks — resolved: pipeline applied at all three sites
`src/input/windows.gaming.input.cpp:463-499, 649`: the background-render fallback
applies `SK_XInput_ApplyRemapping` but not the pipeline, so one game can see
different stick values from different APIs. Pre-existing pattern, much larger
divergence now.
Decision 2026-07-22: apply the pipeline everywhere WGI delivers a gamepad reading.
`SK_XInput_ShapeSticks` now runs at the native focused path
(windows.gaming.input.cpp:533) and at both XInput-fallback branches (:466, :669),
alongside the existing `SK_XInput_ApplyRemapping` call, so a game reading
Windows.Gaming.Input gets the same curve as XInput regardless of which of the
three paths services it. See item 24 (the GameInput half of this item) for the
slot rule and the cross-reference to item 9; that half's dispatch-hook
mechanism shapes GameInput identically whether `Input.XInput.EnableEmulation`
(Xbox Mode) is on or off.

### 24. Native GameInput bypasses the pipeline entirely — resolved: vtable hook shapes every native reading
(Numbered out of order to keep 1-23 stable; the GameInput half of item 11.)
`SK_IWrapGameInputReading::GetGamepadState` (`src/input/game_input.cpp:1546`)
forwards `pReal->GetGamepadState` unmodified apart from zeroing on
`SK_ImGui_WantGamepadCapture`, so a game reading an Xbox pad through GameInput gets
raw sticks — every curve/deadzone setting is inert, with no UI indication.

The PlayStation→GameInput path *is* shaped, but only incidentally:
`SK_IPlayStationGameInputReading::GetGamepadState` (game_input.cpp:2252) reads
`xinput.getLatestState()` (playstation.cpp:2904 → `prev_report`), and that report was
copied from `xinput.report` at playstation.cpp:2738 *after*
`SK_XInput_ApplyDeadzone` ran on it at :2658. Net effect: within one GameInput game,
a DualSense gets the configured curve and an Xbox pad does not. Same split in WGI
(item 11): the PS branch at windows.gaming.input.cpp:556-564 is shaped, while
:463-466 and :645-652 fill `xi_state` from `SK_XInput_PollController`, which reads
SK's private `XInput_SK64.dll` and so misses SK's own hooks (cf. item 10).

Upstream precedent argues for parity, not documentation: CHANGELOG 25.2.8.1
(line 3692) extended *Xbox analog stick remapping* to WGI and GameInput, and
`SK_XInput_ApplyRemapping` is duly called at game_input.cpp:2278 and
windows.gaming.input.cpp:466, 564, 652. `SK_XInput_ApplyDeadzone` is called at none
of them — only xinput_core.cpp:556, 917 and playstation.cpp:2658.
Decision 2026-07-22: shape at parity with XInput, everywhere. Every native
GameInput reading is shaped by a vtable hook on the real
`IGameInputReading::GetGamepadState` (game_input.cpp:220-238), installed exactly
once (guarded by `s_GameInputReadingHooked`, released and retried if hook
creation fails) via a shared helper, `SK_GameInput_InstallReadingHook`
(:243-262). Update 2026-07-23: the install call sits on the real `IGameInput` itself,
independent of `SK_IWrapGameInput` and of Xbox Mode.
`SK_GameInput_InstallDispatchHooks` (:434-477) hooks five vtable slots on that
real object — `GetCurrentReading`, `GetNextReading`, `GetPreviousReading`,
`GetTemporalReading`, and `RegisterReadingCallback` (indices 4-8) — called from
both `GameInputCreate_Detour` (:1091-1139) and `GameInputCreate_Redist_Detour`
(:1141-1189) on the object each hands back, ahead of the `xinput.emulate` check
that decides whether to build the Xbox Mode wrapper; `SK_GameInput_IsOwnVFTable`
(:430-442) stops the Xbox Mode inner (redist) detour's wrapper object from being
hooked when it reaches the outer detour. Shaping and capture-zeroing apply the
same whether `Input.XInput.EnableEmulation` (Xbox Mode) is on or off.
`RegisterReadingCallback`'s own override (:371-405) interposes a thunk,
`SK_GameInput_ReadingCallbackThunk` (:354-366), that runs the same
`SK_GameInput_InstallReadingHook` call before forwarding to the game's callback,
so a title that acquires readings *exclusively* via callbacks is shaped from its
first delivered reading — item 25's reading-callback test verifies this. The
`GameInputCreate` export itself is hooked before a title can call it, too:
`SK_Input_HookGameInput` (:2098-2159) hooks inline when the module is already
loaded, and the `LoadLibrary` trace (`src/diagnostics/load_library.cpp:520,523`)
hooks it as soon as a title loads the DLL dynamically.
Update 2026-07-23: two timing gaps made that arming miss in practice; both are
closed in game_input.cpp. (a) Queued-enable race: `SK_CreateDLLHook2` /
`SK_CreateVFTableHook2` only queue enables, and `SK_ApplyQueuedHooks` is a
silent no-op while the global apply flag is off during early init — a hook
created synchronously inside the title's `LoadLibraryW` still missed the
one-shot `GameInputCreate` call microseconds later. `SK_GameInput_HookCreate`
(:2014) and the `GI_VIRTUAL_HOOK` macro (:51) call `SK_EnableHook` directly
after creation. (b) Late attach: global injection attaches around window
creation, after a top-of-main `GameInputCreate` — an export hook armed then can
never fire. `SK_GameInput_HookExistingInstance` (:2046, called at :2112 and
:2120) acquires SK's own instance of the process-wide singleton via the create
trampoline on a worker thread, installs the dispatch vtable hooks (code patches
shared by the title's existing object), and self-polls `GetCurrentReading`
until a reading arrives to install the `GetGamepadState` shaping hook —
covering callback-only titles whose `RegisterReadingCallback` predates SK.
Verified 2026-07-23: item 25's poll and callback tests shaped under both local
(dxgi.dll wrapper) and global (SKIF) injection.
`SK_IWrapGameInputReading::GetGamepadState` (:1837) stays a pure forwarder to
`pReal->GetGamepadState`, which lands in the hooked vtable slot, so Xbox Mode
does not re-shape on top of it; the PlayStation virtual reading never touches
that vtable (it is returned directly, bypassing `pReal->GetCurrentReading`), so
it stays shaped exactly once via the pre-existing xinput.report path above — no
double shaping on either branch.
Virtual-device guards: every `SK_IWrapGameInput` path that could hand SK-owned
objects to the real implementation answers for the virtual device itself —
`GetPreviousReading` (:891) and non-gamepad `GetNextReading` kinds (:760) return
`GAMEINPUT_E_READING_NOT_FOUND` (the emulation keeps no reading history),
`GetTemporalReading` (:984) returns the static virtual reading like
`GetCurrentReading`, and the four `Register*Callback` methods (:1013, :1039,
:1069, :1088) substitute `device = nullptr` so the title holds a real token
that `StopCallback`/`UnregisterCallback` accept. Game-supplied reference
readings are sanitized the same way before every forward
(`SK_GameInput_SanitizeReferenceReading`, :647-675, applied at :810 ahead of
both `GetNextReading` forwards and at :900 ahead of both `GetPreviousReading`
forwards): SK's PlayStation virtual reading answers
`GAMEINPUT_E_READING_NOT_FOUND`, and an `SK_IWrapGameInputReading` is
unwrapped to its inner real reading so Xbox Mode's reading chain keeps
forwarding.
Slot rule: GameInput and WGI have no XInput slot concept, so every gamepad
reading is shaped there, unlike XInput's post-remap `dwUserIndex == 0` gate. Item
9 (XInput slot scope) stays open; if XInput remains slot-0-only by design, that's
the documented asymmetry between the APIs.
Single-implementation caveat: retired. A vtable-ownership probe (design spec
§2) found `GameInput.dll` is a pass-through handing back `GameInputRedist.dll`'s
own object unwrapped, so there is exactly one implementation reachable two
ways — the single static trampoline (`IGameInputReading_GetGamepadState_Original`)
covers it, and both `GameInputCreate` detours seeing the same object is harmless.

### 25. Test programs per read path, plus a raw-linearity sweep
No standalone verification exists per code path. Build small test programs
exercising: XInput native; GameInput's `GetCurrentReading`, `GetNextReading`, and
reading callbacks; WGI's focused native path; WGI's background fallback; and the
PS-emulated variant of each. Verify the curve applies exactly once (no stacking)
and that capture-zeroing still works. Add a raw-linearity sweep: with SK's shaping
set neutral, sweep the stick slowly and log values to confirm the API itself
injects no hidden deadzone/curve — GameInput is the case to watch, since per GDK
guidance deadzone processing is the app's responsibility, but `GameInput.dll`'s
internals are unverifiable from source and its gamepad mapping for non-Xbox pads
could differ. Cover both `GameInput.dll` and `GameInputRedist.dll` in the test
matrix if possible.

### 26. GameInput rumble hooks are wrapper-only, so inert outside Xbox Mode
The `IGameInputDevice::SetHapticMotorState` / `SetRumbleState` vtable hooks
(indices 9/10) install only from `SK_IWrapGameInput::GetNextReading`
(game_input.cpp:657-673), so with Xbox Mode off (`EnableEmulation=false`) native
GameInput titles get no rumble interception — `disable_rumble` and capture-time
rumble suppression do nothing there. Natural fix path: the `IGameInput` dispatch
overrides already receive an `IGameInputDevice *`, so an install site
independent of the wrapper exists for a follow-up spec. Open follow-up; not
addressed by the wrapper-free shaping change.

### 27. Stick remapping is not applied to native GameInput readings
`IGameInputReading_GetGamepadState_Override` (game_input.cpp:229) applies
`SK_XInput_ShapeSticks` only; `SK_XInput_ApplyRemapping` (stick swap / axis
inversion) never runs on native GameInput readings, while Xbox Mode's
PlayStation virtual reading applies it
(`SK_IPlayStationGameInputReading::GetGamepadState`, :2485). Invisible while
swap/invert are off; wrong axes once a user enables them for a native GameInput
title. Natural fix site: the override already holds the four float stick
values, but `SK_XInput_ApplyRemapping` takes an `XINPUT_STATE`, so it needs a
float variant or a SHORT round-trip. Open follow-up, same class as item 26.

### 12. Swap Sticks runs after the pipeline
Per-stick shaping (xinput_core.cpp:4100-4101) precedes `SK_XInput_ApplyRemapping`'s
`std::swap`, so "Left Stick" settings govern the game-facing right stick when
swapped. Document, or remap before shaping.

### 13. INI key naming mixes conventions — resolved
`InputDeadzoneL/R` + `DeadzoneEliminationL/R` vs `StickCurveLeft/Right` +
30-char `StickCurveSigmoidSteepnessLeft` within one feature; section style is terse
(`InvertLX`, `UISlot`). Resolution 2026-09-27: every key ends in `Left`/`Right`
(`InputDeadzoneLeft`, `DeadzoneEliminationLeft`, `StickCurveLeft`, ...).

### 14. Curve defaults duplicated — resolved
`SK_StickCurve` NSDMIs (include/SpecialK/input/xinput.h) mirror config.h defaults
but are never load-bearing (`SK_XInput_GetStickCurve` fully populates).
Resolution 2026-09-27: the struct is now `SK_StickShaping` (deadzones included,
normalized), a plain aggregate with no initializers; config.h is the only place
defaults live.

### 15. Sigmoid Steepness/Midpoint sliders lack tooltips — resolved
`src/control_panel/cfg_input.cpp:1896-1897`; every other new control has one.
Resolution 2026-09-27: added.

### 16. Orphaned `#pragma warning(suppress : 4996)` in injection.cpp — resolved
Three inserted comment lines separated the pragma from the code it suppresses.
The pragma itself is upstream's (present on `main@upstream`) and dead there too,
since `_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS` is defined in all configs; removing
it is upstream's cleanup, not this PR's. Resolution 2026-09-27: our comment moved
above the `imbue` call, so upstream's pragma stays adjacent to its statement.

## Nits

### 17. config.cpp column alignment broken by the four new wiring blocks — resolved
Parameter declarations, ConfigEntry table, load and store lists all drift from the
file's strict alignment. Resolution 2026-09-27: the declarations fit the existing
20/24 columns (using the file's `sk::` line-break trick for `ParameterStringW`).
The names are too long for the ConfigEntry, load and store columns, so those three
blocks are aligned as islands, matching the precedent of other overlong entries.

### 18. `static_cast<float>(X)` without SK's spaces — resolved: moot, block deleted by item 1
xinput_core.cpp:4085-4086 (inside the `#if 0` block; moot if the block is deleted
per item 1). House style is `static_cast <float> (X)`.

### 19. xinput.h newcomers break the header's conventions — resolved
Return type not on its own line for the three new functions; `SK_StickCurve::type`
is `int` rather than `SK_StickCurveType`; `SK_XInput_GetStickCurve (int stick)`
takes a 0/1 magic argument. Resolution 2026-09-27: return types on their own line,
`SK_StickShaping::curve` is `SK_StickCurveType`, and the stick is an `SK_Stick`
enum (`SK_Stick_Left`/`SK_Stick_Right`). The INI string helpers moved from
config.cpp to xinput_core.cpp next to the rest of the pipeline.

### 20. Stale "post-elimination" wording — resolved: moot, block deleted by item 1
xinput_core.cpp:4093-4094 no longer exists: item 1's resolution deleted the
entire `#if 0`/`#else` DeadzonePercent block wholesale, taking the stale
"elimination" wording with it. Nothing left to reword.

### 21. Full deflection −32768 becomes −32767 when the pipeline is active
`out01 ≤ 1` caps magnitude at 32767; the old path could reach −32768. One count,
imperceptible; note only.

## Pre-existing upstream bug (not from this branch)

### 22. playstation.cpp clamps the right stick with the left stick's signs
`src/input/hid_reports/playstation.cpp:2630, 2633`: `sThumbRX/RY` branch on
`uLX < 0` / `uLY < 0`, zeroing right-stick axes whenever the corresponding left
axis has the opposite sign. Verified in the tree. Candidate separate upstream
report/fix.

## Umbrella

### 23. Restructure the branch into an upstream PR
Current shape (2026-09-27): (1) build fix `wrstuyopurly`;
(2) XInput pipeline `pvpzlnzxoonu`, self-contained and building on its own, with
the settings and the DeadzonePercent removal in its message; (3) GameInput/WGI
`mvvzqwrsnswv`, which depends on (2). Whether (3) ships in the same PR is open:
it is large and carries items 26/27 as known gaps. Drop everything in items 2-3.
The PR description must state the DeadzonePercent behavior change (items 1, 5).
