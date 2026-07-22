# Fork issues — upstreaming review findings

Findings from the 2026-07-22 review of `main@upstream..main` (XInput deadzone/curve
pipeline + build fixes), numbered for stable reference. Item 4 (commit messages
describing changes that don't exist) was fixed directly in that session by rewriting
the messages of `wrstuyopurly` and `pvpzlnzxoonu`, and is not listed. Line numbers
refer to the branch tip at review time.

## Blockers

### 1. `#if 0` silently disables the shipped DeadzonePercent feature
`src/input/xinput_core.cpp:4061-4097`. The pipeline commit wraps the entire percent-
deadzone + log10 response logic in `#if 0` with `(void)` casts in the `#else`.
`Input.XInput / DeadzonePercent` defaults to 5.0 and upstream applies it to both the
native slot-0 path (xinput_core.cpp:556, 917) and the PlayStation HID→XInput report
(playstation.cpp:2658), so every existing user's default stick response changes
(5% deadzone and log boost gone; drift returns on worn pads). The INI key, its
ConfigEntry description, the Xbox-Mode slider (cfg_input.cpp:2343-2351), and the
`deadzone_percent` parameter all remain live-looking but inert.
**Decide explicitly**: (a) keep the legacy path active when the new pipeline is
neutral, (b) migrate DeadzonePercent into the input deadzone on load, or (c) remove
the setting/slider/parameter and document the removal. Delete the `#if 0` block and
the dead `unit` variable either way.
Provenance (found 2026-07-22): the disable was deliberate — curves-design §1 cites
a since-squashed commit titled "Disable deadzone addition feature and hardcoded
non-configurable exp curve", whose rationale was lost in a history rewrite. That
points at (c), but (a)/(b)/(c) remains an open choice.

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

### 5. Non-neutral pipeline circularizes diagonals — resolved: keep as intentional
`src/input/xinput_core.cpp:3998, 4051`. `r = min(1, (u-c)/(1-c))` caps output
magnitude at 32767: square-gate corners (32767, 32767) (norm ≈ 46340) become
(23169, 23169), and real Xbox pads lose their ~5-20% diagonal calibration
overshoot. Decision 2026-07-22: keep this behavior — output is intentionally
normalized to the circular gate (removes per-pad calibration slop; only affects
per-axis readers in the overshoot band; radially-clamping games see no change).
Remaining actions:
- Mention the behavior change vs upstream's DeadzonePercent path in the
  CHANGELOG entry / PR description (with item 7).
- Add a short code comment at the clamp stating the normalization is
  intentional, so upstream review doesn't read it as an oversight.
- The local design docs contradict the decision (curves-design §3.4 promises
  "extrapolate monotonically … preserving the diagonal"; pipeline-design line
  170 calls the clamp "same diagonal handling as today", which is false vs the
  old code). They stay out of the PR (item 3) but should be corrected if kept.
Considered and rejected: ratio-preservation via `out01 / min(u, 1.0f)` (creates
a curve-dead raw tail with a slope kink at the circle — the old upstream code's
own artifact); curve extrapolation per curves-design §3.4 (viable and smooth,
but the clamp's simplicity and cross-pad consistency were preferred).

### 6. No validation of the new INI parameters; degenerate values peg the stick
`src/config.cpp:5577ff`, `src/input/xinput_core.cpp:3963-3981`.
`StickCurveSigmoidSteepness=0` → `lo == hi` → NaN → `std::min(1.0f, NaN)` returns
1.0f → full deflection for any input above c. Power ≤ 0 pegs output; Expo > 1 is
non-monotonic; `InputDeadzone ≥ 32767` → dead stick / div-by-zero on diagonals;
`DeadzoneElimination ≥ 32767` pegs everything. The safety comment at
xinput_core.cpp:3995-3997 is false: this ImGui fork only clamps Ctrl+Click entry
with `ImGuiSliderFlags_AlwaysClamp` (none of the new sliders pass it), and load
clamps nothing.
**Remedy**: clamp at load (house precedent config.cpp:4900-4904, 5445), sanitize in
`SK_XInput_GetStickCurve` as choke point, clamp after sliders (precedent
cfg_input.cpp:2347-2348), fix the comment.

### 7. No CHANGELOG entry or version bump
Upstream pairs `CHANGELOG.txt` entries with `include/SpecialK/DLL_VERSION.H` bumps.
The feature adds 14 INI keys (plus the item-1 behavior decision) and documents none
of it. Add a proposed `+` entry in upstream's format; version number is Kaldaien's.

## Minors

### 8. '≈' (U+2248) doesn't render in the UI font
`src/control_panel/cfg_input.cpp:1749, 1759`. `SK_ImGui_GetGlyphRangesDefaultEx`
(include/imgui/imgui_user.inl:43-54) omits Mathematical Operators, so the tooltip
glyph falls back to '?'. Em-dashes render but have no precedent in src/ string
literals. Use "Set just above the game's…" (also more accurate).

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

### 11. Windows.Gaming.Input fallback delivers unshaped sticks
`src/input/windows.gaming.input.cpp:463-499, 649`: the background-render fallback
applies `SK_XInput_ApplyRemapping` but not the pipeline, so one game can see
different stick values from different APIs. Pre-existing pattern, much larger
divergence now. Apply the pipeline there too, or document.

### 24. Native GameInput bypasses the pipeline entirely
(Numbered out of order to keep 1-23 stable; the GameInput half of item 11.)
`SK_IWrapGameInputReading::GetGamepadState` (`src/input/game_input.cpp:1546`)
forwards `pReal->GetGamepadState` unmodified apart from zeroing on
`SK_ImGui_WantGamepadCapture`, so a game reading an Xbox pad through GameInput gets
raw sticks — every curve/deadzone setting is inert, with no UI indication.

The PlayStation→GameInput path *is* shaped, but only incidentally:
`SK_IPlayStationGameInputReading::GetGamepadState` (game_input.cpp:1941) reads
`xinput.getLatestState()` (playstation.cpp:2904 → `prev_report`), and that report was
copied from `xinput.report` at playstation.cpp:2738 *after*
`SK_XInput_ApplyDeadzone` ran on it at :2658. Net effect: within one GameInput game,
a DualSense gets the configured curve and an Xbox pad does not. Same split in WGI
(item 11): the PS branch at windows.gaming.input.cpp:556-564 is shaped, while
:463-466 and :645-652 fill `xi_state` from `SK_XInput_PollController`, which reads
SK's private `XInput_SK64.dll` and so misses SK's own hooks (cf. item 10).

Upstream precedent argues for parity, not documentation: CHANGELOG 25.2.8.1
(line 3692) extended *Xbox analog stick remapping* to WGI and GameInput, and
`SK_XInput_ApplyRemapping` is duly called at game_input.cpp:1964 and
windows.gaming.input.cpp:466, 564, 652. `SK_XInput_ApplyDeadzone` is called at none
of them — only xinput_core.cpp:556, 917 and playstation.cpp:2658.
**Remedy**: call the pipeline alongside `SK_XInput_ApplyRemapping` at those four
sites (watch the ordering trap in item 12, and don't double-shape the PS branches,
which arrive pre-shaped) — or scope the feature's UI/INI docs to XInput and say so.
Interacts with item 9: whatever slot rule is chosen there should hold here too.

### 12. Swap Sticks runs after the pipeline
Per-stick shaping (xinput_core.cpp:4100-4101) precedes `SK_XInput_ApplyRemapping`'s
`std::swap`, so "Left Stick" settings govern the game-facing right stick when
swapped. Document, or remap before shaping.

### 13. INI key naming mixes conventions
`InputDeadzoneL/R` + `DeadzoneEliminationL/R` vs `StickCurveLeft/Right` +
30-char `StickCurveSigmoidSteepnessLeft` within one feature; section style is terse
(`InvertLX`, `UISlot`). Pick one convention before the keys ship.

### 14. Curve defaults duplicated
`SK_StickCurve` NSDMIs (include/SpecialK/input/xinput.h) mirror config.h defaults
but are never load-bearing (`SK_XInput_GetStickCurve` fully populates). Drop the
struct initializers or single-source the constants.

### 15. Sigmoid Steepness/Midpoint sliders lack tooltips
`src/control_panel/cfg_input.cpp:1896-1897`; every other new control has one.

### 16. Orphaned, dead `#pragma warning(suppress : 4996)` in injection.cpp
Three inserted comment lines separate the pragma from the code; it targeted the
now-removed `locale::empty()` and is dead anyway (`_SILENCE_ALL_CXX17_DEPRECATION_
WARNINGS` is defined in all configs). Remove it when the commit is rewritten.

## Nits

### 17. config.cpp column alignment broken by the four new wiring blocks
Parameter declarations, ConfigEntry table, load and store lists all drift from the
file's strict alignment. Re-pad to surrounding columns.

### 18. `static_cast<float>(X)` without SK's spaces
xinput_core.cpp:4085-4086 (inside the `#if 0` block; moot if the block is deleted
per item 1). House style is `static_cast <float> (X)`.

### 19. xinput.h newcomers break the header's conventions
Return type not on its own line for the three new functions; `SK_StickCurve::type`
is `int` rather than `SK_StickCurveType`; `SK_XInput_GetStickCurve (int stick)`
takes a 0/1 magic argument.

### 20. Stale "post-elimination" wording
xinput_core.cpp:4093-4094 `#else` comment still uses the c2-era "elimination" name
for the unified pipeline. Reword when item 1 is resolved.

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

### 23. Restructure the branch into a 2-commit upstream PR
(1) build fix = injection.cpp only (item 16 applied), already re-described as
"Fix build with newer MSVC: replace non-Standard std::locale::empty()";
(2) feature = `pvpzlnzxoonu` + `wzuzomvsstnv` + `kutqovymkoql` squashed (the plan
doc notes intermediate commits don't build), message listing the settings as
implemented, items 1/5/6/7 resolved first. Drop everything in items 2-3.
