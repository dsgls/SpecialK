# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Special K is a PC gaming enhancement framework that acts as a DLL injection payload. It intercepts and modifies graphics APIs, input systems, and other game functionality to fix issues and add features. The project outputs `SpecialK32.dll` and `SpecialK64.dll` which can be injected into games via proxy DLL wrapping or global Win32 hooks.

**Key Characteristics:**
- Designed to produce debuggable Release builds (Debug configuration may not compile correctly)
- Requires Visual C++ 2022 or newer (uses modern C++ language features)
- Minimum supported OS: Windows 8.1 (Windows 7 support is feature-reduced as of 23.5.7)
- All build dependencies are included in the repository (no external SDK required for versions 23.5.7+)
- Works with WINE when configured with `UsingWINE=true` in per-game INI files

## Build Commands

### Building the Project

Build 64-bit version:
```batch
buildx64.bat
```
Or directly:
```batch
msbuild SpecialK.sln -t:Rebuild -p:Configuration=Release -p:Platform=x64 -m
```

Build 32-bit version:
```batch
buildx86.bat
```
Or directly:
```batch
msbuild SpecialK.sln -t:Rebuild -p:Configuration=Release -p:Platform=Win32 -m
```

However, these build commands depend on environment setup. Instead use this to build the 64-bit version with the correct environment:
```batch
build-claude.bat
```

**Build Output Location:** `~\Documents\My Mods\SpecialK\SpecialK*.dll`

The build scripts integrate with SKIF (Special K Injection Frontend) if available, automatically stopping and restarting the build agent process during compilation.

## Code Architecture

### Injection Mechanism

Special K uses two primary injection methods:

1. **Local Injection (Proxy/Wrapper DLL)**: Rename the DLL to match a system DLL (dxgi.dll, d3d11.dll, d3d9.dll, etc.) and load via static imports or LoadLibrary calls
2. **Global Injection (Win32 Hooks)**: Uses CBT/Shell hooks to inject before swapchain creation, bootstrapped via `RunDLL_InjectionManager` with rundll32.exe

CBT hooks are used specifically because they execute before graphics API initialization, allowing Special K to intercept D3D9/11/12 swapchain creation.

### Source Organization

**Core Systems** (`src/`):
- `core.cpp` - Initialization, backend management, path handling
- `hooks.cpp` - MinHook-based function hooking infrastructure using cache records
- `config.cpp` - INI configuration system
- `command.cpp` - Command interpreter
- `framerate.cpp` - Frame pacing and timing control
- `import.cpp` - Dynamic import resolution

**Rendering Backends** (`src/render/`, `include/SpecialK/render/`):
- `render_backend.cpp` - Abstract render backend interface
- `d3d9/`, `d3d11/`, `d3d12/` - Direct3D API interception
- `dxgi/` - DXGI swapchain management
- `gl/` - OpenGL support
- `vulkan/` - Vulkan support
- `ddraw/`, `d3d8/` - Legacy API support
- `ngx/` - NVIDIA NGX integration
- `reflex/` - NVIDIA Reflex support
- `streamline/` - NVIDIA Streamline
- `dstorage/` - DirectStorage API

**Input Systems** (`src/input/`, `include/SpecialK/input/`):
- `input.cpp` - Core input management
- `xinput_core.cpp`, `xinput_hotplug.cpp` - XInput interception
- `dinput7.cpp`, `dinput8.cpp` - DirectInput hooks
- `raw_input.cpp` - RawInput API interception
- `hid.cpp` - HID device management
- `game_input.cpp` - GameInput API support
- `windows.gaming.input.cpp` - Windows.Gaming.Input
- `keyboard.cpp`, `cursor.cpp` - Keyboard and mouse handling

**Control Panel/UI** (`src/control_panel/`, `include/SpecialK/control_panel/`):
- `control_panel.cpp` - Main ImGui-based interface
- ImGui backends for D3D9/11/12, OpenGL, Vulkan

**Storefront Integration** (`src/storefront/`):
- `achievements.cpp` - Achievement system abstraction
- `epic.cpp` - Epic Games Store integration (EOS SDK)
- `gog.cpp` - GOG Galaxy integration
- `xbox.cpp` - Xbox platform integration

**Performance & Diagnostics** (`src/diagnostics/`, `src/performance/`):
- CPU/memory monitoring, crash handling, module tracking
- Performance analysis and correction

### Hook Management System

Special K uses a hook caching system defined in `include/SpecialK/hooks.h`:

- `sk_hook_cache_record_s` - Stores target address, detour, trampoline, and state
- `SK_HookCacheEntry` macro - Declares hook records
- `SK_HookCacheEntryGlobal` / `SK_HookCacheEntryLocal` - Global vs per-DLL hooks
- Hooks persist target addresses in INI files for performance (address prediction)

### Dependencies

**Included Libraries** (`depends/`):
- MinHook - Low-level API hooking
- DirectXTex - Texture processing
- ImGui - UI framework
- Boost - Container utilities (static_vector, intrusive containers)
- NVAPI, ADL - GPU vendor APIs
- EOS SDK - Epic Online Services
- ReShade API - Graphics mod interop
- libzma - LZMA compression
- Various vendor SDKs (Mono, il2cpp, Vulkan, etc.)

**Custom Derivative** (`depends/derivative/SKinHook/`):
- Modified MinHook variant specific to Special K

### Configuration System

- INI-based configuration via `iSK_INI` interface (`ini.cpp`, `config.cpp`)
- Per-game configuration stored in `SpecialK.ini` in game directory
- Global configuration in Special K install directory
- Settings include render options, input blocking, storefront integration, etc.

### Platform & Compiler Settings

- Platform Toolset: v145 (VS 2022)
- Character Set: Unicode
- Whole Program Optimization: Enabled (Release builds)
- Uses aggressive optimization pragmas in `stdafx.h` for Release builds
- Code indentation: 2 spaces (see `.editorconfig`)

## Development Notes

### Working with Graphics APIs

When modifying render backends, understand that Special K intercepts at multiple levels:
- Swapchain creation and presentation
- Device creation and reset
- Resource creation and binding
- Command list recording (D3D12)
- Shader compilation and execution

Changes to one backend often require corresponding changes in others for feature parity.

### Hook Installation Pattern

Hooks follow a standard pattern:
1. Declare global hook cache entry
2. Create local hook if targeting specific DLL
3. Use `SK_Hook_PredictTarget` to load cached address from INI
4. Install hook via MinHook API
5. Store trampoline pointer for calling original function

### Input Blocking

Special K can selectively block input APIs from seeing devices (e.g., `HideRawInput` setting). When working on input code, be aware of multiple interception layers and blocking mechanisms that affect what the game sees.

### Thread Safety

The codebase uses volatile LONG for atomic flags and extensive critical sections. Be cautious when modifying initialization sequences or hook installation code as threading issues can cause crashes or deadlocks.

### Shader and Texture Modding

The render backends support runtime shader interception and texture replacement. Changes to resource tracking must account for dumping and injection workflows used by shader/texture modders.

## Version Management

Version information is tracked in `CHANGELOG.txt`. The changelog uses semantic versioning (major.minor.patch.revision) and documents all user-facing changes.

Build artifacts include product version metadata that gets embedded in the DLL and used for update checking.

## CI/CD

GitHub Actions workflow (`.github/workflows/build-windows.yml`):
- Builds both x86 and x64 configurations
- Uploads DLL artifacts and debug symbols (.pdb)
- Artifact naming includes version and git SHA
- Uses `SpecialKO/GA-setup-cpp-n20` for build environment setup

## Other notes

Don't call git directly. You are running under WSL, and the repository is checked out on the windows side. To avoid issues with line endings, call git through cmd.exe.
