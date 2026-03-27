#!/usr/bin/env bash
# Build SpecialK (Release, Win32 + x64) from WSL and install the results.
#
# msbuild runs on the Windows side via cmd.exe, so every path handed to it is
# converted with wslpath. The x64 developer environment builds both platforms;
# msbuild picks the x86 cross-compiler from -p:Platform=Win32.

set -euo pipefail

REPO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="/mnt/c/apps/Special K"
TARGET="Rebuild"

usage () {
  cat <<'USAGE'
Usage: build.sh [-i|--incremental] [-d|--dest DIR]

  -i, --incremental  msbuild target Build instead of Rebuild
  -d, --dest DIR     install directory (default: /mnt/c/apps/Special K)
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -i|--incremental) TARGET="Build"; shift ;;
    -d|--dest)        DEST_DIR="${2:?--dest needs a directory}"; shift 2 ;;
    -h|--help)        usage; exit 0 ;;
    *)                echo "build.sh: unknown argument '$1'" >&2; usage >&2; exit 2 ;;
  esac
done

command -v cmd.exe  >/dev/null || { echo "build.sh: cmd.exe not on PATH; run this under WSL" >&2; exit 1; }
command -v wslpath  >/dev/null || { echo "build.sh: wslpath not found; run this under WSL" >&2; exit 1; }

# Strip the CR that cmd.exe appends to each line.
win_out () { cmd.exe /d /c "$@" 2>/dev/null | tr -d '\r'; }

VSWHERE="/mnt/c/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe"
[[ -x "$VSWHERE" ]] || { echo "build.sh: vswhere.exe not found; is Visual Studio installed?" >&2; exit 1; }

VS_PATH="$("$VSWHERE" -latest -property installationPath | tr -d '\r')"
[[ -n "$VS_PATH" ]] || { echo "build.sh: vswhere found no Visual Studio installation" >&2; exit 1; }

VCVARS="$VS_PATH\\VC\\Auxiliary\\Build\\vcvars64.bat"
[[ -f "$(wslpath -u "$VCVARS")" ]] || { echo "build.sh: missing $VCVARS" >&2; exit 1; }

REPO_WIN="$(wslpath -w "$REPO_DIR")"

# Windows-side temp dir: the generated batch file must live on a drive letter,
# because cmd.exe cannot use a \\wsl.localhost UNC path as its working directory.
WIN_TEMP="$(wslpath -u "$(win_out "echo %TEMP%")")"

# Quoting survives the WSL -> cmd.exe handoff far more reliably in a batch file
# than in a `cmd.exe /c "..."` one-liner, so each build gets one.
build () {
  local platform="$1"
  local bat; bat="$(mktemp "$WIN_TEMP/sk-build-XXXXXX.bat")"

  printf '@echo off\r\ncd /d "%s"\r\ncall "%s" || exit /b 1\r\nmsbuild SpecialK.sln -t:%s -p:Configuration=Release -p:Platform=%s -m\r\n' \
    "$REPO_WIN" "$VCVARS" "$TARGET" "$platform" > "$bat"

  echo "==> Building Release|$platform ($TARGET)"
  local rc=0
  cmd.exe /d /c "$(wslpath -w "$bat")" || rc=$?
  rm -f "$bat"
  return $rc
}

# SKIF keeps SpecialK*.dll/.pdb open, which makes the linker fail with LNK1201.
# It is stopped here and not restarted afterwards: start it yourself when the
# new DLLs should be injected.
# Discovery order follows buildx64.bat (env var, cached path, PATH), plus the
# path of an already-running SKIF — the common case, since SKIF is rarely on PATH.
skif_running_path () {
  powershell.exe -NoProfile -NonInteractive -Command \
    '(Get-Process SKIF -ErrorAction SilentlyContinue | Select-Object -First 1).Path' 2>/dev/null | tr -d '\r'
}

find_build_agent () {
  local candidate
  for candidate in "${SKIF_BUILDAGENT:-}" \
                   "$([[ -f "$REPO_DIR/SKIF.BuildAgent" ]] && head -n1 "$REPO_DIR/SKIF.BuildAgent" | tr -d '\r')" \
                   "$(win_out "where SKIF" | head -n1)" \
                   "$(skif_running_path)"; do
    [[ -n "$candidate" ]] || continue
    candidate="$(wslpath -u "$candidate" 2>/dev/null || echo "$candidate")"
    [[ -f "$candidate" ]] && { echo "$candidate"; return 0; }
  done
  return 1
}

BUILD_AGENT="$(find_build_agent || true)"
if [[ -n "$BUILD_AGENT" ]]; then
  echo "==> Stopping build agent: $BUILD_AGENT"
  # Launched detached, as buildx64.bat does — SKIF does not return promptly.
  agent_win="$(wslpath -w "$BUILD_AGENT")"
  cmd.exe /d /c start "" "$agent_win" Stop Quit >/dev/null 2>&1 || true
  # The agent exits asynchronously; give it a moment to release its file locks.
  for _ in {1..20}; do
    win_out tasklist | grep -qi '^SKIF\.exe' || break
    sleep 0.5
  done
fi

# SpecialK.vcxproj writes to $(USERPROFILE)\Documents\My Mods\SpecialK for Release.
OUT_DIR="$(wslpath -u "$(win_out "echo %USERPROFILE%")")/Documents/My Mods/SpecialK"

# A game running with Special K injected holds these open, and the linker only
# reports that as a bare LNK1201 half an hour into the build. Fail fast instead.
for f in "$OUT_DIR"/SpecialK{32,64}.{dll,pdb}; do
  [[ -e "$f" ]] || continue
  # Subshell: a failed redirection on `exec` would otherwise kill this script.
  ( exec 3>>"$f" ) 2>/dev/null ||
    { echo "build.sh: $f is locked — close SKIF and any game running Special K" >&2; exit 1; }
done

build Win32
build x64

mkdir -p "$DEST_DIR"
copied=0
for f in SpecialK32.dll SpecialK32.pdb SpecialK64.dll SpecialK64.pdb; do
  src="$OUT_DIR/$f"
  [[ -f "$src" ]] || { echo "build.sh: expected build output missing: $src" >&2; exit 1; }
  cp -- "$src" "$DEST_DIR/$f"
  copied=$((copied + 1))
done

echo "==> Copied $copied files to $DEST_DIR"
