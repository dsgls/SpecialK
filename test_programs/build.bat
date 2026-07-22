@echo off
setlocal EnableExtensions
REM Builds the four input read-path diagnostic programs under test_programs\.
REM Not part of SpecialK.sln -- these are throwaway verification tools, not
REM shipped product; see README.md for what they check and how to run them.
REM
REM Each program is its own translation unit compiled together with the
REM shared common\sk_test_harness.cpp and linked to its own .exe, dropped
REM flat in this directory (test_programs\, alongside the .cpp files).

cd /d "%~dp0"

echo [build.bat] Setting up the VC++ x64 toolchain...
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"

where cl.exe >nul 2>nul
if errorlevel 1 (
  echo [build.bat] ERROR: cl.exe not on PATH after vcvars64.bat -- toolchain setup failed.
  exit /b 1
)

set "COMMON_FLAGS=/nologo /std:c++17 /EHsc /O2 /DUNICODE /D_UNICODE /MD /W3"
set "COMMON_LIBS=d3d11.lib d2d1.lib dwrite.lib dxgi.lib"
set "HARNESS=common\sk_test_harness.cpp"

REM user32.lib is not listed above: common\sk_test_harness.cpp carries its own
REM #pragma comment(lib, "user32.lib"), so every program that links the
REM harness gets it without repeating it on each link line here.

set "OVERALL_RESULT=0"

REM --- Probe the SDK include path for GameInput.h up front. Split INCLUDE
REM (semicolon-separated) into quoted tokens and test each; older SDKs don't
REM carry the header, and the two GameInput programs cannot build without it.
set "GAMEINPUT_H_FOUND="
for %%I in ("%INCLUDE:;=" "%") do (
  if exist "%%~I\GameInput.h" set "GAMEINPUT_H_FOUND=1"
)

if not defined GAMEINPUT_H_FOUND (
  echo [build.bat] WARNING: GameInput.h not found anywhere on INCLUDE.
  echo [build.bat] WARNING: gameinput_poll_test and gameinput_callback_test will be SKIPPED.
  echo [build.bat] WARNING: install a Windows SDK that ships GameInput.h ^(10.0.22000+^) to build them.
)

echo.
echo ===== xinput_test =====
del /q xinput_test.exe 2>nul
cl %COMMON_FLAGS% xinput_test.cpp %HARNESS% /Fe:xinput_test.exe %COMMON_LIBS%
if errorlevel 1 (
  echo [build.bat] FAILED: xinput_test
  set "RESULT_XINPUT=FAIL"
  set "OVERALL_RESULT=1"
) else (
  echo [build.bat] OK: xinput_test.exe
  set "RESULT_XINPUT=OK"
)

echo.
echo ===== gameinput_poll_test =====
if not defined GAMEINPUT_H_FOUND (
  echo [build.bat] SKIPPED: GameInput.h absent.
  set "RESULT_GI_POLL=SKIP"
  set "OVERALL_RESULT=1"
) else (
  del /q gameinput_poll_test.exe 2>nul
  cl %COMMON_FLAGS% gameinput_poll_test.cpp %HARNESS% /Fe:gameinput_poll_test.exe %COMMON_LIBS%
  if errorlevel 1 (
    echo [build.bat] FAILED: gameinput_poll_test
    set "RESULT_GI_POLL=FAIL"
    set "OVERALL_RESULT=1"
  ) else (
    echo [build.bat] OK: gameinput_poll_test.exe
    set "RESULT_GI_POLL=OK"
  )
)

echo.
echo ===== gameinput_callback_test =====
if not defined GAMEINPUT_H_FOUND (
  echo [build.bat] SKIPPED: GameInput.h absent.
  set "RESULT_GI_CB=SKIP"
  set "OVERALL_RESULT=1"
) else (
  del /q gameinput_callback_test.exe 2>nul
  cl %COMMON_FLAGS% gameinput_callback_test.cpp %HARNESS% /Fe:gameinput_callback_test.exe %COMMON_LIBS%
  if errorlevel 1 (
    echo [build.bat] FAILED: gameinput_callback_test
    set "RESULT_GI_CB=FAIL"
    set "OVERALL_RESULT=1"
  ) else (
    echo [build.bat] OK: gameinput_callback_test.exe
    set "RESULT_GI_CB=OK"
  )
)

REM wgi_test needs /std:c++20 (not c++17): C++/WinRT's generated headers pull
REM in coroutine machinery, and under c++17 this toolchain falls back to the
REM removed <experimental/coroutine> and hard-errors. c++20 pulls the
REM standard <coroutine> header instead. Scoped to wgi_test only -- also
REM applies to the harness TU compiled alongside it in this one invocation,
REM but that does not change the harness for the other three builds above.
echo.
echo ===== wgi_test =====
del /q wgi_test.exe 2>nul
cl /nologo /std:c++20 /EHsc /O2 /DUNICODE /D_UNICODE /MD /W3 wgi_test.cpp %HARNESS% /Fe:wgi_test.exe %COMMON_LIBS% windowsapp.lib
if errorlevel 1 (
  echo [build.bat] FAILED: wgi_test
  set "RESULT_WGI=FAIL"
  set "OVERALL_RESULT=1"
) else (
  echo [build.bat] OK: wgi_test.exe
  set "RESULT_WGI=OK"
)

echo.
echo ================================================
echo  Build summary
echo ------------------------------------------------
echo  xinput_test                : %RESULT_XINPUT%
echo  gameinput_poll_test        : %RESULT_GI_POLL%
echo  gameinput_callback_test    : %RESULT_GI_CB%
echo  wgi_test                   : %RESULT_WGI%
echo ================================================

if "%OVERALL_RESULT%"=="0" (
  echo [build.bat] ALL BUILDS SUCCEEDED
) else (
  echo [build.bat] ONE OR MORE BUILDS FAILED OR WERE SKIPPED
)

exit /b %OVERALL_RESULT%
