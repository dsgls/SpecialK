/**
 * This file is part of Special K.
 *
 * Special K is free software : you can redistribute it
 * and/or modify it under the terms of the GNU General Public License
 * as published by The Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Special K is distributed in the hope that it will be useful,
 *
 * But WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Special K.
 *
 *   If not, see <http://www.gnu.org/licenses/>.
 *
**/

#include <SpecialK/stdafx.h>

#include "tools.h"

#include <psapi.h>
#include <shlwapi.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cmath>
#include <cstdlib>
#include <exception>
#include <limits>

using json = nlohmann::json;

#define SK_MCP_LOG_SRC L" MCP-Srv "


static std::string
SK_MCP_Lower (std::string str)
{
  std::transform ( str.cbegin (), str.cend (), str.begin (),
    [](unsigned char c) { return (char)std::tolower (c); } );

  return str;
}

std::string
SK_MCP_FormatAddress (uintptr_t addr)
{
  char szHex [32] = { };

  snprintf ( szHex, sizeof (szHex), "0x%llx",
               (unsigned long long)addr );

  return szHex;
}


std::vector <SK_MCP_Module>
SK_MCP_EnumModules (void)
{
  const HANDLE hProcess =
    GetCurrentProcess ();

  std::vector <HMODULE> mods (256);
  DWORD                 cbNeeded       = 0;
  size_t                capacity_bytes = mods.size () * sizeof (HMODULE);

  if (! EnumProcessModulesEx ( hProcess, mods.data (), (DWORD)capacity_bytes,
                                 &cbNeeded, LIST_MODULES_ALL ))
  {
    throw SK_MCP_ToolError { "EnumProcessModulesEx failed" };
  }

  if (cbNeeded > capacity_bytes)
  {
    mods.resize (cbNeeded / sizeof (HMODULE));

    capacity_bytes =
      mods.size () * sizeof (HMODULE);

    if (! EnumProcessModulesEx ( hProcess, mods.data (), (DWORD)capacity_bytes,
                                   &cbNeeded, LIST_MODULES_ALL ))
    {
      throw SK_MCP_ToolError { "EnumProcessModulesEx failed" };
    }
  }

  // A module loaded between the two calls leaves cbNeeded above the buffer.
  mods.resize (
    std::min <size_t> (cbNeeded, capacity_bytes) / sizeof (HMODULE)
  );

  std::vector <SK_MCP_Module> modules;
                              modules.reserve (mods.size ());

  for (auto hMod : mods)
  {
    MODULEINFO mod_info = { };

    if (! GetModuleInformation (hProcess, hMod, &mod_info, sizeof (mod_info)))
      continue;

    wchar_t wszPath [MAX_PATH + 1] = { };

    // 0 means the module unloaded between enumeration and this call.
    if (0 == GetModuleFileNameExW (hProcess, hMod, wszPath, MAX_PATH))
      continue;

    wchar_t wszName [MAX_PATH + 1] = { };
    wcsncpy_s      (wszName, wszPath, _TRUNCATE);
    PathStripPathW (wszName);

    modules.push_back ({
      hMod,
      (uintptr_t)mod_info.lpBaseOfDll,
      (size_t)   mod_info.SizeOfImage,
      SK_MCP_ToUTF8 (wszName),
      wszPath
    });
  }

  return modules;
}

std::optional <SK_MCP_Module>
SK_MCP_FindModule ( const std::string&                  name,
                    const std::vector <SK_MCP_Module>&  modules )
{
  const std::string wanted =
    SK_MCP_Lower (name);

  // The name with its extension wins; only then is the stem considered.
  for (const auto& mod : modules)
  {
    if (SK_MCP_Lower (mod.name) == wanted)
      return mod;
  }

  for (const auto& mod : modules)
  {
    std::string stem =
      SK_MCP_Lower (mod.name);

    const size_t dot =
      stem.rfind ('.');

    if (dot != std::string::npos)
      stem.resize (dot);

    if (stem == wanted)
      return mod;
  }

  return std::nullopt;
}

std::optional <SK_MCP_Module>
SK_MCP_FindModule (const std::string& name)
{
  return
    SK_MCP_FindModule (name, SK_MCP_EnumModules ());
}

const SK_MCP_Module*
SK_MCP_ModuleForAddress ( uintptr_t addr,
                          const std::vector <SK_MCP_Module>& modules )
{
  for (const auto& mod : modules)
  {
    if (addr >= mod.base && addr < mod.base + mod.size)
      return &mod;
  }

  return nullptr;
}

std::optional <SK_MCP_Module>
SK_MCP_ModuleForAddress (uintptr_t addr)
{
  const auto modules =
    SK_MCP_EnumModules ();

  const SK_MCP_Module* mod =
    SK_MCP_ModuleForAddress (addr, modules);

  if (mod == nullptr)
    return std::nullopt;

  return *mod;
}

json
SK_MCP_Symbolize ( uintptr_t addr,
                   const std::vector <SK_MCP_Module>& modules )
{
  const SK_MCP_Module* mod =
    SK_MCP_ModuleForAddress (addr, modules);

  if (mod == nullptr)
    return nullptr;

  char szOffset [32] = { };

  snprintf ( szOffset, sizeof (szOffset), "+0x%llx",
               (unsigned long long)(addr - mod->base) );

  return
    mod->name + szOffset;
}

json
SK_MCP_Symbolize (uintptr_t addr)
{
  return
    SK_MCP_Symbolize (addr, SK_MCP_EnumModules ());
}


// The digits of a bare or 0x-prefixed hex number, or nullopt.
static std::optional <uintptr_t>
SK_MCP_ParseHex (const std::string& text)
{
  size_t pos = 0;

  if ( text.length () > 2 && text [0] == '0' &&
       (text [1] == 'x' || text [1] == 'X') )
  {
    pos = 2;
  }

  if (pos >= text.length ())
    return std::nullopt;

  uintptr_t value = 0;

  for (; pos < text.length (); ++pos)
  {
    const unsigned char c = (unsigned char)text [pos];

    int digit;

    if      (c >= '0' && c <= '9') digit = c - '0';
    else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
    else
      return std::nullopt;

    // Anything wider than a pointer cannot name an address in this process.
    if (value > (std::numeric_limits <uintptr_t>::max () >> 4))
      return std::nullopt;

    value = (value << 4) | (uintptr_t)digit;
  }

  return value;
}

static std::string
SK_MCP_Trim (const std::string& text)
{
  size_t first = text.find_first_not_of (" \t\r\n");

  if (first == std::string::npos)
    return "";

  const size_t last =
    text.find_last_not_of (" \t\r\n");

  return
    text.substr (first, last - first + 1);
}


static constexpr size_t SK_MCP_MaxAddressLength = 1024;
static constexpr int    SK_MCP_MaxChainLevels   =   16;

static bool
SK_MCP_IsSpace (char c)
{
  return
    c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static bool
SK_MCP_IsHexDigit (char c)
{
  return
    (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

// Recursive descent over the grammar documented at SK_MCP_ParseAddress.
struct SK_MCP_AddressParser {
  const std::string&                  text;
  const std::vector <SK_MCP_Module>*  modules;  // nullptr: enumerate on demand
  size_t                              pos    = 0;
  int                                 derefs = 0;

  [[noreturn]] void Fail (const std::string& reason) const
  {
    throw SK_MCP_ToolError {
      "invalid address '" + text + "' (" + reason + "); expected 0x hex, "
      "module+offset or a pointer chain such as [[game.exe+0x10]+0x20]+8"
    };
  }

  void SkipSpace (void)
  {
    while (pos < text.length () && SK_MCP_IsSpace (text [pos]))
      ++pos;
  }

  bool AtHexPrefix (void) const
  {
    return
      pos + 2 < text.length () &&  text [pos] == '0'         &&
      (text [pos + 1] == 'x'   ||  text [pos + 1] == 'X')    &&
      SK_MCP_IsHexDigit (text [pos + 2]);
  }

  // A bare or 0x-prefixed hex number; it ends at the first non-hex character.
  uintptr_t HexNumber (void)
  {
    if (AtHexPrefix ())
      pos += 2;

    if (pos >= text.length () || ! SK_MCP_IsHexDigit (text [pos]))
      Fail ("expected a hex number at offset " + std::to_string (pos));

    const size_t start = pos;

    while (pos < text.length () && SK_MCP_IsHexDigit (text [pos]))
      ++pos;

    const auto value =
      SK_MCP_ParseHex (text.substr (start, pos - start));

    if (! value.has_value ())
    {
      Fail ( "hex number at offset " + std::to_string (start) +
               " is wider than a pointer" );
    }

    return *value;
  }

  uintptr_t Deref (uintptr_t addr)
  {
    const int level = ++derefs;

    uintptr_t value = 0;

    try
    {
      SK_MCP_SafeRead (addr, &value, sizeof (value));
    }

    catch (const SK_MCP_ToolError& e)
    {
      throw SK_MCP_ToolError {
        "pointer chain '" + text + "': level " + std::to_string (level) +
          " read of " + SK_MCP_FormatAddress (addr) + " failed: " + e.message
      };
    }

    return value;
  }

  uintptr_t Lead (int depth)
  {
    if (pos < text.length () && text [pos] == '[')
    {
      if (depth >= SK_MCP_MaxChainLevels)
      {
        throw SK_MCP_ToolError {
          "pointer chain '" + text + "' nests more than " +
            std::to_string (SK_MCP_MaxChainLevels) + " levels"
        };
      }

      ++pos;

      const uintptr_t inner =
        Address (depth + 1);

      if (pos >= text.length () || text [pos] != ']')
        Fail ("missing ']'");

      ++pos;

      return
        Deref (inner);
    }

    if (AtHexPrefix ())
      return HexNumber ();

    // bare: up to the first '+' outside brackets, or the ']' closing the
    //   enclosing bracket.  Module names may themselves contain brackets.
    const size_t start   = pos;
    int          nesting = 0;

    for (; pos < text.length (); ++pos)
    {
      const char c = text [pos];

      if      (c == '+' && nesting == 0) break;
      else if (c == '[')                 ++nesting;
      else if (c == ']')
      {
        if (nesting > 0)       --nesting;
        else if (depth > 0)    break;
      }
    }

    const std::string bare =
      SK_MCP_Trim (text.substr (start, pos - start));

    if (bare.empty ())
      Fail ("expected an address at offset " + std::to_string (start));

    // Nothing follows: the lead is a bare hex number.
    if (pos >= text.length () || text [pos] != '+')
    {
      const auto value =
        SK_MCP_ParseHex (bare);

      if (! value.has_value ())
        Fail ("'" + bare + "' is not hex; a module needs +offset");

      return *value;
    }

    std::optional <SK_MCP_Module> mod;

    if (modules != nullptr) mod = SK_MCP_FindModule (bare, *modules);
    else                    mod = SK_MCP_FindModule (bare);

    if (! mod.has_value ())
    {
      throw SK_MCP_ToolError {
        "module '" + bare + "' in address '" + text + "' is not loaded"
      };
    }

    return mod->base;
  }

  // Stops at the end of the text, or before a ']' when depth > 0.
  uintptr_t Address (int depth)
  {
    SkipSpace ();

    uintptr_t value =
      Lead (depth);

    for (;;)
    {
      SkipSpace ();

      if (pos >= text.length ())
        break;

      const char c = text [pos];

      if (c == ']' && depth > 0)
        break;

      if (c != '+' && c != '-')
      {
        Fail ( "unexpected '" + std::string (1, c) + "' at offset " +
                 std::to_string (pos) );
      }

      ++pos;

      SkipSpace ();

      const uintptr_t offset =
        HexNumber ();

      // Wraps like any uintptr_t arithmetic.
      value = (c == '+') ? value + offset
                         : value - offset;
    }

    return value;
  }
};

static uintptr_t
SK_MCP_ParseAddressImpl ( const std::string&                  text,
                          const std::vector <SK_MCP_Module>*  modules )
{
  if (text.length () > SK_MCP_MaxAddressLength)
  {
    throw SK_MCP_ToolError {
      "address is longer than " + std::to_string (SK_MCP_MaxAddressLength) +
        " characters"
    };
  }

  SK_MCP_AddressParser parser { text, modules };

  return
    parser.Address (0);
}

uintptr_t
SK_MCP_ParseAddress (const std::string& text)
{
  return
    SK_MCP_ParseAddressImpl (text, nullptr);
}

uintptr_t
SK_MCP_ParseAddress ( const std::string&                  text,
                      const std::vector <SK_MCP_Module>&  modules )
{
  return
    SK_MCP_ParseAddressImpl (text, &modules);
}

double
SK_MCP_ParseFloatValue (const json& v)
{
  if (v.is_number ())
    return v.get <double> ();

  if (v.is_string ())
  {
    const std::string s =
      v.get <std::string> ();

    const char* begin = s.c_str ();
    char*       end   = nullptr;

    errno = 0;

    const double parsed =
      strtod (begin, &end);

    // strtod reports an empty string and leading junk the same way, and
    //   returns a usable value while leaving trailing junk unconsumed.
    if (end == begin || *end != '\0')
      throw SK_MCP_ToolError { "invalid float value '" + s + "'" };

    // Underflow to a denormal also sets ERANGE, and that result is fine to
    //   write; only a magnitude strtod could not represent is an error.
    if (errno == ERANGE && (parsed >= HUGE_VAL || parsed <= -HUGE_VAL))
      throw SK_MCP_ToolError { "float value '" + s + "' is out of range" };

    return parsed;
  }

  throw SK_MCP_ToolError {
    std::string ("float value must be a number or a numeric string, got ") +
      v.type_name ()
  };
}


std::string
SK_MCP_ProtectString (DWORD protect)
{
  bool r = false,
       w = false,
       x = false;

  switch (protect & 0xFF)
  {
    case PAGE_READONLY:          r =                 true; break;
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:         r = w =             true; break;
    case PAGE_EXECUTE:                   x =         true; break;
    case PAGE_EXECUTE_READ:      r =     x =         true; break;
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY: r = w = x =         true; break;
    default:                                              break;
  }

  return
    std::string (r ? "r" : "-") +
                (w ? "w" : "-") +
                (x ? "x" : "-");
}

bool
SK_MCP_IsReadableRange ( uintptr_t addr, size_t len,
                         MEMORY_BASIC_INFORMATION* out )
{
  MEMORY_BASIC_INFORMATION mbi = { };

  if (0 == VirtualQuery ((LPCVOID)addr, &mbi, sizeof (mbi)))
    return false;

  if (out != nullptr)
     *out = mbi;

  if (mbi.State != MEM_COMMIT)
    return false;

  if ((mbi.Protect & 0xFF) == PAGE_NOACCESS || (mbi.Protect & PAGE_GUARD))
    return false;

  if (len == 0)
    return true;

  if (addr + len < addr)
    return false;

  return
    (addr + len) <= (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
}


bool
SK_MCP_RegionFilter::Matches (const MEMORY_BASIC_INFORMATION& mbi) const
{
  // sk_list_regions reports anything that is neither image nor mapped as
  //   private, so the filter classifies it the same way.
  const bool type_ok =
    (mbi.Type == MEM_IMAGE)  ? image  :
    (mbi.Type == MEM_MAPPED) ? mapped :
                               priv;

  if (! type_ok)
    return false;

  if (protect.empty ())
    return true;

  const std::string protect_str =
    SK_MCP_ProtectString (mbi.Protect);

  for (char c : protect)
  {
    if (protect_str.find (c) == std::string::npos)
      return false;
  }

  return true;
}

SK_MCP_RegionFilter
SK_MCP_ParseRegionFilter (const json& args)
{
  SK_MCP_RegionFilter filter;

  if (! args.is_object ())
    return filter;

  if (args.contains ("protect"))
  {
    if (! args.at ("protect").is_string ())
      throw SK_MCP_ToolError { "protect must be a string" };

    filter.protect =
      args.at ("protect").get <std::string> ();

    for (char c : filter.protect)
    {
      if (c != 'r' && c != 'w' && c != 'x')
      {
        throw SK_MCP_ToolError {
          "invalid protect '" + filter.protect + "'; use only the letters r, w "
          "and x"
        };
      }
    }
  }

  if (args.contains ("region_type"))
  {
    const json& types =
      args.at ("region_type");

    if (! types.is_array ())
      throw SK_MCP_ToolError { "region_type must be an array of strings" };

    if (types.empty ())
    {
      throw SK_MCP_ToolError {
        "region_type must not be empty; omit it to keep every type"
      };
    }

    filter.image  = false;
    filter.priv   = false;
    filter.mapped = false;

    for (const auto& type : types)
    {
      if (! type.is_string ())
        throw SK_MCP_ToolError { "region_type must be an array of strings" };

      const std::string name =
        type.get <std::string> ();

      if      (name == "image")   filter.image  = true;
      else if (name == "private") filter.priv   = true;
      else if (name == "mapped")  filter.mapped = true;
      else
      {
        throw SK_MCP_ToolError {
          "invalid region_type '" + name + "'; expected image, private or "
          "mapped"
        };
      }
    }
  }

  return filter;
}


// Rejects a range that is not fully committed, readable and guard-free.
//   Returns the number of regions the range spans, which is the most entries
//   SK_MCP_SafeWrite can need in its rollback record.
static size_t
SK_MCP_RequireAccessible (uintptr_t addr, size_t len, const char* what)
{
  if (len == 0)
    return 0;

  if (addr + len < addr)
  {
    throw SK_MCP_ToolError {
      std::string (what) + " of " + SK_MCP_FormatAddress (addr) +
                           " overflows the address space"
    };
  }

  const uintptr_t end = addr + len;
        uintptr_t pos = addr;

  size_t regions = 0;

  while (pos < end)
  {
    MEMORY_BASIC_INFORMATION mbi = { };

    const char* reason = nullptr;

    if (0 == VirtualQuery ((LPCVOID)pos, &mbi, sizeof (mbi)))
      reason = "is not mapped";
    else if (mbi.State != MEM_COMMIT)
      reason = "is not committed";
    else if ((mbi.Protect & 0xFF) == PAGE_NOACCESS)
      reason = "is PAGE_NOACCESS";
    else if (mbi.Protect & PAGE_GUARD)
      reason = "is a guard page";

    if (reason != nullptr)
    {
      throw SK_MCP_ToolError {
        std::string (what) + " of " + SK_MCP_FormatAddress (addr) + " failed: " +
                             SK_MCP_FormatAddress (pos)  + " " + reason
      };
    }

    const uintptr_t next =
      (uintptr_t)mbi.BaseAddress + mbi.RegionSize;

    // VirtualQuery is expected to move forward; a stall would spin forever.
    if (next <= pos)
    {
      throw SK_MCP_ToolError {
        std::string (what) + " of " + SK_MCP_FormatAddress (addr) +
                             " failed: the region walk made no progress"
      };
    }

    pos = next;

    ++regions;
  }

  return regions;
}

static int
SK_MCP_FaultFilter ( EXCEPTION_POINTERS* pExc,
                     DWORD*              pCode,
                     uintptr_t*          pFaultAddr )
{
  *pCode =
    pExc->ExceptionRecord->ExceptionCode;

  // ExceptionInformation [1] is the address the faulting instruction touched.
  *pFaultAddr =
    ( pExc->ExceptionRecord->NumberParameters >= 2 &&
      ( *pCode == EXCEPTION_ACCESS_VIOLATION ||
        *pCode == EXCEPTION_IN_PAGE_ERROR ) )
      ? (uintptr_t)pExc->ExceptionRecord->ExceptionInformation [1]
      : (uintptr_t)pExc->ExceptionRecord->ExceptionAddress;

  return
    EXCEPTION_EXECUTE_HANDLER;
}

// __try/__except needs a frame with nothing to unwind, so the copy lives in
//   its own raw-pointer helper.  Returns the exception code, 0 on success.
static DWORD
SK_MCP_CopyGuarded ( void* dst, const void* src, size_t len,
                     uintptr_t* pFaultAddr )
{
  DWORD     code  = 0;
  uintptr_t fault = 0;

  __try
  {
    memcpy (dst, src, len);
  }

  __except (SK_MCP_FaultFilter (GetExceptionInformation (), &code, &fault))
  {
    *pFaultAddr = fault;

    return code;
  }

  *pFaultAddr = 0;

  return 0;
}

static SK_MCP_ToolError
SK_MCP_FaultError (const char* what, uintptr_t addr, DWORD code, uintptr_t fault)
{
  char szMessage [160] = { };

  // The faulting address is only worth naming when it is not the target.
  if (fault == 0 || fault == addr)
  {
    snprintf ( szMessage, sizeof (szMessage), "%s of 0x%llx faulted: 0x%lx",
                 what, (unsigned long long)addr, code );
  }

  else
  {
    snprintf ( szMessage, sizeof (szMessage),
                 "%s of 0x%llx faulted: 0x%lx at 0x%llx",
                   what, (unsigned long long)addr, code,
                         (unsigned long long)fault );
  }

  return { szMessage };
}

void
SK_MCP_SafeRead (uintptr_t addr, void* dst, size_t len)
{
  if (len == 0)
    return;

  SK_MCP_RequireAccessible (addr, len, "read");

  uintptr_t fault = 0;

  const DWORD code =
    SK_MCP_CopyGuarded (dst, (const void *)addr, len, &fault);

  if (code != 0)
    throw SK_MCP_FaultError ("read", addr, code, fault);
}


// The writable counterpart of a base protection, or 0 when it already writes.
static DWORD
SK_MCP_WritableProtect (DWORD base_protect)
{
  switch (base_protect)
  {
    case PAGE_READONLY:          return PAGE_READWRITE;
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:      return PAGE_EXECUTE_READWRITE;

    // Copy-on-write pages get their private copy from the OS.
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY: return 0;

    default:                     return 0;
  }
}

static bool
SK_MCP_IsExecutableProtect (DWORD base_protect)
{
  return ( base_protect == PAGE_EXECUTE           ||
           base_protect == PAGE_EXECUTE_READ      ||
           base_protect == PAGE_EXECUTE_READWRITE ||
           base_protect == PAGE_EXECUTE_WRITECOPY );
}

struct SK_MCP_ProtectedRange {
  uintptr_t base;
  size_t    size;
  DWORD     original;   // With its modifier bits, exactly as it was
};

// Puts every widened run back the way it was.  A failure is logged and the
//   remaining runs are still restored; log_failures is false while rolling
//   back a write that has not started, where the caller reports the reason.
static void
SK_MCP_RestoreRanges ( const std::vector <SK_MCP_ProtectedRange>& changed,
                       bool                                       log_failures )
{
  for (const auto& range : changed)
  {
    DWORD old_protect = 0;

    if (! VirtualProtect ( (LPVOID)range.base, range.size,
                             range.original,  &old_protect ) && log_failures )
    {
      SK_LOG0 ( ( L"Could not restore page protection at %p after an MCP write",
                    (void *)range.base ), SK_MCP_LOG_SRC );
    }
  }
}

void
SK_MCP_SafeWrite (uintptr_t addr, const void* src, size_t len)
{
  if (len == 0)
    return;

  const size_t regions =
    SK_MCP_RequireAccessible (addr, len, "write");

  const uintptr_t end = addr + len;

  std::vector <SK_MCP_ProtectedRange> changed;

  // Reserved up front so that recording a widened run cannot throw and strand
  //   it un-restored.  The walk below sees the same regions this counted.
  changed.reserve (regions);

  bool executable = false;

  // Widen every non-writable run in the range, remembering what it was.  Any
  //   failure rolls the earlier ones back before it throws, so a write that
  //   never happens leaves protections exactly as it found them.
  try
  {
    for (uintptr_t pos = addr; pos < end; )
    {
      MEMORY_BASIC_INFORMATION mbi = { };

      if (0 == VirtualQuery ((LPCVOID)pos, &mbi, sizeof (mbi)))
      {
        throw SK_MCP_ToolError {
          "write of " + SK_MCP_FormatAddress (addr) + " failed: " +
                        SK_MCP_FormatAddress (pos)  + " is not mapped"
        };
      }

      const uintptr_t region_end =
        (uintptr_t)mbi.BaseAddress + mbi.RegionSize;

      const uintptr_t run_end =
        std::min (region_end, end);

      const DWORD base_protect = mbi.Protect & 0xFF;
      const DWORD writable     = SK_MCP_WritableProtect (base_protect);

      if (SK_MCP_IsExecutableProtect (base_protect))
        executable = true;

      if (writable != 0)
      {
        // Another thread splitting a region since the count would push the
        //   record past its reservation; grow before widening anything, never
        //   after.
        if (changed.size () == changed.capacity ())
          changed.reserve (changed.capacity () + 8);

        DWORD old_protect = 0;

        const DWORD modifiers =
          mbi.Protect & (PAGE_NOCACHE | PAGE_WRITECOMBINE);

        if (! VirtualProtect ( (LPVOID)pos, (SIZE_T)(run_end - pos),
                                 writable | modifiers, &old_protect ))
        {
          const DWORD err = GetLastError ();

          char szMessage [160] = { };

          snprintf ( szMessage, sizeof (szMessage),
                       "write of 0x%llx failed: VirtualProtect (0x%llx) error %lu",
                         (unsigned long long)addr, (unsigned long long)pos, err );

          throw SK_MCP_ToolError { szMessage };
        }

        changed.push_back ({ pos, (size_t)(run_end - pos), mbi.Protect });
      }

      pos = run_end;
    }
  }

  catch (const SK_MCP_ToolError&)
  {
    SK_MCP_RestoreRanges (changed, false);

    throw;
  }

  catch (const std::exception&)
  {
    SK_MCP_RestoreRanges (changed, false);

    throw;
  }

  uintptr_t fault = 0;

  const DWORD code =
    SK_MCP_CopyGuarded ((void *)addr, src, len, &fault);

  // Restore on every path; a completed copy still counts, the bytes landed.
  SK_MCP_RestoreRanges (changed, true);

  if (executable)
  {
    FlushInstructionCache (GetCurrentProcess (), (LPCVOID)addr, len);
  }

  if (code != 0)
    throw SK_MCP_FaultError ("write", addr, code, fault);
}


std::string
SK_MCP_BytesToHex (const void* data, size_t len)
{
  static constexpr char digits [] = "0123456789abcdef";

  std::string hex;
              hex.reserve (len * 2);

  const uint8_t* bytes =
    (const uint8_t *)data;

  for (size_t i = 0; i < len; ++i)
  {
    hex += digits [bytes [i] >> 4  ];
    hex += digits [bytes [i] &  0xF];
  }

  return hex;
}

std::vector <uint8_t>
SK_MCP_HexToBytes (const std::string& hex)
{
  if ((hex.length () % 2) != 0)
  {
    throw SK_MCP_ToolError {
      "hex string '" + hex + "' has an odd number of digits"
    };
  }

  std::vector <uint8_t> bytes;
                        bytes.reserve (hex.length () / 2);

  for (size_t i = 0; i < hex.length (); i += 2)
  {
    int nibbles [2] = { };

    for (int n = 0; n < 2; ++n)
    {
      const unsigned char c = (unsigned char)hex [i + n];

      if      (c >= '0' && c <= '9') nibbles [n] = c - '0';
      else if (c >= 'a' && c <= 'f') nibbles [n] = c - 'a' + 10;
      else if (c >= 'A' && c <= 'F') nibbles [n] = c - 'A' + 10;
      else
      {
        throw SK_MCP_ToolError {
          "hex string '" + hex + "' contains a non-hex character"
        };
      }
    }

    bytes.push_back ((uint8_t)((nibbles [0] << 4) | nibbles [1]));
  }

  return bytes;
}

std::string
SK_MCP_SanitizeUTF8 (const std::string& in)
{
  std::string out;
              out.reserve (in.size ());

  const size_t n = in.size ();
        size_t i = 0;

  while (i < n)
  {
    const unsigned char c0 = (unsigned char)in [i];

    if (c0 < 0x80)
    {
      out += (char)c0;
      ++i;
      continue;
    }

    int      len    = 0;
    uint32_t cp     = 0;
    uint32_t min_cp = 0;

    if      ((c0 & 0xE0) == 0xC0) { len = 2; cp = c0 & 0x1F; min_cp = 0x80;    }
    else if ((c0 & 0xF0) == 0xE0) { len = 3; cp = c0 & 0x0F; min_cp = 0x800;   }
    else if ((c0 & 0xF8) == 0xF0) { len = 4; cp = c0 & 0x07; min_cp = 0x10000; }
    else
    {
      out += "\xEF\xBF\xBD";
      ++i;
      continue;
    }

    if (i + (size_t)len > n)
    {
      out += "\xEF\xBF\xBD";
      ++i;
      continue;
    }

    bool     valid = true;
    uint32_t acc   = cp;

    for (int k = 1; k < len; ++k)
    {
      const unsigned char ck = (unsigned char)in [i + (size_t)k];

      if ((ck & 0xC0) != 0x80) { valid = false; break; }

      acc = (acc << 6) | (ck & 0x3F);
    }

    // Overlong forms, surrogates and anything past U+10FFFF are as invalid as
    //   a broken sequence; resync one byte at a time either way.
    if ( (! valid) || acc < min_cp || acc > 0x10FFFF ||
         (acc >= 0xD800 && acc <= 0xDFFF) )
    {
      out += "\xEF\xBF\xBD";
      ++i;
      continue;
    }

    out.append (in, i, (size_t)len);

    i += (size_t)len;
  }

  return out;
}
