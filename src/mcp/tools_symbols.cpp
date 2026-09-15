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

#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

using json = nlohmann::json;


//
// §4.4/§4.5: symbol resolution and the export-directory walk.
//

// Reads a NUL-terminated 8-bit string one byte at a time through
//   SK_MCP_SafeRead, so a name that runs off the end of a readable region
//   fails cleanly instead of over-reading.  Throws SK_MCP_ToolError if the
//   first byte is unreadable.  Export names are ASCII in practice, but the
//   bytes come from raw process memory, so the name is sanitized.
static std::string
SK_MCP_ReadExportName (uintptr_t addr)
{
  static constexpr size_t kMaxLen = 512;

  std::string raw;
              raw.reserve (32);

  for (size_t i = 0; i < kMaxLen; ++i)
  {
    char c = 0;

    SK_MCP_SafeRead (addr + i, &c, 1);

    if (c == '\0')
      break;

    raw.push_back (c);
  }

  return SK_MCP_SanitizeUTF8 (raw);
}

// Parses the module's IMAGE_DIRECTORY_ENTRY_EXPORT by hand, reading every
//   header and table through SK_MCP_SafeRead (the module can unload between
//   enumeration and this parse) and bounds-checking every RVA and table size
//   against the image size.  Returns the export at or below addr with the
//   greatest address, or null on no such export, an unreadable module, or a
//   malformed header -- this never fails the tool call.
static json
SK_MCP_FindNearestExport (const SK_MCP_Module& mod, uintptr_t addr)
{
  try
  {
    if (mod.size < sizeof (IMAGE_DOS_HEADER))
      return nullptr;

    IMAGE_DOS_HEADER dos = { };

    SK_MCP_SafeRead (mod.base, &dos, sizeof (dos));

    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
      return nullptr;

    if (dos.e_lfanew < 0)
      return nullptr;

    const uint64_t nt_off =
      (uint64_t)(uint32_t)dos.e_lfanew;

    if (nt_off + sizeof (IMAGE_NT_HEADERS) > mod.size)
      return nullptr;

    IMAGE_NT_HEADERS nt = { };

    SK_MCP_SafeRead (mod.base + (uintptr_t)nt_off, &nt, sizeof (nt));

    if (nt.Signature != IMAGE_NT_SIGNATURE)
      return nullptr;

    // IMAGE_NT_OPTIONAL_HDR_MAGIC and IMAGE_NT_HEADERS already resolve to the
    //   32- or 64-bit variant depending on this build's bitness, so a 32-bit
    //   build parses PE32 headers and a 64-bit build parses PE32+ headers.
    if (nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
      return nullptr;

    if (nt.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
      return nullptr;

    const IMAGE_DATA_DIRECTORY exp_dir =
      nt.OptionalHeader.DataDirectory [IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (exp_dir.VirtualAddress == 0 || exp_dir.Size == 0)
      return nullptr;

    if ((uint64_t)exp_dir.VirtualAddress + exp_dir.Size > mod.size)
      return nullptr;

    if ((uint64_t)exp_dir.VirtualAddress + sizeof (IMAGE_EXPORT_DIRECTORY) > mod.size)
      return nullptr;

    IMAGE_EXPORT_DIRECTORY exp = { };

    SK_MCP_SafeRead (mod.base + exp_dir.VirtualAddress, &exp, sizeof (exp));

    const uint64_t func_bytes =
      (uint64_t)exp.NumberOfFunctions * sizeof (DWORD);

    if ((uint64_t)exp.AddressOfFunctions + func_bytes > mod.size)
      return nullptr;

    std::vector <DWORD> functions (exp.NumberOfFunctions);

    if (! functions.empty ())
    {
      SK_MCP_SafeRead ( mod.base + exp.AddressOfFunctions,
                         functions.data (), (size_t)func_bytes );
    }

    bool      found      = false;
    uintptr_t best_addr  = 0;
    uint32_t  best_index = 0;

    for (uint32_t i = 0; i < exp.NumberOfFunctions; ++i)
    {
      const DWORD func_rva = functions [i];

      // 0 means no export at this ordinal slot.
      if (func_rva == 0)
        continue;

      // A forwarder's RVA points back inside the export directory itself;
      //   this walk never leaves the module, so those are skipped.
      if ( func_rva >= exp_dir.VirtualAddress &&
           func_rva <  exp_dir.VirtualAddress + exp_dir.Size )
        continue;

      if (func_rva >= mod.size)
        continue;

      const uintptr_t candidate =
        mod.base + func_rva;

      if (candidate > addr)
        continue;

      if ((! found) || candidate > best_addr)
      {
        best_addr  = candidate;
        best_index = i;
        found      = true;
      }
    }

    if (! found)
      return nullptr;

    // Only the winning ordinal's name is looked up, not every export's.
    std::string name;

    const uint64_t name_bytes =
      (uint64_t)exp.NumberOfNames * sizeof (DWORD);
    const uint64_t ord_bytes =
      (uint64_t)exp.NumberOfNames * sizeof (WORD);

    if ( exp.NumberOfNames > 0                                        &&
         (uint64_t)exp.AddressOfNames        + name_bytes <= mod.size &&
         (uint64_t)exp.AddressOfNameOrdinals + ord_bytes  <= mod.size )
    {
      std::vector <DWORD> names    (exp.NumberOfNames);
      std::vector <WORD>  ordinals (exp.NumberOfNames);

      SK_MCP_SafeRead ( mod.base + exp.AddressOfNames,
                         names.data (), (size_t)name_bytes );
      SK_MCP_SafeRead ( mod.base + exp.AddressOfNameOrdinals,
                         ordinals.data (), (size_t)ord_bytes );

      for (uint32_t j = 0; j < exp.NumberOfNames; ++j)
      {
        if (ordinals [j] != best_index)
          continue;

        if (names [j] < mod.size)
          name = SK_MCP_ReadExportName (mod.base + names [j]);

        break;
      }
    }

    if (name.empty ())
    {
      name =
        "#" + std::to_string ((uint32_t)exp.Base + best_index);
    }

    return json {
      { "name",     name                              },
      { "address",  SK_MCP_FormatAddress (best_addr)  },
      { "distance", (uint64_t)(addr - best_addr)       }
    };
  }

  // A module can unload mid-walk, or carry a malformed header; either way
  //   this yields nearest_export: null rather than failing the call.
  catch (const SK_MCP_ToolError&)
  {
    return nullptr;
  }
}


static json
SK_MCP_ResolveSymbol (const json& args)
{
  if ( (! args.is_object ())         ||
       (! args.contains ("symbol"))  ||
       (! args.at        ("symbol").is_string ()) )
  {
    throw SK_MCP_ToolError { "symbol is required and must be a string" };
  }

  const std::string symbol =
    args.at ("symbol").get <std::string> ();

  const size_t bang =
    symbol.find ('!');

  if (bang == std::string::npos)
  {
    throw SK_MCP_ToolError {
      "symbol '" + symbol + "' is missing '!'; expected module!name or module!#ordinal"
    };
  }

  const std::string module_name =
    symbol.substr (0, bang);
  const std::string export_spec =
    symbol.substr (bang + 1);

  const auto mod =
    SK_MCP_FindModule (module_name);

  if (! mod.has_value ())
  {
    throw SK_MCP_ToolError {
      "module '" + module_name + "' in symbol '" + symbol + "' is not loaded"
    };
  }

  FARPROC proc = nullptr;

  if ( (! export_spec.empty ()) && export_spec [0] == '#' )
  {
    const std::string ordinal_text =
      export_spec.substr (1);

    bool     valid   = (! ordinal_text.empty ());
    uint32_t ordinal = 0;

    for (size_t i = 0; valid && i < ordinal_text.length (); ++i)
    {
      const char c = ordinal_text [i];

      if (c < '0' || c > '9')
      {
        valid = false;
        break;
      }

      ordinal = ordinal * 10 + (uint32_t)(c - '0');

      if (ordinal > 0xFFFF)
      {
        valid = false;
        break;
      }
    }

    if (valid)
    {
      proc =
        GetProcAddress (mod->handle, MAKEINTRESOURCEA ((WORD)ordinal));
    }
  }

  else
  {
    proc =
      GetProcAddress (mod->handle, export_spec.c_str ());
  }

  if (proc == nullptr)
  {
    throw SK_MCP_ToolError {
      "export '" + export_spec + "' not found in module '" + module_name + "'"
    };
  }

  const uintptr_t addr =
    (uintptr_t)proc;

  return {
    { "address", SK_MCP_FormatAddress (addr) },
    { "symbol",  SK_MCP_Symbolize     (addr)  },
    { "module",  mod->name                    },
    { "export",  export_spec                  }
  };
}

static json
SK_MCP_SymbolizeAddress (const json& args)
{
  if ( (! args.is_object ())          ||
       (! args.contains ("address"))  ||
       (! args.at        ("address").is_string ()) )
  {
    throw SK_MCP_ToolError { "address is required and must be a string" };
  }

  const uintptr_t addr =
    SK_MCP_ParseAddress (args.at ("address").get <std::string> ());

  const auto modules =
    SK_MCP_EnumModules ();

  const SK_MCP_Module* mod =
    SK_MCP_ModuleForAddress (addr, modules);

  if (mod == nullptr)
  {
    return {
      { "address",        SK_MCP_FormatAddress (addr) },
      { "module",         nullptr                      },
      { "offset",         nullptr                      },
      { "symbol",         nullptr                      },
      { "nearest_export", nullptr                      }
    };
  }

  char szOffset [32] = { };

  snprintf ( szOffset, sizeof (szOffset), "0x%llx",
               (unsigned long long)(addr - mod->base) );

  return {
    { "address",        SK_MCP_FormatAddress (addr)           },
    { "module",         mod->name                             },
    { "offset",         szOffset                               },
    { "symbol",         SK_MCP_Symbolize (addr, modules)      },
    { "nearest_export", SK_MCP_FindNearestExport (*mod, addr) }
  };
}


void
SK_MCP_RegisterSymbolTools (void)
{
  SK_MCP_RegisterTool ({
    "sk_resolve_symbol",
    "Resolves a module!name or module!#ordinal export symbol (e.g. kernel32.dll!GetTickCount) "
    "to its address via GetProcAddress, following export forwarders into another module.",
    {
      { "type",       "object" },
      { "properties",
        { { "symbol", { { "type", "string" } } } }
      },
      { "required",             { "symbol" } },
      { "additionalProperties", false        }
    },
    SK_MCP_ResolveSymbol
  });

  SK_MCP_RegisterTool ({
    "sk_symbolize_address",
    "Resolves an address (0x hex, module+offset or a pointer chain like "
    "[game.exe+0x10]+8) to its containing module and offset, plus the nearest "
    "export in that module at or below the address.",
    {
      { "type",       "object" },
      { "properties",
        { { "address", { { "type", "string" } } } }
      },
      { "required",             { "address" } },
      { "additionalProperties", false         }
    },
    SK_MCP_SymbolizeAddress
  });
}
