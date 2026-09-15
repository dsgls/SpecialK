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

#include <algorithm>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>

using json = nlohmann::json;


//
// §4.2/§4.3 element types
//

enum class SK_MCP_MemType {
  U8, U16, U32, U64,
  I8, I16, I32, I64,
  F32, F64,
  Ptr,
  CStr, WStr,
  Hex
};

static SK_MCP_MemType
SK_MCP_ParseMemType (const std::string& text)
{
  if (text == "u8")   return SK_MCP_MemType::U8;
  if (text == "u16")  return SK_MCP_MemType::U16;
  if (text == "u32")  return SK_MCP_MemType::U32;
  if (text == "u64")  return SK_MCP_MemType::U64;
  if (text == "i8")   return SK_MCP_MemType::I8;
  if (text == "i16")  return SK_MCP_MemType::I16;
  if (text == "i32")  return SK_MCP_MemType::I32;
  if (text == "i64")  return SK_MCP_MemType::I64;
  if (text == "f32")  return SK_MCP_MemType::F32;
  if (text == "f64")  return SK_MCP_MemType::F64;
  if (text == "ptr")  return SK_MCP_MemType::Ptr;
  if (text == "cstr") return SK_MCP_MemType::CStr;
  if (text == "wstr") return SK_MCP_MemType::WStr;
  if (text == "hex")  return SK_MCP_MemType::Hex;

  throw SK_MCP_ToolError {
    "invalid type '" + text + "'; expected one of u8, u16, u32, u64, i8, i16, "
    "i32, i64, f32, f64, ptr, cstr, wstr, hex"
  };
}

static size_t
SK_MCP_TypeElemSize (SK_MCP_MemType type)
{
  switch (type)
  {
    case SK_MCP_MemType::U8:
    case SK_MCP_MemType::I8:  return 1;
    case SK_MCP_MemType::U16:
    case SK_MCP_MemType::I16: return 2;
    case SK_MCP_MemType::U32:
    case SK_MCP_MemType::I32: return 4;
    case SK_MCP_MemType::U64:
    case SK_MCP_MemType::I64: return 8;
    case SK_MCP_MemType::F32: return 4;
    case SK_MCP_MemType::F64: return 8;
    case SK_MCP_MemType::Ptr: return sizeof (uintptr_t);
    default:                  return 0;   // CStr, WStr, Hex: no fixed element size
  }
}

// Default and cap for the "count" argument, per §4.2's table.
static void
SK_MCP_TypeCountLimits (SK_MCP_MemType type, size_t& def, size_t& cap)
{
  switch (type)
  {
    case SK_MCP_MemType::CStr:
    case SK_MCP_MemType::WStr: def = 256; cap = 65536; return;
    case SK_MCP_MemType::Hex:  def =  16; cap = 65536; return;
    default:                   def =   1; cap =  4096; return;
  }
}


//
// UTF-16 helpers.  Memory read as text is not guaranteed to be valid text at
//   all, so the conversion must survive garbage input instead of throwing:
//   an unpaired surrogate becomes U+FFFD, one input unit at a time.  The
//   UTF-8 direction is SK_MCP_SanitizeUTF8 in address.cpp.
//

static void
SK_MCP_AppendUtf8 (std::string& out, uint32_t cp)
{
  if (cp < 0x80)
  {
    out += (char)cp;
  }

  else if (cp < 0x800)
  {
    out += (char)(0xC0 | (cp >>  6));
    out += (char)(0x80 | (cp        & 0x3F));
  }

  else if (cp < 0x10000)
  {
    out += (char)(0xE0 |  (cp >> 12));
    out += (char)(0x80 | ((cp >>  6) & 0x3F));
    out += (char)(0x80 |  (cp        & 0x3F));
  }

  else
  {
    out += (char)(0xF0 |  (cp >> 18));
    out += (char)(0x80 | ((cp >> 12) & 0x3F));
    out += (char)(0x80 | ((cp >>  6) & 0x3F));
    out += (char)(0x80 |  (cp        & 0x3F));
  }
}

// raw holds an even number of bytes: little-endian UTF-16 code units, as
//   read from process memory.  Lone surrogates become U+FFFD.
static std::string
SK_MCP_Utf16ToUtf8 (const std::vector <uint8_t>& raw)
{
  std::string out;
              out.reserve (raw.size ());

  const size_t n = raw.size () / 2;

  for (size_t i = 0; i < n; )
  {
    const uint16_t unit =
      (uint16_t)raw [i * 2] | ((uint16_t)raw [i * 2 + 1] << 8);

    if (unit >= 0xD800 && unit <= 0xDBFF)
    {
      if (i + 1 < n)
      {
        const uint16_t low =
          (uint16_t)raw [(i + 1) * 2] | ((uint16_t)raw [(i + 1) * 2 + 1] << 8);

        if (low >= 0xDC00 && low <= 0xDFFF)
        {
          const uint32_t cp =
            0x10000 + (((uint32_t)(unit - 0xD800)) << 10) + (low - 0xDC00);

          SK_MCP_AppendUtf8 (out, cp);

          i += 2;
          continue;
        }
      }

      out += "\xEF\xBF\xBD";
      ++i;
      continue;
    }

    if (unit >= 0xDC00 && unit <= 0xDFFF)
    {
      out += "\xEF\xBF\xBD";
      ++i;
      continue;
    }

    SK_MCP_AppendUtf8 (out, unit);
    ++i;
  }

  return out;
}


//
// §4.2 page-by-page string reads.  The first chunk runs to the next page
//   boundary, then whole pages; a chunk fails only when its page is
//   unreadable.  A later chunk's failure ends the string, a first chunk's
//   failure fails the call.  stop_check inspects out after every byte and
//   returns true (after popping its terminator) once the string is done.
//
template <typename StopCheck>
static void
SK_MCP_ReadStringChunks ( uintptr_t addr, size_t max_bytes,
                          std::vector <uint8_t>& out, StopCheck stop_check )
{
  SYSTEM_INFO si = { };
  SK_GetSystemInfo (&si);

  const size_t page_size =
    (size_t)si.dwPageSize;

  uintptr_t pos   = addr;
  bool      first = true;

  while (out.size () < max_bytes)
  {
    const uintptr_t next_page =
      (pos + page_size) & ~((uintptr_t)page_size - 1);

    size_t chunk_len =
      first ? (size_t)(next_page - pos) : page_size;

    chunk_len =
      std::min (chunk_len, max_bytes - out.size ());

    std::vector <uint8_t> buf (chunk_len);

    try
    {
      SK_MCP_SafeRead (pos, buf.data (), chunk_len);
    }

    catch (const SK_MCP_ToolError&)
    {
      if (first)
        throw;

      return;   // A later chunk's fault ends the string, not the call.
    }

    for (uint8_t byte : buf)
    {
      out.push_back (byte);

      if (stop_check (out))
        return;
    }

    pos  += chunk_len;
    first = false;
  }
}


//
// Integer/float/pointer value parsing for sk_write_memory.
//

static uint64_t
SK_MCP_ParseIntValue (const json& v)
{
  if (v.is_number_unsigned ())
    return v.get <uint64_t> ();

  if (v.is_number_integer ())
    return (uint64_t)v.get <int64_t> ();

  if (v.is_number_float ())
  {
    throw SK_MCP_ToolError {
      "integer value must be a whole number, not a float"
    };
  }

  if (v.is_string ())
  {
    const std::string s =
      v.get <std::string> ();

    if ( s.size () > 2 && s [0] == '0' &&
         (s [1] == 'x' || s [1] == 'X') )
    {
      uint64_t value = 0;

      for (size_t i = 2; i < s.size (); ++i)
      {
        const unsigned char c = (unsigned char)s [i];

        int digit;

        if      (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else
        {
          throw SK_MCP_ToolError { "invalid hex value '" + s + "'" };
        }

        // More significant digits than a 64-bit value can hold would
        //   otherwise wrap around silently.
        if (value > (0xFFFFFFFFFFFFFFFFULL >> 4))
        {
          throw SK_MCP_ToolError {
            "hex value '" + s + "' does not fit in 64 bits"
          };
        }

        value = (value << 4) | (uint64_t)digit;
      }

      return value;
    }

    throw SK_MCP_ToolError {
      "invalid integer value '" + s + "'; expected a number or a 0x hex string"
    };
  }

  throw SK_MCP_ToolError { "integer value must be a number or a hex string" };
}

// Rejects a parsed integer that does not fit in type's element size, signed
//   or unsigned as the type demands, instead of silently truncating it on the
//   memcpy that follows.  label names the offending argument for the error
//   ("value", or "values[<i>]").
static void
SK_MCP_CheckIntRange ( SK_MCP_MemType type, uint64_t raw,
                       const std::string& label, const std::string& type_text )
{
  const size_t elem_size =
    SK_MCP_TypeElemSize (type);

  // A full 64-bit element has no narrower range to enforce.
  if (elem_size >= 8)
    return;

  const bool is_signed =
    ( type == SK_MCP_MemType::I8 || type == SK_MCP_MemType::I16 ||
      type == SK_MCP_MemType::I32 );

  const unsigned bits =
    (unsigned)elem_size * 8;

  bool in_range;

  if (is_signed)
  {
    const int64_t signed_val = (int64_t)raw;
    const int64_t min_val    = -(int64_t)(1ULL << (bits - 1));
    const int64_t max_val    =  (int64_t)((1ULL << (bits - 1)) - 1);

    in_range =
      (signed_val >= min_val && signed_val <= max_val);
  }

  else
  {
    const uint64_t max_val =
      (1ULL << bits) - 1;

    in_range =
      (raw <= max_val);
  }

  if (! in_range)
  {
    char szDecimal [32] = { };

    if (is_signed)
      snprintf (szDecimal, sizeof (szDecimal), "%lld", (long long)(int64_t)raw);
    else
      snprintf (szDecimal, sizeof (szDecimal), "%llu", (unsigned long long)raw);

    throw SK_MCP_ToolError {
      label + " = " + szDecimal + " does not fit in " + type_text
    };
  }
}

static uintptr_t
SK_MCP_ParsePtrValue (const json& v)
{
  if (! v.is_string ())
    throw SK_MCP_ToolError { "ptr value must be an address string" };

  return SK_MCP_ParseAddress (v.get <std::string> ());
}


//
// sk_list_regions
//

static void
SK_MCP_WalkRegions ( uintptr_t                          start,
                     uintptr_t                          end,
                     size_t                              max_count,
                     const SK_MCP_RegionFilter&          filter,
                     const std::vector <SK_MCP_Module>&  modules,
                     json&                                out_regions,
                     bool&                                truncated )
{
  uintptr_t addr = start;
  size_t    reported = 0;

  truncated = false;

  for (;;)
  {
    MEMORY_BASIC_INFORMATION mbi = { };

    if (0 == VirtualQuery ((LPCVOID)addr, &mbi, sizeof (mbi)))
      break;

    if (mbi.State == MEM_COMMIT && filter.Matches (mbi))
    {
      const std::string protect_str =
        SK_MCP_ProtectString (mbi.Protect);

      if (reported >= max_count)
      {
        truncated = true;
        break;
      }

      const char* type_str = "private";

      if      (mbi.Type == MEM_IMAGE)  type_str = "image";
      else if (mbi.Type == MEM_MAPPED) type_str = "mapped";

      const SK_MCP_Module* mod =
        SK_MCP_ModuleForAddress ((uintptr_t)mbi.BaseAddress, modules);

      out_regions.push_back ({
        { "base",    SK_MCP_FormatAddress ((uintptr_t)mbi.BaseAddress) },
        { "size",    (uint64_t)mbi.RegionSize                          },
        { "protect", protect_str                                      },
        { "guard",   (mbi.Protect & PAGE_GUARD) != 0                  },
        { "type",    type_str                                         },
        { "module",  mod != nullptr ? json (mod->name) : json (nullptr) },
        { "symbol",  SK_MCP_Symbolize ((uintptr_t)mbi.BaseAddress, modules) }
      });

      ++reported;
    }

    const uintptr_t next =
      (uintptr_t)mbi.BaseAddress + mbi.RegionSize;

    // end is exclusive: a region that starts exactly there belongs to
    //   whatever follows the scope, not to it.
    if (next >= end)
      break;

    // A stalled or wrapped walk would otherwise spin forever.
    if (next <= addr)
      break;

    addr = next;
  }
}

static json
SK_MCP_ListRegions (const json& args)
{
  bool        has_module = false;
  std::string module_name;
  size_t      max_count = 1024;

  const SK_MCP_RegionFilter filter =
    SK_MCP_ParseRegionFilter (args);

  if (args.is_object ())
  {
    if (args.contains ("module"))
    {
      if (! args.at ("module").is_string ())
        throw SK_MCP_ToolError { "module must be a string" };

      has_module  = true;
      module_name = args.at ("module").get <std::string> ();
    }

    if (args.contains ("max"))
    {
      if (! args.at ("max").is_number ())
        throw SK_MCP_ToolError { "max must be a number" };

      const double m =
        args.at ("max").get <double> ();

      if (m < 0.0)
        throw SK_MCP_ToolError { "max must not be negative" };

      max_count =
        (size_t)std::min (m, 4096.0);
    }
  }

  const std::vector <SK_MCP_Module> modules =
    SK_MCP_EnumModules ();

  uintptr_t start = 0,
            end   = 0;

  if (has_module)
  {
    const auto mod =
      SK_MCP_FindModule (module_name);

    if (! mod.has_value ())
    {
      throw SK_MCP_ToolError {
        "module '" + module_name + "' is not loaded"
      };
    }

    start = mod->base;
    end   = mod->base + mod->size;
  }

  else
  {
    SYSTEM_INFO si = { };
    SK_GetSystemInfo (&si);

    start = 0;
    end   = (uintptr_t)si.lpMaximumApplicationAddress;
  }

  json regions   = json::array ();
  bool truncated = false;

  SK_MCP_WalkRegions ( start, end, max_count, filter, modules,
                       regions, truncated );

  return {
    { "regions",   regions   },
    { "truncated", truncated }
  };
}


//
// sk_read_memory
//

static json
SK_MCP_ReadElements ( uintptr_t addr, SK_MCP_MemType type, size_t count,
                      const std::vector <SK_MCP_Module>& modules )
{
  const size_t elem_size =
    SK_MCP_TypeElemSize (type);

  std::vector <uint8_t> buf (count * elem_size);

  if (! buf.empty ())
    SK_MCP_SafeRead (addr, buf.data (), buf.size ());

  json values = json::array ();

  const bool want_hex =
    ( type == SK_MCP_MemType::U64 || type == SK_MCP_MemType::I64 ||
      type == SK_MCP_MemType::F32 || type == SK_MCP_MemType::F64 );

  json hex_values =
    want_hex ? json::array () : json (nullptr);

  for (size_t i = 0; i < count; ++i)
  {
    const uint8_t* p =
      buf.data () + i * elem_size;

    char hex [24] = { };

    switch (type)
    {
      case SK_MCP_MemType::U8:  values.push_back ((uint64_t)*p);                          break;
      case SK_MCP_MemType::I8:  values.push_back ((int64_t)(int8_t)*p);                    break;

      case SK_MCP_MemType::U16: { uint16_t v; memcpy (&v, p, 2); values.push_back ((uint64_t)v); break; }
      case SK_MCP_MemType::I16: { int16_t  v; memcpy (&v, p, 2); values.push_back ((int64_t)v);  break; }
      case SK_MCP_MemType::U32: { uint32_t v; memcpy (&v, p, 4); values.push_back ((uint64_t)v); break; }
      case SK_MCP_MemType::I32: { int32_t  v; memcpy (&v, p, 4); values.push_back ((int64_t)v);  break; }

      case SK_MCP_MemType::U64:
      {
        uint64_t v; memcpy (&v, p, 8);
        values.push_back (v);
        snprintf (hex, sizeof (hex), "0x%llx", (unsigned long long)v);
        hex_values.push_back (hex);
        break;
      }

      case SK_MCP_MemType::I64:
      {
        int64_t v; memcpy (&v, p, 8);
        values.push_back (v);
        snprintf (hex, sizeof (hex), "0x%llx", (unsigned long long)(uint64_t)v);
        hex_values.push_back (hex);
        break;
      }

      case SK_MCP_MemType::F32:
      {
        float v; memcpy (&v, p, 4);
        values.push_back (v);
        uint32_t bits; memcpy (&bits, &v, 4);
        snprintf (hex, sizeof (hex), "0x%08x", bits);
        hex_values.push_back (hex);
        break;
      }

      case SK_MCP_MemType::F64:
      {
        double v; memcpy (&v, p, 8);
        values.push_back (v);
        uint64_t bits; memcpy (&bits, &v, 8);
        snprintf (hex, sizeof (hex), "0x%016llx", (unsigned long long)bits);
        hex_values.push_back (hex);
        break;
      }

      case SK_MCP_MemType::Ptr:
      {
        uintptr_t v = 0; memcpy (&v, p, elem_size);
        values.push_back ({
          { "address", SK_MCP_FormatAddress (v)   },
          { "symbol",  SK_MCP_Symbolize (v, modules) }
        });
        break;
      }

      default: break;
    }
  }

  json result = { { "values", values } };

  if (want_hex)
    result ["hex_values"] = hex_values;

  return result;
}

// One sk_read_memory call; modules serves both parsing and symbolizing.
static json
SK_MCP_ReadEntry ( const json&                         args,
                   const std::vector <SK_MCP_Module>&  modules )
{
  if ( (! args.is_object ())                     ||
       (! args.contains ("address"))             ||
       (! args.at        ("address").is_string ()) )
  {
    throw SK_MCP_ToolError { "address is required and must be a string" };
  }

  if ( (! args.contains ("type"))             ||
       (! args.at        ("type").is_string ()) )
  {
    throw SK_MCP_ToolError { "type is required and must be a string" };
  }

  const std::string type_text =
    args.at ("type").get <std::string> ();

  const uintptr_t addr =
    SK_MCP_ParseAddress (args.at ("address").get <std::string> (), modules);

  const SK_MCP_MemType type =
    SK_MCP_ParseMemType (type_text);

  size_t def_count = 0,
         cap_count = 0;

  SK_MCP_TypeCountLimits (type, def_count, cap_count);

  size_t count = def_count;

  if (args.contains ("count"))
  {
    if (! args.at ("count").is_number ())
      throw SK_MCP_ToolError { "count must be a number" };

    const double c =
      args.at ("count").get <double> ();

    if (c < 0.0)
      throw SK_MCP_ToolError { "count must not be negative" };

    count =
      (size_t)std::min (c, (double)cap_count);
  }

  json result = {
    { "address", SK_MCP_FormatAddress (addr)     },
    { "symbol",  SK_MCP_Symbolize (addr, modules) },
    { "type",    type_text                        }
  };

  if (type == SK_MCP_MemType::CStr)
  {
    std::vector <uint8_t> raw;

    SK_MCP_ReadStringChunks ( addr, count, raw,
      [](std::vector <uint8_t>& out) -> bool
      {
        if ((! out.empty ()) && out.back () == 0)
        {
          out.pop_back ();
          return true;
        }

        return false;
      });

    result ["count"]  = 1;
    result ["length"] = raw.size ();
    result ["values"] = json::array ({
      SK_MCP_SanitizeUTF8 (std::string (raw.begin (), raw.end ()))
    });
  }

  else if (type == SK_MCP_MemType::WStr)
  {
    std::vector <uint8_t> raw;

    SK_MCP_ReadStringChunks ( addr, count * 2, raw,
      [](std::vector <uint8_t>& out) -> bool
      {
        if ( out.size () >= 2 && (out.size () % 2) == 0 &&
             out [out.size () - 2] == 0 && out [out.size () - 1] == 0 )
        {
          out.pop_back ();
          out.pop_back ();
          return true;
        }

        return false;
      });

    result ["count"]  = 1;
    result ["length"] = raw.size () / 2;
    result ["values"] = json::array ({ SK_MCP_Utf16ToUtf8 (raw) });
  }

  else if (type == SK_MCP_MemType::Hex)
  {
    std::vector <uint8_t> buf (count);

    if (! buf.empty ())
      SK_MCP_SafeRead (addr, buf.data (), buf.size ());

    result ["count"]  = 1;
    result ["values"] = json::array ({ SK_MCP_BytesToHex (buf.data (), buf.size ()) });
  }

  else
  {
    const json elems =
      SK_MCP_ReadElements (addr, type, count, modules);

    result ["values"] = elems.at ("values");
    result ["count"]  = elems.at ("values").size ();

    if (elems.contains ("hex_values"))
      result ["hex_values"] = elems.at ("hex_values");
  }

  return result;
}

static json
SK_MCP_ReadMemory (const json& args)
{
  return
    SK_MCP_ReadEntry (args, SK_MCP_EnumModules ());
}


//
// sk_read_many
//

static constexpr size_t SK_MCP_ReadManyMaxEntries   = 256;

// SK_MCP_MaxResultBytes in server.cpp, which is checked against the result
//   after it has been dumped into the text item and escaped again.
static constexpr size_t SK_MCP_ReadManyMaxBytes     = 768 * 1024;

// The escaped {"results":[...]} wrapper and the tool result around it.
static constexpr size_t SK_MCP_ReadManyWrapperBytes = 256;

static json
SK_MCP_ReadMany (const json& args)
{
  if ( (! args.is_object ())                  ||
       (! args.contains ("reads"))            ||
       (! args.at        ("reads").is_array ()) ||
          args.at        ("reads").empty ()     ||
          args.at        ("reads").size  () > SK_MCP_ReadManyMaxEntries )
  {
    throw SK_MCP_ToolError {
      "reads is required and must be an array of 1 to " +
        std::to_string (SK_MCP_ReadManyMaxEntries) + " entries"
    };
  }

  const json& reads =
    args.at ("reads");

  const std::vector <SK_MCP_Module> modules =
    SK_MCP_EnumModules ();

  json   results = json::array ();
  size_t bytes   = SK_MCP_ReadManyWrapperBytes;

  for (size_t i = 0; i < reads.size (); ++i)
  {
    // Outside the try below: a cancel must end the call, not fill a slot.
    SK_MCP_CheckCancelled ();

    const json& entry =
      reads [i];

    json slot;

    try
    {
      if (! entry.is_object ())
        throw SK_MCP_ToolError { "each reads entry must be an object" };

      // The server does not enforce the schema's additionalProperties.
      for (auto it = entry.cbegin (); it != entry.cend (); ++it)
      {
        if (it.key () != "address" && it.key () != "type" &&
            it.key () != "count")
        {
          throw SK_MCP_ToolError {
            "unknown key '" + it.key () + "' in reads entry; expected "
            "address, type and count"
          };
        }
      }

      slot =
        SK_MCP_ReadEntry (entry, modules);
    }

    catch (const SK_MCP_ToolError& e)
    {
      const bool has_address =
        entry.is_object () && entry.contains ("address") &&
                              entry.at       ("address").is_string ();

      slot = {
        { "address", has_address ? entry.at ("address") : json (nullptr) },
        { "error",   e.message                                           }
      };
    }

    // Measured the way the server measures it: dumped, then escaped again.
    bytes +=
      json (slot.dump ()).dump ().size ();

    if (bytes > SK_MCP_ReadManyMaxBytes)
    {
      throw SK_MCP_ToolError {
        "batch result too large after " + std::to_string (i) + " of " +
          std::to_string (reads.size ()) + " reads; split the batch"
      };
    }

    results.push_back (std::move (slot));
  }

  return {
    { "results", results }
  };
}


//
// sk_write_memory
//

static json
SK_MCP_WriteMemory (const json& args)
{
  if ( (! args.is_object ())                     ||
       (! args.contains ("address"))             ||
       (! args.at        ("address").is_string ()) )
  {
    throw SK_MCP_ToolError { "address is required and must be a string" };
  }

  if ( (! args.contains ("type"))             ||
       (! args.at        ("type").is_string ()) )
  {
    throw SK_MCP_ToolError { "type is required and must be a string" };
  }

  const std::string type_text =
    args.at ("type").get <std::string> ();

  const uintptr_t      addr = SK_MCP_ParseAddress (args.at ("address").get <std::string> ());
  const SK_MCP_MemType type = SK_MCP_ParseMemType (type_text);

  const bool has_value  = args.contains ("value");
  const bool has_values = args.contains ("values");

  if (has_value == has_values)
    throw SK_MCP_ToolError { "exactly one of value or values is required" };

  bool terminate = false;

  if (args.contains ("terminate"))
  {
    if (! args.at ("terminate").is_boolean ())
      throw SK_MCP_ToolError { "terminate must be a boolean" };

    terminate = args.at ("terminate").get <bool> ();
  }

  const bool is_string_type =
    ( type == SK_MCP_MemType::CStr || type == SK_MCP_MemType::WStr ||
      type == SK_MCP_MemType::Hex );

  std::vector <uint8_t> bytes;

  if (is_string_type)
  {
    if (has_values)
    {
      throw SK_MCP_ToolError {
        "values is not valid for type '" + type_text + "'; use value"
      };
    }

    const json& v =
      args.at ("value");

    if (type == SK_MCP_MemType::Hex)
    {
      if (! v.is_string ())
        throw SK_MCP_ToolError { "value must be a hex string for type hex" };

      bytes = SK_MCP_HexToBytes (v.get <std::string> ());
    }

    else if (type == SK_MCP_MemType::CStr)
    {
      if (! v.is_string ())
        throw SK_MCP_ToolError { "value must be a string for type cstr" };

      const std::string s =
        v.get <std::string> ();

      bytes.assign (s.begin (), s.end ());

      if (terminate)
        bytes.push_back (0);
    }

    else   // WStr
    {
      if (! v.is_string ())
        throw SK_MCP_ToolError { "value must be a string for type wstr" };

      std::wstring wide =
        SK_UTF8ToWideChar (v.get <std::string> ());

      wide.resize (wcslen (wide.c_str ()));

      const uint8_t* p =
        (const uint8_t *)wide.data ();

      bytes.assign (p, p + wide.size () * sizeof (wchar_t));

      if (terminate)
      {
        bytes.push_back (0);
        bytes.push_back (0);
      }
    }
  }

  else
  {
    const size_t elem_size =
      SK_MCP_TypeElemSize (type);

    std::vector <json> elems;

    if (has_value)
    {
      elems.push_back (args.at ("value"));
    }

    else
    {
      if (! args.at ("values").is_array ())
        throw SK_MCP_ToolError { "values must be an array" };

      for (const auto& e : args.at ("values"))
        elems.push_back (e);
    }

    bytes.resize (elems.size () * elem_size);

    for (size_t i = 0; i < elems.size (); ++i)
    {
      uint8_t* dst =
        bytes.data () + i * elem_size;

      switch (type)
      {
        case SK_MCP_MemType::U8:  case SK_MCP_MemType::U16:
        case SK_MCP_MemType::U32: case SK_MCP_MemType::U64:
        case SK_MCP_MemType::I8:  case SK_MCP_MemType::I16:
        case SK_MCP_MemType::I32: case SK_MCP_MemType::I64:
        {
          const uint64_t v =
            SK_MCP_ParseIntValue (elems [i]);

          const std::string label =
            has_value ? std::string ("value")
                      : ("values[" + std::to_string (i) + "]");

          SK_MCP_CheckIntRange (type, v, label, type_text);

          memcpy (dst, &v, elem_size);

          break;
        }

        case SK_MCP_MemType::Ptr:
        {
          const uintptr_t v =
            SK_MCP_ParsePtrValue (elems [i]);

          memcpy (dst, &v, elem_size);

          break;
        }

        case SK_MCP_MemType::F32:
        {
          const float v =
            (float)SK_MCP_ParseFloatValue (elems [i]);

          memcpy (dst, &v, 4);

          break;
        }

        case SK_MCP_MemType::F64:
        {
          const double v =
            SK_MCP_ParseFloatValue (elems [i]);

          memcpy (dst, &v, 8);

          break;
        }

        default: break;
      }
    }
  }

  // The previous bytes are read before the write is attempted; a failed
  //   read here means the write never touches memory.
  std::vector <uint8_t> previous (bytes.size ());

  if (! previous.empty ())
    SK_MCP_SafeRead (addr, previous.data (), previous.size ());

  if (! bytes.empty ())
    SK_MCP_SafeWrite (addr, bytes.data (), bytes.size ());

  const std::vector <SK_MCP_Module> modules =
    SK_MCP_EnumModules ();

  return {
    { "address",  SK_MCP_FormatAddress (addr)                        },
    { "symbol",   SK_MCP_Symbolize (addr, modules)                   },
    { "bytes",    (uint64_t)bytes.size ()                            },
    { "previous", SK_MCP_BytesToHex (previous.data (), previous.size ()) },
    { "written",  SK_MCP_BytesToHex (bytes.data (),    bytes.size ()) }
  };
}


void
SK_MCP_RegisterMemoryTools (void)
{
  static const json type_enum = {
    "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64",
    "f32", "f64", "ptr", "cstr", "wstr", "hex"
  };

  SK_MCP_RegisterTool ({
    "sk_list_regions",
    "Lists the process's committed virtual memory regions, as 0x hex base addresses. "
    "Optionally restricted to a module's image range (module), and filtered by the "
    "letters the protection must include, from r, w and x, such as \"rw\" or \"x\" "
    "(protect), and by region type (region_type: image, private, mapped). A "
    "whole-process walk on x64 can return thousands of regions; pass module, "
    "protect or region_type to reach the interesting ones.",
    {
      { "type", "object" },
      { "properties",
        { { "module",   { { "type", "string" } } },
          { "protect",  { { "type", "string" } } },
          { "region_type",
                        { { "type",  "array" },
                          { "items", { { "type", "string" },
                                       { "enum", { "image", "private",
                                                   "mapped" } } } } } },
          { "max",      { { "type", "number" } } } }
      },
      { "additionalProperties", false }
    },
    SK_MCP_ListRegions
  });

  SK_MCP_RegisterTool ({
    "sk_read_memory",
    "Reads memory at address (0x hex, module+offset or a pointer chain like "
    "[game.exe+0x10]+8) and returns count elements of type. "
    "u8/u16/u32/u64/i8/i16/i32/i64/f32/f64 are numeric arrays; ptr returns address "
    "objects; cstr/wstr read a NUL-terminated string (wstr is UTF-16, "
    "returned as UTF-8, invalid data becomes U+FFFD); hex returns raw bytes. A bad "
    "address or unreadable page fails with an error naming it.",
    {
      { "type", "object" },
      { "properties",
        { { "address", { { "type", "string" } } },
          { "type",    { { "type", "string" }, { "enum", type_enum } } },
          { "count",   { { "type", "number" } } } }
      },
      { "required",             { "address", "type" } },
      { "additionalProperties", false                  }
    },
    SK_MCP_ReadMemory
  });

  SK_MCP_RegisterTool ({
    "sk_read_many",
    "Runs 1 to 256 sk_read_memory reads in one call. Each entry of reads takes "
    "sk_read_memory's address, type and count. results is in input order; each "
    "slot is what sk_read_memory would return, or {address, error} when that read "
    "failed, so one bad address does not fail the batch. All entries share one "
    "module snapshot. A batch whose result would exceed 768 KiB fails; split it.",
    {
      { "type", "object" },
      { "properties",
        { { "reads",
            { { "type",     "array" },
              { "minItems", 1       },
              { "maxItems", SK_MCP_ReadManyMaxEntries },
              { "items",
                { { "type", "object" },
                  { "properties",
                    { { "address", { { "type", "string" } } },
                      { "type",    { { "type", "string" }, { "enum", type_enum } } },
                      { "count",   { { "type", "number" } } } }
                  },
                  { "required",             { "address", "type" } },
                  { "additionalProperties", false                  }
                }
              } }
          } }
      },
      { "required",             { "reads" } },
      { "additionalProperties", false       }
    },
    SK_MCP_ReadMany
  });

  SK_MCP_RegisterTool ({
    "sk_write_memory",
    "Writes value (one element) or values (an array) of type to address (0x hex, "
    "module+offset or a pointer chain like [game.exe+0x10]+8); exactly one of "
    "value/values is required. Integers accept numbers or hex strings, f32/f64 accept numbers or numeric strings (3, 3.0 and "
    "\"3.0\" are the same value), ptr takes a hex/module+offset string, cstr/wstr "
    "take one string (terminate adds a NUL), hex takes one hex string. Writing the "
    "wrong bytes can crash or corrupt the game. A multi-page write is not atomic "
    "and can tear if another thread is executing the target code; previous holds "
    "the bytes from before the write, and writing them back with type hex undoes it. "
    "Concurrent writes to the same page from two calls can leave its protection "
    "widened.",
    {
      { "type", "object" },
      { "properties",
        { { "address",   { { "type", "string" } } },
          { "type",      { { "type", "string" }, { "enum", type_enum } } },
          { "value",     json::object ()             },
          { "values",    { { "type", "array" } }      },
          { "terminate", { { "type", "boolean" } }    } }
      },
      { "required",             { "address", "type" } },
      { "additionalProperties", false                  }
    },
    SK_MCP_WriteMemory
  });
}
