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
#include <cctype>
#include <cstring>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

using json = nlohmann::json;


//
// Scope: a module's image range, start + size, or the whole user address
//   space.  sk_pattern_scan and sk_value_scan_start share it; exactly one form
//   is legal.
//

static void
SK_MCP_ParseScanScope ( const json& args,
                        uintptr_t&  scope_start,
                        uintptr_t&  scope_end )
{
  const bool has_module = args.is_object () && args.contains ("module");
  const bool has_start  = args.is_object () && args.contains ("start");
  const bool has_size   = args.is_object () && args.contains ("size");
  const bool has_all    = args.is_object () && args.contains ("all");

  const int forms =
    (int)has_module + (int)(has_start || has_size) + (int)has_all;

  if (forms != 1 || (has_start != has_size))
  {
    throw SK_MCP_ToolError {
      "pass exactly one of module, start and size, or all"
    };
  }

  if (has_all)
  {
    if ( (! args.at ("all").is_boolean ()) ||
         (! args.at ("all").get <bool> ()) )
    {
      throw SK_MCP_ToolError { "all must be true when passed" };
    }

    SYSTEM_INFO si = { };
    SK_GetSystemInfo (&si);

    scope_start = (uintptr_t)si.lpMinimumApplicationAddress;
    scope_end   = (uintptr_t)si.lpMaximumApplicationAddress + 1;

    return;
  }

  if (has_module)
  {
    if (! args.at ("module").is_string ())
      throw SK_MCP_ToolError { "module must be a string" };

    const std::string name =
      args.at ("module").get <std::string> ();

    const auto mod =
      SK_MCP_FindModule (name);

    if (! mod.has_value ())
      throw SK_MCP_ToolError { "module '" + name + "' is not loaded" };

    scope_start = mod->base;
    scope_end   = mod->base + mod->size;

    return;
  }

  if (! args.at ("start").is_string ())
    throw SK_MCP_ToolError { "start must be an address string" };

  if (! args.at ("size").is_number ())
    throw SK_MCP_ToolError { "size must be a number" };

  const double size_arg =
    args.at ("size").get <double> ();

  if (! (size_arg > 0.0))
    throw SK_MCP_ToolError { "size must be greater than zero" };

  scope_start =
    SK_MCP_ParseAddress (args.at ("start").get <std::string> ());

  // Anything past the top of the address space is clamped to it rather than
  //   wrapping around to a lower address.
  const uint64_t remaining =
    (uint64_t)(~(uintptr_t)0 - scope_start);

  const uint64_t size_bytes =
    (size_arg >= (double)remaining) ? remaining
                                    : (uint64_t)size_arg;

  scope_end =
    scope_start + (uintptr_t)size_bytes;

  if (scope_end <= scope_start)
    throw SK_MCP_ToolError { "size must be greater than zero" };
}


// Walks the committed, readable part of [start, end), clipped to the scope,
//   one region at a time, by §4.1's stepping rules, skipping regions filter
//   rejects.  fn returns false to stop the walk.
template <typename Fn>
static void
SK_MCP_ForEachScanRegion ( uintptr_t                  start,
                           uintptr_t                  end,
                           const SK_MCP_RegionFilter& filter,
                           Fn                         fn )
{
  uintptr_t addr = start;

  for (;;)
  {
    MEMORY_BASIC_INFORMATION mbi = { };

    if (0 == VirtualQuery ((LPCVOID)addr, &mbi, sizeof (mbi)))
      break;

    const uintptr_t next =
      (uintptr_t)mbi.BaseAddress + mbi.RegionSize;

    const bool readable =
      ( mbi.State                == MEM_COMMIT     &&
       (mbi.Protect & 0xFF)      != PAGE_NOACCESS  &&
       (mbi.Protect & PAGE_GUARD) == 0 );

    if (readable && filter.Matches (mbi))
    {
      // addr is the scope start on the first step (possibly mid-region) and
      //   the region base on every one after it.
      const uintptr_t chunk_start = addr;
      const uintptr_t chunk_end   = std::min (next, end);

      if (chunk_start < chunk_end)
      {
        if (! fn (chunk_start, chunk_end))
          return;
      }
    }

    if (next >= end)
      break;

    // A stalled or wrapped walk would otherwise spin forever.
    if (next <= addr)
      break;

    addr = next;
  }
}

static size_t
SK_MCP_PageSize (void)
{
  SYSTEM_INFO si = { };
  SK_GetSystemInfo (&si);

  return
    (size_t)si.dwPageSize;
}

// Optional "max", with the tool's default and cap.
static size_t
SK_MCP_ParseMax (const json& args, size_t def, size_t cap)
{
  if ( (! args.is_object ()) || (! args.contains ("max")))
    return def;

  if (! args.at ("max").is_number ())
    throw SK_MCP_ToolError { "max must be a number" };

  const double m =
    args.at ("max").get <double> ();

  if (m < 0.0)
    throw SK_MCP_ToolError { "max must not be negative" };

  return
    (size_t)std::min (m, (double)cap);
}


//
// §4.6 sk_pattern_scan
//

struct SK_MCP_PatternByte {
  uint8_t value;
  bool    wildcard;
};

static std::vector <SK_MCP_PatternByte>
SK_MCP_ParsePattern (const std::string& text)
{
  std::vector <SK_MCP_PatternByte> pattern;

  size_t       pos   = 0;
  const size_t len   = text.size ();
  bool         fixed = false;

  while (pos < len)
  {
    while (pos < len && isspace ((unsigned char)text [pos]))
      ++pos;

    if (pos >= len)
      break;

    size_t tok_end = pos;

    while (tok_end < len && (! isspace ((unsigned char)text [tok_end])))
      ++tok_end;

    const std::string token =
      text.substr (pos, tok_end - pos);

    pos = tok_end;

    if (token == "?" || token == "??")
    {
      pattern.push_back ({ 0, true });
      continue;
    }

    uint8_t value = 0;
    bool    good  = (token.size () == 2);

    for (size_t i = 0; good && i < token.size (); ++i)
    {
      const unsigned char c = (unsigned char)token [i];

      int digit;

      if      (c >= '0' && c <= '9') digit = c - '0';
      else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
      else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
      else                         { good  = false; break; }

      value = (uint8_t)((value << 4) | (uint8_t)digit);
    }

    if (! good)
    {
      throw SK_MCP_ToolError {
        "invalid pattern byte '" + token + "'; expected two hex digits, "
        "or ? / ?? for a wildcard"
      };
    }

    pattern.push_back ({ value, false });

    fixed = true;
  }

  if (pattern.empty ())
    throw SK_MCP_ToolError { "pattern is empty" };

  if (! fixed)
  {
    throw SK_MCP_ToolError {
      "pattern '" + text + "' is all wildcards; at least one byte must be fixed"
    };
  }

  return pattern;
}

// Bytes that fill code and data too densely to make a useful memchr anchor:
//   zero and fill bytes, int3 and nop padding, and the REX.W / mov opcodes
//   that start a large share of x64 instructions.
static bool
SK_MCP_IsCommonByte (uint8_t value)
{
  switch (value)
  {
    case 0x00: case 0xFF: case 0xCC: case 0x90:
    case 0x48: case 0x8B: case 0x89:
      return true;
    default:
      return false;
  }
}

static json
SK_MCP_PatternScan (const json& args)
{
  const ULONGLONG started =
    GetTickCount64 ();

  if ( (! args.is_object ())                     ||
       (! args.contains ("pattern"))             ||
       (! args.at        ("pattern").is_string ()) )
  {
    throw SK_MCP_ToolError { "pattern is required and must be a string" };
  }

  const std::vector <SK_MCP_PatternByte> pattern =
    SK_MCP_ParsePattern (args.at ("pattern").get <std::string> ());

  uintptr_t scope_start = 0,
            scope_end   = 0;

  SK_MCP_ParseScanScope (args, scope_start, scope_end);

  const SK_MCP_RegionFilter filter =
    SK_MCP_ParseRegionFilter (args);

  const size_t max_count =
    SK_MCP_ParseMax (args, 64, 1024);

  const size_t pat_len =
    pattern.size ();

  // A wildcard has mask 0 and value 0, so (byte & mask) == value holds for it.
  std::vector <uint8_t> value (pat_len),
                        mask  (pat_len);

  for (size_t i = 0; i < pat_len; ++i)
  {
    value [i] = pattern [i].wildcard ? 0x00 : pattern [i].value;
    mask  [i] = pattern [i].wildcard ? 0x00 : 0xFF;
  }

  // The anchor is the fixed byte memchr searches for; every match has it at
  //   offset anchor from the match start.  SK_MCP_ParsePattern guarantees at
  //   least one fixed byte.
  size_t anchor = pat_len;

  for (size_t i = 0; i < pat_len; ++i)
  {
    if (mask [i] != 0 && (! SK_MCP_IsCommonByte (value [i])))
    {
      anchor = i;
      break;
    }
  }

  if (anchor == pat_len)
  {
    for (size_t i = 0; i < pat_len; ++i)
    {
      if (mask [i] != 0)
      {
        anchor = i;
        break;
      }
    }
  }

  const int anchor_value =
    value [anchor];

  // Chunks never cross a region's end and overlap by pattern length - 1, so a
  //   match spanning two chunks of the same region is found exactly once.
  const size_t chunk_max =
    std::max <size_t> (1024 * 1024, pat_len);

  std::vector <uint8_t> buf (chunk_max);
  std::vector <uintptr_t> hits;

  bool     truncated     = false;
  uint64_t bytes_scanned = 0;

  SK_MCP_ForEachScanRegion ( scope_start, scope_end, filter,
    [&](uintptr_t region_start, uintptr_t region_end) -> bool
    {
      uintptr_t scan_pos = region_start;

      while (scan_pos + pat_len <= region_end)
      {
        const size_t chunk_len =
          (size_t)std::min <uint64_t> ( (uint64_t)chunk_max,
                                        (uint64_t)(region_end - scan_pos) );

        if (chunk_len < pat_len)
          break;

        SK_MCP_CheckCancelled ();

        try
        {
          SK_MCP_SafeRead (scan_pos, buf.data (), chunk_len);
        }

        catch (const SK_MCP_ToolError&)
        {
          // The region went away underneath the walk; skip the rest of it.
          return true;
        }

        bytes_scanned += chunk_len;

        // Match starts are [0, last_off], so their anchors are
        //   [anchor, last_off + anchor]; memchr visits them in ascending order.
        const size_t last_off =
          chunk_len - pat_len;

        const uint8_t* const data   = buf.data ();
        const uint8_t*       search = data + anchor;
        const uint8_t* const limit  = data + last_off + anchor + 1;

        while (search < limit)
        {
          const uint8_t* hit =
            (const uint8_t*)memchr ( search, anchor_value,
                                     (size_t)(limit - search) );

          if (hit == nullptr)
            break;

          search = hit + 1;

          const size_t   off = (size_t)(hit - data) - anchor;
          const uint8_t* p   = data + off;

          bool match = true;

          for (size_t i = 0; i < pat_len; ++i)
          {
            if ((p [i] & mask [i]) != value [i])
            {
              match = false;
              break;
            }
          }

          if (match)
          {
            if (hits.size () >= max_count)
            {
              truncated = true;
              return false;
            }

            hits.push_back (scan_pos + off);
          }
        }

        if (scan_pos + chunk_len >= region_end)
          break;

        scan_pos += chunk_len - (pat_len - 1);
      }

      return true;
    } );

  const std::vector <SK_MCP_Module> modules =
    SK_MCP_EnumModules ();

  json matches = json::array ();

  for (uintptr_t hit : hits)
  {
    matches.push_back ({
      { "address", SK_MCP_FormatAddress (hit)      },
      { "symbol",  SK_MCP_Symbolize (hit, modules) }
    });
  }

  return {
    { "matches",       matches                                 },
    { "truncated",     truncated                               },
    { "bytes_scanned", bytes_scanned                           },
    { "elapsed_ms",    (uint64_t)(GetTickCount64 () - started) }
  };
}


//
// §4.7 value scan sessions
//

enum class SK_MCP_ScanType {
  U8, U16, U32, U64,
  I8, I16, I32, I64,
  F32, F64,
  Ptr
};

enum class SK_MCP_ScanCompare {
  Equal, NotEqual, Greater, Less,
  Changed, Unchanged, Increased, Decreased,
  Unknown
};

struct SK_MCP_Snapshot {
  uintptr_t              base;
  std::vector <uint8_t>  bytes;   // The region's readable bytes at snapshot time
  std::vector <uint64_t> alive;   // One bit per aligned element
};

struct SK_MCP_Candidate {
  uintptr_t addr;
  uint64_t  last;                 // Element bytes, zero-extended
};

struct SK_MCP_ScanSession {
  SK_MCP_ScanType                type      = SK_MCP_ScanType::U32;
  size_t                         alignment = 4;
  // Exactly one of the two is populated.
  std::vector <SK_MCP_Snapshot>  snapshot;
  std::vector <SK_MCP_Candidate> candidates;
};

struct SK_MCP_ScanEntry {
  SK_MCP_ScanSession session;
  uint64_t           owner    = 0;      // SK_MCP_CurrentClientId of its start
  size_t             held     = 0;      // What it is charged against the budget
  // A busy session belongs to the one call using it: no other call reads or
  //   erases it, and that call erases it on exit once it is orphaned.
  bool               busy     = false;
  bool               orphaned = false;  // Its owner disconnected while busy
};

// Tool calls run on several workers at once.  SK_MCP_ScanLock guards
//   everything below, and only around bookkeeping, never across a scan; a
//   busy entry's session is used outside it.  Map nodes are stable, so a busy
//   entry stays put while other entries come and go.
static SK_Thread_HybridSpinlock          SK_MCP_ScanLock;
static std::map <int, SK_MCP_ScanEntry>  SK_MCP_ScanSessions;
static int                               SK_MCP_NextScanSession   = 1;
// Session slots taken by starts that have not stored their session yet.
static size_t                            SK_MCP_ScanSlotsReserved = 0;
// The sum of every stored entry's held, and the growth that calls in progress
//   have reserved but not yet stored.
static size_t                            SK_MCP_ScanHeldBytes     = 0;
static size_t                            SK_MCP_ScanReservedBytes = 0;

static constexpr size_t SK_MCP_MaxScanSessions = 8;

static constexpr size_t SK_MCP_ScanBudgetBytes =
#ifdef _WIN64
  256 * 1024 * 1024;
#else
   32 * 1024 * 1024;
#endif

// Re-reads are done in runs of at most this many bytes, one VirtualQuery and
//   one SK_MCP_SafeRead each.
static constexpr size_t SK_MCP_ScanRunBytes = 1024 * 1024;

static size_t
SK_MCP_ScanTypeSize (SK_MCP_ScanType type)
{
  switch (type)
  {
    case SK_MCP_ScanType::U8:
    case SK_MCP_ScanType::I8:  return 1;
    case SK_MCP_ScanType::U16:
    case SK_MCP_ScanType::I16: return 2;
    case SK_MCP_ScanType::U32:
    case SK_MCP_ScanType::I32:
    case SK_MCP_ScanType::F32: return 4;
    case SK_MCP_ScanType::U64:
    case SK_MCP_ScanType::I64:
    case SK_MCP_ScanType::F64: return 8;
    default:                   return sizeof (uintptr_t);
  }
}

static SK_MCP_ScanType
SK_MCP_ParseScanType (const std::string& text)
{
  if (text == "u8")  return SK_MCP_ScanType::U8;
  if (text == "u16") return SK_MCP_ScanType::U16;
  if (text == "u32") return SK_MCP_ScanType::U32;
  if (text == "u64") return SK_MCP_ScanType::U64;
  if (text == "i8")  return SK_MCP_ScanType::I8;
  if (text == "i16") return SK_MCP_ScanType::I16;
  if (text == "i32") return SK_MCP_ScanType::I32;
  if (text == "i64") return SK_MCP_ScanType::I64;
  if (text == "f32") return SK_MCP_ScanType::F32;
  if (text == "f64") return SK_MCP_ScanType::F64;
  if (text == "ptr") return SK_MCP_ScanType::Ptr;

  throw SK_MCP_ToolError {
    "invalid type '" + text + "'; expected one of u8, u16, u32, u64, i8, i16, "
    "i32, i64, f32, f64, ptr"
  };
}

static SK_MCP_ScanCompare
SK_MCP_ParseScanCompare (const std::string& text, bool starting)
{
  if (starting)
  {
    if (text == "equal")   return SK_MCP_ScanCompare::Equal;
    if (text == "unknown") return SK_MCP_ScanCompare::Unknown;

    throw SK_MCP_ToolError {
      "invalid compare '" + text + "'; expected equal or unknown"
    };
  }

  if (text == "equal")     return SK_MCP_ScanCompare::Equal;
  if (text == "not_equal") return SK_MCP_ScanCompare::NotEqual;
  if (text == "greater")   return SK_MCP_ScanCompare::Greater;
  if (text == "less")      return SK_MCP_ScanCompare::Less;
  if (text == "changed")   return SK_MCP_ScanCompare::Changed;
  if (text == "unchanged") return SK_MCP_ScanCompare::Unchanged;
  if (text == "increased") return SK_MCP_ScanCompare::Increased;
  if (text == "decreased") return SK_MCP_ScanCompare::Decreased;

  throw SK_MCP_ToolError {
    "invalid compare '" + text + "'; expected one of equal, not_equal, "
    "greater, less, changed, unchanged, increased, decreased"
  };
}

// The first four compare against the value argument, the last four against
//   the element's previous bytes.
static bool
SK_MCP_CompareNeedsValue (SK_MCP_ScanCompare op)
{
  return
    ( op == SK_MCP_ScanCompare::Equal   ||
      op == SK_MCP_ScanCompare::NotEqual ||
      op == SK_MCP_ScanCompare::Greater  ||
      op == SK_MCP_ScanCompare::Less );
}


//
// Value parsing: numbers or 0x hex strings for integers, address strings for
//   ptr, numbers for floats.  The result is the element's byte image,
//   zero-extended into a uint64_t.
//

static uint64_t
SK_MCP_ParseScanInt (const json& v)
{
  if (v.is_number_unsigned ())
    return v.get <uint64_t> ();

  if (v.is_number_integer ())
    return (uint64_t)v.get <int64_t> ();

  if (v.is_number_float ())
    throw SK_MCP_ToolError { "value must be a whole number, not a float" };

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
          throw SK_MCP_ToolError { "invalid hex value '" + s + "'" };

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

  throw SK_MCP_ToolError { "value must be a number or a hex string" };
}

// Rejects a parsed integer that does not fit in type's element size, signed or
//   unsigned as the type demands, instead of silently truncating it.
static void
SK_MCP_CheckScanIntRange ( SK_MCP_ScanType    type,
                           uint64_t           raw,
                           const std::string& type_text )
{
  const size_t elem_size =
    SK_MCP_ScanTypeSize (type);

  if (elem_size >= 8)
    return;

  const bool is_signed =
    ( type == SK_MCP_ScanType::I8 || type == SK_MCP_ScanType::I16 ||
      type == SK_MCP_ScanType::I32 );

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
      (bits >= 64) ? 0xFFFFFFFFFFFFFFFFULL
                   : ((1ULL << bits) - 1);

    in_range = (raw <= max_val);
  }

  if (! in_range)
  {
    char szDecimal [32] = { };

    if (is_signed)
      snprintf (szDecimal, sizeof (szDecimal), "%lld", (long long)(int64_t)raw);
    else
      snprintf (szDecimal, sizeof (szDecimal), "%llu", (unsigned long long)raw);

    throw SK_MCP_ToolError {
      std::string ("value = ") + szDecimal + " does not fit in " + type_text
    };
  }
}

static uint64_t
SK_MCP_ParseScanValue ( const json&        v,
                        SK_MCP_ScanType    type,
                        const std::string& type_text )
{
  const size_t elem_size =
    SK_MCP_ScanTypeSize (type);

  switch (type)
  {
    case SK_MCP_ScanType::F32:
    {
      const float   f = (float)SK_MCP_ParseFloatValue (v);
      uint32_t bits32 = 0;

      memcpy (&bits32, &f, sizeof (bits32));

      return (uint64_t)bits32;
    }

    case SK_MCP_ScanType::F64:
    {
      const double  d = SK_MCP_ParseFloatValue (v);
      uint64_t bits64 = 0;

      memcpy (&bits64, &d, sizeof (bits64));

      return bits64;
    }

    case SK_MCP_ScanType::Ptr:
    {
      if (! v.is_string ())
        throw SK_MCP_ToolError { "value must be an address string for type ptr" };

      return
        (uint64_t)SK_MCP_ParseAddress (v.get <std::string> ());
    }

    default:
      break;
  }

  const uint64_t raw =
    SK_MCP_ParseScanInt (v);

  SK_MCP_CheckScanIntRange (type, raw, type_text);

  if (elem_size >= 8)
    return raw;

  return
    raw & ((1ULL << (elem_size * 8)) - 1);
}

static int64_t
SK_MCP_SignExtend (uint64_t bits, size_t elem_size)
{
  if (elem_size >= 8)
    return (int64_t)bits;

  const unsigned shift =
    (unsigned)(64 - elem_size * 8);

  return
    ((int64_t)(bits << shift)) >> shift;
}

// a is the element's current bytes, b the value argument or the element's
//   previous bytes; both zero-extended.
//
// equal and not_equal compare floats as floats and exactly, so a NaN element
//   never equals anything, including itself.  changed and unchanged compare
//   the stored bit pattern instead, so an element that is still the NaN it
//   was reads as unchanged and can be eliminated; ordered comparisons stay
//   numeric for every type.
static bool
SK_MCP_ScanCompareBits ( SK_MCP_ScanType    type,
                         SK_MCP_ScanCompare op,
                         uint64_t           a,
                         uint64_t           b )
{
  bool eq = false,
       gt = false,
       lt = false;

  // Both operands are zero-extended from the same element size, so this is a
  //   memcmp of the element's bytes.  For every type but f32 and f64 it is
  //   the same answer eq gives.
  const bool bits_eq =
    (a == b);

  switch (type)
  {
    case SK_MCP_ScanType::F32:
    {
      const uint32_t a32 = (uint32_t)a,
                     b32 = (uint32_t)b;

      float fa = 0.0f,
            fb = 0.0f;

      memcpy (&fa, &a32, sizeof (fa));
      memcpy (&fb, &b32, sizeof (fb));

      eq = (fa == fb); gt = (fa > fb); lt = (fa < fb);
      break;
    }

    case SK_MCP_ScanType::F64:
    {
      double da = 0.0,
             db = 0.0;

      memcpy (&da, &a, sizeof (da));
      memcpy (&db, &b, sizeof (db));

      eq = (da == db); gt = (da > db); lt = (da < db);
      break;
    }

    case SK_MCP_ScanType::I8:
    case SK_MCP_ScanType::I16:
    case SK_MCP_ScanType::I32:
    case SK_MCP_ScanType::I64:
    {
      const size_t elem_size =
        SK_MCP_ScanTypeSize (type);

      const int64_t ia = SK_MCP_SignExtend (a, elem_size),
                    ib = SK_MCP_SignExtend (b, elem_size);

      eq = (ia == ib); gt = (ia > ib); lt = (ia < ib);
      break;
    }

    default:
    {
      eq = (a == b); gt = (a > b); lt = (a < b);
      break;
    }
  }

  switch (op)
  {
    case SK_MCP_ScanCompare::Equal:     return   eq;
    case SK_MCP_ScanCompare::NotEqual:  return ! eq;
    case SK_MCP_ScanCompare::Unchanged: return   bits_eq;
    case SK_MCP_ScanCompare::Changed:   return ! bits_eq;
    case SK_MCP_ScanCompare::Greater:
    case SK_MCP_ScanCompare::Increased: return   gt;
    case SK_MCP_ScanCompare::Less:
    case SK_MCP_ScanCompare::Decreased: return   lt;
    default:                            return false;
  }
}

static json
SK_MCP_ScanValueJson (SK_MCP_ScanType type, uint64_t bits)
{
  switch (type)
  {
    case SK_MCP_ScanType::F32:
    {
      const uint32_t bits32 = (uint32_t)bits;
      float          f      = 0.0f;

      memcpy (&f, &bits32, sizeof (f));

      return f;
    }

    case SK_MCP_ScanType::F64:
    {
      double d = 0.0;

      memcpy (&d, &bits, sizeof (d));

      return d;
    }

    case SK_MCP_ScanType::Ptr:
      return SK_MCP_FormatAddress ((uintptr_t)bits);

    case SK_MCP_ScanType::I8:
    case SK_MCP_ScanType::I16:
    case SK_MCP_ScanType::I32:
    case SK_MCP_ScanType::I64:
      return SK_MCP_SignExtend (bits, SK_MCP_ScanTypeSize (type));

    default:
      return bits;
  }
}

static uint64_t
SK_MCP_LoadBits (const uint8_t* p, size_t elem_size)
{
  uint64_t bits = 0;

  memcpy (&bits, p, elem_size);

  return bits;
}


//
// Storage accounting.  One global budget across every session: the bytes
//   stored sessions hold plus the growth calls in progress have reserved.  A
//   call reserves each growth before allocating it, so the peak during a next
//   counts the session's old storage and the new storage being built, because
//   the old one is only freed at the end.
//

// Capacity, not size: that is what the session keeps allocated.
static size_t
SK_MCP_SessionBytes (const SK_MCP_ScanSession& session)
{
  size_t total =
    session.candidates.capacity () * sizeof (SK_MCP_Candidate);

  for (const auto& snap : session.snapshot)
  {
    total += snap.bytes.capacity ()                        +
             snap.alive.capacity () * sizeof (uint64_t);
  }

  return total;
}

// One call's reservations.  Whatever is still reserved when it goes out of
//   scope is released; storing a session converts it to held instead.
struct SK_MCP_ScanReservation {
  size_t bytes = 0;

  SK_MCP_ScanReservation            (void)                          = default;
  SK_MCP_ScanReservation            (const SK_MCP_ScanReservation&) = delete;
  SK_MCP_ScanReservation& operator= (const SK_MCP_ScanReservation&) = delete;

  ~SK_MCP_ScanReservation (void)
  {
    if (bytes == 0)
      return;

    std::scoped_lock lock (SK_MCP_ScanLock);

    SK_MCP_ScanReservedBytes -= bytes;
  }

  // Whether delta fits in the budget; reserves it if so.
  bool TryReserve (size_t delta, size_t* used_out = nullptr)
  {
    std::scoped_lock lock (SK_MCP_ScanLock);

    const size_t used =
      SK_MCP_ScanHeldBytes + SK_MCP_ScanReservedBytes + delta;

    if (used_out != nullptr)
       *used_out = used;

    if (used > SK_MCP_ScanBudgetBytes)
      return false;

    SK_MCP_ScanReservedBytes += delta;
    bytes                    += delta;

    return true;
  }

  void Reserve (size_t delta)
  {
    size_t used = 0;

    if (! TryReserve (delta, &used))
    {
      throw SK_MCP_ToolError {
        "scan budget exceeded (" + std::to_string (used) + " of " +
        std::to_string (SK_MCP_ScanBudgetBytes) + " bytes); narrow the scope, "
        "scan for a known value, or end other sessions"
      };
    }
  }

  void Release (size_t delta)
  {
    std::scoped_lock lock (SK_MCP_ScanLock);

    SK_MCP_ScanReservedBytes -= delta;
    bytes                    -= delta;
  }

  // SK_MCP_ScanLock must be held.  Hands the reservation back; the caller
  //   charges the stored session's bytes to SK_MCP_ScanHeldBytes instead.
  void ConvertLocked (void)
  {
    SK_MCP_ScanReservedBytes -= bytes;
    bytes                     = 0;
  }
};

// Appends one candidate, raising capacity in fixed blocks and reserving each
//   raise against the budget first, so the growth is bounded and accounted
//   for.
static void
SK_MCP_PushCandidate ( std::vector <SK_MCP_Candidate>& out,
                       const SK_MCP_Candidate&         candidate,
                       SK_MCP_ScanReservation&         budget )
{
  if (out.size () == out.capacity ())
  {
    const size_t grow = 65536;

    budget.Reserve (grow * sizeof (SK_MCP_Candidate));

    out.reserve (out.capacity () + grow);
  }

  out.push_back (candidate);
}


//
// Session bookkeeping.  Each helper takes SK_MCP_ScanLock itself and throws
//   only after releasing it.
//

static std::string
SK_MCP_UnknownSessionMessage (int id)
{
  return
    "unknown scan session " + std::to_string (id) + "; sessions belong to "
    "the client that started them and are dropped when it disconnects";
}

// One of the session slots, reserved by a start until it stores its session.
struct SK_MCP_ScanSlot {
  bool reserved = false;

  SK_MCP_ScanSlot (void)
  {
    {
      std::scoped_lock lock (SK_MCP_ScanLock);

      if ( SK_MCP_ScanSessions.size () + SK_MCP_ScanSlotsReserved <
             SK_MCP_MaxScanSessions )
      {
        ++SK_MCP_ScanSlotsReserved;

        reserved = true;
      }
    }

    if (! reserved)
      throw SK_MCP_ToolError { "too many scan sessions; end one first" };
  }

  SK_MCP_ScanSlot            (const SK_MCP_ScanSlot&) = delete;
  SK_MCP_ScanSlot& operator= (const SK_MCP_ScanSlot&) = delete;

  ~SK_MCP_ScanSlot (void)
  {
    if (! reserved)
      return;

    std::scoped_lock lock (SK_MCP_ScanLock);

    --SK_MCP_ScanSlotsReserved;
  }

  // SK_MCP_ScanLock must be held.  The stored session now takes the slot.
  void ConvertLocked (void)
  {
    --SK_MCP_ScanSlotsReserved;

    reserved = false;
  }
};

// Marks the caller's session id busy and returns it.  Fails with the unknown
//   session message when it does not exist or belongs to another client.
static SK_MCP_ScanEntry&
SK_MCP_AcquireSession (int id)
{
  SK_MCP_ScanEntry* entry = nullptr;
  bool              busy  = false;

  {
    std::scoped_lock lock (SK_MCP_ScanLock);

    const auto it =
      SK_MCP_ScanSessions.find (id);

    if ( it != SK_MCP_ScanSessions.end () &&
         it->second.owner == SK_MCP_CurrentClientId () )
    {
      busy = it->second.busy;

      if (! busy)
      {
        it->second.busy = true;

        entry = &it->second;
      }
    }
  }

  if (busy)
  {
    throw SK_MCP_ToolError {
      "session " + std::to_string (id) + " is busy with another call"
    };
  }

  if (entry == nullptr)
    throw SK_MCP_ToolError { SK_MCP_UnknownSessionMessage (id) };

  return *entry;
}

// Clears a busy session on exit, or erases it when its owner has
//   disconnected meanwhile or the call asked for that.
struct SK_MCP_ScanBusy {
  int  id;
  bool erase              = false;
  bool erase_if_cancelled = false;

  explicit SK_MCP_ScanBusy (int id_) : id (id_) { }

  SK_MCP_ScanBusy            (const SK_MCP_ScanBusy&) = delete;
  SK_MCP_ScanBusy& operator= (const SK_MCP_ScanBusy&) = delete;

  ~SK_MCP_ScanBusy (void)
  {
    // Declared before the lock, so the storage is freed after it is released.
    decltype (SK_MCP_ScanSessions)::node_type doomed;

    std::scoped_lock lock (SK_MCP_ScanLock);

    const auto it =
      SK_MCP_ScanSessions.find (id);

    if (it == SK_MCP_ScanSessions.end ())
      return;

    if ( erase || it->second.orphaned ||
         (erase_if_cancelled && SK_MCP_IsCancelled ()) )
    {
      SK_MCP_ScanHeldBytes -= it->second.held;

      doomed =
        SK_MCP_ScanSessions.extract (it);
    }

    else
      it->second.busy = false;
  }
};

// Recharges a busy session's held bytes after its storage changed.
static void
SK_MCP_RechargeSession ( SK_MCP_ScanEntry&       entry,
                         SK_MCP_ScanReservation& budget )
{
  const size_t held =
    SK_MCP_SessionBytes (entry.session);

  std::scoped_lock lock (SK_MCP_ScanLock);

  SK_MCP_ScanHeldBytes -= entry.held;
  SK_MCP_ScanHeldBytes += held;
  entry.held            = held;

  budget.ConvertLocked ();
}


//
// Snapshot element addressing: element i lives at base + i * alignment and at
//   offset i * alignment in bytes.
//

static size_t
SK_MCP_SnapshotElements ( const SK_MCP_Snapshot& snap,
                          size_t alignment, size_t elem_size )
{
  if (snap.bytes.size () < elem_size)
    return 0;

  return
    (snap.bytes.size () - elem_size) / alignment + 1;
}

static bool
SK_MCP_IsAlive (const SK_MCP_Snapshot& snap, size_t index)
{
  return
    ((snap.alive [index >> 6] >> (index & 63)) & 1ULL) != 0;
}

static void
SK_MCP_ClearAlive (SK_MCP_Snapshot& snap, size_t index)
{
  snap.alive [index >> 6] &= ~(1ULL << (index & 63));
}


//
// Result shape, shared by start and next.
//

static json
SK_MCP_ScanResult (int id, const SK_MCP_ScanSession& session, size_t max_count)
{
  const size_t elem_size =
    SK_MCP_ScanTypeSize (session.type);

  const std::vector <SK_MCP_Module> modules =
    SK_MCP_EnumModules ();

  json   candidates = json::array ();
  size_t count      = 0;

  auto emit =
  [&](uintptr_t addr, uint64_t bits)
  {
    ++count;

    if (candidates.size () >= max_count)
      return;

    candidates.push_back ({
      { "address", SK_MCP_FormatAddress (addr)          },
      { "symbol",  SK_MCP_Symbolize (addr, modules)     },
      { "value",   SK_MCP_ScanValueJson (session.type, bits) }
    });
  };

  if (! session.snapshot.empty ())
  {
    for (const auto& snap : session.snapshot)
    {
      const size_t elements =
        SK_MCP_SnapshotElements (snap, session.alignment, elem_size);

      for (size_t i = 0; i < elements; ++i)
      {
        if (! SK_MCP_IsAlive (snap, i))
          continue;

        const size_t offset =
          i * session.alignment;

        emit ( snap.base + (uintptr_t)offset,
               SK_MCP_LoadBits (snap.bytes.data () + offset, elem_size) );
      }
    }
  }

  else
  {
    for (const auto& candidate : session.candidates)
      emit (candidate.addr, candidate.last);
  }

  return {
    { "session",    id                                },
    { "count",      (uint64_t)count                   },
    { "truncated",  candidates.size () < count        },
    { "candidates", candidates                        }
  };
}


//
// sk_value_scan_start
//

static json
SK_MCP_ValueScanStart (const json& args)
{
  const ULONGLONG started =
    GetTickCount64 ();

  if ( (! args.is_object ())                  ||
       (! args.contains ("type"))             ||
       (! args.at        ("type").is_string ()) )
  {
    throw SK_MCP_ToolError { "type is required and must be a string" };
  }

  if ( (! args.contains ("compare"))             ||
       (! args.at        ("compare").is_string ()) )
  {
    throw SK_MCP_ToolError { "compare is required and must be a string" };
  }

  const std::string type_text =
    args.at ("type").get <std::string> ();

  const SK_MCP_ScanType type =
    SK_MCP_ParseScanType (type_text);

  const SK_MCP_ScanCompare compare =
    SK_MCP_ParseScanCompare (args.at ("compare").get <std::string> (), true);

  const size_t elem_size =
    SK_MCP_ScanTypeSize (type);

  size_t alignment = elem_size;

  if (args.contains ("alignment"))
  {
    if (! args.at ("alignment").is_number ())
      throw SK_MCP_ToolError { "alignment must be a number" };

    const double a =
      args.at ("alignment").get <double> ();

    if (a < 1.0 || a > 4096.0)
      throw SK_MCP_ToolError { "alignment must be a power of two from 1 to 4096" };

    alignment = (size_t)a;

    if ((double)alignment != a || (alignment & (alignment - 1)) != 0)
      throw SK_MCP_ToolError { "alignment must be a power of two from 1 to 4096" };
  }

  const size_t max_count =
    SK_MCP_ParseMax (args, 32, 256);

  uint64_t value_bits = 0;

  if (compare == SK_MCP_ScanCompare::Equal)
  {
    if (! args.contains ("value"))
      throw SK_MCP_ToolError { "value is required when compare is equal" };

    value_bits =
      SK_MCP_ParseScanValue (args.at ("value"), type, type_text);
  }

  uintptr_t scope_start = 0,
            scope_end   = 0;

  SK_MCP_ParseScanScope (args, scope_start, scope_end);

  const SK_MCP_RegionFilter filter =
    SK_MCP_ParseRegionFilter (args);

  SK_MCP_ScanSlot        slot;
  SK_MCP_ScanReservation budget;

  SK_MCP_ScanSession session;
                     session.type      = type;
                     session.alignment = alignment;

  const size_t chunk_max = 64 * 1024;

  uint64_t bytes_scanned = 0;

  if (compare == SK_MCP_ScanCompare::Equal)
  {
    std::vector <uint8_t> buf (chunk_max);

    SK_MCP_ForEachScanRegion ( scope_start, scope_end, filter,
      [&](uintptr_t region_start, uintptr_t region_end) -> bool
      {
        const uintptr_t first =
          (region_start + (uintptr_t)alignment - 1) &
                       ~((uintptr_t)alignment - 1);

        if (first < region_start)
          return true;   // Aligning up wrapped past the top of the space.

        uintptr_t pos = first;

        while (pos >= first && pos + elem_size <= region_end)
        {
          const size_t chunk_len =
            (size_t)std::min <uint64_t> ( (uint64_t)chunk_max,
                                          (uint64_t)(region_end - pos) );

          if (chunk_len < elem_size)
            break;

          SK_MCP_CheckCancelled ();

          try
          {
            SK_MCP_SafeRead (pos, buf.data (), chunk_len);
          }

          catch (const SK_MCP_ToolError&)
          {
            return true;   // The region went away; skip the rest of it.
          }

          bytes_scanned += chunk_len;

          const size_t last_off =
            ((chunk_len - elem_size) / alignment) * alignment;

          for (size_t off = 0; off <= last_off; off += alignment)
          {
            const uint64_t bits =
              SK_MCP_LoadBits (buf.data () + off, elem_size);

            if (SK_MCP_ScanCompareBits (type, SK_MCP_ScanCompare::Equal,
                                        bits, value_bits))
            {
              SK_MCP_PushCandidate ( session.candidates,
                                     { pos + (uintptr_t)off, bits }, budget );
            }
          }

          pos += (uintptr_t)(last_off + alignment);
        }

        return true;
      } );
  }

  else
  {
    SK_MCP_ForEachScanRegion ( scope_start, scope_end, filter,
      [&](uintptr_t region_start, uintptr_t region_end) -> bool
      {
        const uintptr_t first =
          (region_start + (uintptr_t)alignment - 1) &
                       ~((uintptr_t)alignment - 1);

        if (first < region_start || first >= region_end)
          return true;

        const size_t region_len =
          (size_t)(region_end - first);

        if (region_len < elem_size)
          return true;

        const size_t elements =
          (region_len - elem_size) / alignment + 1;

        const size_t bitmap_bytes =
          ((elements + 63) / 64) * sizeof (uint64_t);

        budget.Reserve (region_len + bitmap_bytes);

        SK_MCP_Snapshot snap;
                        snap.base = first;
                        snap.bytes.reserve (region_len);

        uintptr_t pos = first;

        while (pos < region_end)
        {
          SK_MCP_CheckCancelled ();

          const size_t chunk_len =
            (size_t)std::min <uint64_t> ( (uint64_t)chunk_max,
                                          (uint64_t)(region_end - pos) );

          const size_t filled =
            snap.bytes.size ();

          snap.bytes.resize (filled + chunk_len);

          try
          {
            SK_MCP_SafeRead (pos, snap.bytes.data () + filled, chunk_len);
          }

          catch (const SK_MCP_ToolError&)
          {
            snap.bytes.resize (filled);
            break;
          }

          bytes_scanned += chunk_len;

          pos += (uintptr_t)chunk_len;
        }

        const size_t live =
          SK_MCP_SnapshotElements (snap, alignment, elem_size);

        if (live == 0)
        {
          budget.Release (region_len + bitmap_bytes);

          return true;
        }

        const size_t words =
          (live + 63) / 64;

        // A short read leaves fewer elements than the reservation assumed.
        budget.Release (bitmap_bytes - words * sizeof (uint64_t));

        snap.alive.assign (words, 0xFFFFFFFFFFFFFFFFULL);

        // The tail of the last word covers elements that do not exist.
        if ((live & 63) != 0)
          snap.alive.back () = (1ULL << (live & 63)) - 1;

        session.snapshot.push_back (std::move (snap));

        return true;
      } );
  }

  const size_t held =
    SK_MCP_SessionBytes (session);

  int               id    = 0;
  SK_MCP_ScanEntry* entry = nullptr;

  {
    std::scoped_lock lock (SK_MCP_ScanLock);

    // The listener cancels a client's jobs before it releases the client's
    //   sessions, so a start whose client has left either sees the cancel
    //   here and stores nothing, or stores a busy session that the release
    //   orphans and SK_MCP_ScanBusy then erases.
    SK_MCP_CheckCancelled ();

    id = SK_MCP_NextScanSession++;

    entry =
      &SK_MCP_ScanSessions [id];

    entry->session = std::move (session);
    entry->owner   = SK_MCP_CurrentClientId ();
    entry->held    = held;
    entry->busy    = true;

    SK_MCP_ScanHeldBytes += held;

    slot.ConvertLocked   ();
    budget.ConvertLocked ();
  }

  // Only this response delivers the id, so the session is erased when the
  //   response is lost: the result throws, or a cancel makes the listener
  //   drop it.
  SK_MCP_ScanBusy busy (id);

  busy.erase = true;

  json result =
    SK_MCP_ScanResult (id, entry->session, max_count);

  result ["bytes_scanned"] = bytes_scanned;
  result ["elapsed_ms"]    = (uint64_t)(GetTickCount64 () - started);

  busy.erase              = false;
  busy.erase_if_cancelled = true;

  return result;
}


//
// sk_value_scan_next
//

static int
SK_MCP_ParseSessionArg (const json& args)
{
  if ( (! args.is_object ())                     ||
       (! args.contains ("session"))             ||
       (! args.at        ("session").is_number ()) )
  {
    throw SK_MCP_ToolError { "session is required and must be a number" };
  }

  return
    args.at ("session").get <int> ();
}

// Re-reads a snapshot session in place: one 1 MiB staging buffer, the fresh
//   bytes copied over the snapshot only once every element that still needs
//   them as its previous value has been compared.
static void
SK_MCP_ScanNextSnapshot ( SK_MCP_ScanSession&     session,
                          SK_MCP_ScanCompare      compare,
                          uint64_t                value_bits,
                          bool                    against_value,
                          SK_MCP_ScanReservation& budget )
{
  const size_t elem_size =
    SK_MCP_ScanTypeSize (session.type);

  const size_t alignment =
    session.alignment;

  std::vector <uint8_t> staging (SK_MCP_ScanRunBytes);

  for (auto it = session.snapshot.begin (); it != session.snapshot.end (); )
  {
    SK_MCP_Snapshot& snap = *it;

    bool   dropped = false;
    size_t offset  = 0;

    while (offset + elem_size <= snap.bytes.size ())
    {
      const size_t chunk_len =
        std::min (SK_MCP_ScanRunBytes, snap.bytes.size () - offset);

      if (chunk_len < elem_size)
        break;

      SK_MCP_CheckCancelled ();

      try
      {
        SK_MCP_SafeRead ( snap.base + (uintptr_t)offset,
                          staging.data (), chunk_len );
      }

      catch (const SK_MCP_ToolError&)
      {
        dropped = true;
        break;
      }

      const size_t last_off =
        offset + ((chunk_len - elem_size) / alignment) * alignment;

      for (size_t off = offset; off <= last_off; off += alignment)
      {
        const size_t index =
          off / alignment;

        if (! SK_MCP_IsAlive (snap, index))
          continue;

        const uint64_t current =
          SK_MCP_LoadBits (staging.data () + (off - offset), elem_size);

        const uint64_t reference =
          against_value ? value_bits
                        : SK_MCP_LoadBits (snap.bytes.data () + off, elem_size);

        if (! SK_MCP_ScanCompareBits (session.type, compare, current, reference))
          SK_MCP_ClearAlive (snap, index);
      }

      const size_t next_off =
        last_off + alignment;

      // Everything below next_off has had its previous value consumed, so the
      //   fresh bytes can replace it; the tail is re-read by the next chunk.
      const size_t copy_len =
        std::min (next_off, offset + chunk_len) - offset;

      memcpy (snap.bytes.data () + offset, staging.data (), copy_len);

      offset = next_off;
    }

    if (dropped)
      it = session.snapshot.erase (it);
    else
      ++it;
  }

  size_t live         = 0,
         snap_storage = 0;

  for (const auto& snap : session.snapshot)
  {
    const size_t elements =
      SK_MCP_SnapshotElements (snap, alignment, elem_size);

    for (size_t i = 0; i < elements; ++i)
    {
      if (SK_MCP_IsAlive (snap, i))
        ++live;
    }

    snap_storage += snap.bytes.size ()                        +
                    snap.alive.size () * sizeof (uint64_t);
  }

  // One bit per element is always cheaper than one candidate per element, so
  //   the first narrowing after an unknown scan stays in snapshot form; the
  //   survivors move out once they are a quarter of the storage or less.
  const size_t materialized =
    live * sizeof (SK_MCP_Candidate);

  if (materialized * 4 > snap_storage)
    return;

  // Narrowing has already happened, so this call has succeeded; materializing
  //   is only a change of representation.  If the candidate vector would not
  //   fit alongside the snapshot it is skipped rather than failing the call,
  //   which would leave the session narrowed behind an error.
  if (! budget.TryReserve (materialized))
    return;

  std::vector <SK_MCP_Candidate> survivors;
                                 survivors.reserve (live);

  for (const auto& snap : session.snapshot)
  {
    const size_t elements =
      SK_MCP_SnapshotElements (snap, alignment, elem_size);

    for (size_t i = 0; i < elements; ++i)
    {
      if (! SK_MCP_IsAlive (snap, i))
        continue;

      const size_t offset =
        i * alignment;

      survivors.push_back ({
        snap.base + (uintptr_t)offset,
        SK_MCP_LoadBits (snap.bytes.data () + offset, elem_size)
      });
    }
  }

  session.candidates = std::move (survivors);
  session.snapshot.clear   ();
  session.snapshot.shrink_to_fit ();
}

// Re-reads a candidate session by runs: consecutive candidates within a page
//   of each other, at most 1 MiB of span, one VirtualQuery and one read each.
static void
SK_MCP_ScanNextCandidates ( SK_MCP_ScanSession&     session,
                            SK_MCP_ScanCompare      compare,
                            uint64_t                value_bits,
                            bool                    against_value,
                            SK_MCP_ScanReservation& budget )
{
  const size_t elem_size =
    SK_MCP_ScanTypeSize (session.type);

  const size_t page_size =
    SK_MCP_PageSize ();

  std::vector <uint8_t> staging (SK_MCP_ScanRunBytes + 8);
  std::vector <SK_MCP_Candidate> survivors;

  const std::vector <SK_MCP_Candidate>& live =
    session.candidates;

  size_t i = 0;

  while (i < live.size ())
  {
    SK_MCP_CheckCancelled ();

    size_t j = i + 1;

    while ( j < live.size ()                                             &&
            (live [j].addr - live [j - 1].addr) <= (uintptr_t)page_size  &&
            (uint64_t)(live [j].addr - live [i].addr) + elem_size
                                                <= SK_MCP_ScanRunBytes )
    {
      ++j;
    }

    const uintptr_t run_base =
      live [i].addr;

    const size_t span =
      (size_t)(live [j - 1].addr - run_base) + elem_size;

    bool read_run = false;

    // A run that leaves its region, or whose read faults, falls back to one
    //   read per candidate.
    if (SK_MCP_IsReadableRange (run_base, span, nullptr))
    {
      try
      {
        SK_MCP_SafeRead (run_base, staging.data (), span);

        read_run = true;
      }

      catch (const SK_MCP_ToolError&)
      {
        read_run = false;
      }
    }

    for (size_t k = i; k < j; ++k)
    {
      uint64_t current = 0;

      if (read_run)
      {
        current =
          SK_MCP_LoadBits ( staging.data () + (live [k].addr - run_base),
                            elem_size );
      }

      else
      {
        try
        {
          SK_MCP_SafeRead (live [k].addr, &current, elem_size);
        }

        catch (const SK_MCP_ToolError&)
        {
          continue;   // Unreadable now; drop it.
        }
      }

      const uint64_t reference =
        against_value ? value_bits
                      : live [k].last;

      if (SK_MCP_ScanCompareBits (session.type, compare, current, reference))
        SK_MCP_PushCandidate (survivors, { live [k].addr, current }, budget);
    }

    i = j;
  }

  session.candidates = std::move (survivors);
}

static json
SK_MCP_ValueScanNext (const json& args)
{
  const int id =
    SK_MCP_ParseSessionArg (args);

  if ( (! args.contains ("compare"))             ||
       (! args.at        ("compare").is_string ()) )
  {
    throw SK_MCP_ToolError { "compare is required and must be a string" };
  }

  const SK_MCP_ScanCompare compare =
    SK_MCP_ParseScanCompare (args.at ("compare").get <std::string> (), false);

  const size_t max_count =
    SK_MCP_ParseMax (args, 32, 256);

  SK_MCP_ScanEntry& entry =
    SK_MCP_AcquireSession (id);

  SK_MCP_ScanBusy busy (id);

  SK_MCP_ScanSession& session =
    entry.session;

  const bool against_value =
    SK_MCP_CompareNeedsValue (compare);

  uint64_t value_bits = 0;

  if (against_value)
  {
    if (! args.contains ("value"))
    {
      throw SK_MCP_ToolError {
        "value is required when compare is equal, not_equal, greater or less"
      };
    }

    const char* type_text = "u32";

    switch (session.type)
    {
      case SK_MCP_ScanType::U8:  type_text = "u8";  break;
      case SK_MCP_ScanType::U16: type_text = "u16"; break;
      case SK_MCP_ScanType::U32: type_text = "u32"; break;
      case SK_MCP_ScanType::U64: type_text = "u64"; break;
      case SK_MCP_ScanType::I8:  type_text = "i8";  break;
      case SK_MCP_ScanType::I16: type_text = "i16"; break;
      case SK_MCP_ScanType::I32: type_text = "i32"; break;
      case SK_MCP_ScanType::I64: type_text = "i64"; break;
      case SK_MCP_ScanType::F32: type_text = "f32"; break;
      case SK_MCP_ScanType::F64: type_text = "f64"; break;
      default:                   type_text = "ptr"; break;
    }

    value_bits =
      SK_MCP_ParseScanValue (args.at ("value"), session.type, type_text);
  }

  SK_MCP_ScanReservation budget;

  // A snapshot cancelled partway is half narrowed and half re-baselined, and
  //   later comparisons would silently mix the two, so a cancelled next ends
  //   the session in either form.
  try
  {
    if (! session.snapshot.empty ())
    {
      SK_MCP_ScanNextSnapshot   ( session, compare, value_bits,
                                  against_value, budget );
    }

    else
    {
      SK_MCP_ScanNextCandidates ( session, compare, value_bits,
                                  against_value, budget );
    }
  }

  catch (const SK_MCP_Cancelled&)
  {
    busy.erase = true;
    throw;
  }

  SK_MCP_RechargeSession (entry, budget);

  return
    SK_MCP_ScanResult (id, session, max_count);
}


//
// sk_value_scan_end
//

static json
SK_MCP_ValueScanEnd (const json& args)
{
  const int id =
    SK_MCP_ParseSessionArg (args);

  // Throws unless the session is the caller's and idle.
  SK_MCP_AcquireSession (id);

  SK_MCP_ScanBusy busy (id);
                  busy.erase = true;

  return {
    { "ended", true }
  };
}


void
SK_MCP_RegisterScanTools (void)
{
  static const json scan_type_enum = {
    "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "f32", "f64", "ptr"
  };

  static const json region_type_schema = {
    { "type",  "array" },
    { "items", { { "type", "string" },
                 { "enum", { "image", "private", "mapped" } } } }
  };

  SK_MCP_RegisterTool ({
    "sk_pattern_scan",
    "Scans for an IDA-style byte pattern such as \"48 8b ?? ?? 89 05\" (?? or ? "
    "is a wildcard byte) over a module's image range (module), over start "
    "(0x hex, module+offset or a pointer chain like [game.exe+0x10]+8) plus "
    "size, or over the whole process (all: true); exactly one scope form is "
    "required. A whole-process scan is slow: pair all "
    "with protect (letters the protection must include, from r, w and x, e.g. "
    "\"x\" for code) or region_type (image, private, mapped), which filter every "
    "scope. Returns the matching addresses in address order, plus bytes_scanned "
    "and elapsed_ms to judge whether the next scan needs a narrower scope. Only "
    "committed, readable regions are searched, and a match that straddles two "
    "adjacent regions with different page protections is not found.",
    {
      { "type", "object" },
      { "properties",
        { { "pattern",     { { "type", "string"  } } },
          { "module",      { { "type", "string"  } } },
          { "start",       { { "type", "string"  } } },
          { "size",        { { "type", "number"  } } },
          { "all",         { { "type", "boolean" } } },
          { "protect",     { { "type", "string"  } } },
          { "region_type", region_type_schema        },
          { "max",         { { "type", "number"  } } } }
      },
      { "required",             { "pattern" } },
      { "additionalProperties", false         }
    },
    SK_MCP_PatternScan
  });

  SK_MCP_RegisterTool ({
    "sk_value_scan_start",
    "Starts a value scan over a module's image range (module), over start "
    "(0x hex, module+offset or a pointer chain like [game.exe+0x10]+8) plus "
    "size, or over the whole process (all: true); exactly one scope form is "
    "required. A whole-process scan is slow and an "
    "unknown one is large: pair all with protect (letters the protection must "
    "include, from r, w and x, e.g. \"rw\" for data) or region_type (image, "
    "private, mapped), which filter every scope. compare equal keeps every "
    "aligned element of type matching value; compare unknown keeps a snapshot of "
    "the scope so a later sk_value_scan_next can narrow it by how the values "
    "changed. Returns a session id to pass to sk_value_scan_next and "
    "sk_value_scan_end, plus bytes_scanned and elapsed_ms to judge whether the "
    "next scan needs a narrower scope. Sessions hold memory until they are "
    "ended; they belong to the client that started them and are dropped when "
    "it disconnects.",
    {
      { "type", "object" },
      { "properties",
        { { "type",        { { "type", "string" }, { "enum", scan_type_enum } } },
          { "compare",     { { "type", "string" },
                             { "enum", { "equal", "unknown" } } } },
          { "value",       json::object ()              },
          { "module",      { { "type", "string"  } }    },
          { "start",       { { "type", "string"  } }    },
          { "size",        { { "type", "number"  } }    },
          { "all",         { { "type", "boolean" } }    },
          { "protect",     { { "type", "string"  } }    },
          { "region_type", region_type_schema           },
          { "alignment",   { { "type", "number"  } }    },
          { "max",         { { "type", "number"  } }    } }
      },
      { "required",             { "type", "compare" } },
      { "additionalProperties", false                  }
    },
    SK_MCP_ValueScanStart
  });

  SK_MCP_RegisterTool ({
    "sk_value_scan_next",
    "Narrows the candidates of scan session by re-reading them and keeping the "
    "ones that satisfy compare. equal, not_equal, greater and less compare "
    "against value; changed, unchanged, increased and decreased compare against "
    "each candidate's previous reading. Candidates that have become unreadable "
    "are dropped. Cancelling this call ends the session, because a partly "
    "narrowed session would mix old and new readings.",
    {
      { "type", "object" },
      { "properties",
        { { "session", { { "type", "number" } } },
          { "compare", { { "type", "string" },
                         { "enum", { "equal", "not_equal", "greater", "less",
                                     "changed", "unchanged", "increased",
                                     "decreased" } } } },
          { "value",   json::object ()           },
          { "max",     { { "type", "number" } }   } }
      },
      { "required",             { "session", "compare" } },
      { "additionalProperties", false                     }
    },
    SK_MCP_ValueScanNext
  });

  SK_MCP_RegisterTool ({
    "sk_value_scan_end",
    "Ends scan session and frees the memory it holds. Sessions are also dropped "
    "when the client that started them disconnects.",
    {
      { "type", "object" },
      { "properties",
        { { "session", { { "type", "number" } } } }
      },
      { "required",             { "session" } },
      { "additionalProperties", false         }
    },
    SK_MCP_ValueScanEnd
  });
}

void
SK_MCP_OnClientDisconnected (uint64_t client)
{
  // Moved out under the lock and freed after it is released.
  std::map <int, SK_MCP_ScanEntry> doomed;

  std::scoped_lock lock (SK_MCP_ScanLock);

  auto it =
    SK_MCP_ScanSessions.begin ();

  while (it != SK_MCP_ScanSessions.end ())
  {
    const auto next =
      std::next (it);

    if (it->second.owner == client)
    {
      // A busy session belongs to the call using it, which erases it on exit.
      if (it->second.busy)
        it->second.orphaned = true;

      else
      {
        SK_MCP_ScanHeldBytes -= it->second.held;

        doomed.insert (SK_MCP_ScanSessions.extract (it));
      }
    }

    it = next;
  }
}
