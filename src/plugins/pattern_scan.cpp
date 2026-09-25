// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
//

#include <SpecialK/stdafx.h>
#include <SpecialK/plugin/pattern_scan.h>

static bool
SK_PatternScan_MatchAt (const uint8_t *p, const SK_PatternScan_Pattern& pat)
{
  for (size_t i = 1; i < pat.len; ++i)
  {
    if (pat.mask [i] && p [i] != pat.bytes [i])
      return false;
  }

  return true;
}

bool
SK_PatternScan_ParsePattern (const char *ida, SK_PatternScan_Pattern& pat)
{
  pat.len = 0;

  for (const char *p = ida; *p != '\0';)
  {
    if (*p == ' ') { ++p; continue; }

    if (pat.len >= std::size (pat.bytes))
      return false;

    if (p [0] == '?' && p [1] == '?')
    {
      pat.mask [pat.len++] = false;
    }

    else
    {
      const char hex [3] = { p [0], p [1], '\0' };

      pat.bytes [pat.len  ] = static_cast <uint8_t> (strtoul (hex, nullptr, 16));
      pat.mask  [pat.len++] = true;
    }

    p += 2;
  }

  // The scanner dispatches on the first byte.
  return pat.len > 0 && pat.mask [0];
}

// One pass over [begin, end) for all given patterns; a match may extend past
// end up to limit. SEH only, so no C++ objects here (C2712).
bool
SK_PatternScan_ScanRange ( const uint8_t          *begin, const uint8_t *end,
                            const uint8_t          *limit,
                            SK_PatternScan_Pattern *pats,  size_t         count )
{
  if (count > 16)
    return false;

  // Bit i set = pattern i starts with that byte; most bytes start none.
  uint16_t first_byte [256] = { };

  for (size_t i = 0; i < count; ++i)
    first_byte [pats [i].bytes [0]] |= static_cast <uint16_t> (1u << i);

  __try
  {
    for (const uint8_t *p = begin; p < end; ++p)
    {
      uint32_t candidates = first_byte [*p];

      while (candidates != 0)
      {
        unsigned long i;
        _BitScanForward (&i, candidates);

        candidates &= candidates - 1;

        SK_PatternScan_Pattern& pat = pats [i];

        if (p + pat.len <= limit && SK_PatternScan_MatchAt (p, pat))
        {
          if (pat.match == nullptr) pat.match     = p;
          else                      pat.duplicate = true;
        }
      }
    }
  }

  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    return false;
  }

  return true;
}

bool
SK_PatternScan_FindText (uint8_t *base, uint8_t*& text, size_t& size)
{
  auto *dos =
    reinterpret_cast <IMAGE_DOS_HEADER *> (base);

  if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    return false;

  auto *nt =
    reinterpret_cast <IMAGE_NT_HEADERS *> (base + dos->e_lfanew);

  if (nt->Signature != IMAGE_NT_SIGNATURE)
    return false;

  IMAGE_SECTION_HEADER *section =
    IMAGE_FIRST_SECTION (nt);

  for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
  {
    if (0 == memcmp (section->Name, ".text\0\0", 8))
    {
      text = base + section->VirtualAddress;
      size =        section->Misc.VirtualSize;

      return size != 0;
    }
  }

  return false;
}

uint8_t *
SK_PatternScan_RipTarget (const uint8_t *insn, size_t disp_offset, size_t insn_len)
{
  int32_t disp;
  memcpy (&disp, insn + disp_offset, sizeof (disp));

  return
    const_cast <uint8_t *> (insn + insn_len + disp);
}
