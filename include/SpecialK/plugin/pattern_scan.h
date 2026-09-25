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

#ifndef __SK__Plugin__PatternScan_H__
#define __SK__Plugin__PatternScan_H__

// Shared byte-pattern scanner for game plug-ins that resolve addresses by
// pattern instead of a fixed RVA (e.g. outer_worlds2.cpp). Architecture-
// neutral (built for x86 and x64).
//
// Do not use SK_ScanAlignedExec / SK_ScanIdaStyle for this. With an FF/00
// mask SK_ScanAlignedExec never matches a literal 00 byte, and it costs a QPC
// read and two SEH translator swaps per byte under a 5 s default timeout,
// while plug-in patterns can sit 100+ MB into .text. SK_ScanIdaStyle is
// correct but walks the image once per pattern; SK_PatternScan_ScanRange
// walks it once for up to 16 patterns together.

struct SK_PatternScan_Pattern {
  uint8_t        bytes [64] = { };
  bool           mask  [64] = { }; // false = wildcard
  size_t         len        = 0;

  const uint8_t *match      = nullptr;
  bool           duplicate  = false;
};

// Parses an IDA-style byte pattern ("48 8B 05 ?? ?? ?? ??") into pat. The
// first byte must not be a wildcard; the scanner dispatches on it.
bool
SK_PatternScan_ParsePattern (const char *ida, SK_PatternScan_Pattern& pat);

// One pass over [begin, end) testing every pattern in pats at each position;
// a match may extend past end, up to limit. Sets each pattern's match on the
// first hit and duplicate on a second. count must be <= 16 (one bit per
// pattern in a uint16_t dispatch table), or this returns false with nothing
// scanned; callers static_assert their per-pass counts.
bool
SK_PatternScan_ScanRange ( const uint8_t          *begin, const uint8_t *end,
                            const uint8_t          *limit,
                            SK_PatternScan_Pattern *pats,  size_t         count );

// Locates the .text section of the PE image loaded at base.
bool
SK_PatternScan_FindText (uint8_t *base, uint8_t*& text, size_t& size);

// Resolves a rip-relative operand: reads a little-endian disp32 at
// insn + disp_offset and returns insn + insn_len + disp. E.g. for
// `48 8B 05 disp32` (mov reg, [rip+disp]), disp_offset = 3, insn_len = 7;
// for `80 3D disp32 00` (cmp byte ptr [rip+disp], 0), disp_offset = 2,
// insn_len = 7.
uint8_t *
SK_PatternScan_RipTarget (const uint8_t *insn, size_t disp_offset, size_t insn_len);

#endif /* __SK__Plugin__PatternScan_H__ */
