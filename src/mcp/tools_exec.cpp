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

#include <array>
#include <cstring>
#include <cstdint>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

using json = nlohmann::json;

// Shared by both tools: every call into game code runs inside an SEH frame and
//   reports the faulting address through this.
static DWORD
SK_MCP_CallFilter (EXCEPTION_POINTERS* pointers, uintptr_t* fault_addr)
{
  *fault_addr =
    (uintptr_t)pointers->ExceptionRecord->ExceptionAddress;

  return EXCEPTION_EXECUTE_HANDLER;
}


//
// §6.1 sk_console
//

// A separate, never-inlined frame: the SEH helper below must have nothing
//   needing unwinding, and SK_ICommandResult holds std::strings.
static __declspec (noinline) void
SK_MCP_ConsoleInvoke (const char* command, SK_ICommandResult* out_result)
{
  *out_result =
    SK_GetCommandProcessor ()->ProcessCommandLine (command);
}

// §5: a job body that calls game code wraps that call in its own SEH frame, so
//   a fault reaches the drain as an SK_MCP_ToolError instead of unwinding
//   through it.  Returns the exception code, 0 on success.
static DWORD
SK_MCP_ConsoleGuarded ( const char*        command,
                        SK_ICommandResult* out_result,
                        uintptr_t*         fault_addr )
{
  DWORD code = 0;

  __try
  {
    SK_MCP_ConsoleInvoke (command, out_result);
  }

  __except (SK_MCP_CallFilter (GetExceptionInformation (), fault_addr))
  {
    code =
      GetExceptionCode ();
  }

  return code;
}

static json
SK_MCP_Console (const json& args)
{
  if ( (! args.is_object ())                     ||
       (! args.contains ("command"))             ||
       (! args.at        ("command").is_string ()) )
  {
    throw SK_MCP_ToolError { "command is required and must be a string" };
  }

  const std::string command =
    args.at ("command").get <std::string> ();

  // ProcessCommandLine runs with its lock commented out, so it only ever runs
  //   on the thread the rest of SK's command traffic uses.
  return
    SK_MCP_RunOnRenderThread ([command](void) -> json
    {
      SK_ICommandResult result ("");

      uintptr_t fault_addr = 0;

      const DWORD exception_code =
        SK_MCP_ConsoleGuarded (command.c_str (), &result, &fault_addr);

      if (exception_code != 0)
      {
        char szCode [16] = { };

        snprintf (szCode, sizeof (szCode), "0x%08x", (unsigned int)exception_code);

        std::string message =
          "console command faulted: " + std::string (szCode) +
          " at " + SK_MCP_FormatAddress (fault_addr);

        const json symbol =
          SK_MCP_Symbolize (fault_addr);

        if (symbol.is_string ())
          message += " (" + symbol.get <std::string> () + ")";

        throw SK_MCP_ToolError { message };
      }

      // getStatus is not exposed: it is 0 for many successful commands.
      //   A command is free to put arbitrary bytes in its result, and a
      //   string that is not valid UTF-8 would make the dump throw.
      return json {
        { "result", SK_MCP_SanitizeUTF8 (result.getResult ()) },
        { "word",   SK_MCP_SanitizeUTF8 (result.getWord   ()) }
      };
    }, 5000);
}


//
// §6.2 sk_call_function
//

enum class SK_MCP_ArgType {
  Int, Ptr, F32, F64
};

enum class SK_MCP_RetKind {
  Void, Int, I64, Ptr, F32, F64
};

// Exactly as many slots as the widest layout needs; see the marshalling notes
//   on each platform below.
#ifdef _M_X64
static constexpr size_t SK_MCP_MaxSlots = 8;
using SK_MCP_Slot                       = uint64_t;
#else
static constexpr size_t SK_MCP_MaxSlots = 16;
using SK_MCP_Slot                       = uint32_t;
#endif

static constexpr size_t SK_MCP_MaxArgs = 8;

// Fills *out_int or *out_fp per its own return kind; returns the SEH
//   exception code (0 on success) and the faulting address.
typedef DWORD (*SK_MCP_CallThunk)( uintptr_t            target,
                                   const SK_MCP_Slot*   slots,
                                   uint64_t*            out_int,
                                   double*              out_fp,
                                   uintptr_t*           fault_addr );

// Everything the call needs, POD and copyable, so the render-thread job can
//   own a copy and nothing it touches lives on the handler's stack (§5).
struct SK_MCP_CallPlan {
  uintptr_t        target = 0;
  SK_MCP_CallThunk thunk  = nullptr;
  SK_MCP_RetKind   ret    = SK_MCP_RetKind::Void;
  SK_MCP_Slot      slots [SK_MCP_MaxSlots] = { };
};


#ifdef _M_X64

//
// x64: argument slot n (0-based) rides in RCX/RDX/R8/R9 or XMM0..3 by type,
//   and every slot from 4 on sits at a fixed stack position whatever its type.
//   The caller cleans the stack and a callee ignores slots it was not
//   declared with, so every call passes all 8 slots.
//
//   Slots 0..3 need the right parameter *type* for the value to land in the
//   right register file; trailing slots carry integers directly and floats as
//   their bit pattern.
//

template <typename Ret, typename S0, typename S1, typename S2, typename S3>
using SK_MCP_Fn64 = Ret (*)( S0, S1, S2, S3,
                             uint64_t, uint64_t, uint64_t, uint64_t );

// Slot / return kind 0 = integer, 1 = f32, 2 = f64.
template <size_t K> struct SK_MCP_SlotType64;
template <> struct SK_MCP_SlotType64 <0> { using type = uint64_t; };
template <> struct SK_MCP_SlotType64 <1> { using type = float;    };
template <> struct SK_MCP_SlotType64 <2> { using type = double;   };

template <typename T>
static __forceinline T
SK_MCP_SlotAs64 (uint64_t raw)
{
  if constexpr (std::is_same_v <T, uint64_t>)
  {
    return raw;
  }

  else
  {
    T val;

    // The marshaller put the bit pattern in the low bits of the slot.
    memcpy (&val, &raw, sizeof (T));

    return val;
  }
}

template <typename Ret, typename S0, typename S1, typename S2, typename S3>
static DWORD
SK_MCP_Thunk64 ( uintptr_t          target,
                 const SK_MCP_Slot* slots,
                 uint64_t*          out_int,
                 double*            out_fp,
                 uintptr_t*         fault_addr )
{
  // One of the two is unused per instantiation.
  (void)out_int;
  (void)out_fp;

  const auto fn =
    (SK_MCP_Fn64 <Ret, S0, S1, S2, S3>)target;

  // No object here needs unwinding, which is what lets the typed call sit in
  //   an SEH frame at all (MSVC C2712).
  __try
  {
    if constexpr (std::is_same_v <Ret, uint64_t>)
    {
      *out_int =
        fn ( SK_MCP_SlotAs64 <S0> (slots [0]), SK_MCP_SlotAs64 <S1> (slots [1]),
             SK_MCP_SlotAs64 <S2> (slots [2]), SK_MCP_SlotAs64 <S3> (slots [3]),
             slots [4], slots [5], slots [6], slots [7] );
    }

    else
    {
      *out_fp = (double)
        fn ( SK_MCP_SlotAs64 <S0> (slots [0]), SK_MCP_SlotAs64 <S1> (slots [1]),
             SK_MCP_SlotAs64 <S2> (slots [2]), SK_MCP_SlotAs64 <S3> (slots [3]),
             slots [4], slots [5], slots [6], slots [7] );
    }
  }

  __except (SK_MCP_CallFilter (GetExceptionInformation (), fault_addr))
  {
    return
      GetExceptionCode ();
  }

  return 0;
}

// 81 register layouts x 3 return kinds, indexed by layout_index * 3 + ret.
static constexpr size_t SK_MCP_Layouts64 = 81;
static constexpr size_t SK_MCP_Thunks64  = SK_MCP_Layouts64 * 3;

template <size_t I>
static constexpr SK_MCP_CallThunk
SK_MCP_MakeThunk64 (void)
{
  constexpr size_t layout = I / 3;

  using Ret = typename SK_MCP_SlotType64 <I % 3>::type;
  using S0  = typename SK_MCP_SlotType64 <(layout / 27)     >::type;
  using S1  = typename SK_MCP_SlotType64 <(layout /  9) % 3 >::type;
  using S2  = typename SK_MCP_SlotType64 <(layout /  3) % 3 >::type;
  using S3  = typename SK_MCP_SlotType64 <(layout      ) % 3>::type;

  return
    &SK_MCP_Thunk64 <Ret, S0, S1, S2, S3>;
}

template <size_t... I>
static constexpr std::array <SK_MCP_CallThunk, sizeof... (I)>
SK_MCP_MakeThunkTable64 (std::index_sequence <I...>)
{
  return { SK_MCP_MakeThunk64 <I> ()... };
}

static const std::array <SK_MCP_CallThunk, SK_MCP_Thunks64> _mcp_thunks64 =
  SK_MCP_MakeThunkTable64 (std::make_index_sequence <SK_MCP_Thunks64> ());

#else

//
// x86: stack arguments are 4-byte slots, f64 takes two (low dword first) and
//   f32 one holding its bits, so every parameter can be uint32_t and the
//   layout follows from the slot count alone.
//
//   thiscall is emulated as __fastcall with slot 0 in ECX and a dummy EDX
//   slot, which is byte-for-byte the thiscall layout for a free function,
//   callee cleanup included.
//

// Convention index 0 = cdecl, 1 = stdcall, 2 = fastcall (and thiscall).
template <size_t Conv, typename Ret, typename... A> struct SK_MCP_FnType86;

template <typename Ret, typename... A>
struct SK_MCP_FnType86 <0, Ret, A...> { using type = Ret (__cdecl    *)(A...); };
template <typename Ret, typename... A>
struct SK_MCP_FnType86 <1, Ret, A...> { using type = Ret (__stdcall  *)(A...); };
template <typename Ret, typename... A>
struct SK_MCP_FnType86 <2, Ret, A...> { using type = Ret (__fastcall *)(A...); };

// Return kind 0 = 32-bit (EAX; also void, discarded), 1 = i64 (EDX:EAX),
//   2 = f32, 3 = f64 (both ST(0)).
template <size_t K> struct SK_MCP_RetType86;
template <> struct SK_MCP_RetType86 <0> { using type = uint32_t; };
template <> struct SK_MCP_RetType86 <1> { using type = uint64_t; };
template <> struct SK_MCP_RetType86 <2> { using type = float;    };
template <> struct SK_MCP_RetType86 <3> { using type = double;   };

// One uint32_t parameter per index of the sequence.
template <size_t> using SK_MCP_U32 = uint32_t;

template <typename Ret, size_t Conv, typename Seq> struct SK_MCP_Thunk86;

template <typename Ret, size_t Conv, size_t... I>
struct SK_MCP_Thunk86 <Ret, Conv, std::index_sequence <I...>>
{
  static DWORD
  Call ( uintptr_t          target,
         const SK_MCP_Slot* slots,
         uint64_t*          out_int,
         double*            out_fp,
         uintptr_t*         fault_addr )
  {
    // One of the two is unused per instantiation.
    (void)out_int;
    (void)out_fp;
    (void)slots;

    using fn_t =
      typename SK_MCP_FnType86 <Conv, Ret, SK_MCP_U32 <I>...>::type;

    const auto fn =
      (fn_t)target;

    // No object here needs unwinding (MSVC C2712).
    __try
    {
      if constexpr ( std::is_same_v <Ret, float> ||
                     std::is_same_v <Ret, double> )
      {
        *out_fp  = (double)  fn (slots [I]...);
      }

      else
      {
        *out_int = (uint64_t)fn (slots [I]...);
      }
    }

    __except (SK_MCP_CallFilter (GetExceptionInformation (), fault_addr))
    {
      return
        GetExceptionCode ();
    }

    return 0;
  }
};

// 3 conventions x 17 slot counts (0..16) x 4 return kinds, indexed by
//   (conv * 17 + slots) * 4 + ret.
static constexpr size_t SK_MCP_SlotCounts86 = SK_MCP_MaxSlots + 1;
static constexpr size_t SK_MCP_Thunks86     = 3 * SK_MCP_SlotCounts86 * 4;

template <size_t I>
static constexpr SK_MCP_CallThunk
SK_MCP_MakeThunk86 (void)
{
  constexpr size_t slots = (I / 4) % SK_MCP_SlotCounts86;
  constexpr size_t conv  = (I / 4) / SK_MCP_SlotCounts86;

  using Ret = typename SK_MCP_RetType86 <I % 4>::type;

  return
    &SK_MCP_Thunk86 <Ret, conv, std::make_index_sequence <slots>>::Call;
}

template <size_t... I>
static constexpr std::array <SK_MCP_CallThunk, sizeof... (I)>
SK_MCP_MakeThunkTable86 (std::index_sequence <I...>)
{
  return { SK_MCP_MakeThunk86 <I> ()... };
}

static const std::array <SK_MCP_CallThunk, SK_MCP_Thunks86> _mcp_thunks86 =
  SK_MCP_MakeThunkTable86 (std::make_index_sequence <SK_MCP_Thunks86> ());

#endif


//
// Argument parsing
//

static std::string
SK_MCP_HexU64 (uint64_t value)
{
  char szHex [32] = { };

  snprintf (szHex, sizeof (szHex), "0x%llx", (unsigned long long)value);

  return szHex;
}

static uint64_t
SK_MCP_ParseIntArg (const json& v, const std::string& label)
{
  if (v.is_number_unsigned ())
    return v.get <uint64_t> ();

  if (v.is_number_integer ())
    return (uint64_t)v.get <int64_t> ();

  if (v.is_number_float ())
    throw SK_MCP_ToolError { label + " must be a whole number, not a float" };

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
          throw SK_MCP_ToolError { "invalid hex value '" + s + "' for " + label };

        // More significant digits than a 64-bit value can hold would
        //   otherwise wrap around silently.
        if (value > (0xFFFFFFFFFFFFFFFFULL >> 4))
          throw SK_MCP_ToolError { "hex value '" + s + "' for " + label +
                                   " does not fit in 64 bits" };

        value = (value << 4) | (uint64_t)digit;
      }

      return value;
    }

    throw SK_MCP_ToolError {
      "invalid integer value '" + s + "' for " + label +
      "; expected a number or a 0x hex string"
    };
  }

  throw SK_MCP_ToolError { label + " must be a number or a hex string" };
}

static double
SK_MCP_ParseFloatArg (const json& v, const std::string& label)
{
  if (! v.is_number ())
    throw SK_MCP_ToolError { label + " must be a number" };

  return v.get <double> ();
}

static SK_MCP_ArgType
SK_MCP_ParseArgType (const std::string& text, const std::string& label)
{
  if (text == "int") return SK_MCP_ArgType::Int;
  if (text == "ptr") return SK_MCP_ArgType::Ptr;
  if (text == "f32") return SK_MCP_ArgType::F32;
  if (text == "f64") return SK_MCP_ArgType::F64;

  throw SK_MCP_ToolError {
    "invalid type '" + text + "' for " + label +
    "; expected one of int, ptr, f32, f64"
  };
}

static SK_MCP_RetKind
SK_MCP_ParseRetKind (const std::string& text)
{
  if (text == "void") return SK_MCP_RetKind::Void;
  if (text == "int")  return SK_MCP_RetKind::Int;
  if (text == "i64")  return SK_MCP_RetKind::I64;
  if (text == "ptr")  return SK_MCP_RetKind::Ptr;
  if (text == "f32")  return SK_MCP_RetKind::F32;
  if (text == "f64")  return SK_MCP_RetKind::F64;

  throw SK_MCP_ToolError {
    "invalid return '" + text + "'; expected one of void, int, i64, ptr, f32, f64"
  };
}


//
// The call itself.  Takes its plan by value: on the render path this runs
//   inside a job that may outlive the handler's frame (§5).
//

static json
SK_MCP_PerformCall (SK_MCP_CallPlan plan)
{
  uint64_t  out_int    = 0;
  double    out_fp     = 0.0;
  uintptr_t fault_addr = 0;

  const DWORD exception_code =
    plan.thunk (plan.target, plan.slots, &out_int, &out_fp, &fault_addr);

  if (exception_code != 0)
  {
    char szCode [16] = { };

    snprintf (szCode, sizeof (szCode), "0x%08x", (unsigned int)exception_code);

    std::string message =
      "call to " + SK_MCP_FormatAddress (plan.target) + " faulted: " + szCode +
      " at " + SK_MCP_FormatAddress (fault_addr);

    const json symbol =
      SK_MCP_Symbolize (fault_addr);

    if (symbol.is_string ())
      message += " (" + symbol.get <std::string> () + ")";

    throw SK_MCP_ToolError { message };
  }

  json result;

  switch (plan.ret)
  {
    case SK_MCP_RetKind::Void:
      break;

    case SK_MCP_RetKind::Int:
    case SK_MCP_RetKind::I64:
      result ["return"]     = out_int;
      result ["return_hex"] = SK_MCP_HexU64 (out_int);
      break;

    case SK_MCP_RetKind::Ptr:
    {
      const uintptr_t ptr =
        (uintptr_t)out_int;

      result ["return"]     = SK_MCP_FormatAddress (ptr);
      result ["return_hex"] = SK_MCP_FormatAddress (ptr);
      result ["symbol"]     = SK_MCP_Symbolize (ptr);
      break;
    }

    case SK_MCP_RetKind::F32:
    {
      const float    f32  = (float)out_fp;
            uint32_t bits = 0;

      memcpy (&bits, &f32, sizeof (bits));

      result ["return"]     = (double)f32;
      result ["return_hex"] = SK_MCP_HexU64 (bits);
      break;
    }

    case SK_MCP_RetKind::F64:
    {
      uint64_t bits = 0;

      memcpy (&bits, &out_fp, sizeof (bits));

      result ["return"]     = out_fp;
      result ["return_hex"] = SK_MCP_HexU64 (bits);
      break;
    }
  }

  if (! result.contains ("symbol"))
    result ["symbol"] = nullptr;

  return result;
}

static json
SK_MCP_CallFunction (const json& args)
{
  if ( (! args.is_object ())                     ||
       (! args.contains ("address"))             ||
       (! args.at        ("address").is_string ()) )
  {
    throw SK_MCP_ToolError { "address is required and must be a string" };
  }

  const uintptr_t target =
    SK_MCP_ParseAddress (args.at ("address").get <std::string> ());

  if (! SK_IsAddressExecutable ((LPCVOID)target, true))
  {
    throw SK_MCP_ToolError {
      "address " + SK_MCP_FormatAddress (target) + " is not executable"
    };
  }

  std::string convention;

  if (args.contains ("convention"))
  {
    if (! args.at ("convention").is_string ())
      throw SK_MCP_ToolError { "convention must be a string" };

    convention =
      args.at ("convention").get <std::string> ();
  }

  SK_MCP_RetKind ret_kind =
    SK_MCP_RetKind::Void;

  if (args.contains ("return"))
  {
    if (! args.at ("return").is_string ())
      throw SK_MCP_ToolError { "return must be a string" };

    ret_kind =
      SK_MCP_ParseRetKind (args.at ("return").get <std::string> ());
  }

  bool on_render = true;

  if (args.contains ("thread"))
  {
    if (! args.at ("thread").is_string ())
      throw SK_MCP_ToolError { "thread must be a string" };

    const std::string thread =
      args.at ("thread").get <std::string> ();

    if      (thread == "render")   on_render = true;
    else if (thread == "worker")   on_render = false;
    else
      throw SK_MCP_ToolError {
        "invalid thread '" + thread + "'; expected render or worker"
      };
  }

  DWORD timeout_ms = 5000;

  if (args.contains ("timeout_ms"))
  {
    if (! args.at ("timeout_ms").is_number ())
      throw SK_MCP_ToolError { "timeout_ms must be a number" };

    const double ms =
      args.at ("timeout_ms").get <double> ();

    if (ms <= 0.0)
      throw SK_MCP_ToolError { "timeout_ms must be positive" };

    timeout_ms =
      (DWORD)((ms < 60000.0) ? ms : 60000.0);
  }

  // Argument list: type + value pairs, in call order.
  std::vector <SK_MCP_ArgType> arg_types;
  std::vector <json>           arg_values;

  if (args.contains ("args"))
  {
    if (! args.at ("args").is_array ())
      throw SK_MCP_ToolError { "args must be an array" };

    const json& list =
      args.at ("args");

    if (list.size () > SK_MCP_MaxArgs)
      throw SK_MCP_ToolError { "at most 8 arguments are supported" };

    for (size_t i = 0; i < list.size (); ++i)
    {
      const std::string label =
        "args[" + std::to_string (i) + "]";

      if (! list [i].is_object ())
        throw SK_MCP_ToolError { label + " must be an object with type and value" };

      if ( (! list [i].contains ("type")) ||
           (! list [i].at        ("type").is_string ()) )
      {
        throw SK_MCP_ToolError { label + ".type is required and must be a string" };
      }

      if (! list [i].contains ("value"))
        throw SK_MCP_ToolError { label + ".value is required" };

      arg_types.push_back (
        SK_MCP_ParseArgType (list [i].at ("type").get <std::string> (), label + ".type")
      );

      arg_values.push_back (list [i].at ("value"));
    }
  }

  SK_MCP_CallPlan plan;
                  plan.target = target;
                  plan.ret    = ret_kind;

#ifdef _M_X64

  if ( (! convention.empty ()) && convention != "win64" )
  {
    throw SK_MCP_ToolError {
      "invalid convention '" + convention + "' on x64; omit it or pass win64. "
      "There is only one calling convention, and `this` is simply argument 0."
    };
  }

  // Slot / return kind 0 = integer, 1 = f32, 2 = f64.
  size_t layout = 0;

  for (size_t i = 0; i < arg_types.size (); ++i)
  {
    const std::string label =
      "args[" + std::to_string (i) + "].value";

    size_t kind = 0;

    switch (arg_types [i])
    {
      case SK_MCP_ArgType::Int:
        plan.slots [i] = SK_MCP_ParseIntArg (arg_values [i], label);
        break;

      case SK_MCP_ArgType::Ptr:
      {
        if (! arg_values [i].is_string ())
          throw SK_MCP_ToolError { label + " must be an address string" };

        plan.slots [i] =
          (uint64_t)SK_MCP_ParseAddress (arg_values [i].get <std::string> ());
        break;
      }

      case SK_MCP_ArgType::F32:
      {
        const float    f32  = (float)SK_MCP_ParseFloatArg (arg_values [i], label);
              uint32_t bits = 0;

        memcpy (&bits, &f32, sizeof (bits));

        plan.slots [i] = bits;
        kind           = 1;
        break;
      }

      case SK_MCP_ArgType::F64:
      {
        const double f64 =
          SK_MCP_ParseFloatArg (arg_values [i], label);

        memcpy (&plan.slots [i], &f64, sizeof (f64));

        kind = 2;
        break;
      }
    }

    // Only the first four slots pick a register file; the rest are stack.
    if (i < 4)
    {
      static constexpr size_t weights [4] = { 27, 9, 3, 1 };

      layout += kind * weights [i];
    }
  }

  size_t ret_slot = 0;   // uint64_t: void, int, i64 and ptr all read RAX

  if      (ret_kind == SK_MCP_RetKind::F32) ret_slot = 1;
  else if (ret_kind == SK_MCP_RetKind::F64) ret_slot = 2;

  plan.thunk =
    _mcp_thunks64 [layout * 3 + ret_slot];

#else

  size_t conv = 0;   // 0 cdecl, 1 stdcall, 2 fastcall (and thiscall)

  bool thiscall = false;

  if      (convention.empty () || convention == "cdecl") conv = 0;
  else if (convention == "stdcall")                      conv = 1;
  else if (convention == "fastcall")                     conv = 2;
  else if (convention == "thiscall")             { conv = 2; thiscall = true; }
  else
  {
    throw SK_MCP_ToolError {
      "invalid convention '" + convention +
      "'; expected one of cdecl, stdcall, thiscall, fastcall"
    };
  }

  std::vector <uint32_t> slots;

  for (size_t i = 0; i < arg_types.size (); ++i)
  {
    const std::string label =
      "args[" + std::to_string (i) + "].value";

    const bool is_float =
      ( arg_types [i] == SK_MCP_ArgType::F32 ||
        arg_types [i] == SK_MCP_ArgType::F64 );

    // Real __fastcall skips floats when it assigns ECX/EDX, which this
    //   emulation does not model.
    if (is_float && conv == 2)
    {
      throw SK_MCP_ToolError {
        std::string ("float arguments are not supported under ") +
        (thiscall ? "thiscall" : "fastcall") + " on x86; " + label +
        " is a float"
      };
    }

    switch (arg_types [i])
    {
      case SK_MCP_ArgType::Int:
      {
        const uint64_t raw =
          SK_MCP_ParseIntArg (arg_values [i], label);

        // Accepts either an unsigned 32-bit value or a sign-extended
        //   negative one; anything else would be silently truncated.
        if ( raw > 0xFFFFFFFFULL &&
             raw < 0xFFFFFFFF80000000ULL )
        {
          throw SK_MCP_ToolError { label + " does not fit in 32 bits" };
        }

        slots.push_back ((uint32_t)(raw & 0xFFFFFFFFULL));
        break;
      }

      case SK_MCP_ArgType::Ptr:
      {
        if (! arg_values [i].is_string ())
          throw SK_MCP_ToolError { label + " must be an address string" };

        slots.push_back (
          (uint32_t)SK_MCP_ParseAddress (arg_values [i].get <std::string> ())
        );
        break;
      }

      case SK_MCP_ArgType::F32:
      {
        const float    f32  = (float)SK_MCP_ParseFloatArg (arg_values [i], label);
              uint32_t bits = 0;

        memcpy (&bits, &f32, sizeof (bits));

        slots.push_back (bits);
        break;
      }

      case SK_MCP_ArgType::F64:
      {
        const double f64 =
          SK_MCP_ParseFloatArg (arg_values [i], label);

        uint32_t bits [2] = { };

        memcpy (bits, &f64, sizeof (f64));

        // Low dword first.
        slots.push_back (bits [0]);
        slots.push_back (bits [1]);
        break;
      }
    }
  }

  // thiscall is __fastcall with the object in ECX and EDX unused.
  if (thiscall && (! slots.empty ()))
    slots.insert (slots.begin () + 1, 0);

  if (slots.size () > SK_MCP_MaxSlots)
  {
    throw SK_MCP_ToolError {
      "the arguments need " + std::to_string (slots.size ()) +
      " 4-byte stack slots; the limit is 16"
    };
  }

  for (size_t i = 0; i < slots.size (); ++i)
    plan.slots [i] = slots [i];

  size_t ret_slot = 0;   // uint32_t: void, int and ptr all read EAX

  if      (ret_kind == SK_MCP_RetKind::I64) ret_slot = 1;
  else if (ret_kind == SK_MCP_RetKind::F32) ret_slot = 2;
  else if (ret_kind == SK_MCP_RetKind::F64) ret_slot = 3;

  plan.thunk =
    _mcp_thunks86 [(conv * SK_MCP_SlotCounts86 + slots.size ()) * 4 + ret_slot];

#endif

  if (! on_render)
  {
    return
      SK_MCP_PerformCall (plan);
  }

  // plan is a copy; the job owns everything it touches.
  return
    SK_MCP_RunOnRenderThread ([plan](void) -> json
    {
      return
        SK_MCP_PerformCall (plan);
    }, timeout_ms);
}


void
SK_MCP_RegisterExecTools (void)
{
  SK_MCP_RegisterTool ({
    "sk_console",
    "Runs one Special K console command line (the same commands the control "
    "panel's console accepts) on the presenting thread and returns the command's "
    "result text and the command word it resolved to. Times out after 5 seconds "
    "if the game is not presenting frames.",
    {
      { "type", "object" },
      { "properties",
        { { "command", { { "type", "string" } } } }
      },
      { "required",             { "command" } },
      { "additionalProperties", false          }
    },
    SK_MCP_Console
  });

  static const json arg_type_enum = { "int", "ptr", "f32", "f64" };
  static const json return_enum   = { "void", "int", "i64", "ptr", "f32", "f64" };
  static const json thread_enum   = { "render", "worker" };

#ifdef _M_X64
  static const json convention_enum = { "win64" };
#else
  static const json convention_enum = { "cdecl", "stdcall", "thiscall", "fastcall" };
#endif

  SK_MCP_RegisterTool ({
    "sk_call_function",
    "Calls a function in the game at address (0x hex, module+offset or a pointer "
    "chain like [game.exe+0x10]+8) with up to 8 arguments and returns its value; "
    "calling the wrong address, or the right one with the wrong signature or arguments, will usually crash the game. "
    "thread defaults to render (the presenting thread) because engine code "
    "normally assumes it; use worker (one of the server's 4 tool threads) only for "
    "pure functions that touch no engine state. A callee that never returns hangs "
    "whichever thread it runs on: on render, timeout_ms ends the wait but the frame "
    "never completes, and on worker the call permanently occupies one of the 4 "
    "workers (and one of its client's 2 running slots) and blocks stopping the "
    "server. Not supported: variadic "
    "callees taking floats (the ABI also mirrors those into integer registers) "
    "and functions returning a struct by value (they take a hidden pointer "
    "argument)."
#ifdef _M_X64
    " x64 has one calling convention, so convention may be omitted."
#else
    " On x86, float arguments are rejected under fastcall and thiscall, i64 reads "
    "EDX:EAX so a callee that really returns 32 bits gives garbage in the high "
    "dword, and return must match the callee's real return kind or the x87 stack "
    "is corrupted and the game's later maths with it."
#endif
    ,
    {
      { "type", "object" },
      { "properties",
        { { "address",    { { "type", "string" } } },
          { "convention", { { "type", "string" }, { "enum", convention_enum } } },
          { "args",       { { "type", "array"  },
                            { "items",
                              { { "type", "object" },
                                { "properties",
                                  { { "type",  { { "type", "string" },
                                                 { "enum", arg_type_enum } } },
                                    { "value", json::object () } }
                                },
                                { "required",             { "type", "value" } },
                                { "additionalProperties", false               } }
                            } } },
          { "return",     { { "type", "string" }, { "enum", return_enum } } },
          { "thread",     { { "type", "string" }, { "enum", thread_enum } } },
          { "timeout_ms", { { "type", "number" } } } }
      },
      { "required",             { "address" } },
      { "additionalProperties", false          }
    },
    SK_MCP_CallFunction
  });
}
