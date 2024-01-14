// Copyright (c) 2024, Paul Dreik
// Licensed under Boost software license 1.0
// SPDX-License-Identifier: BSL-1.0

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include <bits/unicode.h>

#include <simdutf.h>

#include "fuzzcombine.h"

namespace {
template<typename OutputCharType, typename View>
constexpr inline auto
make_view(View&& view)
{
  return std::__unicode::_Utf_view<OutputCharType, View>{ std::forward<View>(
    view) };
}

/*
 * this iterates over data, interpreting it as utf data.
 * the point is to exercise std::__unicode::_Utf_view for a variety
 * of input and output types
 */
template<typename OutputCharType>
[[clang::optnone]] int
blah(auto data)
{
  auto v = make_view<OutputCharType>(data);
  using InputCharType = std::remove_cvref_t<decltype(*data.begin())>;

  const std::vector<InputCharType> input{ data.begin(), data.end() };
  const std::vector<OutputCharType> output{ v.begin(), v.end() };

  // could anything be asserted by count vs. data.size()? the answers below are
  // from jonathan wakely.

  // For 32-bit input and char32_t output you should get count == data.size(),
  // because either every input character is a valid UTF-32 code point that
  // can be returned as char32_t, or it's invalid and will be returned as the
  // U'\uFFFD' replacement character. Either way, it's 1 input to 1 output.
  if constexpr (sizeof(InputCharType) == 4 &&
                std::is_same_v<OutputCharType, char32_t>) {
    assert(output.size() == input.size());
  }

  // For 16-bit and 8-bit input and char32_t output then count <= data.size()
  // should be true. Some 16- or 8-bit input values represent a single code
  // point, and so get returned as a char32_t output value. But some 16-bit
  // input values are part of a surrogate pair and so two 16-bit code units are
  // consumed to produce a single UTF-32 output. And some 8-bit input values are
  // part of a multibyte sequence, in which case up to 4 bytes can be consumed
  // to produce a single UTF-32 output. In all cases, count < data.size() holds.
  if constexpr (sizeof(InputCharType) < 4 &&
                std::is_same_v<OutputCharType, char32_t>) {
    assert(output.size() <= input.size());
  }

  // But when the output is 8-bit or 16-bit, then you might get multiple output
  // values for a single input. e.g. the input range U"£" consists of a single
  // char32_t code unit, but is encoded as two bytes in UTF-8. Other code points
  // require three or four bytes. So count >= data.size(). Similarly, any code
  // point that doesn't fit in a single UTF-16 code unit will get encoded as a
  // surrogate pair, so one 32-bit input value can produce up to two 16-bit
  // output values. And 16-bit inputs with 8-bit outputs can also give an output
  // count higher than the input size.
  constexpr bool is_32_to_less_than_32 =
    sizeof(InputCharType) == 4 && sizeof(OutputCharType) < 4;
  constexpr bool is_16_to_8 =
    sizeof(InputCharType) == 2 && sizeof(OutputCharType) < 1;
  if constexpr (is_32_to_less_than_32 || is_16_to_8) {
    assert(output.size() >= input.size());
  }

  // I think it's accurate to say that if sizeof(input) == sizeof(output) then
  // count <= data.size() is true ... but I'd have to think about it further.
  // Even in that case it's not the case that count == data.size() because
  // invalid UTF-8 sequences can be transformed to U+FFFD which requires three
  // bytes, so if the input consists of four bytes, the output will be smaller.
  if constexpr (sizeof(InputCharType) == sizeof(OutputCharType)) {
    // this fails
    // assert(count <= input.size());
  }

  {
    // this does not cause a runtime error, the iterator class protects against
    // misuse
    auto outside = v.end();
    for (int i = 0; i < 8; ++i) {
      [[maybe_unused]] auto illegal = *outside++;
    }
  }

  // validate that the output is correct utf
  if (!output.empty()) {
    if constexpr (std::is_same_v<OutputCharType, char32_t>) {
      const auto ret =
        simdutf::validate_utf32_with_errors(output.data(), output.size());
      assert(ret.error == simdutf::error_code::SUCCESS);
    }
    if constexpr (std::is_same_v<OutputCharType, char16_t>) {
      const auto ret =
        simdutf::validate_utf16_with_errors(output.data(), output.size());
      // assert(ret.error == simdutf::error_code::SUCCESS);
    }
    if constexpr (std::is_same_v<OutputCharType, char8_t>) {
      const auto ret = simdutf::validate_utf8_with_errors(
        reinterpret_cast<const char*>(output.data()), output.size());
      assert(ret.error == simdutf::error_code::SUCCESS);
    }
  }

  return 0;
}
}

extern "C" [[clang::optnone]] int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  FuzzCombiner fuzzdata(data, size);

  using OutputTypes = std::tuple<char8_t, char16_t, char32_t>;
  using InputTypes = std::tuple< // bool,
    char,
    wchar_t,
    char8_t,
    char16_t,
    char32_t,
    signed char,
    unsigned char,
    short,
    unsigned short,
    int,
    unsigned int>;
  fuzzdata.combine_args<OutputTypes, InputTypes>(
    []<typename Out, typename In>(Out, In, FuzzCombiner* fd) {
      if constexpr (sizeof(In) == 1) {
        blah<Out>(fd->get_remainder_as_span<In>());
      } else {
        auto d = fd->get_remainder<In>();
        blah<Out>(std::span{ d.data(), d.data() + d.size() });
      }
    });
  return 0;
}
