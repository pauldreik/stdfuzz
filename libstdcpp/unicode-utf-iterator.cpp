// Copyright (c) 2024, Paul Dreik
// Licensed under Boost software license 1.0
// SPDX-License-Identifier: BSL-1.0

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include <bits/unicode.h>

#include "fuzzcombine.h"

namespace {
template<typename CharType, typename View>
constexpr inline auto
make_view(View&& view)
{
  return std::__unicode::_Utf_view<CharType, View>{ std::forward<View>(view) };
}

/*
 * this iterates over data, interpreting it as utf data.
 * the point is to exercise std::__unicode::_Utf_view for a variety
 * of input and output types
 */
template<typename CharType>
[[clang::optnone]] int
blah(auto data)
{
  auto v = make_view<CharType>(data);

  [[maybe_unused]] auto count = 0u;
  [[maybe_unused]] unsigned int tmp{};
  for (auto e : v) {
    tmp += e;
    ++count;
  }

  // could anything be asserted by count vs. data.size()?
  //  assert(count <= data.size());

  // this does not cause a runtime error, the iterator class protects against
  // misuse
  [[maybe_unused]] auto illegal = *v.end();
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
